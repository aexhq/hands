//! Running a shell command as an operation.
//!
//! * The child gets its own session (`setsid`) so cancellation can signal the whole process
//!   group, and so a backgrounded grandchild never holds the operation open.
//! * We wait on the **direct child's exit**, never on pipe EOF (I6). Reader tasks keep draining
//!   the pipes into the spill files for as long as anything writes to them.
//! * In a persistent lane, an attached command's environment is captured after it exits
//!   (`env -0` trailer) and becomes the lane's environment for the next call.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use brain_protocol::abi::{ErrorCode, Outcome, Stream};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::errors::err;
use crate::ops::Operation;

/// Environment variables bash sets itself; never carried between calls.
const VOLATILE_ENV: &[&str] = &[
    "_",
    "SHLVL",
    "PWD",
    "OLDPWD",
    "HAND_ENV_CAPTURE",
    "BASH_EXECUTION_STRING",
];

pub struct BashSpec {
    pub command: String,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    /// Where to capture the environment after the command exits (persistent lane, attached).
    pub capture_env_to: Option<PathBuf>,
    /// Per-call timeout override from the tool input.
    pub timeout_ms: Option<u64>,
}

pub struct Finished {
    pub captured_env: Option<HashMap<String, String>>,
}

pub struct NodeSpec {
    pub runner: PathBuf,
    pub bundle: PathBuf,
    pub request: Value,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    pub request_path: PathBuf,
    pub result_path: PathBuf,
}

pub struct NodeFinished {
    pub outcome: Outcome,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub output: Option<Value>,
    pub infrastructure_error: Option<String>,
}

fn script(command: &str, capture: bool) -> String {
    if capture {
        // Run the user's command as-is, remember its status, dump the environment, exit with it.
        format!(
            "{command}\n__hand_rc=$?\nenv -0 > \"$HAND_ENV_CAPTURE\" 2>/dev/null\nexit $__hand_rc\n"
        )
    } else {
        command.to_string()
    }
}

/// Runs the command to completion (or cancellation/deadline) and records the terminal state on
/// `op`. Returns the captured environment, if any.
pub async fn run_bash(op: Arc<Operation>, spec: BashSpec) -> Finished {
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg(script(&spec.command, spec.capture_env_to.is_some()));
    cmd.env_clear();
    cmd.envs(&spec.env);
    if let Some(p) = &spec.capture_env_to {
        cmd.env("HAND_ENV_CAPTURE", p);
    }
    cmd.current_dir(&spec.cwd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.kill_on_drop(false);
    // SAFETY: setsid in the forked child before exec; no allocation, async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                ErrorCode::PathNotFound
            } else {
                ErrorCode::Internal
            };
            let info = op.terminal_info(
                Outcome::Failed,
                None,
                None,
                None,
                Some(err(code, format!("spawn: {e}"))),
            );
            op.set_terminal(info);
            return Finished { captured_env: None };
        }
    };
    let pid = child.id().map(|p| p as i32);
    {
        let mut st = op.state.lock().unwrap();
        st.pgid = pid;
        // A cancel that raced the spawn: deliver it now.
        if st.cancel_requested
            && let Some(pgid) = pid
        {
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
        }
    }

    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let out_task = tokio::spawn(drain(op.clone(), Stream::Stdout, stdout));
    let err_task = tokio::spawn(drain(op.clone(), Stream::Stderr, stderr));

    // Deadline: SIGTERM at timeout, SIGKILL after grace.
    let timeout_ms = spec
        .timeout_ms
        .or_else(|| op.bounds.timeout_ms.map(|n| n.get()));
    let deadline_task = timeout_ms.map(|ms| {
        let op = op.clone();
        let grace = op.bounds.grace_ms;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            op.state.lock().unwrap().deadline_hit = true;
            op.signal(libc::SIGTERM);
            tokio::time::sleep(Duration::from_millis(grace)).await;
            op.signal(libc::SIGKILL);
        })
    });

    let status = child.wait().await;
    if let Some(t) = deadline_task {
        t.abort();
    }
    // Give the drainers a moment to flush what the child wrote right before exiting. If a
    // grandchild still holds the pipe, we do not wait for it (I6): the drainer keeps running.
    let _ = tokio::time::timeout(Duration::from_millis(50), async {
        let _ = tokio::join!(out_task, err_task);
    })
    .await;

    let (cancel_requested, deadline_hit) = {
        let st = op.state.lock().unwrap();
        (st.cancel_requested, st.deadline_hit)
    };
    let (exit_code, signal) = match &status {
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            (s.code().map(i64::from), s.signal().map(signal_name))
        }
        Err(_) => (None, None),
    };
    let outcome = if cancel_requested {
        Outcome::Cancelled
    } else if deadline_hit {
        Outcome::DeadlineExceeded
    } else if status.is_err() {
        Outcome::Failed
    } else {
        Outcome::Completed
    };
    let captured_env = match (&spec.capture_env_to, outcome) {
        (Some(p), Outcome::Completed) => read_env_capture(p),
        _ => None,
    };
    if let Some(p) = &spec.capture_env_to {
        let _ = std::fs::remove_file(p);
    }
    let output = if outcome == Outcome::Completed || outcome == Outcome::DeadlineExceeded {
        Some(serde_json::json!({ "timed_out": deadline_hit }))
    } else {
        None
    };
    let error = match &status {
        Err(e) => Some(err(ErrorCode::Internal, format!("wait: {e}"))),
        Ok(_) => None,
    };
    let info = op.terminal_info(outcome, exit_code, signal, output, error);
    op.set_terminal(info);
    Finished { captured_env }
}

/// Runs one checksum-staged ESM bundle in a fresh Node 22 process. The result travels through a
/// private file so customer stdout/stderr remain ordinary operation streams.
pub async fn run_node(op: Arc<Operation>, spec: NodeSpec) -> NodeFinished {
    let request = match serde_json::to_vec(&spec.request) {
        Ok(request) => request,
        Err(error) => {
            return NodeFinished {
                outcome: Outcome::Failed,
                exit_code: None,
                signal: None,
                output: None,
                infrastructure_error: Some(format!("serialize tool request: {error}")),
            };
        }
    };
    if let Some(parent) = spec.request_path.parent()
        && let Err(error) = tokio::fs::create_dir_all(parent).await
    {
        return NodeFinished {
            outcome: Outcome::Failed,
            exit_code: None,
            signal: None,
            output: None,
            infrastructure_error: Some(format!("prepare tool request directory: {error}")),
        };
    }
    if let Err(error) = tokio::fs::write(&spec.request_path, request).await {
        return NodeFinished {
            outcome: Outcome::Failed,
            exit_code: None,
            signal: None,
            output: None,
            infrastructure_error: Some(format!("write tool request: {error}")),
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            tokio::fs::set_permissions(&spec.request_path, std::fs::Permissions::from_mode(0o600))
                .await;
    }
    let _ = tokio::fs::remove_file(&spec.result_path).await;

    let mut cmd = Command::new("node");
    cmd.arg(&spec.runner)
        .arg(&spec.bundle)
        .arg(&spec.request_path)
        .arg(&spec.result_path)
        .env_clear()
        .envs(&spec.env)
        .env("NODE_NO_WARNINGS", "1")
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = tokio::fs::remove_file(&spec.request_path).await;
            return NodeFinished {
                outcome: Outcome::Failed,
                exit_code: None,
                signal: None,
                output: None,
                infrastructure_error: Some(format!("spawn Node tool runner: {error}")),
            };
        }
    };
    let pid = child.id().map(|pid| pid as i32);
    {
        let mut state = op.state.lock().unwrap();
        state.pgid = pid;
        if state.cancel_requested
            && let Some(pgid) = pid
        {
            unsafe { libc::kill(-pgid, libc::SIGTERM) };
        }
    }
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let out_task = tokio::spawn(drain(op.clone(), Stream::Stdout, stdout));
    let err_task = tokio::spawn(drain(op.clone(), Stream::Stderr, stderr));
    let deadline_task = op.bounds.timeout_ms.map(|timeout| {
        let op = op.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(timeout.get())).await;
            op.state.lock().unwrap().deadline_hit = true;
            op.signal(libc::SIGTERM);
            tokio::time::sleep(Duration::from_millis(op.bounds.grace_ms)).await;
            op.signal(libc::SIGKILL);
        })
    });
    let status = child.wait().await;
    if let Some(task) = deadline_task {
        task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_millis(50), async {
        let _ = tokio::join!(out_task, err_task);
    })
    .await;
    let (cancel_requested, deadline_hit) = {
        let state = op.state.lock().unwrap();
        (state.cancel_requested, state.deadline_hit)
    };
    let (exit_code, signal) = match &status {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
            (
                status.code().map(i64::from),
                status.signal().map(signal_name),
            )
        }
        Err(_) => (None, None),
    };
    let mut infrastructure_error = status
        .as_ref()
        .err()
        .map(|error| format!("wait for Node tool runner: {error}"));
    let output = if cancel_requested || deadline_hit {
        None
    } else {
        match tokio::fs::read(&spec.result_path).await {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) if value.get("ok").and_then(Value::as_bool) == Some(true) => {
                    value.get("output").cloned()
                }
                Ok(_) => None,
                Err(error) => {
                    infrastructure_error = Some(format!("parse Node tool result: {error}"));
                    None
                }
            },
            Err(error) if exit_code == Some(0) => {
                infrastructure_error = Some(format!("read Node tool result: {error}"));
                None
            }
            Err(_) => None,
        }
    };
    let _ = tokio::fs::remove_file(&spec.request_path).await;
    let _ = tokio::fs::remove_file(&spec.result_path).await;
    let outcome = if cancel_requested {
        Outcome::Cancelled
    } else if deadline_hit {
        Outcome::DeadlineExceeded
    } else if infrastructure_error.is_some() {
        Outcome::Failed
    } else {
        // A thrown Tool error is a completed invocation with non-zero exit status, matching the
        // preinstalled command tools. Brain exposes it as an error result without replaying it.
        Outcome::Completed
    };
    NodeFinished {
        outcome,
        exit_code,
        signal,
        output,
        infrastructure_error,
    }
}

async fn drain<R: tokio::io::AsyncRead + Unpin>(op: Arc<Operation>, stream: Stream, mut r: R) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if op.append(stream, &buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn read_env_capture(path: &Path) -> Option<HashMap<String, String>> {
    let bytes = std::fs::read(path).ok()?;
    let mut env = HashMap::new();
    for entry in bytes.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(entry);
        if let Some((k, v)) = s.split_once('=') {
            if VOLATILE_ENV.contains(&k) || k.starts_with("BASH_FUNC_") {
                continue;
            }
            env.insert(k.to_string(), v.to_string());
        }
    }
    Some(env)
}

fn signal_name(sig: i32) -> String {
    match sig {
        libc::SIGTERM => "SIGTERM".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGINT => "SIGINT".into(),
        libc::SIGHUP => "SIGHUP".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGPIPE => "SIGPIPE".into(),
        n => format!("SIG{n}"),
    }
}
