//! Typed tools implemented in-process: `read`, `write`, `edit`, `glob`, `grep`, `ls`.
//!
//! Each behaves like a command: it writes its human-readable result to stdout, diagnostics to
//! stderr, exits 0 on success or 1 on a tool-level failure, and returns a small typed `output`
//! (validated against the manifest's `output_schema`) when it succeeds.

pub mod edit;
pub mod glob;
pub mod grep;
pub mod ls;
pub mod read;
pub mod write;

use std::path::{Path, PathBuf};

use serde_json::Value;

pub struct ToolOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Present on exit 0.
    pub output: Option<Value>,
}

impl ToolOutcome {
    pub fn ok(stdout: Vec<u8>, output: Value) -> Self {
        Self {
            exit_code: 0,
            stdout,
            stderr: Vec::new(),
            output: Some(output),
        }
    }
    pub fn fail(msg: impl Into<String>) -> Self {
        let mut stderr = msg.into().into_bytes();
        stderr.push(b'\n');
        Self {
            exit_code: 1,
            stdout: Vec::new(),
            stderr,
            output: None,
        }
    }
}

/// Every hand tool name the manifest v1 lists, in the order the hand dispatches them.
pub const HAND_TOOLS: &[&str] = &["bash", "edit", "glob", "grep", "ls", "read", "write"];

/// Runs a typed tool synchronously (call inside `spawn_blocking`).
pub fn run(tool: &str, input: &Value, cwd: &Path) -> ToolOutcome {
    match tool {
        "read" => read::run(input, cwd),
        "write" => write::run(input, cwd),
        "edit" => edit::run(input, cwd),
        "glob" => glob::run(input, cwd),
        "grep" => grep::run(input, cwd),
        "ls" => ls::run(input, cwd),
        other => ToolOutcome::fail(format!("unknown typed tool {other}")),
    }
}

/// Resolves a tool path argument against the call's cwd.
pub fn resolve(cwd: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

pub fn str_field<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}
pub fn u64_field(input: &Value, key: &str, default: u64) -> u64 {
    input.get(key).and_then(Value::as_u64).unwrap_or(default)
}
pub fn bool_field(input: &Value, key: &str, default: bool) -> bool {
    input.get(key).and_then(Value::as_bool).unwrap_or(default)
}
