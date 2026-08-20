//! Process configuration (environment-driven) and the fixed limits this hand declares.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::PathBuf;

use brain_protocol::abi::{EffectiveBounds, Limits};

/// Environment variables the hand reads at start-up.
pub const ENV_TOKEN: &str = "HAND_TOKEN";
pub const ENV_LISTEN: &str = "HAND_LISTEN";
pub const ENV_WORKSPACE: &str = "HAND_WORKSPACE";
pub const ENV_HOME: &str = "HAND_HOME";
pub const ENV_SPILL_DIR: &str = "HAND_SPILL_DIR";
pub const ENV_TOOL_DIR: &str = "HAND_TOOL_DIR";
pub const ENV_TOOL_RUNNER: &str = "HAND_TOOL_RUNNER";

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// Per-session secret the brain must present in `hello`.
    ///
    /// `None` means the hand boots **unarmed**: every `hello` is refused until the platform
    /// delivers the token through the `/run` lifecycle hook (Lambda MicroVM has no per-VM
    /// environment, so the secret cannot arrive as an env var there).
    pub token: Option<String>,
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub spill_dir: PathBuf,
    pub tool_dir: PathBuf,
    pub tool_runner: PathBuf,
    /// Environment every lane starts from (before the session's `hello.env` overrides).
    pub base_env: HashMap<String, String>,
    pub limits: Limits,
}

impl Config {
    /// Read from the process environment. A missing `HAND_TOKEN` is not an error: the Hand
    /// boots unarmed and waits for the `/run` lifecycle hook to deliver the session token. An
    /// unarmed hand refuses every `hello`, so it never accepts an unauthenticated brain.
    pub fn from_env() -> anyhow::Result<Self> {
        let token = std::env::var(ENV_TOKEN).ok().filter(|t| !t.is_empty());
        let listen: SocketAddr = std::env::var(ENV_LISTEN)
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .map_err(|e| anyhow::anyhow!("{ENV_LISTEN}: {e}"))?;
        let workspace =
            PathBuf::from(std::env::var(ENV_WORKSPACE).unwrap_or_else(|_| "/workspace".into()));
        let home = PathBuf::from(
            std::env::var(ENV_HOME)
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| "/home/agent".into()),
        );
        let spill_dir =
            PathBuf::from(std::env::var(ENV_SPILL_DIR).unwrap_or_else(|_| "/var/hand/ops".into()));
        let mut config = Self::new(listen, token, workspace, home, spill_dir);
        config.tool_dir =
            PathBuf::from(std::env::var(ENV_TOOL_DIR).unwrap_or_else(|_| "/var/hand/tools".into()));
        config.tool_runner = PathBuf::from(
            std::env::var(ENV_TOOL_RUNNER)
                .unwrap_or_else(|_| "/usr/local/lib/hand/tool-runner.mjs".into()),
        );
        Ok(config)
    }

    pub fn new(
        listen: SocketAddr,
        token: Option<String>,
        workspace: PathBuf,
        home: PathBuf,
        spill_dir: PathBuf,
    ) -> Self {
        let tool_dir = spill_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("tools");
        Self {
            listen,
            token,
            base_env: base_env_from_process(&home),
            workspace,
            home,
            spill_dir,
            tool_dir,
            tool_runner: PathBuf::from("/usr/local/lib/hand/tool-runner.mjs"),
            limits: default_limits(),
        }
    }
}

/// The subset of the hand process's own environment that lanes inherit. Everything else
/// (notably our own HAND_* settings) stays out of the agent's shell.
fn base_env_from_process(home: &std::path::Path) -> HashMap<String, String> {
    const INHERIT: &[&str] = &[
        "PATH",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TZ",
        "SHELL",
        "TMPDIR",
        // installers redirected into the workspace (set by the image)
        "npm_config_prefix",
        "GOPATH",
        "GOMODCACHE",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "PIP_CACHE_DIR",
        "PIPX_HOME",
        "PIPX_BIN_DIR",
        "UV_CACHE_DIR",
        "PNPM_HOME",
        "YARN_CACHE_FOLDER",
    ];
    let mut env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| INHERIT.contains(&k.as_str()))
        .collect();
    env.entry("PATH".into())
        .or_insert_with(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    env.insert("HOME".into(), home.to_string_lossy().into_owned());
    env.insert("TERM".into(), "dumb".into());
    env.insert("CI".into(), "1".into());
    env.insert("DEBIAN_FRONTEND".into(), "noninteractive".into());
    env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    env
}

pub const MAX_LANES: u64 = 64;
pub const MAX_CONCURRENT_OPERATIONS: u64 = 64;
pub const MAX_FRAME_BYTES: u64 = 1024 * 1024;
pub const MAX_SLICE_BYTES: u64 = 256 * 1024;
pub const MAX_POLL_WAIT_MS: u64 = 30_000;
pub const MAX_INLINE_PUT_BYTES: u64 = 256 * 1024;
pub const MAX_PERSIST_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_GRACE_MS: u64 = 2_000;
pub const DEFAULT_MAX_RETAINED_BYTES: u64 = 64 * 1024 * 1024;

pub fn default_limits() -> Limits {
    Limits {
        max_lanes: NonZeroU64::new(MAX_LANES).unwrap(),
        max_concurrent_operations: NonZeroU64::new(MAX_CONCURRENT_OPERATIONS).unwrap(),
        max_frame_bytes: MAX_FRAME_BYTES as i64,
        max_slice_bytes: MAX_SLICE_BYTES as i64,
        max_poll_wait_ms: MAX_POLL_WAIT_MS,
        max_inline_put_bytes: MAX_INLINE_PUT_BYTES,
        max_persist_bytes: MAX_PERSIST_BYTES,
        default_bounds: EffectiveBounds {
            timeout_ms: None,
            grace_ms: DEFAULT_GRACE_MS,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
        },
    }
}
