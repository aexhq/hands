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

/// Concrete executables compiled into the image. Selection is by checksum, never by the
/// model-visible Tool name. Renaming a sealed Tool therefore requires no dispatcher change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preinstalled {
    Bash,
    Edit,
    Glob,
    Grep,
    Ls,
    Read,
    Write,
}

pub fn preinstalled(checksum: &str) -> Option<Preinstalled> {
    Some(match checksum {
        "0ed0bae284be7259c3d82f498885dc7010747fdb4b9f3edcc3160c922dac161b" => Preinstalled::Bash,
        "deb8dd2afb0ad6658dd3667a7bc525266b776a959adc0e5c99ff5a3f27ca9c43" => Preinstalled::Edit,
        "4721f58d411cf593b5f91a434680c16c08ae6da7409663928b3b512f3d39ddb4" => Preinstalled::Glob,
        "5fd52904b191d45e58b308a3f336ae534616948fd28ef5a278210571d4d073f1" => Preinstalled::Grep,
        "b9cec943bf70a2896f65ab5120e7a52f20b38ad39536f70058e32bf2bc19943a" => Preinstalled::Ls,
        "74d97cc52d0607605e9b0c0fa3e90127f5cd68fcc4d6673c855b515c582006ef" => Preinstalled::Read,
        "0560ad249be00118236ba6918bb432d64dbc01f92a50e668ca0b7476f3447e46" => Preinstalled::Write,
        _ => return None,
    })
}

/// Runs a typed tool synchronously (call inside `spawn_blocking`).
pub fn run(tool: Preinstalled, input: &Value, cwd: &Path) -> ToolOutcome {
    match tool {
        Preinstalled::Read => read::run(input, cwd),
        Preinstalled::Write => write::run(input, cwd),
        Preinstalled::Edit => edit::run(input, cwd),
        Preinstalled::Glob => glob::run(input, cwd),
        Preinstalled::Grep => grep::run(input, cwd),
        Preinstalled::Ls => ls::run(input, cwd),
        Preinstalled::Bash => ToolOutcome::fail("bash uses the process runner"),
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
