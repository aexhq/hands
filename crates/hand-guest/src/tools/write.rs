//! `write`: create or overwrite a file, creating parent directories.

use std::path::Path;

use serde_json::{Value, json};

use super::{ToolOutcome, resolve, str_field};

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let Some(p) = str_field(input, "path") else {
        return ToolOutcome::fail("path is required");
    };
    let Some(content) = str_field(input, "content") else {
        return ToolOutcome::fail("content is required");
    };
    let path = resolve(cwd, p);
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return ToolOutcome::fail(format!("{}: {e}", parent.display()));
    }
    let created = !path.exists();
    match std::fs::write(&path, content) {
        Ok(()) => ToolOutcome::ok(
            format!("wrote {} bytes to {}\n", content.len(), path.display()).into_bytes(),
            json!({ "bytes_written": content.len(), "created": created }),
        ),
        Err(e) => ToolOutcome::fail(format!("{}: {e}", path.display())),
    }
}
