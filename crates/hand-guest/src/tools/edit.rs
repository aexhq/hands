//! `edit`: exact-string replacement in a file.

use std::path::Path;

use serde_json::{Value, json};

use super::{ToolOutcome, bool_field, resolve, str_field};

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let Some(p) = str_field(input, "path") else {
        return ToolOutcome::fail("path is required");
    };
    let Some(old) = str_field(input, "old_string") else {
        return ToolOutcome::fail("old_string is required");
    };
    let Some(new) = str_field(input, "new_string") else {
        return ToolOutcome::fail("new_string is required");
    };
    let replace_all = bool_field(input, "replace_all", false);
    if old.is_empty() {
        return ToolOutcome::fail("old_string must not be empty");
    }
    let path = resolve(cwd, p);
    let text = match std::fs::read(&path) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => {
                return ToolOutcome::fail(format!(
                    "{}: not valid UTF-8; edit it with a shell tool",
                    path.display()
                ));
            }
        },
        Err(e) => return ToolOutcome::fail(format!("{}: {e}", path.display())),
    };
    let count = text.matches(old).count();
    if count == 0 {
        return ToolOutcome::fail(format!("{}: old_string not found", path.display()));
    }
    if count > 1 && !replace_all {
        return ToolOutcome::fail(format!(
            "{}: old_string matches {count} times; make it unique (add surrounding context) or pass replace_all",
            path.display()
        ));
    }
    let replaced = if replace_all {
        text.replace(old, new)
    } else {
        text.replacen(old, new, 1)
    };
    let replacements = if replace_all { count } else { 1 };
    match std::fs::write(&path, replaced) {
        Ok(()) => ToolOutcome::ok(
            format!(
                "replaced {replacements} occurrence(s) in {}\n",
                path.display()
            )
            .into_bytes(),
            json!({ "replacements": replacements }),
        ),
        Err(e) => ToolOutcome::fail(format!("{}: {e}", path.display())),
    }
}
