//! `ls`: directory listing, `depth` levels, directories suffixed with `/`, symlinks with `@`.

use std::path::Path;

use serde_json::{Value, json};
use walkdir::WalkDir;

use super::{ToolOutcome, bool_field, resolve, str_field, u64_field};

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let base = str_field(input, "path")
        .map(|p| resolve(cwd, p))
        .unwrap_or_else(|| cwd.to_path_buf());
    let depth = u64_field(input, "depth", 1).max(1) as usize;
    let hidden = bool_field(input, "hidden", false);
    let max_entries = u64_field(input, "max_entries", 2000).max(1) as usize;
    if !base.is_dir() {
        return ToolOutcome::fail(format!("{}: not a directory", base.display()));
    }
    let mut lines: Vec<String> = Vec::new();
    let mut total = 0usize;
    let walker = WalkDir::new(&base)
        .min_depth(1)
        .max_depth(depth)
        .follow_links(false)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .filter_entry(move |e| hidden || !e.file_name().to_string_lossy().starts_with('.'));
    for entry in walker {
        let Ok(entry) = entry else { continue };
        total += 1;
        if lines.len() >= max_entries {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(&base)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();
        let suffix = if entry.file_type().is_dir() {
            "/"
        } else if entry.file_type().is_symlink() {
            "@"
        } else {
            ""
        };
        lines.push(format!("{rel}{suffix}"));
    }
    let truncated = total > lines.len();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    ToolOutcome::ok(
        out.into_bytes(),
        json!({ "entries": lines.len(), "truncated": truncated }),
    )
}
