//! `glob`: files matching a pattern under `path` (default cwd), newest first.

use std::path::Path;
use std::time::SystemTime;

use globset::GlobBuilder;
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::{ToolOutcome, resolve, str_field, u64_field};

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let Some(pattern) = str_field(input, "pattern") else {
        return ToolOutcome::fail("pattern is required");
    };
    let base = str_field(input, "path")
        .map(|p| resolve(cwd, p))
        .unwrap_or_else(|| cwd.to_path_buf());
    let max_results = u64_field(input, "max_results", 1000).max(1) as usize;
    let matcher = match GlobBuilder::new(pattern).literal_separator(false).build() {
        Ok(g) => g.compile_matcher(),
        Err(e) => return ToolOutcome::fail(format!("invalid glob {pattern:?}: {e}")),
    };
    if !base.is_dir() {
        return ToolOutcome::fail(format!("{}: not a directory", base.display()));
    }
    let mut hits: Vec<(SystemTime, String)> = Vec::new();
    for entry in WalkDir::new(&base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(&base).unwrap_or(entry.path());
        if matcher.is_match(rel) || matcher.is_match(entry.path()) {
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            hits.push((mtime, entry.path().to_string_lossy().into_owned()));
        }
    }
    hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let total = hits.len();
    let truncated = total > max_results;
    hits.truncate(max_results);
    let mut out = String::new();
    for (_, p) in &hits {
        out.push_str(p);
        out.push('\n');
    }
    ToolOutcome::ok(
        out.into_bytes(),
        json!({ "matches": hits.len(), "truncated": truncated }),
    )
}
