//! `read`: a text file's lines from `offset` (1-based), at most `limit` lines, raw on stdout.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::{Value, json};

use super::{ToolOutcome, resolve, str_field, u64_field};

const BINARY_PROBE_BYTES: usize = 8192;

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let Some(p) = str_field(input, "path") else {
        return ToolOutcome::fail("path is required");
    };
    let path = resolve(cwd, p);
    let offset = u64_field(input, "offset", 1).max(1) as usize;
    let limit = u64_field(input, "limit", 2000).max(1) as usize;

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => return ToolOutcome::fail(format!("{}: {e}", path.display())),
    };
    if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return ToolOutcome::fail(format!("{}: is a directory", path.display()));
    }
    let mut reader = BufReader::new(file);
    // Binary probe: NUL in the first 8 KiB.
    let mut probe = vec![0u8; BINARY_PROBE_BYTES];
    let n = match reader.read(&mut probe) {
        Ok(n) => n,
        Err(e) => return ToolOutcome::fail(format!("{}: {e}", path.display())),
    };
    if probe[..n].contains(&0) {
        return ToolOutcome::fail(format!(
            "{}: binary file (contains NUL bytes); inspect it with a shell tool instead",
            path.display()
        ));
    }
    // Restart from the top, line by line (bytes, so invalid UTF-8 lines are still delivered).
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => return ToolOutcome::fail(format!("{}: {e}", path.display())),
    };
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut end_line = 0usize;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = match reader.read_until(b'\n', &mut line) {
            Ok(n) => n,
            Err(e) => return ToolOutcome::fail(format!("{}: {e}", path.display())),
        };
        if n == 0 {
            break;
        }
        total += 1;
        if total >= offset && total < offset + limit {
            out.extend_from_slice(&line);
            end_line = total;
        }
    }
    let start_line = if end_line == 0 { 0 } else { offset };
    ToolOutcome::ok(
        out,
        json!({ "total_lines": total, "start_line": start_line, "end_line": end_line, "truncated": total > end_line }),
    )
}
