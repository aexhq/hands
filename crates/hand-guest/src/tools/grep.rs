//! `grep`: regex search over file contents with ripgrep's libraries (respects .gitignore, skips
//! hidden files and binaries). Modes: `files` (paths with a match), `content`
//! (`path:line:text`, with optional context), `count` (`path:count`).

use std::io::Write;
use std::path::Path;

use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkContext, SinkContextKind, SinkMatch};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use serde_json::{Value, json};

use super::{ToolOutcome, bool_field, resolve, str_field, u64_field};

pub fn run(input: &Value, cwd: &Path) -> ToolOutcome {
    let Some(pattern) = str_field(input, "pattern") else {
        return ToolOutcome::fail("pattern is required");
    };
    let base = str_field(input, "path")
        .map(|p| resolve(cwd, p))
        .unwrap_or_else(|| cwd.to_path_buf());
    let mode = str_field(input, "mode").unwrap_or("files");
    let case_insensitive = bool_field(input, "case_insensitive", false);
    let context = u64_field(input, "context", 0) as usize;
    let max_results = u64_field(input, "max_results", 1000).max(1) as usize;
    if !matches!(mode, "files" | "content" | "count") {
        return ToolOutcome::fail(format!("mode must be files|content|count, got {mode:?}"));
    }
    if !base.exists() {
        return ToolOutcome::fail(format!("{}: no such file or directory", base.display()));
    }
    let matcher = match RegexMatcherBuilder::new()
        .case_insensitive(case_insensitive)
        .line_terminator(Some(b'\n'))
        .build(pattern)
    {
        Ok(m) => m,
        Err(e) => return ToolOutcome::fail(format!("invalid regex {pattern:?}: {e}")),
    };
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .before_context(if mode == "content" { context } else { 0 })
        .after_context(if mode == "content" { context } else { 0 })
        .binary_detection(grep_searcher::BinaryDetection::quit(0))
        .build();

    let mut walk = WalkBuilder::new(&base);
    walk.hidden(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .follow_links(false);
    if let Some(glob) = str_field(input, "glob") {
        let mut ov = OverrideBuilder::new(&base);
        if let Err(e) = ov.add(glob) {
            return ToolOutcome::fail(format!("invalid glob {glob:?}: {e}"));
        }
        match ov.build() {
            Ok(o) => {
                walk.overrides(o);
            }
            Err(e) => return ToolOutcome::fail(format!("invalid glob {glob:?}: {e}")),
        }
    }

    let mut out: Vec<u8> = Vec::new();
    let mut results = 0usize; // files (files mode) or matching lines (content/count)
    let mut truncated = false;
    'files: for entry in walk.build() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let shown = path.to_string_lossy().into_owned();
        let mut sink = LineSink {
            matcher: &matcher,
            mode,
            path: &shown,
            out: &mut out,
            file_matches: 0,
            budget: max_results.saturating_sub(results),
        };
        if mode == "files" && results >= max_results {
            truncated = true;
            break 'files;
        }
        let _ = searcher.search_path(&matcher, path, &mut sink);
        let file_matches = sink.file_matches;
        let hit_budget = sink.hit_budget();
        if file_matches > 0 {
            match mode {
                "files" => {
                    let _ = writeln!(out, "{shown}");
                    results += 1;
                }
                "count" => {
                    let _ = writeln!(out, "{shown}:{file_matches}");
                    results += file_matches;
                }
                _ => results += file_matches,
            }
        }
        if hit_budget || (mode != "files" && results >= max_results) {
            truncated = true;
            break 'files;
        }
    }
    let _ = searcher; // silence unused warnings on some paths
    ToolOutcome::ok(out, json!({ "matches": results, "truncated": truncated }))
}

struct LineSink<'a, M: Matcher> {
    matcher: &'a M,
    mode: &'a str,
    path: &'a str,
    out: &'a mut Vec<u8>,
    file_matches: usize,
    budget: usize,
}

impl<M: Matcher> LineSink<'_, M> {
    fn hit_budget(&self) -> bool {
        self.mode != "files" && self.file_matches >= self.budget
    }
}

impl<M: Matcher> Sink for LineSink<'_, M> {
    type Error = std::io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        let _ = self.matcher;
        self.file_matches += 1;
        match self.mode {
            "content" => {
                let line = String::from_utf8_lossy(mat.bytes());
                let _ = write!(
                    self.out,
                    "{}:{}:{}",
                    self.path,
                    mat.line_number().unwrap_or(0),
                    line
                );
                if !line.ends_with('\n') {
                    self.out.push(b'\n');
                }
                Ok(self.file_matches < self.budget)
            }
            // files: one match is enough to list the file; count: keep counting.
            "files" => Ok(false),
            _ => Ok(self.file_matches < self.budget),
        }
    }

    fn context(
        &mut self,
        _searcher: &Searcher,
        ctx: &SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        if self.mode == "content" {
            let sep = match ctx.kind() {
                SinkContextKind::Before | SinkContextKind::After => '-',
                SinkContextKind::Other => '-',
            };
            let line = String::from_utf8_lossy(ctx.bytes());
            let _ = write!(
                self.out,
                "{}{sep}{}{sep}{}",
                self.path,
                ctx.line_number().unwrap_or(0),
                line
            );
            if !line.ends_with('\n') {
                self.out.push(b'\n');
            }
        }
        Ok(true)
    }
}
