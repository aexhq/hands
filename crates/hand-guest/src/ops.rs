//! Operations: one tool call with a durable identity, two spilled streams, and a terminal state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use brain_protocol::abi::{
    AbiError, EffectiveBounds, LaneId, LaneMode, OperationId, OperationStatus, OperationView,
    Outcome, OutputSlice, Sha256Hex, Stream, StreamInfo, TerminalInfo, Usage,
};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, watch};

use crate::spill::{ReadError, Spill};

pub struct Operation {
    pub id: OperationId,
    pub tool: String,
    pub lane_id: LaneId,
    pub lane_mode: LaneMode,
    pub detach: bool,
    pub call_hash: Sha256Hex,
    pub correlation: Map<String, Value>,
    pub bounds: EffectiveBounds,
    pub started_at: Instant,
    pub started_at_monotonic_ms: u64,
    pub stdout: Mutex<Spill>,
    pub stderr: Mutex<Spill>,
    pub state: std::sync::Mutex<OpState>,
    /// Bumped on every append and on terminal; pollers wait on it.
    pub version: watch::Sender<u64>,
}

#[derive(Default)]
pub struct OpState {
    pub terminal: Option<TerminalInfo>,
    /// Process group of the child (== its pid, we setsid). None for in-process tools.
    pub pgid: Option<i32>,
    pub cancel_requested: bool,
    pub deadline_hit: bool,
    pub released: bool,
}

impl Operation {
    pub fn is_terminal(&self) -> bool {
        self.state.lock().unwrap().terminal.is_some()
    }

    pub fn bump(&self) {
        self.version.send_modify(|v| *v += 1);
    }

    /// Records the terminal state once; later calls are ignored (first writer wins).
    pub fn set_terminal(&self, info: TerminalInfo) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.terminal.is_some() {
            return false;
        }
        st.terminal = Some(info);
        drop(st);
        self.bump();
        true
    }

    pub fn terminal_info(
        &self,
        outcome: Outcome,
        exit_code: Option<i64>,
        signal: Option<String>,
        output: Option<Value>,
        error: Option<AbiError>,
    ) -> TerminalInfo {
        let now = crate::hand::monotonic_ms();
        TerminalInfo {
            outcome,
            exit_code,
            signal,
            output,
            error,
            ended_at_monotonic_ms: brain_protocol::abi::MonotonicMs(now),
            usage: Usage {
                wall_ms: self.started_at.elapsed().as_millis() as u64,
                cpu_ms: None,
                max_rss_bytes: None,
            },
        }
    }

    pub async fn append(&self, stream: Stream, data: &[u8]) -> std::io::Result<()> {
        let r = match stream {
            Stream::Stdout => self.stdout.lock().await.append(data),
            Stream::Stderr => self.stderr.lock().await.append(data),
        };
        self.bump();
        r
    }

    pub async fn view(&self) -> OperationView {
        let (terminal, status) = {
            let st = self.state.lock().unwrap();
            match &st.terminal {
                Some(t) => (Some(t.clone()), OperationStatus::Terminal),
                None => (None, OperationStatus::Running),
            }
        };
        let is_terminal = terminal.is_some();
        let mut streams = Vec::with_capacity(2);
        for (stream, spill) in [
            (Stream::Stdout, &self.stdout),
            (Stream::Stderr, &self.stderr),
        ] {
            let s = spill.lock().await;
            streams.push(StreamInfo {
                stream,
                produced_bytes: s.produced(),
                retained_from: s.retained_from(),
                spill_path: s.spill_path().map(|p| p.to_string_lossy().into_owned()),
                sha256: if is_terminal { s.sha256() } else { None },
            });
        }
        OperationView {
            operation_id: self.id.clone(),
            tool: self.tool.clone(),
            lane_id: self.lane_id.clone(),
            detach: self.detach,
            status,
            started_at_monotonic_ms: brain_protocol::abi::MonotonicMs(self.started_at_monotonic_ms),
            terminal,
            streams,
            correlation: self.correlation.clone(),
        }
    }

    /// Slices from the given cursors, `max_total` decoded bytes across all of them and
    /// `max_per_stream` per stream.
    pub async fn slices(
        &self,
        cursors: &[(Stream, u64)],
        max_total: u64,
        max_per_stream: u64,
    ) -> Result<Vec<OutputSlice>, AbiError> {
        let mut out = Vec::new();
        let mut budget = max_total;
        for (stream, offset) in cursors {
            if budget == 0 {
                break;
            }
            let want = budget.min(max_per_stream) as usize;
            let mut spill = match stream {
                Stream::Stdout => self.stdout.lock().await,
                Stream::Stderr => self.stderr.lock().await,
            };
            match spill.read(*offset, want) {
                Ok((bytes, eof)) => {
                    budget -= bytes.len() as u64;
                    out.push(OutputSlice {
                        stream: *stream,
                        offset: *offset,
                        data_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                        eof,
                    });
                }
                Err(ReadError::Evicted {
                    offset,
                    retained_from,
                }) => {
                    let mut details = Map::new();
                    details.insert("stream".into(), serde_json::to_value(stream).unwrap());
                    details.insert("offset".into(), offset.into());
                    details.insert("retained_from".into(), retained_from.into());
                    return Err(crate::errors::err_with(
                        brain_protocol::abi::ErrorCode::OperationOutputEvicted,
                        format!(
                            "{stream:?} offset {offset} predates retained region (starts at {retained_from})"
                        ),
                        details,
                    ));
                }
                Err(ReadError::Io(e)) => return Err(crate::errors::internal(e)),
            }
        }
        Ok(out)
    }

    /// Waits until terminal, or until any cursor has bytes past its offset, or `wait` elapses.
    pub async fn wait_for(&self, cursors: &[(Stream, u64)], wait: std::time::Duration) {
        let deadline = tokio::time::Instant::now() + wait;
        let mut rx = self.version.subscribe();
        loop {
            if self.is_terminal() || self.has_bytes_past(cursors).await {
                return;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            let changed = tokio::time::timeout(remaining, rx.changed()).await;
            match changed {
                Ok(Ok(())) => continue,
                Ok(Err(_)) => return, // sender dropped: the op is gone
                Err(_) => return,     // timeout
            }
        }
    }

    async fn has_bytes_past(&self, cursors: &[(Stream, u64)]) -> bool {
        for (stream, offset) in cursors {
            let produced = match stream {
                Stream::Stdout => self.stdout.lock().await.produced(),
                Stream::Stderr => self.stderr.lock().await.produced(),
            };
            if produced > *offset {
                return true;
            }
        }
        false
    }

    /// Sends a signal to the child's process group. No-op for in-process tools.
    pub fn signal(&self, sig: i32) {
        let pgid = self.state.lock().unwrap().pgid;
        if let Some(pgid) = pgid {
            // SAFETY: plain libc call; a stale pgid can only target our own former child group.
            unsafe {
                libc::kill(-pgid, sig);
            }
        }
    }

    pub async fn remove_spill(&self) {
        self.stdout.lock().await.remove();
        self.stderr.lock().await.remove();
    }
}

#[derive(Default)]
pub struct Registry {
    ops: HashMap<String, Arc<Operation>>,
}

impl Registry {
    pub fn get(&self, id: &str) -> Option<Arc<Operation>> {
        self.ops.get(id).cloned()
    }
    pub fn insert(&mut self, op: Arc<Operation>) {
        self.ops.insert(op.id.to_string(), op);
    }
    pub fn remove(&mut self, id: &str) -> Option<Arc<Operation>> {
        self.ops.remove(id)
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn all(&self) -> Vec<Arc<Operation>> {
        let mut v: Vec<_> = self.ops.values().cloned().collect();
        v.sort_by_key(|o| o.started_at_monotonic_ms);
        v
    }
    pub fn running(&self) -> impl Iterator<Item = &Arc<Operation>> {
        self.ops.values().filter(|o| !o.is_terminal())
    }
}
