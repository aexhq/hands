//! `hand_status`: the idle signal. Emitted on every idle/busy transition, when a job ends, and
//! every `heartbeat_ms`. Also carries advisory memory pressure from /proc.

use std::sync::atomic::{AtomicU64, Ordering};

use brain_protocol::abi::{HandStatusEvent, Pressure};
use tokio::sync::broadcast;

pub struct StatusEmitter {
    seq: AtomicU64,
    tx: broadcast::Sender<HandStatusEvent>,
}

impl Default for StatusEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusEmitter {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            seq: AtomicU64::new(0),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HandStatusEvent> {
        self.tx.subscribe()
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn publish(&self, ev: HandStatusEvent) {
        let _ = self.tx.send(ev);
    }
}

/// Reads /proc/meminfo and /proc/pressure/memory. `None` where the kernel does not expose them.
pub fn read_pressure() -> Option<Pressure> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut avail = None;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    for line in meminfo.lines() {
        let mut it = line.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            continue;
        };
        let kb: u64 = v.parse().unwrap_or(0);
        match k {
            "MemAvailable:" => avail = Some(kb * 1024),
            "SwapTotal:" => swap_total = kb * 1024,
            "SwapFree:" => swap_free = kb * 1024,
            _ => {}
        }
    }
    let psi = std::fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("some")).and_then(|l| {
                l.split_whitespace()
                    .find_map(|kv| kv.strip_prefix("avg10="))
                    .and_then(|v| v.parse::<f64>().ok())
            })
        });
    Some(Pressure {
        mem_available_bytes: avail?,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
        psi_some_avg10: psi,
    })
}
