//! Lanes: persistent shell environments. Lane "0" is the root and always exists.
//!
//! A lane carries environment variables. `cwd` is per call and never stored here. Persistent
//! lanes are created on first use and inherit the root lane's environment; ephemeral lanes are
//! forked from `parent`'s environment for one operation and discarded when it ends. An attached
//! operation holds its lane (`inflight`) until terminal.

use std::collections::HashMap;

use brain_protocol::abi::{
    ErrorCode, LaneId, LaneMode, LaneRef, LaneSummary, LaneSummaryState, MonotonicMs, OperationId,
};

use crate::errors::{AbiResult, err};

pub const ROOT_LANE: &str = "0";

#[derive(Debug, Clone)]
pub struct Lane {
    pub id: LaneId,
    pub mode: LaneMode,
    pub parent: Option<LaneId>,
    pub env: HashMap<String, String>,
    pub closed: bool,
    pub inflight: Option<OperationId>,
    pub created_at_monotonic_ms: u64,
}

pub struct Lanes {
    map: HashMap<String, Lane>,
    max_lanes: usize,
}

impl Lanes {
    pub fn new(root_env: HashMap<String, String>, max_lanes: usize, now_ms: u64) -> Self {
        let mut map = HashMap::new();
        map.insert(
            ROOT_LANE.to_string(),
            Lane {
                id: ROOT_LANE.parse().unwrap(),
                mode: LaneMode::Persistent,
                parent: None,
                env: root_env,
                closed: false,
                inflight: None,
                created_at_monotonic_ms: now_ms,
            },
        );
        Self { map, max_lanes }
    }

    pub fn live_count(&self) -> usize {
        self.map.values().filter(|l| !l.closed).count()
    }

    pub fn get(&self, id: &str) -> Option<&Lane> {
        self.map.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Lane> {
        self.map.get_mut(id)
    }

    /// Resolves the lane for a `start`, creating it if it is new. Returns the lane's env.
    pub fn resolve_for_start(&mut self, lane: &LaneRef, now_ms: u64) -> AbiResult<&mut Lane> {
        let key = lane.id.to_string();
        if let Some(existing) = self.map.get(&key) {
            if existing.closed {
                return Err(err(ErrorCode::LaneGone, format!("lane {key} was closed")));
            }
            if existing.mode != lane.mode {
                return Err(err(
                    ErrorCode::MalformedRequest,
                    format!(
                        "lane {key} exists with mode {:?}, request says {:?}",
                        existing.mode, lane.mode
                    ),
                ));
            }
            return Ok(self.map.get_mut(&key).expect("just checked"));
        }
        if self.live_count() >= self.max_lanes {
            return Err(err(
                ErrorCode::LaneLimitExceeded,
                format!("max_lanes = {}", self.max_lanes),
            ));
        }
        let env = match lane.mode {
            LaneMode::Persistent => self
                .map
                .get(ROOT_LANE)
                .map(|r| r.env.clone())
                .unwrap_or_default(),
            LaneMode::Ephemeral => {
                let parent = lane.parent.as_ref().ok_or_else(|| {
                    err(
                        ErrorCode::MalformedRequest,
                        "ephemeral lane requires parent",
                    )
                })?;
                let p = self
                    .map
                    .get(parent.as_str())
                    .filter(|p| !p.closed)
                    .ok_or_else(|| {
                        err(
                            ErrorCode::LaneGone,
                            format!("parent lane {} is gone", **parent),
                        )
                    })?;
                p.env.clone()
            }
        };
        self.map.insert(
            key.clone(),
            Lane {
                id: lane.id.clone(),
                mode: lane.mode,
                parent: lane.parent.clone(),
                env,
                closed: false,
                inflight: None,
                created_at_monotonic_ms: now_ms,
            },
        );
        Ok(self.map.get_mut(&key).expect("just inserted"))
    }

    /// Marks the operation as terminal for lane-keeping: frees `inflight`, applies a captured
    /// environment to a persistent lane, and drops an ephemeral lane entirely.
    pub fn on_operation_terminal(
        &mut self,
        lane_id: &str,
        op: &OperationId,
        captured_env: Option<HashMap<String, String>>,
    ) {
        let Some(lane) = self.map.get_mut(lane_id) else {
            return;
        };
        if lane.inflight.as_deref() == Some(&**op) {
            lane.inflight = None;
        }
        match lane.mode {
            LaneMode::Ephemeral => {
                self.map.remove(lane_id);
            }
            LaneMode::Persistent => {
                if let Some(env) = captured_env {
                    lane.env = env;
                }
            }
        }
    }

    /// Closes a lane (tombstone). Returns the attached operation that was in flight, if any, so
    /// the caller can cancel it. Lane 0 is not closable.
    pub fn close(&mut self, id: &str) -> AbiResult<(bool, Option<OperationId>)> {
        if id == ROOT_LANE {
            return Err(err(
                ErrorCode::LaneNotClosable,
                "lane 0 cannot be closed while the session lives",
            ));
        }
        match self.map.get_mut(id) {
            None => Err(err(
                ErrorCode::LaneGone,
                format!("lane {id} does not exist"),
            )),
            Some(l) if l.closed => Ok((false, None)),
            Some(l) => {
                l.closed = true;
                let inflight = l.inflight.take();
                l.env.clear();
                Ok((true, inflight))
            }
        }
    }

    pub fn summaries(&self) -> Vec<LaneSummary> {
        let mut v: Vec<LaneSummary> = self
            .map
            .values()
            .map(|l| LaneSummary {
                id: l.id.clone(),
                mode: l.mode,
                parent: l.parent.clone(),
                state: if l.closed {
                    LaneSummaryState::Closed
                } else {
                    LaneSummaryState::Live
                },
                inflight: l.inflight.clone(),
                created_at_monotonic_ms: Some(MonotonicMs(l.created_at_monotonic_ms)),
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }
}
