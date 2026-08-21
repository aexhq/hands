//! One lazy default sandbox per root tree plus an explicit additional-sandbox inventory.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connector::ConnectorClass;

pub const DEFAULT_TARGET_ID: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Default,
    Additional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRecord {
    pub target_id: String,
    pub kind: TargetKind,
    pub connector: ConnectorClass,
    pub generation: u64,
    pub state: TargetState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum TargetState {
    Unmaterialized,
    Materializing {
        reservation_id: String,
        fresh_after_loss: bool,
    },
    Running {
        physical_id: String,
    },
    Suspended {
        physical_id: String,
    },
    Gone {
        previous_physical_id: Option<String>,
        reason: String,
        observed_at_ms: u64,
    },
    Terminating {
        physical_id: String,
    },
    Terminated {
        previous_physical_id: Option<String>,
        observed_at_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginMaterialization {
    Reserved {
        generation: u64,
        fresh_after_loss: bool,
    },
    InProgress {
        generation: u64,
    },
    AlreadyMaterialized {
        generation: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupTarget {
    pub target_id: String,
    pub generation: u64,
    pub physical_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Serializable Hand-owned target mapping for one root session tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInventory {
    root_id: String,
    default: TargetRecord,
    additional: BTreeMap<String, TargetRecord>,
    max_additional: usize,
}

impl TargetInventory {
    pub fn new(
        root_id: impl Into<String>,
        connector: ConnectorClass,
        max_additional: usize,
    ) -> Result<Self, TargetError> {
        let root_id = root_id.into();
        validate_id(&root_id)?;
        Ok(Self {
            root_id,
            default: TargetRecord {
                target_id: DEFAULT_TARGET_ID.into(),
                kind: TargetKind::Default,
                connector,
                generation: 0,
                state: TargetState::Unmaterialized,
            },
            additional: BTreeMap::new(),
            max_additional,
        })
    }

    #[must_use]
    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    #[must_use]
    pub fn default(&self) -> &TargetRecord {
        &self.default
    }

    pub fn create_additional(
        &mut self,
        target_id: impl Into<String>,
        connector: ConnectorClass,
    ) -> Result<&TargetRecord, TargetError> {
        let target_id = target_id.into();
        validate_id(&target_id)?;
        if target_id == DEFAULT_TARGET_ID {
            return Err(TargetError::ReservedId);
        }
        if self.additional.contains_key(&target_id) {
            let existing = self.additional.get(&target_id).expect("contains key");
            if existing.connector != connector {
                return Err(TargetError::ConnectorConflict);
            }
            return Ok(existing);
        }
        if self.additional.len() >= self.max_additional {
            return Err(TargetError::QuotaExceeded);
        }
        self.additional.insert(
            target_id.clone(),
            TargetRecord {
                target_id: target_id.clone(),
                kind: TargetKind::Additional,
                connector,
                generation: 0,
                state: TargetState::Unmaterialized,
            },
        );
        Ok(self.additional.get(&target_id).expect("just inserted"))
    }

    pub fn begin_default_materialization(
        &mut self,
        reservation_id: &str,
    ) -> Result<BeginMaterialization, TargetError> {
        begin_materialization(&mut self.default, reservation_id, true)
    }

    pub fn begin_additional_materialization(
        &mut self,
        target_id: &str,
        reservation_id: &str,
    ) -> Result<BeginMaterialization, TargetError> {
        let record = self
            .additional
            .get_mut(target_id)
            .ok_or(TargetError::UnknownTarget)?;
        begin_materialization(record, reservation_id, false)
    }

    pub fn commit_materialization(
        &mut self,
        target_id: &str,
        reservation_id: &str,
        physical_id: impl Into<String>,
    ) -> Result<u64, TargetError> {
        let physical_id = physical_id.into();
        validate_id(&physical_id)?;
        let record = self.get_mut(target_id)?;
        match &record.state {
            TargetState::Materializing {
                reservation_id: expected,
                ..
            } if expected == reservation_id => {
                record.state = TargetState::Running { physical_id };
                Ok(record.generation)
            }
            TargetState::Materializing { .. } => Err(TargetError::ReservationConflict),
            TargetState::Running {
                physical_id: existing,
            } if existing == &physical_id => Ok(record.generation),
            _ => Err(TargetError::InvalidTransition),
        }
    }

    /// A known failed launch creates no physical target and can be retried. Unknown outcomes stay
    /// `materializing` until the caller reconciles the provider by its idempotency identity.
    pub fn abort_materialization(
        &mut self,
        target_id: &str,
        reservation_id: &str,
    ) -> Result<(), TargetError> {
        let record = self.get_mut(target_id)?;
        match &record.state {
            TargetState::Materializing {
                reservation_id: expected,
                fresh_after_loss,
            } if expected == reservation_id => {
                record.state = if *fresh_after_loss {
                    TargetState::Gone {
                        previous_physical_id: None,
                        reason: "replacement materialization failed".into(),
                        observed_at_ms: 0,
                    }
                } else {
                    TargetState::Unmaterialized
                };
                Ok(())
            }
            TargetState::Materializing { .. } => Err(TargetError::ReservationConflict),
            _ => Err(TargetError::InvalidTransition),
        }
    }

    pub fn mark_suspended(&mut self, target_id: &str) -> Result<(), TargetError> {
        let record = self.get_mut(target_id)?;
        match std::mem::replace(&mut record.state, TargetState::Unmaterialized) {
            TargetState::Running { physical_id } | TargetState::Suspended { physical_id } => {
                record.state = TargetState::Suspended { physical_id };
                Ok(())
            }
            state => {
                record.state = state;
                Err(TargetError::InvalidTransition)
            }
        }
    }

    pub fn mark_running(&mut self, target_id: &str) -> Result<(), TargetError> {
        let record = self.get_mut(target_id)?;
        match std::mem::replace(&mut record.state, TargetState::Unmaterialized) {
            TargetState::Suspended { physical_id } | TargetState::Running { physical_id } => {
                record.state = TargetState::Running { physical_id };
                Ok(())
            }
            state => {
                record.state = state;
                Err(TargetError::InvalidTransition)
            }
        }
    }

    pub fn mark_gone(
        &mut self,
        target_id: &str,
        reason: impl Into<String>,
        observed_at_ms: u64,
    ) -> Result<(), TargetError> {
        let record = self.get_mut(target_id)?;
        let physical_id = match &record.state {
            TargetState::Running { physical_id }
            | TargetState::Suspended { physical_id }
            | TargetState::Terminating { physical_id } => Some(physical_id.clone()),
            TargetState::Gone {
                previous_physical_id,
                ..
            }
            | TargetState::Terminated {
                previous_physical_id,
                ..
            } => previous_physical_id.clone(),
            TargetState::Unmaterialized | TargetState::Materializing { .. } => None,
        };
        record.state = TargetState::Gone {
            previous_physical_id: physical_id,
            reason: reason.into(),
            observed_at_ms,
        };
        Ok(())
    }

    /// Enforces live-file generation semantics without materializing or restoring anything.
    pub fn guard_live_files(
        &self,
        target_id: &str,
        expected_generation: Option<u64>,
    ) -> Result<&TargetRecord, LiveFilesError> {
        let record = self.get(target_id).ok_or(LiveFilesError::UnknownTarget)?;
        if let Some(expected) = expected_generation
            && expected != record.generation
        {
            return Err(LiveFilesError::Gone {
                generation: expected,
                reason: format!("current generation is {}", record.generation),
            });
        }
        match &record.state {
            TargetState::Unmaterialized | TargetState::Materializing { .. }
                if record.generation == 0 =>
            {
                Err(LiveFilesError::NotMaterialized)
            }
            TargetState::Running { .. } | TargetState::Suspended { .. } => Ok(record),
            TargetState::Unmaterialized
            | TargetState::Materializing { .. }
            | TargetState::Gone { .. }
            | TargetState::Terminating { .. }
            | TargetState::Terminated { .. } => Err(LiveFilesError::Gone {
                generation: record.generation,
                reason: state_reason(&record.state),
            }),
        }
    }

    pub fn begin_termination(&mut self, target_id: &str) -> Result<Option<String>, TargetError> {
        let record = self.get_mut(target_id)?;
        match std::mem::replace(&mut record.state, TargetState::Unmaterialized) {
            TargetState::Running { physical_id } | TargetState::Suspended { physical_id } => {
                record.state = TargetState::Terminating {
                    physical_id: physical_id.clone(),
                };
                Ok(Some(physical_id))
            }
            TargetState::Terminating { physical_id } => {
                record.state = TargetState::Terminating {
                    physical_id: physical_id.clone(),
                };
                Ok(Some(physical_id))
            }
            TargetState::Unmaterialized => {
                record.state = TargetState::Terminated {
                    previous_physical_id: None,
                    observed_at_ms: 0,
                };
                Ok(None)
            }
            TargetState::Gone {
                previous_physical_id,
                ..
            }
            | TargetState::Terminated {
                previous_physical_id,
                ..
            } => {
                record.state = TargetState::Terminated {
                    previous_physical_id,
                    observed_at_ms: 0,
                };
                Ok(None)
            }
            state @ TargetState::Materializing { .. } => {
                record.state = state;
                Err(TargetError::MaterializationInProgress)
            }
        }
    }

    pub fn confirm_terminated(
        &mut self,
        target_id: &str,
        observed_at_ms: u64,
    ) -> Result<(), TargetError> {
        let record = self.get_mut(target_id)?;
        let previous_physical_id = match &record.state {
            TargetState::Terminating { physical_id } => Some(physical_id.clone()),
            TargetState::Terminated {
                previous_physical_id,
                ..
            }
            | TargetState::Gone {
                previous_physical_id,
                ..
            } => previous_physical_id.clone(),
            _ => return Err(TargetError::InvalidTransition),
        };
        record.state = TargetState::Terminated {
            previous_physical_id,
            observed_at_ms,
        };
        Ok(())
    }

    #[must_use]
    pub fn list_additional(&self, cursor: Option<&str>, limit: usize) -> Page<TargetRecord> {
        let limit = limit.clamp(1, 100);
        let mut iter = self
            .additional
            .range(cursor.unwrap_or("").to_owned()..)
            .filter(|(key, _)| cursor != Some(key.as_str()));
        let items: Vec<_> = iter
            .by_ref()
            .take(limit + 1)
            .map(|(_, value)| value.clone())
            .collect();
        page(items, limit)
    }

    /// Returns at most `limit` physical resources requiring provider termination.
    #[must_use]
    pub fn cleanup_page(&self, cursor: Option<&str>, limit: usize) -> Page<CleanupTarget> {
        let limit = limit.clamp(1, 100);
        let all = std::iter::once((&self.default.target_id, &self.default))
            .chain(self.additional.iter())
            .filter(|(key, _)| cursor.is_none_or(|cursor| key.as_str() > cursor))
            .filter_map(|(_, record)| {
                let physical_id = match &record.state {
                    TargetState::Running { physical_id }
                    | TargetState::Suspended { physical_id }
                    | TargetState::Terminating { physical_id } => physical_id.clone(),
                    _ => return None,
                };
                Some(CleanupTarget {
                    target_id: record.target_id.clone(),
                    generation: record.generation,
                    physical_id,
                })
            })
            .take(limit + 1)
            .collect();
        page(all, limit)
    }

    fn get(&self, target_id: &str) -> Option<&TargetRecord> {
        if target_id == DEFAULT_TARGET_ID {
            Some(&self.default)
        } else {
            self.additional.get(target_id)
        }
    }

    fn get_mut(&mut self, target_id: &str) -> Result<&mut TargetRecord, TargetError> {
        if target_id == DEFAULT_TARGET_ID {
            Ok(&mut self.default)
        } else {
            self.additional
                .get_mut(target_id)
                .ok_or(TargetError::UnknownTarget)
        }
    }
}

fn begin_materialization(
    record: &mut TargetRecord,
    reservation_id: &str,
    allow_replacement: bool,
) -> Result<BeginMaterialization, TargetError> {
    validate_id(reservation_id)?;
    match &record.state {
        TargetState::Unmaterialized if record.generation == 0 => {
            record.generation = 1;
            record.state = TargetState::Materializing {
                reservation_id: reservation_id.into(),
                fresh_after_loss: false,
            };
            Ok(BeginMaterialization::Reserved {
                generation: record.generation,
                fresh_after_loss: false,
            })
        }
        TargetState::Materializing { .. } => Ok(BeginMaterialization::InProgress {
            generation: record.generation,
        }),
        TargetState::Running { .. } | TargetState::Suspended { .. } => {
            Ok(BeginMaterialization::AlreadyMaterialized {
                generation: record.generation,
            })
        }
        TargetState::Gone { .. } | TargetState::Terminated { .. } if allow_replacement => {
            record.generation = record.generation.saturating_add(1);
            record.state = TargetState::Materializing {
                reservation_id: reservation_id.into(),
                fresh_after_loss: true,
            };
            Ok(BeginMaterialization::Reserved {
                generation: record.generation,
                fresh_after_loss: true,
            })
        }
        TargetState::Gone { .. }
        | TargetState::Terminated { .. }
        | TargetState::Terminating { .. } => Err(TargetError::Gone),
        TargetState::Unmaterialized => Err(TargetError::InvalidTransition),
    }
}

fn state_reason(state: &TargetState) -> String {
    match state {
        TargetState::Gone { reason, .. } => reason.clone(),
        TargetState::Terminating { .. } => "sandbox is terminating".into(),
        TargetState::Terminated { .. } => "sandbox was terminated".into(),
        TargetState::Materializing { .. } => "replacement generation is materializing".into(),
        TargetState::Unmaterialized => "generation is unavailable".into(),
        TargetState::Running { .. } | TargetState::Suspended { .. } => "generation changed".into(),
    }
}

fn page<T>(mut items: Vec<T>, limit: usize) -> Page<T>
where
    T: PageIdentity,
{
    let next_cursor = (items.len() > limit).then(|| items[limit - 1].page_identity().to_owned());
    items.truncate(limit);
    Page { items, next_cursor }
}

trait PageIdentity {
    fn page_identity(&self) -> &str;
}

impl PageIdentity for TargetRecord {
    fn page_identity(&self) -> &str {
        &self.target_id
    }
}

impl PageIdentity for CleanupTarget {
    fn page_identity(&self) -> &str {
        &self.target_id
    }
}

fn validate_id(value: &str) -> Result<(), TargetError> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(TargetError::InvalidId);
    };
    if value.len() > 128
        || !value.is_ascii()
        || !first.is_ascii_alphanumeric()
        || chars.any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-')))
    {
        return Err(TargetError::InvalidId);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    #[error("target identity does not satisfy the canonical Hand identifier grammar")]
    InvalidId,
    #[error("default is a reserved target id")]
    ReservedId,
    #[error("target is already sealed to a different connector class")]
    ConnectorConflict,
    #[error("additional sandbox quota is exhausted")]
    QuotaExceeded,
    #[error("target is unknown")]
    UnknownTarget,
    #[error("target materialization reservation conflicts")]
    ReservationConflict,
    #[error("target materialization is still in progress")]
    MaterializationInProgress,
    #[error("target is gone and cannot be rematerialized")]
    Gone,
    #[error("invalid target lifecycle transition")]
    InvalidTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiveFilesError {
    #[error("sandbox has never been materialized")]
    NotMaterialized,
    #[error("sandbox generation {generation} is gone: {reason}")]
    Gone { generation: u64, reason: String },
    #[error("sandbox target is unknown")]
    UnknownTarget,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> TargetInventory {
        TargetInventory::new("root-1", ConnectorClass::None, 2).unwrap()
    }

    #[test]
    fn default_is_lazy_and_concurrent_first_calls_share_one_reservation() {
        let mut inventory = inventory();
        assert_eq!(
            inventory.guard_live_files(DEFAULT_TARGET_ID, None),
            Err(LiveFilesError::NotMaterialized)
        );
        assert_eq!(
            inventory.begin_default_materialization("create-1"),
            Ok(BeginMaterialization::Reserved {
                generation: 1,
                fresh_after_loss: false
            })
        );
        assert_eq!(
            inventory.begin_default_materialization("create-2"),
            Ok(BeginMaterialization::InProgress { generation: 1 })
        );
        inventory
            .commit_materialization(DEFAULT_TARGET_ID, "create-1", "mvm-1")
            .unwrap();
        assert_eq!(
            inventory.begin_default_materialization("create-2"),
            Ok(BeginMaterialization::AlreadyMaterialized { generation: 1 })
        );
    }

    #[test]
    fn default_can_restart_fresh_but_old_generation_file_access_is_gone() {
        let mut inventory = inventory();
        inventory.begin_default_materialization("create-1").unwrap();
        inventory
            .commit_materialization(DEFAULT_TARGET_ID, "create-1", "mvm-1")
            .unwrap();
        inventory
            .mark_gone(DEFAULT_TARGET_ID, "platform lifetime expired", 42)
            .unwrap();
        assert!(matches!(
            inventory.guard_live_files(DEFAULT_TARGET_ID, Some(1)),
            Err(LiveFilesError::Gone { generation: 1, .. })
        ));
        assert_eq!(
            inventory.begin_default_materialization("create-2"),
            Ok(BeginMaterialization::Reserved {
                generation: 2,
                fresh_after_loss: true
            })
        );
        inventory
            .commit_materialization(DEFAULT_TARGET_ID, "create-2", "mvm-2")
            .unwrap();
        assert!(matches!(
            inventory.guard_live_files(DEFAULT_TARGET_ID, Some(1)),
            Err(LiveFilesError::Gone { generation: 1, .. })
        ));
        assert!(
            inventory
                .guard_live_files(DEFAULT_TARGET_ID, Some(2))
                .is_ok()
        );
    }

    #[test]
    fn additional_targets_are_explicit_bounded_and_never_rematerialize() {
        let mut inventory = inventory();
        inventory
            .create_additional("extra-a", ConnectorClass::None)
            .unwrap();
        inventory
            .create_additional("extra-b", ConnectorClass::Allowlist)
            .unwrap();
        assert_eq!(
            inventory.create_additional("extra-c", ConnectorClass::None),
            Err(TargetError::QuotaExceeded)
        );
        inventory
            .begin_additional_materialization("extra-a", "create-a")
            .unwrap();
        inventory
            .commit_materialization("extra-a", "create-a", "mvm-a")
            .unwrap();
        inventory.mark_gone("extra-a", "lost", 4).unwrap();
        assert_eq!(
            inventory.begin_additional_materialization("extra-a", "create-again"),
            Err(TargetError::Gone)
        );
    }

    #[test]
    fn cleanup_and_list_are_bounded_and_cursor_stable() {
        let mut inventory = TargetInventory::new("root-1", ConnectorClass::None, 200).unwrap();
        inventory
            .begin_default_materialization("create-default")
            .unwrap();
        inventory
            .commit_materialization(DEFAULT_TARGET_ID, "create-default", "mvm-default")
            .unwrap();
        for n in 0..105 {
            let id = format!("extra-{n:03}");
            inventory
                .create_additional(&id, ConnectorClass::None)
                .unwrap();
            inventory
                .begin_additional_materialization(&id, &format!("create-{n:03}"))
                .unwrap();
            inventory
                .commit_materialization(&id, &format!("create-{n:03}"), format!("mvm-{n:03}"))
                .unwrap();
        }
        let first = inventory.list_additional(None, 1000);
        assert_eq!(first.items.len(), 100);
        assert_eq!(first.next_cursor.as_deref(), Some("extra-099"));
        let second = inventory.list_additional(first.next_cursor.as_deref(), 100);
        assert_eq!(second.items.len(), 5);
        assert!(second.next_cursor.is_none());

        let cleanup = inventory.cleanup_page(None, 10);
        assert_eq!(cleanup.items.len(), 10);
        assert!(cleanup.next_cursor.is_some());
    }

    #[test]
    fn serialized_inventory_keeps_generation_and_connector_fences() {
        let mut inventory = inventory();
        inventory.begin_default_materialization("create-1").unwrap();
        inventory
            .commit_materialization(DEFAULT_TARGET_ID, "create-1", "mvm-1")
            .unwrap();
        let bytes = serde_json::to_vec(&inventory).unwrap();
        let restored: TargetInventory = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.root_id(), "root-1");
        assert_eq!(restored.default().connector, ConnectorClass::None);
        assert_eq!(restored.default().generation, 1);
    }
}
