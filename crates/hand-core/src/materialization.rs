//! Durable target materialization before any guest effect is allowed to start.
//!
//! Brain has already committed the operation identity and digest when this state machine runs.
//! Hand only needs one durable routing record per physical target: after the record is installed,
//! retries reach the same guest and that guest atomically deduplicates `(operation_id, digest)`.
//! There is deliberately no per-operation database write on the ordinary execution path.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::connector::ConnectorClass;

pub const TARGET_KEY_PREFIX: &str = "target:";
pub const DEFAULT_TARGET_KEY: &str = "target:default";
pub use crate::page::MAX_PAGE as MAX_TARGET_PAGE;
/// A durable uncertainty lease can span the provider's full target lifetime, but callers waiting
/// on the worker that owns a normal launch must poll on a short bounded cadence. Exposing the
/// lease deadline as `retry_after_ms` would turn an ordinary first-call race into an eight-hour
/// outage even though the installed target is normally visible within seconds.
pub const MAX_MATERIALIZATION_POLL_MS: u64 = 1_000;

// The secret newtypes live in the vocabulary crate; this re-export keeps every consumer of the
// materialization contract on one import path.
pub use hand_policy::secret::{
    ControlToken, DurableLaunchRequest, MAX_DURABLE_LAUNCH_REQUEST_BYTES, SecretError,
};

impl From<SecretError> for MaterializationError {
    fn from(error: SecretError) -> Self {
        match error {
            SecretError::InvalidControlToken => MaterializationError::InvalidControlToken,
            SecretError::InvalidLaunchRequest => MaterializationError::InvalidLaunchRequest,
        }
    }
}

/// A logical target within one root session tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TargetKey {
    pub root_id: String,
    /// `target:default` or `target:additional:<sandbox_id>`.
    pub target_key: String,
}

impl TargetKey {
    pub fn default(root_id: impl Into<String>) -> Result<Self, MaterializationError> {
        let root_id = root_id.into();
        validate_identifier(&root_id, "root_id")?;
        Ok(Self {
            root_id,
            target_key: DEFAULT_TARGET_KEY.into(),
        })
    }

    pub fn additional(
        root_id: impl Into<String>,
        sandbox_id: impl Into<String>,
    ) -> Result<Self, MaterializationError> {
        let root_id = root_id.into();
        let sandbox_id = sandbox_id.into();
        validate_identifier(&root_id, "root_id")?;
        validate_identifier(&sandbox_id, "sandbox_id")?;
        Ok(Self {
            root_id,
            target_key: format!("target:additional:{sandbox_id}"),
        })
    }

    #[must_use]
    pub fn is_default(&self) -> bool {
        self.target_key == DEFAULT_TARGET_KEY
    }

    pub fn validate(&self) -> Result<(), MaterializationError> {
        validate_identifier(&self.root_id, "root_id")?;
        if self.is_default() {
            return Ok(());
        }
        validate_identifier(self.sandbox_identity()?, "sandbox_id")
    }

    /// Sandbox identity for capability minting and status projection: `"default"` for the
    /// default target, the sandbox id for additional targets. Fails on any other key shape
    /// instead of guessing.
    pub fn sandbox_identity(&self) -> Result<&str, MaterializationError> {
        if self.is_default() {
            return Ok("default");
        }
        self.target_key
            .strip_prefix("target:additional:")
            .ok_or(MaterializationError::InvalidIdentity("target_key"))
    }
}

/// Everything that must remain immutable for one physical generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub connector: ConnectorClass,
    /// Immutable image digest/version identity resolved by the trusted Hand process.
    pub image_identity: String,
    /// Plane-owned physical size/class. Tenant input never becomes a provider identifier.
    pub resource_class: String,
    /// Physical provider memory charged against the account/region materialization quota.
    pub materialized_mib: u64,
    /// Digest of the exact execution-resource ceiling sealed for this generation.
    pub resource_policy_digest: String,
    /// Digest of the exact network ceiling sealed for this generation. Connector class alone is
    /// insufficient because two allowlists can name different destinations.
    pub network_policy_digest: String,
}

impl TargetSpec {
    pub fn new(
        connector: ConnectorClass,
        image_identity: impl Into<String>,
        resource_class: impl Into<String>,
        materialized_mib: u64,
        resource_policy_digest: impl Into<String>,
        network_policy_digest: impl Into<String>,
    ) -> Result<Self, MaterializationError> {
        let image_identity = image_identity.into();
        let resource_class = resource_class.into();
        let resource_policy_digest = resource_policy_digest.into();
        let network_policy_digest = network_policy_digest.into();
        validate_bounded_token(&image_identity, "image_identity", 256)?;
        validate_identifier(&resource_class, "resource_class")?;
        if materialized_mib == 0 || materialized_mib > 1_048_576 {
            return Err(MaterializationError::InvalidCapacity);
        }
        validate_digest(&resource_policy_digest, "resource_policy_digest")?;
        validate_digest(&network_policy_digest, "network_policy_digest")?;
        Ok(Self {
            connector,
            image_identity,
            resource_class,
            materialized_mib,
            resource_policy_digest,
            network_policy_digest,
        })
    }

    /// Stable digest used by storage CAS expressions. This is an internal identity, not a fork of
    /// Brain's public contract digest. Canonical JSON (JCS) keeps the digest independent of
    /// struct field order.
    #[must_use]
    pub fn digest(&self) -> String {
        let encoded = serde_jcs::to_vec(self).expect("TargetSpec serialization is infallible");
        hex::encode(Sha256::digest(encoded))
    }
}

// Deliberately not serde-serializable: `recovery_attempt` has no safe deserialization default
// (a deserialized `false` would let recovery treat a possibly-dispatched launch as fresh), and
// leases are always rebuilt field-by-field from durable records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationLease {
    pub key: TargetKey,
    pub spec: TargetSpec,
    pub spec_digest: String,
    pub reservation_id: String,
    pub generation: String,
    pub launch_request: DurableLaunchRequest,
    /// Short ownership lease for one exact provider attempt. It is independent of the long
    /// uncertainty fence below: takeover retries the same client token and provider request.
    pub attempt_id: String,
    pub attempt_expires_at_ms: u64,
    /// Conservative provider hard deadline, measured from reservation before Run is dispatched.
    pub target_expires_at_ms: u64,
    pub lease_expires_at_ms: u64,
    /// Ephemeral attempt provenance. `false` means this worker installed the durable reservation
    /// before its first provider dispatch. `true` means a prior worker may already have
    /// dispatched the exact sealed provider request, so an error from the idempotent replay can
    /// never be used as proof that no physical target exists.
    pub recovery_attempt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledTarget {
    pub key: TargetKey,
    pub spec: TargetSpec,
    pub spec_digest: String,
    pub target_ref: String,
    pub generation: String,
    pub control_token: ControlToken,
    pub installed_at_ms: u64,
    pub expires_at_ms: u64,
}

impl InstalledTarget {
    pub fn validate(&self) -> Result<(), MaterializationError> {
        self.key.validate()?;
        validate_digest(&self.spec_digest, "spec_digest")?;
        if self.spec.digest() != self.spec_digest {
            return Err(MaterializationError::SpecConflict);
        }
        validate_identifier(&self.target_ref, "target_ref")?;
        validate_identifier(&self.generation, "generation")?;
        if self.expires_at_ms == 0 || self.expires_at_ms < self.installed_at_ms {
            return Err(MaterializationError::InvalidLease);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DurableTargetState {
    Materializing {
        reservation_id: String,
        launch_request: DurableLaunchRequest,
        attempt_id: String,
        attempt_expires_at_ms: u64,
        target_expires_at_ms: u64,
        lease_expires_at_ms: u64,
    },
    Installed {
        target_ref: String,
        control_token: ControlToken,
        installed_at_ms: u64,
        expires_at_ms: u64,
    },
    Gone {
        reason: String,
        gone_at_ms: u64,
    },
    Terminated {
        reason: String,
        terminated_at_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableTargetRecord {
    pub key: TargetKey,
    pub spec: TargetSpec,
    pub spec_digest: String,
    pub generation: String,
    pub state: DurableTargetState,
    pub updated_at_ms: u64,
}

impl DurableTargetRecord {
    pub fn validate(&self) -> Result<(), MaterializationError> {
        self.key.validate()?;
        validate_digest(&self.spec_digest, "spec_digest")?;
        if self.spec.digest() != self.spec_digest {
            return Err(MaterializationError::SpecConflict);
        }
        validate_identifier(&self.generation, "generation")?;
        match &self.state {
            DurableTargetState::Materializing {
                reservation_id,
                launch_request,
                attempt_id,
                attempt_expires_at_ms,
                target_expires_at_ms,
                lease_expires_at_ms,
            } => {
                validate_identifier(reservation_id, "reservation_id")?;
                launch_request.validate()?;
                validate_identifier(attempt_id, "attempt_id")?;
                if *target_expires_at_ms == 0
                    || *target_expires_at_ms >= *lease_expires_at_ms
                    || *target_expires_at_ms < self.updated_at_ms
                    || *attempt_expires_at_ms <= self.updated_at_ms
                    || *attempt_expires_at_ms > *lease_expires_at_ms
                {
                    return Err(MaterializationError::InvalidLease);
                }
                Ok(())
            }
            DurableTargetState::Installed {
                target_ref,
                installed_at_ms,
                expires_at_ms,
                ..
            } => {
                validate_identifier(target_ref, "target_ref")?;
                if *expires_at_ms == 0 || *expires_at_ms < *installed_at_ms {
                    return Err(MaterializationError::InvalidLease);
                }
                Ok(())
            }
            DurableTargetState::Gone { reason, .. }
            | DurableTargetState::Terminated { reason, .. } => validate_reason(reason),
        }
    }

    #[must_use]
    pub fn installed(&self) -> Option<InstalledTarget> {
        let DurableTargetState::Installed {
            target_ref,
            control_token,
            installed_at_ms,
            expires_at_ms,
        } = &self.state
        else {
            return None;
        };
        Some(InstalledTarget {
            key: self.key.clone(),
            spec: self.spec.clone(),
            spec_digest: self.spec_digest.clone(),
            target_ref: target_ref.clone(),
            generation: self.generation.clone(),
            control_token: control_token.clone(),
            installed_at_ms: *installed_at_ms,
            expires_at_ms: *expires_at_ms,
        })
    }

    /// Reconstructs the exact durable provider attempt for reconciliation. A lease obtained from
    /// a record is always a recovery attempt: even when this process has not called the provider,
    /// an earlier owner may have dispatched the same idempotency token before it crashed.
    pub fn recovery_lease(&self) -> Result<MaterializationLease, MaterializationError> {
        lease_from_materializing_record(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireTarget {
    pub key: TargetKey,
    pub spec: TargetSpec,
    pub reservation_id: String,
    pub generation: String,
    pub launch_request: DurableLaunchRequest,
    pub attempt_id: String,
    pub attempt_duration_ms: u64,
    /// Brain-minted create operations fence on this generation. Lazy managed execution lets Hand
    /// mint it and therefore accepts the already-installed generation on a retry.
    pub generation_is_fenced: bool,
    pub now_ms: u64,
    pub lease_duration_ms: u64,
    /// Maximum physical target lifetime. It must fit strictly inside the uncertainty lease.
    pub target_lifetime_ms: u64,
    /// Only the shared default target may get a fresh generation after confirmed loss.
    pub replace_after_loss: bool,
}

impl AcquireTarget {
    pub fn validate(&self) -> Result<(), MaterializationError> {
        self.key.validate()?;
        validate_identifier(&self.reservation_id, "reservation_id")?;
        validate_identifier(&self.generation, "generation")?;
        self.launch_request.validate()?;
        validate_identifier(&self.attempt_id, "attempt_id")?;
        if self.target_lifetime_ms == 0 || self.lease_duration_ms <= self.target_lifetime_ms {
            return Err(MaterializationError::InvalidLease);
        }
        if self.attempt_duration_ms == 0 || self.attempt_duration_ms >= self.lease_duration_ms {
            return Err(MaterializationError::InvalidLease);
        }
        if self.replace_after_loss && !self.key.is_default() {
            return Err(MaterializationError::InvalidReplacement);
        }
        Ok(())
    }

    pub fn lease(&self) -> Result<MaterializationLease, MaterializationError> {
        self.validate()?;
        let lease_expires_at_ms = self
            .now_ms
            .checked_add(self.lease_duration_ms)
            .ok_or(MaterializationError::InvalidLease)?;
        let target_expires_at_ms = self
            .now_ms
            .checked_add(self.target_lifetime_ms)
            .ok_or(MaterializationError::InvalidLease)?;
        let attempt_expires_at_ms = self
            .now_ms
            .checked_add(self.attempt_duration_ms)
            .ok_or(MaterializationError::InvalidLease)?;
        Ok(MaterializationLease {
            key: self.key.clone(),
            spec: self.spec.clone(),
            spec_digest: self.spec.digest(),
            reservation_id: self.reservation_id.clone(),
            generation: self.generation.clone(),
            launch_request: self.launch_request.clone(),
            attempt_id: self.attempt_id.clone(),
            attempt_expires_at_ms,
            target_expires_at_ms,
            lease_expires_at_ms,
            recovery_attempt: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireOutcome {
    Acquired(MaterializationLease),
    Pending {
        generation: String,
        retry_after_ms: u64,
    },
    Installed(InstalledTarget),
    Gone,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// This transition sits on first materialization only. Keeping the installed proof inline avoids a
// second allocation and makes the returned CAS evidence one owned value.
#[allow(clippy::large_enum_variant)]
pub enum InstallOutcome {
    Installed(InstalledTarget),
    ReservationLost,
}

pub type TargetPage = crate::page::Page<DurableTargetRecord>;

impl crate::page::PageIdentity for DurableTargetRecord {
    fn page_identity(&self) -> &str {
        &self.key.target_key
    }
}

/// Durable storage operations needed by target materialization.
#[async_trait]
pub trait DurableTargetRegistry: Send + Sync {
    async fn acquire(
        &self,
        request: &AcquireTarget,
    ) -> Result<AcquireOutcome, MaterializationError>;

    async fn install(
        &self,
        lease: &MaterializationLease,
        target: &PhysicalTarget,
        now_ms: u64,
    ) -> Result<InstallOutcome, MaterializationError>;

    async fn get(
        &self,
        key: &TargetKey,
    ) -> Result<Option<DurableTargetRecord>, MaterializationError>;

    /// Removes a known-no-effect failed launch attempt. Outcome-unknown launches retain the exact
    /// provider request and idempotency token so a later attempt can recover the same target.
    async fn expire_lease(
        &self,
        lease: &MaterializationLease,
        now_ms: u64,
    ) -> Result<(), MaterializationError>;

    async fn mark_gone(
        &self,
        target: &InstalledTarget,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), MaterializationError>;

    async fn mark_terminated(
        &self,
        target: &InstalledTarget,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), MaterializationError>;

    async fn list_root(
        &self,
        root_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<TargetPage, MaterializationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalTarget {
    pub target_ref: String,
    pub generation: String,
    pub control_token: ControlToken,
}

impl PhysicalTarget {
    pub fn new(
        target_ref: impl Into<String>,
        generation: impl Into<String>,
        control_token: ControlToken,
    ) -> Result<Self, MaterializationError> {
        let target_ref = target_ref.into();
        let generation = generation.into();
        validate_identifier(&target_ref, "target_ref")?;
        validate_identifier(&generation, "generation")?;
        Ok(Self {
            target_ref,
            generation,
            control_token,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchError {
    /// The provider rejected admission because this plane has no allocatable capacity/quota.
    /// No target was created, connector fallback is forbidden, and callers may surface the
    /// bounded retry hint without hiding the saturation signal.
    #[error("provider capacity exhausted ({scope}); retry after {retry_after_ms} ms: {message}")]
    Capacity {
        scope: String,
        retry_after_ms: u64,
        message: String,
    },
    /// The platform attested that no physical target was launched. The lease may be shortened safely.
    #[error("launch rejected before a target was created: {0}")]
    KnownNoTarget(String),
    /// A dependency failed before provider dispatch, so no target exists and capacity may be
    /// refunded, but the same exact materialization is safe to retry later.
    #[error("launch dependency unavailable before a target was created: {0}")]
    RetryableKnownNoTarget(String),
    /// The control call may have launched an idle target. The durable reservation remains charged;
    /// a later short attempt replays the exact provider request and idempotency token.
    #[error("launch outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

#[async_trait]
pub trait PhysicalTargetLauncher: Send + Sync {
    async fn launch(&self, lease: &MaterializationLease) -> Result<PhysicalTarget, LaunchError>;

    /// A worker that loses the install CAS must destroy a different target returned in violation
    /// of the provider idempotency contract. An exact replay normally returns the installed target.
    async fn terminate_stale(&self, target: &PhysicalTarget) -> Result<(), String>;
}

/// Coordinates one target launch. It only returns after physical routing is durably installed.
pub struct TargetMaterializer<R, L> {
    registry: R,
    launcher: L,
}

impl<R, L> TargetMaterializer<R, L> {
    pub const fn new(registry: R, launcher: L) -> Self {
        Self { registry, launcher }
    }

    #[must_use]
    pub const fn registry(&self) -> &R {
        &self.registry
    }
}

impl<R, L> TargetMaterializer<R, L>
where
    R: DurableTargetRegistry,
    L: PhysicalTargetLauncher,
{
    /// No caller may dispatch a guest effect until this returns `InstalledTarget`.
    pub async fn ensure(
        &self,
        request: &AcquireTarget,
    ) -> Result<InstalledTarget, MaterializationError> {
        let lease = match self.registry.acquire(request).await? {
            AcquireOutcome::Installed(target) => return Ok(target),
            AcquireOutcome::Acquired(lease) => lease,
            AcquireOutcome::Pending { retry_after_ms, .. } => {
                return Err(MaterializationError::Pending { retry_after_ms });
            }
            AcquireOutcome::Gone => return Err(MaterializationError::Gone),
            AcquireOutcome::Terminated => return Err(MaterializationError::Terminated),
        };

        let physical = match self.launcher.launch(&lease).await {
            Ok(target) => target,
            Err(LaunchError::Capacity {
                scope,
                retry_after_ms,
                message,
            }) => {
                if !lease.recovery_attempt {
                    self.registry.expire_lease(&lease, request.now_ms).await?;
                }
                return Err(MaterializationError::Capacity {
                    scope,
                    retry_after_ms,
                    message,
                });
            }
            Err(LaunchError::KnownNoTarget(message)) => {
                if lease.recovery_attempt {
                    return Err(MaterializationError::LaunchOutcomeUnknown(format!(
                        "exact launch recovery returned no target; reservation remains fenced: {message}"
                    )));
                }
                self.registry.expire_lease(&lease, request.now_ms).await?;
                return Err(MaterializationError::LaunchRejected(message));
            }
            Err(LaunchError::RetryableKnownNoTarget(message)) => {
                if !lease.recovery_attempt {
                    self.registry.expire_lease(&lease, request.now_ms).await?;
                }
                return Err(MaterializationError::LaunchRetryable(message));
            }
            Err(LaunchError::OutcomeUnknown(message)) => {
                return Err(MaterializationError::LaunchOutcomeUnknown(message));
            }
        };

        match self
            .registry
            .install(&lease, &physical, request.now_ms)
            .await?
        {
            InstallOutcome::Installed(target) => Ok(target),
            InstallOutcome::ReservationLost => {
                let cleanup = self.launcher.terminate_stale(&physical).await.err();
                Err(MaterializationError::ReservationLost { cleanup })
            }
        }
    }
}

/// In-memory conformance implementation. Production uses the DynamoDB implementation, while this
/// one makes every transition and crash point deterministic in tests.
#[derive(Debug)]
pub struct MemoryTargetRegistry {
    records: Mutex<BTreeMap<TargetKey, DurableTargetRecord>>,
    capacity: Mutex<MemoryCapacity>,
}

#[derive(Debug)]
struct MemoryCapacity {
    max_mib: u64,
    reserved_mib: u64,
}

impl Default for MemoryTargetRegistry {
    fn default() -> Self {
        Self::with_capacity(u64::MAX)
    }
}

impl MemoryTargetRegistry {
    #[must_use]
    pub fn with_capacity(max_mib: u64) -> Self {
        assert!(max_mib > 0);
        Self {
            records: Mutex::new(BTreeMap::new()),
            capacity: Mutex::new(MemoryCapacity {
                max_mib,
                reserved_mib: 0,
            }),
        }
    }

    fn reserve_capacity(&self, mib: u64) -> Result<(), MaterializationError> {
        let mut capacity = self.capacity.lock().map_err(|_| poisoned())?;
        if capacity.reserved_mib > capacity.max_mib.saturating_sub(mib) {
            return Err(MaterializationError::Capacity {
                scope: "plane_materialized_memory_mib".into(),
                retry_after_ms: 1_000,
                message: format!("{mib} MiB target exceeds remaining plane allocation"),
            });
        }
        capacity.reserved_mib += mib;
        Ok(())
    }

    fn refund_capacity(&self, mib: u64) -> Result<(), MaterializationError> {
        let mut capacity = self.capacity.lock().map_err(|_| poisoned())?;
        capacity.reserved_mib = capacity
            .reserved_mib
            .checked_sub(mib)
            .ok_or_else(|| MaterializationError::Corrupt("capacity counter underflow".into()))?;
        Ok(())
    }

    #[must_use]
    pub fn reserved_mib(&self) -> u64 {
        self.capacity.lock().expect("capacity lock").reserved_mib
    }
}

#[async_trait]
impl DurableTargetRegistry for MemoryTargetRegistry {
    async fn acquire(
        &self,
        request: &AcquireTarget,
    ) -> Result<AcquireOutcome, MaterializationError> {
        let lease = request.lease()?;
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let Some(record) = records.get_mut(&request.key) else {
            self.reserve_capacity(lease.spec.materialized_mib)?;
            records.insert(
                request.key.clone(),
                record_from_lease(&lease, request.now_ms),
            );
            return Ok(AcquireOutcome::Acquired(lease));
        };
        record.validate()?;
        if record.spec_digest != lease.spec_digest {
            return Err(MaterializationError::SpecConflict);
        }
        if request.generation_is_fenced
            && record.generation != lease.generation
            && !(request.replace_after_loss
                && matches!(&record.state, DurableTargetState::Gone { .. }))
        {
            return Err(MaterializationError::SpecConflict);
        }
        match record.state.clone() {
            DurableTargetState::Installed { .. } => Ok(AcquireOutcome::Installed(
                record.installed().expect("installed state projects"),
            )),
            DurableTargetState::Materializing {
                lease_expires_at_ms,
                ..
            } if lease_expires_at_ms <= request.now_ms => {
                // The provider's complete possible target lifetime plus skew has elapsed. The
                // old charged slot is now safe to reuse for a newly sealed exact request.
                *record = record_from_lease(&lease, request.now_ms);
                Ok(AcquireOutcome::Acquired(lease))
            }
            DurableTargetState::Materializing {
                target_expires_at_ms,
                lease_expires_at_ms,
                ..
            } if target_expires_at_ms <= request.now_ms => Ok(AcquireOutcome::Pending {
                generation: record.generation.clone(),
                retry_after_ms: materialization_poll_after(lease_expires_at_ms, request.now_ms),
            }),
            DurableTargetState::Materializing {
                attempt_expires_at_ms,
                ..
            } if attempt_expires_at_ms > request.now_ms => Ok(AcquireOutcome::Pending {
                generation: record.generation.clone(),
                retry_after_ms: materialization_poll_after(attempt_expires_at_ms, request.now_ms),
            }),
            DurableTargetState::Materializing { .. } => Ok(AcquireOutcome::Acquired(
                take_materialization_attempt(record, request)?,
            )),
            DurableTargetState::Gone { .. } if request.replace_after_loss => {
                self.reserve_capacity(lease.spec.materialized_mib)?;
                *record = record_from_lease(&lease, request.now_ms);
                Ok(AcquireOutcome::Acquired(lease))
            }
            DurableTargetState::Gone { .. } => Ok(AcquireOutcome::Gone),
            DurableTargetState::Terminated { .. } => Ok(AcquireOutcome::Terminated),
        }
    }

    async fn install(
        &self,
        lease: &MaterializationLease,
        target: &PhysicalTarget,
        now_ms: u64,
    ) -> Result<InstallOutcome, MaterializationError> {
        validate_identifier(&target.target_ref, "target_ref")?;
        validate_identifier(&target.generation, "generation")?;
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let Some(record) = records.get_mut(&lease.key) else {
            return Ok(InstallOutcome::ReservationLost);
        };
        if record.spec_digest != lease.spec_digest || record.generation != lease.generation {
            return Ok(InstallOutcome::ReservationLost);
        }
        match &record.state {
            DurableTargetState::Materializing { reservation_id, .. }
                if reservation_id == &lease.reservation_id =>
            {
                record.state = DurableTargetState::Installed {
                    target_ref: target.target_ref.clone(),
                    control_token: target.control_token.clone(),
                    installed_at_ms: now_ms,
                    expires_at_ms: lease.target_expires_at_ms,
                };
                record.generation = target.generation.clone();
                record.updated_at_ms = now_ms;
                Ok(InstallOutcome::Installed(
                    record.installed().expect("installed state projects"),
                ))
            }
            DurableTargetState::Installed {
                target_ref: existing,
                control_token,
                ..
            } if existing == &target.target_ref
                && control_token == &target.control_token
                && record.generation == target.generation =>
            {
                Ok(InstallOutcome::Installed(
                    record.installed().expect("installed state projects"),
                ))
            }
            _ => Ok(InstallOutcome::ReservationLost),
        }
    }

    async fn get(
        &self,
        key: &TargetKey,
    ) -> Result<Option<DurableTargetRecord>, MaterializationError> {
        key.validate()?;
        Ok(self
            .records
            .lock()
            .map_err(|_| poisoned())?
            .get(key)
            .cloned())
    }

    async fn expire_lease(
        &self,
        lease: &MaterializationLease,
        now_ms: u64,
    ) -> Result<(), MaterializationError> {
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let release = if let Some(record) = records.get(&lease.key)
            && record.generation == lease.generation
            && matches!(
                &record.state,
                DurableTargetState::Materializing {
                    reservation_id,
                    attempt_id,
                    ..
                } if reservation_id == &lease.reservation_id && attempt_id == &lease.attempt_id
            ) {
            true
        } else {
            false
        };
        if release {
            records.remove(&lease.key);
            self.refund_capacity(lease.spec.materialized_mib)?;
        }
        let _ = now_ms;
        Ok(())
    }

    async fn mark_gone(
        &self,
        target: &InstalledTarget,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), MaterializationError> {
        validate_reason(reason)?;
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let was_installed = records.get(&target.key).is_some_and(|record| {
            matches!(&record.state, DurableTargetState::Installed { target_ref, .. } if target_ref == &target.target_ref)
                && record.generation == target.generation
        });
        transition_installed(&mut records, target, |record| {
            record.state = DurableTargetState::Gone {
                reason: reason.into(),
                gone_at_ms: now_ms,
            };
            record.updated_at_ms = now_ms;
        })?;
        if was_installed {
            self.refund_capacity(target.spec.materialized_mib)?;
        }
        Ok(())
    }

    async fn mark_terminated(
        &self,
        target: &InstalledTarget,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), MaterializationError> {
        validate_reason(reason)?;
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let was_installed = records.get(&target.key).is_some_and(|record| {
            matches!(&record.state, DurableTargetState::Installed { target_ref, .. } if target_ref == &target.target_ref)
                && record.generation == target.generation
        });
        transition_installed(&mut records, target, |record| {
            record.state = DurableTargetState::Terminated {
                reason: reason.into(),
                terminated_at_ms: now_ms,
            };
            record.updated_at_ms = now_ms;
        })?;
        if was_installed {
            self.refund_capacity(target.spec.materialized_mib)?;
        }
        Ok(())
    }

    async fn list_root(
        &self,
        root_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<TargetPage, MaterializationError> {
        validate_identifier(root_id, "root_id")?;
        let limit = limit.clamp(1, MAX_TARGET_PAGE);
        let records = self.records.lock().map_err(|_| poisoned())?;
        let items: Vec<_> = records
            .values()
            .filter(|record| {
                record.key.root_id == root_id
                    && cursor.is_none_or(|cursor| record.key.target_key.as_str() > cursor)
            })
            .take(limit + 1)
            .cloned()
            .collect();
        Ok(crate::page::page(items, limit))
    }
}

fn record_from_lease(lease: &MaterializationLease, now_ms: u64) -> DurableTargetRecord {
    DurableTargetRecord {
        key: lease.key.clone(),
        spec: lease.spec.clone(),
        spec_digest: lease.spec_digest.clone(),
        generation: lease.generation.clone(),
        state: DurableTargetState::Materializing {
            reservation_id: lease.reservation_id.clone(),
            launch_request: lease.launch_request.clone(),
            attempt_id: lease.attempt_id.clone(),
            attempt_expires_at_ms: lease.attempt_expires_at_ms,
            target_expires_at_ms: lease.target_expires_at_ms,
            lease_expires_at_ms: lease.lease_expires_at_ms,
        },
        updated_at_ms: now_ms,
    }
}

fn lease_from_materializing_record(
    record: &DurableTargetRecord,
) -> Result<MaterializationLease, MaterializationError> {
    let DurableTargetState::Materializing {
        reservation_id,
        launch_request,
        attempt_id,
        attempt_expires_at_ms,
        target_expires_at_ms,
        lease_expires_at_ms,
    } = &record.state
    else {
        return Err(MaterializationError::Corrupt(
            "expected materializing target".into(),
        ));
    };
    Ok(MaterializationLease {
        key: record.key.clone(),
        spec: record.spec.clone(),
        spec_digest: record.spec_digest.clone(),
        reservation_id: reservation_id.clone(),
        generation: record.generation.clone(),
        launch_request: launch_request.clone(),
        attempt_id: attempt_id.clone(),
        attempt_expires_at_ms: *attempt_expires_at_ms,
        target_expires_at_ms: *target_expires_at_ms,
        lease_expires_at_ms: *lease_expires_at_ms,
        recovery_attempt: true,
    })
}

fn take_materialization_attempt(
    record: &mut DurableTargetRecord,
    request: &AcquireTarget,
) -> Result<MaterializationLease, MaterializationError> {
    let DurableTargetState::Materializing {
        attempt_id,
        attempt_expires_at_ms,
        lease_expires_at_ms,
        ..
    } = &mut record.state
    else {
        return Err(MaterializationError::Corrupt(
            "expected materializing target".into(),
        ));
    };
    *attempt_id = request.attempt_id.clone();
    *attempt_expires_at_ms = request
        .now_ms
        .checked_add(request.attempt_duration_ms)
        .ok_or(MaterializationError::InvalidLease)?
        .min(*lease_expires_at_ms);
    record.updated_at_ms = request.now_ms;
    record.validate()?;
    lease_from_materializing_record(record)
}

#[must_use]
pub fn materialization_poll_after(lease_expires_at_ms: u64, now_ms: u64) -> u64 {
    lease_expires_at_ms
        .saturating_sub(now_ms)
        .clamp(1, MAX_MATERIALIZATION_POLL_MS)
}

fn transition_installed(
    records: &mut BTreeMap<TargetKey, DurableTargetRecord>,
    target: &InstalledTarget,
    transition: impl FnOnce(&mut DurableTargetRecord),
) -> Result<(), MaterializationError> {
    let record = records
        .get_mut(&target.key)
        .ok_or(MaterializationError::ReservationLost { cleanup: None })?;
    match &record.state {
        DurableTargetState::Installed { target_ref, .. }
            if target_ref == &target.target_ref && record.generation == target.generation =>
        {
            transition(record);
            Ok(())
        }
        DurableTargetState::Gone { .. } | DurableTargetState::Terminated { .. } => Ok(()),
        _ => Err(MaterializationError::ReservationLost { cleanup: None }),
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), MaterializationError> {
    hand_policy::identity::validate_identifier(value, field)
        .map_err(|error| MaterializationError::InvalidIdentity(error.field))
}

fn validate_bounded_token(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), MaterializationError> {
    hand_policy::identity::validate_bounded_token(value, field, max)
        .map_err(|error| MaterializationError::InvalidIdentity(error.field))
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), MaterializationError> {
    hand_policy::identity::validate_digest(value, field)
        .map_err(|error| MaterializationError::InvalidIdentity(error.field))
}

fn validate_reason(reason: &str) -> Result<(), MaterializationError> {
    if reason.is_empty() || reason.len() > 512 {
        return Err(MaterializationError::InvalidIdentity("reason"));
    }
    Ok(())
}

fn poisoned() -> MaterializationError {
    MaterializationError::Storage("target registry lock is poisoned".into())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaterializationError {
    #[error("{0} does not satisfy the canonical Hand identifier grammar")]
    InvalidIdentity(&'static str),
    #[error("materialization lease must have a positive, representable duration")]
    InvalidLease,
    #[error("durable provider launch request is empty or exceeds its sealed byte bound")]
    InvalidLaunchRequest,
    #[error("generation control token is outside its exact secret boundary")]
    InvalidControlToken,
    #[error("only the default target may be replaced after confirmed loss")]
    InvalidReplacement,
    #[error("target materialized memory must be a positive bounded MiB value")]
    InvalidCapacity,
    #[error("target is sealed to a different connector, image, resource, or network policy")]
    SpecConflict,
    #[error("target materialization is in progress; retry after {retry_after_ms} ms")]
    Pending { retry_after_ms: u64 },
    #[error("target generation is gone")]
    Gone,
    #[error("target was explicitly terminated")]
    Terminated,
    #[error("provider capacity exhausted ({scope}); retry after {retry_after_ms} ms: {message}")]
    Capacity {
        scope: String,
        retry_after_ms: u64,
        message: String,
    },
    #[error("launch was rejected before target creation: {0}")]
    LaunchRejected(String),
    #[error("launch dependency failed before target creation: {0}")]
    LaunchRetryable(String),
    #[error("launch outcome is unknown; the lease is retained: {0}")]
    LaunchOutcomeUnknown(String),
    #[error("materialization reservation was lost; stale-target cleanup: {cleanup:?}")]
    ReservationLost { cleanup: Option<String> },
    #[error("durable target registry unavailable: {0}")]
    Storage(String),
    #[error("durable target registry contains an invalid record: {0}")]
    Corrupt(String),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct RejectingLauncher(LaunchError);

    #[async_trait]
    impl PhysicalTargetLauncher for RejectingLauncher {
        async fn launch(
            &self,
            _lease: &MaterializationLease,
        ) -> Result<PhysicalTarget, LaunchError> {
            Err(self.0.clone())
        }

        async fn terminate_stale(&self, _target: &PhysicalTarget) -> Result<(), String> {
            Ok(())
        }
    }

    fn target_spec(connector: ConnectorClass) -> TargetSpec {
        TargetSpec::new(
            connector,
            "image-digest-1",
            "microvm-1gb",
            1024,
            "a".repeat(64),
            "b".repeat(64),
        )
        .unwrap()
    }

    fn control_token() -> ControlToken {
        ControlToken::new(format!("control-{}", "a".repeat(64))).expect("test control token")
    }

    #[test]
    fn spec_digest_is_canonical_json_independent_of_field_order() {
        let spec = target_spec(ConnectorClass::None);
        let canonical = format!(
            "{{\"connector\":\"none\",\"image_identity\":\"image-digest-1\",\
             \"materialized_mib\":1024,\"network_policy_digest\":\"{}\",\
             \"resource_class\":\"microvm-1gb\",\"resource_policy_digest\":\"{}\"}}",
            "b".repeat(64),
            "a".repeat(64),
        );
        assert_eq!(spec.digest(), hex::encode(Sha256::digest(canonical)));
    }

    fn physical(target_ref: impl Into<String>, generation: impl Into<String>) -> PhysicalTarget {
        PhysicalTarget::new(target_ref, generation, control_token()).expect("test physical target")
    }

    fn request(now_ms: u64, reservation: &str, generation: &str) -> AcquireTarget {
        AcquireTarget {
            key: TargetKey::default("root-1").unwrap(),
            spec: target_spec(ConnectorClass::Allowlist),
            reservation_id: reservation.into(),
            generation: generation.into(),
            launch_request: DurableLaunchRequest::new(format!("launch-{reservation}")).unwrap(),
            attempt_id: format!("attempt-{reservation}"),
            attempt_duration_ms: 100,
            generation_is_fenced: false,
            now_ms,
            lease_duration_ms: 1_000,
            target_lifetime_ms: 900,
            replace_after_loss: true,
        }
    }

    #[tokio::test]
    async fn a_target_is_durable_before_effect_dispatch_and_reuses_without_a_write() {
        let registry = MemoryTargetRegistry::default();
        let first = request(1, "reservation-1", "generation-1");
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first call must acquire")
        };
        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(installed) = registry
            .install(&lease, &target, first.now_ms)
            .await
            .unwrap()
        else {
            panic!("lease must install")
        };
        // The adapter may only dispatch after it possesses this installed proof.
        assert_eq!(installed.target_ref, "mvm-1");
        assert_eq!(installed.generation, "guest-generation-1");

        let retry = request(2, "reservation-2", "generation-2");
        assert!(matches!(
            registry.acquire(&retry).await.unwrap(),
            AcquireOutcome::Installed(InstalledTarget { target_ref, .. }) if target_ref == "mvm-1"
        ));
    }

    #[tokio::test]
    async fn crash_after_run_before_install_retains_capacity_until_the_orphan_lifetime_ends() {
        let registry = MemoryTargetRegistry::with_capacity(1_024);
        let effects = AtomicUsize::new(0);

        let first = request(100, "reservation-old", "generation-old");
        let AcquireOutcome::Acquired(_old_lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        let orphan = physical("mvm-idle-orphan", "guest-generation-old");
        // Crash here: the provider launch returned, but no install CAS and therefore no code path has the
        // InstalledTarget proof accepted by the dispatcher.
        assert_eq!(effects.load(Ordering::SeqCst), 0);

        // Once the target's physical hard deadline has passed, retrying Run cannot recover a live
        // target. The target row and counter therefore remain charged through the conservative
        // uncertainty fence instead of reusing the slot for a possible second VM.
        let second = request(1_099, "reservation-new", "generation-new");
        assert!(matches!(
            registry.acquire(&second).await.unwrap(),
            AcquireOutcome::Pending { .. }
        ));
        assert_eq!(registry.reserved_mib(), 1_024);
        assert_eq!(effects.load(Ordering::SeqCst), 0);

        // Only once the configured possible-target lifetime has elapsed may the same charged slot
        // be reclaimed. Production sets that guard to the provider's 8h wall plus skew.
        let third = request(1_101, "reservation-new", "generation-new");
        let AcquireOutcome::Acquired(new_lease) = registry.acquire(&third).await.unwrap() else {
            panic!("guarded lease may be reclaimed only after its possible target lifetime")
        };
        let target = physical("mvm-routable", "guest-generation-new");
        let InstallOutcome::Installed(installed) = registry
            .install(&new_lease, &target, third.now_ms)
            .await
            .unwrap()
        else {
            panic!("replacement installs")
        };
        effects.fetch_add(1, Ordering::SeqCst);
        assert_eq!(installed.target_ref, "mvm-routable");
        assert_eq!(effects.load(Ordering::SeqCst), 1);
        assert_eq!(registry.reserved_mib(), 1_024);
        assert_eq!(orphan.target_ref, "mvm-idle-orphan");
    }

    #[tokio::test]
    async fn crash_after_provider_success_replays_one_exact_run_and_installs_one_target() {
        #[derive(Default)]
        struct IdempotentProvider {
            targets: Mutex<BTreeMap<String, (DurableLaunchRequest, PhysicalTarget)>>,
            creations: AtomicUsize,
        }

        impl IdempotentProvider {
            fn run(&self, lease: &MaterializationLease) -> PhysicalTarget {
                let mut targets = self.targets.lock().unwrap();
                if let Some((request, target)) = targets.get(&lease.reservation_id) {
                    assert_eq!(
                        request, &lease.launch_request,
                        "same token requires exact params"
                    );
                    return target.clone();
                }
                let target = PhysicalTarget::new(
                    format!("mvm-{}", self.creations.fetch_add(1, Ordering::SeqCst) + 1),
                    lease.generation.clone(),
                    control_token(),
                )
                .unwrap();
                targets.insert(
                    lease.reservation_id.clone(),
                    (lease.launch_request.clone(), target.clone()),
                );
                target
            }
        }

        let registry = MemoryTargetRegistry::with_capacity(1_024);
        let provider = IdempotentProvider::default();
        let first = request(1, "reservation-stable", "generation-stable");
        let AcquireOutcome::Acquired(first_lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        assert!(!first_lease.recovery_attempt);
        let first_target = provider.run(&first_lease);
        // Crash after the provider accepted the launch and returned the target, before the install CAS.

        let retry = request(102, "reservation-unused", "generation-unused");
        let AcquireOutcome::Acquired(recovery_lease) = registry.acquire(&retry).await.unwrap()
        else {
            panic!("expired attempt ownership is recoverable")
        };
        assert_eq!(recovery_lease.reservation_id, first_lease.reservation_id);
        assert_eq!(recovery_lease.generation, first_lease.generation);
        assert_eq!(recovery_lease.launch_request, first_lease.launch_request);
        assert_ne!(recovery_lease.attempt_id, first_lease.attempt_id);
        assert!(recovery_lease.recovery_attempt);

        let recovered_target = provider.run(&recovery_lease);
        assert_eq!(recovered_target, first_target);
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        let InstallOutcome::Installed(installed) = registry
            .install(&recovery_lease, &recovered_target, retry.now_ms)
            .await
            .unwrap()
        else {
            panic!("recovered exact target installs")
        };
        assert_eq!(installed.target_ref, first_target.target_ref);
        assert_eq!(registry.reserved_mib(), 1_024);
    }

    #[tokio::test]
    async fn initial_attested_no_target_refunds_capacity() {
        let materializer = TargetMaterializer::new(
            MemoryTargetRegistry::with_capacity(1_024),
            RejectingLauncher(LaunchError::KnownNoTarget(
                "provider rejected before admission".into(),
            )),
        );
        let request = request(1, "reservation-1", "generation-1");
        assert!(matches!(
            materializer.ensure(&request).await,
            Err(MaterializationError::LaunchRejected(_))
        ));
        assert_eq!(materializer.registry().reserved_mib(), 0);
        assert!(
            materializer
                .registry()
                .get(&request.key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn recovery_provider_errors_never_refund_a_possible_existing_target() {
        let failures = [
            LaunchError::Capacity {
                scope: "provider_account".into(),
                retry_after_ms: 1_000,
                message: "quota".into(),
            },
            LaunchError::KnownNoTarget("idempotent replay returned no target".into()),
            LaunchError::RetryableKnownNoTarget("provider throttled replay".into()),
            LaunchError::OutcomeUnknown("transport closed".into()),
        ];
        for (index, failure) in failures.into_iter().enumerate() {
            let materializer = TargetMaterializer::new(
                MemoryTargetRegistry::with_capacity(1_024),
                RejectingLauncher(failure),
            );
            let first = request(1, "reservation-stable", "generation-stable");
            let AcquireOutcome::Acquired(first_lease) =
                materializer.registry().acquire(&first).await.unwrap()
            else {
                panic!("first worker acquires")
            };
            assert!(!first_lease.recovery_attempt);

            let retry = request(102, "reservation-unused", "generation-unused");
            let error = materializer.ensure(&retry).await.unwrap_err();
            match index {
                0 => assert!(matches!(error, MaterializationError::Capacity { .. })),
                1 | 3 => assert!(matches!(
                    error,
                    MaterializationError::LaunchOutcomeUnknown(_)
                )),
                2 => assert!(matches!(error, MaterializationError::LaunchRetryable(_))),
                _ => unreachable!(),
            }
            let record = materializer
                .registry()
                .get(&first.key)
                .await
                .unwrap()
                .expect("recovery failure retains the exact target reservation");
            assert!(matches!(
                record.state,
                DurableTargetState::Materializing {
                    ref reservation_id,
                    ..
                } if reservation_id == &first_lease.reservation_id
            ));
            assert_eq!(materializer.registry().reserved_mib(), 1_024);
        }
    }

    #[tokio::test]
    async fn concurrent_first_call_uses_a_short_poll_without_shortening_the_safety_lease() {
        let registry = MemoryTargetRegistry::with_capacity(1_024);
        let mut first = request(1, "reservation-old", "generation-old");
        first.lease_duration_ms = 8 * 60 * 60 * 1_000 + 5 * 60 * 1_000;
        first.target_lifetime_ms = 8 * 60 * 60 * 1_000;
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };

        let mut retry = first.clone();
        retry.now_ms = 2;
        retry.reservation_id = "reservation-retry".into();
        retry.generation = "generation-retry".into();
        let AcquireOutcome::Pending { retry_after_ms, .. } =
            registry.acquire(&retry).await.unwrap()
        else {
            panic!("concurrent caller waits for the installed proof")
        };
        assert!((1..=MAX_MATERIALIZATION_POLL_MS).contains(&retry_after_ms));
        let record = registry.get(&first.key).await.unwrap().unwrap();
        assert!(matches!(
            record.state,
            DurableTargetState::Materializing {
                lease_expires_at_ms,
                ..
            } if lease_expires_at_ms == lease.lease_expires_at_ms
        ));
        assert_eq!(registry.reserved_mib(), 1_024);
    }

    #[tokio::test]
    async fn stale_worker_cannot_install_or_execute_after_lease_takeover() {
        let registry = MemoryTargetRegistry::default();
        let first = request(1, "reservation-old", "generation-old");
        let AcquireOutcome::Acquired(old) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        let second = request(1_002, "reservation-new", "generation-new");
        let AcquireOutcome::Acquired(new) = registry.acquire(&second).await.unwrap() else {
            panic!("second worker takes expired lease")
        };
        let stale_target = physical("mvm-stale", "guest-generation-stale");
        assert_eq!(
            registry
                .install(&old, &stale_target, second.now_ms)
                .await
                .unwrap(),
            InstallOutcome::ReservationLost
        );
        let current_target = physical("mvm-current", "guest-generation-current");
        assert!(matches!(
            registry
                .install(&new, &current_target, second.now_ms)
                .await
                .unwrap(),
            InstallOutcome::Installed(_)
        ));
    }

    #[tokio::test]
    async fn crash_after_effect_before_brain_receipt_dedupes_on_the_installed_guest() {
        let registry = MemoryTargetRegistry::default();
        let first = request(1, "reservation-1", "generation-1");
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(installed) = registry
            .install(&lease, &target, first.now_ms)
            .await
            .unwrap()
        else {
            panic!("target installs")
        };

        let mut guest = crate::operation::OperationRegistry::new(8, 4096);
        let first_reservation = guest.reserve("operation-1", &"a".repeat(64), 1024).unwrap();
        assert_eq!(first_reservation, crate::operation::Reservation::New);
        let effects = AtomicUsize::new(0);
        effects.fetch_add(1, Ordering::SeqCst);
        // Brain did not receive the receipt. It retries the durable intent against target_ref.
        let retry_reservation = guest.reserve("operation-1", &"a".repeat(64), 1024).unwrap();
        assert_eq!(retry_reservation, crate::operation::Reservation::Existing);
        assert_eq!(effects.load(Ordering::SeqCst), 1);
        assert_eq!(installed.target_ref, "mvm-1");
    }

    #[tokio::test]
    async fn conflicting_digest_is_permanent_and_never_reaches_the_effect_body() {
        let registry = MemoryTargetRegistry::default();
        let request = request(1, "reservation-1", "generation-1");
        let AcquireOutcome::Acquired(lease) = registry.acquire(&request).await.unwrap() else {
            panic!("first worker acquires")
        };
        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(_installed) = registry
            .install(&lease, &target, request.now_ms)
            .await
            .unwrap()
        else {
            panic!("target installs")
        };

        let mut guest = crate::operation::OperationRegistry::new(8, 4096);
        let effects = AtomicUsize::new(0);
        let dispatch = |guest: &mut crate::operation::OperationRegistry,
                        digest: &str|
         -> Result<
            crate::operation::Reservation,
            crate::operation::OperationError,
        > {
            let reservation = guest.reserve("operation-1", digest, 1024)?;
            if reservation == crate::operation::Reservation::New {
                effects.fetch_add(1, Ordering::SeqCst);
            }
            Ok(reservation)
        };
        assert_eq!(
            dispatch(&mut guest, &"a".repeat(64)),
            Ok(crate::operation::Reservation::New)
        );
        assert_eq!(
            dispatch(&mut guest, &"b".repeat(64)),
            Err(crate::operation::OperationError::IdempotencyConflict)
        );
        // A permanent conflict is answered at reservation; dispatch never invokes user code.
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_target_spec_is_a_permanent_conflict() {
        let registry = MemoryTargetRegistry::default();
        registry
            .acquire(&request(1, "reservation-1", "generation-1"))
            .await
            .unwrap();
        let mut conflict = request(2, "reservation-2", "generation-2");
        conflict.spec = target_spec(ConnectorClass::Public);
        assert_eq!(
            registry.acquire(&conflict).await,
            Err(MaterializationError::SpecConflict)
        );
    }

    #[tokio::test]
    async fn plane_capacity_is_reserved_atomically_and_refunded_once() {
        let registry = MemoryTargetRegistry::with_capacity(2_048);
        let mut first = request(1, "reservation-1", "generation-1");
        first.key = TargetKey::default("root-1").unwrap();
        let mut second = request(1, "reservation-2", "generation-2");
        second.key = TargetKey::default("root-2").unwrap();
        let mut third = request(1, "reservation-3", "generation-3");
        third.key = TargetKey::default("root-3").unwrap();
        let AcquireOutcome::Acquired(first_lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first target reserves")
        };
        assert!(matches!(
            registry.acquire(&second).await.unwrap(),
            AcquireOutcome::Acquired(_)
        ));
        assert_eq!(registry.reserved_mib(), 2_048);
        assert!(matches!(
            registry.acquire(&third).await,
            Err(MaterializationError::Capacity {
                retry_after_ms: 1_000,
                ..
            })
        ));

        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(installed) =
            registry.install(&first_lease, &target, 2).await.unwrap()
        else {
            panic!("first target installs")
        };
        registry
            .mark_terminated(&installed, "explicit cleanup", 3)
            .await
            .unwrap();
        // Idempotent terminal retry does not decrement twice.
        registry
            .mark_terminated(&installed, "explicit cleanup", 3)
            .await
            .unwrap();
        assert_eq!(registry.reserved_mib(), 1_024);
        assert!(matches!(
            registry.acquire(&third).await.unwrap(),
            AcquireOutcome::Acquired(_)
        ));
    }

    #[tokio::test]
    async fn scheduled_hard_deadline_reconciliation_reclaims_abandoned_capacity() {
        let registry = MemoryTargetRegistry::with_capacity(5 * 1_024);
        let mut installed_targets = Vec::new();
        for index in 0..5 {
            let mut target = request(
                1,
                &format!("reservation-{index}"),
                &format!("generation-{index}"),
            );
            target.key = TargetKey::default(format!("root-{index}")).unwrap();
            let AcquireOutcome::Acquired(lease) = registry.acquire(&target).await.unwrap() else {
                panic!("abandoned target reserves")
            };
            let physical = physical(format!("mvm-{index}"), format!("guest-generation-{index}"));
            let InstallOutcome::Installed(installed) = registry
                .install(&lease, &physical, target.now_ms)
                .await
                .unwrap()
            else {
                panic!("abandoned target installs")
            };
            assert_eq!(installed.expires_at_ms, 901);
            installed_targets.push(installed);
        }
        assert_eq!(registry.reserved_mib(), 5 * 1_024);

        // No customer request is needed. Brain journals each returned hard deadline and schedules
        // an exact target inspection/termination; each confirmed transition atomically refunds
        // its one capacity reservation while retaining the logical tombstone.
        for installed in &installed_targets {
            registry
                .mark_terminated(installed, "physical target hard deadline reached", 901)
                .await
                .unwrap();
        }
        assert_eq!(registry.reserved_mib(), 0);
        for installed in installed_targets {
            assert!(matches!(
                registry.get(&installed.key).await.unwrap().unwrap().state,
                DurableTargetState::Terminated { .. }
            ));
        }
    }

    #[tokio::test]
    async fn brain_minted_create_generation_is_an_exact_fence() {
        let registry = MemoryTargetRegistry::default();
        let mut first = request(1, "reservation-1", "generation-1");
        first.generation_is_fenced = true;
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first create reserves")
        };
        let target = physical("mvm-1", "generation-1");
        registry
            .install(&lease, &target, first.now_ms)
            .await
            .unwrap();

        let mut exact = first.clone();
        exact.now_ms = 2;
        exact.reservation_id = "reservation-exact-retry".into();
        assert!(matches!(
            registry.acquire(&exact).await.unwrap(),
            AcquireOutcome::Installed(_)
        ));

        let mut conflict = exact;
        conflict.generation = "generation-2".into();
        assert_eq!(
            registry.acquire(&conflict).await,
            Err(MaterializationError::SpecConflict)
        );
    }

    #[tokio::test]
    async fn confirmed_no_target_releases_the_exact_lease_and_capacity() {
        let registry = MemoryTargetRegistry::with_capacity(1_024);
        let first = request(1, "reservation-1", "generation-1");
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("target reserves")
        };
        assert_eq!(registry.reserved_mib(), 1_024);
        registry.expire_lease(&lease, 2).await.unwrap();
        registry.expire_lease(&lease, 3).await.unwrap();
        assert_eq!(registry.reserved_mib(), 0);
        assert!(registry.get(&first.key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn additional_target_never_rematerializes_after_loss() {
        let registry = MemoryTargetRegistry::default();
        let mut first = request(1, "reservation-1", "generation-1");
        first.key = TargetKey::additional("root-1", "sandbox-1").unwrap();
        first.replace_after_loss = false;
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(installed) = registry
            .install(&lease, &target, first.now_ms)
            .await
            .unwrap()
        else {
            panic!("target installs")
        };
        registry
            .mark_gone(&installed, "provider lifetime expired", 10)
            .await
            .unwrap();
        let mut retry = first.clone();
        retry.now_ms = 20;
        retry.reservation_id = "reservation-2".into();
        retry.generation = "generation-2".into();
        assert_eq!(
            registry.acquire(&retry).await.unwrap(),
            AcquireOutcome::Gone
        );
    }

    #[tokio::test]
    async fn terminated_additional_id_remains_fenced_until_explicit_root_purge() {
        let registry = MemoryTargetRegistry::default();
        let mut first = request(1, "reservation-1", "generation-1");
        first.key = TargetKey::additional("root-1", "sandbox-1").unwrap();
        first.replace_after_loss = false;
        let AcquireOutcome::Acquired(lease) = registry.acquire(&first).await.unwrap() else {
            panic!("first worker acquires")
        };
        let target = physical("mvm-1", "guest-generation-1");
        let InstallOutcome::Installed(installed) = registry
            .install(&lease, &target, first.now_ms)
            .await
            .unwrap()
        else {
            panic!("target installs")
        };
        registry
            .mark_terminated(&installed, "explicit lifecycle operation", 10)
            .await
            .unwrap();

        let mut retry = first;
        retry.now_ms = u64::MAX / 2;
        retry.reservation_id = "reservation-after-arbitrary-delay".into();
        retry.generation = "generation-after-arbitrary-delay".into();
        assert_eq!(
            registry.acquire(&retry).await.unwrap(),
            AcquireOutcome::Terminated
        );
    }

    #[test]
    fn identifiers_match_the_brain_contract_boundary() {
        assert!(TargetKey::default("A._:-9").is_ok());
        for invalid in ["", "-starts-wrong", "has space", "é", &"a".repeat(129)] {
            assert!(TargetKey::default(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn control_tokens_are_exact_and_never_debug_formatted() {
        let raw = format!("control-{}", "c".repeat(64));
        let token = ControlToken::new(raw.clone()).unwrap();
        assert_eq!(token.expose(), raw);
        assert_eq!(format!("{token:?}"), "ControlToken([redacted])");
        for invalid in [
            String::new(),
            format!("control-{}", "c".repeat(63)),
            format!("control-{}", "C".repeat(64)),
            format!("wrong-{}", "c".repeat(64)),
        ] {
            assert_eq!(
                ControlToken::new(invalid).unwrap_err(),
                SecretError::InvalidControlToken
            );
        }
    }
}
