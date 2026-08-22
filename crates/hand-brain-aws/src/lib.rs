//! Production Aex-managed Hand implementation for AWS Lambda MicroVMs.
//!
//! Brain owns the public contract and commits operation intent before dispatch. This adapter owns
//! physical target routing only: a first target reservation and the plane memory counter are one
//! DynamoDB transaction, RunMicrovm remains effect-free, the target is durably installed before
//! any guest request, and established submit calls use Brain's projected `target_ref` without a
//! registry read or write. Observe/cancel/ack carry the exact rooted target and intentionally
//! reconcile that target row so a lost supervisor can be terminated and its capacity refunded.

pub mod client;
mod dynamo;
pub mod definitions;
pub mod registry;

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use brain::hand::{
    HandPort, HandResult, SandboxControlPort, SandboxFileContent, SandboxFileList,
    SandboxFileListRequest, SandboxFilesPort, SandboxSearchRequest, SecretDeliveryPort,
    SessionPreparationPort,
};
use brain_protocol::contract::{
    HAND_CONTRACT_DIGEST, canonical_digest, operation_request_digest, sandbox_copy_request_digest,
    sandbox_execution_request_digest, sandbox_file_write_request_digest,
    write_stdin_request_digest,
};
use brain_protocol::hand::{
    AcknowledgeTerminalRequest, Acknowledgement, BundleDescriptor, BundleFetch, BundleRuntime,
    CancelRequest, CancellationReceipt, CreateSandboxRequest, ExecutionRealm, FileEntry,
    HandCapability, HandError, HandErrorCode, NetworkCeiling, NetworkCeilingDestinationsItem,
    ObjectReference, ObjectTransferAuthority, ObjectTransferAuthorityMethod, ObserveRequest,
    OperationObservation, OperationRef, PrepareSessionRequest, PreparedBindingBundles,
    PreparedSession, RecoveryClass, ResolvedBinding, ResolvedBindingLimits, ResourceCeiling,
    SandboxCopyRequest, SandboxCopyRequestDirection, SandboxCopyResult, SandboxExecutionRequest,
    SandboxFileRequest, SandboxFileWriteRequest, SandboxFileWriteResult, SandboxFileWriteSource,
    SandboxState, SandboxStatus, SandboxTarget, SealedBinding, SecretDeliveryRequest,
    SubmitReceipt, SubmitRequest, TargetKind, WriteStdinReceipt, WriteStdinRequest,
};
use brain_protocol::network::network_ceiling_is_subset;
use futures_util::StreamExt as _;
use hand_core::connector::{ConnectorCatalog, ConnectorClass, GatewayAuthority};
use hand_core::materialization::{
    AcquireTarget, ControlToken, DurableLaunchRequest, DurableTargetRegistry, DurableTargetState,
    InstalledTarget, LaunchError, MaterializationError, MaterializationLease, PhysicalTarget,
    PhysicalTargetLauncher, TargetKey, TargetMaterializer, TargetSpec,
};
use hand_egress_gateway::{
    Capability, CapabilityDestination, DestinationProtocol, encode_signed_token,
    unsigned_capability_bytes,
};
use hand_lambda::control::{
    Control, ControlError, ControlPacingConfig, ExactRunMicrovmRequest, is_terminated,
};
use hand_lambda::launch::{self, LaunchFailure};
use hand_policy::MAX_OBJECT_BYTES;
use hand_policy::guest_env::{
    environment_name_is_valid, reserved_tool_environment, secret_material_fits,
};
use hand_wire::{
    AllowlistProxy, FileEffectIdentity, FileEffectKind, FileEffectReservation,
    FileEffectStoredResult, GuestFileWriteRequest, GuestFileWriteSource, InstallBindingRequest,
    InstallBundleMetadata, InstallObjectMetadata, InstallSecretsRequest, RequestCall,
    ResponseReply, RunPayload,
};
use ipnet::Ipv4Net;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, RwLock, Semaphore};
use zeroize::Zeroize as _;

use crate::client::{GuestClient, control_error, error, temporary};
use crate::definitions::{
    DefinitionError, DefinitionKind, DefinitionRecord, DynamoDefinitionRegistry,
};
use crate::registry::DynamoTargetRegistry;

const HAND_ID: &str = "aex-aws-hand";
const RESOURCE_CLASS: &str = "microvm-1gb";
const MIB: usize = 1024 * 1024;
const TARGET_MEMORY_MIB: u64 = hand_lambda::image::MVP_TARGET_MEMORY_MIB as u64;
const MAX_PREPARED_BUNDLES: usize = brain_protocol::MAX_MODEL_TOOLS;
const MAX_CACHED_BUNDLES: usize = 4_096;
const MAX_CACHED_PREPARATIONS: usize = 16_384;
const MAX_CACHED_PREPARATION_BYTES: usize = 64 * MIB;
const MAX_CONCURRENT_BUNDLE_INSTALLS: usize = 4;
const MAX_CONCURRENT_SECRET_INSTALLS: usize = 4;
const SECRET_INSTALL_LOCK_SHARDS: usize = 64;
const FILE_EFFECT_LOCK_SHARDS: usize = 64;
const DEFAULT_BUNDLE_CACHE_MAX_MIB: u64 = 128;
const DEFAULT_BUNDLE_FETCH_MAX_MIB: u64 = 32;
const MAX_CONFIGURED_BUNDLE_CACHE_MIB: u64 = 512;
// A process crash anywhere around RunMicrovm cannot prove whether a VM was created. The reserved
// capacity therefore stays unavailable for the provider's full eight-hour VM wall plus skew;
// only an explicit KnownNoTarget response refunds early. Reclaiming a shorter lease could launch
// two physical VMs while charging the registry for one.
const TARGET_LEASE_MS: u64 = hand_lambda::MAX_DURATION_SECONDS * 1_000 + 5 * 60 * 1_000;
const TARGET_LIFETIME_MS: u64 = hand_lambda::MAX_DURATION_SECONDS * 1_000;
const TARGET_ATTEMPT_MS: u64 = 30_000;
// An exact client-token replay is useful only in the bounded crash-recovery window around the
// first RunMicrovm call. Allowing the first successful dispatch near the end of the eight-hour
// uncertainty lease would let that VM outlive the capacity reservation. Four minutes preserves
// several attempt takeovers while leaving at least one minute between the latest possible
// dispatch and the conservative provider-lifetime-plus-skew refund boundary.
const TARGET_DISPATCH_WINDOW_MS: u64 = 4 * 60 * 1_000;

#[derive(Debug, Clone)]
pub struct HandPlaneConfig {
    pub region: String,
    pub image: String,
    pub image_version: String,
    pub registry_table: String,
    pub max_materialized_mib: u64,
    pub bundle_cache_max_bytes: usize,
    pub bundle_fetch_max_bytes: usize,
    pub connectors: ConnectorCatalog,
    pub capability_signing_key_id: String,
    pub egress_gateway_authority: GatewayAuthority,
}

impl HandPlaneConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let required = |name: &str| -> anyhow::Result<String> {
            let value = std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for the production Hand"))?;
            anyhow::ensure!(!value.trim().is_empty(), "{name} cannot be empty");
            Ok(value)
        };
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into());
        anyhow::ensure!(
            region == "us-east-1",
            "the MVP Hand plane is pinned to us-east-1"
        );
        let connectors = ConnectorCatalog::from_lookup(|class| {
            let name = match class {
                ConnectorClass::None => "HAND_NETWORK_CONNECTOR_NONE",
                ConnectorClass::Allowlist => "HAND_NETWORK_CONNECTOR_ALLOWLIST",
                ConnectorClass::Public => "HAND_NETWORK_CONNECTOR_PUBLIC",
            };
            std::env::var(name).ok()
        })?;
        for class in [
            ConnectorClass::None,
            ConnectorClass::Allowlist,
            ConnectorClass::Public,
        ] {
            hand_lambda::image::validate_network_connector_arn(
                connectors.resolve(class).as_str(),
                &region,
            )?;
        }
        let max_materialized_mib: u64 = required("HAND_MAX_MATERIALIZED_MIB")?.parse()?;
        anyhow::ensure!(
            max_materialized_mib >= TARGET_MEMORY_MIB
                && max_materialized_mib.is_multiple_of(TARGET_MEMORY_MIB),
            "HAND_MAX_MATERIALIZED_MIB must be a positive multiple of 1024"
        );
        let bundle_cache_max_mib = optional_mib(
            "HAND_BUNDLE_CACHE_MAX_MIB",
            DEFAULT_BUNDLE_CACHE_MAX_MIB,
            16,
            MAX_CONFIGURED_BUNDLE_CACHE_MIB,
        )?;
        let bundle_fetch_max_mib = optional_mib(
            "HAND_BUNDLE_FETCH_MAX_MIB",
            DEFAULT_BUNDLE_FETCH_MAX_MIB,
            16,
            bundle_cache_max_mib,
        )?;
        Ok(Self {
            region,
            image: required("HAND_IMAGE")?,
            image_version: required("HAND_IMAGE_VERSION")?,
            registry_table: required("HAND_REGISTRY_TABLE")?,
            max_materialized_mib,
            bundle_cache_max_bytes: mib_bytes(bundle_cache_max_mib)?,
            bundle_fetch_max_bytes: mib_bytes(bundle_fetch_max_mib)?,
            connectors,
            capability_signing_key_id: required("HAND_CAPABILITY_SIGNING_KEY_ID")?,
            egress_gateway_authority: GatewayAuthority::parse(&required(
                "HAND_EGRESS_GATEWAY_AUTHORITY",
            )?)?,
        })
    }
}

fn optional_mib(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{name} must be an integer number of MiB"))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} must be valid UTF-8")
        }
    };
    anyhow::ensure!(
        (min..=max).contains(&value),
        "{name} must be between {min} and {max} MiB"
    );
    Ok(value)
}

fn mib_bytes(value: u64) -> anyhow::Result<usize> {
    usize::try_from(
        value
            .checked_mul(MIB as u64)
            .ok_or_else(|| anyhow::anyhow!("bundle memory bound overflows"))?,
    )
    .map_err(|_| anyhow::anyhow!("bundle memory bound does not fit this process"))
}

pub struct HandPlane {
    pub cfg: HandPlaneConfig,
    pub control: Control,
    pub registry: DynamoTargetRegistry,
    pub definitions: DynamoDefinitionRegistry,
    pub guest: GuestClient,
    kms: aws_sdk_kms::Client,
    image_arn: tokio::sync::OnceCell<String>,
}

impl HandPlane {
    pub async fn from_env(cfg: HandPlaneConfig) -> anyhow::Result<Self> {
        let aws = hand_lambda::aws_config(&cfg.region).await;
        let control = Control::with_pacing(
            aws_sdk_lambdamicrovms::Client::new(&aws),
            cfg.region.clone(),
            ControlPacingConfig::from_env()?,
        );
        let http = hand_lambda::endpoint_http_client_builder()
            .pool_max_idle_per_host(64)
            .build()
            .expect("HTTP client configuration");
        let db = aws_sdk_dynamodb::Client::new(&aws);
        Ok(Self {
            registry: DynamoTargetRegistry::new(
                db.clone(),
                &cfg.registry_table,
                cfg.max_materialized_mib,
            ),
            definitions: DynamoDefinitionRegistry::new(db, &cfg.registry_table),
            guest: GuestClient::new(control.clone(), http),
            kms: aws_sdk_kms::Client::new(&aws),
            control,
            cfg,
            image_arn: tokio::sync::OnceCell::new(),
        })
    }

    async fn image_arn(&self) -> HandResult<String> {
        self.image_arn
            .get_or_try_init(|| async {
                hand_lambda::image::find_image_arn(&self.control, &self.cfg.image)
                    .await
                    .map_err(|_| temporary("MicroVM image lookup failed"))?
                    .ok_or_else(|| {
                        error(
                            HandErrorCode::CapabilityUnavailable,
                            false,
                            "configured MicroVM image does not exist",
                        )
                    })
            })
            .await
            .cloned()
    }

    async fn sign_capability(&self, capability: &Capability) -> HandResult<String> {
        use aws_sdk_kms::primitives::Blob;
        use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
        let payload = unsigned_capability_bytes(capability)
            .map_err(|_| invalid("network capability is invalid"))?;
        let digest = Sha256::digest(&payload);
        let response = self
            .kms
            .sign()
            .key_id(&self.cfg.capability_signing_key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|_| temporary("network capability signing failed"))?;
        let signature = response
            .signature()
            .ok_or_else(|| temporary("network capability signature is absent"))?;
        encode_signed_token(&payload, signature.as_ref())
            .map_err(|_| invalid("sealed network policy cannot fit the gateway transport bound"))
    }
}

#[derive(Clone)]
struct Preparation {
    request: Arc<PrepareSessionRequest>,
    public_digest: String,
    metadata_bytes: usize,
    last_access: Arc<AtomicU64>,
}

struct CachedBundle {
    bytes: Arc<Vec<u8>>,
    last_access: u64,
}

#[derive(Debug)]
struct ValidatedPreparedBundle {
    bytes: u64,
    descriptor_digest: String,
    digest: String,
}

struct PreparationCache {
    sessions: HashMap<String, Preparation>,
    root_sessions: HashMap<String, HashSet<String>>,
    preparation_bytes: usize,
    max_preparation_bytes: usize,
    max_preparations: usize,
    preparation_access_clock: AtomicU64,
    bundles: HashMap<String, CachedBundle>,
    bundle_bytes: usize,
    max_bundle_bytes: usize,
    access_clock: u64,
}

impl PreparationCache {
    fn with_limit(max_bundle_bytes: usize) -> Self {
        Self::with_limits(
            max_bundle_bytes,
            MAX_CACHED_PREPARATION_BYTES,
            MAX_CACHED_PREPARATIONS,
        )
    }

    fn with_limits(
        max_bundle_bytes: usize,
        max_preparation_bytes: usize,
        max_preparations: usize,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            root_sessions: HashMap::new(),
            preparation_bytes: 0,
            max_preparation_bytes,
            max_preparations,
            preparation_access_clock: AtomicU64::new(0),
            bundles: HashMap::new(),
            bundle_bytes: 0,
            max_bundle_bytes,
            access_clock: 0,
        }
    }

    fn get(&self, session_id: &str) -> Option<Preparation> {
        let access = self
            .preparation_access_clock
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.sessions
            .get(session_id)
            .cloned()
            .inspect(|preparation| {
                preparation.last_access.store(access, Ordering::Relaxed);
            })
    }

    fn remove_session(&mut self, session_id: &str) -> Option<Preparation> {
        let removed = self.sessions.remove(session_id)?;
        self.preparation_bytes = self
            .preparation_bytes
            .saturating_sub(removed.metadata_bytes);
        let root_id = removed.request.root_id.to_string();
        if let Some(sessions) = self.root_sessions.get_mut(&root_id) {
            sessions.remove(session_id);
            if sessions.is_empty() {
                self.root_sessions.remove(&root_id);
            }
        }
        Some(removed)
    }

    fn evict_preparations_to_fit(
        &mut self,
        additional_bytes: usize,
        additional_entries: usize,
        protected_session_id: &str,
    ) -> HandResult<()> {
        loop {
            let bytes_fit = self
                .preparation_bytes
                .checked_add(additional_bytes)
                .is_some_and(|total| total <= self.max_preparation_bytes);
            let entries_fit = self
                .sessions
                .len()
                .checked_add(additional_entries)
                .is_some_and(|total| total <= self.max_preparations);
            if bytes_fit && entries_fit {
                return Ok(());
            }
            let candidate = self
                .sessions
                .iter()
                .filter(|(session_id, _)| session_id.as_str() != protected_session_id)
                .min_by_key(|(_, preparation)| preparation.last_access.load(Ordering::Relaxed))
                .map(|(session_id, _)| session_id.clone())
                .ok_or_else(|| preparation_cache_capacity_error(self.max_preparation_bytes))?;
            self.remove_session(&candidate)
                .expect("preparation eviction candidate exists");
        }
    }

    fn bundle(&mut self, digest: &str) -> Option<Arc<Vec<u8>>> {
        self.access_clock = self.access_clock.saturating_add(1);
        let access = self.access_clock;
        self.bundles.get_mut(digest).map(|bundle| {
            bundle.last_access = access;
            bundle.bytes.clone()
        })
    }

    /// Makes room without invalidating an in-progress installation. A cached Arc is borrowed
    /// while it is being installed into a guest; only entries owned solely by this cache are
    /// eviction candidates. Immutable preparation metadata intentionally does not pin bytes.
    fn evict_idle_to_fit(
        &mut self,
        additional_bytes: usize,
        additional_entries: usize,
        protected: &HashSet<String>,
    ) -> HandResult<()> {
        loop {
            let bytes_fit = self
                .bundle_bytes
                .checked_add(additional_bytes)
                .is_some_and(|total| total <= self.max_bundle_bytes);
            let entries_fit = self
                .bundles
                .len()
                .checked_add(additional_entries)
                .is_some_and(|total| total <= MAX_CACHED_BUNDLES);
            if bytes_fit && entries_fit {
                return Ok(());
            }
            let candidate = self
                .bundles
                .iter()
                .filter(|(digest, bundle)| {
                    !protected.contains(digest.as_str()) && Arc::strong_count(&bundle.bytes) == 1
                })
                .min_by_key(|(_, bundle)| bundle.last_access)
                .map(|(digest, _)| digest.clone())
                .ok_or_else(|| {
                    if !entries_fit && bytes_fit {
                        bundle_cache_entry_capacity_error()
                    } else {
                        bundle_cache_capacity_error(self.max_bundle_bytes)
                    }
                })?;
            let evicted = self.bundles.remove(&candidate).expect("candidate exists");
            self.bundle_bytes = self.bundle_bytes.saturating_sub(evicted.bytes.len());
        }
    }

    fn install(
        &mut self,
        request: PrepareSessionRequest,
        public_digest: String,
        fetched: HashMap<String, Arc<Vec<u8>>>,
    ) -> HandResult<()> {
        let session_id = request.session_id.to_string();
        let root_id = request.root_id.to_string();
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|old| old.request.root_id != request.root_id)
        {
            return Err(binding_error(
                "prepared session cannot move to a different root",
            ));
        }
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|old| old.public_digest != public_digest)
        {
            return Err(binding_error(
                "prepared session immutable routing or bundle seal changed",
            ));
        }
        let required = required_bundle_digests(&request)?;
        if fetched.keys().any(|digest| !required.contains(digest)) {
            return Err(invalid(
                "preparation contains a fetch for an unreferenced bundle",
            ));
        }
        for digest in &required {
            if !fetched.contains_key(digest) && !self.bundles.contains_key(digest) {
                return Err(error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "bundle cache recovery requires a fresh preparation fetch",
                ));
            }
        }

        // Preparation metadata is cold-path state and may be reconstructed by Brain. Bound it
        // separately from resident bundle bytes so a large population of dormant sessions cannot
        // grow the shared hosted process without limit. Eviction is safe: the next operation gets
        // CapabilityUnavailable before materialization/effect and Brain supplies a fresh prepare.
        let metadata_bytes = serde_jcs::to_vec(&request)
            .map_err(|_| invalid("preparation metadata cannot be bounded"))?
            .len();
        if metadata_bytes > self.max_preparation_bytes || self.max_preparations == 0 {
            return Err(preparation_cache_capacity_error(self.max_preparation_bytes));
        }
        let prior_metadata_bytes = self
            .sessions
            .get(&session_id)
            .map_or(0, |preparation| preparation.metadata_bytes);
        let additional_bytes = metadata_bytes.saturating_sub(prior_metadata_bytes);
        let additional_entries = usize::from(!self.sessions.contains_key(&session_id));
        self.evict_preparations_to_fit(additional_bytes, additional_entries, &session_id)?;

        let missing = required
            .iter()
            .filter(|digest| !self.bundles.contains_key(digest.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let additional_bytes = missing.iter().try_fold(0usize, |total, digest| {
            total
                .checked_add(fetched.get(digest).expect("required fetch checked").len())
                .ok_or_else(|| bundle_cache_capacity_error(self.max_bundle_bytes))
        })?;
        self.evict_idle_to_fit(additional_bytes, missing.len(), &required)?;
        for digest in &required {
            if !self.bundles.contains_key(digest) {
                let bytes = fetched.get(digest).expect("required fetch checked").clone();
                self.bundle_bytes += bytes.len();
                self.access_clock = self.access_clock.saturating_add(1);
                self.bundles.insert(
                    digest.clone(),
                    CachedBundle {
                        bytes,
                        last_access: self.access_clock,
                    },
                );
            }
            let _ = self.bundle(digest);
        }
        if self.sessions.contains_key(&session_id) {
            self.remove_session(&session_id);
        }
        self.preparation_access_clock
            .fetch_add(1, Ordering::Relaxed);
        let last_access = self.preparation_access_clock.load(Ordering::Relaxed);
        self.preparation_bytes = self
            .preparation_bytes
            .checked_add(metadata_bytes)
            .ok_or_else(|| preparation_cache_capacity_error(self.max_preparation_bytes))?;
        self.sessions.insert(
            session_id.clone(),
            Preparation {
                request: Arc::new(request),
                public_digest,
                metadata_bytes,
                last_access: Arc::new(AtomicU64::new(last_access)),
            },
        );
        self.root_sessions
            .entry(root_id)
            .or_default()
            .insert(session_id);
        debug_assert_eq!(
            self.bundle_bytes,
            self.bundles
                .values()
                .map(|bundle| bundle.bytes.len())
                .sum::<usize>()
        );
        Ok(())
    }

    /// Drops at most `limit` logical preparations and their bundle references.
    fn purge_root_page(&mut self, root_id: &str, limit: usize) -> bool {
        let session_ids = self
            .root_sessions
            .get(root_id)
            .into_iter()
            .flat_map(|sessions| sessions.iter().take(limit))
            .cloned()
            .collect::<Vec<_>>();
        for session_id in session_ids {
            let _ = self.remove_session(&session_id);
        }
        let complete = self
            .root_sessions
            .get(root_id)
            .is_none_or(HashSet::is_empty);
        if complete {
            self.root_sessions.remove(root_id);
        }
        complete
    }
}

impl Default for PreparationCache {
    fn default() -> Self {
        Self::with_limit(DEFAULT_BUNDLE_CACHE_MAX_MIB as usize * MIB)
    }
}

/// Bundle fetch URLs and headers are short-lived bearer authorities. They are consumed while the
/// preparation request is active and must not become part of the process-lifetime session cache.
/// The immutable descriptors and binding-to-digest projection remain in the request, so bundle
/// cache recovery still fails closed and asks Brain for a fresh preparation authority.
fn cacheable_preparation(mut request: PrepareSessionRequest) -> PrepareSessionRequest {
    request.bundles.clear();
    request
}

fn preparation_public_projection(request: &PrepareSessionRequest) -> HandResult<serde_json::Value> {
    let mut secret_env_names = request
        .secret_capability
        .iter()
        .flat_map(|capability| capability.env_names.iter())
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    secret_env_names.sort_unstable();
    if secret_env_names.len() > brain_protocol::MAX_SESSION_SECRET_NAMES
        || secret_env_names
            .iter()
            .any(|name| !environment_name_is_valid(name) || reserved_tool_environment(name))
        || secret_env_names.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(invalid(
            "secret capability has invalid, reserved, or repeated environment names",
        ));
    }
    Ok(serde_json::json!({
        "bindings": request.bindings,
        "network": request.network,
        "resources": request.resources,
        "root_id": request.root_id,
        // The one-purpose bearer and expiry may be refreshed after a control-process loss, but
        // the declared session environment-name union is part of the immutable preparation.
        "secret_env_names": secret_env_names,
        "session_id": request.session_id,
    }))
}

#[derive(Clone, Copy)]
enum MaterializationMode<'a> {
    LazyDefault,
    ExplicitDefault(&'a str),
    Additional(&'a str),
}

impl<'a> MaterializationMode<'a> {
    fn generation_intent(self) -> Option<&'a str> {
        match self {
            Self::LazyDefault => None,
            Self::ExplicitDefault(generation) | Self::Additional(generation) => Some(generation),
        }
    }

    fn replace_after_loss(self) -> bool {
        matches!(self, Self::LazyDefault | Self::ExplicitDefault(_))
    }
}

fn zeroize_secret_values(values: &mut HashMap<String, String>) {
    for value in values.values_mut() {
        value.zeroize();
    }
    values.clear();
}

/// One shard derivation for every lock array: SHA-256 over NUL-joined parts, first 8 bytes.
fn shard_index(parts: &[&str], shards: usize) -> usize {
    let mut digest = Sha256::new();
    for (position, part) in parts.iter().enumerate() {
        if position > 0 {
            digest.update([0]);
        }
        digest.update(part.as_bytes());
    }
    let digest = digest.finalize();
    let prefix = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
    prefix as usize % shards
}

fn secret_install_lock_index(target_ref: &str, session_id: &str) -> usize {
    shard_index(&[target_ref, session_id], SECRET_INSTALL_LOCK_SHARDS)
}

/// Supervisor-owned temporary object. It has no stable external name, is mode 0600, and is
/// removed automatically. Transfer authorities and values are deliberately not retained here.
struct StagedObject {
    file: tempfile::NamedTempFile,
    bytes: u64,
    sha256: String,
}

/// Process-wide bytes admitted for verified bundles that are currently being fetched but are not
/// yet represented in `PreparationCache::bundle_bytes`. The reservation uses a synchronous lock
/// only for integer accounting, so its `Drop` path remains cancellation-safe across network
/// awaits.
#[derive(Clone, Copy, Debug, Default)]
struct BundleFetchInFlight {
    bytes: usize,
    entries: usize,
}

#[derive(Debug)]
struct BundleFetchReservation {
    reserved: Arc<StdMutex<BundleFetchInFlight>>,
    bytes: usize,
    entries: usize,
}

impl BundleFetchReservation {
    /// Reserves the declared upper bound, rather than the eventual response size. This keeps the
    /// cache plus every concurrent cold fetch below one process-wide limit even if all servers
    /// return their maximum response at once.
    fn admit(
        reserved: Arc<StdMutex<BundleFetchInFlight>>,
        cached_bytes: usize,
        cached_entries: usize,
        fetch_bytes: usize,
        fetch_entries: usize,
        cache_limit_bytes: usize,
        fetch_limit_bytes: usize,
    ) -> HandResult<Self> {
        let mut in_flight = reserved
            .lock()
            .map_err(|_| temporary("bundle fetch admission is unavailable"))?;
        let projected_fetch = in_flight
            .bytes
            .checked_add(fetch_bytes)
            .ok_or_else(|| bundle_fetch_capacity_error(fetch_limit_bytes))?;
        if projected_fetch > fetch_limit_bytes {
            return Err(bundle_fetch_capacity_error(fetch_limit_bytes));
        }
        let admitted = cached_bytes
            .checked_add(in_flight.bytes)
            .and_then(|bytes| bytes.checked_add(fetch_bytes))
            .ok_or_else(|| bundle_cache_capacity_error(cache_limit_bytes))?;
        if admitted > cache_limit_bytes {
            return Err(bundle_cache_capacity_error(cache_limit_bytes));
        }
        let admitted_entries = cached_entries
            .checked_add(in_flight.entries)
            .and_then(|entries| entries.checked_add(fetch_entries))
            .ok_or_else(|| bundle_cache_capacity_error(cache_limit_bytes))?;
        if admitted_entries > MAX_CACHED_BUNDLES {
            return Err(bundle_cache_entry_capacity_error());
        }
        in_flight.bytes = projected_fetch;
        in_flight.entries += fetch_entries;
        drop(in_flight);
        Ok(Self {
            reserved,
            bytes: fetch_bytes,
            entries: fetch_entries,
        })
    }
}

impl Drop for BundleFetchReservation {
    fn drop(&mut self) {
        let mut reserved = self
            .reserved
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        reserved.bytes = reserved.bytes.saturating_sub(self.bytes);
        reserved.entries = reserved.entries.saturating_sub(self.entries);
    }
}

/// The canonical production implementation of Brain's Hand ports.
pub struct AwsHand {
    plane: Arc<HandPlane>,
    preparation_cache: RwLock<PreparationCache>,
    prepared_targets: RwLock<HashMap<String, HashSet<String>>>,
    secret_install_locks: [Mutex<()>; SECRET_INSTALL_LOCK_SHARDS],
    file_effect_locks: [Mutex<()>; FILE_EFFECT_LOCK_SHARDS],
    secret_delivery: StdRwLock<Option<Arc<dyn SecretDeliveryPort>>>,
    bundle_fetch_reserved: Arc<StdMutex<BundleFetchInFlight>>,
    bundle_fetch_max_bytes: usize,
    bundle_install_permits: Semaphore,
    secret_install_permits: Semaphore,
}

impl AwsHand {
    pub async fn from_env() -> anyhow::Result<Arc<Self>> {
        let cfg = HandPlaneConfig::from_env()?;
        Ok(Self::with_plane(Arc::new(HandPlane::from_env(cfg).await?)))
    }

    pub fn with_plane(plane: Arc<HandPlane>) -> Arc<Self> {
        let bundle_cache_max_bytes = plane.cfg.bundle_cache_max_bytes;
        let bundle_fetch_max_bytes = plane.cfg.bundle_fetch_max_bytes;
        Arc::new(Self {
            plane,
            preparation_cache: RwLock::new(PreparationCache::with_limit(bundle_cache_max_bytes)),
            prepared_targets: RwLock::new(HashMap::new()),
            secret_install_locks: std::array::from_fn(|_| Mutex::new(())),
            file_effect_locks: std::array::from_fn(|_| Mutex::new(())),
            secret_delivery: StdRwLock::new(None),
            bundle_fetch_reserved: Arc::new(StdMutex::new(BundleFetchInFlight::default())),
            bundle_fetch_max_bytes,
            bundle_install_permits: Semaphore::new(MAX_CONCURRENT_BUNDLE_INSTALLS),
            secret_install_permits: Semaphore::new(MAX_CONCURRENT_SECRET_INSTALLS),
        })
    }

    /// Completes the deliberate Brain↔Hand composition cycle. It must be called before a session
    /// with declared secrets first materializes; replacing an installed callback is refused.
    pub fn attach_secret_delivery(&self, port: Arc<dyn SecretDeliveryPort>) -> HandResult<()> {
        let mut slot = self
            .secret_delivery
            .write()
            .map_err(|_| temporary("secret delivery lock is unavailable"))?;
        if slot.is_some() {
            return Err(invalid("secret delivery port is already attached"));
        }
        *slot = Some(port);
        Ok(())
    }

    async fn binding(&self, root_id: &str, binding_ref: &str) -> HandResult<SealedBinding> {
        self.plane
            .definitions
            .get(root_id, DefinitionKind::Binding, binding_ref)
            .await
            .map_err(definition_error)?
            .ok_or_else(|| binding_error("binding_ref is unknown"))?
            .decode()
            .map_err(definition_error)
    }

    /// Resolves the complete preparation batch before any definition write, authority fetch, or
    /// target effect. A prepared bundle authority is useful only for the exact immutable binding
    /// in this root/session; accepting an unscoped digest bag would let a malformed caller warm
    /// unrelated code into the process cache and defer a permanent mismatch until dispatch.
    async fn validate_prepared_bindings(
        &self,
        request: &PrepareSessionRequest,
    ) -> HandResult<HashMap<String, ValidatedPreparedBundle>> {
        let mut seen = HashSet::with_capacity(request.bindings.len());
        for prepared in &request.bindings {
            if !seen.insert(prepared.binding_ref.to_string()) {
                return Err(binding_error("preparation repeats a binding_ref"));
            }
        }

        let validations = futures_util::stream::iter(request.bindings.iter().cloned().map(
            |prepared| async move {
                let binding = self
                    .binding(request.root_id.as_str(), prepared.binding_ref.as_str())
                    .await?;
                validate_prepared_binding_projection(
                    &prepared,
                    &binding,
                    request.root_id.as_str(),
                    request.session_id.as_str(),
                )
            },
        ))
        // Preparation is a cold control operation, but validating a large fixed Tool set one
        // strongly-consistent Dynamo read at a time would add avoidable linear latency.
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;

        let mut required = HashMap::with_capacity(validations.len());
        for validation in validations {
            merge_validated_prepared_bundle(&mut required, validation?)?;
        }
        Ok(required)
    }

    async fn preparation(&self, session_id: &str) -> HandResult<Preparation> {
        self.preparation_cache
            .read()
            .await
            .get(session_id)
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "session must be prepared again after Hand control-process recovery",
                )
            })
    }

    async fn route_for_submit(&self, request: &SubmitRequest) -> HandResult<InstalledTarget> {
        let envelope = &request.envelope;
        match (&envelope.target_ref, &envelope.generation) {
            (Some(target_ref), Some(generation)) => {
                // Hot path: Brain journaled this receipt. Do not read or write DynamoDB.
                let prep = self.preparation(envelope.session_id.as_str()).await?;
                if prep.request.root_id != envelope.root_id {
                    return Err(binding_error("prepared root does not match operation root"));
                }
                validate_operation_root_seal(envelope, &prep.request)?;
                let spec = target_spec(
                    &self.plane.cfg,
                    &prep.request.resources,
                    &prep.request.network,
                    RESOURCE_CLASS,
                )?;
                // The provider JWE authenticates public ingress, while the installed target row
                // owns the generation bearer that authenticates the supervisor inside the shared
                // guest network namespace. Resolve that durable row even for an established
                // operation so a restarted Hand never invents or loses the bearer.
                let installed = self
                    .resolve_target(&default_target(envelope)?, Some(generation.as_str()))
                    .await?;
                if installed.target_ref != target_ref.as_str()
                    || installed.spec_digest != spec.digest()
                {
                    return Err(generation_error());
                }
                Ok(installed)
            }
            (None, None) => {
                let prep = self.preparation(envelope.session_id.as_str()).await?;
                if prep.request.root_id != envelope.root_id {
                    return Err(binding_error("prepared root does not match operation root"));
                }
                validate_operation_root_seal(envelope, &prep.request)?;
                self.materialize(
                    TargetKey::default(envelope.root_id.as_str()).map_err(materialization_error)?,
                    envelope.session_id.as_str(),
                    &prep.request.resources,
                    &prep.request.network,
                    RESOURCE_CLASS,
                    MaterializationMode::LazyDefault,
                )
                .await
            }
            _ => Err(invalid(
                "target_ref and generation must either both be absent or both be present",
            )),
        }
    }

    async fn materialize(
        &self,
        key: TargetKey,
        owner_session_id: &str,
        resources: &ResourceCeiling,
        network: &NetworkCeiling,
        resource_class: &str,
        mode: MaterializationMode<'_>,
    ) -> HandResult<InstalledTarget> {
        if resource_class != RESOURCE_CLASS {
            return Err(error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "the MVP plane exposes only the microvm-1gb resource class",
            ));
        }
        let spec = target_spec(&self.plane.cfg, resources, network, resource_class)?;
        let now = now_ms();
        let reservation_id = random_identifier("reservation");
        let generation = mode
            .generation_intent()
            .map(str::to_owned)
            .unwrap_or_else(|| random_identifier("generation"));
        let attempt_id = random_identifier("attempt");
        // Build the exact provider request before the reservation transaction. This provisional
        // value is never persisted or dispatched; it supplies only the generation/deadlines used
        // to mint the immutable run payload. The completed sealed request replaces it below.
        let mut request = AcquireTarget {
            key: key.clone(),
            spec,
            reservation_id,
            generation,
            launch_request: DurableLaunchRequest::new("unsealed")
                .expect("non-empty provisional launch request"),
            attempt_id,
            attempt_duration_ms: TARGET_ATTEMPT_MS,
            generation_is_fenced: mode.generation_intent().is_some(),
            now_ms: now,
            lease_duration_ms: TARGET_LEASE_MS,
            target_lifetime_ms: TARGET_LIFETIME_MS,
            replace_after_loss: mode.replace_after_loss(),
        };
        let launcher = GenerationLauncher {
            plane: self.plane.clone(),
            key,
            owner_session_id: owner_session_id.into(),
            resources: resources.clone(),
            network: network.clone(),
            resource_class: resource_class.into(),
        };
        let preview = request.lease().map_err(materialization_error)?;
        request.launch_request = launcher.seal_launch(&preview).await?;
        TargetMaterializer::new(self.plane.registry.clone(), launcher)
            .ensure(&request)
            .await
            .map_err(materialization_error)
    }

    async fn install_for_operation(
        &self,
        route: &InstalledTarget,
        request: &SubmitRequest,
    ) -> HandResult<()> {
        let envelope = &request.envelope;
        let binding = self
            .binding(envelope.root_id.as_str(), envelope.binding_ref.as_str())
            .await?;
        let descriptor = binding.bundle.as_ref().ok_or_else(|| {
            error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "managed binding has no immutable bundle",
            )
        })?;
        let install_key = format!(
            "{}:{}",
            envelope.binding_ref.as_str(),
            descriptor.bundle_digest.as_str()
        );
        let installed = self
            .prepared_targets
            .read()
            .await
            .get(&route.target_ref)
            .is_some_and(|items| items.contains(&install_key));
        if !installed {
            // Brain's maximum Tool bundle is 4 MiB. Bound concurrent transient request-body
            // copies in the hosted process and buffered bodies in a 1-GiB guest when many first
            // calls arrive at once; established calls skip this cold path entirely.
            let _install_permit = self
                .bundle_install_permits
                .acquire()
                .await
                .map_err(|_| temporary("bundle installation admission is unavailable"))?;
            let bundle = self
                .preparation_cache
                .write()
                .await
                .bundle(descriptor.bundle_digest.as_str())
                .ok_or_else(|| {
                    error(
                        HandErrorCode::CapabilityUnavailable,
                        false,
                        "bundle bytes are not cached; Brain must prepare the session again",
                    )
                })?;
            self.plane
                .guest
                .post_blob(
                    route,
                    &format!("/internal/bundles/{}", descriptor.bundle_digest.as_str()),
                    &InstallBundleMetadata {
                        descriptor: descriptor.clone(),
                    },
                    bundle.as_slice(),
                )
                .await?;
            self.plane
                .guest
                .post_json(
                    route,
                    "/internal/bindings",
                    &InstallBindingRequest {
                        binding_ref: envelope.binding_ref.to_string(),
                        binding: binding.clone(),
                    },
                )
                .await?;
            self.prepared_targets
                .write()
                .await
                .entry(route.target_ref.clone())
                .or_default()
                .insert(install_key);
        }
        self.install_secrets(route, envelope, &binding).await
    }

    async fn install_object(
        &self,
        route: &InstalledTarget,
        object: &ObjectReference,
        staged: &StagedObject,
    ) -> HandResult<()> {
        if staged.bytes != object.bytes || staged.sha256 != object.sha256.as_str() {
            return Err(invalid(
                "staged object does not match its immutable reference",
            ));
        }
        self.plane
            .guest
            .post_file(
                route,
                &format!("/internal/objects/{}", object.sha256.as_str()),
                &InstallObjectMetadata {
                    object: object.clone(),
                },
                staged.file.path(),
                staged.bytes,
            )
            .await
    }

    async fn install_secrets(
        &self,
        route: &InstalledTarget,
        envelope: &brain_protocol::hand::OperationEnvelope,
        binding: &SealedBinding,
    ) -> HandResult<()> {
        let required = binding
            .bundle
            .as_ref()
            .map(|bundle| !bundle.required_env.is_empty())
            .unwrap_or(false);
        if !required {
            return Ok(());
        }
        let installed_key = format!("secret-session:{}", envelope.session_id.as_str());
        if self
            .prepared_targets
            .read()
            .await
            .get(&route.target_ref)
            .is_some_and(|items| items.contains(&installed_key))
        {
            return Ok(());
        }

        // Secret capabilities are single-use per logical session and physical generation.
        // A fixed shard set serializes the cold path without retaining an attacker-controlled
        // number of keys; an unrelated hash collision only delays this rare preparation step.
        let secret_lock =
            secret_install_lock_index(route.target_ref.as_str(), envelope.session_id.as_str());
        let _secret_install_guard = self.secret_install_locks[secret_lock].lock().await;
        if self
            .prepared_targets
            .read()
            .await
            .get(&route.target_ref)
            .is_some_and(|items| items.contains(&installed_key))
        {
            return Ok(());
        }
        let _secret_memory_permit = self
            .secret_install_permits
            .acquire()
            .await
            .map_err(|_| temporary("secret installation admission is unavailable"))?;
        let preparation = self.preparation(envelope.session_id.as_str()).await?;
        let capability = preparation
            .request
            .secret_capability
            .clone()
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "declared Tool environment requires a fresh preparation capability",
                )
            })?;
        let env_names = capability
            .env_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>();
        let port = self
            .secret_delivery
            .read()
            .map_err(|_| temporary("secret delivery lock is unavailable"))?
            .clone()
            .ok_or_else(|| {
                error(
                    HandErrorCode::CapabilityUnavailable,
                    false,
                    "secret delivery port is not attached",
                )
            })?;
        let target = default_target(envelope)?;
        let capability_ref = capability.capability_ref.clone();
        // Remove the bearer before crossing the asynchronous callback boundary. Cancellation,
        // timeout, or an uncertain response can therefore never reuse a single-use capability.
        // Brain may prepare a fresh grant; the guest install is exact-idempotent if the first
        // response was merely lost.
        self.consume_secret_capability(envelope.session_id.as_str(), capability_ref.as_str())
            .await;
        let material = port
            .redeem(SecretDeliveryRequest {
                capability_ref,
                generation_intent: route.generation.parse().map_err(|_| generation_error())?,
                hand_id: HAND_ID.parse().expect("hand id"),
                root_id: envelope.root_id.clone(),
                session_id: envelope.session_id.clone(),
                target,
            })
            .await?;
        let mut values = material.into_env();
        if let Err(refusal) = secret_material_fits(&env_names, &values) {
            zeroize_secret_values(&mut values);
            return Err(error(
                HandErrorCode::CapabilityUnavailable,
                false,
                format!(
                    "secret delivery returned material outside the declared bounded environment: {refusal}"
                ),
            ));
        }
        let mut payload = InstallSecretsRequest {
            session_id: envelope.session_id.to_string(),
            generation: route.generation.clone(),
            env_names,
            values,
        };
        self.post_secret_payload(route, &mut payload).await?;
        self.prepared_targets
            .write()
            .await
            .entry(route.target_ref.clone())
            .or_default()
            .insert(installed_key);
        Ok(())
    }

    async fn consume_secret_capability(&self, session_id: &str, capability_ref: &str) {
        let mut cache = self.preparation_cache.write().await;
        let Some(preparation) = cache.sessions.get_mut(session_id) else {
            return;
        };
        if preparation
            .request
            .secret_capability
            .as_ref()
            .is_some_and(|capability| capability.capability_ref.as_str() == capability_ref)
        {
            Arc::make_mut(&mut preparation.request).secret_capability = None;
        }
    }

    async fn post_secret_payload(
        &self,
        route: &InstalledTarget,
        payload: &mut InstallSecretsRequest,
    ) -> HandResult<()> {
        let result = self
            .plane
            .guest
            .post_json(route, "/internal/secrets", payload)
            .await;
        zeroize_secret_values(&mut payload.values);
        result
    }

    async fn resolve_target(
        &self,
        target: &SandboxTarget,
        expected_generation: Option<&str>,
    ) -> HandResult<InstalledTarget> {
        let key = target_key(target)?;
        let record = self
            .plane
            .registry
            .get(&key)
            .await
            .map_err(materialization_error)?
            .ok_or_else(|| {
                error(
                    HandErrorCode::SandboxNotMaterialized,
                    false,
                    "sandbox has never been materialized",
                )
            })?;
        let installed = match record.state {
            DurableTargetState::Installed { .. } => record.installed().expect("installed target"),
            DurableTargetState::Gone { .. } | DurableTargetState::Terminated { .. } => {
                return Err(error(HandErrorCode::SandboxGone, false, "sandbox is gone"));
            }
            DurableTargetState::Materializing { .. } => {
                return Err(temporary("sandbox materialization is in progress"));
            }
        };
        if expected_generation.is_some_and(|expected| expected != installed.generation) {
            return Err(generation_error());
        }
        if now_ms() >= installed.expires_at_ms {
            self.confirm_provider_termination(&installed).await?;
            self.record_gone(&installed, "physical target hard deadline reached")
                .await?;
            return Err(error(
                HandErrorCode::SandboxGone,
                false,
                "sandbox physical generation has expired",
            ));
        }
        Ok(installed)
    }

    async fn resolve_operation_target(
        &self,
        operation: &OperationRef,
    ) -> HandResult<InstalledTarget> {
        let installed = self
            .resolve_target(&operation.target, Some(operation.generation.as_str()))
            .await?;
        if installed.target_ref != operation.target_ref.as_str() {
            return Err(generation_error());
        }
        Ok(installed)
    }

    async fn terminate_target(&self, installed: &InstalledTarget, reason: &str) -> HandResult<()> {
        self.confirm_provider_termination(installed).await?;
        self.plane
            .registry
            .mark_terminated(installed, reason, now_ms())
            .await
            .map_err(materialization_error)?;
        self.forget_target(installed).await;
        Ok(())
    }

    /// Confirms that a physical target no longer consumes provider memory before any registry
    /// transition refunds its charged plane capacity. A successful/ambiguous terminate response
    /// is not enough: only `Terminated` or authoritative not-found closes the accounting fence.
    async fn confirm_provider_termination(&self, installed: &InstalledTarget) -> HandResult<()> {
        // Every retry reconciles provider state before another state-changing call. In
        // particular, `Terminating` is not considered absent: it may still consume account memory
        // and the registry capacity counter must remain charged until termination is confirmed.
        match self.plane.control.get(&installed.target_ref).await {
            Err(ControlError::Gone(_)) => {}
            Ok(vm) if is_terminated(&vm.state) => {}
            Ok(vm) if vm.state == aws_sdk_lambdamicrovms::types::MicrovmState::Terminating => {
                return Err(temporary("sandbox termination is still in progress"));
            }
            Ok(_) => match self.plane.control.terminate(&installed.target_ref).await {
                Ok(()) | Err(ControlError::Unknown(_)) => {
                    match self.plane.control.get(&installed.target_ref).await {
                        Err(ControlError::Gone(_)) => {}
                        Ok(vm) if is_terminated(&vm.state) => {}
                        _ => {
                            return Err(temporary(
                                "sandbox termination outcome is not yet confirmed",
                            ));
                        }
                    }
                }
                Err(ControlError::Gone(_)) => {}
                Err(error_value) => return Err(control_error(error_value)),
            },
            Err(error_value) => return Err(control_error(error_value)),
        }
        Ok(())
    }

    async fn forget_target(&self, installed: &InstalledTarget) {
        self.plane.guest.forget(&installed.target_ref).await;
        self.prepared_targets
            .write()
            .await
            .remove(&installed.target_ref);
    }

    /// A provider-confirmed loss must release this plane's charged capacity before Brain is told
    /// that a fresh default generation may be created. Otherwise the durable registry would keep
    /// routing retries to a dead VM and status would lie indefinitely.
    async fn record_gone(&self, installed: &InstalledTarget, reason: &str) -> HandResult<()> {
        self.plane
            .registry
            .mark_gone(installed, reason, now_ms())
            .await
            .map_err(materialization_error)?;
        self.forget_target(installed).await;
        Ok(())
    }

    /// Persistent endpoint 502 means the supervisor generation cannot be re-armed, even when
    /// GetMicrovm still says RUNNING. It does not, by itself, prove that provider memory was
    /// released. Terminate and reconcile first; otherwise keep the reservation charged and ask
    /// Brain to retry recovery.
    async fn retire_endpoint_lost_target(&self, installed: &InstalledTarget) -> HandResult<()> {
        self.confirm_provider_termination(installed).await?;
        self.record_gone(
            installed,
            "guest supervisor endpoint is permanently unavailable",
        )
        .await?;
        Ok(())
    }

    async fn settle_guest_result<T>(
        &self,
        installed: &InstalledTarget,
        result: HandResult<T>,
    ) -> HandResult<T> {
        match result {
            Err(error_value) if error_value.code == HandErrorCode::SandboxGone => {
                self.retire_endpoint_lost_target(installed).await?;
                Err(error_value)
            }
            result => result,
        }
    }

    async fn guest_rpc(
        &self,
        installed: &InstalledTarget,
        call: RequestCall,
    ) -> HandResult<ResponseReply> {
        let result = self.plane.guest.rpc(installed, call).await;
        self.settle_guest_result(installed, result).await
    }

    /// Dispatches the one RPC whose missing receipt can hide a started Tool effect. A persistent
    /// endpoint loss is deliberately *not* reconciled to a Gone target here: that durable target
    /// fence is what forces every lost-response retry back to the same physical generation. Brain
    /// records the unknown outcome, then observes/schedules the target's bounded hard-deadline
    /// cleanup before a later explicit generation may replace it.
    async fn guest_submit_rpc(
        &self,
        installed: &InstalledTarget,
        request: SubmitRequest,
    ) -> HandResult<ResponseReply> {
        self.plane
            .guest
            .rpc(installed, RequestCall::Submit(Box::new(request)))
            .await
            .map_err(classify_submit_delivery_error)
    }

    async fn reserve_file_effect(
        &self,
        installed: &InstalledTarget,
        identity: FileEffectIdentity,
    ) -> HandResult<FileEffectReservation> {
        match self
            .guest_rpc(installed, RequestCall::ReserveFileEffect(identity))
            .await?
        {
            ResponseReply::ReserveFileEffect(reservation) => Ok(reservation),
            _ => Err(wrong_reply("file reservation")),
        }
    }

    async fn claim_file_effect(
        &self,
        installed: &InstalledTarget,
        identity: FileEffectIdentity,
    ) -> HandResult<FileEffectReservation> {
        match self
            .guest_rpc(installed, RequestCall::ClaimFileEffect(identity))
            .await?
        {
            ResponseReply::ClaimFileEffect(reservation) => Ok(reservation),
            _ => Err(wrong_reply("file claim")),
        }
    }
}

#[async_trait]
impl HandPort for AwsHand {
    async fn resolve_binding(&self, binding: SealedBinding) -> HandResult<ResolvedBinding> {
        validate_managed_binding(&binding)?;
        let digest =
            canonical_digest(&binding).map_err(|_| invalid("binding cannot be canonicalized"))?;
        let binding_ref = format!("binding:{}", digest.as_str());
        let record = DefinitionRecord::canonical(
            binding.root_id.as_str(),
            DefinitionKind::Binding,
            &binding_ref,
            &binding,
            now_ms(),
        )
        .map_err(definition_error)?;
        self.plane
            .definitions
            .install(&record)
            .await
            .map_err(definition_error)?;
        Ok(ResolvedBinding {
            binding_ref: binding_ref.parse().expect("binding ref"),
            capabilities: vec![
                HandCapability::Execution,
                HandCapability::SessionPreparation,
                HandCapability::SandboxFiles,
                HandCapability::SandboxControl,
            ],
            hand_id: HAND_ID.parse().expect("hand id"),
            limits: ResolvedBindingLimits {
                max_inline_input_bytes: NonZeroU64::new(
                    brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES as u64,
                )
                .unwrap(),
                max_inline_result_bytes: NonZeroU64::new(
                    brain_protocol::MAX_TOOL_TERMINAL_INLINE_BYTES as u64,
                )
                .unwrap(),
                max_wait_ms: 30_000,
            },
            realm: ExecutionRealm::AexManaged,
            recovery: RecoveryClass::Retained,
        })
    }

    async fn submit(&self, request: SubmitRequest) -> HandResult<SubmitReceipt> {
        validate_inline_input(&request.envelope.input)?;
        if operation_request_digest(&request.envelope) != request.envelope.request_digest {
            return Err(invalid("operation request_digest is not canonical"));
        }
        let route = self.route_for_submit(&request).await?;
        let installed = self.install_for_operation(&route, &request).await;
        self.settle_guest_result(&route, installed).await?;
        let reply = self.guest_submit_rpc(&route, request).await?;
        match reply {
            ResponseReply::Submit(receipt) => Ok(receipt),
            _ => Err(wrong_reply("submit")),
        }
    }

    async fn observe(&self, request: ObserveRequest) -> HandResult<OperationObservation> {
        let installed = self.resolve_operation_target(&request.operation).await?;
        match self
            .guest_rpc(&installed, RequestCall::Observe(request))
            .await?
        {
            ResponseReply::Observe(observation) => Ok(observation),
            _ => Err(wrong_reply("observe")),
        }
    }

    async fn cancel(&self, request: CancelRequest) -> HandResult<CancellationReceipt> {
        let installed = self.resolve_operation_target(&request.operation).await?;
        match self
            .guest_rpc(&installed, RequestCall::Cancel(request))
            .await?
        {
            ResponseReply::Cancel(receipt) => Ok(receipt),
            _ => Err(wrong_reply("cancel")),
        }
    }

    async fn acknowledge_terminal(
        &self,
        request: AcknowledgeTerminalRequest,
    ) -> HandResult<Acknowledgement> {
        let installed = self.resolve_operation_target(&request.operation).await?;
        match self
            .guest_rpc(&installed, RequestCall::AcknowledgeTerminal(request))
            .await?
        {
            ResponseReply::AcknowledgeTerminal(receipt) => Ok(receipt),
            _ => Err(wrong_reply("acknowledgement")),
        }
    }
}

#[async_trait]
impl SessionPreparationPort for AwsHand {
    async fn prepare(&self, request: PrepareSessionRequest) -> HandResult<PreparedSession> {
        if request.bundles.len() > MAX_PREPARED_BUNDLES
            || request.bindings.len() > MAX_PREPARED_BUNDLES
        {
            return Err(invalid("preparation exceeds the bundle/binding bound"));
        }
        let projection = preparation_public_projection(&request)?;
        // Reject an unenforceable physical root before reading definitions, writing durable
        // state, or fetching any one-purpose authority.
        target_spec(
            &self.plane.cfg,
            &request.resources,
            &request.network,
            RESOURCE_CLASS,
        )?;
        // Resolve the whole immutable binding projection before consuming a bundle/secret
        // authority or mutating any durable preparation row.
        let required_bundles = self.validate_prepared_bindings(&request).await?;
        let mut supplied_bundles = HashMap::with_capacity(request.bundles.len());
        for fetch in &request.bundles {
            let digest = fetch.bundle_digest.to_string();
            if !required_bundles.contains_key(&digest) {
                return Err(invalid(
                    "preparation contains a fetch for an unreferenced bundle",
                ));
            }
            if supplied_bundles.insert(digest, fetch.clone()).is_some() {
                return Err(invalid("preparation repeats a bundle fetch"));
            }
        }
        let digest = canonical_digest(&projection)
            .map_err(|_| invalid("preparation cannot be canonicalized"))?;
        let preparation_ref = format!("preparation:{}", digest.as_str());
        let root_seal = serde_json::json!({
            "network": request.network,
            "resource_class": RESOURCE_CLASS,
            "resources": request.resources,
            "root_id": request.root_id,
        });
        let root_record = DefinitionRecord::canonical(
            request.root_id.as_str(),
            DefinitionKind::RootSeal,
            "physical",
            &root_seal,
            now_ms(),
        )
        .map_err(definition_error)?;
        self.plane
            .definitions
            .install(&root_record)
            .await
            .map_err(root_seal_error)?;
        let record = DefinitionRecord::canonical(
            request.root_id.as_str(),
            DefinitionKind::Preparation,
            request.session_id.as_str(),
            &projection,
            now_ms(),
        )
        .map_err(definition_error)?;
        self.plane
            .definitions
            .install(&record)
            .await
            .map_err(definition_error)?;

        // A replay for a still-cached bundle is network-free. On cache loss, every missing bundle
        // must carry a fresh one-purpose fetch authority. Admission is performed while holding the
        // cache read guard so cache bytes and concurrent reservations form one atomic bound; the
        // guard is released before any network await.
        let (missing_fetches, _fetch_reservation, _resident_borrows) = {
            let mut cache = self.preparation_cache.write().await;
            let mut missing_fetches = Vec::new();
            let mut resident_borrows = Vec::new();
            let mut fetch_bytes = 0usize;
            for (digest, seal) in &required_bundles {
                if let Some(bytes) = cache.bundle(digest) {
                    // Keep this Arc borrowed until fetched bundles are installed. Another
                    // preparation may evict unrelated idle entries while network I/O is pending,
                    // but it cannot turn this exact preparation into a post-fetch cache miss.
                    resident_borrows.push(bytes);
                    continue;
                }
                let fetch = supplied_bundles.get(digest).ok_or_else(|| {
                    error(
                        HandErrorCode::CapabilityUnavailable,
                        false,
                        "bundle cache recovery requires a fresh preparation fetch",
                    )
                })?;
                if fetch.expires_at_ms.get() <= now_ms()
                    || fetch.max_bytes.get() as usize > brain_protocol::MAX_TOOL_BUNDLE_BYTES
                    || fetch.max_bytes.get() < seal.bytes
                {
                    return Err(invalid(
                        "bundle fetch authority is expired or exceeds the bundle bound",
                    ));
                }
                fetch_bytes = fetch_bytes
                    .checked_add(fetch.max_bytes.get() as usize)
                    .ok_or_else(|| bundle_fetch_capacity_error(self.bundle_fetch_max_bytes))?;
                missing_fetches.push(fetch.clone());
            }
            let in_flight = *self
                .bundle_fetch_reserved
                .lock()
                .map_err(|_| temporary("bundle fetch admission lock is unavailable"))?;
            let cache_limit = cache.max_bundle_bytes;
            cache.evict_idle_to_fit(
                in_flight
                    .bytes
                    .checked_add(fetch_bytes)
                    .ok_or_else(|| bundle_fetch_capacity_error(self.bundle_fetch_max_bytes))?,
                in_flight
                    .entries
                    .checked_add(missing_fetches.len())
                    .ok_or_else(|| bundle_cache_capacity_error(cache_limit))?,
                &required_bundles.keys().cloned().collect(),
            )?;
            let reservation = BundleFetchReservation::admit(
                self.bundle_fetch_reserved.clone(),
                cache.bundle_bytes,
                cache.bundles.len(),
                fetch_bytes,
                missing_fetches.len(),
                cache.max_bundle_bytes,
                self.bundle_fetch_max_bytes,
            )?;
            (missing_fetches, reservation, resident_borrows)
        };
        let fetched_results =
            futures_util::stream::iter(missing_fetches.into_iter().map(|fetch| {
                let expected_bytes = required_bundles
                    .get(fetch.bundle_digest.as_str())
                    .expect("required fetch was validated")
                    .bytes;
                async move {
                    let digest = fetch.bundle_digest.to_string();
                    let bytes = fetch_bundle(self.plane.guest.http(), &fetch).await?;
                    if bytes.len() as u64 != expected_bytes {
                        return Err(invalid(
                            "fetched bundle bytes conflict with the immutable descriptor",
                        ));
                    }
                    HandResult::Ok((digest, Arc::new(bytes)))
                }
            }))
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        let mut fetched = HashMap::with_capacity(fetched_results.len());
        for result in fetched_results {
            let (digest, bytes) = result?;
            let prior = fetched.insert(digest, bytes);
            debug_assert!(prior.is_none());
        }
        let request = cacheable_preparation(request);
        self.preparation_cache
            .write()
            .await
            .install(request, digest.to_string(), fetched)?;
        Ok(PreparedSession {
            preparation_ref: preparation_ref.parse().expect("preparation ref"),
        })
    }

    async fn materialize_default(
        &self,
        request: CreateSandboxRequest,
    ) -> HandResult<SandboxStatus> {
        if request.target.kind != TargetKind::Default || request.target.sandbox_id.is_some() {
            return Err(invalid("default sandbox target is required"));
        }
        let preparation = self.preparation(request.target.session_id.as_str()).await?;
        if preparation.request.root_id != request.target.root_id {
            return Err(binding_error(
                "default sandbox target does not belong to the prepared root",
            ));
        }
        require_exact_root_seal(&request, &preparation.request)?;
        let installed = self
            .materialize(
                target_key(&request.target)?,
                request.target.session_id.as_str(),
                &preparation.request.resources,
                &preparation.request.network,
                request.resource_class.as_str(),
                MaterializationMode::ExplicitDefault(request.generation_intent.as_str()),
            )
            .await?;
        Ok(running_status(request.target, &installed))
    }

    async fn dematerialize_default(&self, target: SandboxTarget) -> HandResult<SandboxStatus> {
        if target.kind != TargetKind::Default || target.sandbox_id.is_some() {
            return Err(invalid("default sandbox target is required"));
        }
        let installed = self.resolve_target(&target, None).await?;
        self.terminate_target(&installed, "explicit default lifecycle operation")
            .await?;
        Ok(terminated_status(
            target,
            &installed,
            "explicit default lifecycle operation",
        ))
    }

    async fn purge_tree(&self, root_id: &str) -> HandResult<()> {
        const MAX_TARGETS_PER_PURGE_ATTEMPT: usize = 25;
        let page = self
            .plane
            .registry
            .list_root(root_id, None, MAX_TARGETS_PER_PURGE_ATTEMPT)
            .await
            .map_err(materialization_error)?;
        let mut unresolved_materialization = false;
        for record in page.items {
            if let Some(installed) = record.installed() {
                self.terminate_target(&installed, "root purge").await?;
                self.plane
                    .registry
                    .purge_terminal(&record.key, &record.generation)
                    .await
                    .map_err(materialization_error)?;
                continue;
            }
            match &record.state {
                DurableTargetState::Gone { .. } | DurableTargetState::Terminated { .. } => {
                    self.plane
                        .registry
                        .purge_terminal(&record.key, &record.generation)
                        .await
                        .map_err(materialization_error)?;
                }
                DurableTargetState::Materializing { .. } => {
                    let now = now_ms();
                    let lease = record.recovery_lease().map_err(materialization_error)?;
                    if lease.lease_expires_at_ms <= now {
                        // The lease includes the provider's full possible VM lifetime plus skew.
                        // Exact delete/refund is authoritative now; one retry closes an install-CAS
                        // race before definition rows are removed.
                        self.plane
                            .registry
                            .expire_lease(&lease, now)
                            .await
                            .map_err(materialization_error)?;
                        // A concurrent install can win the conditional delete. Re-read on the
                        // bounded delete retry before purging session definitions.
                        unresolved_materialization = true;
                        continue;
                    }
                    if lease.target_expires_at_ms <= now || lease.attempt_expires_at_ms > now {
                        // Do not replay after the target's provider lifetime, and do not race the
                        // worker that currently owns the short attempt. The long fence remains
                        // charged until exact recovery or the provider lifetime plus skew ends.
                        unresolved_materialization = true;
                        continue;
                    }

                    let recovery = recovery_request(&lease, now);
                    let recovered_lease = match self
                        .plane
                        .registry
                        .acquire(&recovery)
                        .await
                        .map_err(materialization_error)?
                    {
                        hand_core::materialization::AcquireOutcome::Acquired(recovered)
                            if recovered.recovery_attempt =>
                        {
                            recovered
                        }
                        hand_core::materialization::AcquireOutcome::Acquired(fresh) => {
                            // The row disappeared between the list and acquisition. `acquire`
                            // may have installed a fresh reservation, but no provider call has
                            // happened. Remove it immediately; deletion must never materialize a
                            // new target merely to discover that the old row was already gone.
                            self.plane
                                .registry
                                .expire_lease(&fresh, now)
                                .await
                                .map_err(materialization_error)?;
                            unresolved_materialization = true;
                            continue;
                        }
                        hand_core::materialization::AcquireOutcome::Installed(installed) => {
                            self.terminate_target(&installed, "root purge").await?;
                            self.plane
                                .registry
                                .purge_terminal(&installed.key, &installed.generation)
                                .await
                                .map_err(materialization_error)?;
                            continue;
                        }
                        hand_core::materialization::AcquireOutcome::Pending { .. }
                        | hand_core::materialization::AcquireOutcome::Gone
                        | hand_core::materialization::AcquireOutcome::Terminated => {
                            unresolved_materialization = true;
                            continue;
                        }
                    };

                    let launcher =
                        GenerationLauncher::from_durable(self.plane.clone(), &recovered_lease)
                            .map_err(materialization_error)?;
                    let physical = launcher
                        .launch(&recovered_lease)
                        .await
                        .map_err(recovery_launch_error)
                        .map_err(materialization_error)?;
                    let installed = match self
                        .plane
                        .registry
                        .install(&recovered_lease, &physical, now_ms())
                        .await
                        .map_err(materialization_error)?
                    {
                        hand_core::materialization::InstallOutcome::Installed(installed) => {
                            installed
                        }
                        hand_core::materialization::InstallOutcome::ReservationLost => {
                            // Root deletion owns cleanup. If another transition won the install
                            // CAS, destroy the exact recovered physical target and retry the
                            // durable projection rather than leaking it.
                            launcher
                                .terminate_stale(&physical)
                                .await
                                .map_err(temporary)?;
                            unresolved_materialization = true;
                            continue;
                        }
                    };
                    self.terminate_target(&installed, "root purge").await?;
                    self.plane
                        .registry
                        .purge_terminal(&installed.key, &installed.generation)
                        .await
                        .map_err(materialization_error)?;
                }
                DurableTargetState::Installed { .. } => unreachable!("handled above"),
            }
        }
        let targets_remain = !self
            .plane
            .registry
            .list_root(root_id, None, 1)
            .await
            .map_err(materialization_error)?
            .items
            .is_empty();
        if unresolved_materialization || targets_remain {
            return Err(temporary(
                "sandbox tree cleanup is incomplete; bounded purge will retry",
            ));
        }
        let definitions_purged = self
            .plane
            .definitions
            .purge_root_page(root_id, MAX_TARGETS_PER_PURGE_ATTEMPT)
            .await
            .map_err(definition_error)?;
        if !definitions_purged {
            return Err(temporary(
                "sandbox definition cleanup is incomplete; bounded purge will retry",
            ));
        }
        if !self
            .preparation_cache
            .write()
            .await
            .purge_root_page(root_id, MAX_TARGETS_PER_PURGE_ATTEMPT)
        {
            return Err(temporary(
                "session preparation cleanup is incomplete; bounded purge will retry",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl SandboxFilesPort for AwsHand {
    async fn status(&self, target: SandboxTarget) -> HandResult<SandboxStatus> {
        let key = target_key(&target)?;
        let record = self
            .plane
            .registry
            .get(&key)
            .await
            .map_err(materialization_error)?;
        let Some(record) = record else {
            return Ok(status_from_record(target, None));
        };
        let Some(installed) = record.installed() else {
            return Ok(status_from_record(target, Some(record)));
        };
        if now_ms() >= installed.expires_at_ms {
            let reason = "physical target hard deadline reached";
            // Hard lifetime expiry is a confirmed physical loss, not an explicit logical
            // termination. A default target may therefore get a fresh generation later, while an
            // additional target remains fenced by its durable Gone tombstone.
            self.confirm_provider_termination(&installed).await?;
            self.record_gone(&installed, reason).await?;
            return Ok(gone_status(target, &installed, reason));
        }
        match self.plane.control.get(&installed.target_ref).await {
            Ok(vm) if is_terminated(&vm.state) => {
                let reason = "provider reports physical generation gone";
                self.record_gone(&installed, reason).await?;
                Ok(gone_status(target, &installed, reason))
            }
            Ok(vm) => {
                let mut status = status_from_record(target, Some(record));
                // The provider exposes only the state observed by this GetMicrovm call. It does
                // not expose when auto-suspend occurred, so preserve the durable registry
                // timestamp rather than fabricating a suspension transition timestamp.
                status.state = sandbox_state_from_provider(&vm.state)?;
                Ok(status)
            }
            Err(ControlError::Gone(_)) => {
                let reason = "provider reports physical generation gone";
                self.record_gone(&installed, reason).await?;
                Ok(gone_status(target, &installed, reason))
            }
            Err(error_value) => Err(control_error(error_value)),
        }
    }

    async fn list(&self, request: SandboxFileListRequest) -> HandResult<SandboxFileList> {
        let installed = self
            .resolve_target(&request.target, Some(&request.expected_generation))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::ListFiles(request))
            .await?
        {
            ResponseReply::ListFiles(value) => Ok(value),
            _ => Err(wrong_reply("list")),
        }
    }

    async fn stat(&self, request: SandboxFileRequest) -> HandResult<FileEntry> {
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::StatFile(request))
            .await?
        {
            ResponseReply::StatFile(value) => Ok(value),
            _ => Err(wrong_reply("stat")),
        }
    }

    async fn read(&self, request: SandboxFileRequest) -> HandResult<SandboxFileContent> {
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::ReadFile(request))
            .await?
        {
            ResponseReply::ReadFile(value) => Ok(value),
            _ => Err(wrong_reply("read")),
        }
    }

    async fn write(&self, request: SandboxFileWriteRequest) -> HandResult<SandboxFileWriteResult> {
        if sandbox_file_write_request_digest(&request) != request.request_digest {
            return Err(invalid(
                "sandbox file write request_digest is not canonical",
            ));
        }
        let lock = file_effect_lock_index(request.operation_id.as_str());
        let _guard = self.file_effect_locks[lock].lock().await;
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        let identity = FileEffectIdentity {
            kind: FileEffectKind::Write,
            operation_id: request.operation_id.to_string(),
            request_digest: request.request_digest.to_string(),
        };
        match self.reserve_file_effect(&installed, identity).await? {
            FileEffectReservation::Replay(result) => {
                let FileEffectStoredResult::Write(result) = *result else {
                    return Err(temporary("guest replayed the wrong file effect kind"));
                };
                return Ok(result);
            }
            FileEffectReservation::New => {}
        }
        if let SandboxFileWriteSource::Object { object, fetch } = &request.source {
            let staged = fetch_object(self.plane.guest.http(), fetch, object).await?;
            let result = self.install_object(&installed, object, &staged).await;
            self.settle_guest_result(&installed, result).await?;
            // The guest receives the original immutable reference and finds the verified staged
            // bytes by digest. The one-purpose authority is never dereferenced by untrusted code.
        }
        match self
            .guest_rpc(
                &installed,
                RequestCall::WriteFile(project_guest_file_write(request)),
            )
            .await?
        {
            ResponseReply::WriteFile(FileEffectStoredResult::Write(value)) => Ok(value),
            _ => Err(wrong_reply("write")),
        }
    }

    async fn find(&self, request: SandboxSearchRequest) -> HandResult<SandboxFileList> {
        let installed = self
            .resolve_target(&request.target, Some(&request.expected_generation))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::FindFiles(request))
            .await?
        {
            ResponseReply::FindFiles(value) => Ok(value),
            _ => Err(wrong_reply("find")),
        }
    }

    async fn grep(&self, request: SandboxSearchRequest) -> HandResult<SandboxFileList> {
        let installed = self
            .resolve_target(&request.target, Some(&request.expected_generation))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::GrepFiles(request))
            .await?
        {
            ResponseReply::GrepFiles(value) => Ok(value),
            _ => Err(wrong_reply("grep")),
        }
    }

    async fn transfer(&self, request: SandboxCopyRequest) -> HandResult<SandboxCopyResult> {
        if sandbox_copy_request_digest(&request) != request.request_digest {
            return Err(invalid("sandbox copy request_digest is not canonical"));
        }
        let lock = file_effect_lock_index(request.operation_id.as_str());
        let _guard = self.file_effect_locks[lock].lock().await;
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        let effect_kind = match request.direction {
            SandboxCopyRequestDirection::Import => FileEffectKind::CopyImport,
            SandboxCopyRequestDirection::Export => FileEffectKind::CopyExport,
        };
        let identity = file_effect_identity(&request, effect_kind);
        match self
            .reserve_file_effect(&installed, identity.clone())
            .await?
        {
            FileEffectReservation::Replay(result) => {
                let FileEffectStoredResult::Copy(result) = *result else {
                    return Err(temporary("guest replayed the wrong copy effect kind"));
                };
                return Ok(result);
            }
            FileEffectReservation::New => {}
        }
        match request.direction {
            SandboxCopyRequestDirection::Import => {
                let object = request
                    .object
                    .as_ref()
                    .ok_or_else(|| invalid("import requires an object reference"))?;
                let staged =
                    fetch_object(self.plane.guest.http(), &request.transfer, object).await?;
                let result = self.install_object(&installed, object, &staged).await;
                self.settle_guest_result(&installed, result).await?;
                let write = GuestFileWriteRequest {
                    effect: identity,
                    expected_generation: request.expected_generation.to_string(),
                    overwrite: request.overwrite,
                    path: request.path.to_string(),
                    source: GuestFileWriteSource::InstalledObject {
                        object: object.clone(),
                    },
                    target: request.target,
                };
                match self
                    .guest_rpc(&installed, RequestCall::WriteFile(write))
                    .await?
                {
                    ResponseReply::WriteFile(FileEffectStoredResult::Copy(result)) => Ok(result),
                    _ => Err(wrong_reply("import")),
                }
            }
            SandboxCopyRequestDirection::Export => {
                let read: SandboxFileRequest = serde_json::from_value(serde_json::json!({
                    "expected_generation": request.expected_generation,
                    "path": request.path,
                    "target": request.target
                }))
                .map_err(|_| invalid("export request cannot be projected"))?;
                validate_transfer_authority(
                    &request.transfer,
                    ObjectTransferAuthorityMethod::Put,
                    0,
                )?;
                let result = self.plane.guest.export_file(&installed, &read).await;
                let (mut file, response) = self.settle_guest_result(&installed, result).await?;
                let staged = stage_response(
                    response,
                    request.transfer.max_bytes.get().min(MAX_OBJECT_BYTES),
                    request.transfer.expires_at_ms.get(),
                )
                .await?;
                match self.claim_file_effect(&installed, identity).await? {
                    FileEffectReservation::Replay(result) => {
                        let FileEffectStoredResult::Copy(result) = *result else {
                            return Err(temporary("guest replayed the wrong copy claim kind"));
                        };
                        return Ok(result);
                    }
                    FileEffectReservation::New => {}
                }
                put_object(self.plane.guest.http(), &request.transfer, &staged).await?;
                // The Tool may mutate an open file while it is copied. Publish the exact streamed
                // snapshot identity, not stale pre-stream metadata from the opened path.
                file.bytes = staged.bytes;
                file.sha256 = Some(staged.sha256.parse().expect("digest"));
                let object = ObjectReference {
                    bytes: staged.bytes,
                    media_type: None,
                    object_id: request.transfer.object_id.clone(),
                    sha256: staged.sha256.parse().expect("digest"),
                };
                let result = SandboxCopyResult {
                    file,
                    object: Some(object),
                    operation_id: request.operation_id,
                    replayed: false,
                    request_digest: request.request_digest,
                };
                match self
                    .guest_rpc(
                        &installed,
                        RequestCall::CompleteFileEffect(FileEffectStoredResult::Copy(result)),
                    )
                    .await?
                {
                    ResponseReply::CompleteFileEffect(FileEffectStoredResult::Copy(result)) => {
                        Ok(result)
                    }
                    _ => Err(wrong_reply("copy completion")),
                }
            }
        }
    }
}

#[async_trait]
impl SandboxControlPort for AwsHand {
    async fn create(&self, request: CreateSandboxRequest) -> HandResult<SandboxStatus> {
        require_additional_target(&request.target)?;
        let preparation = self.preparation(request.target.session_id.as_str()).await?;
        if preparation.request.root_id != request.target.root_id {
            return Err(binding_error(
                "additional sandbox target does not belong to the prepared root",
            ));
        }
        validate_resource_ceiling_subset(&request.resources, &preparation.request.resources)?;
        if !network_ceiling_is_subset(&request.network, &preparation.request.network) {
            return Err(error(
                HandErrorCode::GenerationConflict,
                false,
                "additional sandbox network policy widens the immutable root seal",
            ));
        }
        let key = target_key(&request.target)?;
        let installed = self
            .materialize(
                key,
                request.target.session_id.as_str(),
                &request.resources,
                &request.network,
                request.resource_class.as_str(),
                MaterializationMode::Additional(request.generation_intent.as_str()),
            )
            .await?;
        Ok(running_status(request.target, &installed))
    }

    async fn inspect(&self, target: SandboxTarget) -> HandResult<SandboxStatus> {
        require_additional_target(&target)?;
        SandboxFilesPort::status(self, target).await
    }

    async fn execute(&self, request: SandboxExecutionRequest) -> HandResult<SubmitReceipt> {
        require_additional_target(&request.target)?;
        if sandbox_execution_request_digest(&request) != request.request_digest {
            return Err(invalid("sandbox execution request_digest is not canonical"));
        }
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::ExecuteSandbox(request))
            .await?
        {
            ResponseReply::ExecuteSandbox(receipt) => Ok(receipt),
            _ => Err(wrong_reply("execute")),
        }
    }

    async fn write_stdin(&self, request: WriteStdinRequest) -> HandResult<WriteStdinReceipt> {
        require_additional_target(&request.target)?;
        if write_stdin_request_digest(&request) != request.request_digest {
            return Err(invalid("write_stdin request_digest is not canonical"));
        }
        if request.text.len() > brain_protocol::MAX_WRITE_STDIN_BYTES {
            return Err(invalid(format!(
                "write_stdin text exceeds the {}-byte atomic bound",
                brain_protocol::MAX_WRITE_STDIN_BYTES
            )));
        }
        let installed = self
            .resolve_target(&request.target, Some(request.expected_generation.as_str()))
            .await?;
        match self
            .guest_rpc(&installed, RequestCall::WriteStdin(request))
            .await?
        {
            ResponseReply::WriteStdin(receipt) => Ok(receipt),
            _ => Err(wrong_reply("stdin")),
        }
    }

    async fn terminate(&self, target: SandboxTarget) -> HandResult<SandboxStatus> {
        require_additional_target(&target)?;
        let installed = self.resolve_target(&target, None).await?;
        self.terminate_target(&installed, "explicit additional lifecycle operation")
            .await?;
        Ok(terminated_status(
            target,
            &installed,
            "explicit additional lifecycle operation",
        ))
    }
}

fn require_additional_target(target: &SandboxTarget) -> HandResult<()> {
    if target.kind != TargetKind::Additional || target.sandbox_id.is_none() {
        return Err(invalid("additional sandbox target is required"));
    }
    Ok(())
}

fn project_guest_file_write(request: SandboxFileWriteRequest) -> GuestFileWriteRequest {
    GuestFileWriteRequest {
        effect: FileEffectIdentity {
            kind: FileEffectKind::Write,
            operation_id: request.operation_id.to_string(),
            request_digest: request.request_digest.to_string(),
        },
        expected_generation: request.expected_generation.to_string(),
        overwrite: request.overwrite,
        path: request.path.to_string(),
        source: match request.source {
            SandboxFileWriteSource::Inline { content_base64 } => GuestFileWriteSource::Inline {
                content_base64: content_base64.to_string(),
            },
            SandboxFileWriteSource::Object { object, .. } => {
                GuestFileWriteSource::InstalledObject { object }
            }
        },
        target: request.target,
    }
}

fn file_effect_identity(request: &SandboxCopyRequest, kind: FileEffectKind) -> FileEffectIdentity {
    FileEffectIdentity {
        kind,
        operation_id: request.operation_id.to_string(),
        request_digest: request.request_digest.to_string(),
    }
}

fn file_effect_lock_index(operation_id: &str) -> usize {
    shard_index(&[operation_id], FILE_EFFECT_LOCK_SHARDS)
}

struct GenerationLauncher {
    plane: Arc<HandPlane>,
    key: TargetKey,
    owner_session_id: String,
    resources: ResourceCeiling,
    network: NetworkCeiling,
    resource_class: String,
}

/// Full RunMicrovm parameter projection. It intentionally has no `Debug`: the nested run-hook
/// payload can contain the allowlist gateway bearer for this one private-network target generation.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SealedProviderLaunch {
    image_identity: String,
    dispatch_deadline_at_ms: u64,
    request: ExactRunMicrovmRequest,
}

impl GenerationLauncher {
    fn from_durable(
        plane: Arc<HandPlane>,
        lease: &MaterializationLease,
    ) -> Result<Self, MaterializationError> {
        let sealed: SealedProviderLaunch = serde_json::from_str(lease.launch_request.expose())
            .map_err(|_| {
                MaterializationError::LaunchOutcomeUnknown(
                    "durable provider launch request is corrupt".into(),
                )
            })?;
        let payload: RunPayload =
            serde_json::from_str(&sealed.request.run_hook_payload).map_err(|_| {
                MaterializationError::LaunchOutcomeUnknown("durable run payload is corrupt".into())
            })?;
        Ok(Self {
            plane,
            key: lease.key.clone(),
            owner_session_id: payload.owner_session_id,
            resources: payload.resources,
            network: payload.network,
            resource_class: payload.resource_class,
        })
    }

    async fn seal_launch(&self, lease: &MaterializationLease) -> HandResult<DurableLaunchRequest> {
        let connector = connector_class(&self.network);
        let allowlist_proxy = if let NetworkCeiling::Allowlist(destinations) = &self.network {
            let issued_at_ms = now_ms();
            let capability = Capability {
                root_id: self.key.root_id.clone(),
                session_id: self.owner_session_id.clone(),
                sandbox_id: sandbox_identity(&self.key)?,
                generation: lease.generation.clone(),
                issued_at_ms,
                // The grant never outlives Brain's journaled physical target deadline. That
                // deadline is conservative (computed before KMS and provider dispatch), so it is
                // also no later than the provider's eight-hour VM wall.
                expires_at_ms: lease.target_expires_at_ms,
                policy_digest: canonical_digest(&self.network)
                    .expect("network is canonicalizable")
                    .to_string(),
                destinations: capability_destinations(destinations)?,
            };
            Some(AllowlistProxy {
                authority: self.plane.cfg.egress_gateway_authority.as_authority(),
                capability: self.plane.sign_capability(&capability).await?,
            })
        } else {
            None
        };
        let payload = RunPayload {
            contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
            generation: lease.generation.clone(),
            expires_at_ms: lease.target_expires_at_ms,
            root_id: self.key.root_id.clone(),
            owner_session_id: self.owner_session_id.clone(),
            connector,
            resource_class: self.resource_class.clone(),
            resources: self.resources.clone(),
            network: self.network.clone(),
            control_token: ControlToken::new(format!(
                "control-{}",
                hex::encode(rand::random::<[u8; 32]>())
            ))
            .expect("random control token satisfies its exact grammar"),
            allowlist_proxy,
            canary_exit_after_operation_id: None,
        };
        let image_arn = self.plane.image_arn().await?;
        let image_version = self.plane.cfg.image_version.clone();
        let connector_ref = self.plane.cfg.connectors.resolve(connector).clone();
        let run_hook_payload = launch::run_payload(&payload)
            .map_err(|_| invalid("provider launch payload cannot be encoded"))?;
        let request = self.plane.control.exact_run_request(
            &image_arn,
            &image_version,
            &run_hook_payload,
            &lease.reservation_id,
            &connector_ref,
        );
        let sealed = SealedProviderLaunch {
            image_identity: lease.spec.image_identity.clone(),
            dispatch_deadline_at_ms: launch_dispatch_deadline(lease)
                .map_err(materialization_error)?,
            request,
        };
        let bytes = serde_jcs::to_vec(&sealed)
            .map_err(|_| invalid("provider launch request cannot be sealed"))?;
        let encoded = String::from_utf8(bytes)
            .map_err(|_| invalid("provider launch request is not UTF-8"))?;
        DurableLaunchRequest::new(encoded)
            .map_err(|error| materialization_error(error.into()))
    }

    fn decode_launch(
        &self,
        lease: &MaterializationLease,
    ) -> Result<SealedProviderLaunch, LaunchError> {
        let sealed: SealedProviderLaunch = serde_json::from_str(lease.launch_request.expose())
            .map_err(|_| LaunchError::OutcomeUnknown("durable launch request is corrupt".into()))?;
        let payload: RunPayload = serde_json::from_str(&sealed.request.run_hook_payload)
            .map_err(|_| LaunchError::OutcomeUnknown("durable run payload is corrupt".into()))?;
        let resource_digest = canonical_digest(&payload.resources)
            .map_err(|_| LaunchError::OutcomeUnknown("durable resource seal is corrupt".into()))?;
        let network_digest = canonical_digest(&payload.network)
            .map_err(|_| LaunchError::OutcomeUnknown("durable network seal is corrupt".into()))?;
        let expected_dispatch_deadline = launch_dispatch_deadline(lease)
            .map_err(|error| LaunchError::OutcomeUnknown(error.to_string()))?;
        if payload.contract_digest != HAND_CONTRACT_DIGEST.trim()
            || payload.generation != lease.generation
            || payload.expires_at_ms != lease.target_expires_at_ms
            || payload.root_id != lease.key.root_id
            || payload.connector != lease.spec.connector
            || payload.resource_class != lease.spec.resource_class
            || sealed.image_identity != lease.spec.image_identity
            || sealed.dispatch_deadline_at_ms != expected_dispatch_deadline
            || resource_digest.as_str() != lease.spec.resource_policy_digest
            || network_digest.as_str() != lease.spec.network_policy_digest
            || payload.canary_exit_after_operation_id.is_some()
            || sealed.request.image_identifier.is_empty()
            || sealed.request.client_token != lease.reservation_id
        {
            return Err(LaunchError::OutcomeUnknown(
                "durable provider launch request conflicts with the target seal".into(),
            ));
        }
        if self
            .plane
            .control
            .validate_exact_run_request(&sealed.request)
            .is_err()
        {
            return Err(LaunchError::OutcomeUnknown(
                "durable provider request is outside the sealed exact RunMicrovm boundary".into(),
            ));
        }
        Ok(sealed)
    }
}

fn recovery_request(lease: &MaterializationLease, now_ms: u64) -> AcquireTarget {
    AcquireTarget {
        key: lease.key.clone(),
        spec: lease.spec.clone(),
        reservation_id: lease.reservation_id.clone(),
        generation: lease.generation.clone(),
        launch_request: lease.launch_request.clone(),
        attempt_id: random_identifier("purge-attempt"),
        attempt_duration_ms: TARGET_ATTEMPT_MS,
        generation_is_fenced: true,
        now_ms,
        lease_duration_ms: TARGET_LEASE_MS,
        target_lifetime_ms: TARGET_LIFETIME_MS,
        // Deletion is reconciliation of one exact existing row. It must never replace a gone
        // default target or create a fresh physical generation.
        replace_after_loss: false,
    }
}

fn recovery_launch_error(error_value: LaunchError) -> MaterializationError {
    match error_value {
        LaunchError::Capacity {
            scope,
            retry_after_ms,
            message,
        } => MaterializationError::Capacity {
            scope,
            retry_after_ms,
            message,
        },
        LaunchError::KnownNoTarget(message) => MaterializationError::LaunchOutcomeUnknown(format!(
            "exact launch recovery returned no target; reservation remains fenced: {message}"
        )),
        LaunchError::RetryableKnownNoTarget(message) => {
            MaterializationError::LaunchRetryable(message)
        }
        LaunchError::OutcomeUnknown(message) => MaterializationError::LaunchOutcomeUnknown(message),
    }
}

#[async_trait]
impl PhysicalTargetLauncher for GenerationLauncher {
    async fn launch(&self, lease: &MaterializationLease) -> Result<PhysicalTarget, LaunchError> {
        let sealed = self.decode_launch(lease)?;
        let control_token = serde_json::from_str::<RunPayload>(&sealed.request.run_hook_payload)
            .map_err(|_| LaunchError::OutcomeUnknown("durable run payload is corrupt".into()))?
            .control_token;
        admit_provider_dispatch(lease, sealed.dispatch_deadline_at_ms, now_ms())?;
        let hand = launch::launch_exact(&self.plane.control, &sealed.request)
            .await
            .map_err(|failure| match failure {
                LaunchFailure::Run(ControlError::Capacity {
                    scope,
                    retry_after_ms,
                    message,
                }) => LaunchError::Capacity {
                    scope,
                    retry_after_ms,
                    message,
                },
                LaunchFailure::Run(ControlError::Unknown(message)) => {
                    LaunchError::OutcomeUnknown(message)
                }
                LaunchFailure::Run(ControlError::Retryable(message))
                | LaunchFailure::Run(ControlError::Throttled(message)) => {
                    LaunchError::RetryableKnownNoTarget(message)
                }
                LaunchFailure::Run(ControlError::Fatal(message))
                | LaunchFailure::Run(ControlError::Gone(message)) => {
                    LaunchError::KnownNoTarget(message)
                }
            })?;
        PhysicalTarget::new(hand.microvm_id, lease.generation.clone(), control_token)
            .map_err(|error| LaunchError::OutcomeUnknown(error.to_string()))
    }

    async fn terminate_stale(&self, target: &PhysicalTarget) -> Result<(), String> {
        self.plane
            .control
            .terminate(&target.target_ref)
            .await
            .map_err(|error| error.to_string())
    }
}

fn launch_dispatch_deadline(lease: &MaterializationLease) -> Result<u64, MaterializationError> {
    let reserved_at_ms = lease
        .target_expires_at_ms
        .checked_sub(TARGET_LIFETIME_MS)
        .ok_or(MaterializationError::InvalidLease)?;
    let deadline = reserved_at_ms
        .checked_add(TARGET_DISPATCH_WINDOW_MS)
        .ok_or(MaterializationError::InvalidLease)?;
    if deadline >= lease.lease_expires_at_ms
        || lease.lease_expires_at_ms.saturating_sub(deadline) < TARGET_LIFETIME_MS
    {
        return Err(MaterializationError::InvalidLease);
    }
    Ok(deadline)
}

fn admit_provider_dispatch(
    lease: &MaterializationLease,
    dispatch_deadline_at_ms: u64,
    now_ms: u64,
) -> Result<(), LaunchError> {
    if now_ms <= dispatch_deadline_at_ms {
        return Ok(());
    }
    if lease.recovery_attempt {
        Err(LaunchError::OutcomeUnknown(
            "exact launch recovery window elapsed; possible target remains capacity-fenced".into(),
        ))
    } else {
        Err(LaunchError::KnownNoTarget(
            "provider dispatch deadline elapsed before the first RunMicrovm call".into(),
        ))
    }
}

fn target_spec(
    cfg: &HandPlaneConfig,
    resources: &ResourceCeiling,
    network: &NetworkCeiling,
    resource_class: &str,
) -> HandResult<TargetSpec> {
    if resources.max_output_bytes.get() > brain_protocol::MAX_TOOL_TERMINAL_INLINE_BYTES as u64
        || resources.timeout_ms.get() > TARGET_LIFETIME_MS
    {
        return Err(error(
            HandErrorCode::CapabilityUnavailable,
            false,
            "the selected target cannot enforce the requested resource ceiling",
        ));
    }
    TargetSpec::new(
        connector_class(network),
        format!("{}@{}", cfg.image, cfg.image_version),
        resource_class,
        TARGET_MEMORY_MIB,
        canonical_digest(resources)
            .map_err(|_| invalid("resource seal cannot be canonicalized"))?
            .to_string(),
        canonical_digest(network)
            .map_err(|_| invalid("network seal cannot be canonicalized"))?
            .to_string(),
    )
    .map_err(materialization_error)
}

fn validate_resource_ceiling_subset(
    request: &ResourceCeiling,
    physical: &ResourceCeiling,
) -> HandResult<()> {
    if request.timeout_ms > physical.timeout_ms
        || request.max_output_bytes > physical.max_output_bytes
    {
        return Err(error(
            HandErrorCode::GenerationConflict,
            false,
            "sandbox resources widen the immutable root target seal",
        ));
    }
    Ok(())
}

fn validate_operation_root_seal(
    envelope: &brain_protocol::hand::OperationEnvelope,
    preparation: &PrepareSessionRequest,
) -> HandResult<()> {
    validate_resource_ceiling_subset(&envelope.resources, &preparation.resources)?;
    if !network_ceiling_is_subset(&envelope.network, &preparation.network) {
        return Err(error(
            HandErrorCode::GenerationConflict,
            false,
            "operation network policy widens the immutable root target seal",
        ));
    }
    Ok(())
}

fn require_exact_root_seal(
    request: &CreateSandboxRequest,
    preparation: &PrepareSessionRequest,
) -> HandResult<()> {
    if request.resource_class.as_str() != RESOURCE_CLASS
        || canonical_digest(&request.resources)
            .map_err(|_| invalid("resource seal cannot be canonicalized"))?
            != canonical_digest(&preparation.resources)
                .map_err(|_| invalid("prepared resource seal cannot be canonicalized"))?
        || canonical_digest(&request.network)
            .map_err(|_| invalid("network seal cannot be canonicalized"))?
            != canonical_digest(&preparation.network)
                .map_err(|_| invalid("prepared network seal cannot be canonicalized"))?
    {
        return Err(error(
            HandErrorCode::GenerationConflict,
            false,
            "default sandbox must use the immutable prepared root seal",
        ));
    }
    Ok(())
}

fn validate_inline_input(input: &brain_protocol::hand::OperationInput) -> HandResult<()> {
    if input.kind != serde_json::Value::String("inline".into()) {
        return Err(invalid("managed Tool input kind must be inline"));
    }
    let encoded = serde_jcs::to_vec(input)
        .map_err(|_| invalid("managed Tool input cannot be canonicalized"))?;
    if encoded.len() > brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES {
        return Err(invalid(format!(
            "managed Tool input exceeds the {}-byte canonical bound",
            brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES
        )));
    }
    Ok(())
}

fn validate_prepared_binding_projection(
    prepared: &PreparedBindingBundles,
    binding: &SealedBinding,
    root_id: &str,
    session_id: &str,
) -> HandResult<ValidatedPreparedBundle> {
    if binding.root_id.as_str() != root_id || binding.session_id.as_str() != session_id {
        return Err(binding_error(
            "prepared binding is outside the exact root/session scope",
        ));
    }
    let descriptor = validate_managed_binding(binding)?;
    if prepared.bundle_digests.len() != 1 || prepared.bundle_digests[0] != descriptor.bundle_digest
    {
        return Err(binding_error(
            "prepared bundle digests do not match the immutable binding descriptor",
        ));
    }
    let descriptor_digest = canonical_digest(descriptor)
        .map_err(|_| binding_error("bundle descriptor cannot be canonicalized"))?;
    Ok(ValidatedPreparedBundle {
        bytes: descriptor.bytes.get(),
        descriptor_digest: descriptor_digest.to_string(),
        digest: descriptor.bundle_digest.to_string(),
    })
}

/// Rejects malformed or internally inconsistent immutable implementation metadata before it can
/// become a durable binding definition. The guest repeats the byte/digest checks at installation,
/// immediately before the first import of customer code.
fn validate_managed_binding(binding: &SealedBinding) -> HandResult<&BundleDescriptor> {
    let descriptor = binding.bundle.as_ref().ok_or_else(|| {
        error(
            HandErrorCode::CapabilityUnavailable,
            false,
            "the AWS Hand accepts only Aex-managed immutable Node22 bundles",
        )
    })?;
    if binding.realm != ExecutionRealm::AexManaged
        || descriptor.runtime != BundleRuntime::Node22
        || descriptor.contract_digest != binding.contract_digest
    {
        return Err(error(
            HandErrorCode::CapabilityUnavailable,
            false,
            "the AWS Hand accepts only Aex-managed immutable Node22 bundles with an exact contract seal",
        ));
    }
    if descriptor.bytes.get() > brain_protocol::MAX_TOOL_BUNDLE_BYTES as u64
        || descriptor.object.bytes != descriptor.bytes.get()
        || descriptor.object.sha256 != descriptor.bundle_digest
    {
        return Err(binding_error(
            "bundle descriptor size or object digest conflicts with its immutable bundle seal",
        ));
    }
    if descriptor.required_env.len() > brain_protocol::MAX_SESSION_SECRET_NAMES {
        return Err(binding_error(
            "bundle descriptor exceeds the required environment-name bound",
        ));
    }
    let mut env_names = HashSet::with_capacity(descriptor.required_env.len());
    if descriptor.required_env.iter().any(|name| {
        !environment_name_is_valid(name.as_str())
            || reserved_tool_environment(name.as_str())
            || !env_names.insert(name.as_str())
    }) {
        return Err(binding_error(
            "bundle descriptor has invalid, reserved, or repeated environment names",
        ));
    }
    let mut capabilities = HashSet::with_capacity(binding.required_capabilities.len());
    if binding
        .required_capabilities
        .iter()
        .any(|capability| !capabilities.insert(*capability))
    {
        return Err(binding_error("binding repeats a required capability"));
    }
    Ok(descriptor)
}

fn merge_validated_prepared_bundle(
    required: &mut HashMap<String, ValidatedPreparedBundle>,
    bundle: ValidatedPreparedBundle,
) -> HandResult<()> {
    if let Some(existing) = required.get(&bundle.digest)
        && existing.descriptor_digest != bundle.descriptor_digest
    {
        return Err(binding_error(
            "one bundle digest is sealed by conflicting immutable descriptors",
        ));
    }
    required.insert(bundle.digest.clone(), bundle);
    Ok(())
}

fn required_bundle_digests(request: &PrepareSessionRequest) -> HandResult<HashSet<String>> {
    let mut required = HashSet::new();
    for binding in &request.bindings {
        for digest in &binding.bundle_digests {
            required.insert(digest.to_string());
            if required.len() > MAX_PREPARED_BUNDLES {
                return Err(invalid("preparation exceeds the unique bundle bound"));
            }
        }
    }
    Ok(required)
}

fn preparation_cache_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process session preparation metadata budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_preparation_cache_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value.details.insert(
        "entry_limit".into(),
        (MAX_CACHED_PREPARATIONS as u64).into(),
    );
    value
}

fn bundle_cache_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process verified bundle memory budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_cache_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value
}

fn bundle_fetch_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process cold bundle fetch budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_fetch_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value
}

fn bundle_cache_entry_capacity_error() -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process verified bundle entry budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_cache_entries".into());
    value
        .details
        .insert("limit".into(), (MAX_CACHED_BUNDLES as u64).into());
    value
}

fn connector_class(network: &NetworkCeiling) -> ConnectorClass {
    match network {
        NetworkCeiling::None => ConnectorClass::None,
        NetworkCeiling::Public => ConnectorClass::Public,
        NetworkCeiling::Allowlist(_) => ConnectorClass::Allowlist,
    }
}

fn capability_destinations(
    items: &[NetworkCeilingDestinationsItem],
) -> HandResult<Vec<CapabilityDestination>> {
    items
        .iter()
        .map(|item| match item {
            NetworkCeilingDestinationsItem::Tls { host, .. } => Ok(CapabilityDestination {
                host: Some(host.as_str().into()),
                cidr: None,
                ports: vec![443],
                protocol: DestinationProtocol::Tls,
            }),
            NetworkCeilingDestinationsItem::Tcp { cidr, ports } => Ok(CapabilityDestination {
                host: None,
                cidr: Some(
                    cidr.as_str()
                        .parse::<Ipv4Net>()
                        .map_err(|_| invalid("allowlist CIDR is invalid"))?,
                ),
                ports: ports
                    .iter()
                    .map(|port| {
                        u16::try_from(port.get()).map_err(|_| invalid("allowlist port is invalid"))
                    })
                    .collect::<HandResult<Vec<_>>>()?,
                protocol: DestinationProtocol::Tcp,
            }),
        })
        .collect()
}

async fn fetch_bundle(http: &reqwest::Client, fetch: &BundleFetch) -> HandResult<Vec<u8>> {
    if fetch.expires_at_ms.get() <= now_ms()
        || fetch.max_bytes.get() as usize > brain_protocol::MAX_TOOL_BUNDLE_BYTES
    {
        return Err(invalid(
            "bundle fetch authority is expired or exceeds the bundle bound",
        ));
    }
    let response = authorized_get(
        http,
        fetch.url.as_str(),
        fetch
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        fetch.expires_at_ms.get(),
    )
    .await?;
    let staged = stage_response(response, fetch.max_bytes.get(), fetch.expires_at_ms.get()).await?;
    let bytes = tokio::fs::read(staged.file.path())
        .await
        .map_err(|_| temporary("verified bundle staging is unavailable"))?;
    if hex::encode(Sha256::digest(&bytes)) != fetch.bundle_digest.as_str() {
        return Err(invalid("fetched bundle does not match its digest"));
    }
    Ok(bytes)
}

async fn fetch_object(
    http: &reqwest::Client,
    authority: &ObjectTransferAuthority,
    object: &ObjectReference,
) -> HandResult<StagedObject> {
    if authority.object_id != object.object_id {
        return Err(invalid(
            "object fetch authority is sealed to a different object identity",
        ));
    }
    validate_transfer_authority(authority, ObjectTransferAuthorityMethod::Get, object.bytes)?;
    let response = authorized_get(
        http,
        authority.url.as_str(),
        authority
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        authority.expires_at_ms.get(),
    )
    .await?;
    let staged = stage_response(response, object.bytes, authority.expires_at_ms.get()).await?;
    if staged.bytes != object.bytes || staged.sha256 != object.sha256.as_str() {
        return Err(invalid(
            "downloaded object does not match its immutable reference",
        ));
    }
    Ok(staged)
}

async fn authorized_get<'a>(
    http: &reqwest::Client,
    url: &str,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
    expires_at_ms: u64,
) -> HandResult<reqwest::Response> {
    let url = validate_https_authority_url(url)?;
    let request = apply_authority_headers(http.get(url), headers)?;
    let timeout = transfer_timeout(expires_at_ms)?;
    let response = request
        .timeout(timeout)
        .send()
        .await
        .map_err(|_| temporary("authorized object download failed"))?;
    if !response.status().is_success() {
        return Err(temporary("authorized object download was refused"));
    }
    Ok(response)
}

async fn stage_response(
    response: reqwest::Response,
    limit: u64,
    expires_at_ms: u64,
) -> HandResult<StagedObject> {
    if limit > MAX_OBJECT_BYTES {
        return Err(invalid(
            "authorized object exceeds the 512 MiB transfer bound",
        ));
    }
    if response.content_length().is_some_and(|bytes| bytes > limit) {
        return Err(error(
            HandErrorCode::ResourceExhausted,
            false,
            "authorized object exceeds its byte bound",
        ));
    }
    let file = tempfile::NamedTempFile::new()
        .map_err(|_| temporary("supervisor object staging is unavailable"))?;
    let std_file = file
        .reopen()
        .map_err(|_| temporary("supervisor object staging is unavailable"))?;
    let mut output = tokio::fs::File::from_std(std_file);
    let mut bytes = 0u64;
    let mut hash = Sha256::new();
    let mut stream = response.bytes_stream();
    loop {
        // `Response::bytes_stream` may remain pending without yielding another chunk. Bound that
        // wait itself by the one-purpose authority deadline; checking only after a chunk arrives
        // would let a stalled guest export hold supervisor resources after its grant expired.
        let wait = transfer_timeout(expires_at_ms)?;
        let next = tokio::time::timeout(wait, stream.next())
            .await
            .map_err(|_| {
                if now_ms() >= expires_at_ms {
                    invalid("object transfer authority expired during download")
                } else {
                    temporary("authorized object stream exceeded its bounded transfer wait")
                }
            })?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_| temporary("authorized object stream failed"))?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes > limit {
            return Err(error(
                HandErrorCode::ResourceExhausted,
                false,
                "authorized object exceeds its byte bound",
            ));
        }
        hash.update(&chunk);
        tokio::io::AsyncWriteExt::write_all(&mut output, &chunk)
            .await
            .map_err(|_| temporary("supervisor object staging failed"))?;
    }
    tokio::io::AsyncWriteExt::flush(&mut output)
        .await
        .map_err(|_| temporary("supervisor object staging failed"))?;
    output
        .sync_all()
        .await
        .map_err(|_| temporary("supervisor object staging sync failed"))?;
    drop(output);
    Ok(StagedObject {
        file,
        bytes,
        sha256: hex::encode(hash.finalize()),
    })
}

async fn put_object(
    http: &reqwest::Client,
    authority: &ObjectTransferAuthority,
    staged: &StagedObject,
) -> HandResult<()> {
    validate_transfer_authority(authority, ObjectTransferAuthorityMethod::Put, staged.bytes)?;
    let url = validate_https_authority_url(authority.url.as_str())?;
    let file = tokio::fs::File::open(staged.file.path())
        .await
        .map_err(|_| temporary("supervisor object staging is unavailable"))?;
    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(
        tokio::io::AsyncReadExt::take(file, staged.bytes.saturating_add(1)),
    ));
    let request = apply_authority_headers(
        http.put(url),
        authority
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )?;
    let response = request
        .header(reqwest::header::CONTENT_LENGTH, staged.bytes)
        .body(body)
        .timeout(transfer_timeout(authority.expires_at_ms.get())?)
        .send()
        .await
        .map_err(|_| temporary("authorized object upload failed"))?;
    if response.status().is_success() && now_ms() < authority.expires_at_ms.get() {
        Ok(())
    } else {
        Err(temporary("authorized object upload was refused"))
    }
}

fn validate_transfer_authority(
    authority: &ObjectTransferAuthority,
    method: ObjectTransferAuthorityMethod,
    required_bytes: u64,
) -> HandResult<()> {
    if authority.method != method
        || authority.expires_at_ms.get() <= now_ms()
        || authority.max_bytes.get() < required_bytes
        || authority.max_bytes.get() > MAX_OBJECT_BYTES
        || required_bytes > MAX_OBJECT_BYTES
    {
        return Err(invalid(
            "object authority does not cover the bounded transfer",
        ));
    }
    validate_https_authority_url(authority.url.as_str())?;
    Ok(())
}

fn validate_https_authority_url(value: &str) -> HandResult<reqwest::Url> {
    let url =
        reqwest::Url::parse(value).map_err(|_| invalid("transfer authority URL is invalid"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "transfer authority must be a sealed HTTPS URL without credentials",
        ));
    }
    Ok(url)
}

fn apply_authority_headers<'a>(
    mut request: reqwest::RequestBuilder,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
) -> HandResult<reqwest::RequestBuilder> {
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("transfer authority header name is invalid"))?;
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) {
            return Err(invalid(
                "transfer authority contains a forbidden transport header",
            ));
        }
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| invalid("transfer authority header value is invalid"))?;
        request = request.header(name, value);
    }
    Ok(request)
}

fn transfer_timeout(expires_at_ms: u64) -> HandResult<Duration> {
    let remaining = expires_at_ms.saturating_sub(now_ms());
    if remaining == 0 {
        return Err(invalid("transfer authority is expired"));
    }
    Ok(Duration::from_millis(remaining.min(15 * 60 * 1_000)))
}

fn target_key(target: &SandboxTarget) -> HandResult<TargetKey> {
    match target.kind {
        TargetKind::Default if target.sandbox_id.is_none() => {
            TargetKey::default(target.root_id.as_str()).map_err(materialization_error)
        }
        TargetKind::Additional => TargetKey::additional(
            target.root_id.as_str(),
            target
                .sandbox_id
                .as_ref()
                .ok_or_else(|| invalid("additional target requires sandbox_id"))?
                .as_str(),
        )
        .map_err(materialization_error),
        TargetKind::Default => Err(invalid("default target cannot carry sandbox_id")),
    }
}

fn default_target(envelope: &brain_protocol::hand::OperationEnvelope) -> HandResult<SandboxTarget> {
    Ok(SandboxTarget {
        binding_ref: envelope.binding_ref.clone(),
        kind: TargetKind::Default,
        root_id: envelope.root_id.clone(),
        sandbox_id: None,
        session_id: envelope.session_id.clone(),
    })
}

fn status_from_record(
    target: SandboxTarget,
    record: Option<hand_core::materialization::DurableTargetRecord>,
) -> SandboxStatus {
    let Some(record) = record else {
        return SandboxStatus {
            changed_at_ms: None,
            expires_at_ms: None,
            generation: None,
            reason: None,
            state: SandboxState::NeverMaterialized,
            target,
            target_ref: None,
        };
    };
    match record.state {
        DurableTargetState::Materializing {
            target_expires_at_ms,
            ..
        } => SandboxStatus {
            changed_at_ms: Some(record.updated_at_ms),
            expires_at_ms: NonZeroU64::new(target_expires_at_ms),
            generation: Some(record.generation.parse().expect("generation")),
            reason: None,
            state: SandboxState::Creating,
            target,
            target_ref: None,
        },
        DurableTargetState::Installed {
            target_ref,
            expires_at_ms,
            ..
        } => SandboxStatus {
            changed_at_ms: Some(record.updated_at_ms),
            expires_at_ms: NonZeroU64::new(expires_at_ms),
            generation: Some(record.generation.parse().expect("generation")),
            reason: None,
            state: SandboxState::Running,
            target,
            target_ref: Some(target_ref.parse().expect("target ref")),
        },
        DurableTargetState::Gone { reason, .. } => SandboxStatus {
            changed_at_ms: Some(record.updated_at_ms),
            expires_at_ms: None,
            generation: Some(record.generation.parse().expect("generation")),
            reason: Some(reason.parse().expect("reason")),
            state: SandboxState::Gone,
            target,
            target_ref: None,
        },
        DurableTargetState::Terminated { reason, .. } => SandboxStatus {
            changed_at_ms: Some(record.updated_at_ms),
            expires_at_ms: None,
            generation: Some(record.generation.parse().expect("generation")),
            reason: Some(reason.parse().expect("reason")),
            state: SandboxState::Terminated,
            target,
            target_ref: None,
        },
    }
}

fn sandbox_state_from_provider(
    state: &aws_sdk_lambdamicrovms::types::MicrovmState,
) -> HandResult<SandboxState> {
    use aws_sdk_lambdamicrovms::types::MicrovmState;

    match state {
        MicrovmState::Running => Ok(SandboxState::Running),
        MicrovmState::Pending => Ok(SandboxState::Creating),
        MicrovmState::Suspended => Ok(SandboxState::Suspended),
        MicrovmState::Suspending => Err(temporary("sandbox suspension is still in progress")),
        MicrovmState::Terminated => Err(error(
            HandErrorCode::SandboxGone,
            false,
            "provider reports physical generation gone",
        )),
        MicrovmState::Terminating => Err(temporary("sandbox termination is still in progress")),
        // The provider enum is non-exhaustive. A future state must never be reported as running
        // until Hands has explicit routing semantics for it.
        _ => Err(temporary("sandbox provider returned an unsupported state")),
    }
}

fn running_status(target: SandboxTarget, installed: &InstalledTarget) -> SandboxStatus {
    SandboxStatus {
        changed_at_ms: Some(installed.installed_at_ms),
        expires_at_ms: NonZeroU64::new(installed.expires_at_ms),
        generation: Some(installed.generation.parse().expect("generation")),
        reason: None,
        state: SandboxState::Running,
        target,
        target_ref: Some(installed.target_ref.parse().expect("target ref")),
    }
}

fn gone_status(target: SandboxTarget, installed: &InstalledTarget, reason: &str) -> SandboxStatus {
    SandboxStatus {
        changed_at_ms: Some(now_ms()),
        expires_at_ms: None,
        generation: Some(installed.generation.parse().expect("generation")),
        reason: Some(reason.parse().expect("reason")),
        state: SandboxState::Gone,
        target,
        target_ref: None,
    }
}

fn terminated_status(
    target: SandboxTarget,
    installed: &InstalledTarget,
    reason: &str,
) -> SandboxStatus {
    SandboxStatus {
        changed_at_ms: Some(now_ms()),
        expires_at_ms: None,
        generation: Some(installed.generation.parse().expect("generation")),
        reason: Some(reason.parse().expect("reason")),
        state: SandboxState::Terminated,
        target,
        target_ref: None,
    }
}

fn sandbox_identity(key: &TargetKey) -> HandResult<String> {
    key.sandbox_identity()
        .map(str::to_owned)
        .map_err(|_| invalid("target key has an unrecognized shape"))
}

fn random_identifier(prefix: &str) -> String {
    format!("{prefix}-{}", hex::encode(rand::random::<[u8; 16]>()))
}

// Fail closed: every expiry predicate in this crate compares against this value, so a pre-epoch
// clock must abort rather than make every expired authority look valid.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the UNIX epoch")
        .as_millis() as u64
}

fn invalid(message: impl Into<String>) -> HandError {
    error(HandErrorCode::InvalidRequest, false, message)
}

/// A reply variant that does not match the request method is a host/guest contract violation
/// (for example protocol-version skew), never a transient fault: a retry replays the exact same
/// mismatch, so fail fast and non-retryable.
fn wrong_reply(context: &'static str) -> HandError {
    error(
        HandErrorCode::InvalidRequest,
        false,
        format!("guest returned the wrong {context} reply"),
    )
}

fn binding_error(message: impl Into<String>) -> HandError {
    error(HandErrorCode::BindingConflict, false, message)
}

fn generation_error() -> HandError {
    error(
        HandErrorCode::GenerationConflict,
        false,
        "request does not match the live sandbox generation",
    )
}

/// Once the operation submit RPC has been attempted, loss of its physical generation cannot prove
/// that the guest effect did not start. Brain has durable intent but may not yet have received the
/// operation receipt, so returning `sandbox_gone` would let recovery route the target-less intent
/// into a replacement generation. Preserve the uncertainty explicitly and never repeat the effect.
fn classify_submit_delivery_error(error_value: HandError) -> HandError {
    if error_value.code == HandErrorCode::SandboxGone {
        error(
            HandErrorCode::OperationUnknown,
            false,
            "managed operation delivery became unknown when its physical generation was lost",
        )
    } else {
        error_value
    }
}

fn definition_error(error_value: DefinitionError) -> HandError {
    match error_value {
        DefinitionError::Conflict => binding_error(error_value.to_string()),
        DefinitionError::Storage(_) => temporary(error_value.to_string()),
        _ => invalid(error_value.to_string()),
    }
}

fn root_seal_error(error_value: DefinitionError) -> HandError {
    if error_value == DefinitionError::Conflict {
        error(
            HandErrorCode::GenerationConflict,
            false,
            "root sandbox network/resource seal conflicts with an earlier preparation",
        )
    } else {
        definition_error(error_value)
    }
}

fn materialization_error(error_value: MaterializationError) -> HandError {
    match error_value {
        MaterializationError::Capacity {
            scope,
            retry_after_ms,
            message,
        } => {
            let mut value = error(HandErrorCode::ResourceExhausted, true, message);
            value.details.insert("scope".into(), scope.into());
            value
                .details
                .insert("retry_after_ms".into(), retry_after_ms.into());
            value
        }
        MaterializationError::Pending { retry_after_ms } => {
            let mut value = temporary(error_value.to_string());
            value
                .details
                .insert("retry_after_ms".into(), retry_after_ms.into());
            value
        }
        MaterializationError::Gone | MaterializationError::Terminated => {
            error(HandErrorCode::SandboxGone, false, error_value.to_string())
        }
        MaterializationError::SpecConflict => error(
            HandErrorCode::GenerationConflict,
            false,
            error_value.to_string(),
        ),
        MaterializationError::Storage(_)
        | MaterializationError::LaunchRetryable(_)
        | MaterializationError::LaunchOutcomeUnknown(_)
        | MaterializationError::ReservationLost { .. } => temporary(error_value.to_string()),
        MaterializationError::LaunchRejected(_) => error(
            HandErrorCode::CapabilityUnavailable,
            false,
            error_value.to_string(),
        ),
        _ => invalid(error_value.to_string()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn preparation(session_id: &str, root_id: &str, digest: &str) -> PrepareSessionRequest {
        serde_json::from_value(serde_json::json!({
            "bindings": [{
                "binding_ref": format!("binding-{session_id}"),
                "bundle_digests": [digest]
            }],
            "bundles": [],
            "network": {"kind": "none"},
            "resources": {"max_output_bytes": 65536, "timeout_ms": 60000},
            "root_id": root_id,
            "session_id": session_id
        }))
        .unwrap()
    }

    fn managed_binding(session_id: &str, root_id: &str, digest: &str) -> SealedBinding {
        serde_json::from_value(serde_json::json!({
            "binding_id": format!("binding-{session_id}"),
            "bundle": {
                "bundle_digest": digest,
                "bytes": 1,
                "contract_digest": "b".repeat(64),
                "object": {"bytes": 1, "object_id": "object-1", "sha256": digest},
                "required_env": [],
                "runtime": "node22",
                "tool_name": "fixture"
            },
            "capability": "fixture",
            "contract_digest": "b".repeat(64),
            "implementation_identity": "c".repeat(64),
            "policy_digest": "d".repeat(64),
            "realm": "aex_managed",
            "realm_id": "aex",
            "required_capabilities": ["execution"],
            "root_id": root_id,
            "session_id": session_id
        }))
        .unwrap()
    }

    fn materialization_lease(now_ms: u64) -> MaterializationLease {
        AcquireTarget {
            key: TargetKey::default("root-dispatch").unwrap(),
            spec: TargetSpec::new(
                ConnectorClass::None,
                "image-1",
                RESOURCE_CLASS,
                TARGET_MEMORY_MIB,
                "a".repeat(64),
                "b".repeat(64),
            )
            .unwrap(),
            reservation_id: "reservation-dispatch".into(),
            generation: "generation-dispatch".into(),
            launch_request: DurableLaunchRequest::new("sealed-launch").unwrap(),
            attempt_id: "attempt-dispatch".into(),
            attempt_duration_ms: TARGET_ATTEMPT_MS,
            generation_is_fenced: true,
            now_ms,
            lease_duration_ms: TARGET_LEASE_MS,
            target_lifetime_ms: TARGET_LIFETIME_MS,
            replace_after_loss: false,
        }
        .lease()
        .unwrap()
    }

    async fn streaming_response(body: Vec<u8>, declared_length: usize) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            for chunk in body.chunks(16 * 1024) {
                socket.write_all(chunk).await.unwrap();
            }
        });
        reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap()
    }

    async fn stalled_streaming_response() -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap()
    }

    #[test]
    fn target_specs_seal_physical_memory_and_exact_network_policy() {
        let cfg = HandPlaneConfig {
            region: "us-east-1".into(),
            image: "image".into(),
            image_version: "1".into(),
            registry_table: "table".into(),
            max_materialized_mib: 1_024,
            bundle_cache_max_bytes: DEFAULT_BUNDLE_CACHE_MAX_MIB as usize * MIB,
            bundle_fetch_max_bytes: DEFAULT_BUNDLE_FETCH_MAX_MIB as usize * MIB,
            connectors: ConnectorCatalog::new(
                hand_core::connector::ConnectorRef::parse("none").unwrap(),
                hand_core::connector::ConnectorRef::parse("public").unwrap(),
                hand_core::connector::ConnectorRef::parse("allowlist").unwrap(),
            ),
            capability_signing_key_id: "key".into(),
            egress_gateway_authority: GatewayAuthority::parse("10.0.0.10:8443").unwrap(),
        };
        let resources: ResourceCeiling = serde_json::from_value(serde_json::json!({
            "max_output_bytes": 1024,
            "timeout_ms": 1000
        }))
        .unwrap();
        let none = target_spec(&cfg, &resources, &NetworkCeiling::None, RESOURCE_CLASS).unwrap();
        let public =
            target_spec(&cfg, &resources, &NetworkCeiling::Public, RESOURCE_CLASS).unwrap();
        assert_eq!(none.materialized_mib, 1_024);
        assert_ne!(none.network_policy_digest, public.network_policy_digest);
        assert_ne!(none.digest(), public.digest());
    }

    #[test]
    fn provider_status_projection_never_calls_a_transitional_or_future_state_running() {
        use aws_sdk_lambdamicrovms::types::MicrovmState;

        assert_eq!(
            sandbox_state_from_provider(&MicrovmState::Running).unwrap(),
            SandboxState::Running
        );
        assert!(sandbox_state_from_provider(&MicrovmState::Suspending).is_err());
        let terminating = sandbox_state_from_provider(&MicrovmState::Terminating).unwrap_err();
        assert_eq!(terminating.code, HandErrorCode::TemporarilyUnavailable);
        assert!(terminating.retryable);
        let future = sandbox_state_from_provider(&MicrovmState::from("FUTURE_STATE")).unwrap_err();
        assert_eq!(future.code, HandErrorCode::TemporarilyUnavailable);
        assert!(future.retryable);
    }

    #[test]
    fn physical_loss_after_submit_dispatch_is_operation_unknown_not_a_replacement_signal() {
        let classified = classify_submit_delivery_error(error(
            HandErrorCode::SandboxGone,
            false,
            "physical generation disappeared",
        ));
        assert_eq!(classified.code, HandErrorCode::OperationUnknown);
        assert!(!classified.retryable);

        let pre_dispatch = error(
            HandErrorCode::CapabilityUnavailable,
            false,
            "bundle was not installed",
        );
        let classified = classify_submit_delivery_error(pre_dispatch);
        assert_eq!(classified.code, HandErrorCode::CapabilityUnavailable);
        assert!(!classified.retryable);
        assert_eq!(classified.message.as_str(), "bundle was not installed");
    }

    #[test]
    fn verified_bundle_cache_is_lru_and_only_active_borrowers_pin_bytes() {
        let digest = "a".repeat(64);
        let mut cache = PreparationCache::with_limit(3);
        cache
            .install(
                preparation("session-1", "root-1", &digest),
                "preparation-1".into(),
                HashMap::from([(digest.clone(), Arc::new(vec![1, 2, 3]))]),
            )
            .unwrap();
        cache
            .install(
                preparation("session-2", "root-1", &digest),
                "preparation-2".into(),
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(cache.bundle_bytes, 3);
        assert_eq!(cache.bundle(&digest).unwrap().as_slice(), &[1, 2, 3]);

        assert!(!cache.purge_root_page("root-1", 1));
        assert!(cache.bundle(&digest).is_some());
        assert!(cache.purge_root_page("root-1", 1));
        // Preparation metadata no longer pins resident bytes. Purge need not synchronously flush
        // a content-addressed cache entry, but the next admission may evict it immediately.
        let borrowed = cache.bundle(&digest).unwrap();
        let replacement = "b".repeat(64);
        let error = cache
            .install(
                preparation("session-3", "root-2", &replacement),
                "preparation-3".into(),
                HashMap::from([(replacement.clone(), Arc::new(vec![4, 5, 6]))]),
            )
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::ResourceExhausted);
        assert_eq!(cache.bundle_bytes, 3);
        drop(borrowed);

        cache
            .install(
                preparation("session-3", "root-2", &replacement),
                "preparation-3".into(),
                HashMap::from([(replacement.clone(), Arc::new(vec![4, 5, 6]))]),
            )
            .unwrap();
        assert!(cache.bundle(&digest).is_none());
        assert_eq!(cache.bundle(&replacement).unwrap().as_slice(), &[4, 5, 6]);
        assert_eq!(cache.bundle_bytes, 3);
    }

    #[test]
    fn preparation_metadata_is_bounded_lru_and_eviction_requires_reprepare() {
        let digest = "a".repeat(64);
        let first = preparation("session-1", "root-1", &digest);
        let metadata_bytes = serde_jcs::to_vec(&first).unwrap().len();
        let mut cache = PreparationCache::with_limits(3, metadata_bytes * 2, 2);
        cache
            .install(
                first,
                "preparation-1".into(),
                HashMap::from([(digest.clone(), Arc::new(vec![1, 2, 3]))]),
            )
            .unwrap();
        cache
            .install(
                preparation("session-2", "root-2", &digest),
                "preparation-2".into(),
                HashMap::new(),
            )
            .unwrap();

        // Touch session 1 after session 2 was installed, making session 2 the cold candidate.
        assert!(cache.get("session-1").is_some());
        cache
            .install(
                preparation("session-3", "root-3", &digest),
                "preparation-3".into(),
                HashMap::new(),
            )
            .unwrap();
        assert!(cache.get("session-1").is_some());
        assert!(cache.get("session-2").is_none());
        assert!(cache.get("session-3").is_some());
        assert_eq!(cache.sessions.len(), 2);
        assert!(cache.preparation_bytes <= metadata_bytes * 2);
        assert!(!cache.root_sessions.contains_key("root-2"));
    }

    #[test]
    fn cold_bundle_fetch_admission_bounds_cache_and_all_in_flight_bytes() {
        let reserved = Arc::new(StdMutex::new(BundleFetchInFlight::default()));
        let cache_limit = DEFAULT_BUNDLE_CACHE_MAX_MIB as usize * MIB;
        let fetch_limit = DEFAULT_BUNDLE_FETCH_MAX_MIB as usize * MIB;
        let first = BundleFetchReservation::admit(
            reserved.clone(),
            cache_limit - 8,
            1,
            8,
            1,
            cache_limit,
            fetch_limit,
        )
        .unwrap();
        assert_eq!(reserved.lock().unwrap().bytes, 8);

        let error = BundleFetchReservation::admit(
            reserved.clone(),
            cache_limit - 8,
            1,
            1,
            1,
            cache_limit,
            fetch_limit,
        )
        .unwrap_err();
        assert_eq!(error.code, HandErrorCode::ResourceExhausted);
        assert!(error.retryable);
        assert_eq!(reserved.lock().unwrap().bytes, 8);

        drop(first);
        assert_eq!(reserved.lock().unwrap().bytes, 0);
        let retry = BundleFetchReservation::admit(
            reserved.clone(),
            cache_limit - 8,
            1,
            8,
            1,
            cache_limit,
            fetch_limit,
        )
        .unwrap();
        drop(retry);
        assert_eq!(reserved.lock().unwrap().bytes, 0);

        let first = BundleFetchReservation::admit(
            reserved.clone(),
            0,
            0,
            fetch_limit,
            1,
            cache_limit,
            fetch_limit,
        )
        .unwrap();
        let error =
            BundleFetchReservation::admit(reserved.clone(), 0, 0, 1, 1, cache_limit, fetch_limit)
                .unwrap_err();
        assert_eq!(
            error.details.get("scope"),
            Some(&serde_json::Value::String("hand_bundle_fetch_bytes".into()))
        );
        drop(first);
    }

    #[test]
    fn cache_loss_requires_a_fresh_fetch_before_any_tool_effect() {
        let digest = "a".repeat(64);
        let mut cache = PreparationCache::default();
        let error = cache
            .install(
                preparation("session-1", "root-1", &digest),
                "preparation-1".into(),
                HashMap::new(),
            )
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::CapabilityUnavailable);
        assert!(!error.retryable);
        assert!(cache.get("session-1").is_none());
    }

    #[test]
    fn prepared_session_public_seal_is_immutable_but_fresh_fetches_may_replay() {
        let digest = "a".repeat(64);
        let mut cache = PreparationCache::default();
        let request = preparation("session-1", "root-1", &digest);
        cache
            .install(
                request.clone(),
                "preparation-1".into(),
                HashMap::from([(digest.clone(), Arc::new(vec![1, 2, 3]))]),
            )
            .unwrap();
        cache
            .install(request.clone(), "preparation-1".into(), HashMap::new())
            .unwrap();
        let conflict = cache
            .install(request, "preparation-changed".into(), HashMap::new())
            .unwrap_err();
        assert_eq!(conflict.code, HandErrorCode::BindingConflict);
    }

    #[test]
    fn preparation_seals_secret_names_but_not_the_refreshable_bearer() {
        let digest = "a".repeat(64);
        let mut first = preparation("session-1", "root-1", &digest);
        first.secret_capability = serde_json::from_value(serde_json::json!({
            "capability_ref": "secret-capability-1",
            "env_names": ["DATABASE_URL", "OPENAI_API_KEY"],
            "expires_at_ms": 1000
        }))
        .unwrap();
        let mut refreshed = first.clone();
        refreshed.secret_capability.as_mut().unwrap().capability_ref =
            "secret-capability-2".parse().unwrap();
        refreshed.secret_capability.as_mut().unwrap().expires_at_ms =
            std::num::NonZeroU64::new(2_000).unwrap();
        assert_eq!(
            preparation_public_projection(&first).unwrap(),
            preparation_public_projection(&refreshed).unwrap()
        );

        refreshed.secret_capability.as_mut().unwrap().env_names =
            vec!["DATABASE_URL".parse().unwrap()];
        assert_ne!(
            preparation_public_projection(&first).unwrap(),
            preparation_public_projection(&refreshed).unwrap()
        );
    }

    #[test]
    fn preparation_binding_projection_is_exactly_root_session_and_descriptor_scoped() {
        let digest = "a".repeat(64);
        let request = preparation("session-1", "root-1", &digest);
        let prepared = &request.bindings[0];
        let binding = managed_binding("session-1", "root-1", &digest);
        assert_eq!(
            validate_prepared_binding_projection(prepared, &binding, "root-1", "session-1")
                .unwrap()
                .digest,
            digest
        );

        let wrong_session = managed_binding("session-2", "root-1", &digest);
        assert_eq!(
            validate_prepared_binding_projection(prepared, &wrong_session, "root-1", "session-1")
                .unwrap_err()
                .code,
            HandErrorCode::BindingConflict
        );
        let mut wrong_digest = prepared.clone();
        wrong_digest.bundle_digests = vec!["e".repeat(64).parse().unwrap()];
        assert_eq!(
            validate_prepared_binding_projection(&wrong_digest, &binding, "root-1", "session-1")
                .unwrap_err()
                .code,
            HandErrorCode::BindingConflict
        );

        let mut inconsistent_object = binding.clone();
        inconsistent_object.bundle.as_mut().unwrap().object.bytes = 2;
        assert_eq!(
            validate_managed_binding(&inconsistent_object)
                .unwrap_err()
                .code,
            HandErrorCode::BindingConflict
        );

        let mut exact_limit = binding.clone();
        let bytes = NonZeroU64::new(brain_protocol::MAX_TOOL_BUNDLE_BYTES as u64).unwrap();
        exact_limit.bundle.as_mut().unwrap().bytes = bytes;
        exact_limit.bundle.as_mut().unwrap().object.bytes = bytes.get();
        validate_managed_binding(&exact_limit).unwrap();

        let mut oversized = exact_limit;
        let bytes = NonZeroU64::new(bytes.get() + 1).unwrap();
        oversized.bundle.as_mut().unwrap().bytes = bytes;
        oversized.bundle.as_mut().unwrap().object.bytes = bytes.get();
        assert_eq!(
            validate_managed_binding(&oversized).unwrap_err().code,
            HandErrorCode::BindingConflict
        );

        let mut repeated_env = binding.clone();
        repeated_env.bundle.as_mut().unwrap().required_env =
            vec!["TOKEN".parse().unwrap(), "TOKEN".parse().unwrap()];
        assert_eq!(
            validate_managed_binding(&repeated_env).unwrap_err().code,
            HandErrorCode::BindingConflict
        );

        let first = validate_prepared_binding_projection(prepared, &binding, "root-1", "session-1")
            .unwrap();
        let mut conflicting_descriptor = binding.clone();
        conflicting_descriptor.bundle.as_mut().unwrap().tool_name = "other".parse().unwrap();
        let second = validate_prepared_binding_projection(
            prepared,
            &conflicting_descriptor,
            "root-1",
            "session-1",
        )
        .unwrap();
        let mut required = HashMap::new();
        merge_validated_prepared_bundle(&mut required, first).unwrap();
        assert_eq!(
            merge_validated_prepared_bundle(&mut required, second)
                .unwrap_err()
                .code,
            HandErrorCode::BindingConflict
        );
    }

    #[test]
    fn short_lived_bundle_fetch_authorities_are_not_retained_in_session_cache() {
        const URL_SECRET: &str = "presigned-url-secret";
        const HEADER_SECRET: &str = "authorization-header-secret";
        let digest = "a".repeat(64);
        let mut request = preparation("session-1", "root-1", &digest);
        request.bundles = serde_json::from_value(serde_json::json!([{
            "bundle_digest": digest,
            "url": format!("https://objects.example.test/bundle?signature={URL_SECRET}"),
            "headers": {"Authorization": HEADER_SECRET},
            "expires_at_ms": 123456,
            "max_bytes": 4096
        }]))
        .unwrap();

        let cached = cacheable_preparation(request);
        assert!(cached.bundles.is_empty());
        let encoded = serde_json::to_string(&cached).unwrap();
        assert!(!encoded.contains(URL_SECRET));
        assert!(!encoded.contains(HEADER_SECRET));
        assert!(encoded.contains("binding-session-1"));
    }

    #[test]
    fn additional_target_cannot_widen_root_resource_or_network_seals() {
        let root: ResourceCeiling = serde_json::from_value(serde_json::json!({
            "max_output_bytes": 65536,
            "timeout_ms": 60000
        }))
        .unwrap();
        let narrower: ResourceCeiling = serde_json::from_value(serde_json::json!({
            "max_output_bytes": 32768,
            "timeout_ms": 30000
        }))
        .unwrap();
        assert!(validate_resource_ceiling_subset(&narrower, &root).is_ok());
        let wider: ResourceCeiling = serde_json::from_value(serde_json::json!({
            "max_output_bytes": 65537,
            "timeout_ms": 60000
        }))
        .unwrap();
        assert_eq!(
            validate_resource_ceiling_subset(&wider, &root)
                .unwrap_err()
                .code,
            HandErrorCode::GenerationConflict
        );

        let root_network: NetworkCeiling = serde_json::from_value(serde_json::json!({
            "kind": "allowlist",
            "destinations": [
                {"protocol": "tls", "host": "*.example.com", "ports": [443]},
                {"protocol": "tcp", "cidr": "8.8.8.0/24", "ports": [443, 8443]}
            ]
        }))
        .unwrap();
        let narrow_network: NetworkCeiling = serde_json::from_value(serde_json::json!({
            "kind": "allowlist",
            "destinations": [
                {"protocol": "tls", "host": "objects.example.com", "ports": [443]},
                {"protocol": "tcp", "cidr": "8.8.8.8/32", "ports": [443]}
            ]
        }))
        .unwrap();
        assert!(network_ceiling_is_subset(&narrow_network, &root_network));
        assert!(!network_ceiling_is_subset(
            &NetworkCeiling::Public,
            &root_network
        ));
    }

    #[test]
    fn additional_control_port_never_overloads_default_lifecycle() {
        let default: SandboxTarget = serde_json::from_value(serde_json::json!({
            "binding_ref": "binding-default",
            "kind": "default",
            "root_id": "root-1",
            "session_id": "session-1"
        }))
        .unwrap();
        let error = require_additional_target(&default).unwrap_err();
        assert_eq!(error.code, HandErrorCode::InvalidRequest);

        let additional: SandboxTarget = serde_json::from_value(serde_json::json!({
            "binding_ref": "binding-additional",
            "kind": "additional",
            "root_id": "root-1",
            "sandbox_id": "sandbox-1",
            "session_id": "session-1"
        }))
        .unwrap();
        require_additional_target(&additional).unwrap();
    }

    #[test]
    fn managed_tool_input_is_inline_and_bounded_before_materialization() {
        let small = serde_json::from_value(serde_json::json!({
            "kind": "inline",
            "value": {"prompt": "hello"}
        }))
        .unwrap();
        assert!(validate_inline_input(&small).is_ok());

        let wrong_kind = brain_protocol::hand::OperationInput {
            kind: serde_json::json!("object"),
            value: serde_json::json!({}),
        };
        assert_eq!(
            validate_inline_input(&wrong_kind).unwrap_err().code,
            HandErrorCode::InvalidRequest
        );
        let empty = brain_protocol::hand::OperationInput {
            kind: serde_json::json!("inline"),
            value: serde_json::json!(""),
        };
        let framing = serde_jcs::to_vec(&empty).unwrap().len();
        let exact = brain_protocol::hand::OperationInput {
            kind: serde_json::json!("inline"),
            value: serde_json::json!(
                "x".repeat(brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES - framing)
            ),
        };
        assert_eq!(
            serde_jcs::to_vec(&exact).unwrap().len(),
            brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES
        );
        assert!(validate_inline_input(&exact).is_ok());

        let oversized = brain_protocol::hand::OperationInput {
            kind: serde_json::json!("inline"),
            value: serde_json::json!(
                "x".repeat(brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES - framing + 1)
            ),
        };
        assert_eq!(
            serde_jcs::to_vec(&oversized).unwrap().len(),
            brain_protocol::MAX_MANAGED_TOOL_INPUT_BYTES + 1
        );
        assert_eq!(
            validate_inline_input(&oversized).unwrap_err().code,
            HandErrorCode::InvalidRequest
        );
    }

    #[test]
    fn capacity_errors_are_typed_and_expose_retry_without_a_fallback() {
        let error = materialization_error(MaterializationError::Capacity {
            scope: "plane_materialized_memory_mib".into(),
            retry_after_ms: 1_000,
            message: "full".into(),
        });
        assert_eq!(error.code, HandErrorCode::ResourceExhausted);
        assert!(error.retryable);
        assert_eq!(error.details["retry_after_ms"], 1_000);
        assert_eq!(error.details["scope"], "plane_materialized_memory_mib");
    }

    #[test]
    fn delayed_provider_dispatch_never_outlives_the_capacity_fence() {
        let fresh = materialization_lease(1_000);
        let deadline = launch_dispatch_deadline(&fresh).unwrap();
        assert_eq!(deadline, 1_000 + TARGET_DISPATCH_WINDOW_MS);
        assert!(admit_provider_dispatch(&fresh, deadline, deadline).is_ok());
        assert!(matches!(
            admit_provider_dispatch(&fresh, deadline, deadline + 1),
            Err(LaunchError::KnownNoTarget(_))
        ));

        let mut recovery = fresh;
        recovery.recovery_attempt = true;
        assert!(matches!(
            admit_provider_dispatch(&recovery, deadline, deadline + 1),
            Err(LaunchError::OutcomeUnknown(_))
        ));
        assert!(
            recovery.lease_expires_at_ms.saturating_sub(deadline) >= TARGET_LIFETIME_MS,
            "the latest admitted provider dispatch must expire before capacity can be reused"
        );
    }

    #[test]
    fn transfer_authorities_require_sealed_https_without_url_credentials() {
        assert!(
            validate_https_authority_url("https://objects.example/a?X-Amz-Signature=opaque")
                .is_ok()
        );
        for invalid_url in [
            "http://objects.example/a",
            "https://user:secret@objects.example/a",
            "https://objects.example/a#fragment",
            "/relative/path",
        ] {
            let error = validate_https_authority_url(invalid_url).unwrap_err();
            assert_eq!(error.code, HandErrorCode::InvalidRequest);
            assert!(!error.retryable);
        }
    }

    #[test]
    fn transfer_authorities_cannot_override_transport_routing_headers() {
        let http = reqwest::Client::new();
        for name in [
            "Host",
            "Content-Length",
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "Proxy-Connection",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            let error = apply_authority_headers(
                http.get("https://objects.example.test/object"),
                std::iter::once((name, "opaque")),
            )
            .unwrap_err();
            assert_eq!(error.code, HandErrorCode::InvalidRequest, "{name}");
            assert!(!error.retryable, "{name}");
        }
        assert!(
            apply_authority_headers(
                http.get("https://objects.example.test/object"),
                std::iter::once(("Authorization", "Bearer opaque")),
            )
            .is_ok()
        );
    }

    #[test]
    fn source_authorities_refresh_but_export_destination_identity_conflicts() {
        let file_write = |transfer_id: &str, token: &str| -> SandboxFileWriteRequest {
            serde_json::from_value(serde_json::json!({
                "operation_id": "file-write-refresh-1",
                "request_digest": "0".repeat(64),
                "expected_generation": "generation-1",
                "overwrite": false,
                "path": "/workspace/input.bin",
                "source": {
                    "kind": "object",
                    "fetch": {
                        "expires_at_ms": 9_000_000_000_000_u64,
                        "headers": {"Authorization": format!("Bearer {token}")},
                        "max_bytes": 1024,
                        "method": "GET",
                        "object_id": "object-source-1",
                        "transfer_id": transfer_id,
                        "url": format!("https://objects.example.test/input?token={token}")
                    },
                    "object": {
                        "bytes": 7,
                        "object_id": "object-source-1",
                        "sha256": "a".repeat(64)
                    }
                },
                "target": {
                    "binding_ref": "binding-1",
                    "kind": "default",
                    "root_id": "root-1",
                    "session_id": "session-1"
                }
            }))
            .unwrap()
        };
        assert_eq!(
            sandbox_file_write_request_digest(&file_write("fetch-1", "old")),
            sandbox_file_write_request_digest(&file_write("fetch-2", "fresh")),
            "the immutable ObjectReference, not a refreshed GET reservation, owns source identity"
        );

        let copy = |direction: &str, transfer_id: &str, token: &str| -> SandboxCopyRequest {
            let importing = direction == "import";
            serde_json::from_value(serde_json::json!({
                "direction": direction,
                "expected_generation": "generation-1",
                "object": importing.then(|| serde_json::json!({
                    "bytes": 7,
                    "object_id": "object-source-1",
                    "sha256": "a".repeat(64)
                })),
                "operation_id": format!("copy-{direction}-refresh-1"),
                "overwrite": false,
                "path": "/workspace/input.bin",
                "request_digest": "0".repeat(64),
                "target": {
                    "binding_ref": "binding-1",
                    "kind": "default",
                    "root_id": "root-1",
                    "session_id": "session-1"
                },
                "transfer": {
                    "expires_at_ms": 9_000_000_000_000_u64,
                    "headers": {"Authorization": format!("Bearer {token}")},
                    "max_bytes": 1024,
                    "method": if importing { "GET" } else { "PUT" },
                    "object_id": if importing { "object-source-1" } else { "object-destination-1" },
                    "transfer_id": transfer_id,
                    "url": format!("https://objects.example.test/{direction}?token={token}")
                }
            }))
            .unwrap()
        };
        assert_eq!(
            sandbox_copy_request_digest(&copy("import", "fetch-1", "old")),
            sandbox_copy_request_digest(&copy("import", "fetch-2", "fresh")),
            "import GET reservations are refreshable"
        );
        assert_ne!(
            sandbox_copy_request_digest(&copy("export", "upload-1", "old")),
            sandbox_copy_request_digest(&copy("export", "upload-2", "fresh")),
            "export transfer_id names the pending destination and cannot refresh"
        );
    }

    #[test]
    fn object_write_projection_never_forwards_storage_authority_to_the_guest() {
        const URL_SECRET: &str = "presigned-object-url-secret";
        const HEADER_SECRET: &str = "presigned-object-header-secret";
        let mut request: SandboxFileWriteRequest = serde_json::from_value(serde_json::json!({
            "operation_id": "file-write-1",
            "request_digest": "0".repeat(64),
            "expected_generation": "generation-1",
            "overwrite": false,
            "path": "/workspace/input.bin",
            "source": {
                "kind": "object",
                "fetch": {
                    "expires_at_ms": u64::MAX,
                    "headers": {"Authorization": HEADER_SECRET},
                    "max_bytes": 1024,
                    "method": "GET",
                    "object_id": "object-1",
                    "transfer_id": "transfer-1",
                    "url": format!("https://objects.example.test/input?signature={URL_SECRET}")
                },
                "object": {
                    "bytes": 7,
                    "object_id": "object-1",
                    "sha256": "a".repeat(64)
                }
            },
            "target": {
                "binding_ref": "binding-1",
                "kind": "default",
                "root_id": "root-1",
                "session_id": "session-1"
            }
        }))
        .unwrap();
        request.request_digest = sandbox_file_write_request_digest(&request);
        let encoded = serde_json::to_string(&project_guest_file_write(request)).unwrap();
        assert!(!encoded.contains(URL_SECRET));
        assert!(!encoded.contains(HEADER_SECRET));
        assert!(!encoded.contains("transfer-1"));
        assert!(encoded.contains("object-1"));
        assert!(encoded.contains("installed_object"));
        assert!(encoded.contains("file-write-1"));
    }

    #[tokio::test]
    async fn object_staging_streams_beyond_inline_size_and_enforces_the_bound() {
        let body = vec![0x5a; 2 * 1024 * 1024];
        let expected = hex::encode(Sha256::digest(&body));
        let response = streaming_response(body.clone(), body.len()).await;
        let staged = stage_response(response, body.len() as u64, now_ms() + 60_000)
            .await
            .unwrap();
        assert_eq!(staged.bytes, body.len() as u64);
        assert_eq!(staged.sha256, expected);
        assert_eq!(
            std::fs::metadata(staged.file.path()).unwrap().len(),
            body.len() as u64
        );

        let response = streaming_response(vec![0_u8; 2], 2).await;
        let error = match stage_response(response, 1, now_ms() + 60_000).await {
            Ok(_) => panic!("over-bound response must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, HandErrorCode::ResourceExhausted);
        assert!(!error.retryable);

        let response = streaming_response(Vec::new(), 0).await;
        let staged = stage_response(response, 0, now_ms() + 60_000)
            .await
            .expect("an immutable empty object is valid");
        assert_eq!(staged.bytes, 0);
        assert_eq!(staged.sha256, hex::encode(Sha256::digest([])));
        assert_eq!(std::fs::metadata(staged.file.path()).unwrap().len(), 0);

        let response = stalled_streaming_response().await;
        let expired = match tokio::time::timeout(
            Duration::from_millis(250),
            stage_response(response, 1, now_ms() + 25),
        )
        .await
        .expect("a stalled body must be bounded by its authority deadline")
        {
            Err(error) => error,
            Ok(_) => panic!("a body that did not arrive before expiry must be rejected"),
        };
        assert!(!expired.retryable);
    }
}
