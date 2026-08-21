//! Physical-generation implementation of Brain's canonical receipt protocol.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use brain::hand::{
    SandboxFileContent, SandboxFileList, SandboxFileListRequest, SandboxSearchRequest,
};
use brain_protocol::contract::{
    HAND_CONTRACT_DIGEST, operation_request_digest, sandbox_execution_request_digest,
    terminal_inline_fits, terminal_result_digest, write_stdin_request_digest,
};
use brain_protocol::hand::{
    AcknowledgeTerminalRequest, Acknowledgement, BundleDescriptor, BundleRuntime, CancelRequest,
    CancellationReceipt, Digest, ExecutionRealm, FileEntry, FileEntryKind, HandError,
    HandErrorCode, NetworkCeiling, ObserveRequest, OperationEnvelope, OperationObservation,
    OperationRef, OperationState as ContractOperationState, ResourceCeiling, SandboxCopyResult,
    SandboxExecutionRequest, SandboxFileRequest, SandboxFileWriteResult, SandboxTarget,
    SealedBinding, SubmitReceipt, SubmitRequest, TargetKind, TargetReceipt, TerminalOutcome,
    TerminalResult, WriteStdinReceipt, WriteStdinRequest,
};
use brain_protocol::network::network_ceiling_is_subset;
use hand_core::connector::ConnectorClass;
use hand_core::files::{LiveFileEntry, LiveFileError, LiveFileKind, LiveFiles};
use hand_core::operation::{OperationError, OperationRegistry, OperationState, Reservation};
use hand_core::resources::{ResourceRequest, ResourceSupport};
use hand_wire::{
    FileEffectIdentity, FileEffectKind, FileEffectReservation, FileEffectStoredResult,
    GuestFileWriteRequest, GuestFileWriteSource, InstallBindingRequest, InstallBundleMetadata,
    InstallObjectMetadata, InstallReceipt, InstallSecretsRequest, MAX_INLINE_FILE_BYTES,
    RunPayload, TargetRuntimeStatus, environment_name_is_valid, reserved_tool_environment,
    secret_material_fits,
};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize as _;

use crate::acks::{AckStoreError, AcknowledgementStore, SubmissionFence};
use crate::config::{
    Config, MANAGED_BINDING_UID_MIN, MANAGED_BINDING_UID_SPAN, MAX_CONCURRENT_OPERATIONS,
    MAX_OPERATION_OUTPUT_BYTES, MAX_OPERATION_TIMEOUT_MS, MAX_PREPARED_BINDINGS,
    MAX_RETAINED_OPERATIONS, MAX_RETAINED_STDIN_WRITES, MAX_RETAINED_TERMINAL_BYTES,
    MAX_TARGET_LIFETIME_MS, MAX_WAIT_MS, ToolIdentity,
};
use crate::errors::{hand_error, invalid, unavailable};
use crate::file_effects::{EffectReservation, FileEffectStore, FileEffectStoreError};
use crate::process::{
    BundleExecution, InteractiveControl, ShellExecution, execute_bundle, execute_shell,
};

// Brain reserves 4 KiB above the canonical inline value for the terminal outcome, digest, timing,
// operation locator, and target receipt. Reserve that complete envelope before starting an effect
// so terminal retention cannot leave an operation permanently `running` after its child exits.
const TERMINAL_ENVELOPE_BYTES: usize = brain_protocol::MAX_TOOL_TERMINAL_INLINE_BYTES + 4 * 1024;
const FILE_EFFECT_LOCK_SHARDS: usize = 64;

/// No `Debug`: an allowlist target contains a bearer capability.
struct ArmedTarget {
    target_ref: String,
    generation: String,
    expires_at_ms: u64,
    root_id: String,
    owner_session_id: String,
    connector: ConnectorClass,
    resource_class: String,
    resources: ResourceCeiling,
    network: NetworkCeiling,
    proxy_environment: HashMap<String, String>,
    canary_exit_after_operation_id: Option<String>,
}

struct InstalledBinding {
    seal: SealedBinding,
    bundle_path: PathBuf,
    identity: Option<ToolIdentity>,
}

/// Per-generation registry for the kernel identity assigned to each immutable binding. A hash
/// collision is rejected instead of aliasing two secret subsets onto one uid. The very large uid
/// range makes a collision vanishingly unlikely, while the explicit binding cap keeps the registry
/// and collision analysis bounded.
struct BindingIdentityRegistry {
    by_ref: HashMap<String, Option<ToolIdentity>>,
    by_uid: HashMap<u32, String>,
    uid_min: u32,
    uid_span: u32,
    max_bindings: usize,
}

impl BindingIdentityRegistry {
    fn production() -> Self {
        Self::with_bounds(
            MANAGED_BINDING_UID_MIN,
            MANAGED_BINDING_UID_SPAN,
            MAX_PREPARED_BINDINGS,
        )
    }

    fn with_bounds(uid_min: u32, uid_span: u32, max_bindings: usize) -> Self {
        Self {
            by_ref: HashMap::new(),
            by_uid: HashMap::new(),
            uid_min,
            uid_span,
            max_bindings,
        }
    }

    fn allocate(
        &mut self,
        binding_ref: &str,
        sandbox_identity: Option<ToolIdentity>,
    ) -> Result<Option<ToolIdentity>, HandError> {
        if let Some(identity) = self.by_ref.get(binding_ref) {
            return Ok(*identity);
        }
        if self.by_ref.len() >= self.max_bindings {
            return Err(hand_error(
                HandErrorCode::ResourceExhausted,
                false,
                "physical generation has reached the prepared-binding limit",
            ));
        }
        let Some(sandbox_identity) = sandbox_identity else {
            self.by_ref.insert(binding_ref.to_owned(), None);
            return Ok(None);
        };
        if self.uid_span == 0 {
            return Err(hand_error(
                HandErrorCode::ResourceExhausted,
                false,
                "managed-binding uid range is empty",
            ));
        }
        let digest = Sha256::digest(binding_ref.as_bytes());
        let hash = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let uid = self.uid_min + (hash % u64::from(self.uid_span)) as u32;
        if self.by_uid.contains_key(&uid) {
            return Err(hand_error(
                HandErrorCode::BindingConflict,
                false,
                "managed-binding uid collision",
            ));
        }
        let identity = ToolIdentity {
            uid,
            gid: sandbox_identity.gid,
            supervisor_uid: sandbox_identity.supervisor_uid,
        };
        self.by_uid.insert(uid, binding_ref.to_owned());
        self.by_ref.insert(binding_ref.to_owned(), Some(identity));
        Ok(Some(identity))
    }
}

/// Deliberately cannot be serialized or formatted. Values are zeroized when a generation exits.
struct SessionSecrets {
    generation: String,
    declared: BTreeSet<String>,
    values: HashMap<String, String>,
}

impl Drop for SessionSecrets {
    fn drop(&mut self) {
        for value in self.values.values_mut() {
            value.zeroize();
        }
        self.values.clear();
    }
}

struct OperationMeta {
    operation: OperationRef,
    target: TargetReceipt,
    cancellation: CancellationToken,
    notify: Arc<Notify>,
    stdin: Option<Arc<InteractiveControl>>,
}

struct OperationBook {
    registry: OperationRegistry,
    metadata: HashMap<String, OperationMeta>,
}

struct StdinBook {
    records: HashMap<String, StdinRecord>,
}

enum StdinRecord {
    InFlight { request_digest: Digest },
    Complete(Box<WriteStdinReceipt>),
}

/// One Hand guest per physical sandbox generation.
pub struct Hand {
    pub cfg: Config,
    target: RwLock<Option<ArmedTarget>>,
    bundles: RwLock<HashMap<String, (BundleDescriptor, PathBuf)>>,
    bindings: RwLock<HashMap<String, InstalledBinding>>,
    binding_identities: Mutex<BindingIdentityRegistry>,
    secrets: RwLock<HashMap<String, SessionSecrets>>,
    operations: Mutex<OperationBook>,
    acknowledgements: Arc<AcknowledgementStore>,
    file_effects: Arc<FileEffectStore>,
    file_effect_locks: [Mutex<()>; FILE_EFFECT_LOCK_SHARDS],
    stdin_writes: Mutex<StdinBook>,
    operation_slots: Arc<Semaphore>,
    files: LiveFiles,
    shutdown: CancellationToken,
}

impl Hand {
    pub fn new(cfg: Config) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(&cfg.workspace)?;
        std::fs::create_dir_all(&cfg.state_dir)?;
        std::fs::create_dir_all(&cfg.binding_dir)?;
        std::fs::create_dir_all(&cfg.tool_dir)?;
        std::fs::create_dir_all(&cfg.object_dir)?;
        let acknowledgement_dir = cfg.state_dir.join("ops");
        std::fs::create_dir_all(&acknowledgement_dir)?;
        let acknowledgements = Arc::new(AcknowledgementStore::open(
            &acknowledgement_dir.join("acknowledged.jsonl"),
        )?);
        let file_effects = Arc::new(FileEffectStore::open(
            &acknowledgement_dir.join("file-effects.jsonl"),
        )?);
        let files = LiveFiles::new(&cfg.workspace, cfg.state_dir.join("file-staging"))?;
        Ok(Arc::new(Self {
            cfg,
            target: RwLock::new(None),
            bundles: RwLock::new(HashMap::new()),
            bindings: RwLock::new(HashMap::new()),
            binding_identities: Mutex::new(BindingIdentityRegistry::production()),
            secrets: RwLock::new(HashMap::new()),
            operations: Mutex::new(OperationBook {
                registry: OperationRegistry::new(
                    MAX_RETAINED_OPERATIONS,
                    MAX_RETAINED_TERMINAL_BYTES,
                ),
                metadata: HashMap::new(),
            }),
            acknowledgements,
            file_effects,
            file_effect_locks: std::array::from_fn(|_| Mutex::new(())),
            stdin_writes: Mutex::new(StdinBook {
                records: HashMap::new(),
            }),
            operation_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_OPERATIONS)),
            files,
            shutdown: CancellationToken::new(),
        }))
    }

    pub async fn armed(&self) -> bool {
        self.target.read().await.is_some()
    }

    /// Arms an unconfigured generation exactly once. An exact provider retry is harmless; a
    /// different root/generation/network/resource seal is a permanent conflict.
    pub async fn arm(&self, target_ref: String, payload: RunPayload) -> Result<bool, HandError> {
        if payload.contract_digest != HAND_CONTRACT_DIGEST.trim() {
            return Err(invalid("Hand contract digest does not match the image"));
        }
        let now = wall_ms();
        if payload.expires_at_ms <= now
            || payload.expires_at_ms > now.saturating_add(MAX_TARGET_LIFETIME_MS)
        {
            return Err(invalid(
                "physical target expiry is outside the supported lifetime",
            ));
        }
        validate_connector(
            payload.connector,
            &payload.network,
            payload.allowlist_proxy.is_some(),
        )?;
        if payload
            .canary_exit_after_operation_id
            .as_ref()
            .is_some_and(|id| {
                !id.starts_with("image-canary-")
                    || id.parse::<brain_protocol::hand::Identifier>().is_err()
            })
        {
            return Err(invalid("image canary operation id is invalid"));
        }
        let proxy_environment = match payload.allowlist_proxy {
            Some(proxy) => {
                let proxy_url = format!("http://aex:{}@{}", proxy.capability, proxy.authority);
                HashMap::from([
                    ("HTTPS_PROXY".into(), proxy_url.clone()),
                    ("https_proxy".into(), proxy_url),
                ])
            }
            None => HashMap::new(),
        };
        let candidate = ArmedTarget {
            target_ref,
            generation: payload.generation,
            expires_at_ms: payload.expires_at_ms,
            root_id: payload.root_id,
            owner_session_id: payload.owner_session_id,
            connector: payload.connector,
            resource_class: payload.resource_class,
            resources: payload.resources,
            network: payload.network,
            proxy_environment,
            canary_exit_after_operation_id: payload.canary_exit_after_operation_id,
        };
        let mut target = self.target.write().await;
        if let Some(existing) = target.as_ref() {
            let exact = existing.target_ref == candidate.target_ref
                && existing.generation == candidate.generation
                && existing.expires_at_ms == candidate.expires_at_ms
                && existing.root_id == candidate.root_id
                && existing.owner_session_id == candidate.owner_session_id
                && existing.connector == candidate.connector
                && existing.resource_class == candidate.resource_class
                && canonical_equal(&existing.resources, &candidate.resources)?
                && canonical_equal(&existing.network, &candidate.network)?
                && existing.canary_exit_after_operation_id
                    == candidate.canary_exit_after_operation_id;
            return if exact {
                Ok(true)
            } else {
                Err(hand_error(
                    HandErrorCode::GenerationConflict,
                    false,
                    "physical generation is already armed with a different immutable seal",
                ))
            };
        }
        *target = Some(candidate);
        Ok(false)
    }

    pub async fn runtime_status(&self) -> Option<TargetRuntimeStatus> {
        self.target
            .read()
            .await
            .as_ref()
            .map(|target| TargetRuntimeStatus {
                target_ref: target.target_ref.clone(),
                generation: target.generation.clone(),
                root_id: target.root_id.clone(),
                owner_session_id: target.owner_session_id.clone(),
                connector: target.connector,
                resource_class: target.resource_class.clone(),
                armed: true,
            })
    }

    pub async fn should_exit_after_canary_receipt(&self, operation_id: &str) -> bool {
        self.target
            .read()
            .await
            .as_ref()
            .and_then(|target| target.canary_exit_after_operation_id.as_deref())
            == Some(operation_id)
    }

    pub async fn install_bundle(
        &self,
        metadata: InstallBundleMetadata,
        bytes: &[u8],
    ) -> Result<InstallReceipt, HandError> {
        if metadata.descriptor.runtime != BundleRuntime::Node22 {
            return Err(invalid(
                "the default Hand supports only the Node22 Tool runtime",
            ));
        }
        if metadata.descriptor.bytes.get() > brain_protocol::MAX_TOOL_BUNDLE_BYTES as u64
            || metadata.descriptor.bytes.get() != bytes.len() as u64
            || metadata.descriptor.object.bytes != bytes.len() as u64
            || metadata.descriptor.object.sha256 != metadata.descriptor.bundle_digest
            || hex::encode(Sha256::digest(bytes)) != metadata.descriptor.bundle_digest.as_str()
        {
            return Err(invalid(
                "bundle bytes do not match the immutable descriptor",
            ));
        }
        let required_env = metadata
            .descriptor
            .required_env
            .iter()
            .map(|name| name.as_str())
            .collect::<BTreeSet<_>>();
        if metadata.descriptor.required_env.len() > brain_protocol::MAX_SESSION_SECRET_NAMES
            || required_env.len() != metadata.descriptor.required_env.len()
            || metadata.descriptor.required_env.iter().any(|name| {
                !environment_name_is_valid(name.as_str())
                    || reserved_tool_environment(name.as_str())
            })
        {
            return Err(invalid(
                "bundle descriptor contains an invalid or reserved environment name",
            ));
        }
        let digest = metadata.descriptor.bundle_digest.to_string();
        let mut bundles = self.bundles.write().await;
        if let Some((existing, _)) = bundles.get(&digest) {
            return if canonical_equal(existing, &metadata.descriptor)? {
                Ok(InstallReceipt {
                    installed: true,
                    replayed: true,
                })
            } else {
                Err(hand_error(
                    HandErrorCode::BindingConflict,
                    false,
                    "bundle digest is already installed with a different descriptor",
                ))
            };
        }
        let path = self.cfg.tool_dir.join(format!("{digest}.mjs"));
        let temporary = self.cfg.tool_dir.join(format!(".{digest}.install"));
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            // Every managed binding may read the verified module through the shared Tool group,
            // but no untrusted Tool process may rewrite code after digest verification.
            options.mode(0o640);
        }
        let mut file = options
            .open(&temporary)
            .await
            .map_err(|_| unavailable("could not stage the Tool bundle"))?;
        if file.write_all(bytes).await.is_err()
            || file.flush().await.is_err()
            || file.sync_all().await.is_err()
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(unavailable("could not stage the Tool bundle"));
        }
        drop(file);
        tokio::fs::rename(&temporary, &path)
            .await
            .map_err(|_| unavailable("could not install the Tool bundle"))?;
        bundles.insert(digest, (metadata.descriptor, path));
        Ok(InstallReceipt {
            installed: true,
            replayed: false,
        })
    }

    pub async fn install_binding(
        &self,
        request: InstallBindingRequest,
    ) -> Result<InstallReceipt, HandError> {
        let target = self.require_target().await?;
        if request.binding.root_id.as_str() != target.root_id
            || request.binding.realm != ExecutionRealm::AexManaged
        {
            return Err(hand_error(
                HandErrorCode::BindingConflict,
                false,
                "binding is outside this target root or execution realm",
            ));
        }
        let descriptor = request.binding.bundle.as_ref().ok_or_else(|| {
            hand_error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "managed execution requires an immutable Tool bundle",
            )
        })?;
        if descriptor.contract_digest != request.binding.contract_digest {
            return Err(hand_error(
                HandErrorCode::BindingConflict,
                false,
                "bundle and binding contract digests differ",
            ));
        }
        let bundles = self.bundles.read().await;
        let bundle_path = match bundles.get(descriptor.bundle_digest.as_str()) {
            Some((installed, path)) if canonical_equal(installed, descriptor)? => path.clone(),
            _ => return Err(invalid("binding references a bundle that is not installed")),
        };
        drop(bundles);
        let requires_undeclared_secret = self
            .secrets
            .read()
            .await
            .get(request.binding.session_id.as_str())
            .is_some_and(|secrets| {
                descriptor
                    .required_env
                    .iter()
                    .any(|name| !secrets.declared.contains(name.as_str()))
            });
        if requires_undeclared_secret {
            return Err(hand_error(
                HandErrorCode::BindingConflict,
                false,
                "binding requires environment outside the prepared session secret union",
            ));
        }
        let mut bindings = self.bindings.write().await;
        if let Some(existing) = bindings.get(request.binding_ref.as_str()) {
            return if canonical_equal(&existing.seal, &request.binding)? {
                Ok(InstallReceipt {
                    installed: true,
                    replayed: true,
                })
            } else {
                Err(hand_error(
                    HandErrorCode::BindingConflict,
                    false,
                    "binding_ref is already installed with a different seal",
                ))
            };
        }
        let identity = self
            .binding_identities
            .lock()
            .await
            .allocate(request.binding_ref.as_str(), self.cfg.tool_identity)?;
        bindings.insert(
            request.binding_ref.to_string(),
            InstalledBinding {
                seal: request.binding,
                bundle_path,
                identity,
            },
        );
        Ok(InstallReceipt {
            installed: true,
            replayed: false,
        })
    }

    pub async fn install_object_file(
        &self,
        metadata: InstallObjectMetadata,
        temporary: PathBuf,
        actual_bytes: u64,
        actual_sha256: &str,
    ) -> Result<InstallReceipt, HandError> {
        if metadata.object.bytes != actual_bytes || actual_sha256 != metadata.object.sha256.as_str()
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(invalid("object bytes do not match the immutable reference"));
        }
        let digest = metadata.object.sha256.as_str();
        let path = self.cfg.object_dir.join(digest);
        if path.exists() {
            let existing = tokio::fs::metadata(&path)
                .await
                .map_err(|_| unavailable("installed object is unavailable"))?;
            let _ = tokio::fs::remove_file(&temporary).await;
            return if existing.is_file() && existing.len() == actual_bytes {
                Ok(InstallReceipt {
                    installed: true,
                    replayed: true,
                })
            } else {
                Err(invalid("object digest is installed with different bytes"))
            };
        }
        if tokio::fs::rename(&temporary, &path).await.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            let existing = tokio::fs::metadata(&path)
                .await
                .map_err(|_| unavailable("could not atomically install object input"))?;
            if !existing.is_file() || existing.len() != actual_bytes {
                return Err(unavailable("could not atomically install object input"));
            }
            return Ok(InstallReceipt {
                installed: true,
                replayed: true,
            });
        }
        Ok(InstallReceipt {
            installed: true,
            replayed: false,
        })
    }

    pub async fn open_file_export(
        &self,
        request: SandboxFileRequest,
    ) -> Result<(FileEntry, std::fs::File), HandError> {
        self.fence(&request.target, request.expected_generation.as_str())
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let reader = blocking_file(move || files.open_reader(&path)).await?;
        Ok((file_entry(&reader.entry)?, reader.file))
    }

    pub async fn install_secrets(
        &self,
        request: InstallSecretsRequest,
    ) -> Result<InstallReceipt, HandError> {
        let target = self.require_target().await?;
        if request.generation != target.generation {
            return Err(generation_conflict());
        }
        let declared = request.env_names.iter().cloned().collect::<BTreeSet<_>>();
        if !secret_material_fits(&request.env_names, &request.values) {
            return Err(invalid(
                "secret material is outside the canonical bounded environment union",
            ));
        }
        if declared.iter().any(|name| reserved_tool_environment(name)) {
            return Err(invalid(
                "secret environment name conflicts with the trusted Tool runtime boundary",
            ));
        }
        let installed_requirements_are_declared = self
            .bindings
            .read()
            .await
            .values()
            .filter(|binding| binding.seal.session_id.as_str() == request.session_id)
            .flat_map(|binding| {
                binding
                    .seal
                    .bundle
                    .iter()
                    .flat_map(|bundle| bundle.required_env.iter())
            })
            .all(|name| declared.contains(name.as_str()));
        if !installed_requirements_are_declared {
            return Err(invalid(
                "prepared environment-name union omits an installed binding requirement",
            ));
        }
        let mut secrets = self.secrets.write().await;
        if let Some(existing) = secrets.get(&request.session_id) {
            return if existing.generation == request.generation
                && existing.declared == declared
                && existing.values == request.values
            {
                Ok(InstallReceipt {
                    installed: true,
                    replayed: true,
                })
            } else {
                Err(hand_error(
                    HandErrorCode::GenerationConflict,
                    false,
                    "secret material conflicts with the installed generation",
                ))
            };
        }
        secrets.insert(
            request.session_id,
            SessionSecrets {
                generation: request.generation,
                declared,
                values: request.values,
            },
        );
        Ok(InstallReceipt {
            installed: true,
            replayed: false,
        })
    }

    pub async fn submit(
        self: &Arc<Self>,
        request: SubmitRequest,
    ) -> Result<SubmitReceipt, HandError> {
        validate_wait(request.wait_up_to_ms)?;
        if operation_request_digest(&request.envelope) != request.envelope.request_digest {
            return Err(invalid("operation request_digest is not canonical"));
        }
        self.fence_acknowledged_submission(
            request.envelope.operation_id.as_str(),
            request.envelope.request_digest.as_str(),
        )?;
        let execution = self.validate_operation(&request.envelope).await?;
        let operation = operation_ref(&request.envelope, &execution.target)?;
        let target = target_receipt(&execution.target)?;
        let reservation_bytes = TERMINAL_ENVELOPE_BYTES;
        let notify = Arc::new(Notify::new());
        let cancellation = CancellationToken::new();
        let reservation = {
            let mut operations = self.operations.lock().await;
            let reservation = operations
                .registry
                .reserve(
                    request.envelope.operation_id.as_str(),
                    request.envelope.request_digest.as_str(),
                    reservation_bytes,
                )
                .map_err(operation_error)?;
            if reservation == Reservation::New {
                operations.metadata.insert(
                    request.envelope.operation_id.to_string(),
                    OperationMeta {
                        operation: operation.clone(),
                        target: target.clone(),
                        cancellation: cancellation.clone(),
                        notify: notify.clone(),
                        stdin: None,
                    },
                );
                operations
                    .registry
                    .mark_running(request.envelope.operation_id.as_str())
                    .map_err(operation_error)?;
            } else {
                validate_operation_ref(
                    operations
                        .metadata
                        .get(request.envelope.operation_id.as_str()),
                    &operation,
                )?;
            }
            reservation
        };
        if reservation == Reservation::New {
            let hand = self.clone();
            tokio::spawn(async move {
                let _slot = match hand.operation_slots.clone().acquire_owned().await {
                    Ok(slot) => slot,
                    Err(_) => return,
                };
                let result = execute_bundle(BundleExecution {
                    bundle_path: execution.bundle_path,
                    descriptor: execution.descriptor,
                    envelope: request.envelope.clone(),
                    workspace: hand.cfg.workspace.clone(),
                    runner: hand.cfg.tool_runner.clone(),
                    environment: execution.environment,
                    proxy_environment: execution.target.proxy_environment,
                    identity: execution.identity,
                    boundary_library: hand.cfg.tool_boundary_library.clone(),
                    target_expires_at_ms: execution.target.expires_at_ms,
                    cancellation,
                })
                .await;
                hand.finish(request.envelope.operation_id.as_str(), result)
                    .await;
            });
        }
        let observation = self
            .observe_inner(operation.clone(), request.wait_up_to_ms)
            .await?;
        Ok(SubmitReceipt {
            observation,
            operation,
            replayed: reservation == Reservation::Existing,
        })
    }

    pub async fn observe(
        &self,
        request: ObserveRequest,
    ) -> Result<OperationObservation, HandError> {
        validate_wait(request.wait_ms)?;
        self.observe_inner(request.operation, request.wait_ms).await
    }

    pub async fn cancel(&self, request: CancelRequest) -> Result<CancellationReceipt, HandError> {
        let (accepted, cancellation) = {
            let mut operations = self.operations.lock().await;
            validate_operation_ref(
                operations
                    .metadata
                    .get(request.operation.operation_id.as_str()),
                &request.operation,
            )?;
            let accepted = operations
                .registry
                .request_cancel(request.operation.operation_id.as_str())
                .map_err(operation_error)?;
            let cancellation = operations
                .metadata
                .get(request.operation.operation_id.as_str())
                .map(|meta| meta.cancellation.clone());
            (accepted, cancellation)
        };
        if accepted && let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        let observation = self.observe_inner(request.operation.clone(), 0).await?;
        Ok(CancellationReceipt {
            accepted,
            observation,
            operation: request.operation,
        })
    }

    pub async fn acknowledge_terminal(
        &self,
        request: AcknowledgeTerminalRequest,
    ) -> Result<Acknowledgement, HandError> {
        let acknowledgements = self.acknowledgements.clone();
        let replay_operation = request.operation.clone();
        let replay_digest = request.terminal_digest.clone();
        let replayed = tokio::task::spawn_blocking(move || {
            acknowledgements.acknowledgement_exists(&replay_operation, &replay_digest)
        })
        .await
        .map_err(|_| unavailable("acknowledgement storage task failed"))?
        .map_err(ack_store_error)?;
        if replayed {
            self.release_acknowledged_terminal(&request.operation, &request.terminal_digest)
                .await?;
            return Ok(Acknowledgement { acknowledged: true });
        }

        {
            let operations = self.operations.lock().await;
            validate_operation_ref(
                operations
                    .metadata
                    .get(request.operation.operation_id.as_str()),
                &request.operation,
            )?;
            operations
                .registry
                .validate_terminal_ack(
                    request.operation.operation_id.as_str(),
                    request.terminal_digest.as_str(),
                )
                .map_err(operation_error)?;
        }

        let acknowledgements = self.acknowledgements.clone();
        let operation = request.operation.clone();
        let terminal_digest = request.terminal_digest.clone();
        tokio::task::spawn_blocking(move || acknowledgements.retain(&operation, &terminal_digest))
            .await
            .map_err(|_| unavailable("acknowledgement storage task failed"))?
            .map_err(ack_store_error)?;

        // Concurrent exact acknowledgements may race after the durable tombstone. The first one
        // releases the payload; all others replay success from the same tombstone.
        self.release_acknowledged_terminal(&request.operation, &request.terminal_digest)
            .await?;
        Ok(Acknowledgement { acknowledged: true })
    }

    async fn release_acknowledged_terminal(
        &self,
        operation: &OperationRef,
        terminal_digest: &Digest,
    ) -> Result<(), HandError> {
        let mut operations = self.operations.lock().await;
        match operations
            .registry
            .acknowledge_terminal(operation.operation_id.as_str(), terminal_digest.as_str())
        {
            Ok(()) => {
                operations.metadata.remove(operation.operation_id.as_str());
            }
            // Exact replay after an earlier release or guest reconstruction needs no payload.
            Err(OperationError::Unknown) => {}
            Err(error) => return Err(operation_error(error)),
        }
        drop(operations);
        // Once Brain has durably committed and acknowledged the execution terminal, stdin
        // receipts for that execution no longer need generation-lifetime retention. Exact ACK
        // replay remains fenced by the durable payload-free acknowledgement log.
        self.stdin_writes.lock().await.records.retain(|_, record| {
            !matches!(
                record,
                StdinRecord::Complete(receipt)
                    if receipt.observation.operation.operation_id == operation.operation_id
            )
        });
        Ok(())
    }

    fn workspace_files(&self) -> Result<LiveFiles, HandError> {
        self.files
            .try_clone()
            .map_err(|_| unavailable("workspace capability cannot be cloned"))
    }

    pub async fn list_files(
        &self,
        request: SandboxFileListRequest,
    ) -> Result<SandboxFileList, HandError> {
        self.fence(&request.target, &request.expected_generation)
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let cursor = request.cursor.map(|cursor| cursor.to_string());
        let limit = request.limit as usize;
        let page = blocking_file(move || files.list(&path, cursor.as_deref(), limit)).await?;
        Ok(SandboxFileList {
            entries: page
                .entries
                .iter()
                .map(file_entry)
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor,
        })
    }

    pub async fn stat_file(&self, request: SandboxFileRequest) -> Result<FileEntry, HandError> {
        self.fence(&request.target, request.expected_generation.as_str())
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let entry = blocking_file(move || files.stat(&path)).await?;
        file_entry(&entry)
    }

    pub async fn read_file(
        &self,
        request: SandboxFileRequest,
    ) -> Result<SandboxFileContent, HandError> {
        self.fence(&request.target, request.expected_generation.as_str())
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let content = blocking_file(move || files.read(&path, MAX_INLINE_FILE_BYTES)).await?;
        Ok(SandboxFileContent {
            entry: file_entry(&content.entry)?,
            content_base64: base64::engine::general_purpose::STANDARD.encode(content.bytes),
        })
    }

    pub async fn write_file(
        &self,
        request: GuestFileWriteRequest,
    ) -> Result<FileEffectStoredResult, HandError> {
        self.fence(&request.target, request.expected_generation.as_str())
            .await?;
        if request.effect.kind == FileEffectKind::CopyExport {
            return Err(invalid("copy export cannot use the workspace write path"));
        }
        let lock = file_effect_lock_index(&request.effect.operation_id);
        let _guard = self.file_effect_locks[lock].lock().await;
        match self.claim_file_effect_inner(request.effect.clone()).await? {
            FileEffectReservation::Replay(result) => return Ok(*result),
            FileEffectReservation::New => {}
        }
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let overwrite = request.overwrite;
        let entry = match request.source {
            GuestFileWriteSource::Inline { content_base64 } => {
                blocking_hand(move || {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(content_base64.as_bytes())
                        .map_err(|_| invalid("inline file content is not padded base64"))?;
                    if bytes.len() > 1024 * 1024 {
                        return Err(invalid("inline file content exceeds 1 MiB"));
                    }
                    files.write(&path, &bytes, overwrite).map_err(file_error)
                })
                .await?
            }
            GuestFileWriteSource::InstalledObject { object } => {
                let source = self.cfg.object_dir.join(object.sha256.as_str());
                let bytes = object.bytes;
                let digest = object.sha256.to_string();
                blocking_hand(move || {
                    if !source.is_file() {
                        return Err(invalid(
                            "object file write was not staged by the trusted Hand adapter",
                        ));
                    }
                    files
                        .write_from_file(&path, &source, bytes, &digest, overwrite)
                        .map_err(file_error)
                })
                .await?
            }
        };
        let file = file_entry(&entry)?;
        let result = match request.effect.kind {
            FileEffectKind::Write => FileEffectStoredResult::Write(SandboxFileWriteResult {
                file,
                operation_id: request
                    .effect
                    .operation_id
                    .parse()
                    .map_err(|_| invalid("file operation_id is invalid"))?,
                replayed: false,
                request_digest: request
                    .effect
                    .request_digest
                    .parse()
                    .map_err(|_| invalid("file request_digest is invalid"))?,
            }),
            FileEffectKind::CopyImport => FileEffectStoredResult::Copy(SandboxCopyResult {
                file,
                object: None,
                operation_id: request
                    .effect
                    .operation_id
                    .parse()
                    .map_err(|_| invalid("copy operation_id is invalid"))?,
                replayed: false,
                request_digest: request
                    .effect
                    .request_digest
                    .parse()
                    .map_err(|_| invalid("copy request_digest is invalid"))?,
            }),
            FileEffectKind::CopyExport => unreachable!("checked above"),
        };
        self.complete_file_effect_inner(request.effect, result)
            .await
    }

    pub async fn reserve_file_effect(
        &self,
        identity: FileEffectIdentity,
    ) -> Result<FileEffectReservation, HandError> {
        self.reserve_file_effect_inner(identity).await
    }

    pub async fn claim_file_effect(
        &self,
        identity: FileEffectIdentity,
    ) -> Result<FileEffectReservation, HandError> {
        self.claim_file_effect_inner(identity).await
    }

    pub async fn complete_file_effect(
        &self,
        result: FileEffectStoredResult,
    ) -> Result<FileEffectStoredResult, HandError> {
        let identity = file_effect_result_identity(&result)?;
        let lock = file_effect_lock_index(&identity.operation_id);
        let _guard = self.file_effect_locks[lock].lock().await;
        self.complete_file_effect_inner(identity, result).await
    }

    async fn reserve_file_effect_inner(
        &self,
        identity: FileEffectIdentity,
    ) -> Result<FileEffectReservation, HandError> {
        let store = self.file_effects.clone();
        blocking_hand(move || {
            store
                .reserve(&identity)
                .map(|reservation| match reservation {
                    EffectReservation::New => FileEffectReservation::New,
                    EffectReservation::Replay(result) => FileEffectReservation::Replay(result),
                })
                .map_err(file_effect_store_error)
        })
        .await
    }

    async fn claim_file_effect_inner(
        &self,
        identity: FileEffectIdentity,
    ) -> Result<FileEffectReservation, HandError> {
        let store = self.file_effects.clone();
        blocking_hand(move || {
            store
                .claim(&identity)
                .map(|reservation| match reservation {
                    EffectReservation::New => FileEffectReservation::New,
                    EffectReservation::Replay(result) => FileEffectReservation::Replay(result),
                })
                .map_err(file_effect_store_error)
        })
        .await
    }

    async fn complete_file_effect_inner(
        &self,
        identity: FileEffectIdentity,
        result: FileEffectStoredResult,
    ) -> Result<FileEffectStoredResult, HandError> {
        let store = self.file_effects.clone();
        blocking_hand(move || {
            store
                .complete(&identity, result)
                .map_err(file_effect_store_error)
        })
        .await
    }

    pub async fn find_files(
        &self,
        request: SandboxSearchRequest,
    ) -> Result<SandboxFileList, HandError> {
        self.fence(&request.target, &request.expected_generation)
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let expression = request.expression.to_string();
        let cursor = request.cursor.map(|cursor| cursor.to_string());
        let limit = request.limit as usize;
        let page =
            blocking_file(move || files.find(&path, &expression, cursor.as_deref(), limit)).await?;
        Ok(SandboxFileList {
            entries: page
                .entries
                .iter()
                .map(file_entry)
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor,
        })
    }

    pub async fn grep_files(
        &self,
        request: SandboxSearchRequest,
    ) -> Result<SandboxFileList, HandError> {
        self.fence(&request.target, &request.expected_generation)
            .await?;
        let files = self.workspace_files()?;
        let path = request.path.to_string();
        let expression = request.expression.to_string();
        let cursor = request.cursor.map(|cursor| cursor.to_string());
        let limit = request.limit as usize;
        let page =
            blocking_file(move || files.grep(&path, &expression, cursor.as_deref(), limit)).await?;
        Ok(SandboxFileList {
            entries: page
                .entries
                .iter()
                .map(file_entry)
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor,
        })
    }

    pub async fn execute_sandbox(
        self: &Arc<Self>,
        request: SandboxExecutionRequest,
    ) -> Result<SubmitReceipt, HandError> {
        if sandbox_execution_request_digest(&request) != request.request_digest {
            return Err(invalid("sandbox execution request_digest is not canonical"));
        }
        self.fence_acknowledged_submission(
            request.execution_id.as_str(),
            request.request_digest.as_str(),
        )?;
        let target = self
            .fence(&request.target, request.expected_generation.as_str())
            .await?;
        validate_resource_subset(&request.resources, &target.resources)?;
        if !network_ceiling_is_subset(&request.network, &target.network) {
            return Err(hand_error(
                HandErrorCode::GenerationConflict,
                false,
                "sandbox execution network policy widens the immutable root target seal",
            ));
        }
        let cwd = request
            .input
            .cwd
            .as_ref()
            .map_or("/workspace", |cwd| cwd.as_str());
        if cwd.is_empty() {
            return Err(invalid(
                "sandbox execution cwd must be /workspace or a child path",
            ));
        }
        let files = self.workspace_files()?;
        let cwd = cwd.to_owned();
        let cwd = blocking_file(move || files.open_directory(&cwd)).await?;
        let operation = OperationRef {
            generation: target
                .generation
                .parse()
                .map_err(|_| invalid("generation is not a canonical operation locator"))?,
            operation_id: request.execution_id.clone(),
            receipt_ref: operation_receipt_ref(
                request.execution_id.as_str(),
                request.request_digest.as_str(),
                target.target_ref.as_str(),
                target.generation.as_str(),
            )?,
            request_digest: request.request_digest.clone(),
            target: request.target.clone(),
            target_ref: target
                .target_ref
                .parse()
                .map_err(|_| invalid("target_ref is not a canonical operation locator"))?,
        };
        let target_receipt = target_receipt(&target)?;
        let reservation_bytes = TERMINAL_ENVELOPE_BYTES;
        let notify = Arc::new(Notify::new());
        let cancellation = CancellationToken::new();
        let control = request
            .input
            .interactive
            .then(|| Arc::new(InteractiveControl::default()));
        let reservation = {
            let mut operations = self.operations.lock().await;
            let reservation = operations
                .registry
                .reserve(
                    request.execution_id.as_str(),
                    request.request_digest.as_str(),
                    reservation_bytes,
                )
                .map_err(operation_error)?;
            if reservation == Reservation::New {
                operations.metadata.insert(
                    request.execution_id.to_string(),
                    OperationMeta {
                        operation: operation.clone(),
                        target: target_receipt.clone(),
                        cancellation: cancellation.clone(),
                        notify: notify.clone(),
                        stdin: control.clone(),
                    },
                );
                operations
                    .registry
                    .mark_running(request.execution_id.as_str())
                    .map_err(operation_error)?;
            } else {
                validate_operation_ref(
                    operations.metadata.get(request.execution_id.as_str()),
                    &operation,
                )?;
            }
            reservation
        };
        if reservation == Reservation::New {
            let hand = self.clone();
            let execution_id = request.execution_id.to_string();
            let command = request.input.command.to_string();
            let timeout_ms = request.resources.timeout_ms.get();
            let max_output_bytes = request.resources.max_output_bytes.get();
            let interactive = request.input.interactive;
            tokio::spawn(async move {
                let _slot = match hand.operation_slots.clone().acquire_owned().await {
                    Ok(slot) => slot,
                    Err(_) => return,
                };
                let result = execute_shell(ShellExecution {
                    command,
                    cwd,
                    workspace: hand.cfg.workspace.clone(),
                    timeout_ms,
                    max_output_bytes,
                    interactive,
                    proxy_environment: target.proxy_environment,
                    identity: hand.cfg.tool_identity,
                    boundary_library: hand.cfg.tool_boundary_library.clone(),
                    target_expires_at_ms: target.expires_at_ms,
                    cancellation,
                    control,
                })
                .await;
                hand.finish(&execution_id, result).await;
            });
        }
        let observation = self.observe_inner(operation.clone(), 0).await?;
        Ok(SubmitReceipt {
            observation,
            operation,
            replayed: reservation == Reservation::Existing,
        })
    }

    pub async fn write_stdin(
        &self,
        request: WriteStdinRequest,
    ) -> Result<WriteStdinReceipt, HandError> {
        if write_stdin_request_digest(&request) != request.request_digest {
            return Err(invalid("write_stdin request_digest is not canonical"));
        }
        if request.text.len() > brain_protocol::MAX_WRITE_STDIN_BYTES {
            return Err(invalid(
                "stdin text exceeds the atomic 4096-byte pipe-write bound",
            ));
        }
        let target = self
            .fence(&request.target, request.expected_generation.as_str())
            .await?;
        let (control, execution_operation) = {
            let operations = self.operations.lock().await;
            let meta = operations
                .metadata
                .get(request.execution_id.as_str())
                .ok_or_else(|| operation_error(OperationError::Unknown))?;
            if meta.operation.operation_id != request.execution_id
                || !canonical_equal(&meta.operation.target, &request.target)?
                || meta.operation.generation.as_str() != target.generation
                || meta.operation.target_ref.as_str() != target.target_ref
                || meta.target.target_ref.as_str() != target.target_ref
                || meta.target.generation.as_str() != target.generation
            {
                return Err(hand_error(
                    HandErrorCode::OperationConflict,
                    false,
                    "stdin target does not match the reserved sandbox execution",
                ));
            }
            (meta.stdin.clone(), meta.operation.clone())
        };
        // Reserve globally, then release the book lock before touching a potentially full pipe.
        // Exact concurrent retries wait on the short bounded write; unrelated executions never
        // queue behind a hostile shell that refuses to read stdin.
        let wait_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut writes = self.stdin_writes.lock().await;
            match writes.records.get(request.operation_id.as_str()) {
                Some(StdinRecord::Complete(existing)) => {
                    if existing.request_digest == request.request_digest {
                        let mut receipt = existing.as_ref().clone();
                        receipt.replayed = true;
                        drop(writes);
                        receipt.observation =
                            self.observe_inner(execution_operation.clone(), 0).await?;
                        return Ok(receipt);
                    } else {
                        return Err(stdin_conflict());
                    }
                }
                Some(StdinRecord::InFlight { request_digest }) => {
                    if request_digest != &request.request_digest {
                        return Err(stdin_conflict());
                    }
                }
                None => {
                    if writes.records.len() >= MAX_RETAINED_STDIN_WRITES {
                        return Err(hand_error(
                            HandErrorCode::ResourceExhausted,
                            false,
                            "stdin idempotency retention is full for this sandbox generation",
                        ));
                    }
                    writes.records.insert(
                        request.operation_id.to_string(),
                        StdinRecord::InFlight {
                            request_digest: request.request_digest.clone(),
                        },
                    );
                    break;
                }
            }
            drop(writes);
            if tokio::time::Instant::now() >= wait_deadline {
                return Err(unavailable(
                    "an exact stdin write is still completing; observe and retry",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // Empty text without EOF is an observation-only poll. Otherwise the byte bound is
        // PIPE_BUF on supported Linux images, so the one append is all-or-nothing; EOF closes the
        // same pipe only after that append succeeds.
        let accepted = if request.text.is_empty() && !request.eof {
            false
        } else {
            match control {
                Some(control) => {
                    control
                        .send_atomic(request.text.as_bytes(), request.eof)
                        .await
                }
                None => false,
            }
        };
        let observation = self.observe_inner(execution_operation, 0).await?;
        let receipt = WriteStdinReceipt {
            accepted,
            observation,
            operation_id: request.operation_id.clone(),
            replayed: false,
            request_digest: request.request_digest.clone(),
        };
        let mut writes = self.stdin_writes.lock().await;
        match writes.records.get(request.operation_id.as_str()) {
            Some(StdinRecord::InFlight { request_digest })
                if request_digest == &request.request_digest =>
            {
                writes.records.insert(
                    request.operation_id.to_string(),
                    StdinRecord::Complete(Box::new(receipt.clone())),
                );
            }
            _ => return Err(stdin_conflict()),
        }
        Ok(receipt)
    }

    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        // Refuse every queued operation before collecting active cancellations. Existing tasks
        // retain their permits until their process group has been killed, reaped, and projected
        // terminal; queued tasks never spawn a child after shutdown begins.
        self.operation_slots.close();
        let cancellations = self
            .operations
            .lock()
            .await
            .metadata
            .values()
            .map(|meta| meta.cancellation.clone())
            .collect::<Vec<_>>();
        for cancellation in cancellations {
            cancellation.cancel();
        }
        // `terminate_process_group` allows two seconds for TERM and one second for the final KILL
        // reap. Keep the supervisor (and therefore CAP_KILL) alive across that complete bounded
        // cleanup path instead of dropping Tokio while cross-UID children can still be running.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
        while self.operation_slots.available_permits() != MAX_CONCURRENT_OPERATIONS
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn require_target(&self) -> Result<TargetSnapshot, HandError> {
        let target = self
            .target
            .read()
            .await
            .as_ref()
            .map(TargetSnapshot::from)
            .ok_or_else(|| {
                hand_error(
                    HandErrorCode::SandboxNotMaterialized,
                    false,
                    "physical generation has not been armed",
                )
            })?;
        if wall_ms() >= target.expires_at_ms {
            return Err(hand_error(
                HandErrorCode::SandboxGone,
                false,
                "physical sandbox generation reached its hard deadline",
            ));
        }
        Ok(target)
    }

    async fn fence(
        &self,
        target: &brain_protocol::hand::SandboxTarget,
        generation: &str,
    ) -> Result<TargetSnapshot, HandError> {
        let physical = self.require_target().await?;
        if target.root_id.as_str() != physical.root_id || generation != physical.generation {
            return Err(generation_conflict());
        }
        Ok(physical)
    }

    async fn validate_operation(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<ValidatedExecution, HandError> {
        let target = self.require_target().await?;
        if envelope.root_id.as_str() != target.root_id
            || envelope
                .generation
                .as_ref()
                .is_some_and(|generation| generation.as_str() != target.generation)
            || envelope
                .target_ref
                .as_ref()
                .is_some_and(|target_ref| target_ref.as_str() != target.target_ref)
        {
            return Err(generation_conflict());
        }
        validate_resource_subset(&envelope.resources, &target.resources)?;
        if !network_ceiling_is_subset(&envelope.network, &target.network) {
            return Err(hand_error(
                HandErrorCode::GenerationConflict,
                false,
                "operation network policy widens the immutable root target seal",
            ));
        }
        let bindings = self.bindings.read().await;
        let binding = bindings.get(envelope.binding_ref.as_str()).ok_or_else(|| {
            hand_error(
                HandErrorCode::BindingConflict,
                false,
                "binding_ref is not installed",
            )
        })?;
        if binding.seal.root_id != envelope.root_id
            || binding.seal.session_id != envelope.session_id
            || binding.seal.capability != envelope.capability
            || binding.seal.realm != ExecutionRealm::AexManaged
        {
            return Err(hand_error(
                HandErrorCode::BindingConflict,
                false,
                "operation does not match the immutable binding seal",
            ));
        }
        let descriptor = binding.seal.bundle.clone().ok_or_else(|| {
            hand_error(
                HandErrorCode::CapabilityUnavailable,
                false,
                "managed binding has no Tool bundle",
            )
        })?;
        let secrets = self.secrets.read().await;
        let values = secrets.get(envelope.session_id.as_str());
        let mut environment = HashMap::new();
        for name in &descriptor.required_env {
            let value = values
                .and_then(|values| values.values.get(name.as_str()))
                .ok_or_else(|| unavailable("required Tool environment has not been delivered"))?;
            environment.insert(name.to_string(), value.clone());
        }
        Ok(ValidatedExecution {
            bundle_path: binding.bundle_path.clone(),
            descriptor,
            environment,
            identity: binding.identity,
            target,
        })
    }

    fn fence_acknowledged_submission(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<(), HandError> {
        match self
            .acknowledgements
            .fence_submission(operation_id, request_digest)
            .map_err(ack_store_error)?
        {
            SubmissionFence::Clear => Ok(()),
            SubmissionFence::Acknowledged => Err(hand_error(
                HandErrorCode::OperationUnknown,
                false,
                "operation terminal was already committed and released",
            )),
        }
    }

    async fn finish(&self, operation_id: &str, mut result: crate::process::ExecutionResult) {
        // The child boundary already enforces the operation's narrower output ceiling. Keep this
        // final check at the receipt boundary as defense in depth: a future executor must never
        // retain a success that Brain cannot journal after the effect has happened.
        if !terminal_inline_fits(&result.inline) {
            result.inline = serde_json::json!({
                "error": "execution may have completed, but its inline result exceeded the Brain terminal limit; store large data in session storage or the sandbox and return a key/path"
            });
            result.is_error = true;
            result.outcome = TerminalOutcome::Failed;
        }
        let mut terminal = TerminalResult {
            duration_ms: Some(result.duration_ms),
            exit_code: result.exit_code,
            inline: Some(result.inline),
            is_error: result.is_error,
            object: None,
            outcome: result.outcome,
            terminal_digest: "0".repeat(64).parse().expect("digest placeholder"),
        };
        terminal.terminal_digest = terminal_result_digest(&terminal);
        let mut operations = self.operations.lock().await;
        let Some(meta) = operations.metadata.get(operation_id) else {
            return;
        };
        let operation = meta.operation.clone();
        let target = meta.target.clone();
        let notify = meta.notify.clone();
        let observation = OperationObservation {
            next_cursor: "1".parse().expect("cursor"),
            operation: operation.clone(),
            output: Vec::new(),
            state: ContractOperationState::Terminal,
            target: Some(target.clone()),
            terminal: Some(terminal.clone()),
        };
        let completed = serde_json::to_vec(&observation).is_ok_and(|payload| {
            operations
                .registry
                .complete(operation_id, terminal.terminal_digest.as_str(), payload)
                .is_ok()
        });
        if completed {
            notify.notify_waiters();
            return;
        }

        // This should be unreachable after admission reserves output plus worst-case encoded
        // diagnostics. Still fail terminally instead of retaining a fictitious `running` state if
        // a future contract shape grows beyond that calculation.
        let mut fallback = TerminalResult {
            duration_ms: Some(result.duration_ms),
            exit_code: result.exit_code,
            inline: Some(serde_json::json!({
                "error": "terminal result could not be retained within its reserved capacity"
            })),
            is_error: true,
            object: None,
            outcome: TerminalOutcome::Interrupted,
            terminal_digest: "0".repeat(64).parse().expect("digest placeholder"),
        };
        fallback.terminal_digest = terminal_result_digest(&fallback);
        let fallback_observation = OperationObservation {
            next_cursor: "1".parse().expect("cursor"),
            operation,
            output: Vec::new(),
            state: ContractOperationState::Terminal,
            target: Some(target),
            terminal: Some(fallback.clone()),
        };
        if let Ok(payload) = serde_json::to_vec(&fallback_observation)
            && operations
                .registry
                .complete(operation_id, fallback.terminal_digest.as_str(), payload)
                .is_ok()
        {
            notify.notify_waiters();
        }
    }

    async fn observe_inner(
        &self,
        operation: OperationRef,
        wait_ms: u64,
    ) -> Result<OperationObservation, HandError> {
        let notify = {
            let operations = self.operations.lock().await;
            validate_operation_ref(
                operations.metadata.get(operation.operation_id.as_str()),
                &operation,
            )?;
            operations
                .registry
                .observe(operation.operation_id.as_str())
                .ok_or_else(|| operation_error(OperationError::Unknown))?;
            operations
                .metadata
                .get(operation.operation_id.as_str())
                .map(|meta| meta.notify.clone())
                .ok_or_else(|| operation_error(OperationError::Unknown))?
        };
        if wait_ms > 0 {
            // Enable the owned notification before the second state check. `notify_waiters`
            // does not retain a permit for a future waiter, so checking once and then creating a
            // waiter has a race that can add the entire 30-second observe window after terminal.
            let notified = notify.notified_owned();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let terminal = {
                let operations = self.operations.lock().await;
                matches!(
                    operations
                        .registry
                        .observe(operation.operation_id.as_str())
                        .map(|record| &record.state),
                    Some(OperationState::Terminal { .. })
                )
            };
            if !terminal {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(wait_ms.min(MAX_WAIT_MS)),
                    notified,
                )
                .await;
            }
        }
        let operations = self.operations.lock().await;
        let record = operations
            .registry
            .observe(operation.operation_id.as_str())
            .ok_or_else(|| operation_error(OperationError::Unknown))?;
        let meta = operations
            .metadata
            .get(operation.operation_id.as_str())
            .ok_or_else(|| operation_error(OperationError::Unknown))?;
        match &record.state {
            OperationState::Terminal { payload, .. } => serde_json::from_slice(payload)
                .map_err(|_| unavailable("retained terminal observation is unavailable")),
            OperationState::Accepted | OperationState::Running => Ok(OperationObservation {
                next_cursor: "0".parse().expect("cursor"),
                operation,
                output: Vec::new(),
                state: match record.state {
                    OperationState::Accepted => ContractOperationState::Accepted,
                    OperationState::Running => ContractOperationState::Running,
                    OperationState::Terminal { .. } => unreachable!(),
                },
                target: Some(meta.target.clone()),
                terminal: None,
            }),
        }
    }
}

#[derive(Clone)]
struct TargetSnapshot {
    target_ref: String,
    generation: String,
    expires_at_ms: u64,
    root_id: String,
    resources: ResourceCeiling,
    network: NetworkCeiling,
    proxy_environment: HashMap<String, String>,
}

impl From<&ArmedTarget> for TargetSnapshot {
    fn from(target: &ArmedTarget) -> Self {
        Self {
            target_ref: target.target_ref.clone(),
            generation: target.generation.clone(),
            expires_at_ms: target.expires_at_ms,
            root_id: target.root_id.clone(),
            resources: target.resources.clone(),
            network: target.network.clone(),
            proxy_environment: target.proxy_environment.clone(),
        }
    }
}

struct ValidatedExecution {
    bundle_path: PathBuf,
    descriptor: BundleDescriptor,
    environment: HashMap<String, String>,
    identity: Option<ToolIdentity>,
    target: TargetSnapshot,
}

fn operation_ref(
    envelope: &OperationEnvelope,
    physical: &TargetSnapshot,
) -> Result<OperationRef, HandError> {
    Ok(OperationRef {
        generation: physical
            .generation
            .as_str()
            .parse()
            .map_err(|_| invalid("generation is not a canonical operation locator"))?,
        operation_id: envelope.operation_id.clone(),
        receipt_ref: operation_receipt_ref(
            envelope.operation_id.as_str(),
            envelope.request_digest.as_str(),
            physical.target_ref.as_str(),
            physical.generation.as_str(),
        )?,
        request_digest: envelope.request_digest.clone(),
        target: SandboxTarget {
            binding_ref: envelope.binding_ref.clone(),
            kind: TargetKind::Default,
            root_id: envelope.root_id.clone(),
            sandbox_id: None,
            session_id: envelope.session_id.clone(),
        },
        target_ref: physical
            .target_ref
            .as_str()
            .parse()
            .map_err(|_| invalid("target_ref is not a canonical operation locator"))?,
    })
}

/// The target reference routes later work to one physical filesystem; the receipt reference names
/// one reserved operation on that target. It is deterministic so a lost submit response can be
/// reconstructed without adding a hot-path registry write, but distinct operations cannot alias.
fn operation_receipt_ref(
    operation_id: &str,
    request_digest: &str,
    target_ref: &str,
    generation: &str,
) -> Result<brain_protocol::hand::Identifier, HandError> {
    let mut hasher = Sha256::new();
    for part in [operation_id, request_digest, target_ref, generation] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("receipt:{}", hex::encode(hasher.finalize()))
        .parse()
        .map_err(|_| invalid("operation receipt locator is invalid"))
}

fn target_receipt(target: &TargetSnapshot) -> Result<TargetReceipt, HandError> {
    Ok(TargetReceipt {
        expires_at_ms: std::num::NonZeroU64::new(target.expires_at_ms)
            .ok_or_else(|| invalid("target expiry is invalid"))?,
        generation: target
            .generation
            .parse()
            .map_err(|_| invalid("generation is invalid"))?,
        target_ref: target
            .target_ref
            .parse()
            .map_err(|_| invalid("target_ref is invalid"))?,
    })
}

fn validate_operation_ref(
    meta: Option<&OperationMeta>,
    operation: &OperationRef,
) -> Result<(), HandError> {
    match meta {
        Some(meta) if canonical_equal(&meta.operation, operation)? => Ok(()),
        Some(_) => Err(hand_error(
            HandErrorCode::OperationConflict,
            false,
            "operation locator does not match the reserved receipt",
        )),
        None => Err(operation_error(OperationError::Unknown)),
    }
}

fn validate_wait(wait_ms: u64) -> Result<(), HandError> {
    if wait_ms > MAX_WAIT_MS {
        Err(invalid(format!("wait exceeds the {MAX_WAIT_MS} ms bound")))
    } else {
        Ok(())
    }
}

fn validate_connector(
    connector: ConnectorClass,
    network: &NetworkCeiling,
    has_proxy: bool,
) -> Result<(), HandError> {
    let exact = matches!(
        (connector, network, has_proxy),
        (ConnectorClass::None, NetworkCeiling::None, false)
            | (ConnectorClass::Public, NetworkCeiling::Public, false)
            | (
                ConnectorClass::Allowlist,
                NetworkCeiling::Allowlist(_),
                true
            )
    );
    if exact {
        Ok(())
    } else {
        Err(invalid(
            "connector class does not exactly match the root network seal",
        ))
    }
}

fn validate_resource_subset(
    request: &ResourceCeiling,
    physical: &ResourceCeiling,
) -> Result<(), HandError> {
    ResourceSupport {
        max_timeout_ms: physical.timeout_ms.get().min(MAX_OPERATION_TIMEOUT_MS),
        max_output_bytes: physical
            .max_output_bytes
            .get()
            .min(MAX_OPERATION_OUTPUT_BYTES),
    }
    .validate(ResourceRequest {
        timeout_ms: request.timeout_ms.get(),
        max_output_bytes: request.max_output_bytes.get(),
    })
    .map_err(|error| invalid(error.to_string()))?;
    let within = request.timeout_ms <= physical.timeout_ms
        && request.max_output_bytes <= physical.max_output_bytes;
    if within {
        Ok(())
    } else {
        Err(invalid(
            "operation resources widen the immutable root target seal",
        ))
    }
}

async fn blocking_file<T, F>(work: F) -> Result<T, HandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, LiveFileError> + Send + 'static,
{
    blocking_hand(move || work().map_err(file_error)).await
}

async fn blocking_hand<T, F>(work: F) -> Result<T, HandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, HandError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| unavailable("bounded file worker failed"))?
}

fn canonical_equal<T: serde::Serialize>(left: &T, right: &T) -> Result<bool, HandError> {
    let left =
        serde_jcs::to_vec(left).map_err(|_| invalid("sealed value is not canonicalizable"))?;
    let right =
        serde_jcs::to_vec(right).map_err(|_| invalid("sealed value is not canonicalizable"))?;
    Ok(left == right)
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn operation_error(error: OperationError) -> HandError {
    let code = match error {
        OperationError::IdempotencyConflict | OperationError::TerminalConflict => {
            HandErrorCode::OperationConflict
        }
        OperationError::Unknown => HandErrorCode::OperationUnknown,
        OperationError::Capacity | OperationError::TerminalCapacity => {
            HandErrorCode::ResourceExhausted
        }
        OperationError::InvalidIdentity(_)
        | OperationError::AlreadyTerminal
        | OperationError::NotTerminal
        | OperationError::TerminalDigestMismatch => HandErrorCode::InvalidRequest,
    };
    hand_error(code, false, error.to_string())
}

fn stdin_conflict() -> HandError {
    hand_error(
        HandErrorCode::OperationConflict,
        false,
        "stdin operation_id is already reserved for a different request digest",
    )
}

fn ack_store_error(error: AckStoreError) -> HandError {
    let (code, retryable) = match error {
        AckStoreError::Conflict => (HandErrorCode::OperationConflict, false),
        AckStoreError::Capacity => (HandErrorCode::ResourceExhausted, false),
        AckStoreError::Invalid(_) => (HandErrorCode::InvalidRequest, false),
        AckStoreError::Io(_) => (HandErrorCode::TemporarilyUnavailable, true),
        AckStoreError::Corrupt(_) => (HandErrorCode::TemporarilyUnavailable, false),
    };
    hand_error(code, retryable, error.to_string())
}

fn file_effect_store_error(error: FileEffectStoreError) -> HandError {
    let (code, retryable) = match error {
        FileEffectStoreError::Conflict => (HandErrorCode::BindingConflict, false),
        FileEffectStoreError::Ambiguous => (HandErrorCode::OperationUnknown, false),
        FileEffectStoreError::Capacity => (HandErrorCode::ResourceExhausted, false),
        FileEffectStoreError::Invalid(_) => (HandErrorCode::InvalidRequest, false),
        FileEffectStoreError::Io(_) => (HandErrorCode::TemporarilyUnavailable, true),
        FileEffectStoreError::Corrupt(_) => (HandErrorCode::CapabilityUnavailable, false),
    };
    hand_error(code, retryable, error.to_string())
}

fn file_effect_lock_index(operation_id: &str) -> usize {
    let digest = Sha256::digest(operation_id.as_bytes());
    let prefix = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
    prefix as usize % FILE_EFFECT_LOCK_SHARDS
}

fn file_effect_result_identity(
    result: &FileEffectStoredResult,
) -> Result<FileEffectIdentity, HandError> {
    let (kind, operation_id, request_digest) = match result {
        FileEffectStoredResult::Write(result) => (
            FileEffectKind::Write,
            result.operation_id.to_string(),
            result.request_digest.to_string(),
        ),
        FileEffectStoredResult::Copy(result) => {
            // Only export is completed as a separate trusted-adapter phase. Import is committed
            // atomically by `write_file` around the workspace mutation.
            (
                FileEffectKind::CopyExport,
                result.operation_id.to_string(),
                result.request_digest.to_string(),
            )
        }
    };
    Ok(FileEffectIdentity {
        kind,
        operation_id,
        request_digest,
    })
}

fn file_error(error: LiveFileError) -> HandError {
    let code = match error {
        LiveFileError::NotFound => HandErrorCode::FileNotFound,
        LiveFileError::TooLarge | LiveFileError::SearchBoundExceeded => {
            HandErrorCode::ResourceExhausted
        }
        LiveFileError::Io(_) => HandErrorCode::TemporarilyUnavailable,
        _ => HandErrorCode::InvalidRequest,
    };
    hand_error(
        code,
        matches!(error, LiveFileError::Io(_)),
        error.to_string(),
    )
}

fn file_entry(entry: &LiveFileEntry) -> Result<FileEntry, HandError> {
    Ok(FileEntry {
        bytes: entry.bytes,
        kind: match entry.kind {
            LiveFileKind::File => FileEntryKind::File,
            LiveFileKind::Directory => FileEntryKind::Directory,
            LiveFileKind::Symlink => FileEntryKind::Symlink,
        },
        modified_at_ms: entry.modified_at_ms,
        path: entry
            .path
            .parse()
            .map_err(|_| invalid("file path is invalid"))?,
        sha256: entry
            .sha256
            .as_deref()
            .map(str::parse::<Digest>)
            .transpose()
            .map_err(|_| invalid("file digest is invalid"))?,
    })
}

fn generation_conflict() -> HandError {
    hand_error(
        HandErrorCode::GenerationConflict,
        false,
        "request does not match the live physical generation",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use brain_protocol::contract::{sandbox_execution_request_digest, write_stdin_request_digest};
    #[cfg(unix)]
    use brain_protocol::hand::{ObserveRequest, SandboxExecutionRequest, WriteStdinRequest};
    use hand_wire::{AllowlistProxy, InstallBundleMetadata, RunPayload};

    fn run_payload(network: NetworkCeiling) -> RunPayload {
        RunPayload {
            contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
            generation: "generation-1".into(),
            expires_at_ms: wall_ms() + MAX_TARGET_LIFETIME_MS,
            root_id: "root-1".into(),
            owner_session_id: "session-1".into(),
            connector: match network {
                NetworkCeiling::None => ConnectorClass::None,
                NetworkCeiling::Public => ConnectorClass::Public,
                NetworkCeiling::Allowlist(_) => ConnectorClass::Allowlist,
            },
            resource_class: "microvm-1gb".into(),
            resources: serde_json::from_value(serde_json::json!({
                "max_output_bytes": 65536,
                "timeout_ms": 60000
            }))
            .unwrap(),
            allowlist_proxy: matches!(network, NetworkCeiling::Allowlist(_)).then(|| {
                AllowlistProxy {
                    authority: "10.0.0.10:8443".into(),
                    capability: "opaque-capability".into(),
                }
            }),
            canary_exit_after_operation_id: None,
            network,
        }
    }

    fn sandbox_identity() -> ToolIdentity {
        ToolIdentity {
            uid: 1_000,
            gid: 1_000,
            supervisor_uid: 1_001,
        }
    }

    fn default_file_target() -> SandboxTarget {
        serde_json::from_value(serde_json::json!({
            "binding_ref": "file-binding-1",
            "kind": "default",
            "root_id": "root-1",
            "session_id": "session-1"
        }))
        .unwrap()
    }

    fn file_effect_identity(operation_id: &str, digest: char) -> FileEffectIdentity {
        FileEffectIdentity {
            kind: FileEffectKind::Write,
            operation_id: operation_id.into(),
            request_digest: digest.to_string().repeat(64),
        }
    }

    #[test]
    fn managed_binding_uids_are_bounded_exact_and_never_alias() {
        let mut registry = BindingIdentityRegistry::with_bounds(65_536, 1_000_000, 2);
        let first = registry
            .allocate("binding-a", Some(sandbox_identity()))
            .unwrap()
            .unwrap();
        assert!((65_536..1_065_536).contains(&first.uid));
        assert_eq!(
            registry
                .allocate("binding-a", Some(sandbox_identity()))
                .unwrap(),
            Some(first),
        );

        // A one-element uid range makes a distinct hash collision deterministic. It is a
        // permanent binding conflict and never aliases the two secret subsets.
        let mut collision = BindingIdentityRegistry::with_bounds(65_536, 1, 2);
        collision
            .allocate("binding-a", Some(sandbox_identity()))
            .unwrap();
        let error = collision
            .allocate("binding-b", Some(sandbox_identity()))
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::BindingConflict);
        assert!(!error.retryable);

        let mut exhausted = BindingIdentityRegistry::with_bounds(65_536, 1_000_000, 1);
        exhausted
            .allocate("binding-a", Some(sandbox_identity()))
            .unwrap();
        let error = exhausted
            .allocate("binding-b", Some(sandbox_identity()))
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::ResourceExhausted);
        assert!(!error.retryable);
    }

    #[test]
    fn operation_receipts_are_stable_per_operation_and_distinct_from_target_identity() {
        let digest = "a".repeat(64);
        let first =
            operation_receipt_ref("operation-1", &digest, "target-1", "generation-1").unwrap();
        let replay =
            operation_receipt_ref("operation-1", &digest, "target-1", "generation-1").unwrap();
        let second =
            operation_receipt_ref("operation-2", &digest, "target-1", "generation-1").unwrap();

        assert_eq!(first, replay);
        assert_ne!(first, second);
        assert_ne!(first.as_str(), "target-1");
    }

    #[tokio::test]
    async fn file_write_lost_success_replays_and_conflict_never_mutates_workspace() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::for_test(directory.path());
        let workspace = config.workspace.clone();
        let hand = Hand::new(config).unwrap();
        hand.arm("target-1".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();

        let identity = file_effect_identity("file-operation-1", 'a');
        assert!(matches!(
            hand.reserve_file_effect(identity.clone()).await.unwrap(),
            FileEffectReservation::New
        ));
        let mut request = GuestFileWriteRequest {
            effect: identity.clone(),
            expected_generation: "generation-1".into(),
            overwrite: false,
            path: "/workspace/result.txt".into(),
            source: GuestFileWriteSource::Inline {
                content_base64: base64::engine::general_purpose::STANDARD.encode(b"first"),
            },
            target: default_file_target(),
        };
        let FileEffectStoredResult::Write(first) = hand.write_file(request.clone()).await.unwrap()
        else {
            panic!("file write returned a copy result");
        };
        assert!(!first.replayed);
        assert_eq!(
            std::fs::read(workspace.join("result.txt")).unwrap(),
            b"first"
        );

        // Model a successful mutation whose response was lost. Even a different private-wire
        // payload carrying the retained exact identity cannot enter the mutation body again.
        request.overwrite = true;
        request.source = GuestFileWriteSource::Inline {
            content_base64: base64::engine::general_purpose::STANDARD.encode(b"second"),
        };
        let FileEffectStoredResult::Write(replayed) = hand.write_file(request).await.unwrap()
        else {
            panic!("file write replay returned a copy result");
        };
        assert!(replayed.replayed);
        assert_eq!(
            std::fs::read(workspace.join("result.txt")).unwrap(),
            b"first"
        );

        let conflict = hand
            .reserve_file_effect(file_effect_identity("file-operation-1", 'b'))
            .await
            .unwrap_err();
        assert_eq!(conflict.code, HandErrorCode::BindingConflict);
        assert!(!conflict.retryable);
        assert_eq!(
            std::fs::read(workspace.join("result.txt")).unwrap(),
            b"first"
        );
    }

    #[tokio::test]
    async fn file_write_intent_only_restart_is_unknown_and_never_mutates_workspace() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::for_test(directory.path());
        let workspace = config.workspace.clone();
        let identity = file_effect_identity("file-operation-restart", 'a');
        {
            let hand = Hand::new(config.clone()).unwrap();
            hand.arm("target-1".into(), run_payload(NetworkCeiling::None))
                .await
                .unwrap();
            assert!(matches!(
                hand.reserve_file_effect(identity.clone()).await.unwrap(),
                FileEffectReservation::New
            ));
        }

        let restarted = Hand::new(config).unwrap();
        restarted
            .arm("target-1".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();
        let error = restarted.reserve_file_effect(identity).await.unwrap_err();
        assert_eq!(error.code, HandErrorCode::OperationUnknown);
        assert!(!error.retryable);
        assert!(!workspace.join("result.txt").exists());
    }

    #[test]
    fn exact_max_inline_terminal_fits_the_reserved_full_observation() {
        let inline = serde_json::Value::String(
            "x".repeat(brain_protocol::MAX_TOOL_TERMINAL_INLINE_BYTES - 2),
        );
        assert!(terminal_inline_fits(&inline));
        let mut terminal = TerminalResult {
            duration_ms: Some(u64::MAX),
            exit_code: Some(i64::MIN),
            inline: Some(inline),
            is_error: false,
            object: None,
            outcome: TerminalOutcome::Completed,
            terminal_digest: "0".repeat(64).parse().unwrap(),
        };
        terminal.terminal_digest = terminal_result_digest(&terminal);
        let observation: OperationObservation = serde_json::from_value(serde_json::json!({
            "next_cursor": "c".repeat(256),
            "operation": {
                "generation": "g".repeat(128),
                "operation_id": "o".repeat(128),
                "receipt_ref": "r".repeat(128),
                "request_digest": "a".repeat(64),
                "target": {
                    "binding_ref": "b".repeat(128),
                    "kind": "default",
                    "root_id": "t".repeat(128),
                    "session_id": "s".repeat(128)
                },
                "target_ref": "p".repeat(128)
            },
            "output": [],
            "state": "terminal",
            "target": {
                "expires_at_ms": u64::MAX,
                "generation": "g".repeat(128),
                "target_ref": "p".repeat(128)
            },
            "terminal": terminal
        }))
        .unwrap();
        let bytes = serde_json::to_vec(&observation).unwrap();
        assert!(
            bytes.len() <= TERMINAL_ENVELOPE_BYTES,
            "max canonical inline plus maximum receipt fields encoded to {} bytes, above the {}-byte reservation",
            bytes.len(),
            TERMINAL_ENVELOPE_BYTES
        );
    }

    async fn prepared_hand() -> (tempfile::TempDir, Arc<Hand>, String) {
        let directory = tempfile::tempdir().unwrap();
        let hand = Hand::new(Config::for_test(directory.path())).unwrap();
        hand.arm("mvm-1".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();
        let bytes = br#"export default {kind:'brain.tool-runtime',name:'fixture',contractDigest:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',input:null,requiredEnv:['FIXTURE_SECRET'],execute: async () => ({ok:true})};"#;
        let digest = hex::encode(Sha256::digest(bytes));
        let descriptor: BundleDescriptor = serde_json::from_value(serde_json::json!({
            "bundle_digest": digest,
            "bytes": bytes.len(),
            "contract_digest": "a".repeat(64),
            "object": {
                "bytes": bytes.len(),
                "object_id": "object-1",
                "sha256": digest
            },
            "required_env": ["FIXTURE_SECRET"],
            "runtime": "node22",
            "tool_name": "fixture"
        }))
        .unwrap();
        hand.install_bundle(
            InstallBundleMetadata {
                descriptor: descriptor.clone(),
            },
            bytes,
        )
        .await
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let installed =
                std::fs::metadata(hand.cfg.tool_dir.join(format!("{digest}.mjs"))).unwrap();
            assert_eq!(installed.permissions().mode() & 0o777, 0o640);
        }
        let binding: SealedBinding = serde_json::from_value(serde_json::json!({
            "binding_id": "binding-1",
            "bundle": descriptor,
            "capability": "fixture",
            "contract_digest": "a".repeat(64),
            "implementation_identity": "b".repeat(64),
            "policy_digest": "c".repeat(64),
            "realm": "aex_managed",
            "realm_id": "aex",
            "required_capabilities": ["execution"],
            "root_id": "root-1",
            "session_id": "session-1"
        }))
        .unwrap();
        hand.install_binding(InstallBindingRequest {
            binding_ref: "binding-ref-1".into(),
            binding,
        })
        .await
        .unwrap();
        (directory, hand, digest)
    }

    #[tokio::test]
    async fn root_network_and_resource_seals_cannot_be_widened() {
        let directory = tempfile::tempdir().unwrap();
        let hand = Hand::new(Config::for_test(directory.path())).unwrap();
        hand.arm("mvm-1".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();
        let error = hand
            .arm("mvm-1".into(), run_payload(NetworkCeiling::Public))
            .await
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::GenerationConflict);
        let status = hand.runtime_status().await.unwrap();
        assert_eq!(status.connector, ConnectorClass::None);
    }

    #[tokio::test]
    async fn secrets_are_declared_exact_replay_only_and_absent_from_receipts() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let secret = "never-print-this-value";
        let request = || InstallSecretsRequest {
            session_id: "session-1".into(),
            generation: "generation-1".into(),
            env_names: vec!["FIXTURE_SECRET".into(), "FUTURE_SECRET".into()],
            values: HashMap::from([
                ("FIXTURE_SECRET".into(), secret.into()),
                ("FUTURE_SECRET".into(), "future-value".into()),
            ]),
        };
        let first = hand.install_secrets(request()).await.unwrap();
        assert!(!first.replayed);
        assert!(hand.install_secrets(request()).await.unwrap().replayed);
        let conflict = hand
            .install_secrets(InstallSecretsRequest {
                session_id: "session-1".into(),
                generation: "generation-1".into(),
                env_names: vec!["FIXTURE_SECRET".into(), "FUTURE_SECRET".into()],
                values: HashMap::from([
                    ("FIXTURE_SECRET".into(), "different".into()),
                    ("FUTURE_SECRET".into(), "future-value".into()),
                ]),
            })
            .await
            .unwrap_err();
        assert_eq!(conflict.code, HandErrorCode::GenerationConflict);
        let status = serde_json::to_string(&hand.runtime_status().await).unwrap();
        let receipt = serde_json::to_string(&first).unwrap();
        assert!(!status.contains(secret));
        assert!(!receipt.contains(secret));
    }

    #[tokio::test]
    async fn guest_repeats_the_exact_brain_secret_document_boundary() {
        let exact_directory = tempfile::tempdir().unwrap();
        let exact_hand = Hand::new(Config::for_test(exact_directory.path())).unwrap();
        exact_hand
            .arm("mvm-exact".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();
        let exact_value = format!("{}aaaaaaaa", "é".repeat(2040));
        let exact = InstallSecretsRequest {
            session_id: "session-exact".into(),
            generation: "generation-1".into(),
            env_names: vec!["A".into()],
            values: HashMap::from([("A".into(), exact_value)]),
        };
        assert_eq!(
            serde_jcs::to_vec(&exact.values).unwrap().len(),
            brain_protocol::MAX_SESSION_SECRET_DOCUMENT_BYTES
        );
        exact_hand.install_secrets(exact).await.unwrap();

        let oversized_directory = tempfile::tempdir().unwrap();
        let oversized_hand = Hand::new(Config::for_test(oversized_directory.path())).unwrap();
        oversized_hand
            .arm("mvm-oversized".into(), run_payload(NetworkCeiling::None))
            .await
            .unwrap();
        let oversized_value = format!("{}aaaaaaaa€", "é".repeat(2039));
        let oversized = InstallSecretsRequest {
            session_id: "session-oversized".into(),
            generation: "generation-1".into(),
            env_names: vec!["A".into()],
            values: HashMap::from([("A".into(), oversized_value)]),
        };
        assert_eq!(
            serde_jcs::to_vec(&oversized.values).unwrap().len(),
            brain_protocol::MAX_SESSION_SECRET_DOCUMENT_BYTES + 1
        );
        assert_eq!(
            oversized_hand
                .install_secrets(oversized)
                .await
                .unwrap_err()
                .code,
            HandErrorCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn undeclared_secret_names_are_refused_without_installing_values() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let error = hand
            .install_secrets(InstallSecretsRequest {
                session_id: "session-1".into(),
                generation: "generation-1".into(),
                env_names: vec!["FIXTURE_SECRET".into()],
                values: HashMap::from([("NOT_DECLARED".into(), "secret".into())]),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, HandErrorCode::InvalidRequest);
        assert!(hand.secrets.read().await.is_empty());
    }

    #[test]
    fn customer_environment_cannot_replace_runtime_or_connector_authority() {
        for name in [
            "LD_PRELOAD",
            "node_options",
            "HTTPS_PROXY",
            "AEX_WORKSPACE",
            "HAND_TOOL_RUNNER",
            "OPENSSL_MODULES",
        ] {
            assert!(reserved_tool_environment(name), "{name}");
        }
        for name in ["OPENAI_API_KEY", "PROC_SECRET", "DATABASE_URL"] {
            assert!(!reserved_tool_environment(name), "{name}");
        }
    }

    #[cfg(unix)]
    fn sandbox_request(
        execution_id: &str,
        command: &str,
        interactive: bool,
    ) -> SandboxExecutionRequest {
        let mut request: SandboxExecutionRequest = serde_json::from_value(serde_json::json!({
            "execution_id": execution_id,
            "expected_generation": "generation-1",
            "input": {
                "command": command,
                "cwd": "/workspace",
                "interactive": interactive
            },
            "network": {"kind": "none"},
            "request_digest": "0".repeat(64),
            "resources": {
                "max_output_bytes": 65536,
                "timeout_ms": 5000
            },
            "target": {
                "binding_ref": "sandbox-binding-1",
                "kind": "default",
                "root_id": "root-1",
                "session_id": "session-1"
            }
        }))
        .unwrap();
        request.request_digest = sandbox_execution_request_digest(&request);
        request
    }

    #[cfg(unix)]
    async fn wait_terminal(hand: &Hand, operation: OperationRef) -> OperationObservation {
        hand.observe(ObserveRequest {
            cursor: "0".parse().unwrap(),
            operation,
            wait_ms: 5_000,
        })
        .await
        .unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sandbox_exact_replay_and_conflicting_digest_never_repeat_the_effect() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let first = sandbox_request(
            "sandbox-execution-1",
            "printf first >> /workspace/effect.txt",
            false,
        );
        let receipt = hand.execute_sandbox(first.clone()).await.unwrap();
        assert_eq!(
            wait_terminal(&hand, receipt.operation.clone()).await.state,
            ContractOperationState::Terminal
        );

        let replay = hand.execute_sandbox(first).await.unwrap();
        assert!(replay.replayed);
        let conflict = hand
            .execute_sandbox(sandbox_request(
                "sandbox-execution-1",
                "printf second >> /workspace/effect.txt",
                false,
            ))
            .await
            .unwrap_err();
        assert_eq!(conflict.code, HandErrorCode::OperationConflict);
        assert_eq!(
            std::fs::read_to_string(hand.cfg.workspace.join("effect.txt")).unwrap(),
            "first"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_ack_replays_and_permanently_fences_resubmission() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let request = sandbox_request(
            "sandbox-execution-acked",
            "printf once >> /workspace/acked-effect.txt",
            false,
        );
        let receipt = hand.execute_sandbox(request.clone()).await.unwrap();
        let terminal = wait_terminal(&hand, receipt.operation.clone())
            .await
            .terminal
            .expect("terminal result");
        let acknowledgement = AcknowledgeTerminalRequest {
            operation: receipt.operation.clone(),
            terminal_digest: terminal.terminal_digest,
        };
        assert!(
            hand.acknowledge_terminal(acknowledgement.clone())
                .await
                .unwrap()
                .acknowledged
        );
        assert!(
            hand.acknowledge_terminal(acknowledgement)
                .await
                .unwrap()
                .acknowledged
        );

        let exact = hand.execute_sandbox(request).await.unwrap_err();
        assert_eq!(exact.code, HandErrorCode::OperationUnknown);
        let conflicting = hand
            .execute_sandbox(sandbox_request(
                "sandbox-execution-acked",
                "printf twice >> /workspace/acked-effect.txt",
                false,
            ))
            .await
            .unwrap_err();
        assert_eq!(conflicting.code, HandErrorCode::OperationConflict);
        assert_eq!(
            std::fs::read_to_string(hand.cfg.workspace.join("acked-effect.txt")).unwrap(),
            "once"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_stdin_is_exact_pair_idempotent() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let execution = sandbox_request(
            "sandbox-execution-stdin",
            "IFS= read -r line; printf '%s' \"$line\" > /workspace/stdin.txt",
            true,
        );
        let receipt = hand.execute_sandbox(execution.clone()).await.unwrap();
        let mut write: WriteStdinRequest = serde_json::from_value(serde_json::json!({
            "execution_id": execution.execution_id.clone(),
            "expected_generation": "generation-1",
            "eof": false,
            "operation_id": "stdin-write-1",
            "request_digest": "0".repeat(64),
            "target": execution.target.clone(),
            "text": "hello\n"
        }))
        .unwrap();
        write.request_digest = write_stdin_request_digest(&write);
        // JSON Schema counts Unicode scalar values, while Linux PIPE_BUF is bytes. The runtime
        // closes that gap before reserving the idempotency key or touching the pipe.
        let mut oversized = write.clone();
        oversized.operation_id = "stdin-write-oversized".parse().unwrap();
        oversized.text = "é"
            .repeat(brain_protocol::MAX_WRITE_STDIN_BYTES)
            .parse()
            .unwrap();
        oversized.request_digest = write_stdin_request_digest(&oversized);
        let error = hand.write_stdin(oversized).await.unwrap_err();
        assert_eq!(error.code, HandErrorCode::InvalidRequest);

        let first = hand.write_stdin(write.clone()).await.unwrap();
        assert!(first.accepted);
        assert!(!first.replayed);
        assert!(canonical_equal(&first.observation.operation, &receipt.operation).unwrap());
        let replay = hand.write_stdin(write.clone()).await.unwrap();
        assert!(replay.accepted);
        assert!(replay.replayed);
        assert!(canonical_equal(&replay.observation.operation, &receipt.operation).unwrap());
        let mut conflict = write;
        conflict.text = "different\n".parse().unwrap();
        conflict.request_digest = write_stdin_request_digest(&conflict);
        let error = hand.write_stdin(conflict).await.unwrap_err();
        assert_eq!(error.code, HandErrorCode::OperationConflict);
        assert_eq!(
            wait_terminal(&hand, receipt.operation).await.state,
            ContractOperationState::Terminal
        );
        assert_eq!(
            std::fs::read_to_string(hand.cfg.workspace.join("stdin.txt")).unwrap(),
            "hello"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_stdin_supports_explicit_eof_and_observation_only_poll() {
        let (_directory, hand, _digest) = prepared_hand().await;
        let execution = sandbox_request(
            "sandbox-execution-eof",
            "cat > /workspace/stdin-eof.txt",
            true,
        );
        let submitted = hand.execute_sandbox(execution.clone()).await.unwrap();
        let mut close: WriteStdinRequest = serde_json::from_value(serde_json::json!({
            "eof": true,
            "execution_id": execution.execution_id.clone(),
            "expected_generation": "generation-1",
            "operation_id": "stdin-close-1",
            "request_digest": "0".repeat(64),
            "target": execution.target.clone(),
            "text": "without-newline"
        }))
        .unwrap();
        close.request_digest = write_stdin_request_digest(&close);
        let first = hand.write_stdin(close.clone()).await.unwrap();
        assert!(first.accepted);
        assert!(!first.replayed);
        assert!(canonical_equal(&first.observation.operation, &submitted.operation).unwrap());

        let terminal = wait_terminal(&hand, submitted.operation.clone()).await;
        assert_eq!(terminal.state, ContractOperationState::Terminal);
        assert_eq!(
            std::fs::read_to_string(hand.cfg.workspace.join("stdin-eof.txt")).unwrap(),
            "without-newline"
        );

        let replay = hand.write_stdin(close).await.unwrap();
        assert!(replay.accepted);
        assert!(replay.replayed);
        assert_eq!(replay.observation.state, ContractOperationState::Terminal);

        let mut poll: WriteStdinRequest = serde_json::from_value(serde_json::json!({
            "eof": false,
            "execution_id": execution.execution_id,
            "expected_generation": "generation-1",
            "operation_id": "stdin-poll-1",
            "request_digest": "0".repeat(64),
            "target": execution.target,
            "text": ""
        }))
        .unwrap();
        poll.request_digest = write_stdin_request_digest(&poll);
        let polled = hand.write_stdin(poll).await.unwrap();
        assert!(!polled.accepted);
        assert_eq!(polled.observation.state, ContractOperationState::Terminal);
        assert_eq!(hand.stdin_writes.lock().await.records.len(), 2);
        hand.acknowledge_terminal(AcknowledgeTerminalRequest {
            operation: submitted.operation,
            terminal_digest: terminal.terminal.unwrap().terminal_digest,
        })
        .await
        .unwrap();
        assert!(hand.stdin_writes.lock().await.records.is_empty());
    }
}
