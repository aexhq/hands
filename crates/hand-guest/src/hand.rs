//! The hand: session state, lanes, operations, and one handler per ABI operation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use brain_protocol::abi::{
    AbiError, BootId, CancelRequest, CancelResponse, Clock, EffectiveBounds, ErrorCode,
    GenerationId, HandStatusEvent, HelloRequest, HelloResponse, LaneCloseRequest,
    LaneCloseResponse, LaneMode, MonotonicMs, Outcome, PersistRequest, PersistResponse,
    PersistResponsePersistedItem, PersistSource, PollRequest, PollResponse, ProtocolVersion,
    PutRequest, PutResponse, PutResponseWrittenItem, PutSource, ReleaseRequest, ReleaseResponse,
    Reply, Request, RequestCall, ResponseResult, SessionId, Sha256Hex, StartRequest, StartResponse,
    Stream, SyncRequest, SyncResponse, ToolExecutableSource, ToolManifest, WallMs,
};
use brain_protocol::tools::manifest_digest;
use serde_json::{Map, Value};
use tokio::sync::Mutex as AsyncMutex;

use crate::config::Config;
use crate::errors::{AbiResult, err, err_retryable, err_with, internal, malformed};
use crate::exec::{BashSpec, NodeSpec, run_bash, run_node};
use crate::lanes::Lanes;
use crate::ops::{Operation, Registry};
use crate::spill::Spill;
use crate::status::{StatusEmitter, read_pressure};
use crate::sync::{SyncScope, SyncState};
use crate::tools;
use crate::transfer::{self, Scope};

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since this hand process started (the guest's monotonic clock as the ABI sees it).
pub fn monotonic_ms() -> u64 {
    PROCESS_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as u64
}

pub fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_id(prefix: &str) -> String {
    use rand::Rng;
    let n: u128 = rand::rng().random();
    format!("{prefix}-{n:032x}")
}

/// Sealed at the first `hello` of this generation.
pub struct Session {
    pub session_id: SessionId,
    pub scope: Scope,
    pub sync_scope: SyncScope,
    pub heartbeat_ms: u64,
    pub manifest: ToolManifest,
    pub manifest_digest: Sha256Hex,
    validators: HashMap<String, (jsonschema::Validator, jsonschema::Validator)>,
    executables: HashMap<String, SessionExecutable>,
}

#[derive(Debug, Clone)]
enum SessionExecutable {
    Preinstalled(tools::Preinstalled),
    Bundle(PathBuf),
}

struct BundleInvocation {
    op: Arc<Operation>,
    tool: String,
    bundle: PathBuf,
    input: Value,
    env: HashMap<String, String>,
    cwd: PathBuf,
    session: Arc<Session>,
}

pub struct Hand {
    pub cfg: Config,
    pub generation_id: GenerationId,
    pub boot_id: BootId,
    fence: AtomicU64,
    session: RwLock<Option<Arc<Session>>>,
    lanes: Mutex<Option<Lanes>>,
    ops: Mutex<Registry>,
    sync: AsyncMutex<SyncState>,
    pub status: StatusEmitter,
    http: reqwest::Client,
    idle_since: Mutex<Instant>,
    heartbeat: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The armed per-session secret. `None` until the environment or the `/run` lifecycle hook
    /// supplies it; an unarmed hand refuses every `hello`.
    token: RwLock<Option<String>>,
    /// Where the hand is in the provider lifecycle. Informational (probe + status); admission
    /// is gated by the armed token, not by this.
    pub lifecycle: RwLock<LifecyclePhase>,
}

/// The provider-lifecycle phase, as the hooks report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    /// Booted; `/run` has not completed (only reachable when the token comes from `/run`).
    AwaitingRun,
    /// `/run` or `/resume` completed; serving.
    Serving,
    /// `/suspend` completed; the platform is snapshotting (or resumed us without re-posting).
    Suspended,
    /// `/terminate` received; the VM is going away.
    Terminating,
}

impl Hand {
    pub fn new(cfg: Config) -> anyhow::Result<Arc<Self>> {
        PROCESS_START.get_or_init(Instant::now);
        std::fs::create_dir_all(&cfg.spill_dir)?;
        std::fs::create_dir_all(cfg.spill_dir.join("sync"))?;
        std::fs::create_dir_all(&cfg.workspace)?;
        std::fs::create_dir_all(&cfg.tool_dir)?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        let hand = Arc::new(Self {
            cfg,
            generation_id: random_id("gen").parse().expect("id"),
            boot_id: random_id("boot").parse().expect("id"),
            fence: AtomicU64::new(0),
            session: RwLock::new(None),
            lanes: Mutex::new(None),
            ops: Mutex::new(Registry::default()),
            sync: AsyncMutex::new(SyncState::default()),
            status: StatusEmitter::new(),
            http,
            idle_since: Mutex::new(Instant::now()),
            heartbeat: Mutex::new(None),
            token: RwLock::new(None),
            lifecycle: RwLock::new(LifecyclePhase::AwaitingRun),
        });
        if let Some(token) = hand.cfg.token.clone() {
            // Environment-armed (plain container): serving from boot, no run hook required.
            *hand.token.write().unwrap() = Some(token);
            *hand.lifecycle.write().unwrap() = LifecyclePhase::Serving;
        }
        Ok(hand)
    }

    /// Arms the hand with the per-session secret (from the `/run` hook). Idempotent for the
    /// same token; refuses a different one — a hand serves exactly one session in its life.
    pub fn arm(&self, token: &str) -> Result<(), &'static str> {
        if token.is_empty() {
            return Err("empty token");
        }
        let mut cur = self.token.write().unwrap();
        match cur.as_deref() {
            None => {
                *cur = Some(token.to_owned());
                Ok(())
            }
            Some(t) if t == token => Ok(()),
            Some(_) => Err("hand is already armed with a different token"),
        }
    }

    pub fn armed(&self) -> bool {
        self.token.read().unwrap().is_some()
    }

    /// Forces every retained stream byte to durable storage (the `/suspend` hook).
    pub async fn flush_spills(&self) {
        let ops = self.ops.lock().unwrap().all();
        for op in ops {
            op.stdout.lock().await.flush();
            op.stderr.lock().await.flush();
        }
    }

    fn session(&self) -> AbiResult<Arc<Session>> {
        self.session
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| err(ErrorCode::Unauthorized, "hello first"))
    }

    /// Envelope checks (fence, generation, session), then dispatch. Never panics across the
    /// boundary: an internal failure becomes an `internal` error for that request only.
    pub async fn handle(self: &Arc<Self>, req: Request) -> ResponseResult {
        match self.handle_inner(req).await {
            Ok(reply) => ResponseResult::Ok { reply },
            Err(error) => ResponseResult::Error { error },
        }
    }

    async fn handle_inner(self: &Arc<Self>, req: Request) -> AbiResult<Reply> {
        // Fence: a stale owner is refused with no side effect; equal or higher is accepted.
        let cur = self.fence.load(Ordering::SeqCst);
        if req.fence < cur {
            return Err(err(
                ErrorCode::FenceStale,
                format!("fence {} < accepted {cur}", req.fence),
            ));
        }
        self.fence.fetch_max(req.fence, Ordering::SeqCst);
        if !matches!(req.call, RequestCall::Hello(_)) {
            match &req.generation_id {
                None => {
                    return Err(malformed(
                        "generation_id is required on every request except hello",
                    ));
                }
                Some(g) if *g != self.generation_id => {
                    return Err(err(
                        ErrorCode::GenerationMismatch,
                        format!("hand generation is {}", *self.generation_id),
                    ));
                }
                _ => {}
            }
        }
        match req.call {
            RequestCall::Hello(a) => self.hello(a).await.map(Reply::Hello),
            RequestCall::Start(a) => self.start(a).await.map(Reply::Start),
            RequestCall::Poll(a) => self.poll(a).await.map(Reply::Poll),
            RequestCall::Cancel(a) => self.cancel(a).await.map(Reply::Cancel),
            RequestCall::Release(a) => self.release(a).await.map(Reply::Release),
            RequestCall::LaneClose(a) => self.lane_close(a).await.map(Reply::LaneClose),
            RequestCall::Put(a) => self.put(a).await.map(Reply::Put),
            RequestCall::Persist(a) => self.persist(a).await.map(Reply::Persist),
            RequestCall::Sync(a) => self.sync(a).await.map(Reply::Sync),
        }
    }

    // ----- hello -------------------------------------------------------------------------

    async fn prepare_manifest(
        &self,
        requested: &ToolManifest,
        expected_digest: &Sha256Hex,
    ) -> AbiResult<(
        ToolManifest,
        HashMap<String, (jsonschema::Validator, jsonschema::Validator)>,
        HashMap<String, SessionExecutable>,
    )> {
        let actual_digest = manifest_digest(requested);
        if &actual_digest != expected_digest {
            return Err(err_with(
                ErrorCode::ToolManifestMismatch,
                "tool manifest does not match its sealed digest",
                [(
                    "computed_digest".into(),
                    Value::String(actual_digest.to_string()),
                )]
                .into_iter()
                .collect(),
            ));
        }

        let mut manifest = requested.clone();
        let mut validators = HashMap::new();
        let mut executables = HashMap::new();
        for tool in &mut manifest.tools {
            let name = tool.name.to_string();
            if validators.contains_key(&name) {
                return Err(err(
                    ErrorCode::ToolManifestMismatch,
                    format!("duplicate tool name {name}"),
                ));
            }
            if tool.executable.protocol != 1 {
                return Err(err(
                    ErrorCode::ToolBundleInvalid,
                    format!("tool {name} uses unsupported executable protocol"),
                ));
            }
            let input = jsonschema::draft202012::new(&Value::Object(tool.input_schema.clone()))
                .map_err(|error| {
                    err(
                        ErrorCode::ToolManifestMismatch,
                        format!("tool {name} input schema: {error}"),
                    )
                })?;
            let output = jsonschema::draft202012::new(&Value::Object(tool.output_schema.clone()))
                .map_err(|error| {
                err(
                    ErrorCode::ToolManifestMismatch,
                    format!("tool {name} output schema: {error}"),
                )
            })?;
            validators.insert(name.clone(), (input, output));

            let executable = match tool.executable.source {
                ToolExecutableSource::Preinstalled => {
                    if tool.executable.get_url.is_some() || tool.executable.bytes.is_some() {
                        return Err(err(
                            ErrorCode::ToolBundleInvalid,
                            format!("preinstalled tool {name} carries bundle transport fields"),
                        ));
                    }
                    let implementation = tools::preinstalled(&tool.executable.checksum)
                        .ok_or_else(|| {
                            err(
                                ErrorCode::ToolBundleInvalid,
                                format!(
                                    "preinstalled checksum {} is unavailable in this Hand image",
                                    *tool.executable.checksum
                                ),
                            )
                        })?;
                    SessionExecutable::Preinstalled(implementation)
                }
                ToolExecutableSource::Bundle => {
                    let bytes =
                        tool.executable
                            .bytes
                            .map(|value| value.get())
                            .ok_or_else(|| {
                                err(
                                    ErrorCode::ToolBundleInvalid,
                                    format!("bundle tool {name} is missing bytes"),
                                )
                            })?;
                    if bytes > 4 * 1024 * 1024 {
                        return Err(err(
                            ErrorCode::ToolBundleInvalid,
                            format!("bundle tool {name} exceeds 4 MiB"),
                        ));
                    }
                    let get_url = tool.executable.get_url.as_deref().ok_or_else(|| {
                        err(
                            ErrorCode::ToolBundleInvalid,
                            format!("bundle tool {name} is missing get_url"),
                        )
                    })?;
                    let path = self
                        .cfg
                        .tool_dir
                        .join(format!("{}.mjs", *tool.executable.checksum));
                    let already_valid = transfer::sha256_file(&path)
                        .map(|(existing_bytes, checksum)| {
                            existing_bytes == bytes && checksum == tool.executable.checksum
                        })
                        .unwrap_or(false);
                    if !already_valid {
                        transfer::download_to(
                            &self.http,
                            get_url,
                            &path,
                            Some(bytes),
                            Some(&tool.executable.checksum),
                        )
                        .await?;
                    }
                    SessionExecutable::Bundle(path)
                }
            };
            // A presigned URL is bearer material. Keep only the sealed identity after staging.
            tool.executable.get_url = None;
            executables.insert(name, executable);
        }
        Ok((manifest, validators, executables))
    }

    async fn hello(self: &Arc<Self>, a: HelloRequest) -> AbiResult<HelloResponse> {
        if a.protocol.major != ProtocolVersion::CURRENT.major {
            return Err(err(
                ErrorCode::ProtocolUnsupported,
                format!(
                    "hand speaks major {}, brain sent {}",
                    ProtocolVersion::CURRENT.major,
                    a.protocol.major
                ),
            ));
        }
        match self.token.read().unwrap().as_deref() {
            None => {
                return Err(err(
                    ErrorCode::Unauthorized,
                    "hand is not armed: the run hook has not delivered a session token",
                ));
            }
            Some(t) if *t != *a.session_token => {
                return Err(err(ErrorCode::Unauthorized, "session_token mismatch"));
            }
            Some(_) => {}
        }
        let existing = self.session.read().unwrap().clone();
        let session = match existing {
            Some(s) => {
                if s.session_id != a.session_id {
                    return Err(err(
                        ErrorCode::Unauthorized,
                        "this hand belongs to another session",
                    ));
                }
                if s.manifest_digest != a.tool_manifest_digest {
                    return Err(err(
                        ErrorCode::ToolManifestMismatch,
                        "this Hand generation is already sealed to another tool manifest",
                    ));
                }
                s
            }
            None => {
                let (manifest, validators, executables) = self
                    .prepare_manifest(&a.tool_manifest, &a.tool_manifest_digest)
                    .await?;
                let scope = Scope::new(&a.sync.roots)?;
                let sync_scope = SyncScope::new(scope.roots.clone(), &a.sync.exclude)?;
                let mut env = self.cfg.base_env.clone();
                env.extend(a.env.iter().map(|(k, v)| (k.clone(), v.clone())));
                let s = Arc::new(Session {
                    session_id: a.session_id.clone(),
                    scope,
                    sync_scope,
                    heartbeat_ms: a.heartbeat_ms.max(1000) as u64,
                    manifest,
                    manifest_digest: a.tool_manifest_digest.clone(),
                    validators,
                    executables,
                });
                *self.lanes.lock().unwrap() = Some(Lanes::new(
                    env,
                    self.cfg.limits.max_lanes.get() as usize,
                    monotonic_ms(),
                ));
                *self.session.write().unwrap() = Some(s.clone());
                self.start_heartbeat(s.heartbeat_ms);
                s
            }
        };
        // Restore on a fresh generation that has never seen a manifest.
        let mut restore_report = None;
        if let Some(src) = &a.restore {
            let mut st = self.sync.lock().await;
            if st.last.is_none() {
                let tmp = self.cfg.spill_dir.join("sync");
                restore_report = Some(crate::sync::restore(&self.http, &mut st, src, &tmp).await?);
            } else if st.last.as_ref().map(|m| &m.manifest_id) != Some(&src.manifest_id) {
                tracing::warn!(
                    "hello carries restore {} but this generation already holds a manifest; ignoring",
                    &*src.manifest_id
                );
            }
        }
        let _ = session;
        let lanes = self
            .lanes
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| l.summaries())
            .unwrap_or_default();
        let ops: Vec<Arc<Operation>> = self.ops.lock().unwrap().all();
        let mut operations = Vec::with_capacity(ops.len());
        for op in ops {
            operations.push(op.view().await);
        }
        Ok(HelloResponse {
            protocol: ProtocolVersion::CURRENT,
            generation_id: self.generation_id.clone(),
            boot_id: self.boot_id.clone(),
            tool_manifest_digest: session.manifest_digest.clone(),
            tools: session.manifest.tools.clone(),
            lanes,
            operations,
            limits: self.cfg.limits.clone(),
            paths: brain_protocol::abi::Paths {
                workspace: self.cfg.workspace.to_string_lossy().into_owned(),
                home: self.cfg.home.to_string_lossy().into_owned(),
                spill_dir: self.cfg.spill_dir.to_string_lossy().into_owned(),
            },
            clock: Clock {
                monotonic_ms: MonotonicMs(monotonic_ms()),
                wall_ms: WallMs(wall_ms()),
            },
            restore: restore_report,
        })
    }

    fn start_heartbeat(self: &Arc<Self>, heartbeat_ms: u64) {
        let mut slot = self.heartbeat.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let hand = Arc::downgrade(self);
        *slot = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(heartbeat_ms));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match hand.upgrade() {
                    Some(h) => h.emit_status(),
                    None => return,
                }
            }
        }));
    }

    // ----- start / poll / cancel / release ---------------------------------------------------

    fn effective_bounds(&self, b: Option<&brain_protocol::abi::Bounds>) -> EffectiveBounds {
        let d = &self.cfg.limits.default_bounds;
        EffectiveBounds {
            timeout_ms: b.and_then(|b| b.timeout_ms).or(d.timeout_ms),
            grace_ms: b.and_then(|b| b.grace_ms).unwrap_or(d.grace_ms),
            max_retained_bytes: b
                .and_then(|b| b.max_retained_bytes)
                .unwrap_or(d.max_retained_bytes),
        }
    }

    async fn start(self: &Arc<Self>, a: StartRequest) -> AbiResult<StartResponse> {
        let session = self.session()?;
        let Some((input_v, _)) = session.validators.get(&a.tool) else {
            return Err(err(
                ErrorCode::ToolNotFound,
                format!("{} is not in the sealed manifest", a.tool),
            ));
        };
        let executable = session
            .executables
            .get(&a.tool)
            .cloned()
            .ok_or_else(|| err(ErrorCode::ToolNotFound, "tool executable is unavailable"))?;
        if let Some(e) = input_v.iter_errors(&a.input).next() {
            let mut details = Map::new();
            details.insert(
                "schema_path".into(),
                Value::String(e.schema_path().to_string()),
            );
            details.insert(
                "instance_path".into(),
                Value::String(e.instance_path().to_string()),
            );
            return Err(err_with(
                ErrorCode::ToolInputInvalid,
                format!("input{}: {e}", e.instance_path()),
                details,
            ));
        }
        let expected = brain_protocol::tools::call_hash(&a);
        if expected != a.call_hash {
            return Err(malformed(format!(
                "call_hash {} does not match the request identity (expected {})",
                *a.call_hash, *expected
            )));
        }
        // Idempotency: an existing operation with the same identity is replayed, never re-run.
        let existing = self.ops.lock().unwrap().get(&a.operation_id);
        if let Some(existing) = existing {
            if existing.call_hash != a.call_hash {
                return Err(err(
                    ErrorCode::OperationIdempotencyConflict,
                    format!(
                        "operation {} exists with a different call_hash",
                        *a.operation_id
                    ),
                ));
            }
            let view = existing.view().await;
            let slices = self.first_slices(&existing, a.max_bytes).await?;
            return Ok(StartResponse {
                view,
                slices,
                replayed: true,
            });
        }
        let cwd = match &a.cwd {
            Some(c) => {
                let p = Path::new(c);
                if !p.is_absolute() {
                    return Err(malformed(format!("cwd {c} must be absolute")));
                }
                p.to_path_buf()
            }
            None => self.cfg.workspace.clone(),
        };
        let bounds = self.effective_bounds(a.bounds.as_ref());
        let now = monotonic_ms();

        // Lane + registration happen under the locks, before anything runs.
        let (env, lane_mode) = {
            let mut ops = self.ops.lock().unwrap();
            let running = ops.running().count() as u64;
            if running >= self.cfg.limits.max_concurrent_operations.get() {
                return Err(err_retryable(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "max_concurrent_operations = {}",
                        self.cfg.limits.max_concurrent_operations
                    ),
                ));
            }
            let mut lanes_guard = self.lanes.lock().unwrap();
            let lanes = lanes_guard
                .as_mut()
                .ok_or_else(|| err(ErrorCode::Unauthorized, "hello first"))?;
            let lane = lanes.resolve_for_start(&a.lane, now)?;
            if !a.detach {
                if let Some(inflight) = &lane.inflight {
                    return Err(err(
                        ErrorCode::LaneBusy,
                        format!("lane {} is held by operation {}", *lane.id, **inflight),
                    ));
                }
                lane.inflight = Some(a.operation_id.clone());
            }
            let env = lane.env.clone();
            let mode = lane.mode;
            let op = Arc::new(Operation {
                id: a.operation_id.clone(),
                tool: a.tool.clone(),
                lane_id: a.lane.id.clone(),
                lane_mode: mode,
                detach: a.detach,
                call_hash: a.call_hash.clone(),
                correlation: a.correlation.clone(),
                bounds: bounds.clone(),
                started_at: Instant::now(),
                started_at_monotonic_ms: now,
                stdout: AsyncMutex::new(Spill::new(
                    &self.cfg.spill_dir,
                    &format!("{}.stdout", *a.operation_id),
                    bounds.max_retained_bytes,
                )),
                stderr: AsyncMutex::new(Spill::new(
                    &self.cfg.spill_dir,
                    &format!("{}.stderr", *a.operation_id),
                    bounds.max_retained_bytes,
                )),
                state: Mutex::new(Default::default()),
                version: tokio::sync::watch::channel(0).0,
            });
            ops.insert(op);
            (env, mode)
        };
        let op = self
            .ops
            .lock()
            .unwrap()
            .get(&a.operation_id)
            .expect("just inserted");
        self.emit_status();

        // Run it.
        let hand = self.clone();
        let op2 = op.clone();
        let tool = a.tool.clone();
        let input = a.input.clone();
        let capture_env = lane_mode == LaneMode::Persistent
            && !a.detach
            && matches!(
                executable,
                SessionExecutable::Preinstalled(tools::Preinstalled::Bash)
            );
        let spill_dir = self.cfg.spill_dir.clone();
        tokio::spawn(async move {
            let captured = match executable {
                SessionExecutable::Preinstalled(tools::Preinstalled::Bash) => {
                    let command = input
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let timeout_ms = input.get("timeout_ms").and_then(Value::as_u64);
                    let spec = BashSpec {
                        command,
                        env,
                        cwd,
                        capture_env_to: if capture_env {
                            Some(spill_dir.join(format!("{}.env", *op2.id)))
                        } else {
                            None
                        },
                        timeout_ms,
                    };
                    run_bash(op2.clone(), spec).await.captured_env
                }
                SessionExecutable::Preinstalled(implementation) => {
                    hand.run_typed_tool(&op2, &tool, implementation, input, cwd, &session)
                        .await;
                    None
                }
                SessionExecutable::Bundle(bundle) => {
                    hand.run_bundle_tool(BundleInvocation {
                        op: op2.clone(),
                        tool,
                        bundle,
                        input,
                        env,
                        cwd,
                        session,
                    })
                    .await;
                    None
                }
            };
            hand.on_op_terminal(&op2, captured);
        });
        let _ = session;

        if !a.detach && a.wait_ms > 0 {
            let wait = Duration::from_millis(a.wait_ms.min(self.cfg.limits.max_poll_wait_ms));
            op.wait_for(&[], wait).await;
        }
        let view = op.view().await;
        let slices = self.first_slices(&op, a.max_bytes).await?;
        Ok(StartResponse {
            view,
            slices,
            replayed: false,
        })
    }

    /// The preview slices returned by `start` (and replay): each stream from the earliest byte it
    /// still retains, so a head that already rolled off never fails the call.
    async fn first_slices(
        &self,
        op: &Operation,
        max_bytes: u64,
    ) -> AbiResult<Vec<brain_protocol::abi::OutputSlice>> {
        if max_bytes == 0 {
            return Ok(Vec::new());
        }
        let out_from = op.stdout.lock().await.retained_from();
        let err_from = op.stderr.lock().await.retained_from();
        op.slices(
            &[(Stream::Stdout, out_from), (Stream::Stderr, err_from)],
            max_bytes,
            self.cfg.limits.max_slice_bytes as u64,
        )
        .await
    }

    async fn run_typed_tool(
        &self,
        op: &Arc<Operation>,
        tool: &str,
        implementation: tools::Preinstalled,
        input: Value,
        cwd: PathBuf,
        session: &Session,
    ) {
        let res =
            tokio::task::spawn_blocking(move || tools::run(implementation, &input, &cwd)).await;
        let outcome = match res {
            Ok(o) => o,
            Err(e) => {
                let info = op.terminal_info(
                    Outcome::Failed,
                    None,
                    None,
                    None,
                    Some(internal(format!("tool task: {e}"))),
                );
                op.set_terminal(info);
                return;
            }
        };
        let _ = op.append(Stream::Stdout, &outcome.stdout).await;
        let _ = op.append(Stream::Stderr, &outcome.stderr).await;
        let (exit_code, output, error, result_outcome): (
            Option<i32>,
            Option<Value>,
            Option<AbiError>,
            Outcome,
        ) = match (&outcome.output, session.validators.get(tool)) {
            (Some(out), Some((_, output_v))) => match output_v.iter_errors(out).next() {
                None => (
                    Some(outcome.exit_code),
                    outcome.output.clone(),
                    None,
                    Outcome::Completed,
                ),
                Some(e) => (
                    None,
                    None,
                    Some(err(
                        ErrorCode::ToolOutputInvalid,
                        format!("{tool} output{}: {e}", e.instance_path()),
                    )),
                    Outcome::Failed,
                ),
            },
            _ => (Some(outcome.exit_code), None, None, Outcome::Completed),
        };
        let info = op.terminal_info(
            result_outcome,
            exit_code.map(i64::from),
            None,
            output,
            error,
        );
        op.set_terminal(info);
    }

    async fn run_bundle_tool(&self, invocation: BundleInvocation) {
        let BundleInvocation {
            op,
            tool,
            bundle,
            input,
            env,
            cwd,
            session,
        } = invocation;
        let Some(spec) = session
            .manifest
            .tools
            .iter()
            .find(|spec| *spec.name == tool)
        else {
            let info = op.terminal_info(
                Outcome::Failed,
                None,
                None,
                None,
                Some(err(
                    ErrorCode::ToolNotFound,
                    "sealed Tool definition is missing",
                )),
            );
            op.set_terminal(info);
            return;
        };
        let timeout_ms = op
            .bounds
            .timeout_ms
            .map(|value| value.get())
            .unwrap_or(24 * 60 * 60 * 1000);
        let request_path = self
            .cfg
            .spill_dir
            .join(format!("{}.tool-request.json", *op.id));
        let result_path = self
            .cfg
            .spill_dir
            .join(format!("{}.tool-result.json", *op.id));
        let request = serde_json::json!({
            "call_id": op.id.to_string(),
            "definition": {
                "name": spec.name.to_string(),
                "description": spec.description,
            },
            "required_env": spec.executable.required_env.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
            "input": input,
            "workspace": self.cfg.workspace.to_string_lossy(),
            "deadline_ms": wall_ms().saturating_add(timeout_ms),
        });
        let finished = run_node(
            op.clone(),
            NodeSpec {
                runner: self.cfg.tool_runner.clone(),
                bundle,
                request,
                env,
                cwd,
                request_path,
                result_path,
            },
        )
        .await;
        let mut outcome = finished.outcome;
        let mut output = finished.output;
        let mut error = finished
            .infrastructure_error
            .map(|message| err(ErrorCode::Internal, message));
        let validation_error = output.as_ref().and_then(|value| {
            session.validators.get(&tool).and_then(|(_, validator)| {
                validator.iter_errors(value).next().map(|validation| {
                    format!("{tool} output{}: {validation}", validation.instance_path())
                })
            })
        });
        if let Some(validation_error) = validation_error {
            outcome = Outcome::Failed;
            output = None;
            error = Some(err(ErrorCode::ToolOutputInvalid, validation_error));
        }
        let info = op.terminal_info(outcome, finished.exit_code, finished.signal, output, error);
        op.set_terminal(info);
    }

    fn on_op_terminal(&self, op: &Arc<Operation>, captured_env: Option<HashMap<String, String>>) {
        if let Some(lanes) = self.lanes.lock().unwrap().as_mut() {
            lanes.on_operation_terminal(&op.lane_id, &op.id, captured_env);
        }
        let none_running = self.ops.lock().unwrap().running().next().is_none();
        if none_running {
            *self.idle_since.lock().unwrap() = Instant::now();
        }
        self.emit_status();
    }

    async fn poll(&self, a: PollRequest) -> AbiResult<PollResponse> {
        self.session()?;
        let op = self
            .ops
            .lock()
            .unwrap()
            .get(&a.operation_id)
            .ok_or_else(|| {
                err(
                    ErrorCode::OperationNotFound,
                    format!("operation {} is unknown or released", *a.operation_id),
                )
            })?;
        let cursors: Vec<(Stream, u64)> = a.cursors.iter().map(|c| (c.stream, c.offset)).collect();
        if a.wait_ms > 0 {
            op.wait_for(
                &cursors,
                Duration::from_millis(a.wait_ms.min(self.cfg.limits.max_poll_wait_ms)),
            )
            .await;
        }
        let view = op.view().await;
        let slices = op
            .slices(
                &cursors,
                a.max_bytes,
                self.cfg.limits.max_slice_bytes as u64,
            )
            .await?;
        Ok(PollResponse { view, slices })
    }

    async fn cancel(&self, a: CancelRequest) -> AbiResult<CancelResponse> {
        self.session()?;
        let op = self
            .ops
            .lock()
            .unwrap()
            .get(&a.operation_id)
            .ok_or_else(|| {
                err(
                    ErrorCode::OperationNotFound,
                    format!("operation {} is unknown or released", *a.operation_id),
                )
            })?;
        let accepted = self.cancel_op(&op, a.grace_ms);
        Ok(CancelResponse {
            accepted,
            view: op.view().await,
        })
    }

    /// TERM -> grace -> KILL. Returns false if the operation was already terminal.
    fn cancel_op(&self, op: &Arc<Operation>, grace_ms: Option<u64>) -> bool {
        {
            let mut st = op.state.lock().unwrap();
            if st.terminal.is_some() {
                return false;
            }
            st.cancel_requested = true;
        }
        op.signal(libc::SIGTERM);
        let grace = Duration::from_millis(grace_ms.unwrap_or(op.bounds.grace_ms));
        let op2 = op.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if !op2.is_terminal() {
                op2.signal(libc::SIGKILL);
            }
        });
        true
    }

    async fn release(&self, a: ReleaseRequest) -> AbiResult<ReleaseResponse> {
        self.session()?;
        let mut released = Vec::new();
        let mut unknown = Vec::new();
        for id in a.operation_ids {
            let removed = self.ops.lock().unwrap().remove(&id);
            match removed {
                Some(op) => {
                    if !op.is_terminal() {
                        // Releasing a running operation: it is forgotten from the registry; the
                        // process (if any) is cancelled so nothing runs unaccounted.
                        self.cancel_op(&op, None);
                    }
                    op.state.lock().unwrap().released = true;
                    op.remove_spill().await;
                    released.push(id);
                }
                None => unknown.push(id),
            }
        }
        self.emit_status();
        Ok(ReleaseResponse { released, unknown })
    }

    async fn lane_close(&self, a: LaneCloseRequest) -> AbiResult<LaneCloseResponse> {
        self.session()?;
        let (closed, inflight) = {
            let mut lanes = self.lanes.lock().unwrap();
            let lanes = lanes
                .as_mut()
                .ok_or_else(|| err(ErrorCode::Unauthorized, "hello first"))?;
            lanes.close(&a.lane_id)?
        };
        let mut cancelled = Vec::new();
        if let Some(op_id) = inflight
            && let Some(op) = self.ops.lock().unwrap().get(&op_id)
            && self.cancel_op(&op, a.grace_ms)
        {
            cancelled.push(op_id);
        }
        self.emit_status();
        Ok(LaneCloseResponse {
            closed,
            cancelled_operations: cancelled,
        })
    }

    // ----- files ---------------------------------------------------------------------------

    async fn put(&self, a: PutRequest) -> AbiResult<PutResponse> {
        let session = self.session()?;
        let mut written = Vec::new();
        for f in a.files {
            let dest = session.scope.resolve(&f.path)?;
            let mode = f.mode.unwrap_or(0o644) as u32;
            let (bytes, sha) = match f.source {
                PutSource::Url {
                    get_url,
                    bytes,
                    sha256,
                } => {
                    transfer::download_to(&self.http, &get_url, &dest, Some(bytes), Some(&sha256))
                        .await?
                }
                PutSource::Inline { data_base64 } => {
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(data_base64.as_bytes())
                        .map_err(|e| malformed(format!("inline data_base64: {e}")))?;
                    if data.len() as u64 > self.cfg.limits.max_inline_put_bytes {
                        return Err(err(
                            ErrorCode::TooLarge,
                            format!(
                                "inline payload {} > max_inline_put_bytes {}",
                                data.len(),
                                self.cfg.limits.max_inline_put_bytes
                            ),
                        ));
                    }
                    if let Some(parent) = dest.parent() {
                        tokio::fs::create_dir_all(parent).await.map_err(internal)?;
                    }
                    let tmp = dest.with_extension("aex-tmp");
                    tokio::fs::write(&tmp, &data).await.map_err(internal)?;
                    tokio::fs::rename(&tmp, &dest).await.map_err(internal)?;
                    (data.len() as u64, transfer::sha256_hex(&data))
                }
            };
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
                .await
                .map_err(internal)?;
            written.push(PutResponseWrittenItem {
                path: dest.to_string_lossy().into_owned(),
                bytes,
                sha256: sha,
            });
        }
        Ok(PutResponse { written })
    }

    async fn persist(&self, a: PersistRequest) -> AbiResult<PersistResponse> {
        let session = self.session()?;
        let mut persisted = Vec::new();
        for item in a.items {
            let (bytes, sha, media_type) = match &item.source {
                PersistSource::Path { path } => {
                    let p = session.scope.resolve(path)?;
                    let md = tokio::fs::metadata(&p)
                        .await
                        .map_err(|e| err(ErrorCode::PathNotFound, format!("{path}: {e}")))?;
                    if !md.is_file() {
                        return Err(err(
                            ErrorCode::PathNotFound,
                            format!("{path}: not a regular file"),
                        ));
                    }
                    if md.len() > self.cfg.limits.max_persist_bytes {
                        return Err(err(
                            ErrorCode::TooLarge,
                            format!(
                                "{path}: {} bytes > max_persist_bytes {}",
                                md.len(),
                                self.cfg.limits.max_persist_bytes
                            ),
                        ));
                    }
                    let media_type = item
                        .media_type
                        .clone()
                        .unwrap_or_else(|| guess_media_type(&p).to_string());
                    let (b, s) =
                        transfer::upload_file(&self.http, &item.put_url, &p, &media_type).await?;
                    (b, s, media_type)
                }
                PersistSource::OperationStream {
                    operation_id,
                    stream,
                } => {
                    let op = self.ops.lock().unwrap().get(operation_id).ok_or_else(|| {
                        err(
                            ErrorCode::OperationNotFound,
                            format!("operation {} is unknown or released", **operation_id),
                        )
                    })?;
                    let data = match stream {
                        Stream::Stdout => op.stdout.lock().await.read_retained(),
                        Stream::Stderr => op.stderr.lock().await.read_retained(),
                    }
                    .map_err(internal)?;
                    if data.len() as u64 > self.cfg.limits.max_persist_bytes {
                        return Err(err(ErrorCode::TooLarge, "stream exceeds max_persist_bytes"));
                    }
                    let media_type = item
                        .media_type
                        .clone()
                        .unwrap_or_else(|| "text/plain".to_string());
                    let (b, s) =
                        transfer::upload_bytes(&self.http, &item.put_url, data, &media_type)
                            .await?;
                    (b, s, media_type)
                }
            };
            persisted.push(PersistResponsePersistedItem {
                name: item.name.to_string(),
                bytes,
                sha256: sha,
                media_type,
            });
        }
        Ok(PersistResponse { persisted })
    }

    async fn sync(&self, a: SyncRequest) -> AbiResult<SyncResponse> {
        let session = self.session()?;
        let mut st = self.sync.lock().await;
        let tmp = self.cfg.spill_dir.join("sync");
        crate::sync::sync(
            &self.http,
            &session.sync_scope,
            &mut st,
            &a,
            &self.generation_id,
            &tmp,
        )
        .await
    }

    // ----- status ------------------------------------------------------------------------

    pub fn emit_status(&self) {
        let ev = self.status_event();
        self.status.publish(ev);
    }

    pub fn status_event(&self) -> HandStatusEvent {
        let (inflight, live_jobs, retained, retained_bytes) = {
            let ops = self.ops.lock().unwrap();
            let mut inflight = Vec::new();
            let mut live_jobs = Vec::new();
            let mut retained = 0u64;
            for op in ops.all() {
                if op.is_terminal() {
                    retained += 1;
                } else if op.detach {
                    live_jobs.push(op.id.clone());
                } else {
                    inflight.push(op.id.clone());
                }
            }
            // retained_bytes is best-effort without awaiting the spill locks: use try_lock.
            let mut bytes = 0u64;
            for op in ops.all() {
                if let Ok(s) = op.stdout.try_lock() {
                    bytes += s.retained_bytes();
                }
                if let Ok(s) = op.stderr.try_lock() {
                    bytes += s.retained_bytes();
                }
            }
            (inflight, live_jobs, retained, bytes)
        };
        let idle_for_ms = if inflight.is_empty() && live_jobs.is_empty() {
            self.idle_since.lock().unwrap().elapsed().as_millis() as u64
        } else {
            0
        };
        let lanes_live = self
            .lanes
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| l.live_count())
            .unwrap_or(0) as u64;
        HandStatusEvent {
            generation_id: self.generation_id.clone(),
            boot_id: self.boot_id.clone(),
            seq: self.status.next_seq(),
            at_monotonic_ms: MonotonicMs(monotonic_ms()),
            at_wall_ms: WallMs(wall_ms()),
            inflight,
            live_jobs,
            lanes_live,
            operations_retained: retained,
            retained_bytes,
            idle_for_ms,
            pressure: read_pressure(),
        }
    }

    /// Cancels everything (session end / shutdown).
    pub async fn shutdown(&self) {
        let ops = self.ops.lock().unwrap().all();
        for op in ops {
            self.cancel_op(&op, Some(2000));
        }
        if let Some(h) = self.heartbeat.lock().unwrap().take() {
            h.abort();
        }
    }
}

fn guess_media_type(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("txt") | Some("log") => "text/plain",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("html") | Some("htm") => "text/html",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("zip") => "application/zip",
        Some("gz") | Some("tgz") => "application/gzip",
        Some("zst") => "application/zstd",
        Some("tar") => "application/x-tar",
        Some("py") | Some("rs") | Some("js") | Some("ts") | Some("go") | Some("sh")
        | Some("toml") | Some("yaml") | Some("yml") => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Errors after which the connection is closed (the peer is not our brain, or cannot talk v1).
pub fn is_fatal_for_connection(e: &AbiError) -> bool {
    matches!(
        e.code,
        ErrorCode::Unauthorized | ErrorCode::ProtocolUnsupported
    )
}
