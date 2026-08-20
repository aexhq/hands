//! End-to-end tests: a real hand (in-process, listening on localhost), the real client, and an
//! in-process HTTP blob store standing in for presigned S3 URLs. Linux only.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use brain_hand_client::{ClientError, HandClient, root_lane, start_request};
use brain_protocol::abi::{
    Bounds, CancelRequest, Cursor, ErrorCode, HelloRequest, LaneCloseRequest, LaneMode, LaneRef,
    OperationStatus, Outcome, PersistItem, PersistRequest, PersistSource, PollRequest,
    ProtocolVersion, PutFile, PutRequest, PutSource, ReleaseRequest, RestoreSource,
    RestoreSourcePacksItem, Stream, SyncReason, SyncRequest, SyncScope, ToolManifest,
};
use hand_guest::{Config, Hand, Server};
use serde_json::json;
use tempfile::TempDir;

const TOKEN: &str = "tok-test";
const SESSION: &str = "ses_test0000000000000000000";

// ----- fixtures ---------------------------------------------------------------------------

struct TestHand {
    _dir: TempDir,
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub spill: PathBuf,
    pub addr: SocketAddr,
    pub hand: Arc<Hand>,
    _server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn spawn_hand_at(dir: TempDir, workspace: PathBuf, home: PathBuf) -> TestHand {
    let spill = dir.path().join("spill");
    let mut cfg = Config::new(
        "127.0.0.1:0".parse().unwrap(),
        Some(TOKEN.into()),
        workspace.clone(),
        home.clone(),
        spill.clone(),
    );
    cfg.tool_runner =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../image/tool-runner.mjs");
    cfg.tool_dir = dir.path().join("tools");
    let hand = Hand::new(cfg).unwrap();
    let server = Server::bind(hand.clone()).await.unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.run());
    TestHand {
        _dir: dir,
        workspace,
        home,
        spill,
        addr,
        hand,
        _server: task,
    }
}

async fn spawn_hand() -> TestHand {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("workspace");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    spawn_hand_at(dir, ws, home).await
}

fn hello_req(h: &TestHand) -> HelloRequest {
    HelloRequest {
        protocol: ProtocolVersion::CURRENT,
        session_id: SESSION.parse().unwrap(),
        session_token: TOKEN.into(),
        expected_generation_id: None,
        tool_manifest: brain_protocol::tools::manifest_v1().clone(),
        tool_manifest_digest: brain_protocol::tools::TOOL_MANIFEST_V1_DIGEST
            .trim()
            .parse()
            .unwrap(),
        env: HashMap::from([("SESSION_TAG".to_string(), "t1".to_string())]),
        sync: SyncScope {
            roots: vec![
                h.workspace.to_string_lossy().into_owned(),
                h.home.to_string_lossy().into_owned(),
            ],
            exclude: vec!["**/.cache".into(), "**/.cache/**".into()],
        },
        restore: None,
        heartbeat_ms: 1000,
    }
}

async fn connect(h: &TestHand) -> HandClient {
    let c = HandClient::connect(&format!("ws://{}/", h.addr), 1)
        .await
        .unwrap();
    c.hello(hello_req(h)).await.unwrap();
    c
}

fn b64(s: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn stdout_of(slices: &[brain_protocol::abi::OutputSlice]) -> String {
    let mut v = Vec::new();
    for s in slices.iter().filter(|s| s.stream == Stream::Stdout) {
        v.extend(b64(s.data_base64.as_bytes()));
    }
    String::from_utf8_lossy(&v).into_owned()
}
fn stderr_of(slices: &[brain_protocol::abi::OutputSlice]) -> String {
    let mut v = Vec::new();
    for s in slices.iter().filter(|s| s.stream == Stream::Stderr) {
        v.extend(b64(s.data_base64.as_bytes()));
    }
    String::from_utf8_lossy(&v).into_owned()
}

async fn bash(c: &HandClient, id: &str, cmd: &str) -> brain_protocol::abi::StartResponse {
    c.start(start_request(
        id,
        "bash",
        json!({"command": cmd}),
        root_lane(),
        None,
        false,
        10_000,
        65536,
    ))
    .await
    .unwrap()
}

async fn bash_out(c: &HandClient, id: &str, cmd: &str) -> String {
    let r = bash(c, id, cmd).await;
    assert_eq!(
        r.view.status,
        OperationStatus::Terminal,
        "{cmd} did not finish"
    );
    stdout_of(&r.slices)
}

fn abi_code(e: &ClientError) -> Option<ErrorCode> {
    match e {
        ClientError::Abi(a) => Some(a.code),
        _ => None,
    }
}

fn custom_bundle(dir: &Path) -> (ToolManifest, brain_protocol::abi::Sha256Hex) {
    use sha2::Digest as _;

    let source = br#"
const reverse = (value) => [...value].reverse().join("");
export default {
  kind: "brain.tool",
  name: "third_party_lookup",
  description: "Exercise a bundled third-party Tool.",
  requiredEnv: ["CUSTOM_SECRET"],
  async execute({ value, delay_ms = 0 }, { signal }) {
    if (delay_ms > 0) await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, delay_ms);
      signal.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(signal.reason ?? new Error("cancelled"));
      }, { once: true });
    });
    process.stdout.write(`bundle:${process.env.CUSTOM_SECRET}\n`);
    return { value: `${reverse(value)}:${process.env.CUSTOM_SECRET}` };
  },
};
"#;
    let path = dir.join("third-party-tool.mjs");
    std::fs::write(&path, source).unwrap();
    let checksum = hex::encode(sha2::Sha256::digest(source));
    let manifest: ToolManifest = serde_json::from_value(json!({
        "version": "1",
        "tools": [{
            "name": "third_party_lookup",
            "description": "Exercise a bundled third-party Tool.",
            "input_schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["value"],
                "properties": {
                    "value": {"type": "string"},
                    "delay_ms": {"type": "integer", "minimum": 0}
                }
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["value"],
                "properties": {"value": {"type": "string"}}
            },
            "executable": {
                "protocol": 1,
                "checksum": checksum,
                "source": "bundle",
                "required_env": ["CUSTOM_SECRET"],
                "get_url": format!("file://{}", path.display()),
                "bytes": source.len()
            }
        }]
    }))
    .unwrap();
    let digest = brain_protocol::tools::manifest_digest(&manifest);
    (manifest, digest)
}

async fn connect_custom(
    hand: &TestHand,
    session: &str,
    secret: &str,
    manifest: ToolManifest,
    digest: brain_protocol::abi::Sha256Hex,
) -> HandClient {
    let client = HandClient::connect(&format!("ws://{}/", hand.addr), 1)
        .await
        .unwrap();
    let mut hello = hello_req(hand);
    hello.session_id = session.parse().unwrap();
    hello.env = HashMap::from([("CUSTOM_SECRET".to_string(), secret.to_string())]);
    hello.tool_manifest = manifest;
    hello.tool_manifest_digest = digest;
    client.hello(hello).await.unwrap();
    client
}

/// In-process object store: PUT /{key} stores, GET /{key} serves. Stands in for presigned URLs.
type BlobStore = Arc<Mutex<HashMap<String, (Vec<u8>, String)>>>;

struct Blob {
    addr: SocketAddr,
    store: BlobStore,
}

impl Blob {
    async fn start() -> Blob {
        use axum::{
            Router,
            body::Bytes,
            extract::{Path as AxPath, State},
            http::{HeaderMap, StatusCode},
            routing::get,
        };
        type Store = Arc<Mutex<HashMap<String, (Vec<u8>, String)>>>;
        let store: Store = Default::default();
        async fn put(
            State(s): State<Store>,
            AxPath(key): AxPath<String>,
            headers: HeaderMap,
            body: Bytes,
        ) -> StatusCode {
            let ct = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            s.lock().unwrap().insert(key, (body.to_vec(), ct));
            StatusCode::OK
        }
        async fn get_(
            State(s): State<Store>,
            AxPath(key): AxPath<String>,
        ) -> Result<Vec<u8>, StatusCode> {
            s.lock()
                .unwrap()
                .get(&key)
                .map(|(b, _)| b.clone())
                .ok_or(StatusCode::NOT_FOUND)
        }
        let app = Router::new()
            .route("/{*key}", get(get_).put(put))
            .with_state(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Blob { addr, store }
    }
    fn url(&self, key: &str) -> String {
        format!("http://{}/{key}?X-Amz-Signature=fake", self.addr)
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.store.lock().unwrap().get(key).map(|(b, _)| b.clone())
    }
    fn put(&self, key: &str, bytes: &[u8]) {
        self.store
            .lock()
            .unwrap()
            .insert(key.into(), (bytes.to_vec(), String::new()));
    }
}

// ----- tests -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundled_tools_are_isolated_cancelled_and_restaged_after_recreation() {
    let alpha = spawn_hand().await;
    let beta = spawn_hand().await;
    let (alpha_manifest, alpha_digest) = custom_bundle(alpha._dir.path());
    let (beta_manifest, beta_digest) = custom_bundle(beta._dir.path());
    let alpha_client = connect_custom(
        &alpha,
        "ses_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "alpha-secret",
        alpha_manifest.clone(),
        alpha_digest.clone(),
    );
    let beta_client = connect_custom(
        &beta,
        "ses_bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "beta-secret",
        beta_manifest,
        beta_digest,
    );
    let (alpha_client, beta_client) = tokio::join!(alpha_client, beta_client);

    let alpha_call = alpha_client.start(start_request(
        "bundle-alpha",
        "third_party_lookup",
        json!({"value": "one"}),
        root_lane(),
        None,
        false,
        10_000,
        4_096,
    ));
    let beta_call = beta_client.start(start_request(
        "bundle-beta",
        "third_party_lookup",
        json!({"value": "two"}),
        root_lane(),
        None,
        false,
        10_000,
        4_096,
    ));
    let (alpha_result, beta_result) = tokio::join!(alpha_call, beta_call);
    let alpha_result = alpha_result.unwrap();
    let beta_result = beta_result.unwrap();
    assert_eq!(
        alpha_result.view.terminal.as_ref().unwrap().output.clone(),
        Some(json!({"value": "eno:alpha-secret"}))
    );
    assert_eq!(
        beta_result.view.terminal.as_ref().unwrap().output.clone(),
        Some(json!({"value": "owt:beta-secret"}))
    );
    assert!(stdout_of(&alpha_result.slices).contains("alpha-secret"));
    assert!(!stdout_of(&alpha_result.slices).contains("beta-secret"));
    assert!(stdout_of(&beta_result.slices).contains("beta-secret"));
    assert!(!stdout_of(&beta_result.slices).contains("alpha-secret"));

    let started = alpha_client
        .start(start_request(
            "bundle-cancel",
            "third_party_lookup",
            json!({"value": "slow", "delay_ms": 30_000}),
            root_lane(),
            None,
            false,
            0,
            0,
        ))
        .await
        .unwrap();
    assert_eq!(started.view.status, OperationStatus::Running);
    let cancelled = alpha_client
        .cancel(CancelRequest {
            operation_id: "bundle-cancel".parse().unwrap(),
            grace_ms: Some(500),
        })
        .await
        .unwrap();
    assert!(cancelled.accepted);
    let terminal = loop {
        let polled = alpha_client
            .poll(PollRequest {
                operation_id: "bundle-cancel".parse().unwrap(),
                cursors: vec![],
                max_bytes: 0,
                wait_ms: 2_000,
            })
            .await
            .unwrap();
        if polled.view.status == OperationStatus::Terminal {
            break polled.view.terminal.unwrap();
        }
    };
    assert_eq!(terminal.outcome, Outcome::Cancelled);

    // A fresh Hand has no staged state. Supplying the same sealed manifest restages the exact
    // bytes and runs successfully; no preinstalled-name fallback is involved.
    let recreated = spawn_hand().await;
    let recreated_client = connect_custom(
        &recreated,
        "ses_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "alpha-secret",
        alpha_manifest,
        alpha_digest,
    )
    .await;
    let result = recreated_client
        .start(start_request(
            "bundle-restored",
            "third_party_lookup",
            json!({"value": "again"}),
            root_lane(),
            None,
            false,
            10_000,
            4_096,
        ))
        .await
        .unwrap();
    assert_eq!(
        result.view.terminal.unwrap().output,
        Some(json!({"value": "niaga:alpha-secret"}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_seals_manifest_and_bash_round_trips_in_one_call() {
    let h = spawn_hand().await;
    let c = HandClient::connect(&format!("ws://{}/", h.addr), 1)
        .await
        .unwrap();
    let hello = c.hello(hello_req(&h)).await.unwrap();
    let names: Vec<String> = hello.tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(
        names,
        ["bash", "edit", "glob", "grep", "ls", "read", "write"]
    );
    assert_eq!(
        &*hello.tool_manifest_digest,
        brain_protocol::tools::TOOL_MANIFEST_V1_DIGEST.trim()
    );
    assert_eq!(hello.lanes.len(), 1);
    assert_eq!(&*hello.lanes[0].id, "0");
    assert!(hello.operations.is_empty());
    assert_eq!(hello.paths.workspace, h.workspace.to_string_lossy());

    let r = bash(&c, "op-1", "echo hi; echo err >&2; exit 3").await;
    assert!(!r.replayed);
    assert_eq!(r.view.status, OperationStatus::Terminal);
    let t = r.view.terminal.as_ref().unwrap();
    assert_eq!(t.outcome, Outcome::Completed);
    assert_eq!(t.exit_code, Some(3));
    assert_eq!(t.output, Some(json!({"timed_out": false})));
    assert_eq!(stdout_of(&r.slices), "hi\n");
    assert_eq!(stderr_of(&r.slices), "err\n");
    let out = r
        .view
        .streams
        .iter()
        .find(|s| s.stream == Stream::Stdout)
        .unwrap();
    assert_eq!(out.produced_bytes, 3);
    assert!(out.sha256.is_some());
    assert!(
        out.spill_path
            .as_ref()
            .unwrap()
            .starts_with(&*h.spill.to_string_lossy())
    );

    // Session env reaches the shell; per-call cwd defaults to the workspace.
    assert_eq!(
        bash_out(&c, "op-2", "echo $SESSION_TAG; pwd").await,
        format!("t1\n{}\n", h.workspace.canonicalize().unwrap().display())
    );

    let rel = c
        .release(ReleaseRequest {
            operation_ids: vec![
                "op-1".parse().unwrap(),
                "op-1".parse().unwrap(),
                "nope".parse().unwrap(),
            ],
        })
        .await
        .unwrap();
    assert_eq!(rel.released.len(), 1);
    assert_eq!(rel.unknown.len(), 2);
    let e = c
        .poll(PollRequest {
            operation_id: "op-1".parse().unwrap(),
            cursors: vec![],
            max_bytes: 0,
            wait_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::OperationNotFound));
    assert!(
        !h.spill.join("op-1.stdout").exists(),
        "spill removed on release"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lanes_persist_env_and_ephemeral_lanes_discard_it() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    bash_out(&c, "a1", "export FOO=bar; cd /tmp").await;
    assert_eq!(
        bash_out(&c, "a2", "echo $FOO; pwd").await,
        format!("bar\n{}\n", h.workspace.canonicalize().unwrap().display()),
        "env persists, cwd does not"
    );
    let eph = LaneRef {
        id: "L1".parse().unwrap(),
        mode: LaneMode::Ephemeral,
        parent: Some("0".parse().unwrap()),
    };
    let r = c
        .start(start_request(
            "a3",
            "bash",
            json!({"command": "export BAZ=1; echo $FOO"}),
            eph,
            None,
            false,
            10_000,
            4096,
        ))
        .await
        .unwrap();
    assert_eq!(
        stdout_of(&r.slices),
        "bar\n",
        "ephemeral lane inherits parent env"
    );
    assert_eq!(
        bash_out(&c, "a4", "echo ${BAZ:-unset}").await,
        "unset\n",
        "ephemeral mutations are discarded"
    );
    // Persistent lane other than 0 inherits root env at creation, then lives on its own.
    let p = LaneRef {
        id: "P1".parse().unwrap(),
        mode: LaneMode::Persistent,
        parent: None,
    };
    let r = c
        .start(start_request(
            "a5",
            "bash",
            json!({"command": "echo $FOO; export ONLY_P1=1"}),
            p.clone(),
            None,
            false,
            10_000,
            4096,
        ))
        .await
        .unwrap();
    assert_eq!(stdout_of(&r.slices), "bar\n");
    let r = c
        .start(start_request(
            "a6",
            "bash",
            json!({"command": "echo ${ONLY_P1:-unset}"}),
            p,
            None,
            false,
            10_000,
            4096,
        ))
        .await
        .unwrap();
    assert_eq!(stdout_of(&r.slices), "1\n");
    assert_eq!(
        bash_out(&c, "a7", "echo ${ONLY_P1:-unset}").await,
        "unset\n"
    );
    // cwd is a per-call parameter.
    let r = c
        .start(start_request(
            "a8",
            "bash",
            json!({"command": "pwd"}),
            root_lane(),
            Some(h.home.to_string_lossy().into_owned()),
            false,
            10_000,
            4096,
        ))
        .await
        .unwrap();
    assert_eq!(
        stdout_of(&r.slices),
        format!("{}\n", h.home.canonicalize().unwrap().display())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_tools_behave_like_commands() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let ws = h.workspace.to_string_lossy().into_owned();
    let call = |id: &str, tool: &str, input: serde_json::Value| {
        start_request(id, tool, input, root_lane(), None, false, 10_000, 65536)
    };

    let r = c
        .start(call(
            "w1",
            "write",
            json!({"path": "src/main.rs", "content": "fn main() {}\nfn helper() {}\n"}),
        ))
        .await
        .unwrap();
    let t = r.view.terminal.unwrap();
    assert_eq!(t.exit_code, Some(0));
    assert_eq!(
        t.output,
        Some(json!({"bytes_written": 28, "created": true}))
    );
    assert!(h.workspace.join("src/main.rs").is_file());

    let r = c
        .start(call(
            "r1",
            "read",
            json!({"path": format!("{ws}/src/main.rs"), "offset": 2}),
        ))
        .await
        .unwrap();
    assert_eq!(stdout_of(&r.slices), "fn helper() {}\n");
    assert_eq!(
        r.view.terminal.unwrap().output,
        Some(json!({"total_lines": 2, "start_line": 2, "end_line": 2, "truncated": false}))
    );

    let r = c
        .start(call(
            "e1",
            "edit",
            json!({"path": "src/main.rs", "old_string": "helper", "new_string": "assistant"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.view.terminal.unwrap().output,
        Some(json!({"replacements": 1}))
    );
    let r = c
        .start(call(
            "e2",
            "edit",
            json!({"path": "src/main.rs", "old_string": "missing", "new_string": "x"}),
        ))
        .await
        .unwrap();
    let t = r.view.terminal.unwrap();
    assert_eq!(t.exit_code, Some(1));
    assert!(t.output.is_none());
    assert!(stderr_of(&r.slices).contains("old_string not found"));
    let r = c
        .start(call(
            "e3",
            "edit",
            json!({"path": "src/main.rs", "old_string": "fn", "new_string": "fn"}),
        ))
        .await
        .unwrap();
    assert!(stderr_of(&r.slices).contains("matches 2 times"));

    let r = c
        .start(call("g1", "glob", json!({"pattern": "**/*.rs"})))
        .await
        .unwrap();
    assert_eq!(
        stdout_of(&r.slices).trim(),
        h.workspace.join("src/main.rs").to_string_lossy()
    );
    assert_eq!(
        r.view.terminal.unwrap().output,
        Some(json!({"matches": 1, "truncated": false}))
    );

    let r = c
        .start(call(
            "gr1",
            "grep",
            json!({"pattern": "assistant", "mode": "content"}),
        ))
        .await
        .unwrap();
    assert!(
        stdout_of(&r.slices).ends_with("src/main.rs:2:fn assistant() {}\n"),
        "{}",
        stdout_of(&r.slices)
    );
    assert_eq!(
        r.view.terminal.unwrap().output,
        Some(json!({"matches": 1, "truncated": false}))
    );
    let r = c
        .start(call(
            "gr2",
            "grep",
            json!({"pattern": "FN", "case_insensitive": true, "mode": "count"}),
        ))
        .await
        .unwrap();
    assert!(stdout_of(&r.slices).ends_with("src/main.rs:2\n"));
    let r = c
        .start(call("gr3", "grep", json!({"pattern": "main"})))
        .await
        .unwrap();
    assert_eq!(
        stdout_of(&r.slices).trim(),
        h.workspace.join("src/main.rs").to_string_lossy()
    );

    let r = c
        .start(call("l1", "ls", json!({"depth": 2})))
        .await
        .unwrap();
    assert_eq!(stdout_of(&r.slices), "src/\nsrc/main.rs\n");

    std::fs::write(h.workspace.join("bin.dat"), [0u8, 1, 2, 3]).unwrap();
    let r = c
        .start(call("r2", "read", json!({"path": "bin.dat"})))
        .await
        .unwrap();
    assert_eq!(r.view.terminal.unwrap().exit_code, Some(1));
    assert!(stderr_of(&r.slices).contains("binary"));

    let e = c
        .start(call("x1", "read", json!({"nope": 1})))
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::ToolInputInvalid));
    let e = c
        .start(call("x2", "teleport", json!({})))
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::ToolNotFound));
}

#[tokio::test(flavor = "multi_thread")]
async fn detached_job_polls_cancels_and_shows_in_status() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let mut status = c.status_events();
    let r = c
        .start(start_request(
            "j1",
            "bash",
            json!({"command": "for i in $(seq 1 200); do echo line$i; sleep 0.05; done"}),
            root_lane(),
            None,
            true,
            0,
            0,
        ))
        .await
        .unwrap();
    assert_eq!(r.view.status, OperationStatus::Running);
    assert!(r.view.detach);
    // Lane 0 is not held by a detached job.
    assert_eq!(bash_out(&c, "j2", "echo free").await, "free\n");
    let p = c
        .poll(PollRequest {
            operation_id: "j1".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: 0,
            }],
            max_bytes: 65536,
            wait_ms: 2000,
        })
        .await
        .unwrap();
    assert_eq!(p.view.status, OperationStatus::Running);
    let text = stdout_of(&p.slices);
    assert!(text.starts_with("line1\n"), "{text:?}");
    let next = p.slices[0].offset + b64(p.slices[0].data_base64.as_bytes()).len() as u64;
    // Poll from the cursor: only new bytes, and it waits for them.
    let p2 = c
        .poll(PollRequest {
            operation_id: "j1".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: next,
            }],
            max_bytes: 65536,
            wait_ms: 2000,
        })
        .await
        .unwrap();
    assert_eq!(p2.slices[0].offset, next);
    assert!(!b64(p2.slices[0].data_base64.as_bytes()).is_empty());
    // A status event mentioning the live job arrives.
    let ev = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let ev = status.recv().await.unwrap();
            if ev.live_jobs.iter().any(|o| &**o == "j1") {
                return ev;
            }
        }
    })
    .await
    .expect("status with live job");
    assert_eq!(ev.idle_for_ms, 0);
    let cr = c
        .cancel(CancelRequest {
            operation_id: "j1".parse().unwrap(),
            grace_ms: Some(1000),
        })
        .await
        .unwrap();
    assert!(cr.accepted);
    let p3 = c
        .poll(PollRequest {
            operation_id: "j1".parse().unwrap(),
            cursors: vec![],
            max_bytes: 0,
            wait_ms: 5000,
        })
        .await
        .unwrap();
    assert_eq!(p3.view.status, OperationStatus::Terminal);
    let t = p3.view.terminal.unwrap();
    assert_eq!(t.outcome, Outcome::Cancelled);
    assert_eq!(t.signal.as_deref(), Some("SIGTERM"));
    let cr2 = c
        .cancel(CancelRequest {
            operation_id: "j1".parse().unwrap(),
            grace_ms: None,
        })
        .await
        .unwrap();
    assert!(!cr2.accepted, "cancelling a terminal op is not an error");
    // Idle again, and the retained op shows in status.
    let ev = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let ev = status.recv().await.unwrap();
            if ev.live_jobs.is_empty() && ev.inflight.is_empty() {
                return ev;
            }
        }
    })
    .await
    .unwrap();
    assert!(ev.operations_retained >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_and_grandchildren_do_not_hang_the_operation() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let mut req = start_request(
        "d1",
        "bash",
        json!({"command": "sleep 30"}),
        root_lane(),
        None,
        false,
        10_000,
        0,
    );
    req.bounds = Some(Bounds {
        timeout_ms: Some(300.try_into().unwrap()),
        grace_ms: Some(200),
        max_retained_bytes: None,
    });
    req.call_hash = brain_protocol::tools::call_hash(&req);
    let r = c.start(req).await.unwrap();
    let t = r.view.terminal.unwrap();
    assert_eq!(t.outcome, Outcome::DeadlineExceeded);
    assert_eq!(t.output, Some(json!({"timed_out": true})));
    // Per-call timeout via the tool input.
    let r = c
        .start(start_request(
            "d2",
            "bash",
            json!({"command": "sleep 30", "timeout_ms": 200}),
            root_lane(),
            None,
            false,
            10_000,
            0,
        ))
        .await
        .unwrap();
    assert_eq!(r.view.terminal.unwrap().outcome, Outcome::DeadlineExceeded);
    // A backgrounded grandchild holding stdout must not keep the operation open (I6).
    let started = std::time::Instant::now();
    let r = bash(&c, "d3", "(sleep 20 &) ; echo parent-done").await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "waited on pipe EOF instead of child exit"
    );
    assert_eq!(r.view.terminal.unwrap().exit_code, Some(0));
    assert!(stdout_of(&r.slices).contains("parent-done"));
}

#[tokio::test(flavor = "multi_thread")]
async fn start_is_idempotent_and_envelope_checks_hold() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let marker = h.workspace.join("count.txt");
    let cmd = format!("echo x >> {}", marker.display());
    let r1 = bash(&c, "i1", &cmd).await;
    assert!(!r1.replayed);
    let r2 = bash(&c, "i1", &cmd).await;
    assert!(r2.replayed, "same operation_id + call_hash replays");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "x\n",
        "the command ran once"
    );
    let e = c
        .start(start_request(
            "i1",
            "bash",
            json!({"command": "echo other"}),
            root_lane(),
            None,
            false,
            0,
            0,
        ))
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::OperationIdempotencyConflict));

    // call_hash must match the request identity.
    let mut bad = start_request(
        "i2",
        "bash",
        json!({"command": "true"}),
        root_lane(),
        None,
        false,
        0,
        0,
    );
    bad.call_hash = "0".repeat(64).parse().unwrap();
    let e = c.start(bad).await.unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::MalformedRequest));

    // Fence: lower is refused; generation must match.
    c.set_fence(0);
    let e = bash_err(&c, "i3", "true").await;
    assert_eq!(abi_code(&e), Some(ErrorCode::FenceStale));
    c.set_fence(5);
    let generation = c.generation().await;
    c.set_generation(Some("gen-other".parse().unwrap())).await;
    let e = bash_err(&c, "i4", "true").await;
    assert_eq!(abi_code(&e), Some(ErrorCode::GenerationMismatch));
    c.set_generation(generation).await;
    bash_out(&c, "i5", "true").await;

    // Wrong token: unauthorized and the connection is closed.
    let c2 = HandClient::connect(&format!("ws://{}/", h.addr), 10)
        .await
        .unwrap();
    let mut req = hello_req(&h);
    req.session_token = "wrong".into();
    let e = c2.hello(req).await.unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::Unauthorized));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let e = c2.hello(hello_req(&h)).await.unwrap_err();
    assert!(
        matches!(e, ClientError::Closed | ClientError::Transport(_)),
        "{e:?}"
    );

    // Wrong manifest digest fails the hello.
    let c3 = HandClient::connect(&format!("ws://{}/", h.addr), 10)
        .await
        .unwrap();
    let mut req = hello_req(&h);
    req.tool_manifest_digest = "f".repeat(64).parse().unwrap();
    let e = c3.hello(req).await.unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::ToolManifestMismatch));
    // Before hello, nothing else works.
    let e = c3
        .poll(PollRequest {
            operation_id: "i1".parse().unwrap(),
            cursors: vec![],
            max_bytes: 0,
            wait_ms: 0,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        abi_code(&e),
        Some(ErrorCode::MalformedRequest) | Some(ErrorCode::Unauthorized)
    ));

    // Reconnect: a fresh connection to the same generation sees the retained operations.
    let c4 = HandClient::connect(&format!("ws://{}/", h.addr), 10)
        .await
        .unwrap();
    let mut req = hello_req(&h);
    req.expected_generation_id = Some(h.hand.generation_id.clone());
    let hello = c4.hello(req).await.unwrap();
    assert!(hello.operations.iter().any(|o| &*o.operation_id == "i1"));
    assert!(hello.restore.is_none());
}

async fn bash_err(c: &HandClient, id: &str, cmd: &str) -> ClientError {
    c.start(start_request(
        id,
        "bash",
        json!({"command": cmd}),
        root_lane(),
        None,
        false,
        1000,
        0,
    ))
    .await
    .unwrap_err()
}

#[tokio::test(flavor = "multi_thread")]
async fn output_retention_is_bounded_and_eviction_is_reported() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let mut req = start_request(
        "o1",
        "bash",
        json!({"command": "head -c 40000 /dev/zero | tr '\\0' a"}),
        root_lane(),
        None,
        false,
        10_000,
        1024,
    );
    req.bounds = Some(Bounds {
        timeout_ms: None,
        grace_ms: None,
        max_retained_bytes: Some(8192),
    });
    req.call_hash = brain_protocol::tools::call_hash(&req);
    let r = c.start(req).await.unwrap();
    let out = r
        .view
        .streams
        .iter()
        .find(|s| s.stream == Stream::Stdout)
        .unwrap();
    assert_eq!(out.produced_bytes, 40000);
    assert!(
        out.retained_from > 0 && out.retained_from <= 40000 - 4096,
        "retained_from = {}",
        out.retained_from
    );
    assert!(out.sha256.is_none(), "no digest once bytes were evicted");
    assert!(out.spill_path.is_none(), "rolled spill has no single path");
    let e = c
        .poll(PollRequest {
            operation_id: "o1".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: 0,
            }],
            max_bytes: 100,
            wait_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::OperationOutputEvicted));
    let p = c
        .poll(PollRequest {
            operation_id: "o1".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: out.retained_from,
            }],
            max_bytes: 100_000,
            wait_ms: 0,
        })
        .await
        .unwrap();
    let bytes = b64(p.slices[0].data_base64.as_bytes());
    assert_eq!(bytes.len() as u64, 40000 - out.retained_from);
    assert!(p.slices[0].eof);
    assert!(bytes.iter().all(|b| *b == b'a'));
    // Slices are capped per response by max_bytes.
    let p = c
        .poll(PollRequest {
            operation_id: "o1".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: out.retained_from,
            }],
            max_bytes: 10,
            wait_ms: 0,
        })
        .await
        .unwrap();
    assert_eq!(b64(p.slices[0].data_base64.as_bytes()).len(), 10);
    assert!(!p.slices[0].eof);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_and_persist_move_files_over_urls_and_check_scope() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let blob = Blob::start().await;
    let payload = b"hello from s3\n".to_vec();
    blob.put("in/data.txt", &payload);
    let sha = hex::encode(sha2::Sha256::digest(&payload));
    let dest = h.workspace.join("input/data.txt");
    let r = c
        .put(PutRequest {
            files: vec![
                PutFile {
                    path: dest.to_string_lossy().into_owned(),
                    source: PutSource::Url {
                        get_url: blob.url("in/data.txt"),
                        bytes: payload.len() as u64,
                        sha256: sha.parse().unwrap(),
                    },
                    mode: Some(0o600),
                },
                PutFile {
                    path: h.workspace.join("note.md").to_string_lossy().into_owned(),
                    source: PutSource::Inline {
                        data_base64: base64::engine::general_purpose::STANDARD.encode(b"# hi\n"),
                    },
                    mode: None,
                },
            ],
        })
        .await
        .unwrap();
    assert_eq!(r.written.len(), 2);
    assert_eq!(std::fs::read(&dest).unwrap(), payload);
    assert_eq!(
        std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::read_to_string(h.workspace.join("note.md")).unwrap(),
        "# hi\n"
    );
    // Checksum mismatch: nothing written.
    let e = c
        .put(PutRequest {
            files: vec![PutFile {
                path: h.workspace.join("bad.txt").to_string_lossy().into_owned(),
                source: PutSource::Url {
                    get_url: blob.url("in/data.txt"),
                    bytes: payload.len() as u64,
                    sha256: "0".repeat(64).parse().unwrap(),
                },
                mode: None,
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::ChecksumMismatch));
    assert!(!h.workspace.join("bad.txt").exists());
    // Outside the sync scope: refused (also through a symlink).
    let e = c
        .put(PutRequest {
            files: vec![PutFile {
                path: "/etc/aex-should-not-exist".into(),
                source: PutSource::Inline {
                    data_base64: "aGk=".into(),
                },
                mode: None,
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::PathOutsideScope));
    std::os::unix::fs::symlink("/etc", h.workspace.join("escape")).unwrap();
    let e = c
        .put(PutRequest {
            files: vec![PutFile {
                path: h
                    .workspace
                    .join("escape/aex-nope")
                    .to_string_lossy()
                    .into_owned(),
                source: PutSource::Inline {
                    data_base64: "aGk=".into(),
                },
                mode: None,
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::PathOutsideScope));

    // persist a path and an operation stream.
    let r = bash(&c, "p1", "echo build-log-line").await;
    assert_eq!(r.view.terminal.unwrap().exit_code, Some(0));
    let pr = c
        .persist(PersistRequest {
            items: vec![
                PersistItem {
                    name: "data.txt".parse().unwrap(),
                    source: PersistSource::Path {
                        path: dest.to_string_lossy().into_owned(),
                    },
                    put_url: blob.url("art/data.txt"),
                    media_type: None,
                },
                PersistItem {
                    name: "build.log".parse().unwrap(),
                    source: PersistSource::OperationStream {
                        operation_id: "p1".parse().unwrap(),
                        stream: Stream::Stdout,
                    },
                    put_url: blob.url("art/build.log"),
                    media_type: Some("text/plain".into()),
                },
            ],
        })
        .await
        .unwrap();
    assert_eq!(pr.persisted[0].bytes, payload.len() as u64);
    assert_eq!(&*pr.persisted[0].sha256, &sha);
    assert_eq!(pr.persisted[0].media_type, "text/plain");
    assert_eq!(blob.get("art/data.txt").unwrap(), payload);
    assert_eq!(blob.get("art/build.log").unwrap(), b"build-log-line\n");
    let e = c
        .persist(PersistRequest {
            items: vec![PersistItem {
                name: "x".parse().unwrap(),
                source: PersistSource::Path {
                    path: "/etc/passwd".into(),
                },
                put_url: blob.url("art/x"),
                media_type: None,
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::PathOutsideScope));
}

/// Snapshot of a tree for byte-for-byte comparison after restore.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    File {
        path: PathBuf,
        content: Vec<u8>,
        mode: u32,
        mtime_ns: i128,
    },
    Dir {
        path: PathBuf,
        mode: u32,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

fn snapshot(root: &Path) -> Vec<Node> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
        let e = e.unwrap();
        let ft = e.file_type();
        let path = e.path().to_path_buf();
        if ft.is_symlink() {
            out.push(Node::Symlink {
                target: std::fs::read_link(&path).unwrap(),
                path,
            });
        } else if ft.is_dir() {
            out.push(Node::Dir {
                mode: e.metadata().unwrap().mode() & 0o7777,
                path,
            });
        } else {
            let md = e.metadata().unwrap();
            let mtime_ns = md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128;
            out.push(Node::File {
                content: std::fs::read(&path).unwrap(),
                mode: md.mode() & 0o7777,
                mtime_ns,
                path,
            });
        }
    }
    out.sort();
    out
}

fn wipe(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() && !p.is_symlink() {
            std::fs::remove_dir_all(&p).unwrap()
        } else {
            std::fs::remove_file(&p).unwrap()
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_then_restore_into_a_fresh_hand_reproduces_the_tree() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let blob = Blob::start().await;
    // Populate: files, nested dirs, an executable, a symlink, an empty dir, a $HOME file, and
    // an excluded cache tree.
    let ws = &h.workspace;
    std::fs::create_dir_all(ws.join("src/deep")).unwrap();
    std::fs::write(ws.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(ws.join("src/deep/lib.rs"), vec![b'z'; 100_000]).unwrap();
    std::fs::write(ws.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(ws.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("src/main.rs", ws.join("latest")).unwrap();
    std::fs::create_dir_all(ws.join("empty")).unwrap();
    std::fs::create_dir_all(ws.join(".cache/pip")).unwrap();
    std::fs::write(ws.join(".cache/pip/big.bin"), vec![1u8; 10_000]).unwrap();
    std::fs::write(h.home.join(".gitconfig"), "[user]\n\tname = agent\n").unwrap();

    let r1 = do_sync(&c, &blob, 1, SyncReason::TurnEnd, false).await;
    assert!(r1.changed);
    assert_eq!(&*r1.manifest_id, "m-1");
    assert_eq!(r1.files_added, 4, "{r1:?}"); // main.rs lib.rs run.sh .gitconfig; latest is a symlink, .cache excluded
    assert_eq!(r1.files_total, 4);
    assert_eq!(r1.packs_referenced, 1);
    assert!(
        r1.bytes_uploaded > 0 && r1.bytes_uploaded < 100_000,
        "zstd should squash the zeros: {}",
        r1.bytes_uploaded
    );
    let manifest_1: brain_protocol::abi::SyncManifest =
        serde_json::from_slice(&blob.get("ses/m-1.json").unwrap()).unwrap();
    assert!(
        manifest_1
            .entries
            .iter()
            .all(|e| !hand_guest::sync::entry_path(e).contains(".cache")),
        "excluded tree must not be in the manifest"
    );

    // Nothing changed: no upload.
    let r2 = do_sync(&c, &blob, 2, SyncReason::Interval, false).await;
    assert!(!r2.changed);
    assert_eq!(&*r2.manifest_id, "m-1");
    assert!(blob.get("ses/m-2.json").is_none());

    // Modify one, delete one, add one, then sync: only those go into the new pack.
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::write(ws.join("src/main.rs"), "fn main() { println!(\"v2\"); }\n").unwrap();
    std::fs::remove_file(ws.join("run.sh")).unwrap();
    std::fs::write(ws.join("NEW.md"), "new\n").unwrap();
    let r3 = do_sync(&c, &blob, 3, SyncReason::TurnEnd, false).await;
    assert!(r3.changed);
    assert_eq!(
        (r3.files_added, r3.files_modified, r3.files_deleted),
        (1, 1, 1),
        "{r3:?}"
    );
    assert_eq!(r3.files_total, 4);
    assert_eq!(
        r3.packs_referenced, 2,
        "old pack still holds lib.rs and .gitconfig"
    );
    let manifest_3: brain_protocol::abi::SyncManifest =
        serde_json::from_slice(&blob.get("ses/m-3.json").unwrap()).unwrap();
    assert_eq!(
        manifest_3.parent_manifest_id.as_deref().map(|s| &**s),
        Some("m-1")
    );

    // Snapshot, wipe (a fresh VM has empty dirs), spawn a fresh generation, restore, compare.
    let before_ws = snapshot(ws);
    let before_home = snapshot(&h.home);
    wipe(ws);
    wipe(&h.home);
    let dir2 = tempfile::tempdir().unwrap();
    let h2 = spawn_hand_at(dir2, ws.clone(), h.home.clone()).await;
    let c2 = HandClient::connect(&format!("ws://{}/", h2.addr), 2)
        .await
        .unwrap();
    let mut req = hello_req(&h2);
    req.restore = Some(RestoreSource {
        manifest_id: "m-3".parse().unwrap(),
        manifest_get_url: blob.url("ses/m-3.json"),
        packs: manifest_3
            .packs
            .iter()
            .map(|p| RestoreSourcePacksItem {
                pack_id: p.pack_id.clone(),
                get_url: blob.url(&format!("ses/{}.tar.zst", *p.pack_id)),
            })
            .collect(),
    });
    let hello = c2.hello(req).await.unwrap();
    let rep = hello.restore.expect("restore report");
    assert_eq!(rep.files, 4);
    assert_eq!(&*rep.manifest_id, "m-3");
    // The excluded cache tree is gone (never synced); everything else is byte-for-byte.
    let after_ws: Vec<Node> = snapshot(ws);
    let expected_ws: Vec<Node> = before_ws
        .into_iter()
        .filter(|n| !node_path(n).to_string_lossy().contains(".cache"))
        .collect();
    assert_eq!(after_ws, expected_ws);
    assert_eq!(snapshot(&h.home), before_home);
    // And the fresh generation considers itself in sync: nothing to upload.
    let r4 = do_sync(&c2, &blob, 4, SyncReason::Interval, false).await;
    assert!(!r4.changed, "{r4:?}");
    // Compaction: full=true repacks everything into one pack.
    let r5 = do_sync(&c2, &blob, 5, SyncReason::Explicit, true).await;
    assert!(r5.changed);
    assert_eq!(r5.packs_referenced, 1);
    assert_eq!(r5.files_total, 4);
}

async fn do_sync(
    c: &HandClient,
    blob: &Blob,
    n: u32,
    reason: SyncReason,
    full: bool,
) -> brain_protocol::abi::SyncResponse {
    c.sync(SyncRequest {
        reason,
        manifest_id: format!("m-{n}").parse().unwrap(),
        manifest_put_url: blob.url(&format!("ses/m-{n}.json")),
        pack_id: format!("p-{n}").parse().unwrap(),
        pack_put_url: blob.url(&format!("ses/p-{n}.tar.zst")),
        full,
    })
    .await
    .unwrap()
}

fn node_path(n: &Node) -> &Path {
    match n {
        Node::File { path, .. } | Node::Dir { path, .. } | Node::Symlink { path, .. } => path,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lane_close_cancels_the_attached_op_but_not_detached_jobs() {
    let h = spawn_hand().await;
    let c = connect(&h).await;
    let lane = LaneRef {
        id: "S1".parse().unwrap(),
        mode: LaneMode::Persistent,
        parent: None,
    };
    // A detached job started from the lane and an attached op holding it.
    c.start(start_request(
        "job",
        "bash",
        json!({"command": "sleep 5; echo survived"}),
        lane.clone(),
        None,
        true,
        0,
        0,
    ))
    .await
    .unwrap();
    let c_att = c
        .start(start_request(
            "att",
            "bash",
            json!({"command": "sleep 30"}),
            lane.clone(),
            None,
            false,
            0,
            0,
        ))
        .await
        .unwrap();
    assert_eq!(c_att.view.status, OperationStatus::Running);
    let e = c
        .start(start_request(
            "att2",
            "bash",
            json!({"command": "true"}),
            lane.clone(),
            None,
            false,
            0,
            0,
        ))
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::LaneBusy));
    let r = c
        .lane_close(LaneCloseRequest {
            lane_id: "S1".parse().unwrap(),
            grace_ms: Some(500),
        })
        .await
        .unwrap();
    assert!(r.closed);
    assert_eq!(
        r.cancelled_operations
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>(),
        ["att"]
    );
    let p = c
        .poll(PollRequest {
            operation_id: "att".parse().unwrap(),
            cursors: vec![],
            max_bytes: 0,
            wait_ms: 5000,
        })
        .await
        .unwrap();
    assert_eq!(p.view.terminal.unwrap().outcome, Outcome::Cancelled);
    let p = c
        .poll(PollRequest {
            operation_id: "job".parse().unwrap(),
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: 0,
            }],
            max_bytes: 100,
            wait_ms: 8000,
        })
        .await
        .unwrap();
    assert_eq!(
        stdout_of(&p.slices),
        "survived
"
    );
    let p = c
        .poll(PollRequest {
            operation_id: "job".parse().unwrap(),
            cursors: vec![],
            max_bytes: 0,
            wait_ms: 3000,
        })
        .await
        .unwrap();
    assert_eq!(
        p.view.terminal.unwrap().outcome,
        Outcome::Completed,
        "detached job outlives its lane"
    );
    let e = c
        .start(start_request(
            "att3",
            "bash",
            json!({"command": "true"}),
            lane,
            None,
            false,
            0,
            0,
        ))
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::LaneGone));
    let e = c
        .lane_close(LaneCloseRequest {
            lane_id: "0".parse().unwrap(),
            grace_ms: None,
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::LaneNotClosable));
    let e = c
        .lane_close(LaneCloseRequest {
            lane_id: "never".parse().unwrap(),
            grace_ms: None,
        })
        .await
        .unwrap_err();
    assert_eq!(abi_code(&e), Some(ErrorCode::LaneGone));
}

use sha2::Digest;
