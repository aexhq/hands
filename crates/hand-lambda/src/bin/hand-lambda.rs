//! Operator CLI for aex hands on AWS Lambda MicroVMs.
//!
//! - `image publish` — pack the guest into a build-context ZIP, upload, register, wait.
//! - `image status` — versions and whether an expiry-driven rebuild is due.
//! - `list` / `get` / `suspend` / `resume` / `terminate` — raw lifecycle.
//! - `e2e` — the slice-2 gate: launch → build → suspend → resume → sync → terminate →
//!   re-materialise from the sync into a fresh VM, byte-for-byte.
//! - `spike` — S2-A burst, S2-B swap, S2-C latency, S2-D imds; JSON records on stdout.

use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use aws_sdk_s3::presigning::PresigningConfig;
use clap::{Parser, Subcommand};
use hand_lambda::REGION;
use hand_lambda::control::Control;
use hand_lambda::image::{self, PublishConfig};
use hand_lambda::launch::{self, Disposition, LaunchedHand};

use aex_contracts::abi::{
    Cursor, HelloRequest, OperationStatus, PollRequest, ProtocolVersion, RestoreSource,
    RestoreSourcePacksItem, Stream, SyncReason, SyncRequest, SyncScope,
};
use base64::Engine as _;
use hand_client::{HandClient, root_lane, start_request};
use serde_json::json;

#[derive(Parser)]
#[command(name = "hand-lambda", about = "aex hands on AWS Lambda MicroVMs")]
struct Cli {
    /// AWS region.
    #[arg(long, default_value = REGION)]
    region: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Image pipeline.
    Image {
        #[command(subcommand)]
        cmd: ImageCmd,
    },
    /// List MicroVMs.
    List,
    /// Describe one MicroVM.
    Get {
        id: String,
    },
    Suspend {
        id: String,
    },
    Resume {
        id: String,
    },
    Terminate {
        id: String,
    },
    /// The slice-2 gate, end to end against real AWS.
    E2e {
        /// Image name or ARN.
        #[arg(long)]
        image: String,
        /// Image version (e.g. `1.0`).
        #[arg(long)]
        version: String,
        /// Bucket for sync manifests/packs (presigned URLs).
        #[arg(long)]
        bucket: String,
    },
    /// Slice-2 spikes. Emits one JSON record per spike on stdout.
    Spike {
        #[arg(long)]
        image: String,
        #[arg(long)]
        version: String,
        /// Which spikes: burst, swap, latency, imds (default: all).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ImageCmd {
    /// Pack + upload + register (create or new version) + wait for AWS's build.
    Publish {
        /// The aarch64-unknown-linux-gnu hand-guest binary.
        #[arg(long)]
        binary: std::path::PathBuf,
        #[arg(long, default_value = "aex-hands-dev-1gb")]
        name: String,
        #[arg(long, default_value_t = 1024)]
        memory_mib: u32,
        #[arg(long)]
        bucket: String,
        #[arg(long)]
        build_role: String,
        #[arg(long, default_value = "/aex/dev/hands/image-build")]
        log_group: String,
    },
    /// Latest version, its base version, and whether a rebuild is due.
    Status {
        #[arg(long, default_value = "aex-hands-dev-1gb")]
        name: String,
    },
    /// Print the generated Dockerfile (what goes into the ZIP).
    Dockerfile,
}

fn main() -> anyhow::Result<()> {
    // The `e2e` subcommand is one long linear async fn; its future is large and is polled by
    // `block_on` on this thread, so give that thread a generous stack instead of the OS default.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("worker thread panicked"))?
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hand_lambda=info".parse()?)
                .add_directive("hand_lambda_bin=info".parse()?),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let control = Control::from_env(&cli.region).await;
    match cli.cmd {
        Cmd::Image { cmd } => image_cmd(&control, &cli.region, cmd).await,
        Cmd::List => {
            for vm in control.list().await? {
                println!("{}\t{:?}", vm.id, vm.state);
            }
            Ok(())
        }
        Cmd::Get { id } => {
            let vm = control.get(&id).await?;
            println!(
                "{}\t{:?}\t{}",
                vm.id,
                vm.state,
                vm.endpoint.unwrap_or_default()
            );
            Ok(())
        }
        Cmd::Suspend { id } => Ok(control.suspend(&id).await?),
        Cmd::Resume { id } => Ok(control.resume(&id).await?),
        Cmd::Terminate { id } => Ok(control.terminate(&id).await?),
        Cmd::E2e {
            image,
            version,
            bucket,
        } => e2e(&control, &cli.region, &image, &version, &bucket).await,
        Cmd::Spike {
            image,
            version,
            only,
        } => spikes(&control, &image, &version, &only).await,
    }
}

async fn image_cmd(control: &Control, region: &str, cmd: ImageCmd) -> anyhow::Result<()> {
    match cmd {
        ImageCmd::Dockerfile => {
            print!("{}", image::dockerfile());
            Ok(())
        }
        ImageCmd::Publish {
            binary,
            name,
            memory_mib,
            bucket,
            build_role,
            log_group,
        } => {
            let bytes =
                std::fs::read(&binary).with_context(|| format!("reading {}", binary.display()))?;
            // An x86 or Windows binary would build fine and then fail at VM boot; catch it here.
            anyhow::ensure!(
                bytes.len() > 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'] && bytes[18] == 0xb7,
                "{} is not an aarch64 ELF binary",
                binary.display()
            );
            let zip = image::pack_zip(&bytes)?;
            tracing::info!(bytes = zip.len(), "context packed");
            let aws = aws_config::from_env()
                .region(aws_config::Region::new(region.to_owned()))
                .load()
                .await;
            let s3 = aws_sdk_s3::Client::new(&aws);
            let cfg = PublishConfig {
                name,
                bucket,
                build_role_arn: build_role,
                log_group,
                memory_mib,
            };
            let out = image::publish(control, &s3, &cfg, zip).await?;
            println!("{}\t{}", out.image_arn, out.image_version);
            Ok(())
        }
        ImageCmd::Status { name } => {
            let Some(arn) = image::find_image_arn(control, &name).await? else {
                bail!("no image named {name}");
            };
            let versions = control
                .sdk()
                .list_microvm_image_versions()
                .image_identifier(&arn)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("list versions: {e}"))?;
            for v in versions.items() {
                println!(
                    "{}\t{:?}\t{:?}\tbase={}",
                    v.image_version(),
                    v.state(),
                    v.status(),
                    v.base_image_version().unwrap_or("?")
                );
                if matches!(
                    v.state(),
                    aws_sdk_lambdamicrovms::types::MicrovmImageVersionState::Successful
                ) {
                    match image::rebuild_due(control, &arn, v.image_version()).await? {
                        Some(newer) => {
                            println!("\trebuild due: managed base has version {newer}");
                        }
                        None => println!("\tbase is current"),
                    }
                    break;
                }
            }
            Ok(())
        }
    }
}

// ----- shared session driving ---------------------------------------------------------------

fn fresh_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn session_id(tag: &str) -> String {
    let mut suffix = String::with_capacity(24);
    suffix.push_str(tag);
    while suffix.len() < 24 {
        suffix.push('0');
    }
    format!("ses_{}", &suffix[..24])
}

fn hello_req(session: &str, token: &str) -> HelloRequest {
    HelloRequest {
        protocol: ProtocolVersion::CURRENT,
        session_id: session.parse().expect("session id"),
        session_token: token.to_owned(),
        expected_generation_id: None,
        tool_manifest_digest: Some(
            aex_contracts::tools::TOOL_MANIFEST_V1_DIGEST
                .trim()
                .parse()
                .expect("digest"),
        ),
        env: Default::default(),
        sync: SyncScope {
            roots: vec!["/workspace".into(), "/home/agent".into()],
            exclude: vec![],
        },
        restore: None,
        heartbeat_ms: 5_000,
    }
}

fn decode(slices: &[aex_contracts::abi::OutputSlice]) -> String {
    let mut out = String::new();
    for s in slices {
        if s.stream == Stream::Stdout {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&s.data_base64)
                .unwrap_or_default();
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    out
}

/// Runs one attached bash command to terminal state and returns (exit_code, stdout).
async fn bash(
    c: &HandClient,
    op: &str,
    command: &str,
    wait_ms: u64,
    max_bytes: u64,
) -> anyhow::Result<(i64, String)> {
    let started = c
        .start(start_request(
            op,
            "bash",
            json!({ "command": command }),
            root_lane(),
            None,
            false,
            wait_ms,
            max_bytes,
        ))
        .await?;
    let mut view = started.view;
    let mut out = decode(&started.slices);
    let mut cursor = out.len() as u64;
    while view.status != OperationStatus::Terminal {
        let p = c
            .poll(PollRequest {
                operation_id: op.parse().expect("op id"),
                cursors: vec![Cursor {
                    stream: Stream::Stdout,
                    offset: cursor,
                }],
                wait_ms: 30_000,
                max_bytes: 262_144,
            })
            .await?;
        let chunk = decode(&p.slices);
        cursor += chunk.len() as u64;
        out.push_str(&chunk);
        view = p.view;
    }
    let exit = view
        .terminal
        .as_ref()
        .and_then(|t| t.exit_code)
        .unwrap_or(-1);
    Ok((exit, out))
}

// ----- e2e ----------------------------------------------------------------------------------

/// One command that fingerprints the durable tree: content hashes, then types/modes/links.
const FINGERPRINT: &str = r#"cd /workspace && find . -type f | LC_ALL=C sort | xargs -r sha256sum && find . \( -type d -o -type l \) -printf '%y %M %p %l\n' | LC_ALL=C sort && cd /home/agent && find . -type f | LC_ALL=C sort | xargs -r sha256sum"#;

#[allow(clippy::too_many_lines)]
async fn e2e(
    control: &Control,
    region: &str,
    image: &str,
    version: &str,
    bucket: &str,
) -> anyhow::Result<()> {
    let image_arn = image::find_image_arn(control, image)
        .await?
        .with_context(|| format!("no image named {image}"))?;
    let aws = aws_config::from_env()
        .region(aws_config::Region::new(region.to_owned()))
        .load()
        .await;
    let s3 = aws_sdk_s3::Client::new(&aws);
    let run = hex::encode(rand::random::<[u8; 4]>());
    let prefix = format!("hands/e2e/{run}");
    let presign_put = |key: String| {
        let s3 = s3.clone();
        let bucket = bucket.to_owned();
        async move {
            anyhow::Ok(
                s3.put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .presigned(PresigningConfig::expires_in(Duration::from_secs(3600))?)
                    .await?
                    .uri()
                    .to_string(),
            )
        }
    };
    let presign_get = |key: String| {
        let s3 = s3.clone();
        let bucket = bucket.to_owned();
        async move {
            anyhow::Ok(
                s3.get_object()
                    .bucket(&bucket)
                    .key(&key)
                    .presigned(PresigningConfig::expires_in(Duration::from_secs(3600))?)
                    .await?
                    .uri()
                    .to_string(),
            )
        }
    };

    let mut timings: Vec<(String, u128)> = Vec::new();
    let mut step = |name: &str, t: Instant| {
        timings.push((name.to_owned(), t.elapsed().as_millis()));
        tracing::info!(step = name, ms = t.elapsed().as_millis() as u64, "done");
    };

    // 1. Launch, arm through the run hook, connect through the endpoint.
    let token = fresh_token();
    let t = Instant::now();
    let hand = launch::launch(
        control,
        &image_arn,
        version,
        &token,
        &format!("aexe2e-{run}-a"),
    )
    .await?;
    step("launch_to_running", t);
    tracing::info!(microvm = %hand.microvm_id, endpoint = %hand.endpoint, "launched");
    let t = Instant::now();
    let c = launch::connect(&hand, 1).await?;
    let hello = c.hello(hello_req(&session_id("e2e"), &token)).await?;
    step("connect_and_hello", t);
    anyhow::ensure!(hello.tools.len() == 7, "sealed manifest served");
    // Keepalive holds the VM up while jobs are live; it is stopped before we choose to suspend
    // (otherwise its own traffic would auto-resume the VM we just suspended).
    let keepalive = launch::Keepalive::spawn(hand.clone(), Duration::from_secs(60));

    // 2. A real build: source written through the tool, compiled and run in the VM.
    let t = Instant::now();
    c.start(start_request(
        "e-src",
        "write",
        json!({"path": "hello.c", "content": "#include <stdio.h>\nint main(void){printf(\"built-in-the-hand\\n\");return 0;}\n"}),
        root_lane(),
        None,
        false,
        10_000,
        0,
    ))
    .await?;
    let (exit, out) = bash(
        &c,
        "e-build",
        "gcc -O2 hello.c -o hello && ./hello && python3 -c 'print(\"py ok\")' && node -e 'console.log(\"node ok\")'",
        30_000,
        65_536,
    )
    .await?;
    anyhow::ensure!(exit == 0, "build failed:\n{out}");
    anyhow::ensure!(
        out.contains("built-in-the-hand"),
        "unexpected build output:\n{out}"
    );
    step("build", t);

    // 3. First sync.
    let t = Instant::now();
    let r1 = c
        .sync(SyncRequest {
            reason: SyncReason::TurnEnd,
            manifest_id: "m-1".parse().expect("id"),
            manifest_put_url: presign_put(format!("{prefix}/m-1.json")).await?,
            pack_id: "p-1".parse().expect("id"),
            pack_put_url: presign_put(format!("{prefix}/p-1.tar.zst")).await?,
            full: false,
        })
        .await?;
    anyhow::ensure!(r1.changed, "first sync must upload");
    step("sync_initial", t);

    // 4. Suspend, then resume via the speculative probe (endpoint-held until /resume).
    drop(keepalive); // stop generating traffic, or the VM auto-resumes under us
    let t = Instant::now();
    control.suspend(&hand.microvm_id).await?;
    launch::wait_for_state(
        control,
        &hand.microvm_id,
        &aws_sdk_lambdamicrovms::types::MicrovmState::Suspended,
        Duration::from_secs(120),
    )
    .await?;
    step("suspend", t);
    // Speculative resume: endpoint traffic to the suspended hand, held until /resume completes.
    // Retries across the brief post-suspend window where the endpoint answers 502.
    let t = Instant::now();
    let http = reqwest::Client::new();
    let probe = launch::resume_via_probe(&http, &hand, Duration::from_secs(120)).await?;
    anyhow::ensure!(probe["service"] == "aex-hand", "probe: {probe}");
    step("probe_resume", t);
    launch::wait_for_state(
        control,
        &hand.microvm_id,
        &aws_sdk_lambdamicrovms::types::MicrovmState::Running,
        Duration::from_secs(60),
    )
    .await?;

    // 5. Reconnect, re-attach (same generation), prove state survived the suspend cycle.
    let t = Instant::now();
    let c = launch::connect(&hand, 2).await?;
    let hello2 = c.hello(hello_req(&session_id("e2e"), &token)).await?;
    anyhow::ensure!(
        hello2.generation_id == hello.generation_id,
        "resume must keep the generation"
    );
    let (exit, out) = bash(&c, "e-post-resume", "./hello", 15_000, 4_096).await?;
    anyhow::ensure!(
        exit == 0 && out.contains("built-in-the-hand"),
        "state lost across suspend/resume:\n{out}"
    );
    step("reconnect_after_resume", t);

    // 6. Change the tree, fingerprint it, final sync.
    c.start(start_request(
        "e-mark",
        "write",
        json!({"path": "state.txt", "content": format!("run {run}\n")}),
        root_lane(),
        None,
        false,
        10_000,
        0,
    ))
    .await?;
    let (_, fingerprint_before) = bash(&c, "e-fp1", FINGERPRINT, 30_000, 262_144).await?;
    let t = Instant::now();
    let r2 = c
        .sync(SyncRequest {
            reason: SyncReason::TurnEnd,
            manifest_id: "m-2".parse().expect("id"),
            manifest_put_url: presign_put(format!("{prefix}/m-2.json")).await?,
            pack_id: "p-2".parse().expect("id"),
            pack_put_url: presign_put(format!("{prefix}/p-2.tar.zst")).await?,
            full: false,
        })
        .await?;
    anyhow::ensure!(r2.changed);
    step("sync_incremental", t);

    // 7. Terminate; confirm the loss is diagnosed as lost, not retried.
    let t = Instant::now();
    control.terminate(&hand.microvm_id).await?;
    launch::wait_for_state(
        control,
        &hand.microvm_id,
        &aws_sdk_lambdamicrovms::types::MicrovmState::Terminated,
        Duration::from_secs(120),
    )
    .await
    .ok(); // Terminated VMs may leave the list; diagnose() is the authority.
    let disposition = launch::diagnose(control, &hand.microvm_id).await;
    anyhow::ensure!(
        matches!(disposition, Disposition::Lost(_)),
        "terminated VM must diagnose as lost, got {disposition:?}"
    );
    step("terminate", t);

    // 8. Re-materialise: fresh VM, fresh generation, restore from the sync, compare bytes.
    let manifest_bytes = s3
        .get_object()
        .bucket(bucket)
        .key(format!("{prefix}/m-2.json"))
        .send()
        .await?
        .body
        .collect()
        .await?
        .into_bytes();
    let manifest: aex_contracts::abi::SyncManifest = serde_json::from_slice(&manifest_bytes)?;
    let mut packs = Vec::new();
    for p in &manifest.packs {
        packs.push(RestoreSourcePacksItem {
            pack_id: p.pack_id.clone(),
            get_url: presign_get(format!("{prefix}/{}.tar.zst", *p.pack_id)).await?,
        });
    }
    let t = Instant::now();
    let token2 = fresh_token();
    let hand2 = launch::launch(
        control,
        &image_arn,
        version,
        &token2,
        &format!("aexe2e-{run}-b"),
    )
    .await?;
    let c2 = launch::connect(&hand2, 1).await?;
    let mut req = hello_req(&session_id("e2e"), &token2);
    req.restore = Some(RestoreSource {
        manifest_id: "m-2".parse().expect("id"),
        manifest_get_url: presign_get(format!("{prefix}/m-2.json")).await?,
        packs,
    });
    let hello3 = c2.hello(req).await?;
    let report = hello3.restore.context("restore report missing")?;
    step("rematerialise", t);
    tracing::info!(files = report.files, "restored");
    let (_, fingerprint_after) = bash(&c2, "e-fp2", FINGERPRINT, 30_000, 262_144).await?;
    anyhow::ensure!(
        fingerprint_before == fingerprint_after,
        "re-materialised tree differs:\n--- before\n{fingerprint_before}\n--- after\n{fingerprint_after}"
    );
    let (exit, out) = bash(&c2, "e-rerun", "./hello", 15_000, 4_096).await?;
    anyhow::ensure!(exit == 0 && out.contains("built-in-the-hand"));
    control.terminate(&hand2.microvm_id).await?;

    println!("E2E PASS");
    for (name, ms) in &timings {
        println!("  {name}: {ms} ms");
    }
    Ok(())
}

// ----- spikes -------------------------------------------------------------------------------

async fn spikes(
    control: &Control,
    image: &str,
    version: &str,
    only: &[String],
) -> anyhow::Result<()> {
    let image_arn = image::find_image_arn(control, image)
        .await?
        .with_context(|| format!("no image named {image}"))?;
    let want = |name: &str| only.is_empty() || only.iter().any(|o| o == name);
    let token = fresh_token();
    let run = hex::encode(rand::random::<[u8; 4]>());
    let hand = launch::launch(
        control,
        &image_arn,
        version,
        &token,
        &format!("aexspk-{run}"),
    )
    .await?;
    let _keepalive = launch::Keepalive::spawn(hand.clone(), Duration::from_secs(60));
    let c = launch::connect(&hand, 1).await?;
    c.hello(hello_req(&session_id("spike"), &token)).await?;
    let mut records = Vec::new();

    if want("imds") {
        records.push(spike_imds(&c).await?);
    }
    if want("swap") {
        records.push(spike_swap(&c).await?);
    }
    if want("latency") {
        records.push(spike_latency(&c, &hand).await?);
    }
    if want("burst") {
        records.push(spike_burst(&c).await?);
    }

    control.terminate(&hand.microvm_id).await?;
    for r in records {
        println!("{}", serde_json::to_string_pretty(&r)?);
    }
    Ok(())
}

/// S2-D: no instance identity reachable from inside the guest.
async fn spike_imds(c: &HandClient) -> anyhow::Result<serde_json::Value> {
    let probes = [
        (
            "imdsv1",
            "curl -s -m 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/; echo \" curl_exit=$?\"",
        ),
        (
            "imdsv2_token",
            "curl -s -m 4 -o /dev/null -w '%{http_code}' -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'; echo \" curl_exit=$?\"",
        ),
        (
            "ecs_creds",
            "curl -s -m 4 -o /dev/null -w '%{http_code}' http://169.254.170.2/v2/credentials/; echo \" curl_exit=$?\"",
        ),
        ("aws_env", "env | grep -iE '^AWS_|_TOKEN=' || echo none"),
        (
            "aws_files",
            "ls -la /root/.aws /home/agent/.aws 2>&1 || true",
        ),
    ];
    let mut out = serde_json::Map::new();
    for (name, cmd) in probes {
        let (exit, stdout) = bash(c, &format!("imds-{name}"), cmd, 20_000, 16_384).await?;
        out.insert(
            name.to_owned(),
            json!({"exit": exit, "output": stdout.trim()}),
        );
    }
    Ok(json!({"spike": "s2-imds", "probes": out}))
}

/// S2-B: is swap on (boot script), and does allocation past baseline survive.
async fn spike_swap(c: &HandClient) -> anyhow::Result<serde_json::Value> {
    let (_, swapon) = bash(
        c,
        "swap-show",
        "swapon --show; grep -i swap /proc/meminfo",
        20_000,
        16_384,
    )
    .await?;
    // Touch 1.5 GiB on a 1 GiB-baseline shape: only burst memory or swap can absorb it.
    let alloc = r#"python3 -c '
import time
t0 = time.monotonic()
chunks = []
for i in range(48):
    chunks.append(bytearray(32 * 1024 * 1024))
    for off in range(0, len(chunks[-1]), 4096):
        chunks[-1][off] = 1
print(f"allocated_mib={(len(chunks)*32)} wall_s={time.monotonic()-t0:.2f}")
'"#;
    let (exit, out) = bash(c, "swap-alloc", alloc, 30_000, 16_384).await?;
    Ok(json!({
        "spike": "s2-swap",
        "swapon_show": swapon.trim(),
        "alloc_1_5_gib": {"exit": exit, "output": out.trim()},
    }))
}

/// S2-C: platform-added latency per tool call through the endpoint.
async fn spike_latency(c: &HandClient, hand: &LaunchedHand) -> anyhow::Result<serde_json::Value> {
    // Warm up.
    for i in 0..3 {
        bash(c, &format!("lat-warm-{i}"), "true", 10_000, 0).await?;
    }
    let mut tool_ms = Vec::with_capacity(100);
    for i in 0..100 {
        let t = Instant::now();
        bash(c, &format!("lat-{i}"), "true", 10_000, 0).await?;
        tool_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    // Raw HTTP round trip through the same endpoint, as the network baseline.
    let http = reqwest::Client::new();
    let mut probe_ms = Vec::with_capacity(30);
    for _ in 0..30 {
        let t = Instant::now();
        launch::probe(&http, hand, Duration::from_secs(15)).await?;
        probe_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(json!({
        "spike": "s2-latency",
        "samples": tool_ms.len(),
        "tool_call_ms": percentiles(&mut tool_ms),
        "http_probe_ms": percentiles(&mut probe_ms),
        "note": "measured from the operator's machine; includes internet RTT to eu-west-1. The probe row is the network+proxy baseline; tool-call minus probe is the in-VM ABI cost.",
    }))
}

/// S2-A: does the 4× CPU burst hold through a 5-minute sustained load.
async fn spike_burst(c: &HandClient) -> anyhow::Result<serde_json::Value> {
    // Two full-tilt workers on a 0.5-vCPU-baseline / 2-vCPU-burst shape, reporting the joint
    // hash rate every 5 s for 6 minutes. If AWS throttles the burst, the curve drops.
    let load = r#"python3 -c '
import hashlib, multiprocessing as mp, time

def worker(q):
    payload = b"x" * 4096
    while True:
        n = 0
        t0 = time.monotonic()
        while time.monotonic() - t0 < 5.0:
            hashlib.sha256(payload)
            n += 1
        q.put(n)

q = mp.Queue()
workers = [mp.Process(target=worker, args=(q,), daemon=True) for _ in range(2)]
for w in workers:
    w.start()
t0 = time.monotonic()
while time.monotonic() - t0 < 360:
    a = q.get()
    b = q.get()
    print(f"t={time.monotonic()-t0:.0f}s rate={(a+b)//5}/s", flush=True)
'"#;
    let started = c
        .start(start_request(
            "burst-load",
            "bash",
            json!({ "command": load }),
            root_lane(),
            None,
            true, // detached: outlives any single poll
            0,
            0,
        ))
        .await?;
    anyhow::ensure!(
        started.view.status != OperationStatus::Terminal || started.view.terminal.is_none()
    );
    let mut cursor = 0u64;
    let mut lines = String::new();
    let deadline = Instant::now() + Duration::from_secs(400);
    loop {
        let p = c
            .poll(PollRequest {
                operation_id: "burst-load".parse().expect("id"),
                cursors: vec![Cursor {
                    stream: Stream::Stdout,
                    offset: cursor,
                }],
                wait_ms: 25_000,
                max_bytes: 65_536,
            })
            .await?;
        let chunk = decode(&p.slices);
        cursor += chunk.len() as u64;
        lines.push_str(&chunk);
        if p.view.status == OperationStatus::Terminal || Instant::now() > deadline {
            break;
        }
    }
    // Cancel the load (it loops forever by design).
    let _ = c
        .cancel(aex_contracts::abi::CancelRequest {
            operation_id: "burst-load".parse().expect("id"),
            grace_ms: Some(1000),
        })
        .await;
    let rates: Vec<u64> = lines
        .lines()
        .filter_map(|l| l.split("rate=").nth(1))
        .filter_map(|r| r.trim_end_matches("/s").parse().ok())
        .collect();
    anyhow::ensure!(rates.len() >= 30, "too few samples:\n{lines}");
    let first_min: u64 = rates[..12].iter().sum::<u64>() / 12;
    let last_min: u64 = rates[rates.len() - 12..].iter().sum::<u64>() / 12;
    Ok(json!({
        "spike": "s2-burst",
        "samples": rates.len(),
        "first_minute_rate_per_s": first_min,
        "last_minute_rate_per_s": last_min,
        "sustained_fraction": (last_min as f64) / (first_min as f64),
        "series": rates,
    }))
}

fn percentiles(samples: &mut [f64]) -> serde_json::Value {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let at = |p: f64| samples[((samples.len() as f64 - 1.0) * p) as usize];
    json!({
        "p50": format!("{:.1}", at(0.50)),
        "p95": format!("{:.1}", at(0.95)),
        "p99": format!("{:.1}", at(0.99)),
        "min": format!("{:.1}", samples[0]),
        "max": format!("{:.1}", samples[samples.len() - 1]),
    })
}
