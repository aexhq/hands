//! Explicit live-image proofs for provider behavior and the direct-public connector boundary.

use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, bail, ensure};
use aws_sdk_lambdamicrovms::types::MicrovmState;
use brain_protocol::contract::{HAND_CONTRACT_DIGEST, sandbox_execution_request_digest};
use brain_protocol::hand::{
    NetworkCeiling, ObserveRequest, SandboxExecutionRequest, TerminalOutcome,
};
use futures_util::{SinkExt as _, StreamExt as _};
use hand_core::connector::{ConnectorClass, ConnectorRef, GatewayAuthority};
use hand_core::materialization::ControlToken;
use hand_wire::{
    AllowlistProxy, RequestCall, RequestFrame, ResponseFrame, ResponseReply, RunPayload,
};
use tokio_tungstenite::tungstenite::Message;

use crate::control::{AUTH_HEADER, Control, ControlError, Microvm, is_terminated};
use crate::launch::{self, GuestConnectError, LaunchedHand};

const CANARY_LIFETIME_MS: u64 = 10 * 60 * 1_000;
const STATE_TIMEOUT: Duration = Duration::from_secs(120);
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const REQUIRED_CONSECUTIVE_502: usize = 3;

pub struct NoRespawnCanaryConfig {
    pub image_arn: String,
    pub image_version: String,
    pub none_connector: ConnectorRef,
}

pub struct NetworkBoundaryCanaryConfig {
    pub image_arn: String,
    pub image_version: String,
    pub none_connector: ConnectorRef,
    pub allowlist_connector: ConnectorRef,
    pub public_connector: ConnectorRef,
    pub gateway_authority: GatewayAuthority,
    pub customer_hand_hosts: [String; 2],
}

/// Exercises every deployed connector class against the same exact image version. Restricted
/// connector targets run and terminate sequentially so the dev plane's one-GiB admission budget
/// is never exceeded.
pub async fn run_network_boundary_canary(
    control: &Control,
    cfg: NetworkBoundaryCanaryConfig,
) -> anyhow::Result<()> {
    run_restricted_network_canary(
        control,
        &cfg.image_arn,
        &cfg.image_version,
        cfg.none_connector,
        &cfg.gateway_authority,
        ConnectorClass::None,
    )
    .await?;
    run_restricted_network_canary(
        control,
        &cfg.image_arn,
        &cfg.image_version,
        cfg.allowlist_connector,
        &cfg.gateway_authority,
        ConnectorClass::Allowlist,
    )
    .await?;
    run_public_network_canary(
        control,
        PublicNetworkCanaryConfig {
            image_arn: cfg.image_arn,
            image_version: cfg.image_version,
            public_connector: cfg.public_connector,
            customer_hand_hosts: cfg.customer_hand_hosts,
        },
    )
    .await
}

struct PublicNetworkCanaryConfig {
    image_arn: String,
    image_version: String,
    public_connector: ConnectorRef,
    customer_hand_hosts: [String; 2],
}

struct KnownTargetSeal {
    target_id: String,
    generation: String,
    root_id: String,
    session_id: String,
    operation_id: String,
    control_token: ControlToken,
}

async fn run_restricted_network_canary(
    control: &Control,
    image_arn: &str,
    image_version: &str,
    connector: ConnectorRef,
    gateway: &GatewayAuthority,
    class: ConnectorClass,
) -> anyhow::Result<()> {
    ensure!(
        matches!(class, ConnectorClass::None | ConnectorClass::Allowlist),
        "restricted network canary requires none or allowlist"
    );
    let label = match class {
        ConnectorClass::None => "none",
        ConnectorClass::Allowlist => "allowlist",
        ConnectorClass::Public => unreachable!("validated restricted connector class"),
    };
    let nonce = hex::encode(rand::random::<[u8; 12]>());
    let operation_id = format!("{label}-network-canary-{nonce}");
    let generation = format!("{label}-network-generation-{nonce}");
    let root_id = format!("{label}-network-root-{nonce}");
    let session_id = format!("{label}-network-session-{nonce}");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis() as u64;
    let network = match class {
        ConnectorClass::None => NetworkCeiling::None,
        ConnectorClass::Allowlist => serde_json::from_value(serde_json::json!({
            "kind": "allowlist",
            "destinations": [{
                "protocol": "tls",
                "host": "example.com",
                "ports": [443]
            }]
        }))?,
        ConnectorClass::Public => unreachable!("validated restricted connector class"),
    };
    // The release gate intentionally has no KMS signing authority. A syntactically harmless,
    // invalid grant lets the guest configure its ordinary proxy environment while proving that
    // the gateway itself rejects missing and invalid authentication.
    let allowlist_proxy = matches!(class, ConnectorClass::Allowlist).then(|| AllowlistProxy {
        authority: gateway.as_authority(),
        capability: "invalid-release-canary-capability".into(),
    });
    let control_token = canary_control_token();
    let payload = RunPayload {
        contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
        generation: generation.clone(),
        expires_at_ms: now_ms.saturating_add(CANARY_LIFETIME_MS),
        root_id: root_id.clone(),
        owner_session_id: session_id.clone(),
        connector: class,
        resource_class: "microvm-1gb".into(),
        resources: serde_json::from_value(serde_json::json!({
            "max_output_bytes": 4_096,
            "timeout_ms": 30_000
        }))?,
        network,
        control_token: control_token.clone(),
        allowlist_proxy,
        canary_exit_after_operation_id: None,
    };
    let vm = launch_canary_target(
        control,
        image_arn,
        image_version,
        &serde_json::to_string(&payload)?,
        &format!("hands-{operation_id}"),
        &connector,
    )
    .await
    .with_context(|| format!("launching the {label} connector canary"))?;
    let target = KnownTargetSeal {
        target_id: vm.id,
        generation,
        root_id,
        session_id,
        operation_id,
        control_token,
    };
    let result = run_restricted_network_on_known_target(control, &target, gateway, class).await;
    let cleanup = terminate_known_target(control, &target.target_id).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(canary), Ok(())) => Err(canary),
        (Ok(()), Err(cleanup)) => {
            Err(cleanup.context(format!("{label} canary passed but target cleanup failed")))
        }
        (Err(canary), Err(cleanup)) => {
            Err(canary.context(format!("{label} target cleanup also failed: {cleanup:#}")))
        }
    }
}

async fn run_restricted_network_on_known_target(
    control: &Control,
    target: &KnownTargetSeal,
    gateway: &GatewayAuthority,
    class: ConnectorClass,
) -> anyhow::Result<()> {
    let vm = launch::wait_for_state(
        control,
        &target.target_id,
        &MicrovmState::Running,
        STATE_TIMEOUT,
    )
    .await?;
    let endpoint = vm
        .endpoint
        .context("restricted network canary target has no endpoint")?;
    let hand = LaunchedHand {
        microvm_id: target.target_id.clone(),
        endpoint: launch::normalise_endpoint(&endpoint),
        auth_token: control.auth_token(&target.target_id).await?,
        control_token: target.control_token.clone(),
    };
    let request = restricted_network_execution(
        &target.operation_id,
        &target.generation,
        &target.root_id,
        &target.session_id,
        gateway,
        class,
    )?;
    let mut socket = launch::connect(&hand)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    let mut request_number = 1u64;
    let receipt = match call(
        &mut socket,
        &mut request_number,
        RequestCall::ExecuteSandbox(request),
    )
    .await?
    {
        ResponseReply::ExecuteSandbox(receipt) => receipt,
        _ => bail!("restricted network canary execute returned the wrong response variant"),
    };
    let observe: ObserveRequest = serde_json::from_value(serde_json::json!({
        "cursor": "0",
        "operation": receipt.operation,
        "wait_ms": 30_000
    }))?;
    let observation = match call(
        &mut socket,
        &mut request_number,
        RequestCall::Observe(observe),
    )
    .await?
    {
        ResponseReply::Observe(observation) => observation,
        _ => bail!("restricted network canary observe returned the wrong response variant"),
    };
    let terminal = observation
        .terminal
        .context("restricted network canary did not reach a terminal receipt")?;
    ensure!(
        terminal.outcome == TerminalOutcome::Completed,
        "restricted network canary command failed"
    );
    let stdout = terminal
        .inline
        .as_ref()
        .and_then(|value| value.get("stdout"))
        .and_then(|value| value.as_str())
        .context("restricted network canary returned no stdout")?;
    let label = match class {
        ConnectorClass::None => "none",
        ConnectorClass::Allowlist => "allowlist",
        ConnectorClass::Public => unreachable!("validated restricted connector class"),
    };
    ensure!(
        stdout.starts_with(&format!("restricted_network_canary=ok class={label} ")),
        "restricted network canary returned an unexpected result"
    );
    Ok(())
}

/// Exercises the canonical IPv4 special-use fixtures from inside one exact immutable image.
/// Terraform's exact NACL plan is the authoritative rule proof; connection failures here are only
/// behavioral coverage because an unroutable destination does not identify which layer rejected
/// it. Canonical public controls prevent a completely broken connector from producing a pass.
async fn run_public_network_canary(
    control: &Control,
    cfg: PublicNetworkCanaryConfig,
) -> anyhow::Result<()> {
    validate_customer_hand_hosts(&cfg.customer_hand_hosts)?;
    let nonce = hex::encode(rand::random::<[u8; 12]>());
    let operation_id = format!("network-canary-{nonce}");
    let generation = format!("network-canary-generation-{nonce}");
    let root_id = format!("network-canary-root-{nonce}");
    let session_id = format!("network-canary-session-{nonce}");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis() as u64;
    let control_token = canary_control_token();
    let payload = RunPayload {
        contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
        generation: generation.clone(),
        expires_at_ms: now_ms.saturating_add(CANARY_LIFETIME_MS),
        root_id: root_id.clone(),
        owner_session_id: session_id.clone(),
        connector: ConnectorClass::Public,
        resource_class: "microvm-1gb".into(),
        resources: serde_json::from_value(serde_json::json!({
            "max_output_bytes": 4_096,
            "timeout_ms": 30_000
        }))?,
        network: NetworkCeiling::Public,
        control_token: control_token.clone(),
        allowlist_proxy: None,
        canary_exit_after_operation_id: None,
    };
    let vm = launch_canary_target(
        control,
        &cfg.image_arn,
        &cfg.image_version,
        &serde_json::to_string(&payload)?,
        &format!("hands-{operation_id}"),
        &cfg.public_connector,
    )
    .await
    .context("launching the direct-public network canary")?;
    let target = KnownTargetSeal {
        target_id: vm.id,
        generation,
        root_id,
        session_id,
        operation_id,
        control_token,
    };
    let result =
        run_public_network_on_known_target(control, &target, &cfg.customer_hand_hosts).await;
    let cleanup = terminate_known_target(control, &target.target_id).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(canary), Ok(())) => Err(canary),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("canary passed but target cleanup failed")),
        (Err(canary), Err(cleanup)) => {
            Err(canary.context(format!("target cleanup also failed: {cleanup:#}")))
        }
    }
}

async fn run_public_network_on_known_target(
    control: &Control,
    target: &KnownTargetSeal,
    customer_hand_hosts: &[String; 2],
) -> anyhow::Result<()> {
    let vm = launch::wait_for_state(
        control,
        &target.target_id,
        &MicrovmState::Running,
        STATE_TIMEOUT,
    )
    .await?;
    let endpoint = vm
        .endpoint
        .context("network canary target has no endpoint")?;
    let hand = LaunchedHand {
        microvm_id: target.target_id.clone(),
        endpoint: launch::normalise_endpoint(&endpoint),
        auth_token: control.auth_token(&target.target_id).await?,
        control_token: target.control_token.clone(),
    };
    let request = public_network_execution(
        &target.operation_id,
        &target.generation,
        &target.root_id,
        &target.session_id,
        customer_hand_hosts,
    )?;
    let mut socket = launch::connect(&hand)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    let mut request_number = 1u64;
    let receipt = match call(
        &mut socket,
        &mut request_number,
        RequestCall::ExecuteSandbox(request),
    )
    .await?
    {
        ResponseReply::ExecuteSandbox(receipt) => receipt,
        _ => bail!("network canary execute returned the wrong response variant"),
    };
    let observe: ObserveRequest = serde_json::from_value(serde_json::json!({
        "cursor": "0",
        "operation": receipt.operation,
        "wait_ms": 30_000
    }))?;
    let observation = match call(
        &mut socket,
        &mut request_number,
        RequestCall::Observe(observe),
    )
    .await?
    {
        ResponseReply::Observe(observation) => observation,
        _ => bail!("network canary observe returned the wrong response variant"),
    };
    let terminal = observation
        .terminal
        .context("network canary did not reach a terminal receipt")?;
    ensure!(
        terminal.outcome == TerminalOutcome::Completed,
        "network canary command failed"
    );
    let stdout = terminal
        .inline
        .as_ref()
        .and_then(|value| value.get("stdout"))
        .and_then(|value| value.as_str())
        .context("network canary returned no stdout")?;
    ensure!(
        stdout.starts_with("network_canary=ok "),
        "network canary returned an unexpected result"
    );
    Ok(())
}

/// Runs against one exact immutable image version. This is deliberately separate from normal
/// construction: every production `RunPayload` sets the canary field to `None`.
pub async fn run_no_respawn_canary(
    control: &Control,
    http: &reqwest::Client,
    cfg: NoRespawnCanaryConfig,
) -> anyhow::Result<()> {
    let nonce = hex::encode(rand::random::<[u8; 12]>());
    let operation_id = format!("image-canary-{nonce}");
    let generation = format!("image-canary-generation-{nonce}");
    let root_id = format!("image-canary-root-{nonce}");
    let session_id = format!("image-canary-session-{nonce}");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis() as u64;
    let control_token = canary_control_token();
    let payload = RunPayload {
        contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
        generation: generation.clone(),
        expires_at_ms: now_ms.saturating_add(CANARY_LIFETIME_MS),
        root_id: root_id.clone(),
        owner_session_id: session_id.clone(),
        connector: ConnectorClass::None,
        resource_class: "microvm-1gb".into(),
        resources: serde_json::from_value(serde_json::json!({
            "max_output_bytes": 4_096,
            "timeout_ms": 30_000
        }))?,
        network: NetworkCeiling::None,
        control_token: control_token.clone(),
        allowlist_proxy: None,
        canary_exit_after_operation_id: Some(operation_id.clone()),
    };
    let vm = launch_canary_target(
        control,
        &cfg.image_arn,
        &cfg.image_version,
        &serde_json::to_string(&payload)?,
        &format!("hands-{operation_id}"),
        &cfg.none_connector,
    )
    .await
    .context("launching the no-respawn image canary")?;
    let target = KnownTargetSeal {
        target_id: vm.id,
        generation,
        root_id,
        session_id,
        operation_id,
        control_token,
    };
    let result = run_on_known_target(control, http, &target).await;
    let cleanup = terminate_known_target(control, &target.target_id).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(canary), Ok(())) => Err(canary),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("canary passed but target cleanup failed")),
        (Err(canary), Err(cleanup)) => {
            Err(canary.context(format!("target cleanup also failed: {cleanup:#}")))
        }
    }
}

async fn run_on_known_target(
    control: &Control,
    http: &reqwest::Client,
    target: &KnownTargetSeal,
) -> anyhow::Result<()> {
    let vm = launch::wait_for_state(
        control,
        &target.target_id,
        &MicrovmState::Running,
        STATE_TIMEOUT,
    )
    .await?;
    let endpoint = vm.endpoint.context("canary target has no endpoint")?;
    let mut hand = LaunchedHand {
        microvm_id: target.target_id.clone(),
        endpoint: launch::normalise_endpoint(&endpoint),
        auth_token: control.auth_token(&target.target_id).await?,
        control_token: target.control_token.clone(),
    };
    let request = canary_execution(
        &target.operation_id,
        &target.generation,
        &target.root_id,
        &target.session_id,
    )?;
    let mut socket = launch::connect(&hand)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    let mut request_number = 1u64;
    let receipt = match call(
        &mut socket,
        &mut request_number,
        RequestCall::ExecuteSandbox(request.clone()),
    )
    .await?
    {
        ResponseReply::ExecuteSandbox(receipt) => receipt,
        _ => bail!("canary execute returned the wrong response variant"),
    };
    let observe: ObserveRequest = serde_json::from_value(serde_json::json!({
        "cursor": "0",
        "operation": receipt.operation,
        "wait_ms": 30_000
    }))?;
    let observation = match call(
        &mut socket,
        &mut request_number,
        RequestCall::Observe(observe),
    )
    .await?
    {
        ResponseReply::Observe(observation) => observation,
        _ => bail!("canary observe returned the wrong response variant"),
    };
    let terminal = observation
        .terminal
        .context("canary effect did not reach a terminal receipt")?;
    let diagnostic = terminal
        .inline
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|value| value.as_str())
        .unwrap_or("no error detail");
    ensure!(
        terminal.outcome == TerminalOutcome::Completed,
        "canary marker effect ended as {} with exit code {:?}: {diagnostic}",
        terminal.outcome,
        terminal.exit_code
    );
    ensure!(
        terminal
            .inline
            .as_ref()
            .and_then(|value| value.get("stdout"))
            .and_then(|value| value.as_str())
            == Some("marker_count=1\n"),
        "canary marker was not written exactly once before the crash"
    );
    drop(socket);

    assert_persistent_502(control, http, &hand, "after deliberate crash").await?;
    transition_and_wait(control, &target.target_id, MicrovmState::Suspended).await?;
    transition_and_wait(control, &target.target_id, MicrovmState::Running).await?;
    hand.auth_token = control.auth_token(&target.target_id).await?;
    assert_persistent_502(control, http, &hand, "after suspend/resume").await?;

    // Attempt the exact operation/digest again. Persistent provider 502 must prevent transport
    // admission, which is the physical proof that the already-one-line marker cannot gain a
    // second line. Any successful handshake is a re-arm and blocks image promotion immediately.
    match launch::connect(&hand).await {
        Err(GuestConnectError::Http(502)) => {}
        Err(error) => bail!("exact replay did not receive the expected endpoint 502: {error}"),
        Ok(mut socket) => {
            let _ = call(
                &mut socket,
                &mut request_number,
                RequestCall::ExecuteSandbox(request.clone()),
            )
            .await;
            bail!("physical generation accepted an exact replay after supervisor loss")
        }
    }
    Ok(())
}

fn canary_execution(
    operation_id: &str,
    generation: &str,
    root_id: &str,
    session_id: &str,
) -> anyhow::Result<SandboxExecutionRequest> {
    let mut request: SandboxExecutionRequest = serde_json::from_value(serde_json::json!({
        "execution_id": operation_id,
        "expected_generation": generation,
        "input": {
            "command": "printf 'marker\\n' >> /workspace/image-canary-effect; sync /workspace/image-canary-effect; printf 'marker_count=%s\\n' \"$(wc -l < /workspace/image-canary-effect)\"",
            "cwd": "/workspace",
            "interactive": false
        },
        "network": {"kind": "none"},
        "request_digest": "0".repeat(64),
        "resources": {"max_output_bytes": 4_096, "timeout_ms": 30_000},
        "target": {
            "binding_ref": "image-canary-binding",
            "kind": "additional",
            "root_id": root_id,
            "sandbox_id": "image-canary-sandbox",
            "session_id": session_id
        }
    }))?;
    request.request_digest = sandbox_execution_request_digest(&request);
    Ok(request)
}

fn restricted_network_execution(
    operation_id: &str,
    generation: &str,
    root_id: &str,
    session_id: &str,
    gateway: &GatewayAuthority,
    class: ConnectorClass,
) -> anyhow::Result<SandboxExecutionRequest> {
    ensure!(
        gateway.host().parse::<Ipv4Addr>().is_ok(),
        "release canary requires the platform's fixed IPv4 gateway authority"
    );
    let denied: Vec<&str> = brain_protocol::network::SPECIAL_USE_FIXTURES
        .iter()
        .filter_map(|&(address, _)| address.parse::<Ipv4Addr>().ok().map(|_| address))
        .filter(|address| *address != gateway.host())
        .collect();
    let controls: Vec<&str> = brain_protocol::network::PUBLIC_UNICAST_FIXTURES
        .iter()
        .copied()
        .filter(|address| address.parse::<Ipv4Addr>().is_ok())
        .collect();
    ensure!(!denied.is_empty(), "canonical denied fixture set is empty");
    ensure!(
        !controls.is_empty(),
        "canonical public control set is empty"
    );
    let (label, network, require_gateway) = match class {
        ConnectorClass::None => ("none", serde_json::json!({"kind": "none"}), false),
        ConnectorClass::Allowlist => (
            "allowlist",
            serde_json::json!({
                "kind": "allowlist",
                "destinations": [{
                    "protocol": "tls",
                    "host": "example.com",
                    "ports": [443]
                }]
            }),
            true,
        ),
        ConnectorClass::Public => bail!("restricted network canary cannot use public"),
    };

    let command = r#"node --input-type=module <<'AEX_RESTRICTED_NETWORK_CANARY'
import dns from "node:dns";
import net from "node:net";

const connectorClass = __CLASS__;
const denied = __DENIED__;
const controls = __CONTROLS__;
const gateway = __GATEWAY__;
const requireGateway = __REQUIRE_GATEWAY__;

function probe(host, port) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ host, port });
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(reachable);
    };
    const timer = setTimeout(() => finish(false), 1500);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

function dnsOutcome(host) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    const timer = setTimeout(() => finish("timeout"), 3000);
    dns.lookup(host, (error) => finish(error ? "blocked" : "resolved"));
  });
}

function gatewayStatus(request) {
  return new Promise((resolve) => {
    let settled = false;
    let response = "";
    const socket = net.connect({ host: gateway.host, port: gateway.port });
    const finish = (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(status);
    };
    const timer = setTimeout(() => finish(null), 3000);
    socket.once("connect", () => socket.write(request));
    socket.on("data", (chunk) => {
      response += chunk.toString("ascii");
      const lineEnd = response.indexOf("\r\n");
      if (lineEnd === -1) return;
      const match = /^HTTP\/1\.1 ([0-9]{3}) /.exec(response.slice(0, lineEnd));
      finish(match ? Number(match[1]) : null);
    });
    socket.once("error", () => finish(null));
    socket.once("end", () => finish(null));
  });
}

const dnsState = await dnsOutcome("example.com");
if (dnsState !== "blocked") {
  throw new Error(`restricted connector DNS was not fail-closed: ${dnsState}`);
}

const directHosts = [...new Set([...denied, ...controls])];
if (!requireGateway) directHosts.push(gateway.host);
const directResults = await Promise.all(directHosts.map(async (host) => [
  host,
  (await Promise.all([53, 80, 443, 8443].map((port) => probe(host, port)))).some(Boolean),
]));
const reachableDirect = directResults.filter(([, reachable]) => reachable).map(([host]) => host);
if (reachableDirect.length !== 0) {
  throw new Error(`restricted connector accepted direct TCP: ${reachableDirect.join(",")}`);
}

if (requireGateway) {
  const health = await gatewayStatus(
    `GET /healthz HTTP/1.1\r\nHost: ${gateway.host}\r\nConnection: close\r\n\r\n`,
  );
  if (health !== 200) throw new Error(`allowlist gateway health was not reachable: ${health}`);
  const unauthenticated = await gatewayStatus(
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n",
  );
  if (unauthenticated !== 407) {
    throw new Error(`allowlist gateway accepted or misclassified missing auth: ${unauthenticated}`);
  }
  const invalid = await gatewayStatus(
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer invalid-release-canary-capability\r\nConnection: close\r\n\r\n",
  );
  if (invalid !== 403) {
    throw new Error(`allowlist gateway accepted or misclassified invalid auth: ${invalid}`);
  }
}

process.stdout.write(`restricted_network_canary=ok class=${connectorClass} denied=${denied.length} controls=${controls.length}\n`);
AEX_RESTRICTED_NETWORK_CANARY"#
        .replace("__CLASS__", &serde_json::to_string(label)?)
        .replace("__DENIED__", &serde_json::to_string(&denied)?)
        .replace("__CONTROLS__", &serde_json::to_string(&controls)?)
        .replace(
            "__GATEWAY__",
            &serde_json::to_string(&serde_json::json!({
                "host": gateway.host(),
                "port": gateway.port().get()
            }))?,
        )
        .replace(
            "__REQUIRE_GATEWAY__",
            if require_gateway { "true" } else { "false" },
        );
    let mut request: SandboxExecutionRequest = serde_json::from_value(serde_json::json!({
        "execution_id": operation_id,
        "expected_generation": generation,
        "input": {
            "command": command,
            "cwd": "/workspace",
            "interactive": false
        },
        "network": network,
        "request_digest": "0".repeat(64),
        "resources": {"max_output_bytes": 4_096, "timeout_ms": 30_000},
        "target": {
            "binding_ref": format!("{label}-network-canary-binding"),
            "kind": "additional",
            "root_id": root_id,
            "sandbox_id": format!("{label}-network-canary-sandbox"),
            "session_id": session_id
        }
    }))?;
    request.request_digest = sandbox_execution_request_digest(&request);
    Ok(request)
}

fn public_network_execution(
    operation_id: &str,
    generation: &str,
    root_id: &str,
    session_id: &str,
    customer_hand_hosts: &[String; 2],
) -> anyhow::Result<SandboxExecutionRequest> {
    let denied: Vec<&str> = brain_protocol::network::SPECIAL_USE_FIXTURES
        .iter()
        .filter_map(|&(address, _)| address.parse::<Ipv4Addr>().ok().map(|_| address))
        .collect();
    let controls: Vec<&str> = brain_protocol::network::PUBLIC_UNICAST_FIXTURES
        .iter()
        .copied()
        .filter(|address| address.parse::<Ipv4Addr>().is_ok())
        .collect();
    ensure!(!denied.is_empty(), "canonical denied fixture set is empty");
    ensure!(
        !controls.is_empty(),
        "canonical public control set is empty"
    );
    validate_customer_hand_hosts(customer_hand_hosts)?;
    let http_surfaces = [
        serde_json::json!({"host": "aex.dev", "path": "/"}),
        serde_json::json!({"host": "api.aex.dev", "path": "/v1/rates"}),
        serde_json::json!({"host": "api-dev.aex.dev", "path": "/v1/rates"}),
    ];

    let command = r#"node --input-type=module <<'AEX_NETWORK_CANARY'
import http from "node:http";
import https from "node:https";
import net from "node:net";

const denied = __DENIED__;
const controls = __CONTROLS__;
const httpSurfaces = __HTTP_SURFACES__;
const customerHandHosts = __CUSTOMER_HAND_HOSTS__;

function probe(host, port) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ host, port });
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(reachable);
    };
    const timer = setTimeout(() => finish(false), 1500);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

async function anyReachable(host, ports) {
  const outcomes = await Promise.all(ports.map((port) => probe(host, port)));
  return outcomes.some(Boolean);
}

function requestStatus(module, options) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(status);
    };
    const request = module.request(options);
    const timer = setTimeout(() => {
      request.destroy();
      finish(null);
    }, 3000);
    request.once("response", (response) => {
      response.resume();
      finish(response.statusCode ?? null);
    });
    request.once("upgrade", (response, socket) => {
      socket.destroy();
      finish(response.statusCode ?? 101);
    });
    request.once("error", () => finish(null));
    request.end();
  });
}

const specialResults = await Promise.all(
  denied.map(async (host) => [host, await anyReachable(host, [80, 443])]),
);
const reachableSpecial = specialResults.filter(([, reachable]) => reachable).map(([host]) => host);
if (reachableSpecial.length !== 0) {
  throw new Error(`special-use destinations accepted TCP: ${reachableSpecial.join(",")}`);
}

const controlResults = await Promise.all(
  controls.map(async (host) => [host, await anyReachable(host, [53, 80, 443])]),
);
const unreachableControls = controlResults.filter(([, reachable]) => !reachable).map(([host]) => host);
if (unreachableControls.length !== 0) {
  throw new Error(`public controls were unreachable: ${unreachableControls.join(",")}`);
}

const httpSurfaceResults = await Promise.all(httpSurfaces.map(async (surface) => ({
  surface,
  statuses: await Promise.all([
    requestStatus(http, { hostname: surface.host, path: surface.path, port: 80, method: "GET" }),
    requestStatus(https, { hostname: surface.host, path: surface.path, port: 443, method: "GET" }),
  ]),
})));
for (const { surface, statuses } of httpSurfaceResults) {
  for (const status of statuses) {
    if (status !== 403) {
      throw new Error(`Aex surface did not return the expected source denial: ${surface.host}`);
    }
  }
}

const customerHandResults = await Promise.all(customerHandHosts.map(async (host) => ({
  host,
  websocketStatus: await requestStatus(https, {
    hostname: host,
    path: "/v1",
    port: 443,
    method: "GET",
    headers: {
      Connection: "Upgrade",
      Upgrade: "websocket",
      "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
      "Sec-WebSocket-Version": "13",
    },
  }),
  managementStatus: await requestStatus(https, {
    hostname: host,
    path: "/v1/@connections/aex-network-canary",
    port: 443,
    method: "POST",
    headers: { "Content-Length": "0" },
  }),
})));
for (const { host, websocketStatus, managementStatus } of customerHandResults) {
  if (websocketStatus !== 401 && websocketStatus !== 403) {
    throw new Error(`customer Hand WebSocket did not return an authentication denial: ${host}`);
  }
  if (managementStatus !== 401 && managementStatus !== 403) {
    throw new Error(`customer Hand Management API did not return an authentication denial: ${host}`);
  }
}

process.stdout.write(`network_canary=ok denied=${denied.length} controls=${controls.length} surfaces=${httpSurfaces.length + customerHandHosts.length}\n`);
AEX_NETWORK_CANARY"#
        .replace("__DENIED__", &serde_json::to_string(&denied)?)
        .replace("__CONTROLS__", &serde_json::to_string(&controls)?)
        .replace(
            "__HTTP_SURFACES__",
            &serde_json::to_string(&http_surfaces)?,
        )
        .replace(
            "__CUSTOMER_HAND_HOSTS__",
            &serde_json::to_string(customer_hand_hosts)?,
        );
    let mut request: SandboxExecutionRequest = serde_json::from_value(serde_json::json!({
        "execution_id": operation_id,
        "expected_generation": generation,
        "input": {
            "command": command,
            "cwd": "/workspace",
            "interactive": false
        },
        "network": {"kind": "public"},
        "request_digest": "0".repeat(64),
        "resources": {"max_output_bytes": 4_096, "timeout_ms": 30_000},
        "target": {
            "binding_ref": "network-canary-binding",
            "kind": "additional",
            "root_id": root_id,
            "sandbox_id": "network-canary-sandbox",
            "session_id": session_id
        }
    }))?;
    request.request_digest = sandbox_execution_request_digest(&request);
    Ok(request)
}

fn validate_customer_hand_hosts(hosts: &[String; 2]) -> anyhow::Result<()> {
    ensure!(hosts[0] != hosts[1], "customer Hand hosts must be distinct");
    for host in hosts {
        ensure!(
            host.len() <= 253
                && host == host.trim()
                && host.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
                && host.ends_with(".execute-api.us-east-1.amazonaws.com")
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                }),
            "invalid customer Hand API Gateway host"
        );
    }
    Ok(())
}

async fn call(
    socket: &mut launch::GuestSocket,
    request_number: &mut u64,
    call: RequestCall,
) -> anyhow::Result<ResponseReply> {
    let request_id = format!("image-canary-request-{request_number}");
    *request_number += 1;
    let frame = RequestFrame {
        request_id: request_id.clone(),
        contract_digest: HAND_CONTRACT_DIGEST.trim().into(),
        call,
    };
    socket
        .send(Message::Text(serde_json::to_string(&frame)?.into()))
        .await?;
    while let Some(message) = socket.next().await {
        let text = match message? {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => String::from_utf8(bytes.to_vec())?,
            Message::Ping(bytes) => {
                socket.send(Message::Pong(bytes)).await?;
                continue;
            }
            Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => bail!("canary guest closed before its receipt"),
        };
        let response: ResponseFrame = serde_json::from_str(&text)?;
        if response.request_id != request_id {
            continue;
        }
        return response.result.map_err(|error| {
            anyhow::anyhow!(
                "canary guest refused the request: {}: {}",
                error.code,
                error.message.as_str()
            )
        });
    }
    bail!("canary guest connection ended before its receipt")
}

async fn launch_canary_target(
    control: &Control,
    image_arn: &str,
    image_version: &str,
    run_hook_payload: &str,
    client_token: &str,
    connector: &ConnectorRef,
) -> Result<Microvm, ControlError> {
    let request = control.exact_run_request(
        image_arn,
        image_version,
        run_hook_payload,
        client_token,
        connector,
    );
    let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
    loop {
        match control.run_exact(&request).await {
            Ok(vm) => return Ok(vm),
            Err(
                ControlError::Unknown(_) | ControlError::Retryable(_) | ControlError::Throttled(_),
            ) if tokio::time::Instant::now() < deadline => {
                // RunMicrovm's documented client-token contract makes an exact replay the only
                // safe way to recover the target id after a lost response. `run_exact` applies
                // the configured provider token-bucket before each attempt.
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn assert_persistent_502(
    control: &Control,
    http: &reqwest::Client,
    hand: &LaunchedHand,
    phase: &str,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
    let mut consecutive = 0usize;
    while tokio::time::Instant::now() < deadline {
        let state = control.get(&hand.microvm_id).await?.state;
        let status = http
            .get(format!("{}/", hand.endpoint))
            .header(AUTH_HEADER, &hand.auth_token)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await?
            .status();
        tracing::info!(microvm = %hand.microvm_id, ?state, %status, phase, "no-respawn canary probe");
        if status.as_u16() == 502 {
            consecutive += 1;
            if consecutive == REQUIRED_CONSECUTIVE_502 {
                return Ok(());
            }
        } else {
            ensure!(
                !status.is_success(),
                "image canary endpoint rearmed during {phase}"
            );
            consecutive = 0;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    bail!("image canary did not produce repeated endpoint 502 during {phase}")
}

async fn transition_and_wait(
    control: &Control,
    target_id: &str,
    wanted: MicrovmState,
) -> anyhow::Result<()> {
    let effect = match wanted {
        MicrovmState::Suspended => control.suspend(target_id).await,
        MicrovmState::Running => control.resume(target_id).await,
        _ => bail!("unsupported canary transition {wanted:?}"),
    };
    match effect {
        Ok(()) | Err(ControlError::Unknown(_)) => {}
        Err(error) => return Err(error.into()),
    }
    launch::wait_for_state(control, target_id, &wanted, STATE_TIMEOUT).await?;
    Ok(())
}

async fn terminate_known_target(control: &Control, target_id: &str) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("canary target termination was not confirmed within {STATE_TIMEOUT:?}");
        }
        match control.get(target_id).await {
            Ok(vm) if is_terminated(&vm.state) => return Ok(()),
            Err(ControlError::Gone(_)) => return Ok(()),
            Ok(vm) if vm.state == MicrovmState::Terminating => {}
            Ok(_) => match control.terminate(target_id).await {
                Ok(())
                | Err(
                    ControlError::Gone(_)
                    | ControlError::Unknown(_)
                    | ControlError::Retryable(_)
                    | ControlError::Throttled(_),
                ) => {}
                Err(error) => return Err(error.into()),
            },
            Err(ControlError::Retryable(_) | ControlError::Throttled(_)) => {}
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn canary_control_token() -> ControlToken {
    ControlToken::new(format!(
        "control-{}",
        hex::encode(rand::random::<[u8; 32]>())
    ))
    .expect("random canary control token satisfies its exact grammar")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_request_digest_is_exact_and_marker_command_is_single_effect() {
        let request = canary_execution(
            "image-canary-operation",
            "image-canary-generation",
            "image-canary-root",
            "image-canary-session",
        )
        .unwrap();
        assert_eq!(
            request.request_digest,
            sandbox_execution_request_digest(&request)
        );
        assert!(request.input.command.contains("printf 'marker\\n' >>"));
        assert!(
            request
                .input
                .command
                .contains("sync /workspace/image-canary-effect")
        );
    }

    #[test]
    fn public_network_canary_uses_every_canonical_ipv4_fixture_and_exact_digest() {
        let request = public_network_execution(
            "network-canary-operation",
            "network-canary-generation",
            "network-canary-root",
            "network-canary-session",
            &[
                "dev123.execute-api.us-east-1.amazonaws.com".into(),
                "prd456.execute-api.us-east-1.amazonaws.com".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            request.request_digest,
            sandbox_execution_request_digest(&request)
        );
        for &(address, _) in brain_protocol::network::SPECIAL_USE_FIXTURES {
            if address.parse::<Ipv4Addr>().is_ok() {
                assert!(request.input.command.contains(address), "{address}");
            }
        }
        for &address in brain_protocol::network::PUBLIC_UNICAST_FIXTURES {
            if address.parse::<Ipv4Addr>().is_ok() {
                assert!(request.input.command.contains(address), "{address}");
            }
        }
        assert!(request.input.command.contains("reachableSpecial"));
        assert!(request.input.command.contains("unreachableControls"));
        for host in [
            "aex.dev",
            "api.aex.dev",
            "api-dev.aex.dev",
            "dev123.execute-api.us-east-1.amazonaws.com",
            "prd456.execute-api.us-east-1.amazonaws.com",
        ] {
            assert!(request.input.command.contains(host), "{host}");
        }
        assert!(request.input.command.contains("Sec-WebSocket-Key"));
        assert!(request.input.command.contains("@connections"));
    }

    #[test]
    fn restricted_connector_canaries_cover_dns_direct_tcp_and_gateway_auth() {
        let gateway = GatewayAuthority::parse("10.42.0.10:8443").unwrap();
        for class in [ConnectorClass::None, ConnectorClass::Allowlist] {
            let request = restricted_network_execution(
                "restricted-network-operation",
                "restricted-network-generation",
                "restricted-network-root",
                "restricted-network-session",
                &gateway,
                class,
            )
            .unwrap();
            assert_eq!(
                request.request_digest,
                sandbox_execution_request_digest(&request)
            );
            assert!(request.input.command.contains("dns.lookup"));
            assert!(request.input.command.contains("10.42.0.10"));
            for &(address, _) in brain_protocol::network::SPECIAL_USE_FIXTURES {
                if address.parse::<Ipv4Addr>().is_ok() && address != gateway.host() {
                    assert!(request.input.command.contains(address), "{address}");
                }
            }
            for &address in brain_protocol::network::PUBLIC_UNICAST_FIXTURES {
                if address.parse::<Ipv4Addr>().is_ok() {
                    assert!(request.input.command.contains(address), "{address}");
                }
            }
            match class {
                ConnectorClass::None => {
                    assert!(matches!(request.network, NetworkCeiling::None));
                    assert!(
                        request
                            .input
                            .command
                            .contains("const requireGateway = false;")
                    );
                }
                ConnectorClass::Allowlist => {
                    assert!(matches!(request.network, NetworkCeiling::Allowlist(_)));
                    assert!(
                        request
                            .input
                            .command
                            .contains("const requireGateway = true;")
                    );
                    assert!(request.input.command.contains("CONNECT example.com"));
                    assert!(request.input.command.contains("unauthenticated !== 407"));
                    assert!(request.input.command.contains("invalid !== 403"));
                }
                ConnectorClass::Public => unreachable!(),
            }
        }
    }

    #[test]
    fn customer_hand_canary_hosts_are_two_distinct_us_east_1_api_gateway_hosts() {
        assert!(
            validate_customer_hand_hosts(&[
                "dev123.execute-api.us-east-1.amazonaws.com".into(),
                "prd456.execute-api.us-east-1.amazonaws.com".into(),
            ])
            .is_ok()
        );
        for invalid in [
            [
                "dev123.execute-api.us-east-1.amazonaws.com".into(),
                "dev123.execute-api.us-east-1.amazonaws.com".into(),
            ],
            [
                "https://dev123.execute-api.us-east-1.amazonaws.com/v1".into(),
                "prd456.execute-api.us-east-1.amazonaws.com".into(),
            ],
            [
                "dev123.execute-api.eu-west-1.amazonaws.com".into(),
                "prd456.execute-api.us-east-1.amazonaws.com".into(),
            ],
        ] {
            assert!(validate_customer_hand_hosts(&invalid).is_err());
        }
    }
}
