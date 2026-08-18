//! AWS Lambda MicroVM lifecycle hooks, served on the same port as the ABI WebSocket.
//!
//! The provider POSTs to these paths (`hooks.port` in the image registration; traffic does not
//! flow until `/run` returns 200, and a resuming MicroVM stays SUSPENDED until `/resume`
//! returns 200):
//!
//! - `/run` — first boot of the VM. Body: our [`RunPayload`], carrying the per-session secret.
//!   Lambda MicroVM has no per-VM environment, so this is the only place it can arrive.
//! - `/resume` — restored from a snapshot. Same process, same generation; brains reconnect and
//!   re-attach over the ABI.
//! - `/suspend` — about to snapshot. We flush spill files and return quickly.
//! - `/terminate` — the VM is going away. Best-effort graceful stop; workspace durability is
//!   the brain's job (sync happens *before* a planned termination, never from here — the hand
//!   holds no upload credential).
//! - `/ready` (build) — is the rootfs contract satisfied.
//! - `/validate` (build) — does the curated toolchain actually run.
//!
//! The payload's key set is **closed** (`deny_unknown_fields`): there is deliberately nowhere
//! for a platform credential to arrive. Outside Lambda (plain container), the token comes from
//! `AEX_HAND_TOKEN` instead and these routes are simply never called.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::hand::{Hand, LifecyclePhase};

/// The path prefix AWS posts lifecycle hooks to.
pub const HOOK_PREFIX: &str = "/aws/lambda-microvms/runtime/v1";

/// The envelope Lambda wraps the run hook in. It injects `microvmId` and carries our
/// `runHookPayload` verbatim as a string (docs: microvms-launching, `RunRequestContent`). We do
/// not `deny_unknown_fields` here — the envelope is AWS's and may grow.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunEnvelope {
    #[serde(default)]
    pub microvm_id: Option<String>,
    /// The string we passed to `RunMicrovm` — our [`RunPayload`], JSON-encoded.
    pub run_hook_payload: String,
}

/// Our own run payload, encoded into `runHookPayload`. Closed key set: there is deliberately
/// nowhere for a platform credential to arrive — only the per-session secret.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPayload {
    /// Payload version. Exactly 1.
    pub v: u8,
    /// The per-session secret the brain must present in `hello`.
    pub token: String,
}

pub async fn run(State(hand): State<Arc<Hand>>, body: String) -> (StatusCode, Json<Value>) {
    let envelope: RunEnvelope = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "run hook: malformed envelope");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("malformed run envelope: {e}")})),
            );
        }
    };
    if let Some(id) = &envelope.microvm_id {
        tracing::info!(microvm = %id, "run hook received");
    }
    let payload: RunPayload = match serde_json::from_str(&envelope.run_hook_payload) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "run hook: malformed payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("malformed run payload: {e}")})),
            );
        }
    };
    if payload.v != 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("unsupported run payload version {}", payload.v)})),
        );
    }
    if let Err(reason) = hand.arm(&payload.token) {
        tracing::error!(reason, "run hook: refusing to re-arm");
        return (StatusCode::CONFLICT, Json(json!({"error": reason})));
    }
    *hand.lifecycle.write().unwrap() = LifecyclePhase::Serving;
    tracing::info!(generation = %*hand.generation_id, "run hook: armed, serving");
    (StatusCode::OK, Json(json!({})))
}

pub async fn resume(State(hand): State<Arc<Hand>>) -> (StatusCode, Json<Value>) {
    *hand.lifecycle.write().unwrap() = LifecyclePhase::Serving;
    hand.emit_status();
    tracing::info!("resume hook: serving");
    (StatusCode::OK, Json(json!({})))
}

pub async fn suspend(State(hand): State<Arc<Hand>>) -> (StatusCode, Json<Value>) {
    hand.flush_spills().await;
    *hand.lifecycle.write().unwrap() = LifecyclePhase::Suspended;
    tracing::info!("suspend hook: spills flushed");
    (StatusCode::OK, Json(json!({})))
}

pub async fn terminate(State(hand): State<Arc<Hand>>) -> (StatusCode, Json<Value>) {
    *hand.lifecycle.write().unwrap() = LifecyclePhase::Terminating;
    tracing::info!("terminate hook: stopping operations");
    hand.shutdown().await;
    (StatusCode::OK, Json(json!({})))
}

/// Build hook: the rootfs contract. Everything the image promises the guest, checked from
/// inside the built image before a version goes ACTIVE.
pub async fn ready(State(hand): State<Arc<Hand>>) -> (StatusCode, Json<Value>) {
    let mut failures: Vec<String> = Vec::new();
    for (name, dir) in [
        ("workspace", &hand.cfg.workspace),
        ("home", &hand.cfg.home),
        ("spill_dir", &hand.cfg.spill_dir),
    ] {
        if !dir.is_dir() {
            failures.push(format!("{name} {} is not a directory", dir.display()));
            continue;
        }
        // Writable, not merely present: the agent user must own its working trees.
        let probe = dir.join(".aex-ready-probe");
        match std::fs::write(&probe, b"ok") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => failures.push(format!("{name} {} is not writable: {e}", dir.display())),
        }
    }
    if failures.is_empty() {
        (StatusCode::OK, Json(json!({"ok": true})))
    } else {
        tracing::error!(?failures, "ready hook failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "failures": failures})),
        )
    }
}

/// Build hook: the curated toolchain runs. Each tool must execute, not merely exist — a broken
/// dynamic link or a missing interpreter fails the image build, not a customer session.
pub async fn validate(State(_hand): State<Arc<Hand>>) -> (StatusCode, Json<Value>) {
    let tools: &[(&str, &[&str])] = &[
        ("bash", &["--version"]),
        ("python3", &["--version"]),
        ("node", &["--version"]),
        ("git", &["--version"]),
        ("rg", &["--version"]),
        ("tar", &["--version"]),
        ("zstd", &["--version"]),
    ];
    let mut versions = serde_json::Map::new();
    let mut failures: Vec<String> = Vec::new();
    for (tool, args) in tools {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::process::Command::new(tool).args(*args).output(),
        )
        .await;
        match out {
            Ok(Ok(o)) if o.status.success() => {
                let line = String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                versions.insert((*tool).to_owned(), Value::String(line));
            }
            Ok(Ok(o)) => failures.push(format!("{tool}: exit {:?}", o.status.code())),
            Ok(Err(e)) => failures.push(format!("{tool}: {e}")),
            Err(_) => failures.push(format!("{tool}: timed out")),
        }
    }
    if failures.is_empty() {
        (StatusCode::OK, Json(json!({"ok": true, "tools": versions})))
    } else {
        tracing::error!(?failures, "validate hook failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "failures": failures, "tools": versions})),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{RunEnvelope, RunPayload};

    #[test]
    fn the_run_envelope_unwraps_the_aws_body_and_our_nested_payload() {
        // Exactly the body AWS documents: microvmId injected, our string carried verbatim.
        let body = r#"{"microvmId":"mvm-abc","runHookPayload":"{\"v\":1,\"token\":\"sekret\"}"}"#;
        let env: RunEnvelope = serde_json::from_str(body).expect("envelope parses");
        assert_eq!(env.microvm_id.as_deref(), Some("mvm-abc"));
        let payload: RunPayload =
            serde_json::from_str(&env.run_hook_payload).expect("nested payload parses");
        assert_eq!(payload.v, 1);
        assert_eq!(payload.token, "sekret");
    }

    #[test]
    fn the_envelope_tolerates_extra_aws_fields_but_the_payload_does_not() {
        // The AWS envelope may grow; unknown keys there are ignored.
        let body = r#"{"microvmId":"m","runHookPayload":"{\"v\":1,\"token\":\"t\"}","future":1}"#;
        assert!(serde_json::from_str::<RunEnvelope>(body).is_ok());
        // Our own payload is a closed key set: a stray field is refused.
        assert!(serde_json::from_str::<RunPayload>(r#"{"v":1,"token":"t","x":1}"#).is_err());
    }
}
