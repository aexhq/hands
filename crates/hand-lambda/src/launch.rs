//! One session's arc on a Lambda MicroVM.
//!
//! Launch delivers the per-session secret in the run-hook payload (the only per-VM input the
//! service offers), waits for RUNNING — which by the hook contract means the guest's `/run`
//! returned 200 and the hand is armed — then mints the endpoint JWE and connects the ABI
//! WebSocket through the VM's public endpoint.
//!
//! While a session has live jobs the VM must not idle-suspend, so [`Keepalive`] sends endpoint
//! traffic (an authenticated probe) well inside the 180 s idle window. When the brain admits a
//! message for a possibly-suspended hand it calls [`probe`] first: the endpoint holds the
//! request until `/resume` completes, so the resume cost is paid concurrently with model
//! inference rather than in front of the first tool call (D6/F-4).

use std::time::Duration;

use anyhow::{Context as _, bail};
use aws_sdk_lambdamicrovms::types::MicrovmState;
use hand_client::HandClient;

use crate::control::{AUTH_HEADER, Control, ControlError, Microvm, is_gone};

/// What a launched, armed, reachable hand looks like to the brain.
#[derive(Debug, Clone)]
pub struct LaunchedHand {
    pub microvm_id: String,
    /// `https://…`, no trailing slash.
    pub endpoint: String,
    /// The JWE for `X-aws-proxy-auth`.
    pub auth_token: String,
}

/// The run-hook payload the guest expects (`hand_guest::hooks::RunPayload`).
#[must_use]
pub fn run_payload(session_token: &str) -> String {
    serde_json::json!({ "v": 1, "token": session_token }).to_string()
}

/// Launches (or idempotently re-launches, same `client_token`) a MicroVM and waits until it is
/// RUNNING — i.e. the guest booted and its `/run` hook accepted the session token.
pub async fn launch(
    control: &Control,
    image_arn: &str,
    image_version: &str,
    session_token: &str,
    client_token: &str,
) -> anyhow::Result<LaunchedHand> {
    let vm = control
        .run(
            image_arn,
            image_version,
            &run_payload(session_token),
            client_token,
        )
        .await
        .context("RunMicrovm")?;
    let vm = wait_for_state(
        control,
        &vm.id,
        &MicrovmState::Running,
        Duration::from_secs(180),
    )
    .await?;
    let endpoint = vm
        .endpoint
        .clone()
        .context("RUNNING MicroVM has no endpoint")?;
    let auth_token = control.auth_token(&vm.id).await.context("auth token")?;
    Ok(LaunchedHand {
        microvm_id: vm.id,
        endpoint: normalise_endpoint(&endpoint),
        auth_token,
    })
}

/// `RunMicrovm` returns the endpoint as a bare host (`mvm-….on.aws`); make it a scheme-qualified
/// origin with no trailing slash, so `probe` and `ws_url` can build URLs off it directly.
#[must_use]
pub fn normalise_endpoint(endpoint: &str) -> String {
    let host = endpoint
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!("https://{host}")
}

/// Polls until the VM reaches `want`. Terminal states short-circuit with an error.
pub async fn wait_for_state(
    control: &Control,
    id: &str,
    want: &MicrovmState,
    timeout: Duration,
) -> anyhow::Result<Microvm> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let vm = match control.get(id).await {
            Ok(vm) => vm,
            Err(ControlError::Retryable(e)) => {
                tracing::debug!(error = %e, "get_microvm retry");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if vm.state == *want {
            return Ok(vm);
        }
        if is_gone(&vm.state) {
            bail!("microvm {id} is {:?} while waiting for {want:?}", vm.state);
        }
        if tokio::time::Instant::now() > deadline {
            bail!(
                "microvm {id} still {:?} after {timeout:?} (wanted {want:?})",
                vm.state
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The WebSocket URL for a VM endpoint.
#[must_use]
pub fn ws_url(endpoint: &str) -> String {
    let host = endpoint
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!("wss://{host}/")
}

/// Connects the ABI WebSocket through the authenticated endpoint.
pub async fn connect(hand: &LaunchedHand, fence: u64) -> anyhow::Result<HandClient> {
    HandClient::connect_with_headers(
        &ws_url(&hand.endpoint),
        fence,
        &[(AUTH_HEADER, hand.auth_token.as_str())],
    )
    .await
    .context("connecting through the MicroVM endpoint")
}

/// One authenticated GET to the guest's probe document. To a suspended VM this is the
/// speculative resume: the endpoint holds the request until `/resume` completes, then the
/// probe answers from the running guest.
pub async fn probe(
    http: &reqwest::Client,
    hand: &LaunchedHand,
    timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    let response = http
        .get(format!("{}/", hand.endpoint))
        .header(AUTH_HEADER, &hand.auth_token)
        .timeout(timeout)
        .send()
        .await
        .context("probe request")?;
    let status = response.status();
    if !status.is_success() {
        bail!("probe answered {status}");
    }
    response.json().await.context("probe body")
}

/// The speculative resume: send endpoint traffic to a suspended hand so Lambda holds the request
/// while `/resume` runs, then answers from the resumed guest. Right after an explicit suspend the
/// endpoint can briefly answer 502/503 before auto-resume is wired, so this retries the held
/// request until it succeeds or `overall` elapses. This is the D6/F-4 path a brain uses to hide
/// the resume behind model inference.
pub async fn resume_via_probe(
    http: &reqwest::Client,
    hand: &LaunchedHand,
    overall: Duration,
) -> anyhow::Result<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + overall;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match probe(http, hand, Duration::from_secs(60)).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(
                        e.context(format!("resume-via-probe gave up after {attempt} tries"))
                    );
                }
                tracing::debug!(attempt, error = %e, "resume probe not ready; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Endpoint traffic on a timer, so a hand with live jobs is never idle-suspended under them.
/// Dropping the handle stops it.
pub struct Keepalive {
    task: tokio::task::JoinHandle<()>,
}

impl Keepalive {
    /// Probes every `interval` (choose well under the 180 s idle policy; 60 s is right).
    pub fn spawn(hand: LaunchedHand, interval: Duration) -> Self {
        let http = reqwest::Client::new();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match probe(&http, &hand, Duration::from_secs(30)).await {
                    Ok(_) => tracing::trace!(microvm = %hand.microvm_id, "keepalive"),
                    Err(e) => {
                        tracing::warn!(microvm = %hand.microvm_id, error = %e, "keepalive probe failed");
                    }
                }
            }
        });
        Self { task }
    }
}

impl Drop for Keepalive {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What a connection loss actually means. The brain maps `Lost` to the session-visible
/// `hand_lost` event (never replayed); everything else is reconnectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Running: the drop was transport-level. Reconnect.
    Reconnect,
    /// Suspended (idle policy fired): probe to resume, then reconnect.
    ResumeThenReconnect,
    /// In transition; ask again shortly.
    Wait,
    /// Gone for good: `hand_lost`, with the reason we can attest.
    Lost(String),
}

/// Classifies a dropped hand by asking the control plane what became of the VM.
pub async fn diagnose(control: &Control, microvm_id: &str) -> Disposition {
    match control.get(microvm_id).await {
        Ok(vm) => match vm.state {
            MicrovmState::Running => Disposition::Reconnect,
            MicrovmState::Suspended => Disposition::ResumeThenReconnect,
            MicrovmState::Pending | MicrovmState::Suspending => Disposition::Wait,
            MicrovmState::Terminating | MicrovmState::Terminated => {
                Disposition::Lost(format!("microvm is {:?}", vm.state))
            }
            other => Disposition::Lost(format!("unmodelled microvm state {other:?}")),
        },
        Err(ControlError::Gone(reason)) => Disposition::Lost(reason),
        Err(ControlError::Retryable(_)) | Err(ControlError::Unknown(_)) => Disposition::Wait,
        Err(ControlError::Fatal(reason)) => Disposition::Lost(format!("control: {reason}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_swaps_scheme_and_keeps_the_host() {
        assert_eq!(
            ws_url("https://abc123.lambda-microvm.eu-west-1.on.aws"),
            "wss://abc123.lambda-microvm.eu-west-1.on.aws/"
        );
        assert_eq!(ws_url("https://x/"), "wss://x/");
    }

    #[test]
    fn a_bare_host_endpoint_becomes_a_scheme_qualified_origin() {
        // RunMicrovm returns the endpoint with no scheme and no trailing slash.
        let host = "mvm-01234567-abcd-ef01-2345-6789abcdef01.lambda-microvm.eu-west-1.on.aws";
        assert_eq!(normalise_endpoint(host), format!("https://{host}"));
        assert_eq!(
            normalise_endpoint(&format!("https://{host}/")),
            format!("https://{host}")
        );
        // And the two URL builders compose off the normalised form.
        let n = normalise_endpoint(host);
        assert_eq!(format!("{n}/"), format!("https://{host}/"));
        assert_eq!(ws_url(&n), format!("wss://{host}/"));
    }

    #[test]
    fn the_run_payload_is_versioned_and_carries_only_the_token() {
        let payload: serde_json::Value = serde_json::from_str(&run_payload("s3cret")).unwrap();
        assert_eq!(payload["v"], 1);
        assert_eq!(payload["token"], "s3cret");
        assert_eq!(payload.as_object().unwrap().len(), 2);
    }
}
