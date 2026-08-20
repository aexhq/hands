//! Typed MicroVM lifecycle control over the AWS SDK, with every failure classified.
//!
//! Classification is the `hand_lost` contract: the brain needs to know whether a failed call
//! means *try again* ([`ControlError::Retryable`]), *the hand is gone* ([`ControlError::Gone`],
//! surfaced to the session as `hand_lost` and never replayed), or *the request itself is
//! wrong* ([`ControlError::Fatal`], a bug or a config error, loud and unretried).

use aws_sdk_lambdamicrovms::Client;
use aws_sdk_lambdamicrovms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_lambdamicrovms::types::{IdlePolicy, MicrovmState, PortSpecification};

use crate::{AGENT_PORT, MAX_DURATION_SECONDS, MAX_IDLE_SECONDS, TOKEN_TTL_SECONDS};

/// The JWE goes in this request header, verbatim, on every call through the VM endpoint.
pub const AUTH_HEADER: &str = "X-aws-proxy-auth";

/// The AWS-managed ingress connector that exposes the authenticated public endpoint.
pub const ALL_INGRESS: &str = "ALL_INGRESS";

/// The AWS-managed egress connector for direct public internet access.
pub const INTERNET_EGRESS: &str = "INTERNET_EGRESS";

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Throttle, transient server error, or a network failure on a read — try again.
    #[error("retryable: {0}")]
    Retryable(String),
    /// The VM no longer exists or is past recovery: surface `hand_lost` to the session.
    #[error("microvm gone: {0}")]
    Gone(String),
    /// A network failure during a state-changing call: the effect may or may not have taken.
    /// The caller must re-read (`get`) before deciding anything.
    #[error("outcome unknown: {0}")]
    Unknown(String),
    /// The request is wrong (validation, auth, quota misconfiguration). Not retryable.
    #[error("fatal: {0}")]
    Fatal(String),
}

/// One MicroVM as the control plane sees it.
#[derive(Debug, Clone)]
pub struct Microvm {
    pub id: String,
    pub state: MicrovmState,
    /// `https://…` — present once the VM has one.
    pub endpoint: Option<String>,
}

#[derive(Clone)]
pub struct Control {
    client: Client,
    region: String,
}

impl Control {
    pub fn new(client: Client, region: impl Into<String>) -> Self {
        Self {
            client,
            region: region.into(),
        }
    }

    pub async fn from_env(region: &str) -> Self {
        let cfg = aws_config::from_env()
            .region(aws_config::Region::new(region.to_owned()))
            .load()
            .await;
        Self::new(Client::new(&cfg), region)
    }

    fn connector_arn(&self, name: &str) -> String {
        if name.starts_with("arn:") {
            name.to_owned()
        } else {
            format!(
                "arn:aws:lambda:{}:aws:network-connector:aws-network-connector:{name}",
                self.region
            )
        }
    }

    /// Launches a MicroVM for one session. `client_token` makes the call idempotent — the same
    /// session identity relaunched returns the same VM rather than a second one.
    pub async fn run(
        &self,
        image_arn: &str,
        image_version: &str,
        run_hook_payload: &str,
        client_token: &str,
    ) -> Result<Microvm, ControlError> {
        let idle = IdlePolicy::builder()
            .max_idle_duration_seconds(MAX_IDLE_SECONDS as i32)
            .suspended_duration_seconds(MAX_DURATION_SECONDS as i32)
            .auto_resume_enabled(true)
            .build()
            .map_err(|e| ControlError::Fatal(format!("idle policy: {e}")))?;
        // Deliberately no `.execution_role_arn(...)`: an execution role would make IAM
        // credentials retrievable from inside the guest via IMDSv2. The adversarial IMDS probe
        // confirmed the metadata service answers; only the *absence* of an attached role keeps it
        // empty. I8 —
        // the hand holds no cloud credential — depends on this staying unset.
        let out = self
            .client
            .run_microvm()
            .image_identifier(image_arn)
            .image_version(image_version)
            .ingress_network_connectors(self.connector_arn(ALL_INGRESS))
            .egress_network_connectors(self.connector_arn(INTERNET_EGRESS))
            .idle_policy(idle)
            .maximum_duration_in_seconds(MAX_DURATION_SECONDS as i32)
            .run_hook_payload(run_hook_payload)
            .client_token(client_token)
            .send()
            .await
            .map_err(|e| effect_error(&e))?;
        Ok(Microvm {
            id: out.microvm_id().to_owned(),
            state: out.state().clone(),
            endpoint: Some(out.endpoint().to_owned()).filter(|e| !e.is_empty()),
        })
    }

    pub async fn get(&self, id: &str) -> Result<Microvm, ControlError> {
        let out = self
            .client
            .get_microvm()
            .microvm_identifier(id)
            .send()
            .await
            .map_err(|e| read_error(&e))?;
        Ok(Microvm {
            id: out.microvm_id().to_owned(),
            state: out.state().clone(),
            endpoint: Some(out.endpoint().to_owned()).filter(|e| !e.is_empty()),
        })
    }

    pub async fn suspend(&self, id: &str) -> Result<(), ControlError> {
        self.client
            .suspend_microvm()
            .microvm_identifier(id)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| effect_error(&e))
    }

    pub async fn resume(&self, id: &str) -> Result<(), ControlError> {
        self.client
            .resume_microvm()
            .microvm_identifier(id)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| effect_error(&e))
    }

    pub async fn terminate(&self, id: &str) -> Result<(), ControlError> {
        self.client
            .terminate_microvm()
            .microvm_identifier(id)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| effect_error(&e))
    }

    /// Mints the endpoint JWE, scoped to the one agent port.
    pub async fn auth_token(&self, id: &str) -> Result<String, ControlError> {
        let out = self
            .client
            .create_microvm_auth_token()
            .microvm_identifier(id)
            .expiration_in_minutes((TOKEN_TTL_SECONDS / 60) as i32)
            .allowed_ports(PortSpecification::Port(i32::from(AGENT_PORT)))
            .send()
            .await
            .map_err(|e| effect_error(&e))?;
        out.auth_token()
            .get(AUTH_HEADER)
            .filter(|t| !t.is_empty())
            .cloned()
            .ok_or_else(|| ControlError::Fatal("response carried no auth token".into()))
    }

    pub async fn list(&self) -> Result<Vec<Microvm>, ControlError> {
        let mut vms = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let out = self
                .client
                .list_microvms()
                .set_next_token(next)
                .send()
                .await
                .map_err(|e| read_error(&e))?;
            for item in out.items() {
                vms.push(Microvm {
                    id: item.microvm_id().to_owned(),
                    state: item.state().clone(),
                    endpoint: None,
                });
            }
            next = out.next_token().map(str::to_owned);
            if next.is_none() {
                return Ok(vms);
            }
        }
    }

    pub fn sdk(&self) -> &Client {
        &self.client
    }

    pub fn region(&self) -> &str {
        &self.region
    }
}

/// Whether a VM state means the hand can never come back.
pub fn is_gone(state: &MicrovmState) -> bool {
    matches!(state, MicrovmState::Terminating | MicrovmState::Terminated)
}

fn classify(code: Option<&str>, message: String, effect: bool) -> ControlError {
    match code {
        Some("ResourceNotFoundException") => ControlError::Gone(message),
        Some("ThrottlingException") | Some("TooManyRequestsException") => {
            ControlError::Retryable(message)
        }
        Some("InternalServerException") | Some("ServiceUnavailableException") => {
            ControlError::Retryable(message)
        }
        Some("ConflictException") if effect => ControlError::Unknown(message),
        Some(_) => ControlError::Fatal(message),
        // No service error code: the transport failed.
        None if effect => ControlError::Unknown(message),
        None => ControlError::Retryable(message),
    }
}

fn effect_error<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> ControlError {
    sdk_error(e, true)
}

fn read_error<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> ControlError {
    sdk_error(e, false)
}

fn sdk_error<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>, effect: bool) -> ControlError {
    match e {
        SdkError::ServiceError(s) => classify(
            s.err().code(),
            s.err().message().unwrap_or("service error").to_owned(),
            effect,
        ),
        SdkError::ConstructionFailure(_) => ControlError::Fatal("request construction".into()),
        other => classify(None, other.to_string(), effect),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_connector_names_expand_to_the_documented_arn() {
        let control = Control::new(
            Client::from_conf(aws_sdk_lambdamicrovms::Config::builder().build()),
            "eu-west-1",
        );
        assert_eq!(
            control.connector_arn(ALL_INGRESS),
            "arn:aws:lambda:eu-west-1:aws:network-connector:aws-network-connector:ALL_INGRESS"
        );
        let custom = "arn:aws:lambda:eu-west-1:123456789012:network-connector/custom";
        assert_eq!(control.connector_arn(custom), custom);
    }

    #[test]
    fn not_found_is_gone_and_throttle_is_retryable_and_unknown_codes_fail_closed() {
        assert!(matches!(
            classify(Some("ResourceNotFoundException"), String::new(), true),
            ControlError::Gone(_)
        ));
        assert!(matches!(
            classify(Some("ThrottlingException"), String::new(), true),
            ControlError::Retryable(_)
        ));
        assert!(matches!(
            classify(Some("SomethingNew"), String::new(), true),
            ControlError::Fatal(_)
        ));
        // A transport failure during an effect call must never be presumed to have failed.
        assert!(matches!(
            classify(None, String::new(), true),
            ControlError::Unknown(_)
        ));
        assert!(matches!(
            classify(None, String::new(), false),
            ControlError::Retryable(_)
        ));
    }

    #[test]
    fn terminal_states_are_gone_and_the_rest_are_not() {
        assert!(is_gone(&MicrovmState::Terminated));
        assert!(is_gone(&MicrovmState::Terminating));
        for state in [
            MicrovmState::Pending,
            MicrovmState::Running,
            MicrovmState::Suspending,
            MicrovmState::Suspended,
        ] {
            assert!(!is_gone(&state), "{state:?}");
        }
    }
}
