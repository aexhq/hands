//! Host-side adapter that runs aex hands on **AWS Lambda MicroVMs**.
//!
//! The MicroVM service gives us Firecracker isolation as a product: one VM per session, a
//! Lambda-managed AL2023 base image with our container layer inside it, an authenticated
//! public HTTPS endpoint per VM (JWE in `X-aws-proxy-auth`), traffic-idle auto-suspend, and a
//! hard 8-hour retention wall (running *plus* suspended).
//!
//! Three parts:
//!
//! - [`image`] — the pipeline: generated Dockerfile + guest binary + boot script packed into a
//!   ZIP, uploaded to S3, registered with `CreateMicrovmImage`/`UpdateMicrovmImage` (AWS runs
//!   the build), and checked against the managed base's deprecation schedule (images expire on
//!   AWS's calendar, not ours).
//! - [`control`] — typed lifecycle calls (`RunMicrovm`/`Get`/`Suspend`/`Resume`/`Terminate`,
//!   `CreateMicrovmAuthToken`) with error classification: every failure maps to *retryable*,
//!   *gone* (→ `hand_lost`), or *fatal*.
//! - [`launch`] — a session's arc: launch (or adopt) a VM, deliver the session token through
//!   the run-hook payload, mint an endpoint token, connect the ABI WebSocket through the
//!   endpoint, keep the VM alive while jobs live, probe (speculative resume) on message
//!   admission.

pub mod control;
pub mod image;
pub mod launch;

/// The one region hands run in for MVP.
pub const REGION: &str = "eu-west-1";

/// The single guest port: lifecycle hooks, probe, and the ABI WebSocket. Matches the port the
/// image registration declares and the endpoint auth token is scoped to.
pub const AGENT_PORT: u16 = 8080;

/// Idle policy: AWS suspends the VM after this much endpoint-traffic silence (D6).
pub const MAX_IDLE_SECONDS: u64 = 180;

/// The provider-hard retention wall: running plus suspended (quota L-B430C318).
pub const MAX_DURATION_SECONDS: u64 = 28_800;

/// Endpoint auth token lifetime. `CreateMicrovmAuthToken` accepts minutes, max 60.
pub const TOKEN_TTL_SECONDS: u64 = 3_600;
