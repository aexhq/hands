//! Private production-Hand transport framing.
//!
//! Brain owns every public request and response carried here. These envelopes add only request
//! multiplexing and target bootstrap/install commands; they are not a second public protocol.
//! Every connection and run payload pins Brain's exact canonical contract digest.

use brain::hand::{
    SandboxFileContent, SandboxFileList, SandboxFileListRequest, SandboxSearchRequest,
};
use brain_protocol::hand::{
    AcknowledgeTerminalRequest, Acknowledgement, BundleDescriptor, CancelRequest,
    CancellationReceipt, FileEntry, NetworkCeiling, ObjectReference, ObserveRequest,
    OperationObservation, ResourceCeiling, SandboxCopyResult, SandboxExecutionRequest,
    SandboxFileRequest, SandboxFileWriteResult, SandboxTarget, SealedBinding, SubmitReceipt,
    SubmitRequest, WriteStdinReceipt, WriteStdinRequest,
};
use hand_core::connector::ConnectorClass;
use hand_core::materialization::ControlToken;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

/// Inline file reads/writes are capped at 1 MiB decoded. A 2 MiB frame admits their padded base64
/// plus the exact request/response envelope without making the WebSocket allocation unbounded.
pub const MAX_INLINE_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_WIRE_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Private guest transport headroom. Brain's canonical per-Tool bundle limit is narrower, while
/// this matches the aggregate session-bundle ceiling so the transport cannot become the limiter.
pub const MAX_BUNDLE_INSTALL_BYTES: usize = brain_protocol::MAX_SESSION_BUNDLE_BYTES;
pub const MAX_INSTALL_METADATA_BYTES: usize = 64 * 1024;
pub const MAX_INSTALL_BODY_BYTES: usize = MAX_BUNDLE_INSTALL_BYTES + MAX_INSTALL_METADATA_BYTES + 1;
pub const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
pub const OBJECT_METADATA_HEADER: &str = "x-aex-object-metadata";
pub const FILE_ENTRY_HEADER: &str = "x-aex-file-entry";
pub const CONTROL_AUTH_HEADER: &str = "x-aex-hand-control";

/// The provider run-hook payload. It contains no cloud credential. Its generation-scoped control
/// bearer authenticates the trusted host after the provider proxy and must never enter logs,
/// formatting, argv, Tool environments, or public Brain projections.
///
/// An allowlist capability is intentionally visible to the sandbox generation. It is a sealed
/// destination grant, not an Aex credential, and must still never appear in logs or process argv.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunPayload {
    pub contract_digest: String,
    pub generation: String,
    pub expires_at_ms: u64,
    pub root_id: String,
    pub owner_session_id: String,
    pub connector: ConnectorClass,
    pub resource_class: String,
    pub resources: ResourceCeiling,
    pub network: NetworkCeiling,
    pub control_token: ControlToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_proxy: Option<AllowlistProxy>,
    /// Internal image-promotion canary only. Production Hands always send `None`. When present,
    /// the guest commits the matching terminal response to its private state, writes that response
    /// to the provider socket, and then aborts so release automation can prove the provider never
    /// rearms the same physical generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_exit_after_operation_id: Option<String>,
}

/// Deliberately omits `Debug`: `capability` is a bearer grant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistProxy {
    pub authority: String,
    pub capability: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunEnvelope {
    #[serde(default, rename = "microvmId")]
    pub microvm_id: Option<String>,
    #[serde(rename = "runHookPayload")]
    pub run_hook_payload: String,
}

// Deliberately no `Debug`: nested fetch/transfer authorities contain presigned credentials.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrame {
    pub request_id: String,
    pub contract_digest: String,
    pub call: RequestCall,
}

// Deliberately no `Debug`: some calls carry one-purpose object authorities.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum RequestCall {
    Submit(Box<SubmitRequest>),
    Observe(ObserveRequest),
    Cancel(CancelRequest),
    AcknowledgeTerminal(AcknowledgeTerminalRequest),
    Status,
    ListFiles(SandboxFileListRequest),
    StatFile(SandboxFileRequest),
    ReadFile(SandboxFileRequest),
    WriteFile(GuestFileWriteRequest),
    ReserveFileEffect(FileEffectIdentity),
    ClaimFileEffect(FileEffectIdentity),
    CompleteFileEffect(FileEffectStoredResult),
    FindFiles(SandboxSearchRequest),
    GrepFiles(SandboxSearchRequest),
    ExecuteSandbox(SandboxExecutionRequest),
    WriteStdin(WriteStdinRequest),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFrame {
    pub request_id: String,
    pub result: Result<ResponseReply, brain_protocol::hand::HandError>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum ResponseReply {
    Submit(SubmitReceipt),
    Observe(OperationObservation),
    Cancel(CancellationReceipt),
    AcknowledgeTerminal(Acknowledgement),
    Status(TargetRuntimeStatus),
    ListFiles(SandboxFileList),
    StatFile(FileEntry),
    ReadFile(SandboxFileContent),
    WriteFile(FileEffectStoredResult),
    ReserveFileEffect(FileEffectReservation),
    ClaimFileEffect(FileEffectReservation),
    CompleteFileEffect(FileEffectStoredResult),
    FindFiles(SandboxFileList),
    GrepFiles(SandboxFileList),
    ExecuteSandbox(SubmitReceipt),
    WriteStdin(WriteStdinReceipt),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRuntimeStatus {
    pub target_ref: String,
    pub generation: String,
    pub root_id: String,
    pub owner_session_id: String,
    pub connector: ConnectorClass,
    pub resource_class: String,
    pub armed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBindingRequest {
    pub binding_ref: String,
    pub binding: SealedBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBundleMetadata {
    pub descriptor: BundleDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallObjectMetadata {
    pub object: ObjectReference,
}

/// Only the trusted adapter serializes and the guest HTTP handler deserializes this bounded body.
/// It deliberately has no `Debug`, keeping values out of normal framing and tracing.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallSecretsRequest {
    pub session_id: String,
    pub generation: String,
    /// Immutable preparation-time union. Values must match it exactly; each binding receives only
    /// its descriptor-declared subset when the Tool child is spawned.
    pub env_names: Vec<String>,
    pub values: std::collections::HashMap<String, String>,
}

#[must_use]
pub fn environment_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= brain_protocol::MAX_SESSION_SECRET_NAME_BYTES
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

#[must_use]
pub fn reserved_tool_environment(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name.starts_with("LD_")
        || name.starts_with("HAND_")
        || name.starts_with("AEX_")
        || matches!(
            name.as_str(),
            "PATH"
                | "HOME"
                | "USER"
                | "LOGNAME"
                | "LANG"
                | "TERM"
                | "CI"
                | "IFS"
                | "ENV"
                | "BASH_ENV"
                | "SHELLOPTS"
                | "PS4"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "NODE_REPL_EXTERNAL_MODULE"
                | "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NO_PROXY"
                | "GIT_TERMINAL_PROMPT"
                | "CARGO_HOME"
                | "RUSTUP_HOME"
                | "GOPATH"
                | "GOMODCACHE"
                | "NPM_CONFIG_PREFIX"
                | "NPM_CONFIG_CACHE"
                | "PIP_CACHE_DIR"
                | "PIPX_HOME"
                | "PIPX_BIN_DIR"
                | "UV_CACHE_DIR"
                | "GCONV_PATH"
                | "LOCPATH"
                | "NLSPATH"
                | "OPENSSL_CONF"
                | "OPENSSL_MODULES"
                | "SSLKEYLOGFILE"
        )
}

/// Applies Brain's exact custody-document boundary again at both trusted-adapter and guest
/// ingress. The temporary canonical encoding is immediately zeroized; callers separately zeroize
/// the owned strings after delivery.
#[must_use]
pub fn secret_material_fits(
    env_names: &[String],
    values: &std::collections::HashMap<String, String>,
) -> bool {
    if env_names.len() > brain_protocol::MAX_SESSION_SECRET_NAMES
        || values.len() != env_names.len()
        || env_names.iter().enumerate().any(|(index, name)| {
            !environment_name_is_valid(name)
                || env_names[..index].iter().any(|prior| prior == name)
                || !values.contains_key(name)
        })
        || values.values().any(|value| {
            value.len() > brain_protocol::MAX_SESSION_SECRET_VALUE_UTF8_BYTES
                || value.contains('\0')
        })
    {
        return false;
    }
    let Ok(mut canonical) = serde_jcs::to_vec(values) else {
        return false;
    };
    let fits = canonical.len() <= brain_protocol::MAX_SESSION_SECRET_DOCUMENT_BYTES;
    canonical.zeroize();
    fits
}

/// Private trusted-adapter projection of a canonical file write. A canonical object source also
/// carries a one-purpose storage GET authority; the hosted Hand consumes that authority while
/// staging bytes and must never forward it into the hostile MicroVM.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestFileWriteRequest {
    pub effect: FileEffectIdentity,
    pub expected_generation: String,
    pub overwrite: bool,
    pub path: String,
    pub source: GuestFileWriteSource,
    pub target: SandboxTarget,
}

/// Closed identity for an effectful file/storage operation after storage authorities have been
/// consumed by the trusted adapter. It contains no object URL, header, or secret.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEffectIdentity {
    pub kind: FileEffectKind,
    pub operation_id: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileEffectKind {
    Write,
    CopyImport,
    CopyExport,
}

/// The only retained file-effect values. Canonical transfer authorities are deliberately absent.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
pub enum FileEffectStoredResult {
    Write(SandboxFileWriteResult),
    Copy(SandboxCopyResult),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "state", content = "result", rename_all = "snake_case")]
pub enum FileEffectReservation {
    New,
    Replay(Box<FileEffectStoredResult>),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum GuestFileWriteSource {
    #[serde(rename = "inline")]
    Inline { content_base64: String },
    #[serde(rename = "installed_object")]
    InstalledObject { object: ObjectReference },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub installed: bool,
    pub replayed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mebibyte_inline_file_and_envelope_fit_the_wire_frame() {
        let padded_base64_bytes = MAX_INLINE_FILE_BYTES.div_ceil(3) * 4;
        assert!(padded_base64_bytes + 16 * 1024 < MAX_WIRE_FRAME_BYTES);
    }

    #[test]
    fn secret_document_accepts_the_brain_exact_boundary_and_rejects_plus_one() {
        let names = vec!["A".into()];
        let exact_value = format!("{}aaaaaaaa", "é".repeat(2040));
        let exact = std::collections::HashMap::from([("A".into(), exact_value)]);
        assert_eq!(
            serde_jcs::to_vec(&exact).unwrap().len(),
            brain_protocol::MAX_SESSION_SECRET_DOCUMENT_BYTES
        );
        assert!(secret_material_fits(&names, &exact));

        let oversized_value = format!("{}aaaaaaaa€", "é".repeat(2039));
        let oversized = std::collections::HashMap::from([("A".into(), oversized_value)]);
        assert_eq!(
            serde_jcs::to_vec(&oversized).unwrap().len(),
            brain_protocol::MAX_SESSION_SECRET_DOCUMENT_BYTES + 1
        );
        assert!(!secret_material_fits(&names, &oversized));
        assert!(!environment_name_is_valid("A-B"));
        assert!(!environment_name_is_valid("9TOKEN"));
    }
}
