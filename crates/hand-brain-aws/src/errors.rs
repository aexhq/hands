//! HandError constructors and storage/materialization error classification.

use crate::*;

pub(crate) fn preparation_cache_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process session preparation metadata budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_preparation_cache_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value.details.insert(
        "entry_limit".into(),
        (MAX_CACHED_PREPARATIONS as u64).into(),
    );
    value
}

pub(crate) fn bundle_cache_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process verified bundle memory budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_cache_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value
}

pub(crate) fn bundle_fetch_capacity_error(limit_bytes: usize) -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process cold bundle fetch budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_fetch_bytes".into());
    value
        .details
        .insert("limit_bytes".into(), (limit_bytes as u64).into());
    value
}

pub(crate) fn bundle_cache_entry_capacity_error() -> HandError {
    let mut value = error(
        HandErrorCode::ResourceExhausted,
        true,
        "the in-process verified bundle entry budget is full",
    );
    value
        .details
        .insert("scope".into(), "hand_bundle_cache_entries".into());
    value
        .details
        .insert("limit".into(), (MAX_CACHED_BUNDLES as u64).into());
    value
}

pub(crate) fn invalid(message: impl Into<String>) -> HandError {
    error(HandErrorCode::InvalidRequest, false, message)
}

/// A reply variant that does not match the request method is a host/guest contract violation
/// (for example protocol-version skew), never a transient fault: a retry replays the exact same
/// mismatch, so fail fast and non-retryable.
pub(crate) fn wrong_reply(context: &'static str) -> HandError {
    error(
        HandErrorCode::InvalidRequest,
        false,
        format!("guest returned the wrong {context} reply"),
    )
}

pub(crate) fn binding_error(message: impl Into<String>) -> HandError {
    error(HandErrorCode::BindingConflict, false, message)
}

pub(crate) fn generation_error() -> HandError {
    error(
        HandErrorCode::GenerationConflict,
        false,
        "request does not match the live sandbox generation",
    )
}

/// Once the operation submit RPC has been attempted, loss of its physical generation cannot prove
/// that the guest effect did not start. Brain has durable intent but may not yet have received the
/// operation receipt, so returning `sandbox_gone` would let recovery route the target-less intent
/// into a replacement generation. Preserve the uncertainty explicitly and never repeat the effect.
pub(crate) fn classify_submit_delivery_error(error_value: HandError) -> HandError {
    if error_value.code == HandErrorCode::SandboxGone {
        error(
            HandErrorCode::OperationUnknown,
            false,
            "managed operation delivery became unknown when its physical generation was lost",
        )
    } else {
        error_value
    }
}

pub(crate) fn definition_error(error_value: DefinitionError) -> HandError {
    match error_value {
        DefinitionError::Conflict => binding_error(error_value.to_string()),
        DefinitionError::Storage(_) => temporary(error_value.to_string()),
        _ => invalid(error_value.to_string()),
    }
}

pub(crate) fn root_seal_error(error_value: DefinitionError) -> HandError {
    if error_value == DefinitionError::Conflict {
        error(
            HandErrorCode::GenerationConflict,
            false,
            "root sandbox network/resource seal conflicts with an earlier preparation",
        )
    } else {
        definition_error(error_value)
    }
}

pub(crate) fn materialization_error(error_value: MaterializationError) -> HandError {
    match error_value {
        MaterializationError::Capacity {
            scope,
            retry_after_ms,
            message,
        } => {
            let mut value = error(HandErrorCode::ResourceExhausted, true, message);
            value.details.insert("scope".into(), scope.into());
            value
                .details
                .insert("retry_after_ms".into(), retry_after_ms.into());
            value
        }
        MaterializationError::Pending { retry_after_ms } => {
            let mut value = temporary(error_value.to_string());
            value
                .details
                .insert("retry_after_ms".into(), retry_after_ms.into());
            value
        }
        MaterializationError::Gone | MaterializationError::Terminated => {
            error(HandErrorCode::SandboxGone, false, error_value.to_string())
        }
        MaterializationError::SpecConflict => error(
            HandErrorCode::GenerationConflict,
            false,
            error_value.to_string(),
        ),
        MaterializationError::Storage(_)
        | MaterializationError::LaunchRetryable(_)
        | MaterializationError::LaunchOutcomeUnknown(_)
        | MaterializationError::ReservationLost { .. } => temporary(error_value.to_string()),
        MaterializationError::LaunchRejected(_) => error(
            HandErrorCode::CapabilityUnavailable,
            false,
            error_value.to_string(),
        ),
        _ => invalid(error_value.to_string()),
    }
}
