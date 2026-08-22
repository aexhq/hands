use axum::http::StatusCode;
use brain_protocol::hand::{HandError, HandErrorCode};

/// HTTP projection of a Hand error for the install routes. The code and `retryable` flag carry
/// the real distinction; the status keeps plain HTTP clients from reading every failure as 409.
pub fn status_for(code: HandErrorCode) -> StatusCode {
    match code {
        HandErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        HandErrorCode::FileNotFound | HandErrorCode::OperationUnknown => StatusCode::NOT_FOUND,
        HandErrorCode::BindingConflict
        | HandErrorCode::OperationConflict
        | HandErrorCode::GenerationConflict
        | HandErrorCode::SandboxNotMaterialized => StatusCode::CONFLICT,
        HandErrorCode::SandboxGone => StatusCode::GONE,
        HandErrorCode::ResourceExhausted => StatusCode::PAYLOAD_TOO_LARGE,
        HandErrorCode::CapabilityUnavailable | HandErrorCode::TemporarilyUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

pub fn hand_error(code: HandErrorCode, retryable: bool, message: impl Into<String>) -> HandError {
    let mut message = message.into();
    if message.is_empty() {
        message = "Hand request failed".into();
    }
    truncate_utf8(&mut message, 4096);
    HandError {
        code,
        details: serde_json::Map::new(),
        message: message
            .parse()
            .unwrap_or_else(|_| "Hand request failed".parse().expect("bounded message")),
        retryable,
    }
}

pub(crate) fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

pub fn invalid(message: impl Into<String>) -> HandError {
    hand_error(HandErrorCode::InvalidRequest, false, message)
}

pub fn unavailable(message: impl Into<String>) -> HandError {
    hand_error(HandErrorCode::TemporarilyUnavailable, true, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_unicode_diagnostics_truncate_only_on_a_character_boundary() {
        let error = invalid("x".repeat(4095) + "🦀tail");
        assert!(error.message.as_str().len() <= 4096);
        assert!(error.message.as_str().ends_with('x'));
    }
}
