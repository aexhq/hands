use brain_protocol::hand::{HandError, HandErrorCode};

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

fn truncate_utf8(value: &mut String, max_bytes: usize) {
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
