//! `AbiError` constructors. Every refusal the hand sends goes through here.

use aex_contracts::abi::{AbiError, ErrorCode};
use serde_json::{Map, Value};

pub type AbiResult<T> = Result<T, AbiError>;

pub fn err(code: ErrorCode, message: impl Into<String>) -> AbiError {
    AbiError {
        code,
        message: message.into(),
        retryable: false,
        details: Map::new(),
    }
}

pub fn err_retryable(code: ErrorCode, message: impl Into<String>) -> AbiError {
    AbiError {
        code,
        message: message.into(),
        retryable: true,
        details: Map::new(),
    }
}

pub fn err_with(
    code: ErrorCode,
    message: impl Into<String>,
    details: Map<String, Value>,
) -> AbiError {
    AbiError {
        code,
        message: message.into(),
        retryable: false,
        details,
    }
}

pub fn internal(e: impl std::fmt::Display) -> AbiError {
    err(ErrorCode::Internal, e.to_string())
}

pub fn malformed(e: impl std::fmt::Display) -> AbiError {
    err(ErrorCode::MalformedRequest, e.to_string())
}
