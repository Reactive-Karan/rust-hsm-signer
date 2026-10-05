//! Error types.
//!
//! [`BackendError`] is the domain error returned by every [`KeyBackend`]
//! implementation. [`ApiError`] is the HTTP-facing error: it maps domain errors
//! to status codes and a stable machine-readable `error` code, and makes sure
//! internal details (PKCS#11 return values, module paths, ...) never leak to
//! clients. Details are logged server-side instead.
//!
//! [`KeyBackend`]: crate::backend::KeyBackend

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Errors produced by key backends.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("key `{0}` not found")]
    KeyNotFound(String),

    #[error("key `{key_id}` cannot be used with algorithm {algorithm}")]
    KeyAlgorithmMismatch { key_id: String, algorithm: String },

    #[error("key `{key_id}` does not support the {operation} operation")]
    UnsupportedOperation { key_id: String, operation: &'static str },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// AES-GCM tag mismatch or a wrapped key that fails its integrity check.
    #[error("integrity check failed (tampered ciphertext, wrong AAD/IV or wrong key)")]
    IntegrityCheckFailed,

    /// Too many callers already queued for a session: shed load immediately.
    #[error("too many requests are waiting for an HSM session")]
    PoolExhausted,

    /// Waited `HSM_ACQUIRE_TIMEOUT_MS` without obtaining a session.
    #[error("timed out waiting for an HSM session")]
    AcquireTimeout,

    /// The PKCS#11 call itself exceeded `HSM_OP_TIMEOUT_MS`.
    #[error("HSM operation timed out")]
    OperationTimeout,

    /// Token missing, login failure, cannot open sessions, ...
    #[error("HSM unavailable: {0}")]
    Unavailable(String),

    /// The HSM returned an unexpected error for an operation.
    #[error("HSM error during {operation}: {detail}")]
    Hsm { operation: &'static str, detail: String },

    #[error("internal error: {0}")]
    Internal(String),
}

impl BackendError {
    /// Stable, low-cardinality reason string. Used as the API `error` code and
    /// as the `reason` label on failure metrics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyNotFound(_) => "key_not_found",
            Self::KeyAlgorithmMismatch { .. } => "algorithm_key_mismatch",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::InvalidInput(_) => "invalid_request",
            Self::IntegrityCheckFailed => "integrity_check_failed",
            Self::PoolExhausted => "pool_exhausted",
            Self::AcquireTimeout => "session_acquire_timeout",
            Self::OperationTimeout => "hsm_timeout",
            Self::Unavailable(_) => "hsm_unavailable",
            Self::Hsm { .. } => "hsm_error",
            Self::Internal(_) => "internal_error",
        }
    }
}

/// Errors returned by HTTP handlers.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{message}")]
    BadRequest { code: &'static str, message: String },

    #[error("request body is too large")]
    BodyTooLarge,

    #[error(transparent)]
    Backend(#[from] BackendError),
}

impl ApiError {
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Backend(e) => match e {
                BackendError::KeyNotFound(_) => StatusCode::NOT_FOUND,
                BackendError::KeyAlgorithmMismatch { .. }
                | BackendError::UnsupportedOperation { .. }
                | BackendError::InvalidInput(_)
                | BackendError::IntegrityCheckFailed => StatusCode::BAD_REQUEST,
                BackendError::PoolExhausted | BackendError::AcquireTimeout | BackendError::Unavailable(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                BackendError::OperationTimeout => StatusCode::GATEWAY_TIMEOUT,
                BackendError::Hsm { .. } => StatusCode::BAD_GATEWAY,
                BackendError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { code, .. } => code,
            Self::BodyTooLarge => "payload_too_large",
            Self::Backend(e) => e.code(),
        }
    }

    /// Seconds a client should wait before retrying, for retryable errors.
    fn retry_after(&self) -> Option<u32> {
        match self {
            Self::Backend(
                BackendError::PoolExhausted | BackendError::AcquireTimeout | BackendError::OperationTimeout,
            ) => Some(1),
            Self::Backend(BackendError::Unavailable(_)) => Some(5),
            _ => None,
        }
    }

    /// Client-facing message. Server-side failures get a generic message so
    /// that PKCS#11 internals are never disclosed.
    fn public_message(&self) -> String {
        match self {
            Self::Backend(BackendError::Hsm { .. }) => "the HSM failed to process the request".into(),
            Self::Backend(BackendError::Unavailable(_)) => "the HSM is currently unavailable".into(),
            Self::Backend(BackendError::Internal(_)) => "internal server error".into(),
            other => other.to_string(),
        }
    }
}

/// JSON error body: `{"error": "<stable code>", "message": "<human text>"}`.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            // Full detail (e.g. the PKCS#11 return value) stays in the logs.
            tracing::error!(error.code = self.code(), error.detail = %self, "request failed");
        } else {
            tracing::info!(error.code = self.code(), error.detail = %self, "request rejected");
        }
        let body = ErrorBody {
            error: self.code().to_string(),
            message: self.public_message(),
        };
        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = self.retry_after() {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        let cases: Vec<(ApiError, StatusCode, &str)> = vec![
            (
                BackendError::KeyNotFound("k".into()).into(),
                StatusCode::NOT_FOUND,
                "key_not_found",
            ),
            (
                BackendError::KeyAlgorithmMismatch {
                    key_id: "k".into(),
                    algorithm: "ED25519".into(),
                }
                .into(),
                StatusCode::BAD_REQUEST,
                "algorithm_key_mismatch",
            ),
            (
                BackendError::PoolExhausted.into(),
                StatusCode::SERVICE_UNAVAILABLE,
                "pool_exhausted",
            ),
            (
                BackendError::AcquireTimeout.into(),
                StatusCode::SERVICE_UNAVAILABLE,
                "session_acquire_timeout",
            ),
            (
                BackendError::OperationTimeout.into(),
                StatusCode::GATEWAY_TIMEOUT,
                "hsm_timeout",
            ),
            (
                BackendError::Hsm {
                    operation: "C_Sign",
                    detail: "CKR_DEVICE_ERROR".into(),
                }
                .into(),
                StatusCode::BAD_GATEWAY,
                "hsm_error",
            ),
            (
                BackendError::Internal("x".into()).into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            (
                BackendError::IntegrityCheckFailed.into(),
                StatusCode::BAD_REQUEST,
                "integrity_check_failed",
            ),
            (
                ApiError::BodyTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
            ),
            (
                ApiError::bad_request("invalid_base64", "nope"),
                StatusCode::BAD_REQUEST,
                "invalid_base64",
            ),
        ];
        for (err, status, code) in cases {
            assert_eq!(err.status(), status, "{err:?}");
            assert_eq!(err.code(), code, "{err:?}");
        }
    }

    #[test]
    fn retry_after_only_on_retryable_errors() {
        let r = ApiError::from(BackendError::PoolExhausted).into_response();
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
        let r = ApiError::from(BackendError::AcquireTimeout).into_response();
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
        let r = ApiError::from(BackendError::KeyNotFound("k".into())).into_response();
        assert!(r.headers().get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn hsm_details_are_not_exposed() {
        let err = ApiError::from(BackendError::Hsm {
            operation: "C_Sign",
            detail: "CKR_DEVICE_ERROR at slot 0x1234".into(),
        });
        assert!(!err.public_message().contains("CKR_"));
        assert!(!err.public_message().contains("0x1234"));
    }
}
