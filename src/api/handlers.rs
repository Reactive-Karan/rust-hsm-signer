//! HTTP handlers. They validate and decode input, call the backend through
//! the [`KeyBackend`](crate::backend::KeyBackend) trait object and encode the
//! result; they contain no cryptography of their own except software
//! signature verification with an exported public key.

use std::time::Instant;

use axum::{
    Json,
    extract::{FromRequest, Path, Request, State, rejection::JsonRejection},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use super::{AppState, models::*};
use crate::{
    backend::{AEAD_ALGORITHM, BackendError, Envelope, SignAlgorithm, WRAP_ALGORITHM},
    crypto,
    error::ApiError,
};

/// Maximum accepted signature size (an RSA-4096 signature is 512 bytes).
const MAX_SIGNATURE_BYTES: usize = 1024;
/// Maximum accepted wrapped-key size (a padded AES-256 key wraps to 40 bytes).
const MAX_WRAPPED_KEY_BYTES: usize = 512;
/// Maximum length of a key identifier.
const MAX_KEY_ID_LEN: usize = 128;

/// `Json` extractor whose rejections are our JSON [`ApiError`]s.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::BodyTooLarge),
            Err(rejection) => Err(ApiError::bad_request("invalid_request", rejection.body_text())),
        }
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0
}

/// Validate a key identifier (used as `CKA_LABEL`).
pub fn validate_key_id(field: &'static str, key_id: &str) -> Result<(), ApiError> {
    let ok = !key_id.is_empty()
        && key_id.len() <= MAX_KEY_ID_LEN
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "invalid_key_id",
            format!("`{field}` must be 1-{MAX_KEY_ID_LEN} characters of [A-Za-z0-9._-]"),
        ))
    }
}

pub fn parse_algorithm(raw: &str) -> Result<SignAlgorithm, ApiError> {
    raw.parse().map_err(|e: crate::backend::UnsupportedAlgorithm| {
        let supported: Vec<_> = SignAlgorithm::ALL.iter().map(|a| a.as_str()).collect();
        ApiError::bad_request(
            "unsupported_algorithm",
            format!("{e}; supported: {}", supported.join(", ")),
        )
    })
}

/// Decode a base64 field, enforcing a decoded-size limit *before* decoding.
pub fn decode_b64(field: &'static str, value: &str, max_len: usize) -> Result<Vec<u8>, ApiError> {
    // 4 base64 chars encode 3 bytes: reject oversized input without allocating.
    if value.len() > max_len.div_ceil(3) * 4 {
        return Err(ApiError::bad_request(
            "payload_too_large",
            format!("`{field}` exceeds the maximum of {max_len} bytes"),
        ));
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ApiError::bad_request("invalid_base64", format!("`{field}` is not valid base64")))?;
    if decoded.len() > max_len {
        return Err(ApiError::bad_request(
            "payload_too_large",
            format!("`{field}` exceeds the maximum of {max_len} bytes"),
        ));
    }
    Ok(decoded)
}

fn decode_optional_b64(field: &'static str, value: Option<&str>, max_len: usize) -> Result<Vec<u8>, ApiError> {
    value.map_or(Ok(Vec::new()), |v| decode_b64(field, v, max_len))
}

/// `POST /v1/sign`
pub async fn sign(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    validate_key_id("key_id", &req.key_id)?;
    let algorithm = parse_algorithm(&req.algorithm)?;
    let payload = decode_b64("payload", &req.payload, state.max_payload_bytes)?;
    let started = Instant::now();
    let signature = state.backend.sign(&req.key_id, algorithm, payload).await?;
    Ok(Json(SignResponse {
        duration_ms: elapsed_ms(started),
        key_id: req.key_id,
        algorithm: algorithm.as_str().to_string(),
        signature: STANDARD.encode(signature),
    }))
}

/// `POST /v1/verify`
pub async fn verify(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    validate_key_id("key_id", &req.key_id)?;
    let algorithm = parse_algorithm(&req.algorithm)?;
    let payload = decode_b64("payload", &req.payload, state.max_payload_bytes)?;
    let signature = decode_b64("signature", &req.signature, MAX_SIGNATURE_BYTES)?;
    let started = Instant::now();
    let valid = match req.verifier {
        Verifier::Software => {
            let public_key = state.backend.public_key(&req.key_id).await?;
            if public_key.key_type != algorithm.key_type() {
                return Err(BackendError::KeyAlgorithmMismatch {
                    key_id: req.key_id,
                    algorithm: algorithm.to_string(),
                }
                .into());
            }
            crypto::verify_with_spki(algorithm, &public_key.spki_der, &payload, &signature)
                .map_err(|e| BackendError::Internal(e.to_string()))?
        }
        Verifier::Hsm => state.backend.verify(&req.key_id, algorithm, payload, signature).await?,
    };
    Ok(Json(VerifyResponse {
        duration_ms: elapsed_ms(started),
        key_id: req.key_id,
        algorithm: algorithm.as_str().to_string(),
        valid,
        verifier: req.verifier,
    }))
}

/// `GET /v1/keys/{key_id}/public`
pub async fn public_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    validate_key_id("key_id", &key_id)?;
    let pk = state.backend.public_key(&key_id).await?;
    Ok(Json(PublicKeyResponse {
        algorithms: SignAlgorithm::ALL
            .into_iter()
            .filter(|a| a.key_type() == pk.key_type)
            .map(SignAlgorithm::as_str)
            .collect(),
        public_key_pem: pk.to_pem(),
        public_key_der: STANDARD.encode(&pk.spki_der),
        key_type: pk.key_type,
        key_id: pk.key_id,
    }))
}

/// `GET /v1/keys`
pub async fn list_keys(State(state): State<AppState>) -> Result<Json<KeysResponse>, ApiError> {
    Ok(Json(KeysResponse {
        keys: state.backend.list_keys().await?,
    }))
}

/// `POST /v1/encrypt` — AES-256-GCM with a non-extractable key in the HSM.
pub async fn encrypt(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    validate_key_id("key_id", &req.key_id)?;
    let plaintext = Zeroizing::new(decode_b64("plaintext", &req.plaintext, state.max_payload_bytes)?);
    let aad = decode_optional_b64("aad", req.aad.as_deref(), state.max_payload_bytes)?;
    let started = Instant::now();
    let out = state.backend.encrypt(&req.key_id, plaintext, aad).await?;
    Ok(Json(EncryptResponse {
        duration_ms: elapsed_ms(started),
        key_id: req.key_id,
        algorithm: AEAD_ALGORITHM.to_string(),
        iv: STANDARD.encode(out.iv),
        ciphertext: STANDARD.encode(out.ciphertext),
    }))
}

/// `POST /v1/decrypt`
pub async fn decrypt(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    validate_key_id("key_id", &req.key_id)?;
    let iv = decode_b64("iv", &req.iv, 64)?;
    let ciphertext = decode_b64("ciphertext", &req.ciphertext, state.max_payload_bytes + 16)?;
    let aad = decode_optional_b64("aad", req.aad.as_deref(), state.max_payload_bytes)?;
    let started = Instant::now();
    let plaintext = state.backend.decrypt(&req.key_id, iv, ciphertext, aad).await?;
    Ok(Json(DecryptResponse {
        duration_ms: elapsed_ms(started),
        key_id: req.key_id,
        plaintext: STANDARD.encode(plaintext.as_slice()),
    }))
}

/// `POST /v1/envelope/encrypt` — key-wrapping workflow (see README).
pub async fn envelope_encrypt(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<EnvelopeEncryptRequest>,
) -> Result<Json<EnvelopeEncryptResponse>, ApiError> {
    validate_key_id("wrapping_key_id", &req.wrapping_key_id)?;
    let plaintext = Zeroizing::new(decode_b64("plaintext", &req.plaintext, state.max_payload_bytes)?);
    let aad = decode_optional_b64("aad", req.aad.as_deref(), state.max_payload_bytes)?;
    let started = Instant::now();
    let env = state
        .backend
        .envelope_encrypt(&req.wrapping_key_id, plaintext, aad)
        .await?;
    Ok(Json(EnvelopeEncryptResponse {
        duration_ms: elapsed_ms(started),
        wrapping_key_id: req.wrapping_key_id,
        wrap_algorithm: WRAP_ALGORITHM.to_string(),
        wrapped_key: STANDARD.encode(env.wrapped_key),
        algorithm: AEAD_ALGORITHM.to_string(),
        iv: STANDARD.encode(env.iv),
        ciphertext: STANDARD.encode(env.ciphertext),
    }))
}

/// `POST /v1/envelope/decrypt`
pub async fn envelope_decrypt(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<EnvelopeDecryptRequest>,
) -> Result<Json<EnvelopeDecryptResponse>, ApiError> {
    validate_key_id("wrapping_key_id", &req.wrapping_key_id)?;
    let envelope = Envelope {
        wrapped_key: decode_b64("wrapped_key", &req.wrapped_key, MAX_WRAPPED_KEY_BYTES)?,
        iv: decode_b64("iv", &req.iv, 64)?,
        ciphertext: decode_b64("ciphertext", &req.ciphertext, state.max_payload_bytes + 16)?,
    };
    let aad = decode_optional_b64("aad", req.aad.as_deref(), state.max_payload_bytes)?;
    let started = Instant::now();
    let plaintext = state
        .backend
        .envelope_decrypt(&req.wrapping_key_id, envelope, aad)
        .await?;
    Ok(Json(EnvelopeDecryptResponse {
        duration_ms: elapsed_ms(started),
        wrapping_key_id: req.wrapping_key_id,
        plaintext: STANDARD.encode(plaintext.as_slice()),
    }))
}

/// `GET /healthz` — liveness: the process is up and serving HTTP.
pub async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        backend: None,
        error: None,
    })
}

/// `GET /readyz` — readiness: a logged-in HSM session can be acquired now.
pub async fn readyz(State(state): State<AppState>) -> Response {
    match state.backend.health_check().await {
        Ok(()) => Json(HealthResponse {
            status: "ready".into(),
            backend: Some(state.backend.name().into()),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unavailable".into(),
                    backend: Some(state.backend.name().into()),
                    error: Some(e.code().into()),
                }),
            )
                .into_response()
        }
    }
}

/// `GET /metrics` — Prometheus text format.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_validation() {
        assert!(validate_key_id("key_id", "arkion-intermediate-prod").is_ok());
        assert!(validate_key_id("key_id", "a.b_c-1").is_ok());
        for bad in ["", "has space", "slash/inside", "ünïcode", &"x".repeat(129)] {
            assert!(validate_key_id("key_id", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn base64_limits() {
        assert_eq!(decode_b64("p", "aGVsbG8=", 5).unwrap(), b"hello");
        assert_eq!(decode_b64("p", "", 5).unwrap(), b"");
        let err = decode_b64("p", "aGVsbG8=", 4).unwrap_err();
        assert_eq!(err.code(), "payload_too_large");
        let err = decode_b64("p", "not base64!", 100).unwrap_err();
        assert_eq!(err.code(), "invalid_base64");
        // Huge input rejected before decoding.
        let err = decode_b64("p", &"A".repeat(10_000), 16).unwrap_err();
        assert_eq!(err.code(), "payload_too_large");
    }

    #[test]
    fn algorithm_parsing() {
        assert_eq!(parse_algorithm("ED25519").unwrap(), SignAlgorithm::Ed25519);
        let err = parse_algorithm("ES256").unwrap_err();
        assert_eq!(err.code(), "unsupported_algorithm");
    }
}
