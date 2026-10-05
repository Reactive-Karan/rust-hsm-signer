//! Decorator adding tracing spans, structured logs and metrics to any
//! [`KeyBackend`]. Keeps observability out of both the handlers and the
//! backend implementations.
//!
//! Logged fields: operation, key_id, algorithm, duration, outcome. Payloads,
//! plaintexts, signatures and key material are never logged.

use std::{future::Future, sync::Arc, time::Instant};

use async_trait::async_trait;
use tracing::{Instrument, field};

use super::{
    AeadCiphertext, BackendError, Envelope, KeyBackend, KeyDescriptor, Plaintext, PublicKeyInfo, SignAlgorithm,
};
use crate::metrics::Metrics;

/// Wraps a backend with spans, logs and metrics.
pub struct InstrumentedBackend {
    inner: Arc<dyn KeyBackend>,
    metrics: Arc<Metrics>,
}

impl InstrumentedBackend {
    pub fn new(inner: Arc<dyn KeyBackend>, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }

    async fn observe<T>(
        &self,
        operation: &'static str,
        key_id: &str,
        algorithm: Option<SignAlgorithm>,
        fut: impl Future<Output = Result<T, BackendError>> + Send,
    ) -> Result<T, BackendError> {
        let span = tracing::info_span!(
            "hsm.operation",
            otel.name = %format!("hsm.{operation}"),
            operation,
            backend = self.inner.name(),
            key_id,
            algorithm = algorithm.map(SignAlgorithm::as_str),
            outcome = field::Empty,
            duration_ms = field::Empty,
        );
        let started = Instant::now();
        let result = fut.instrument(span.clone()).await;
        let elapsed = started.elapsed();
        let code = result.as_ref().err().map(BackendError::code);
        match algorithm {
            Some(alg) if operation == "sign" => self.metrics.observe_sign(alg.as_str(), elapsed, code),
            _ => self.metrics.observe_operation(operation, elapsed, code),
        }
        let duration_ms = elapsed.as_secs_f64() * 1000.0;
        span.record("outcome", code.unwrap_or("ok"));
        span.record("duration_ms", duration_ms);
        span.in_scope(|| match code {
            None => tracing::info!(
                operation,
                key_id,
                algorithm = algorithm.map(SignAlgorithm::as_str),
                duration_ms,
                outcome = "ok",
                "hsm operation completed"
            ),
            Some(code) => tracing::warn!(
                operation,
                key_id,
                algorithm = algorithm.map(SignAlgorithm::as_str),
                duration_ms,
                outcome = code,
                "hsm operation failed"
            ),
        });
        result
    }
}

#[async_trait]
impl KeyBackend for InstrumentedBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn sign(&self, key_id: &str, algorithm: SignAlgorithm, payload: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.observe(
            "sign",
            key_id,
            Some(algorithm),
            self.inner.sign(key_id, algorithm, payload),
        )
        .await
    }

    async fn verify(
        &self,
        key_id: &str,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, BackendError> {
        self.observe(
            "verify",
            key_id,
            Some(algorithm),
            self.inner.verify(key_id, algorithm, payload, signature),
        )
        .await
    }

    async fn public_key(&self, key_id: &str) -> Result<PublicKeyInfo, BackendError> {
        self.observe("public_key", key_id, None, self.inner.public_key(key_id))
            .await
    }

    async fn encrypt(&self, key_id: &str, plaintext: Plaintext, aad: Vec<u8>) -> Result<AeadCiphertext, BackendError> {
        self.observe("encrypt", key_id, None, self.inner.encrypt(key_id, plaintext, aad))
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        self.observe("decrypt", key_id, None, self.inner.decrypt(key_id, iv, ciphertext, aad))
            .await
    }

    async fn envelope_encrypt(
        &self,
        wrapping_key_id: &str,
        plaintext: Plaintext,
        aad: Vec<u8>,
    ) -> Result<Envelope, BackendError> {
        self.observe(
            "envelope_encrypt",
            wrapping_key_id,
            None,
            self.inner.envelope_encrypt(wrapping_key_id, plaintext, aad),
        )
        .await
    }

    async fn envelope_decrypt(
        &self,
        wrapping_key_id: &str,
        envelope: Envelope,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        self.observe(
            "envelope_decrypt",
            wrapping_key_id,
            None,
            self.inner.envelope_decrypt(wrapping_key_id, envelope, aad),
        )
        .await
    }

    async fn list_keys(&self) -> Result<Vec<KeyDescriptor>, BackendError> {
        self.observe("list_keys", "*", None, self.inner.list_keys()).await
    }

    async fn health_check(&self) -> Result<(), BackendError> {
        // Not logged per call (probes are frequent); failures surface via /readyz.
        self.inner.health_check().await
    }
}
