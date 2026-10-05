//! Prometheus metrics.
//!
//! Each [`Metrics`] owns its own [`Registry`] (no global state), which keeps
//! tests independent and makes the dependency explicit.

use std::time::Duration;

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};

/// Latency buckets (seconds) tuned for HSM operations: sub-millisecond for
/// SoftHSM up to seconds for a saturated network HSM.
const LATENCY_BUCKETS: &[f64] = &[
    0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// All service metrics.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    /// Sign latency by algorithm and outcome (`ok` / error code).
    pub sign_duration: HistogramVec,
    /// Latency of every backend operation by operation name and outcome.
    pub operation_duration: HistogramVec,
    /// Failures by operation and reason (stable error code).
    pub operation_failures: IntCounterVec,
    /// Configured number of sessions in the pool.
    pub pool_size: IntGauge,
    /// Sessions currently checked out of the pool.
    pub pool_in_use: IntGauge,
    /// Sessions currently open (lazily opened, may be < pool_size).
    pub pool_open_sessions: IntGauge,
    /// Requests currently waiting for a session.
    pub pool_waiters: IntGauge,
    /// Time spent waiting for a session.
    pub pool_acquire_wait: Histogram,
    /// Callers that gave up after `HSM_ACQUIRE_TIMEOUT_MS`.
    pub pool_acquire_timeouts: IntCounter,
    /// Callers rejected immediately because `HSM_MAX_WAITERS` was reached.
    pub pool_rejections: IntCounter,
    /// Sessions discarded because the token reported them invalid.
    pub pool_sessions_discarded: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some("hsm_signer".into()), None).expect("valid registry prefix");

        let sign_duration = HistogramVec::new(
            HistogramOpts::new("sign_duration_seconds", "Latency of signing operations")
                .buckets(LATENCY_BUCKETS.to_vec()),
            &["algorithm", "outcome"],
        )
        .expect("valid metric");
        let operation_duration = HistogramVec::new(
            HistogramOpts::new("operation_duration_seconds", "Latency of key backend operations")
                .buckets(LATENCY_BUCKETS.to_vec()),
            &["operation", "outcome"],
        )
        .expect("valid metric");
        let operation_failures = IntCounterVec::new(
            Opts::new("operation_failures_total", "Failed key backend operations by reason"),
            &["operation", "reason"],
        )
        .expect("valid metric");
        let pool_size = IntGauge::new("pool_size", "Configured HSM session pool size").expect("valid metric");
        let pool_in_use = IntGauge::new("pool_in_use", "HSM sessions currently in use").expect("valid metric");
        let pool_open_sessions =
            IntGauge::new("pool_open_sessions", "HSM sessions currently open").expect("valid metric");
        let pool_waiters = IntGauge::new("pool_waiters", "Requests waiting for an HSM session").expect("valid metric");
        let pool_acquire_wait = Histogram::with_opts(
            HistogramOpts::new("pool_acquire_wait_seconds", "Time spent waiting for an HSM session")
                .buckets(LATENCY_BUCKETS.to_vec()),
        )
        .expect("valid metric");
        let pool_acquire_timeouts = IntCounter::new(
            "pool_acquire_timeouts_total",
            "Requests that timed out waiting for an HSM session",
        )
        .expect("valid metric");
        let pool_rejections = IntCounter::new(
            "pool_rejections_total",
            "Requests rejected immediately because the wait queue was full",
        )
        .expect("valid metric");
        let pool_sessions_discarded = IntCounter::new(
            "pool_sessions_discarded_total",
            "HSM sessions discarded after the token reported them invalid",
        )
        .expect("valid metric");

        for collector in [
            Box::new(sign_duration.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(operation_duration.clone()),
            Box::new(operation_failures.clone()),
            Box::new(pool_size.clone()),
            Box::new(pool_in_use.clone()),
            Box::new(pool_open_sessions.clone()),
            Box::new(pool_waiters.clone()),
            Box::new(pool_acquire_wait.clone()),
            Box::new(pool_acquire_timeouts.clone()),
            Box::new(pool_rejections.clone()),
            Box::new(pool_sessions_discarded.clone()),
        ] {
            registry.register(collector).expect("metric registered once");
        }

        Self {
            registry,
            sign_duration,
            operation_duration,
            operation_failures,
            pool_size,
            pool_in_use,
            pool_open_sessions,
            pool_waiters,
            pool_acquire_wait,
            pool_acquire_timeouts,
            pool_rejections,
            pool_sessions_discarded,
        }
    }

    /// Record the outcome of a backend operation.
    pub fn observe_operation(&self, operation: &str, elapsed: Duration, error_code: Option<&str>) {
        let outcome = error_code.unwrap_or("ok");
        self.operation_duration
            .with_label_values(&[operation, outcome])
            .observe(elapsed.as_secs_f64());
        if let Some(reason) = error_code {
            self.operation_failures.with_label_values(&[operation, reason]).inc();
        }
    }

    /// Record a signing operation (in addition to `observe_operation`).
    pub fn observe_sign(&self, algorithm: &str, elapsed: Duration, error_code: Option<&str>) {
        self.sign_duration
            .with_label_values(&[algorithm, error_code.unwrap_or("ok")])
            .observe(elapsed.as_secs_f64());
        self.observe_operation("sign", elapsed, error_code);
    }

    /// Render all metrics in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        if let Err(e) = TextEncoder::new().encode(&self.registry.gather(), &mut buf) {
            tracing::error!(error = %e, "failed to encode metrics");
        }
        String::from_utf8(buf).unwrap_or_default()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_expected_series() {
        let m = Metrics::new();
        m.observe_sign("ECDSA_P256_SHA256", Duration::from_millis(3), None);
        m.observe_sign("ECDSA_P256_SHA256", Duration::from_millis(3), Some("pool_exhausted"));
        m.pool_size.set(8);
        let text = m.render();
        assert!(text.contains("hsm_signer_sign_duration_seconds_bucket"));
        assert!(text.contains(r#"hsm_signer_operation_failures_total{operation="sign",reason="pool_exhausted"} 1"#));
        assert!(text.contains("hsm_signer_pool_size 8"));
        assert!(text.contains("hsm_signer_pool_acquire_timeouts_total 0"));
    }
}
