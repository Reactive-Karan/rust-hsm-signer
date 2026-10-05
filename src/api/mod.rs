//! HTTP API (Axum).

pub mod handlers;
pub mod models;
#[cfg(test)]
mod tests;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{DefaultBodyLimit, MatchedPath, Request},
    http::{HeaderName, StatusCode},
    response::Response,
    routing::{get, post},
};
use tower::ServiceBuilder;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{Span, field};

use crate::{backend::KeyBackend, metrics::Metrics};

/// Shared handler state. Handlers depend only on the `KeyBackend` trait.
#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<dyn KeyBackend>,
    pub metrics: Arc<Metrics>,
    pub max_payload_bytes: usize,
}

/// Router-level settings.
#[derive(Debug, Clone, Copy)]
pub struct RouterSettings {
    pub request_timeout: Duration,
    pub max_payload_bytes: usize,
}

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

fn make_span(req: &Request) -> Span {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| req.uri().path().to_owned(), |p| p.as_str().to_owned());
    let request_id = req
        .headers()
        .get(&REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    let span = tracing::info_span!(
        "http.request",
        otel.name = %format!("{} {}", req.method(), route),
        otel.kind = "server",
        http.request.method = %req.method(),
        http.route = %route,
        request_id = %request_id,
        http.response.status_code = field::Empty,
    );
    crate::telemetry::set_parent_from_headers(&span, req.headers());
    span
}

fn on_response(res: &Response, latency: Duration, span: &Span) {
    span.record("http.response.status_code", res.status().as_u16());
    tracing::info!(
        status = res.status().as_u16(),
        latency_ms = latency.as_secs_f64() * 1000.0,
        "request completed"
    );
}

/// Build the application router.
pub fn router(state: AppState, settings: RouterSettings) -> Router {
    // JSON + base64 overhead (4/3) plus room for the other fields.
    let body_limit = settings.max_payload_bytes.div_ceil(3) * 4 * 2 + 16 * 1024;

    let api = Router::new()
        .route("/v1/sign", post(handlers::sign))
        .route("/v1/verify", post(handlers::verify))
        .route("/v1/keys", get(handlers::list_keys))
        .route("/v1/keys/{key_id}/public", get(handlers::public_key))
        .route("/v1/encrypt", post(handlers::encrypt))
        .route("/v1/decrypt", post(handlers::decrypt))
        .route("/v1/envelope/encrypt", post(handlers::envelope_encrypt))
        .route("/v1/envelope/decrypt", post(handlers::envelope_decrypt))
        // End-to-end deadline for API calls (not for probes/metrics).
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            settings.request_timeout,
        ));

    Router::new()
        .merge(api)
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route("/metrics", get(handlers::metrics))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(make_span)
                        .on_request(())
                        .on_response(on_response),
                )
                .layer(PropagateRequestIdLayer::new(REQUEST_ID)),
        )
        .with_state(state)
}
