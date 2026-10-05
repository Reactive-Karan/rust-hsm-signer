//! Logging and tracing setup.
//!
//! * Structured logs via `tracing-subscriber` (JSON by default) written by a
//!   background thread so request threads never block on stdout.
//! * Spans: `http.request` → `hsm.operation` → `pkcs11.call`, with the
//!   request id, key id, algorithm, outcome and duration as fields.
//! * With the `otel` feature *and* `OTEL_EXPORTER_OTLP_ENDPOINT` set, the same
//!   spans are exported via OTLP/HTTP, and W3C `traceparent` headers on
//!   incoming requests are honoured. Without a collector nothing changes.

use axum::http::HeaderMap;
use tracing::Span;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LogFormat;

/// Keeps the log writer and (optionally) the OTLP pipeline alive; flushes
/// both on drop.
pub struct TelemetryGuard {
    _log_writer: tracing_appender::non_blocking::WorkerGuard,
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("failed to flush OpenTelemetry spans: {e}");
        }
    }
}

/// Where log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    /// The service logs to stdout (container convention).
    Stdout,
    /// CLI subcommands log to stderr so stdout carries only their output.
    Stderr,
}

/// Install the global subscriber. Call once, before starting the runtime.
pub fn init(format: LogFormat, target: LogTarget) -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_appender::non_blocking::NonBlockingBuilder::default().lossy(false);
    let (writer, log_writer_guard) = match target {
        LogTarget::Stdout => builder.finish(std::io::stdout()),
        LogTarget::Stderr => builder.finish(std::io::stderr()),
    };

    let fmt_layer = match format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_current_span(false)
            .with_span_list(true)
            .flatten_event(true)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer().with_writer(writer).boxed(),
    };

    #[cfg(feature = "otel")]
    let (otel_layer, provider) = match otel::layer()? {
        Some((layer, provider)) => (Some(layer), Some(provider)),
        None => (None, None),
    };
    #[cfg(not(feature = "otel"))]
    let otel_layer: Option<tracing_subscriber::layer::Identity> = None;

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()?;

    Ok(TelemetryGuard {
        _log_writer: log_writer_guard,
        #[cfg(feature = "otel")]
        provider,
    })
}

/// Continue a distributed trace from W3C `traceparent` headers (no-op
/// without the `otel` feature).
pub fn set_parent_from_headers(span: &Span, headers: &HeaderMap) {
    #[cfg(feature = "otel")]
    otel::set_parent(span, headers);
    #[cfg(not(feature = "otel"))]
    let _ = (span, headers);
}

#[cfg(feature = "otel")]
mod otel {
    use axum::http::HeaderMap;
    use opentelemetry::{propagation::Extractor, trace::TracerProvider as _};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::Layer;

    type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync>;

    /// Build the OTLP layer if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
    pub fn layer<S>() -> anyhow::Result<Option<(BoxedLayer<S>, SdkTracerProvider)>>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync,
    {
        let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") else {
            return Ok(None);
        };
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .build()?;
        let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "hsm-signer".into());
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(Resource::builder().with_service_name(service_name).build())
            .build();
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let tracer = provider.tracer("hsm-signer");
        let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
        Ok(Some((layer, provider)))
    }

    struct HeaderExtractor<'a>(&'a HeaderMap);

    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    pub fn set_parent(span: &Span, headers: &HeaderMap) {
        if !headers.contains_key("traceparent") {
            return;
        }
        let cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(headers)));
        let _ = span.set_parent(cx);
    }
}
