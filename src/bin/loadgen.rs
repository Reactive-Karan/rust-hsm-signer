//! Closed-loop load generator for `POST /v1/sign`.
//!
//! For each concurrency level, N workers each keep exactly one request in
//! flight for the configured duration (after a warm-up). Reports throughput,
//! latency percentiles of successful requests, error rate and an error
//! breakdown by HTTP status / API error code.
//!
//! ```text
//! cargo run --release --bin loadgen -- --url http://127.0.0.1:8080 \
//!     --concurrency 1,10,100,500 --duration 15
//! ```

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Markdown,
    Json,
}

#[derive(Parser, Debug)]
#[command(about = "Load generator for the HSM signing service")]
struct Args {
    /// Base URL of the service.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Comma-separated concurrency levels.
    #[arg(long, value_delimiter = ',', default_value = "1,10,100,500")]
    concurrency: Vec<usize>,
    /// Measured duration per level, in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,
    /// Warm-up per level (not measured), in seconds.
    #[arg(long, default_value_t = 2)]
    warmup: u64,
    #[arg(long, default_value = "arkion-intermediate-prod")]
    key_id: String,
    #[arg(long, default_value = "ECDSA_P256_SHA256")]
    algorithm: String,
    /// Size of the random payload to sign, in bytes.
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    /// Per-request client timeout, in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,
    /// Free-form label printed with the results (e.g. "pool=8").
    #[arg(long, default_value = "")]
    label: String,
    #[arg(long, value_enum, default_value = "markdown")]
    format: Format,
}

#[derive(Default)]
struct WorkerStats {
    latencies_us: Option<Histogram<u64>>,
    ok: u64,
    errors: BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct LevelReport {
    label: String,
    algorithm: String,
    concurrency: usize,
    duration_s: f64,
    requests: u64,
    ok: u64,
    errors: u64,
    error_rate: f64,
    throughput_ok_per_s: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    error_breakdown: BTreeMap<String, u64>,
}

fn new_histogram() -> Histogram<u64> {
    // 1 µs .. 120 s, 3 significant digits.
    Histogram::new_with_bounds(1, 120_000_000, 3).expect("valid histogram bounds")
}

async fn worker(client: reqwest::Client, url: Arc<str>, body: Bytes, deadline: Instant) -> WorkerStats {
    let mut stats = WorkerStats {
        latencies_us: Some(new_histogram()),
        ..Default::default()
    };
    while Instant::now() < deadline {
        let started = Instant::now();
        let result = client
            .post(&*url)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await;
        let outcome = match result {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(_) => None,
                Err(e) => Some(format!("body: {}", classify(&e))),
            },
            Ok(resp) => {
                let status = resp.status().as_u16();
                let code = resp
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| "-".into());
                Some(format!("HTTP {status} {code}"))
            }
            Err(e) => Some(format!("transport: {}", classify(&e))),
        };
        let elapsed_us = started.elapsed().as_micros() as u64;
        match outcome {
            None => {
                stats.ok += 1;
                if let Some(h) = stats.latencies_us.as_mut() {
                    h.saturating_record(elapsed_us.max(1));
                }
            }
            Some(err) => *stats.errors.entry(err).or_default() += 1,
        }
    }
    stats
}

fn classify(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_request() {
        "request"
    } else {
        "other"
    }
}

async fn run_level(args: &Args, concurrency: usize, body: Bytes, seconds: u64) -> (WorkerStats, Duration) {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(concurrency)
        .tcp_nodelay(true)
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()
        .expect("HTTP client");
    let url: Arc<str> = format!("{}/v1/sign", args.url.trim_end_matches('/')).into();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let handles: Vec<_> = (0..concurrency)
        .map(|_| tokio::spawn(worker(client.clone(), Arc::clone(&url), body.clone(), deadline)))
        .collect();
    let mut total = WorkerStats {
        latencies_us: Some(new_histogram()),
        ..Default::default()
    };
    for h in handles {
        let s = h.await.expect("worker panicked");
        total.ok += s.ok;
        for (k, v) in s.errors {
            *total.errors.entry(k).or_default() += v;
        }
        if let (Some(t), Some(w)) = (total.latencies_us.as_mut(), s.latencies_us.as_ref()) {
            t.add(w).expect("compatible histograms");
        }
    }
    (total, started.elapsed())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut payload = vec![0u8; args.payload_bytes];
    getrandom::fill(&mut payload).expect("OS RNG");
    let body = Bytes::from(
        serde_json::json!({
            "key_id": args.key_id,
            "algorithm": args.algorithm,
            "payload": STANDARD.encode(&payload),
        })
        .to_string(),
    );

    if matches!(args.format, Format::Markdown) {
        println!(
            "| label | algorithm | concurrency | requests | throughput (ok/s) | p50 ms | p95 ms | p99 ms | max ms | error rate | errors |"
        );
        println!("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|");
    }
    for &concurrency in &args.concurrency {
        if args.warmup > 0 {
            run_level(&args, concurrency, body.clone(), args.warmup).await;
        }
        let (stats, elapsed) = run_level(&args, concurrency, body.clone(), args.duration).await;
        let errors: u64 = stats.errors.values().sum();
        let requests = stats.ok + errors;
        let h = stats.latencies_us.expect("histogram");
        let pct = |q: f64| {
            if stats.ok == 0 {
                0.0
            } else {
                h.value_at_quantile(q) as f64 / 1000.0
            }
        };
        let report = LevelReport {
            label: args.label.clone(),
            algorithm: args.algorithm.clone(),
            concurrency,
            duration_s: elapsed.as_secs_f64(),
            requests,
            ok: stats.ok,
            errors,
            error_rate: if requests == 0 {
                0.0
            } else {
                errors as f64 / requests as f64
            },
            throughput_ok_per_s: stats.ok as f64 / elapsed.as_secs_f64(),
            p50_ms: pct(0.50),
            p95_ms: pct(0.95),
            p99_ms: pct(0.99),
            max_ms: if stats.ok == 0 { 0.0 } else { h.max() as f64 / 1000.0 },
            error_breakdown: stats.errors,
        };
        match args.format {
            Format::Json => println!("{}", serde_json::to_string(&report).expect("serializable")),
            Format::Markdown => {
                let breakdown = if report.error_breakdown.is_empty() {
                    "-".to_string()
                } else {
                    report
                        .error_breakdown
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                };
                println!(
                    "| {} | {} | {} | {} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2}% | {} |",
                    report.label,
                    report.algorithm,
                    report.concurrency,
                    report.requests,
                    report.throughput_ok_per_s,
                    report.p50_ms,
                    report.p95_ms,
                    report.p99_ms,
                    report.max_ms,
                    report.error_rate * 100.0,
                    breakdown
                );
            }
        }
    }
}
