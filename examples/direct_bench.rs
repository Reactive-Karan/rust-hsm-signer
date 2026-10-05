//! HSM-only throughput: calls `Pkcs11Backend::sign` directly (no HTTP, no
//! JSON) with N concurrent tasks, to separate the token's ceiling from the
//! HTTP stack's. Uses the same environment variables as the service.
//!
//! ```text
//! cargo run --release --example direct_bench -- 1,4,8,16 5
//! ```

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use hsm_signer::{
    backend::{KeyBackend, SignAlgorithm, pkcs11::Pkcs11Backend},
    config::{HsmConfig, ProcessEnv},
    keys::{EC_SIGNING_KEY, ED25519_SIGNING_KEY, KeyCatalog, RSA_SIGNING_KEY},
    metrics::Metrics,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let levels: Vec<usize> = args
        .next()
        .unwrap_or_else(|| "1,2,4,8,16".into())
        .split(',')
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;
    let seconds: u64 = args.next().map_or(Ok(5), |s| s.parse())?;
    let algorithm: SignAlgorithm = args
        .next()
        .unwrap_or_else(|| "ECDSA_P256_SHA256".into())
        .parse()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = match algorithm {
        SignAlgorithm::EcdsaP256Sha256 => EC_SIGNING_KEY,
        SignAlgorithm::Ed25519 => ED25519_SIGNING_KEY,
        SignAlgorithm::RsaPssSha256 => RSA_SIGNING_KEY,
    };

    println!("| sessions = callers | signatures/s | mean µs/op |");
    println!("|---:|---:|---:|");
    for n in levels {
        let mut config = HsmConfig::from_env(&ProcessEnv)?;
        config.pool_size = n;
        config.max_waiters = n * 4;
        let backend = Arc::new(Pkcs11Backend::connect(
            &config,
            KeyCatalog::default(),
            Arc::new(Metrics::new()),
        )?);
        backend.warm_up()?;
        let done = Arc::new(AtomicU64::new(0));
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let started = Instant::now();
        let tasks: Vec<_> = (0..n)
            .map(|_| {
                let (backend, done) = (Arc::clone(&backend), Arc::clone(&done));
                tokio::spawn(async move {
                    while Instant::now() < deadline {
                        backend.sign(key, algorithm, vec![42; 256]).await.expect("sign");
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await?;
        }
        let elapsed = started.elapsed().as_secs_f64();
        let ops = done.load(Ordering::Relaxed) as f64;
        println!("| {n} | {:.0} | {:.1} |", ops / elapsed, elapsed * 1e6 * n as f64 / ops);
    }
    Ok(())
}
