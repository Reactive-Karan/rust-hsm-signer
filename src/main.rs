//! `hsm-signer` command-line entry point.
//!
//! ```text
//! hsm-signer serve [--provision]   run the HTTP service (default)
//! hsm-signer init-token            initialize the token if absent (PINs from files/env)
//! hsm-signer provision             create missing keys, then exit
//! hsm-signer keys                  print the keys and their security attributes as JSON
//! ```

use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use hsm_signer::{
    api::{self, AppState, RouterSettings},
    backend::{KeyBackend, instrumented::InstrumentedBackend, mock::SoftwareMockBackend, pkcs11::Pkcs11Backend},
    config::{BackendKind, Config, HsmConfig, ProcessEnv, load_pin},
    keys::KeyCatalog,
    metrics::Metrics,
    telemetry,
};

#[derive(Parser)]
#[command(version, about = "HSM-backed signing and key-management service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP service.
    Serve {
        /// Create missing keys before serving (also: HSM_PROVISION_ON_START=true).
        #[arg(long)]
        provision: bool,
    },
    /// Initialize the token (C_InitToken + C_InitPIN) unless it already exists.
    /// SO PIN from HSM_SO_PIN_FILE / HSM_SO_PIN, user PIN from HSM_PIN_FILE / HSM_PIN.
    InitToken,
    /// Create any missing keys from the key catalog, then exit.
    Provision,
    /// List keys and their security attributes as JSON.
    Keys,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::from_env(&ProcessEnv).context("invalid configuration")?;
    // Telemetry is initialized outside the async runtime: the OTLP exporter
    // uses its own background thread and blocking HTTP client.
    let target = match cli.command {
        None | Some(Command::Serve { .. }) => telemetry::LogTarget::Stdout,
        Some(_) => telemetry::LogTarget::Stderr,
    };
    let _telemetry = telemetry::init(config.log_format, target)?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async move {
        match cli.command.unwrap_or(Command::Serve { provision: false }) {
            Command::Serve { provision } => serve(config, provision).await,
            Command::InitToken => init_token(&config).await,
            Command::Provision => provision(&config).await,
            Command::Keys => list_keys(&config).await,
        }
    });
    if let Err(e) = &result {
        tracing::error!(error = format!("{e:#}"), "fatal error");
    }
    // Shut the runtime down before the telemetry guard flushes.
    drop(runtime);
    result
}

fn hsm_config(config: &Config) -> anyhow::Result<&HsmConfig> {
    match (config.backend, &config.hsm) {
        (BackendKind::Pkcs11, Some(hsm)) => Ok(hsm),
        _ => anyhow::bail!("this command requires BACKEND=pkcs11"),
    }
}

/// Connect to the module on a blocking thread (dlopen + C_Initialize + logins).
async fn connect(config: &Config, metrics: Arc<Metrics>, provision: bool) -> anyhow::Result<Pkcs11Backend> {
    let hsm = hsm_config(config)?.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<Pkcs11Backend> {
        tracing::info!(module = %hsm.module_path.display(), token = %hsm.token_label, pool_size = hsm.pool_size, "connecting to PKCS#11 token");
        let backend = Pkcs11Backend::connect(&hsm, KeyCatalog::default(), metrics)?;
        if provision {
            backend.provision()?;
        }
        backend.warm_up()?;
        Ok(backend)
    })
    .await?
}

async fn serve(config: Config, provision: bool) -> anyhow::Result<()> {
    let metrics = Arc::new(Metrics::new());
    let backend: Arc<dyn KeyBackend> = match config.backend {
        BackendKind::Pkcs11 => {
            Arc::new(connect(&config, Arc::clone(&metrics), provision || config.provision_on_start).await?)
        }
        BackendKind::Mock => {
            tracing::warn!(
                "using the in-memory MOCK backend: keys are not protected by an HSM. Never use in production"
            );
            Arc::new(SoftwareMockBackend::new(&KeyCatalog::default()))
        }
    };
    let backend: Arc<dyn KeyBackend> = Arc::new(InstrumentedBackend::new(backend, Arc::clone(&metrics)));
    let app = api::router(
        AppState {
            backend,
            metrics,
            max_payload_bytes: config.max_payload_bytes,
        },
        RouterSettings {
            request_timeout: config.request_timeout,
            max_payload_bytes: config.max_payload_bytes,
        },
    );
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("cannot bind {}", config.listen_addr))?;
    tracing::info!(addr = %config.listen_addr, backend = ?config.backend, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shut down cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}

async fn init_token(config: &Config) -> anyhow::Result<()> {
    let hsm = hsm_config(config)?.clone();
    let so_pin = load_pin(&ProcessEnv, "HSM_SO_PIN_FILE", "HSM_SO_PIN").context("SO PIN")?;
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let ctx = hsm_signer::backend::pkcs11::load_module(&hsm.module_path)?;
        let outcome = hsm_signer::backend::pkcs11::token::init_token(&ctx, &hsm.token_label, &so_pin, &hsm.user_pin)?;
        tracing::info!(token = %hsm.token_label, ?outcome, "token initialization");
        Ok(())
    })
    .await?
}

async fn provision(config: &Config) -> anyhow::Result<()> {
    let metrics = Arc::new(Metrics::new());
    let hsm = hsm_config(config)?.clone();
    let outcomes =
        tokio::task::spawn_blocking(move || Pkcs11Backend::connect(&hsm, KeyCatalog::default(), metrics)?.provision())
            .await??;
    for (label, outcome) in outcomes {
        println!("{label}: {outcome:?}");
    }
    Ok(())
}

async fn list_keys(config: &Config) -> anyhow::Result<()> {
    let backend = connect(config, Arc::new(Metrics::new()), false).await?;
    let keys = backend.list_keys().await?;
    println!("{}", serde_json::to_string_pretty(&keys)?);
    Ok(())
}
