//! Shared SoftHSM2 test environment.
//!
//! Each integration-test binary (= process) gets one isolated SoftHSM2 setup:
//! a fresh token directory with its own `softhsm2.conf` (selected through
//! `SOFTHSM2_CONF`), a token initialized by `softhsm2-util` with random PINs,
//! and the default key catalog provisioned. A PKCS#11 module can only be
//! initialized once per process, so the environment is created lazily once
//! and shared by all tests of the binary.
//!
//! The module is located via `PKCS11_MODULE`, falling back to common install
//! locations. If SoftHSM2 is not installed, tests print a notice and pass
//! (set `HSM_TESTS_REQUIRED=1` to make that a failure instead, as CI and the
//! Docker test stage do).

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, OnceLock},
    time::Duration,
};

use cryptoki::context::Pkcs11;
use hsm_signer::{
    backend::{
        KeyBackend,
        instrumented::InstrumentedBackend,
        pkcs11::{Pkcs11Backend, load_module},
    },
    config::HsmConfig,
    keys::KeyCatalog,
    metrics::Metrics,
};
use secrecy::SecretString;

/// Common SoftHSM2 module locations (Debian/Ubuntu, Fedora, BSD/local, Homebrew).
const MODULE_CANDIDATES: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
];

pub struct SoftHsm {
    _dir: tempfile::TempDir,
    pub ctx: Pkcs11,
    pub module: PathBuf,
    pub token_label: String,
    pub user_pin: SecretString,
}

fn find_module() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PKCS11_MODULE") {
        return Some(PathBuf::from(p)).filter(|p| p.exists());
    }
    MODULE_CANDIDATES.iter().map(PathBuf::from).find(|p| p.exists())
}

fn find_util(module: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOFTHSM2_UTIL") {
        return Some(PathBuf::from(p));
    }
    let on_path = Command::new("softhsm2-util").arg("--version").output().is_ok();
    if on_path {
        return Some(PathBuf::from("softhsm2-util"));
    }
    // <prefix>/lib/softhsm/libsofthsm2.so → <prefix>/bin/softhsm2-util
    let candidate = module.parent()?.parent()?.parent()?.join("bin/softhsm2-util");
    candidate.exists().then_some(candidate)
}

fn random_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn setup() -> Result<SoftHsm, String> {
    let module = find_module().ok_or("no SoftHSM2 module found (set PKCS11_MODULE)")?;
    let util = find_util(&module).ok_or("softhsm2-util not found (set SOFTHSM2_UTIL)")?;

    // Token state lives under target/ (gitignored), never in the source tree.
    let dir = tempfile::Builder::new()
        .prefix("softhsm-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .map_err(|e| e.to_string())?;
    let token_dir = dir.path().join("tokens");
    std::fs::create_dir_all(&token_dir).map_err(|e| e.to_string())?;
    let conf = dir.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
            token_dir.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    // SAFETY: called exactly once (inside a OnceLock initializer) before the
    // PKCS#11 module is loaded; SoftHSM reads it during C_Initialize.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };

    let token_label = format!("it-{}", random_hex(4));
    let user_pin = random_hex(12);
    let so_pin = random_hex(12);
    let out = Command::new(&util)
        .env("SOFTHSM2_CONF", &conf)
        .args(["--init-token", "--free", "--label", &token_label])
        .args(["--so-pin", &so_pin, "--pin", &user_pin])
        .output()
        .map_err(|e| format!("cannot run softhsm2-util: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "softhsm2-util --init-token failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let ctx = load_module(&module).map_err(|e| e.to_string())?;
    let env = SoftHsm {
        _dir: dir,
        ctx,
        module,
        token_label,
        user_pin: SecretString::from(user_pin),
    };
    env.backend(env.config(2, 64, Duration::from_secs(5)))
        .provision()
        .map_err(|e| format!("provisioning failed: {e}"))?;
    Ok(env)
}

static ENV: OnceLock<Result<SoftHsm, String>> = OnceLock::new();

/// The shared SoftHSM environment, or `None` (test should return early).
pub fn softhsm() -> Option<&'static SoftHsm> {
    match ENV.get_or_init(setup) {
        Ok(env) => Some(env),
        Err(reason) => {
            if std::env::var("HSM_TESTS_REQUIRED").is_ok_and(|v| v == "1") {
                panic!("SoftHSM2 integration tests are required but cannot run: {reason}");
            }
            eprintln!("SKIPPED: SoftHSM2 integration test ({reason})");
            None
        }
    }
}

impl SoftHsm {
    pub fn config(&self, pool_size: usize, max_waiters: usize, acquire_timeout: Duration) -> HsmConfig {
        HsmConfig {
            module_path: PathBuf::from("unused-context-is-shared"),
            token_label: self.token_label.clone(),
            user_pin: self.user_pin.clone(),
            pool_size,
            acquire_timeout,
            max_waiters,
            op_timeout: Duration::from_secs(10),
        }
    }

    pub fn backend(&self, config: HsmConfig) -> Pkcs11Backend {
        self.backend_with_metrics(config, Arc::new(Metrics::new()))
    }

    pub fn backend_with_metrics(&self, config: HsmConfig, metrics: Arc<Metrics>) -> Pkcs11Backend {
        Pkcs11Backend::with_context(self.ctx.clone(), &config, KeyCatalog::default(), metrics)
    }

    /// A backend wrapped like in production (spans, logs, metrics).
    pub fn instrumented(&self, config: HsmConfig, metrics: Arc<Metrics>) -> Arc<dyn KeyBackend> {
        let backend: Arc<dyn KeyBackend> = Arc::new(self.backend_with_metrics(config, Arc::clone(&metrics)));
        Arc::new(InstrumentedBackend::new(backend, metrics))
    }
}
