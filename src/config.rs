//! Runtime configuration, read exclusively from environment variables.
//!
//! Nothing here is ever hard-coded per environment: the PKCS#11 module path,
//! token label and PIN all come from the environment (the PIN preferably from
//! a file, so it can be mounted as a Docker/Kubernetes secret).

use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use secrecy::SecretString;
use zeroize::Zeroizing;

/// Errors raised while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {0} is required")]
    Missing(&'static str),
    #[error("environment variable {name} has an invalid value: {reason}")]
    Invalid { name: &'static str, reason: String },
    #[error("could not read PIN file referenced by {var}: {source}")]
    PinFile {
        var: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// Which key backend the service should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Real PKCS#11 module (SoftHSM2 or a hardware HSM).
    Pkcs11,
    /// In-memory software implementation. For local development and tests only.
    Mock,
}

impl FromStr for BackendKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pkcs11" | "hsm" => Ok(Self::Pkcs11),
            "mock" | "software" => Ok(Self::Mock),
            other => Err(format!("unknown backend `{other}` (expected pkcs11|mock)")),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" | "text" => Ok(Self::Pretty),
            other => Err(format!("unknown log format `{other}` (expected json|pretty)")),
        }
    }
}

/// Settings for the PKCS#11 backend and its session pool.
#[derive(Clone)]
pub struct HsmConfig {
    /// Path to the PKCS#11 shared library (`PKCS11_MODULE`).
    pub module_path: PathBuf,
    /// Label of the token holding the keys (`HSM_TOKEN_LABEL`).
    pub token_label: String,
    /// User PIN. Wrapped in a secret type: never `Debug`/`Display`-printed.
    pub user_pin: SecretString,
    /// Number of sessions kept in the pool (`HSM_POOL_SIZE`).
    pub pool_size: usize,
    /// How long a request may wait for a free session (`HSM_ACQUIRE_TIMEOUT_MS`).
    pub acquire_timeout: Duration,
    /// Maximum number of requests allowed to *wait* for a session
    /// (`HSM_MAX_WAITERS`). Beyond this, callers are rejected immediately.
    pub max_waiters: usize,
    /// Upper bound on a single PKCS#11 operation (`HSM_OP_TIMEOUT_MS`).
    pub op_timeout: Duration,
}

impl fmt::Debug for HsmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmConfig")
            .field("module_path", &self.module_path)
            .field("token_label", &self.token_label)
            .field("user_pin", &"[REDACTED]")
            .field("pool_size", &self.pool_size)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("max_waiters", &self.max_waiters)
            .field("op_timeout", &self.op_timeout)
            .finish()
    }
}

/// Top-level service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub backend: BackendKind,
    /// Present only when `backend == Pkcs11`.
    pub hsm: Option<HsmConfig>,
    /// Max decoded payload / plaintext size in bytes (`MAX_PAYLOAD_BYTES`).
    pub max_payload_bytes: usize,
    /// End-to-end request timeout (`REQUEST_TIMEOUT_MS`).
    pub request_timeout: Duration,
    /// Create missing keys at startup (`HSM_PROVISION_ON_START`).
    pub provision_on_start: bool,
    pub log_format: LogFormat,
}

/// Abstraction over the process environment so configuration parsing can be
/// unit-tested without mutating global state.
pub trait Env {
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }
}

impl<const N: usize> Env for [(&str, &str); N] {
    fn get(&self, key: &str) -> Option<String> {
        self.iter().find(|(k, _)| *k == key).map(|(_, v)| (*v).to_string())
    }
}

fn parse<T: FromStr>(env: &dyn Env, name: &'static str, default: T) -> Result<T, ConfigError>
where
    T::Err: fmt::Display,
{
    match env.get(name) {
        None => Ok(default),
        Some(raw) => raw.trim().parse().map_err(|e: T::Err| ConfigError::Invalid {
            name,
            reason: e.to_string(),
        }),
    }
}

fn parse_millis(env: &dyn Env, name: &'static str, default_ms: u64) -> Result<Duration, ConfigError> {
    parse(env, name, default_ms).map(Duration::from_millis)
}

fn parse_bool(env: &dyn Env, name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env.get(name).map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if matches!(v.as_str(), "1" | "true" | "yes" | "on") => Ok(true),
        Some(v) if matches!(v.as_str(), "0" | "false" | "no" | "off") => Ok(false),
        Some(v) => Err(ConfigError::Invalid {
            name,
            reason: format!("`{v}` is not a boolean"),
        }),
    }
}

/// Resolve the user PIN: `HSM_PIN_FILE` takes precedence over `HSM_PIN`.
///
/// A single trailing newline is stripped from the file so that secrets created
/// with `echo` work as expected.
pub fn load_pin(env: &dyn Env, file_var: &'static str, value_var: &'static str) -> Result<SecretString, ConfigError> {
    if let Some(path) = env.get(file_var) {
        let raw = Zeroizing::new(
            std::fs::read_to_string(&path).map_err(|source| ConfigError::PinFile { var: file_var, source })?,
        );
        let pin = raw.trim_end_matches(['\r', '\n']);
        if pin.is_empty() {
            return Err(ConfigError::Invalid {
                name: file_var,
                reason: "PIN file is empty".into(),
            });
        }
        return Ok(SecretString::from(pin.to_owned()));
    }
    env.get(value_var)
        .map(SecretString::from)
        .ok_or(ConfigError::Missing(file_var))
}

impl HsmConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, ConfigError> {
        let module_path = env
            .get("PKCS11_MODULE")
            .map(PathBuf::from)
            .ok_or(ConfigError::Missing("PKCS11_MODULE"))?;
        let token_label = env.get("HSM_TOKEN_LABEL").unwrap_or_else(|| "arkion".to_string());
        let user_pin = load_pin(env, "HSM_PIN_FILE", "HSM_PIN")?;
        let pool_size: usize = parse(env, "HSM_POOL_SIZE", 8)?;
        if pool_size == 0 {
            return Err(ConfigError::Invalid {
                name: "HSM_POOL_SIZE",
                reason: "must be at least 1".into(),
            });
        }
        Ok(Self {
            module_path,
            token_label,
            user_pin,
            pool_size,
            acquire_timeout: parse_millis(env, "HSM_ACQUIRE_TIMEOUT_MS", 250)?,
            max_waiters: parse(env, "HSM_MAX_WAITERS", pool_size * 16)?,
            op_timeout: parse_millis(env, "HSM_OP_TIMEOUT_MS", 5_000)?,
        })
    }
}

impl Config {
    pub fn from_env(env: &dyn Env) -> Result<Self, ConfigError> {
        let backend: BackendKind = parse(env, "BACKEND", BackendKind::Pkcs11)?;
        let hsm = match backend {
            BackendKind::Pkcs11 => Some(HsmConfig::from_env(env)?),
            BackendKind::Mock => None,
        };
        Ok(Self {
            listen_addr: parse(env, "LISTEN_ADDR", SocketAddr::from(([0, 0, 0, 0], 8080)))?,
            backend,
            hsm,
            max_payload_bytes: parse(env, "MAX_PAYLOAD_BYTES", 64 * 1024)?,
            request_timeout: parse_millis(env, "REQUEST_TIMEOUT_MS", 10_000)?,
            provision_on_start: parse_bool(env, "HSM_PROVISION_ON_START", false)?,
            log_format: parse(env, "LOG_FORMAT", LogFormat::Json)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::io::Write;

    #[test]
    fn mock_backend_needs_no_hsm_settings() {
        let cfg = Config::from_env(&[("BACKEND", "mock")]).unwrap();
        assert_eq!(cfg.backend, BackendKind::Mock);
        assert!(cfg.hsm.is_none());
        assert_eq!(cfg.max_payload_bytes, 64 * 1024);
    }

    #[test]
    fn pkcs11_requires_module_and_pin() {
        let err = Config::from_env(&[("BACKEND", "pkcs11")]).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("PKCS11_MODULE")));
        let err = Config::from_env(&[("PKCS11_MODULE", "libx.so")]).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("HSM_PIN_FILE")));
    }

    #[test]
    fn pin_file_wins_over_env_and_is_trimmed() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "s3cret-from-file").unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        let env = [
            ("PKCS11_MODULE", "libx.so"),
            ("HSM_PIN", "from-env"),
            ("HSM_PIN_FILE", path.as_str()),
            ("HSM_POOL_SIZE", "4"),
        ];
        let cfg = HsmConfig::from_env(&env).unwrap();
        assert_eq!(cfg.user_pin.expose_secret(), "s3cret-from-file");
        assert_eq!(cfg.pool_size, 4);
        assert_eq!(cfg.max_waiters, 64);
    }

    #[test]
    fn debug_output_redacts_pin() {
        let env = [("PKCS11_MODULE", "libx.so"), ("HSM_PIN", "123456")];
        let cfg = HsmConfig::from_env(&env).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("123456"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn rejects_invalid_numbers_and_zero_pool() {
        let env = [("PKCS11_MODULE", "m"), ("HSM_PIN", "1"), ("HSM_POOL_SIZE", "0")];
        assert!(matches!(
            HsmConfig::from_env(&env),
            Err(ConfigError::Invalid {
                name: "HSM_POOL_SIZE",
                ..
            })
        ));
        let env = [("BACKEND", "mock"), ("MAX_PAYLOAD_BYTES", "lots")];
        assert!(Config::from_env(&env).is_err());
        let env = [("BACKEND", "mock"), ("HSM_PROVISION_ON_START", "maybe")];
        assert!(Config::from_env(&env).is_err());
    }
}
