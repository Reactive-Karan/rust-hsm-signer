//! Bounded, logged-in PKCS#11 session pool.
//!
//! Design:
//!
//! * A [`tokio::sync::Semaphore`] with `pool_size` permits bounds how many
//!   PKCS#11 operations run concurrently. A permit is acquired *before* any
//!   blocking work is scheduled, so at most `pool_size` threads of Tokio's
//!   blocking pool are ever busy with the HSM.
//! * Waiting is bounded twice: by `max_waiters` (callers beyond that are
//!   rejected immediately → fast 503) and by `acquire_timeout`.
//! * Sessions are opened lazily (or eagerly via [`SessionPool::warm_up`]),
//!   logged in once, and returned to an idle stack after use. Sessions that
//!   the token reports as invalid are discarded and transparently replaced.
//! * PKCS#11 login state is per-application, not per-session: the first
//!   `C_Login` authenticates every session of this process, so subsequent
//!   sessions see `CKR_USER_ALREADY_LOGGED_IN`, which is expected.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use cryptoki::{
    context::Pkcs11,
    error::{Error as CkError, RvError},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::{error::BackendError, metrics::Metrics};

/// Static configuration of a [`SessionPool`].
#[derive(Clone)]
pub struct PoolSettings {
    pub token_label: String,
    pub user_pin: AuthPin,
    pub size: usize,
    pub max_waiters: usize,
    pub acquire_timeout: Duration,
}

/// Pool of logged-in read-only sessions.
pub struct SessionPool {
    ctx: Pkcs11,
    settings: PoolSettings,
    idle: Mutex<Vec<Session>>,
    permits: Arc<Semaphore>,
    waiters: AtomicUsize,
    in_use: AtomicUsize,
    open: AtomicUsize,
    /// Set after the token rejected our PIN: never retry automatically, as
    /// real HSMs lock the user out after a few wrong attempts.
    pin_rejected: AtomicBool,
    metrics: Arc<Metrics>,
}

/// Whether a PKCS#11 error means the session (or login state) is unusable
/// and must be discarded rather than returned to the pool.
///
/// `CKR_GENERAL_ERROR` normally means the token is in trouble, but SoftHSM
/// also returns it for *bad input* to `C_UnwrapKey` (failed RFC 5649 integrity
/// check). For data-dependent operations it is therefore not treated as
/// session-fatal: otherwise every tampered request would recycle the pool.
pub fn is_session_fatal(function: &str, err: &CkError) -> bool {
    match err {
        CkError::Pkcs11(RvError::GeneralError, _) => !matches!(function, "C_UnwrapKey" | "C_Decrypt"),
        CkError::Pkcs11(
            RvError::SessionHandleInvalid
            | RvError::SessionClosed
            | RvError::TokenNotPresent
            | RvError::TokenNotRecognized
            | RvError::DeviceRemoved
            | RvError::DeviceError
            | RvError::UserNotLoggedIn
            | RvError::OperationActive
            | RvError::CryptokiNotInitialized,
            _,
        ) => true,
        _ => false,
    }
}

/// Find the slot holding the initialized token with the given label.
pub fn find_slot(ctx: &Pkcs11, label: &str) -> Result<Option<Slot>, CkError> {
    for slot in ctx.get_slots_with_initialized_token()? {
        if ctx.get_token_info(slot)?.label().trim_end() == label {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Log a session in as the normal user, accepting "already logged in".
pub fn login_user(session: &Session, pin: &AuthPin) -> Result<(), CkError> {
    match session.login(UserType::User, Some(pin)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(e) => Err(e),
    }
}

impl SessionPool {
    pub fn new(ctx: Pkcs11, settings: PoolSettings, metrics: Arc<Metrics>) -> Arc<Self> {
        metrics.pool_size.set(settings.size as i64);
        Arc::new(Self {
            ctx,
            permits: Arc::new(Semaphore::new(settings.size)),
            idle: Mutex::new(Vec::with_capacity(settings.size)),
            waiters: AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
            pin_rejected: AtomicBool::new(false),
            settings,
            metrics,
        })
    }

    pub fn size(&self) -> usize {
        self.settings.size
    }

    pub fn context(&self) -> &Pkcs11 {
        &self.ctx
    }

    pub fn token_label(&self) -> &str {
        &self.settings.token_label
    }

    pub fn user_pin(&self) -> &AuthPin {
        &self.settings.user_pin
    }

    /// Resolve the token's slot. Done on every session (re)open rather than
    /// cached, because slot ids may change when a token is re-inserted.
    pub fn slot(&self) -> Result<Slot, BackendError> {
        find_slot(&self.ctx, &self.settings.token_label)
            .map_err(|e| BackendError::Unavailable(format!("slot enumeration failed: {e:?}")))?
            .ok_or_else(|| BackendError::Unavailable(format!("token `{}` not found", self.settings.token_label)))
    }

    /// Open and authenticate a new session. **Blocking.**
    fn open_session(&self) -> Result<Session, BackendError> {
        if self.pin_rejected.load(Ordering::Relaxed) {
            return Err(BackendError::Unavailable(
                "token rejected the configured PIN earlier; not retrying".into(),
            ));
        }
        let slot = self.slot()?;
        let session = self
            .ctx
            .open_ro_session(slot)
            .map_err(|e| BackendError::Unavailable(format!("C_OpenSession failed: {e:?}")))?;
        if let Err(e) = login_user(&session, &self.settings.user_pin) {
            if matches!(
                e,
                CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLocked | RvError::PinExpired, _)
            ) {
                self.pin_rejected.store(true, Ordering::Relaxed);
            }
            return Err(BackendError::Unavailable(format!("C_Login failed: {e:?}")));
        }
        let open = self.open.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics.pool_open_sessions.set(open as i64);
        tracing::debug!(session = %session, open, "opened HSM session");
        Ok(session)
    }

    /// Eagerly open every session so the first requests do not pay for
    /// `C_OpenSession` + `C_Login`. **Blocking.**
    pub fn warm_up(&self) -> Result<(), BackendError> {
        let mut opened = Vec::with_capacity(self.settings.size);
        let existing = self.idle.lock().expect("pool lock").len();
        for _ in existing..self.settings.size {
            opened.push(self.open_session()?);
        }
        self.idle.lock().expect("pool lock").extend(opened);
        Ok(())
    }

    /// Acquire a session slot, waiting at most `acquire_timeout`.
    pub async fn acquire(self: &Arc<Self>) -> Result<PooledSession, BackendError> {
        let started = Instant::now();
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(TryAcquireError::Closed) => return Err(BackendError::Unavailable("session pool closed".into())),
            Err(TryAcquireError::NoPermits) => self.acquire_slow().await?,
        };
        self.metrics.pool_acquire_wait.observe(started.elapsed().as_secs_f64());
        let in_use = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics.pool_in_use.set(in_use as i64);
        let session = self.idle.lock().expect("pool lock").pop();
        Ok(PooledSession {
            session,
            pool: Arc::clone(self),
            discard: false,
            _permit: permit,
        })
    }

    async fn acquire_slow(&self) -> Result<OwnedSemaphorePermit, BackendError> {
        // Bound the queue: reject immediately instead of queueing unboundedly.
        // The guard keeps the waiter count correct even if this future is
        // dropped mid-wait (client disconnect, request timeout).
        let waiter = WaiterGuard::register(self);
        if waiter.position >= self.settings.max_waiters {
            self.metrics.pool_rejections.inc();
            return Err(BackendError::PoolExhausted);
        }
        let result = tokio::time::timeout(self.settings.acquire_timeout, self.permits.clone().acquire_owned()).await;
        drop(waiter);
        match result {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(BackendError::Unavailable("session pool closed".into())),
            Err(_elapsed) => {
                self.metrics.pool_acquire_timeouts.inc();
                Err(BackendError::AcquireTimeout)
            }
        }
    }

    /// Close every idle session. Called after a session-fatal error: when one
    /// session is dead (token reset, login state lost, ...) the others usually
    /// are too, and the retry must not pick up another stale one. **Blocking.**
    pub fn purge_idle(&self) {
        let stale: Vec<Session> = std::mem::take(&mut *self.idle.lock().expect("pool lock"));
        if stale.is_empty() {
            return;
        }
        let open = self
            .open
            .fetch_sub(stale.len(), Ordering::Relaxed)
            .saturating_sub(stale.len());
        self.metrics.pool_open_sessions.set(open as i64);
        self.metrics.pool_sessions_discarded.inc_by(stale.len() as u64);
        tracing::warn!(count = stale.len(), "purging idle HSM sessions");
        drop(stale);
    }

    fn release(&self, session: Option<Session>, discard: bool) {
        if let Some(session) = session {
            if discard {
                let open = self.open.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
                self.metrics.pool_open_sessions.set(open as i64);
                self.metrics.pool_sessions_discarded.inc();
                tracing::warn!(session = %session, "discarding invalid HSM session");
                // Dropping closes it; a failure to close an already-dead
                // session is expected and only logged by cryptoki.
                drop(session);
            } else {
                self.idle.lock().expect("pool lock").push(session);
            }
        }
        let in_use = self.in_use.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        self.metrics.pool_in_use.set(in_use as i64);
    }
}

/// Counts a caller as waiting for a session for as long as it lives.
struct WaiterGuard<'a> {
    pool: &'a SessionPool,
    /// Number of callers that were already waiting when this one arrived.
    position: usize,
}

impl<'a> WaiterGuard<'a> {
    fn register(pool: &'a SessionPool) -> Self {
        let position = pool.waiters.fetch_add(1, Ordering::AcqRel);
        pool.metrics.pool_waiters.set((position + 1) as i64);
        Self { pool, position }
    }
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        let now = self.pool.waiters.fetch_sub(1, Ordering::AcqRel).saturating_sub(1);
        self.pool.metrics.pool_waiters.set(now as i64);
    }
}

/// A checked-out pool slot. The underlying session is opened lazily on the
/// blocking thread; dropping the guard returns it to the pool (or discards it).
pub struct PooledSession {
    session: Option<Session>,
    pool: Arc<SessionPool>,
    discard: bool,
    _permit: OwnedSemaphorePermit,
}

impl PooledSession {
    /// The session, opening and logging in a new one if needed. **Blocking.**
    pub fn session(&mut self) -> Result<&Session, BackendError> {
        if self.session.is_none() {
            self.session = Some(self.pool.open_session()?);
        }
        Ok(self.session.as_ref().expect("session set above"))
    }

    /// Do not return this session to the pool, and close the idle ones.
    /// **Blocking.**
    pub fn discard_all(&mut self) {
        self.discard = true;
        self.pool.purge_idle();
    }
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        self.pool.release(self.session.take(), self.discard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    #[test]
    fn classifies_fatal_errors() {
        let err = |rv| CkError::Pkcs11(rv, Function::Sign);
        assert!(is_session_fatal("C_Sign", &err(RvError::SessionHandleInvalid)));
        assert!(is_session_fatal("C_Sign", &err(RvError::DeviceRemoved)));
        assert!(is_session_fatal("C_Sign", &err(RvError::UserNotLoggedIn)));
        assert!(is_session_fatal("C_Sign", &err(RvError::GeneralError)));
        assert!(!is_session_fatal("C_UnwrapKey", &err(RvError::GeneralError)));
        assert!(!is_session_fatal("C_Sign", &err(RvError::KeyHandleInvalid)));
        assert!(!is_session_fatal("C_Sign", &err(RvError::DataLenRange)));
    }
}
