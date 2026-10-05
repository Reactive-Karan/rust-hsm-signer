//! Token initialization (`hsm-signer init-token`).
//!
//! Done through PKCS#11 (`C_InitToken` + `C_InitPIN`) rather than by shelling
//! out to `softhsm2-util`, so PINs never appear on a command line (where they
//! would be visible in the process table).

use cryptoki::{context::Pkcs11, session::UserType, types::AuthPin};

use super::pool::find_slot;
use crate::error::BackendError;

/// What `init_token` did.
#[derive(Debug, PartialEq, Eq)]
pub enum InitOutcome {
    AlreadyInitialized,
    Initialized,
}

fn unavailable(what: &str) -> impl FnOnce(cryptoki::error::Error) -> BackendError + '_ {
    move |e| BackendError::Unavailable(format!("{what}: {e:?}"))
}

/// Initialize a token labelled `label` in the first free slot, set its SO and
/// user PINs. Idempotent: does nothing if a token with that label exists.
pub fn init_token(
    ctx: &Pkcs11,
    label: &str,
    so_pin: &AuthPin,
    user_pin: &AuthPin,
) -> Result<InitOutcome, BackendError> {
    if find_slot(ctx, label)
        .map_err(unavailable("slot enumeration"))?
        .is_some()
    {
        return Ok(InitOutcome::AlreadyInitialized);
    }
    let slot = ctx
        .get_slots_with_token()
        .map_err(unavailable("slot enumeration"))?
        .into_iter()
        .find(|slot| {
            ctx.get_token_info(*slot)
                .map(|info| !info.token_initialized())
                .unwrap_or(false)
        })
        .ok_or_else(|| BackendError::Unavailable("no uninitialized token slot available".into()))?;
    ctx.init_token(slot, so_pin, label)
        .map_err(unavailable("C_InitToken"))?;
    let session = ctx.open_rw_session(slot).map_err(unavailable("C_OpenSession"))?;
    session
        .login(UserType::So, Some(so_pin))
        .map_err(unavailable("C_Login(SO)"))?;
    session.init_pin(user_pin).map_err(unavailable("C_InitPIN"))?;
    session.logout().map_err(unavailable("C_Logout"))?;
    Ok(InitOutcome::Initialized)
}
