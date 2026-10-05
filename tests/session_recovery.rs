//! Session invalidation & recovery against SoftHSM2.
//!
//! Lives in its own test binary (= its own process and token) because it
//! deliberately kills every session of the process with `C_CloseAllSessions`,
//! which would disturb unrelated tests running in parallel.

mod common;

use std::{sync::Arc, time::Duration};

use hsm_signer::{
    backend::{KeyBackend, SignAlgorithm},
    crypto,
    keys::EC_SIGNING_KEY,
    metrics::Metrics,
};

/// Call `C_CloseAllSessions` directly on the module: every pooled session
/// handle becomes invalid and the login state is lost, as after an HSM reset.
fn close_all_sessions(env: &common::SoftHsm) {
    let slot = hsm_signer::backend::pkcs11::pool::find_slot(&env.ctx, &env.token_label)
        .unwrap()
        .unwrap();
    // SAFETY: the library is already loaded and initialized by this process
    // (dlopen returns the same handle); C_CloseAllSessions takes a slot id and
    // returns CK_RV.
    unsafe {
        let lib = libloading::Library::new(&env.module).unwrap();
        let close_all: libloading::Symbol<unsafe extern "C" fn(std::os::raw::c_ulong) -> std::os::raw::c_ulong> =
            lib.get(b"C_CloseAllSessions\0").unwrap();
        assert_eq!(close_all(slot.id() as std::os::raw::c_ulong), 0, "CKR_OK");
    }
}

#[tokio::test]
async fn recovers_from_invalidated_sessions_and_lost_login() {
    let Some(env) = common::softhsm() else { return };
    let metrics = Arc::new(Metrics::new());
    let backend = Arc::new(env.backend_with_metrics(env.config(4, 64, Duration::from_secs(5)), Arc::clone(&metrics)));
    let warm = Arc::clone(&backend);
    tokio::task::spawn_blocking(move || warm.warm_up())
        .await
        .unwrap()
        .unwrap();

    let alg = SignAlgorithm::EcdsaP256Sha256;
    let pk = backend.public_key(EC_SIGNING_KEY).await.unwrap();
    backend.sign(EC_SIGNING_KEY, alg, b"before".to_vec()).await.unwrap();

    close_all_sessions(env);

    // The next call hits a dead session, discards the pool's idle sessions,
    // opens a fresh one, logs in again and succeeds — invisible to the caller.
    let sig = backend.sign(EC_SIGNING_KEY, alg, b"after".to_vec()).await.unwrap();
    assert!(crypto::verify_with_spki(alg, &pk.spki_der, b"after", &sig).unwrap());
    backend.health_check().await.unwrap();

    let text = metrics.render();
    let discarded: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("hsm_signer_pool_sessions_discarded_total "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(discarded >= 4, "all stale sessions discarded, got {discarded}\n{text}");

    // Many concurrent calls afterwards all succeed.
    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let b = Arc::clone(&backend);
            tokio::spawn(async move { b.sign(EC_SIGNING_KEY, alg, b"x".to_vec()).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
}
