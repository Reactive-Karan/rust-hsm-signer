//! Integration tests against a real PKCS#11 token (SoftHSM2).
//!
//! See `tests/common/mod.rs` for how the isolated token is created.

mod common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use cryptoki::{
    error::{Error as CkError, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeInfo, AttributeType, KeyType as CkKeyType, ObjectClass, ObjectHandle},
    session::Session,
};
use hsm_signer::{
    api::{self, AppState, RouterSettings},
    backend::{
        BackendError, KeyBackend, SignAlgorithm,
        pkcs11::{
            objects::{ProvisionOutcome, ephemeral_dek_template, unwrapped_dek_template},
            pool::login_user,
        },
    },
    crypto,
    keys::{DATA_KEY, EC_SIGNING_KEY, ED25519_SIGNING_KEY, RSA_SIGNING_KEY, WRAPPING_KEY},
    metrics::Metrics,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use zeroize::Zeroizing;

use common::{SoftHsm, softhsm};

fn default_config(env: &SoftHsm) -> hsm_signer::config::HsmConfig {
    env.config(4, 256, Duration::from_secs(5))
}

/// Open a logged-in R/O session for low-level assertions.
fn raw_session(env: &SoftHsm) -> Session {
    let slot = hsm_signer::backend::pkcs11::pool::find_slot(&env.ctx, &env.token_label)
        .unwrap()
        .expect("token present");
    let session = env.ctx.open_ro_session(slot).unwrap();
    login_user(&session, &env.user_pin).unwrap();
    session
}

fn find(session: &Session, label: &str, class: ObjectClass) -> ObjectHandle {
    let handles = session
        .find_objects(&[Attribute::Class(class), Attribute::Label(label.as_bytes().to_vec())])
        .unwrap();
    assert_eq!(handles.len(), 1, "exactly one {class:?} labelled {label}");
    handles[0]
}

#[tokio::test]
async fn provisioning_is_idempotent() {
    let Some(env) = softhsm() else { return };
    let backend = env.backend(default_config(env));
    let outcomes = tokio::task::spawn_blocking(move || backend.provision())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcomes.len(), 5);
    assert!(outcomes.iter().all(|(_, o)| *o == ProvisionOutcome::AlreadyPresent));
}

#[tokio::test]
async fn private_and_secret_keys_are_not_exportable() {
    let Some(env) = softhsm() else { return };
    let session = raw_session(env);

    let ec = find(&session, EC_SIGNING_KEY, ObjectClass::PRIVATE_KEY);
    let rsa = find(&session, RSA_SIGNING_KEY, ObjectClass::PRIVATE_KEY);
    let data = find(&session, DATA_KEY, ObjectClass::SECRET_KEY);
    let kek = find(&session, WRAPPING_KEY, ObjectClass::SECRET_KEY);

    // C_GetAttributeValue on the secret value must fail with CKR_ATTRIBUTE_SENSITIVE.
    for (name, handle, attr) in [
        ("EC private key CKA_VALUE", ec, AttributeType::Value),
        ("RSA CKA_PRIVATE_EXPONENT", rsa, AttributeType::PrivateExponent),
        ("RSA CKA_PRIME_1", rsa, AttributeType::Prime1),
        ("AES data key CKA_VALUE", data, AttributeType::Value),
        ("AES wrapping key CKA_VALUE", kek, AttributeType::Value),
    ] {
        let info = session.get_attribute_info(handle, &[attr]).unwrap();
        assert!(
            matches!(info.as_slice(), [AttributeInfo::Sensitive]),
            "{name} must be sensitive: {info:?}"
        );
        let values = session.get_attributes(handle, &[attr]).unwrap();
        assert!(values.is_empty(), "{name} must not be returned");
    }

    // Not even wrapped export is possible: CKA_EXTRACTABLE=false.
    for (name, handle) in [("EC private key", ec), ("AES data key", data)] {
        let err = session.wrap_key(&Mechanism::AesKeyWrapPad, kek, handle).unwrap_err();
        assert!(
            matches!(err, CkError::Pkcs11(RvError::KeyUnextractable, _)),
            "{name}: expected CKR_KEY_UNEXTRACTABLE, got {err:?}"
        );
    }

    // The token attests the keys were generated inside and never left.
    let backend = env.backend(default_config(env));
    let keys = backend.list_keys().await.unwrap();
    assert_eq!(keys.len(), 5, "{keys:?}");
    for key in keys {
        let a = key.attributes;
        assert!(a.token && a.private && a.sensitive, "{key:?}");
        assert!(!a.extractable && a.always_sensitive && a.never_extractable, "{key:?}");
        assert_eq!(
            key.object_id,
            hsm_signer::keys::object_id_for(&key.key_id)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}

#[tokio::test]
async fn sensitive_attribute_cannot_be_relaxed() {
    let Some(env) = softhsm() else { return };
    let slot = hsm_signer::backend::pkcs11::pool::find_slot(&env.ctx, &env.token_label)
        .unwrap()
        .unwrap();
    let session = env.ctx.open_rw_session(slot).unwrap();
    login_user(&session, &env.user_pin).unwrap();
    let data = find(&session, DATA_KEY, ObjectClass::SECRET_KEY);
    for attr in [Attribute::Extractable(true), Attribute::Sensitive(false)] {
        let res = session.update_attributes(data, std::slice::from_ref(&attr));
        assert!(res.is_err(), "{attr:?} must be rejected");
    }
}

#[tokio::test]
async fn sign_and_verify_every_algorithm() {
    let Some(env) = softhsm() else { return };
    let backend = env.backend(default_config(env));
    for (key, alg, sig_len) in [
        (EC_SIGNING_KEY, SignAlgorithm::EcdsaP256Sha256, None),
        (ED25519_SIGNING_KEY, SignAlgorithm::Ed25519, Some(64)),
        (RSA_SIGNING_KEY, SignAlgorithm::RsaPssSha256, Some(384)),
    ] {
        let pk = backend.public_key(key).await.unwrap();
        assert_eq!(pk.key_type, alg.key_type());
        // Many iterations to exercise r/s values with high bits / leading zeros.
        for i in 0..40u32 {
            let msg = format!("message #{i}").into_bytes();
            let sig = backend.sign(key, alg, msg.clone()).await.unwrap();
            if let Some(len) = sig_len {
                assert_eq!(sig.len(), len);
            }
            assert!(
                crypto::verify_with_spki(alg, &pk.spki_der, &msg, &sig).unwrap(),
                "{alg} #{i}"
            );
            assert!(
                backend.verify(key, alg, msg.clone(), sig.clone()).await.unwrap(),
                "C_Verify {alg} #{i}"
            );
            let mut tampered = msg.clone();
            tampered.push(b'!');
            assert!(!crypto::verify_with_spki(alg, &pk.spki_der, &tampered, &sig).unwrap());
            assert!(!backend.verify(key, alg, tampered, sig).await.unwrap());
        }
    }
}

#[tokio::test]
async fn wrong_key_or_algorithm_is_reported_precisely() {
    let Some(env) = softhsm() else { return };
    let backend = env.backend(default_config(env));
    assert!(matches!(
        backend.sign("does-not-exist", SignAlgorithm::Ed25519, vec![1]).await,
        Err(BackendError::KeyNotFound(_))
    ));
    assert!(matches!(
        backend.sign(EC_SIGNING_KEY, SignAlgorithm::Ed25519, vec![1]).await,
        Err(BackendError::KeyAlgorithmMismatch { .. })
    ));
    assert!(matches!(
        backend.encrypt(WRAPPING_KEY, Zeroizing::new(vec![1]), vec![]).await,
        Err(BackendError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        backend.encrypt(EC_SIGNING_KEY, Zeroizing::new(vec![1]), vec![]).await,
        Err(BackendError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        backend.public_key(DATA_KEY).await,
        Err(BackendError::UnsupportedOperation { .. })
    ));
}

#[tokio::test]
async fn aes_gcm_round_trip_and_tamper_detection() {
    let Some(env) = softhsm() else { return };
    let backend = env.backend(default_config(env));
    let plaintext = b"attack at dawn".to_vec();
    let aad = b"tenant=42".to_vec();
    let a = backend
        .encrypt(DATA_KEY, Zeroizing::new(plaintext.clone()), aad.clone())
        .await
        .unwrap();
    let b = backend
        .encrypt(DATA_KEY, Zeroizing::new(plaintext.clone()), aad.clone())
        .await
        .unwrap();
    assert_eq!(a.iv.len(), 12);
    assert_ne!(a.iv, b.iv, "fresh IV per message");
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_eq!(a.ciphertext.len(), plaintext.len() + 16);

    let pt = backend
        .decrypt(DATA_KEY, a.iv.clone(), a.ciphertext.clone(), aad.clone())
        .await
        .unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());

    let mut flipped_ct = a.ciphertext.clone();
    flipped_ct[0] ^= 1;
    let mut flipped_tag = a.ciphertext.clone();
    *flipped_tag.last_mut().unwrap() ^= 1;
    let mut flipped_iv = a.iv.clone();
    flipped_iv[0] ^= 1;
    for (name, iv, ct, aad) in [
        ("ciphertext", a.iv.clone(), flipped_ct, aad.clone()),
        ("tag", a.iv.clone(), flipped_tag, aad.clone()),
        ("iv", flipped_iv, a.ciphertext.clone(), aad.clone()),
        ("aad", a.iv.clone(), a.ciphertext.clone(), b"tenant=43".to_vec()),
    ] {
        let res = backend.decrypt(DATA_KEY, iv, ct, aad).await;
        assert!(
            matches!(res, Err(BackendError::IntegrityCheckFailed)),
            "tampered {name}: {res:?}"
        );
    }
    // The session survives failed decryptions.
    assert!(backend.decrypt(DATA_KEY, a.iv, a.ciphertext, aad).await.is_ok());
}

#[tokio::test]
async fn envelope_encryption_wraps_and_unwraps_inside_the_hsm() {
    let Some(env) = softhsm() else { return };
    let backend = env.backend(default_config(env));
    let envelope = backend
        .envelope_encrypt(
            WRAPPING_KEY,
            Zeroizing::new(b"customer record".to_vec()),
            b"v1".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(envelope.wrapped_key.len(), 40, "RFC 5649 wrap of a 32-byte key");
    let pt = backend
        .envelope_decrypt(WRAPPING_KEY, envelope.clone(), b"v1".to_vec())
        .await
        .unwrap();
    assert_eq!(pt.as_slice(), b"customer record");

    let mut bad = envelope.clone();
    bad.wrapped_key[5] ^= 0x80;
    let res = backend.envelope_decrypt(WRAPPING_KEY, bad, b"v1".to_vec()).await;
    assert!(matches!(res, Err(BackendError::IntegrityCheckFailed)), "{res:?}");
    assert!(matches!(
        backend.envelope_decrypt(WRAPPING_KEY, envelope, b"v2".to_vec()).await,
        Err(BackendError::IntegrityCheckFailed)
    ));
}

#[tokio::test]
async fn unwrapped_key_is_non_extractable_session_object() {
    let Some(env) = softhsm() else { return };
    let session = raw_session(env);
    let kek = find(&session, WRAPPING_KEY, ObjectClass::SECRET_KEY);
    let dek = session
        .generate_key(&Mechanism::AesKeyGen, &ephemeral_dek_template())
        .unwrap();
    let wrapped = session.wrap_key(&Mechanism::AesKeyWrapPad, kek, dek).unwrap();
    session.destroy_object(dek).unwrap();

    let unwrapped = session
        .unwrap_key(&Mechanism::AesKeyWrapPad, kek, &wrapped, &unwrapped_dek_template())
        .unwrap();
    let attrs = session
        .get_attributes(
            unwrapped,
            &[
                AttributeType::Token,
                AttributeType::Extractable,
                AttributeType::Sensitive,
                AttributeType::KeyType,
            ],
        )
        .unwrap();
    assert!(attrs.contains(&Attribute::Token(false)));
    assert!(attrs.contains(&Attribute::Extractable(false)));
    assert!(attrs.contains(&Attribute::Sensitive(true)));
    assert!(attrs.contains(&Attribute::KeyType(CkKeyType::AES)));
    let info = session.get_attribute_info(unwrapped, &[AttributeType::Value]).unwrap();
    assert!(matches!(info.as_slice(), [AttributeInfo::Sensitive]), "{info:?}");
    let err = session.wrap_key(&Mechanism::AesKeyWrapPad, kek, unwrapped).unwrap_err();
    assert!(matches!(err, CkError::Pkcs11(RvError::KeyUnextractable, _)), "{err:?}");
    session.destroy_object(unwrapped).unwrap();
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn sign_request(key_id: &str, algorithm: &str, payload: &[u8]) -> Request<Body> {
    Request::post("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"key_id": key_id, "algorithm": algorithm, "payload": STANDARD.encode(payload)}).to_string(),
        ))
        .unwrap()
}

fn app(backend: Arc<dyn KeyBackend>, metrics: Arc<Metrics>) -> axum::Router {
    api::router(
        AppState {
            backend,
            metrics,
            max_payload_bytes: 64 * 1024,
        },
        RouterSettings {
            request_timeout: Duration::from_secs(10),
            max_payload_bytes: 64 * 1024,
        },
    )
}

#[tokio::test]
async fn http_api_end_to_end() {
    let Some(env) = softhsm() else { return };
    let metrics = Arc::new(Metrics::new());
    let app = app(env.instrumented(default_config(env), Arc::clone(&metrics)), metrics);

    let (status, _, body) = call(&app, sign_request(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"payload")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_id"], EC_SIGNING_KEY);
    assert_eq!(body["algorithm"], "ECDSA_P256_SHA256");
    let signature = body["signature"].as_str().unwrap().to_owned();

    let (status, _, body) = call(
        &app,
        Request::post("/v1/verify")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"key_id": EC_SIGNING_KEY, "algorithm": "ECDSA_P256_SHA256",
                       "payload": STANDARD.encode(b"payload"), "signature": signature})
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);

    let (status, _, body) = call(&app, Request::get("/readyz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = call(&app, sign_request("missing", "ECDSA_P256_SHA256", b"x")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("key_not_found"))
    );
}

#[tokio::test]
async fn pool_exhaustion_sheds_load_with_503() {
    let Some(env) = softhsm() else { return };
    let metrics = Arc::new(Metrics::new());

    // One session, nobody allowed to queue: second caller is rejected at once.
    let backend = Arc::new(env.backend_with_metrics(env.config(1, 0, Duration::from_millis(50)), Arc::clone(&metrics)));
    let router = app(Arc::clone(&backend) as Arc<dyn KeyBackend>, Arc::clone(&metrics));
    let held = backend.pool().acquire().await.unwrap();
    let started = std::time::Instant::now();
    let (status, headers, body) = call(&router, sign_request(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "pool_exhausted");
    assert_eq!(headers[header::RETRY_AFTER], "1");
    assert!(
        started.elapsed() < Duration::from_millis(40),
        "rejected without waiting"
    );

    // Readiness reflects saturation too.
    let (status, _, _) = call(&router, Request::get("/readyz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    drop(held);
    let (status, _, _) = call(&router, sign_request(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x")).await;
    assert_eq!(status, StatusCode::OK);

    // One waiter allowed, but the session is never released in time → acquire timeout.
    let backend = Arc::new(env.backend_with_metrics(env.config(1, 1, Duration::from_millis(50)), Arc::clone(&metrics)));
    let router = app(Arc::clone(&backend) as Arc<dyn KeyBackend>, Arc::clone(&metrics));
    let held = backend.pool().acquire().await.unwrap();
    let (status, headers, body) = call(&router, sign_request(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "session_acquire_timeout");
    assert_eq!(headers[header::RETRY_AFTER], "1");
    drop(held);

    let text = metrics.render();
    assert!(text.contains("hsm_signer_pool_rejections_total 2"), "{text}");
    assert!(text.contains("hsm_signer_pool_acquire_timeouts_total 1"), "{text}");
}

#[tokio::test]
async fn concurrent_callers_share_a_small_pool() {
    let Some(env) = softhsm() else { return };
    let metrics = Arc::new(Metrics::new());
    let backend = env.instrumented(env.config(3, 1000, Duration::from_secs(10)), Arc::clone(&metrics));
    let pk = backend.public_key(EC_SIGNING_KEY).await.unwrap();
    let tasks: Vec<_> = (0..200u32)
        .map(|i| {
            let backend = Arc::clone(&backend);
            tokio::spawn(async move {
                let msg = i.to_be_bytes().to_vec();
                let sig = backend
                    .sign(EC_SIGNING_KEY, SignAlgorithm::EcdsaP256Sha256, msg.clone())
                    .await
                    .unwrap();
                (msg, sig)
            })
        })
        .collect();
    for t in tasks {
        let (msg, sig) = t.await.unwrap();
        assert!(crypto::verify_with_spki(SignAlgorithm::EcdsaP256Sha256, &pk.spki_der, &msg, &sig).unwrap());
    }
    let text = metrics.render();
    assert!(text.contains("hsm_signer_pool_size 3"));
    assert!(text.contains("hsm_signer_pool_in_use 0"));
}

#[tokio::test]
async fn cancelled_waiters_do_not_leak_queue_slots() {
    let Some(env) = softhsm() else { return };
    let metrics = Arc::new(Metrics::new());
    // One session, one waiter slot, long acquire timeout.
    let backend = env.backend_with_metrics(env.config(1, 1, Duration::from_secs(30)), Arc::clone(&metrics));
    let pool = Arc::clone(backend.pool());
    let held = pool.acquire().await.unwrap();
    // Callers that give up early (client disconnect, outer timeout) must
    // release their waiter slot when their future is dropped.
    for _ in 0..5 {
        let res = tokio::time::timeout(Duration::from_millis(10), pool.acquire()).await;
        assert!(res.is_err(), "caller should still be waiting");
    }
    assert!(metrics.render().contains("hsm_signer_pool_waiters 0"));
    // The single waiter slot is still usable.
    let waiter = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.acquire().await.map(drop) }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(held);
    waiter.await.unwrap().unwrap();
}
