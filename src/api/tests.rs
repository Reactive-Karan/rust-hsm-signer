//! Router-level tests against the in-memory mock backend.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{AppState, RouterSettings, router};
use crate::{
    backend::{BackendError, KeyBackend, SignAlgorithm, instrumented::InstrumentedBackend, mock::SoftwareMockBackend},
    crypto,
    keys::{DATA_KEY, EC_SIGNING_KEY, ED25519_SIGNING_KEY, KeyCatalog, WRAPPING_KEY},
    metrics::Metrics,
};

const MAX_PAYLOAD: usize = 1024;

struct Harness {
    app: Router,
    mock: Arc<SoftwareMockBackend>,
}

fn harness_with_timeout(request_timeout: Duration) -> Harness {
    let mock = Arc::new(SoftwareMockBackend::new(&KeyCatalog::default()));
    let metrics = Arc::new(Metrics::new());
    let backend: Arc<dyn KeyBackend> = Arc::new(InstrumentedBackend::new(
        Arc::clone(&mock) as Arc<dyn KeyBackend>,
        Arc::clone(&metrics),
    ));
    let app = router(
        AppState {
            backend,
            metrics,
            max_payload_bytes: MAX_PAYLOAD,
        },
        RouterSettings {
            request_timeout,
            max_payload_bytes: MAX_PAYLOAD,
        },
    );
    Harness { app, mock }
}

fn harness() -> Harness {
    harness_with_timeout(Duration::from_secs(5))
}

impl Harness {
    async fn call(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, headers, body)
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, axum::http::HeaderMap, Value) {
        self.post_raw(path, body.to_string()).await
    }

    async fn post_raw(&self, path: &str, body: String) -> (StatusCode, axum::http::HeaderMap, Value) {
        self.call(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str) -> (StatusCode, axum::http::HeaderMap, Value) {
        self.call(Request::get(path).body(Body::empty()).unwrap()).await
    }
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn sign_body(key_id: &str, algorithm: &str, payload: &[u8]) -> Value {
    json!({"key_id": key_id, "algorithm": algorithm, "payload": b64(payload)})
}

#[tokio::test]
async fn sign_returns_the_documented_shape_and_a_valid_der_signature() {
    let h = harness();
    let (status, headers, body) = h
        .post("/v1/sign", sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"hello"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.contains_key("x-request-id"));
    assert_eq!(body["key_id"], EC_SIGNING_KEY);
    assert_eq!(body["algorithm"], "ECDSA_P256_SHA256");
    assert!(body["duration_ms"].is_number());
    let sig = STANDARD.decode(body["signature"].as_str().unwrap()).unwrap();
    assert_eq!(sig[0], 0x30, "DER SEQUENCE");

    let (_, _, pk) = h.get(&format!("/v1/keys/{EC_SIGNING_KEY}/public")).await;
    let spki = STANDARD.decode(pk["public_key_der"].as_str().unwrap()).unwrap();
    assert!(crypto::verify_with_spki(SignAlgorithm::EcdsaP256Sha256, &spki, b"hello", &sig).unwrap());
    assert!(
        pk["public_key_pem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
    assert_eq!(pk["algorithms"], json!(["ECDSA_P256_SHA256"]));
}

#[tokio::test]
async fn verify_endpoint_in_software_and_in_backend() {
    let h = harness();
    let (_, _, signed) = h
        .post("/v1/sign", sign_body(ED25519_SIGNING_KEY, "ED25519", b"msg"))
        .await;
    let sig = signed["signature"].as_str().unwrap();
    for verifier in ["software", "hsm"] {
        let (status, _, body) = h
            .post(
                "/v1/verify",
                json!({"key_id": ED25519_SIGNING_KEY, "algorithm": "ED25519", "payload": b64(b"msg"),
                       "signature": sig, "verifier": verifier}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true, "{verifier}");
        let (_, _, body) = h
            .post(
                "/v1/verify",
                json!({"key_id": ED25519_SIGNING_KEY, "algorithm": "ED25519", "payload": b64(b"tampered"),
                       "signature": sig, "verifier": verifier}),
            )
            .await;
        assert_eq!(body["valid"], false, "{verifier}");
    }
}

#[tokio::test]
async fn client_errors_map_to_4xx_with_stable_codes() {
    let h = harness();
    let cases = [
        (
            sign_body("missing-key", "ECDSA_P256_SHA256", b"x"),
            StatusCode::NOT_FOUND,
            "key_not_found",
        ),
        (
            sign_body(EC_SIGNING_KEY, "HS256", b"x"),
            StatusCode::BAD_REQUEST,
            "unsupported_algorithm",
        ),
        (
            sign_body(EC_SIGNING_KEY, "ED25519", b"x"),
            StatusCode::BAD_REQUEST,
            "algorithm_key_mismatch",
        ),
        (
            sign_body(DATA_KEY, "ECDSA_P256_SHA256", b"x"),
            StatusCode::BAD_REQUEST,
            "algorithm_key_mismatch",
        ),
        (
            sign_body("bad key!", "ECDSA_P256_SHA256", b"x"),
            StatusCode::BAD_REQUEST,
            "invalid_key_id",
        ),
        (
            json!({"key_id": EC_SIGNING_KEY, "algorithm": "ECDSA_P256_SHA256", "payload": "%%%"}),
            StatusCode::BAD_REQUEST,
            "invalid_base64",
        ),
        (
            sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", &[0u8; MAX_PAYLOAD + 1]),
            StatusCode::BAD_REQUEST,
            "payload_too_large",
        ),
        (
            json!({"key_id": EC_SIGNING_KEY, "algorithm": "ECDSA_P256_SHA256"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"key_id": EC_SIGNING_KEY, "algorithm": "ECDSA_P256_SHA256", "payload": "", "extra": 1}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ];
    for (body, status, code) in cases {
        let (got_status, _, got) = h.post("/v1/sign", body.clone()).await;
        assert_eq!(got_status, status, "{body} → {got}");
        assert_eq!(got["error"], code, "{body} → {got}");
        assert!(got["message"].is_string());
    }
    let (status, _, body) = h.post_raw("/v1/sign", "{not json".into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn oversized_body_is_rejected_with_413() {
    let h = harness();
    let huge = "A".repeat(64 * 1024);
    let (status, _, body) = h
        .post_raw(
            "/v1/sign",
            format!(r#"{{"key_id":"{EC_SIGNING_KEY}","algorithm":"ECDSA_P256_SHA256","payload":"{huge}"}}"#),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "payload_too_large");
}

#[tokio::test]
async fn backend_saturation_maps_to_503_with_retry_after() {
    let h = harness();
    for (fault, code) in [
        (
            (|| BackendError::PoolExhausted) as fn() -> BackendError,
            "pool_exhausted",
        ),
        (|| BackendError::AcquireTimeout, "session_acquire_timeout"),
    ] {
        h.mock.fail_with(Some(fault));
        let (status, headers, body) = h
            .post("/v1/sign", sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x"))
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers[header::RETRY_AFTER], "1");
        assert_eq!(body["error"], code);
    }
}

#[tokio::test]
async fn hsm_failures_are_generic_502s() {
    let h = harness();
    h.mock.fail_with(Some(|| BackendError::Hsm {
        operation: "C_Sign",
        detail: "CKR_DEVICE_ERROR (secret internals)".into(),
    }));
    let (status, _, body) = h
        .post("/v1/sign", sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x"))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "hsm_error");
    assert!(!body.to_string().contains("CKR_"));
    assert!(!body.to_string().contains("internals"));
}

#[tokio::test]
async fn request_timeout_returns_503() {
    let h = harness_with_timeout(Duration::from_millis(50));
    h.mock.set_latency(Some(Duration::from_millis(500)));
    let (status, _, _) = h
        .post("/v1/sign", sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x"))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn aes_gcm_round_trip_and_tamper_detection() {
    let h = harness();
    let (status, _, enc) = h
        .post(
            "/v1/encrypt",
            json!({"key_id": DATA_KEY, "plaintext": b64(b"top secret"), "aad": b64(b"ctx")}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enc}");
    assert_eq!(enc["algorithm"], "AES_256_GCM");
    assert_eq!(STANDARD.decode(enc["iv"].as_str().unwrap()).unwrap().len(), 12);

    let decrypt =
        |aad: &[u8]| json!({"key_id": DATA_KEY, "iv": enc["iv"], "ciphertext": enc["ciphertext"], "aad": b64(aad)});
    let (status, _, dec) = h.post("/v1/decrypt", decrypt(b"ctx")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        STANDARD.decode(dec["plaintext"].as_str().unwrap()).unwrap(),
        b"top secret"
    );

    let (status, _, err) = h.post("/v1/decrypt", decrypt(b"other")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "integrity_check_failed");

    // Encrypting with the wrapping key is not allowed.
    let (status, _, err) = h
        .post("/v1/encrypt", json!({"key_id": WRAPPING_KEY, "plaintext": b64(b"x")}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "unsupported_operation");
}

#[tokio::test]
async fn envelope_round_trip() {
    let h = harness();
    let (status, _, env) = h
        .post(
            "/v1/envelope/encrypt",
            json!({"wrapping_key_id": WRAPPING_KEY, "plaintext": b64(b"document")}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{env}");
    let (status, _, dec) = h
        .post(
            "/v1/envelope/decrypt",
            json!({"wrapping_key_id": WRAPPING_KEY, "wrapped_key": env["wrapped_key"],
                   "iv": env["iv"], "ciphertext": env["ciphertext"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{dec}");
    assert_eq!(
        STANDARD.decode(dec["plaintext"].as_str().unwrap()).unwrap(),
        b"document"
    );
}

#[tokio::test]
async fn public_key_of_symmetric_key_is_refused() {
    let h = harness();
    let (status, _, body) = h.get(&format!("/v1/keys/{DATA_KEY}/public")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_operation");
    let (status, _, body) = h.get("/v1/keys/unknown/public").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "key_not_found");
}

#[tokio::test]
async fn probes_metrics_and_request_ids() {
    let h = harness();
    let (status, _, body) = h.get("/healthz").await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("ok")));
    let (status, _, body) = h.get("/readyz").await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("ready")));

    h.mock
        .fail_with(Some(|| BackendError::Unavailable("token gone".into())));
    let (status, _, body) = h.get("/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "hsm_unavailable");
    h.mock.fail_with(None);

    h.post("/v1/sign", sign_body(EC_SIGNING_KEY, "ECDSA_P256_SHA256", b"x"))
        .await;
    let (status, headers, body) = h.get("/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = body.as_str().unwrap();
    assert!(text.contains(r#"hsm_signer_sign_duration_seconds_count{algorithm="ECDSA_P256_SHA256",outcome="ok"} 1"#));

    // A caller-supplied request id is propagated back.
    let res = h
        .app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-request-id", "abc-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.headers()["x-request-id"], "abc-123");
}

#[tokio::test]
async fn list_keys_reports_non_exportable_attributes() {
    let h = harness();
    let (status, _, body) = h.get("/v1/keys").await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), KeyCatalog::default().specs().len());
    assert!(keys.iter().all(|k| k["attributes"]["extractable"] == false));
}
