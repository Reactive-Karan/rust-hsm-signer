# hsm-signer — HSM-backed signing & key-management service

A Rust (edition 2024) HTTP service that signs, verifies, encrypts and wraps keys
**through PKCS#11**, with every private and secret key generated inside — and
never leaving — the token. Development and tests use **SoftHSM2**; any PKCS#11
v2.40/3.x module (network HSM, cloud HSM, smart card) can be substituted by
changing one environment variable.

* `POST /v1/sign` exactly as specified (`ECDSA_P256_SHA256`), plus `ED25519` and `RSA_PSS_SHA256`
* signature verification in software with the HSM-exported public key, or in the HSM (`C_Verify`)
* AES-256-GCM encrypt/decrypt with a non-extractable AES key, random 96-bit IV per call, AAD
* envelope encryption: an ephemeral DEK is generated in the HSM, exported **only wrapped** (RFC 5649),
  and unwrapped back into the HSM as a non-extractable key to decrypt
* bounded session pool with backpressure, timeouts, fast 503 load-shedding and self-healing sessions
* Prometheus metrics, structured JSON logs, tracing spans with optional OTLP export
* unit tests (mock backend) + integration tests against a real SoftHSM2 token, locally and in Docker
* container image (multi-stage, non-root, SoftHSM inside, first-start token init) + load generator

---

## Contents

1. [Quick start](#1-quick-start)
2. [Code layout](#2-code-layout)
3. [Build, run, test](#3-build-run-test)
4. [API reference](#4-api-reference)
5. [HSM and key-management approach](#5-hsm-and-key-management-approach)
6. [Architectural decisions](#6-architectural-decisions)
7. [Concurrency and session management](#7-concurrency-and-session-management)
8. [Observability](#8-observability)
9. [Benchmark results and bottleneck analysis](#9-benchmark-results-and-bottleneck-analysis)
10. [Optional extensions implemented](#10-optional-extensions-implemented)
11. [Assumptions](#11-assumptions)
12. [Known limitations](#12-known-limitations)
13. [Security considerations](#13-security-considerations)
14. [Production considerations](#14-production-considerations)
15. [Architecture question: 100,000 short-lived certificates per second](#15-architecture-question-100000-short-lived-certificates-per-second)

---

## 1. Quick start

```bash
docker compose up -d --build          # builds the image, inits the token, provisions keys
curl -s localhost:8080/readyz         # {"status":"ready","backend":"pkcs11"}

curl -s localhost:8080/v1/sign -H 'content-type: application/json' -d '{
  "key_id": "arkion-intermediate-prod",
  "algorithm": "ECDSA_P256_SHA256",
  "payload": "aGVsbG8gd29ybGQ="
}'
# {"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","signature":"MEUCIQ...","duration_ms":0.41}

scripts/demo.sh                        # full walkthrough incl. OpenSSL cross-verification
docker compose down -v                 # stop and delete the token volume
```

---

## 2. Code layout

```
hsm-signer/
├── Cargo.toml / Cargo.lock / rustfmt.toml
├── Dockerfile                 multi-stage: builder → test → runtime → smoke
├── docker-compose.yml         service + optional `loadgen` (profile "bench")
├── docker/
│   ├── entrypoint.sh          PIN resolution/generation, token init, exec service
│   ├── softhsm2.conf          token dir on the /data volume
│   └── smoke-test.sh          end-to-end test of the runtime image (+ short load test)
├── scripts/
│   ├── bench-local.sh         throw-away SoftHSM token + release build + loadgen
│   └── demo.sh                curl walkthrough, OpenSSL cross-verification
├── examples/direct_bench.rs   HSM-only throughput (no HTTP), for bottleneck analysis
├── src/
│   ├── main.rs                CLI: serve | init-token | provision | keys
│   ├── lib.rs                 module map
│   ├── config.rs              env-driven config; PIN from file (preferred) or env; secrecy types
│   ├── error.rs               BackendError (domain) and ApiError (HTTP mapping, stable codes)
│   ├── keys.rs                key catalog: labels, CKA_ID derivation, key types, usages
│   ├── crypto.rs              ECDSA raw⇄DER, SPKI building, software verification
│   ├── metrics.rs             Prometheus registry and metrics
│   ├── telemetry.rs           JSON logs (non-blocking writer), spans, optional OTLP
│   ├── api/
│   │   ├── mod.rs             router, middleware (request id, trace, timeout, body limit)
│   │   ├── handlers.rs        input validation/decoding, calls `dyn KeyBackend`
│   │   ├── models.rs          request/response DTOs
│   │   └── tests.rs           router tests on the mock backend
│   ├── backend/
│   │   ├── mod.rs             `KeyBackend` trait + shared types
│   │   ├── instrumented.rs    decorator: spans, logs, metrics for any backend
│   │   ├── mock.rs            `SoftwareMockBackend` (in-memory, fault injection)
│   │   └── pkcs11/
│   │       ├── mod.rs         `Pkcs11Backend`: operations, error classification, retries
│   │       ├── pool.rs        bounded, logged-in session pool with backpressure
│   │       ├── objects.rs     templates, lookup + handle cache, provisioning, attributes
│   │       └── token.rs       C_InitToken / C_InitPIN (no PINs on command lines)
│   └── bin/loadgen.rs         closed-loop load generator (throughput, p50/p95/p99, errors)
├── tests/
│   ├── common/mod.rs          isolated SoftHSM2 environment per test binary
│   ├── softhsm.rs             integration tests (12)
│   └── session_recovery.rs    C_CloseAllSessions → transparent recovery
└── .github/workflows/ci.yml   fmt, clippy (±otel), tests with SoftHSM, docker stages
```

Dependency direction: `api` → `backend` trait ← (`pkcs11`, `mock`, `instrumented`);
`crypto`, `keys`, `config`, `error`, `metrics` are leaf modules. Handlers only see
`Arc<dyn KeyBackend>`.

---

## 3. Build, run, test

All commands below were run while writing this README. Prerequisites: Rust
(stable, edition 2024), SoftHSM2 (`softhsm2` package on Debian/Ubuntu,
`softhsm` formula on Homebrew), Docker with BuildKit/Compose v2, and `curl`,
`jq`, `openssl` for the demo script.

### Local (native)

```bash
cargo build --release
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                       # unit + SoftHSM integration tests (skipped with a notice if SoftHSM is absent)
HSM_TESTS_REQUIRED=1 cargo test  # same, but fail instead of skipping if SoftHSM is missing
```

The integration tests find the module via `PKCS11_MODULE`, otherwise they probe
common install locations (`/usr/lib/softhsm/libsofthsm2.so`,
`/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`,
`/usr/local/lib/softhsm/libsofthsm2.so`, `/opt/homebrew/lib/softhsm/libsofthsm2.so`, ...).
Each test binary creates its own token directory and `softhsm2.conf` under
`target/tmp/`, initializes a token with random PINs via `softhsm2-util`, and
provisions the key catalog.

Run the service against a local SoftHSM token:

```bash
export PKCS11_MODULE=<path to libsofthsm2.so>
export SOFTHSM2_CONF=$PWD/target/dev-softhsm/softhsm2.conf
mkdir -p target/dev-softhsm/tokens
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$PWD/target/dev-softhsm/tokens" > "$SOFTHSM2_CONF"
(umask 077; openssl rand -hex 24 > target/dev-softhsm/user.pin; openssl rand -hex 24 > target/dev-softhsm/so.pin)
export HSM_PIN_FILE=$PWD/target/dev-softhsm/user.pin HSM_SO_PIN_FILE=$PWD/target/dev-softhsm/so.pin

./target/release/hsm-signer init-token     # idempotent
./target/release/hsm-signer provision      # idempotent; prints Created / AlreadyPresent
./target/release/hsm-signer keys           # JSON: keys + CKA_SENSITIVE/EXTRACTABLE/... attributes
LOG_FORMAT=pretty ./target/release/hsm-signer serve
```

Without any HSM: `BACKEND=mock ./target/release/hsm-signer serve` (in-memory
software keys, loudly flagged in the logs, for API development only).

### Docker

```bash
docker build -t hsm-signer:latest .                 # runtime image (~170 MB, debian:bookworm-slim + softhsm2)
docker build --target test .                        # whole test suite inside the builder image, SoftHSM 2.6.1
docker build --target smoke --progress=plain .      # boots the runtime image's entrypoint, exercises every
                                                    # endpoint, checks PIN hygiene + restart idempotency, load-tests

docker compose up -d --build                        # service on :8080 (HSM_SIGNER_PORT to change), token on volume
docker compose run --rm --no-deps loadgen           # load test from a second container (1/10/100/500 callers)
docker compose run --rm --no-deps loadgen --url http://hsm-signer:8080 --concurrency 100 --duration 10
docker compose exec -e HSM_PIN_FILE=/data/user.pin hsm-signer hsm-signer keys
docker compose exec -e HSM_PIN_FILE=/data/user.pin hsm-signer hsm-direct-bench 1,2,4,8 5
docker compose down -v
```

Plain `docker run` equivalent:

```bash
docker volume create hsm-data
docker run -d --name hsm-signer -p 8080:8080 -v hsm-data:/data hsm-signer:latest
```

On first start the entrypoint generates random user and SO PINs into
`/data/user.pin` / `/data/so.pin` (mode 0600; values are never printed),
initializes the token (via PKCS#11, not via a command line that would expose
the PIN), provisions missing keys and execs the service as the non-root `hsm`
user. To supply PINs yourself, mount them as secrets and set `HSM_PIN_FILE` /
`HSM_SO_PIN_FILE` (see the commented `secrets:` block in `docker-compose.yml`).
`HSM_PIN` / `HSM_SO_PIN` also work but environment variables are visible in
`docker inspect`, so files are preferred.

> Note: always pass `--no-deps` to `docker compose run loadgen` after starting
> the service with custom environment variables; otherwise Compose recreates
> the service with the defaults from the compose file.

### Configuration

| variable | default | meaning |
|---|---|---|
| `BACKEND` | `pkcs11` | `pkcs11` or `mock` |
| `PKCS11_MODULE` | — (required) | path to the PKCS#11 library |
| `HSM_TOKEN_LABEL` | `arkion` | token label (slot is resolved by label) |
| `HSM_PIN_FILE` / `HSM_PIN` | — (required) | user PIN; the file wins; one trailing newline is stripped |
| `HSM_SO_PIN_FILE` / `HSM_SO_PIN` | — | SO PIN, `init-token` only |
| `HSM_POOL_SIZE` | `8` | sessions in the pool (= max concurrent PKCS#11 operations) |
| `HSM_MAX_WAITERS` | `16 × pool` | callers allowed to queue for a session; beyond → immediate 503 |
| `HSM_ACQUIRE_TIMEOUT_MS` | `250` | max wait for a session → 503 `session_acquire_timeout` |
| `HSM_OP_TIMEOUT_MS` | `5000` | max duration of one PKCS#11 call → 504 `hsm_timeout` |
| `HSM_PROVISION_ON_START` | `false` | same as `serve --provision` |
| `REQUEST_TIMEOUT_MS` | `10000` | end-to-end deadline for `/v1/*` → 503 |
| `MAX_PAYLOAD_BYTES` | `65536` | decoded payload / plaintext limit → 400 `payload_too_large` |
| `LISTEN_ADDR` | `0.0.0.0:8080` | bind address |
| `LOG_FORMAT` | `json` | `json` or `pretty` |
| `RUST_LOG` | `info` | tracing filter |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | enables OTLP/HTTP span export (e.g. `http://collector:4318`) |

---

## 4. API reference

All binary fields are standard base64 (RFC 4648 §4, padded). Errors are JSON:
`{"error": "<stable_code>", "message": "<human readable>"}`. Every response
carries an `x-request-id` header (generated, or propagated from the request).

### `POST /v1/sign`

```bash
curl -s localhost:8080/v1/sign -H 'content-type: application/json' \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8gd29ybGQ="}'
```
```json
{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","signature":"MEUCIQDl...","duration_ms":0.412}
```

`payload` is the **message** (the service hashes it). `duration_ms` is the time
spent in the key backend — queueing for a session plus the HSM call — as a JSON
number with microsecond precision.

| algorithm | key (default label) | signature encoding |
|---|---|---|
| `ECDSA_P256_SHA256` | `arkion-intermediate-prod` (EC P-256) | **ASN.1 DER `Ecdsa-Sig-Value`** (what X.509, OpenSSL, Go, Java, .NET expect). The HSM returns raw `r‖s` (64 bytes, PKCS#11 convention); the service converts. Not low-S normalized. |
| `ED25519` | `arkion-ed25519-prod` | 64 raw bytes (RFC 8032), pure Ed25519 over the full message |
| `RSA_PSS_SHA256` | `arkion-rsa-pss-prod` (RSA-3072, e=65537) | 384 raw bytes; RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32 bytes |

Signatures verify with stock OpenSSL (`scripts/demo.sh` does exactly this):

```bash
curl -s localhost:8080/v1/keys/arkion-intermediate-prod/public | jq -r .public_key_pem > pub.pem
openssl dgst -sha256 -verify pub.pem -signature sig.der msg.bin          # Verified OK
```

### `POST /v1/verify`

```bash
curl -s localhost:8080/v1/verify -H 'content-type: application/json' -d '{
  "key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256",
  "payload":"aGVsbG8gd29ybGQ=","signature":"MEUCIQDl...","verifier":"software"}'
# {"key_id":"...","algorithm":"ECDSA_P256_SHA256","valid":true,"verifier":"software","duration_ms":0.05}
```

`verifier` is `software` (default) or `hsm`:

* **software** — the public key is exported once from the token (`CKA_EC_POINT`
  / `CKA_MODULUS`+`CKA_PUBLIC_EXPONENT`), turned into an SPKI and cached; the
  signature is checked with RustCrypto (`p256`, `ed25519-dalek` strict
  verification, `rsa` PSS). This is what relying parties do, costs no HSM
  capacity, and independently validates the HSM's output and our DER encoding.
* **hsm** — `C_Verify` with the public key object inside the token: a
  cross-check that the token agrees, at the price of a pooled session.

A wrong signature returns `200` with `"valid": false`; a malformed request is a 400.

### `GET /v1/keys/{key_id}/public`

```json
{"key_id":"arkion-intermediate-prod","key_type":"EC_P256","algorithms":["ECDSA_P256_SHA256"],
 "public_key_pem":"-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----\n",
 "public_key_der":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
```

Only public material. For an AES key: 400 `unsupported_operation`.

### `GET /v1/keys`

Lists private/secret keys with their token attributes (no key material):

```json
{"keys":[{"key_id":"arkion-data-key","key_type":"AES_256","usage":"encrypt_decrypt",
  "object_id":"e2e58313812833ba3fd27862d0118461",
  "attributes":{"token":true,"private":true,"sensitive":true,"extractable":false,
                "always_sensitive":true,"never_extractable":true}}, ...]}
```

### `POST /v1/encrypt` / `POST /v1/decrypt` (AES-256-GCM)

```bash
curl -s localhost:8080/v1/encrypt -H 'content-type: application/json' \
  -d '{"key_id":"arkion-data-key","plaintext":"c2VjcmV0","aad":"b3JkZXItNDI="}'
# {"key_id":"arkion-data-key","algorithm":"AES_256_GCM","iv":"lSCjdhVop8VVPVQb",
#  "ciphertext":"FC185Tm1CjSP...","duration_ms":0.53}

curl -s localhost:8080/v1/decrypt -H 'content-type: application/json' \
  -d '{"key_id":"arkion-data-key","iv":"lSCjdhVop8VVPVQb","ciphertext":"FC185Tm1CjSP...","aad":"b3JkZXItNDI="}'
# {"key_id":"arkion-data-key","plaintext":"c2VjcmV0","duration_ms":0.3}
```

The IV (96 bits) comes from the HSM's RNG (`C_GenerateRandom`) for every call;
the ciphertext carries the 128-bit tag appended. Any change to ciphertext, tag,
IV or AAD → 400 `integrity_check_failed`.

### `POST /v1/envelope/encrypt` / `POST /v1/envelope/decrypt` (key wrapping)

```bash
curl -s localhost:8080/v1/envelope/encrypt -H 'content-type: application/json' \
  -d '{"wrapping_key_id":"arkion-wrapping-key","plaintext":"c2VjcmV0"}'
# {"wrapping_key_id":"arkion-wrapping-key","wrap_algorithm":"AES_KEY_WRAP_PAD",
#  "wrapped_key":"zw4d/4feWLF9...","algorithm":"AES_256_GCM","iv":"...","ciphertext":"...","duration_ms":0.86}

curl -s localhost:8080/v1/envelope/decrypt -H 'content-type: application/json' \
  -d '{"wrapping_key_id":"arkion-wrapping-key","wrapped_key":"zw4d/4feWLF9...","iv":"...","ciphertext":"..."}'
```

Encrypt: `C_GenerateKey` creates a DEK as a *session* object (sensitive,
extractable only so it can be wrapped) → AES-GCM with the DEK inside the HSM →
`C_WrapKey` with `CKM_AES_KEY_WRAP_PAD` (RFC 5649) under the KEK → DEK destroyed.
Decrypt: `C_UnwrapKey` imports the DEK as a session object that is
**sensitive, non-extractable, decrypt-only** → AES-GCM decrypt → DEK destroyed.
Plaintext DEK bytes never exist outside the HSM. The KEK can only wrap/unwrap;
the data key can only encrypt/decrypt (enforced by the token through
`CKA_WRAP`/`CKA_ENCRYPT`).

### Probes and metrics

* `GET /healthz` — liveness, `{"status":"ok"}`.
* `GET /readyz` — readiness: acquires a pooled session and checks it is logged in
  (`C_GetSessionInfo`); 503 with the error code otherwise. A saturated pool
  therefore reports not-ready, which lets a load balancer shift traffic.
* `GET /metrics` — Prometheus text format, see [Observability](#8-observability).

### Error codes

| HTTP | `error` | when |
|---|---|---|
| 400 | `invalid_request` | malformed JSON, missing/unknown fields |
| 400 | `invalid_key_id` | key id not 1–128 chars of `[A-Za-z0-9._-]` |
| 400 | `unsupported_algorithm` | algorithm not one of the three above |
| 400 | `invalid_base64` | a binary field is not valid base64 |
| 400 | `payload_too_large` | decoded payload/plaintext > `MAX_PAYLOAD_BYTES` |
| 400 | `algorithm_key_mismatch` | e.g. `ED25519` with the P-256 key |
| 400 | `unsupported_operation` | e.g. encrypt with the wrapping key, public key of an AES key |
| 400 | `integrity_check_failed` | GCM tag / RFC 5649 integrity failure |
| 404 | `key_not_found` | no key with that label |
| 413 | `payload_too_large` | whole request body above the transport limit |
| 502 | `hsm_error` | unexpected PKCS#11 failure (generic message; detail only in logs) |
| 503 | `pool_exhausted` | wait queue full — rejected immediately; `Retry-After: 1` |
| 503 | `session_acquire_timeout` | no session within `HSM_ACQUIRE_TIMEOUT_MS`; `Retry-After: 1` |
| 503 | `hsm_unavailable` | token missing, login failed, cannot open sessions; `Retry-After: 5` |
| 503 | *(empty body)* | `REQUEST_TIMEOUT_MS` exceeded |
| 504 | `hsm_timeout` | a PKCS#11 call exceeded `HSM_OP_TIMEOUT_MS`; `Retry-After: 1` |
| 500 | `internal_error` | bug / invariant violation |

---

## 5. HSM and key-management approach

**Library and token.** The module is loaded with `cryptoki` 0.12
(`PKCS11_MODULE`), initialized with `CKF_OS_LOCKING_OK`, and the slot is found
by token label (`HSM_TOKEN_LABEL`) every time a session is opened (slot ids can
change when a token is re-inserted). The module is deliberately never unloaded:
`dlclose`-ing SoftHSM before process exit crashes in its static destructors.

**Authentication.** The user PIN is read from `HSM_PIN_FILE` (preferred: a
Docker/Kubernetes secret) or `HSM_PIN`, held as `secrecy::SecretString`
(redacted `Debug`, zeroized on drop) and passed only to `C_Login`. It is never
logged; the config's `Debug` impl prints `[REDACTED]`; the smoke test greps the
logs for the PIN value. If the token rejects the PIN (`CKR_PIN_INCORRECT`/
`LOCKED`/`EXPIRED`) the pool stops retrying — real HSMs lock the user after a
few failures. Token initialization (`hsm-signer init-token`) uses `C_InitToken`
+ `C_InitPIN` so PINs never appear on a command line.

**Key catalog and identifiers** (`src/keys.rs`):

| `key_id` = `CKA_LABEL` | type | usage | mechanism |
|---|---|---|---|
| `arkion-intermediate-prod` | EC P-256 key pair | sign | `CKM_ECDSA` over host-side SHA-256 |
| `arkion-ed25519-prod` | Ed25519 key pair | sign | `CKM_EDDSA` (pure) |
| `arkion-rsa-pss-prod` | RSA-3072 key pair | sign | `CKM_RSA_PKCS_PSS` over host-side SHA-256 |
| `arkion-data-key` | AES-256 | encrypt/decrypt | `CKM_AES_GCM` |
| `arkion-wrapping-key` | AES-256 | wrap/unwrap | `CKM_AES_KEY_WRAP_PAD` |

`CKA_ID` is stable and deterministic: the first 16 bytes of SHA-256(label),
shared by the private and public halves (the convention p11tool/OpenSSL
providers use to pair objects). Keys are located by **label + class + key
type**; more than one match is refused rather than guessed. For EC keys the
curve is additionally checked (`CKA_EC_PARAMS` = prime256v1 OID).

**Attributes.** Every long-term private/secret key is created with
`CKA_TOKEN=true`, `CKA_PRIVATE=true`, `CKA_SENSITIVE=true`,
`CKA_EXTRACTABLE=false`, plus least-privilege usage flags (`CKA_SIGN` only for
signing keys, `CKA_DERIVE=false`, `CKA_DECRYPT=false`/`CKA_UNWRAP=false` on
signing keys, encrypt-only vs wrap-only AES keys). Public halves are public
token objects with `CKA_VERIFY=true`.

**Non-exportability, demonstrated by tests** (`tests/softhsm.rs`):

* `C_GetAttributeValue(CKA_VALUE)` on the EC private key and both AES keys,
  and `CKA_PRIVATE_EXPONENT`/`CKA_PRIME_1` on the RSA key → `CKR_ATTRIBUTE_SENSITIVE`;
* `C_WrapKey` of the EC private key or the data key with the wrapping key →
  `CKR_KEY_UNEXTRACTABLE` (not even encrypted export is possible);
* `C_SetAttributeValue(CKA_EXTRACTABLE=true / CKA_SENSITIVE=false)` → rejected;
* the token attests `CKA_ALWAYS_SENSITIVE=true` and `CKA_NEVER_EXTRACTABLE=true`
  (the key was generated inside and has never been exportable);
* a DEK unwrapped into the HSM is a non-extractable, sensitive session object.

**Provisioning** (`hsm-signer provision`, `serve --provision`, or the container
entrypoint) is idempotent: each catalog entry is created with
`C_GenerateKeyPair`/`C_GenerateKey` only if no object with that label/class/type
exists; an object with the same label but a different type is an error.

**Code-level guarantees.** Private/secret key bytes never exist in the
process: the backend handles only object handles. Plaintexts returned by
decryption are `Zeroizing<Vec<u8>>`. Logs never include payloads, plaintexts,
signatures, PINs or key material — only key id, algorithm, sizes, durations and
outcomes.

---

## 6. Architectural decisions

* **Trait at the boundary.** `KeyBackend` (async, object-safe via
  `async-trait`) is the only thing handlers know. `Pkcs11Backend` and
  `SoftwareMockBackend` implement it; `InstrumentedBackend` is a decorator that
  adds spans/logs/metrics to either, so observability lives in one place and
  the mock is exercised through the same instrumented path in tests.
* **Hash on the host for ECDSA and RSA-PSS** (`CKM_ECDSA`, `CKM_RSA_PKCS_PSS`
  over a SHA-256 digest) rather than `CKM_ECDSA_SHA256`: large payloads never
  cross the PKCS#11 boundary, and the mechanism is available on every HSM.
  Hashing is not a secret operation. Ed25519 is pure EdDSA and gets the message.
* **DER for ECDSA** because that is what X.509/TLS/OpenSSL consume; the
  conversion is hand-written (no curve-specific assumptions), fuzz-style tested
  against RustCrypto's encoder, and the inverse is used to feed `C_Verify`.
* **Software verification by default**, HSM verification on request — see
  §4. Public keys are exported as SPKI and cached.
* **Envelope encryption as the key-wrapping workflow**: it is the canonical
  reason to wrap keys (per-object DEKs, KEK in the HSM), and it exercises
  generate → wrap → unwrap-as-non-extractable → use → destroy.
* **Error classification in one place.** PKCS#11 return values are mapped to
  domain errors (`map_ck_error`) and to "session is dead" (`is_session_fatal`).
  Clients get stable codes and generic messages for server faults; details go
  to the logs.
* **Explicit runtime.** Telemetry is set up before the Tokio runtime is built
  (the OTLP exporter uses its own thread + blocking client), and blocking
  PKCS#11 work only ever runs on `spawn_blocking` after a pool permit is held.
* **Stable, pinned dependencies.** `cryptoki` is the latest release (0.12);
  the RustCrypto crates are the widely deployed stable lines (p256 0.13,
  ed25519-dalek 2, rsa 0.9) that share one `signature`/`spki` version.

---

## 7. Concurrency and session management

```
 HTTP request ──► handler (validate, base64, SHA-256)            async, Tokio worker
                    │
                    ▼
            SessionPool::acquire()  ── permits free? ──yes──► permit
                    │ no
                    ▼
            waiters < HSM_MAX_WAITERS ? ──no──► 503 pool_exhausted (immediate)
                    │ yes
                    ▼
            FIFO wait ≤ HSM_ACQUIRE_TIMEOUT_MS ──timeout──► 503 session_acquire_timeout
                    │ permit
                    ▼
            spawn_blocking { idle session (or open + C_Login)          blocking pool,
                             C_SignInit/C_Sign ... }                   ≤ pool_size threads
                    │        └─ wrapped in HSM_OP_TIMEOUT_MS ──► 504 hsm_timeout
                    ▼
            session returned to idle stack (or discarded if dead) ─► permit released
```

* **Scarce sessions.** A `tokio::sync::Semaphore` with `HSM_POOL_SIZE` permits
  bounds concurrent PKCS#11 operations; sessions are opened once (eagerly at
  startup), logged in once (login state is per application, so later sessions
  see `CKR_USER_ALREADY_LOGGED_IN`, treated as success) and reused.
* **Blocking work off the async runtime.** PKCS#11 calls block, so they run on
  `spawn_blocking` — but only *after* a permit is held, so at most
  `HSM_POOL_SIZE` blocking threads ever touch the HSM; the rest of the callers
  wait asynchronously without consuming threads.
* **Backpressure / load shedding.** The wait queue is bounded
  (`HSM_MAX_WAITERS`) and time-bounded (`HSM_ACQUIRE_TIMEOUT_MS`), so excess
  load gets a fast `503` + `Retry-After` instead of unbounded queueing and
  timeouts. The waiter count is held by an RAII guard so callers that disconnect
  mid-wait release their slot (regression-tested). Requests also have an
  end-to-end deadline (`REQUEST_TIMEOUT_MS`) and the HSM call itself a timeout
  (`HSM_OP_TIMEOUT_MS`; the blocking call cannot be cancelled, but the caller is
  released and the session/permit are returned when the call completes, so
  backpressure keeps reflecting reality).
* **Session invalidation.** Errors such as `CKR_SESSION_HANDLE_INVALID`,
  `CKR_SESSION_CLOSED`, `CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`,
  `CKR_USER_NOT_LOGGED_IN`, `CKR_OPERATION_ACTIVE` mark the session dead: it is
  discarded, the idle sessions are purged (when one is dead the others usually
  are too), and the operation is retried once on a freshly opened, logged-in
  session. A key lookup that finds nothing while the session is not logged in is
  reported as "not logged in" (→ recycle) rather than a misleading 404.
  `tests/session_recovery.rs` calls `C_CloseAllSessions` underneath the pool and
  verifies the next call succeeds transparently.
* **Object handle cache.** `(label, kind) → handle` is cached (handles of token
  objects are valid across sessions). On `CKR_OBJECT_HANDLE_INVALID`/
  `CKR_KEY_HANDLE_INVALID` the entry is evicted and the key looked up again —
  this happens for real with SoftHSM, which invalidates handles when all
  sessions close.
* **Shutdown.** SIGTERM/Ctrl-C trigger graceful shutdown (in-flight requests
  drain), then sessions are closed and the log writer/OTLP exporter flushed.

---

## 8. Observability

**Logs** — JSON lines on stdout (non-blocking writer thread). Per request: an
`hsm operation completed|failed` event (operation, key_id, algorithm,
duration_ms, outcome) and a `request completed` event (status, latency), both
carrying the `http.request` span with `request_id`, method and route.
Server-side errors include the PKCS#11 detail; clients never see it.

**Metrics** (`/metrics`, prefix `hsm_signer_`):

| metric | type | labels |
|---|---|---|
| `sign_duration_seconds` | histogram | `algorithm`, `outcome` |
| `operation_duration_seconds` | histogram | `operation`, `outcome` |
| `operation_failures_total` | counter | `operation`, `reason` (stable error code) |
| `pool_size`, `pool_in_use`, `pool_open_sessions`, `pool_waiters` | gauges | — |
| `pool_acquire_wait_seconds` | histogram | — |
| `pool_acquire_timeouts_total`, `pool_rejections_total`, `pool_sessions_discarded_total` | counters | — |

**Tracing** — spans `http.request` → `hsm.operation` (`hsm.sign`, ...) →
`pkcs11.call` (on the blocking thread, parented correctly). With
`OTEL_EXPORTER_OTLP_ENDPOINT` set (and the default `otel` cargo feature), spans
are exported over OTLP/HTTP and incoming W3C `traceparent` headers are honoured.
Without a collector nothing changes; if the collector is down, export errors are
logged and requests are unaffected (verified both). `cargo build
--no-default-features` removes the exporter entirely.

---

## 9. Benchmark results and bottleneck analysis

**Setup.** `loadgen` (`src/bin/loadgen.rs`) is closed-loop: N workers each keep
one `POST /v1/sign` in flight (256-byte random payload) for a fixed duration
after a warm-up; latencies are for successful requests (HdrHistogram), errors
are broken down by status/code. Hardware: an arm64 developer laptop.

* **Docker** (preferred, reproducible): `docker compose`, service container
  capped at **4 CPUs**, loadgen in a separate container (4 CPUs), Debian
  bookworm SoftHSM **2.6.1**, Docker's Linux VM. 15 s per level, 2 s warm-up.
* **Native**: release build and loadgen on the same host (no CPU cap),
  Homebrew SoftHSM **2.7.0** (`scripts/bench-local.sh`).
* Defaults unless stated: `HSM_POOL_SIZE=8`, `HSM_MAX_WAITERS=128`,
  `HSM_ACQUIRE_TIMEOUT_MS=250`, `RUST_LOG=info` (2 log lines per request).
  The host was also running unrelated containers, so expect ±10–15 % noise.

### 9.1 Headline: `ECDSA_P256_SHA256`, 1 / 10 / 100 / 500 concurrent callers

Docker (service capped at 4 CPUs):

| callers | requests | throughput (ok/s) | p50 ms | p95 ms | p99 ms | error rate | errors |
|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 102,114 | 6,807 | 0.14 | 0.20 | 0.33 | 0.00 % | – |
| 10 | 265,072 | 17,670 | 0.46 | 0.91 | 1.37 | 0.00 % | – |
| 100 | 260,663 | 17,360 | 4.46 | 21.74 | 30.05 | 0.00 % | – |
| 500 | 860,429 | 9,090 | 18.00 | 40.48 | 45.53 | 84.05 % | 503 `pool_exhausted`: 723,176 |
| 500, deep queue¹ | 253,634 | 16,779 | 24.38 | 48.09 | 52.45 | 0.00 % | – |

Native (no CPU cap):

| callers | requests | throughput (ok/s) | p50 ms | p95 ms | p99 ms | error rate | errors |
|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 141,349 | 9,423 | 0.10 | 0.14 | 0.26 | 0.00 % | – |
| 10 | 371,674 | 24,778 | 0.39 | 0.64 | 0.84 | 0.00 % | – |
| 100 | 364,069 | 24,262 | 4.05 | 4.70 | 5.89 | 0.00 % | – |
| 500 | 1,253,536 | 13,093 | 13.18 | 27.58 | 39.01 | 84.32 % | 503 `pool_exhausted`: 1,056,961 |
| 500, deep queue¹ | 366,945 | 24,426 | 20.22 | 22.19 | 27.04 | 0.00 % | – |

¹ `HSM_MAX_WAITERS=1000`, `HSM_ACQUIRE_TIMEOUT_MS=5000`.

### 9.2 Session-pool size at 100 callers (`HSM_MAX_WAITERS=1000`, 10 s)

| pool | Docker ok/s | Docker p50 / p95 / p99 ms | native ok/s | native p50 / p95 / p99 ms |
|---:|---:|---|---:|---|
| 1 | 10,827 | 9.20 / 12.25 / 14.53 | 14,073 | 6.54 / 10.45 / 13.86 |
| 2 | 17,947 | 5.33 / 7.01 / 9.13 | 19,887 | 4.90 / 6.32 / 8.29 |
| 4 | **19,963** | 4.50 / 6.60 / 17.20 | 24,300 | 4.05 / 4.54 / 5.27 |
| 8 | 17,746 | 4.53 / 12.95 / 28.73 | **24,502** | 4.02 / 4.54 / 5.39 |
| 16 | 17,144 | 4.49 / 17.45 / 32.43 | 24,197 | 4.05 / 5.07 / 6.03 |

### 9.3 HSM-only ceiling (no HTTP): `examples/direct_bench.rs`

N tasks call `Pkcs11Backend::sign` in a loop with N sessions (same pool and
`spawn_blocking` path, no HTTP/JSON). Docker figures are inside the
4-CPU-capped service container (`hsm-direct-bench`).

| sessions | ECDSA native | ECDSA Docker | Ed25519 native | Ed25519 Docker | RSA-3072 native | RSA-3072 Docker |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 17,839/s (56 µs) | 12,738/s (79 µs) | 12,023/s | 6,786/s | 752/s (1.33 ms) | 727/s |
| 2 | 29,415/s | 24,776/s | – | – | – | – |
| 4 | 34,682/s | **33,175/s** | 30,100/s | 12,946/s | 2,623/s | 2,470/s |
| 8 | **36,072/s** (222 µs) | 25,269/s | 28,529/s | 5,217/s | 4,606/s | 2,337/s |
| 16 | 30,826/s (519 µs) | 23,521/s | – | – | – | – |

### 9.4 Other algorithms over HTTP (pool 8)

| algorithm | callers | Docker ok/s | Docker p50 / p99 ms | native ok/s | native p50 / p99 ms |
|---|---:|---:|---|---:|---|
| ED25519 | 1 | 2,936 | 0.32 / 0.62 | 7,993 | 0.12 / 0.29 |
| ED25519 | 10 | 5,078 | 1.07 / 45.50 | 23,666 | 0.41 / 0.85 |
| ED25519 | 100 | 4,976 | 10.94 / 70.21 | 23,943 | 4.05 / 6.67 |
| RSA_PSS_SHA256 | 1 | 433 | 2.19 / 3.88 | 720 | 1.35 / 2.11 |
| RSA_PSS_SHA256 | 10 | 1,461 | 3.28 / 54.94 | 4,590 | 2.15 / 3.12 |
| RSA_PSS_SHA256 | 100 | 1,771 (0.49 % 503 `session_acquire_timeout`) | 59.94 / 166.53 | 4,499 | 22.06 / 24.99 |

Logging cost check (Docker, `RUST_LOG=warn`, i.e. no per-request log lines):
5,225 / 16,096 / 15,829 ok/s at 1 / 10 / 100 callers — within noise of the
`info` runs, so logging is not a bottleneck.

### 9.5 What limits throughput

1. **One caller is latency-bound** (~0.1 ms native, ~0.14 ms Docker per
   request): HTTP parse + JSON + base64 + SHA-256, two thread hand-offs for
   `spawn_blocking`, SoftHSM `C_SignInit` (it decrypts the private-key object
   from its store and builds an OpenSSL key on every init) + `C_Sign`, DER
   conversion, two log lines. No parallelism to exploit.
2. **Docker: the 4-CPU quota.** From 10 callers on, the service container
   burns its whole quota (`docker stats`: ~420 % CPU of 400 %, loadgen ~70 %).
   Pool size barely matters beyond 2–4 (§9.2), throughput is flat from 10 to
   500 callers, and the p99 inflation (20–50 ms) is the signature of CFS
   throttling: when the quota is exhausted all threads stall until the next
   100 ms period. Per signed request the container spends ≈ 4 CPU / 17.5k/s ≈
   230 µs of CPU, of which SoftHSM is ~120 µs (§9.3: 33k/s on 4 CPUs) and the
   HTTP/JSON/Tokio/logging path the rest.
3. **Native: SoftHSM's internal serialization.** With idle cores available,
   raw SoftHSM ECDSA plateaus at ~35k/s and the per-operation time grows from
   56 µs (1 session) to 222 µs (8) and 519 µs (16) — operations queue on
   SoftHSM's internal locks (object store / handle manager / per-op key
   decoding), not on CPU. Adding sessions past ~4 only adds contention (16
   sessions is *slower*). The HTTP service tops out lower (~24.5k/s) because the
   HTTP stack and the load generator share the same cores.
4. **Queueing, not work, dominates latency at 100 callers.** Little's law:
   100 in flight / 24k/s ≈ 4.1 ms — exactly the measured p50. Requests wait in
   the pool's FIFO semaphore (visible as `pool_acquire_wait_seconds` and
   `pool_waiters`), not inside the HSM.
5. **500 callers: deliberate load shedding.** With the defaults, at most 8
   operations run and 128 callers queue; the rest receive an immediate `503
   pool_exhausted` + `Retry-After: 1` (84 % of attempts). Successful
   requests keep a bounded p99 (~40–45 ms) instead of every caller timing out.
   Goodput drops (~9–13k vs 17–24k/s) because the load generator retries instantly
   and ignores `Retry-After`, and each rejection still costs HTTP+JSON CPU;
   real clients back off, and in production a cheaper shed at the load
   balancer/rate limiter would protect goodput further. With a deep queue
   (1000 waiters, 5 s) all 500 callers succeed at full throughput, at a p50 of
   ~20–24 ms (Little's law again: 500 / 24k/s ≈ 21 ms). Which one is right is an SLO
   decision; the default favours fast failure so callers can retry elsewhere.
6. **Algorithm cost.** RSA-3072 is pure CPU in SoftHSM (~1.35 ms/op) and scales
   with cores (native 4.5k/s; Docker ~1.8k/s on 4 CPUs, where 100 callers push
   queueing past the 250 ms acquire timeout → 0.5 % 503s — the backpressure
   path working as designed). SoftHSM 2.6.1's EdDSA path is markedly slower and
   more contention-prone than 2.7.0's (Docker vs native), so Ed25519 numbers
   say more about the SoftHSM build than about Ed25519.
7. **Pool sizing guidance.** For SoftHSM: pool ≈ cores available to it (4 in
   the capped container, 4–8 native). For a network HSM the optimum is larger
   (enough sessions to cover HSM parallelism × round-trip time) but bounded by
   the HSM's session limit; the pool metrics (`pool_in_use`, `pool_waiters`,
   `pool_acquire_wait_seconds`) show when to change it.

Reproduce: `docker compose up -d --build && docker compose run --rm --no-deps
loadgen`, `scripts/bench-local.sh`, or `docker build --target smoke
--build-arg BENCH_DURATION=15 --progress=plain .`.

---

## 10. Optional extensions implemented

| extension | where |
|---|---|
| Additional signing algorithms: **Ed25519** (`CKM_EDDSA`) and **RSA-PSS** (`CKM_RSA_PKCS_PSS`, RSA-3072) | `backend/pkcs11/mod.rs`, verified by OpenSSL in `scripts/demo.sh` |
| Additional secure **key-wrapping workflow** (envelope encryption, RFC 5649 wrap, unwrap as non-extractable) | `/v1/envelope/*`, `tests/softhsm.rs` |
| **Prometheus metrics** for signing latency, failures and pool saturation | `metrics.rs`, `/metrics` |
| **OpenTelemetry tracing** around the signing path (OTLP/HTTP, `traceparent` propagation) | `telemetry.rs`, `instrumented.rs`, `pkcs11/mod.rs` |
| Extras: `C_Verify` verification, `/v1/keys` attribute listing, session self-healing, Docker smoke stage, CI workflow | — |

---

## 11. Assumptions

* Callers are authenticated and authorized upstream (mTLS / API gateway); this
  service trusts its network peer. A `key_id` is not tenant-scoped.
* `payload` is the message to be signed, not a pre-computed digest.
* Keys are provisioned by the service from a fixed catalog; key generation via
  the API is out of scope (it is an administrative, audited operation).
* One token per deployment; replicas of the service share it (SoftHSM: shared
  volume; real HSM: the partition).
* SoftHSM2 stands in for an HSM: it enforces PKCS#11 semantics (sensitive,
  non-extractable, usage flags) but its keys are protected only by the token's
  file encryption and the user PIN — it is not a security boundary.

## 12. Known limitations

* **SoftHSM is software.** Its performance characteristics (§9) are not those
  of a hardware HSM, and its token files are only as safe as the host.
* **Vendor-specific error codes.** SoftHSM reports a GCM tag mismatch as
  `CKR_FUNCTION_FAILED` (2.7) or `CKR_GENERAL_ERROR` (2.6) and a failed RFC 5649
  unwrap as `CKR_GENERAL_ERROR`; for `C_Decrypt`/`C_UnwrapKey` the service maps
  these to `integrity_check_failed`. On a real HSM a genuine device fault during
  decrypt could thus surface as a 400; the mapping should be revisited per vendor.
* **Blocking calls cannot be cancelled.** On `HSM_OP_TIMEOUT_MS` the caller
  gets a 504, but the session stays busy until the HSM returns.
* **Public-key cache has no TTL.** After an operator rotates a key under the
  same label, restart the service (or add cache invalidation).
* **Provisioning is not concurrency-safe across processes**: two instances
  provisioning an empty token at the same moment could create duplicate labels
  (lookups then refuse to guess). Provision once (entrypoint/job), then scale.
* **IV uniqueness** relies on 96-bit random IVs: safe for well below 2³² messages
  per key (NIST SP 800-38D); high-volume use should rotate the data key or use
  envelope encryption (fresh DEK per message, as `/v1/envelope` does).
* `REQUEST_TIMEOUT_MS` produces an empty-bodied 503 (tower-http timeout layer).
* The mock backend wraps DEKs with AES-GCM rather than RFC 5649 (blobs are
  opaque; only the PKCS#11 backend is meant to be interoperable).
* `rsa` 0.9 carries advisory RUSTSEC-2023-0071 (timing side channel in
  *private-key* operations). It is used here only for public-key verification
  and in the test-only mock backend.
* Docker benchmarks ran on a shared host with other containers; absolute
  numbers are indicative, ratios are the useful part.

## 13. Security considerations

* **Key material never leaves the token**; the process handles object handles,
  digests, ciphertexts, wrapped blobs and public keys only. Enforced by token
  attributes, verified by tests (§5).
* **Least privilege on keys**: signing keys cannot decrypt/derive/unwrap; the
  data key cannot wrap; the KEK cannot encrypt data; ephemeral DEKs are session
  objects destroyed after use; unwrapped DEKs are non-extractable and
  decrypt-only.
* **PIN hygiene**: file-based secrets, `SecretString`, redacted `Debug`, never
  logged or put on a command line, generated PINs written 0600; no retry storms
  on a wrong PIN.
* **No information leaks in errors**: PKCS#11 details only in server logs.
* **Input hardening**: strict JSON (`deny_unknown_fields`), key-id charset and
  length, size limits checked before base64 decoding, transport body limit,
  request deadline.
* **DoS resistance**: bounded concurrency and queue, fast rejection, timeouts;
  tampered ciphertext/wrapped keys do not recycle the session pool.
* **Container**: non-root (uid 10001), `read_only` root filesystem, all
  capabilities dropped, `no-new-privileges`, token and PINs only on the `/data`
  volume (0700), no secrets in the image or build context (`.dockerignore`).
* **Not covered here (production work)**: client authentication/authorization,
  per-key/per-tenant policy, audit trail to an append-only store, mTLS.

## 14. Production considerations

* **Real HSM**: point `PKCS11_MODULE` at the vendor library; use the vendor's
  HA/load-balancing slot, size `HSM_POOL_SIZE` to the partition's parallelism
  and session limits; FIPS 140-3 Level 3 mode; separate partitions/roles for
  CA keys, KEKs and application keys; M-of-N for administrative operations.
* **Key lifecycle**: versioned labels (`...-v2`) with an alias map, rotation
  runbooks, `CKA_START_DATE`/`CKA_END_DATE`, destruction ceremonies; restrict
  `C_GenerateKey`/`C_DestroyObject` to an admin identity separate from the
  signing identity (crypto-user vs crypto-officer).
* **AuthN/Z + policy** in front of `/v1/sign`: who may sign with which key,
  what payload shapes (e.g. only TBSCertificate with constrained names), rate
  limits per client; immutable audit log of every signature (key id, digest,
  caller, request id).
* **Operations**: alerts on `pool_waiters`, `pool_acquire_timeouts_total`,
  `pool_rejections_total`, `operation_failures_total{reason="hsm_*"}` and sign
  p99; readiness gating; horizontal scaling stops at HSM capacity, so treat HSM
  ops/s as the capacity unit; run multiple replicas per HSM partition for
  process-level availability.
* **Supply chain**: pin base images by digest, SBOM + image scanning, signed
  images, `cargo audit`/`cargo deny` in CI, reproducible builds.
* **Graceful degradation**: clients honour `Retry-After` with jittered backoff;
  shed at the edge before the HSM tier.

---

## 15. Architecture question: 100,000 short-lived certificates per second

> Arkion must issue 100,000 short-lived certificates per second while the
> available HSM signing capacity is significantly lower.

### Capacity reality check

A network/cloud HSM partition sustains roughly **2,000–10,000 ECDSA P-256
signatures/s** in practice (vendor peak figures are higher, but with network
round trips, HA replication and other tenants this is a sane planning range).
Signing every leaf in HSMs would need 100,000 / ~5,000 ≈ **20 HSMs busy at all
times**, then N+1 per region and multi-region headroom: **~35–60 HSM units**, each
adding ~1–2 ms of network latency per issuance. (For calibration, SoftHSM in
this repo does ~35k/s — but it is software, which is exactly the point below.)

Meanwhile one CPU core does ~30,000–50,000 P-256 signatures/s in optimized
software (AWS-LC/BoringSSL/OpenSSL), i.e. ~10,000–20,000 complete certificates/s
including TBS construction and DER encoding. **100k certs/s is ~5–10 cores of
software signing.** The design question is therefore not "how do we get 20× more
HSM throughput" but "how do we keep HSM-grade assurance while the hot path signs
in software".

### Recommendation: HSMs anchor the hierarchy, short-lived issuing keys sign leaves

```
                 ┌──────────────────────────────────────────┐
  offline        │ Root CA  (HSM, air-gapped, M-of-N quorum) │  10–20 y; signs intermediates ~yearly
                 └──────────────────────┬───────────────────┘
                                        │ (ceremony)
          ┌─────────────────────────────┼──────────────────────────────┐
  online  │ Regional Intermediate CA (HSM cluster, non-exportable key)  │  1–3 y; signs ONLY issuing-CA certs
  (HSM)   │  region A                │  region B          │  region C   │  + CRLs  → a few signatures / minute
          └─────────────┬────────────┴─────────┬──────────┴──────┬─────┘
                        │ CSR + attestation    │                 │
          ┌─────────────┴─────────────┐        ...               ...
  hot     │ Issuing signers (N pods / enclaves per region)        │
  path    │  per-node ephemeral issuing-CA key, 6–24 h validity,  │  each ~10–20k leaf certs/s
 (software│  pathLen=0, nameConstraints, EKU-restricted           │  in software, in memory
 signing) └─────────────┬─────────────────────────────────────────┘
                        ▼
                 Leaf certificates (minutes – hours)  ──► async issuance log (audit / CT-style)
```

1. **Root CA — offline, HSM.** Key generated in an HSM, never online; used in
   quorum ceremonies to sign intermediates (and the root CRL). Backed up with
   the HSM vendor's M-of-N cloning to a second, geographically separate HSM.
2. **Regional intermediate CAs — online, HSM, low rate.** One per region (and
   per trust domain if needed), non-exportable keys in an HA HSM cluster. They
   sign *issuing-CA certificates* and CRLs only. This repo's service is exactly
   this tier: a small, bounded, HSM-backed signer with backpressure.
3. **Issuing CAs — short-lived keys in hardened signers.** Each signer node
   generates its own P-256 key **in memory** (ideally inside a TEE: Nitro
   Enclaves, SEV-SNP/TDX confidential VMs, SGX), submits a CSR plus a
   remote-attestation document to the intermediate service, and receives a
   6–24 h issuing-CA certificate constrained by `pathLenConstraint=0`, name
   constraints (tenant/region/trust-domain), EKU and short validity. The key is
   never written to disk and never shared between nodes; it rotates at ~50 % of
   its lifetime with overlap, so certificates are always issued from a key with
   hours of validity left.
4. **Leaf signing in software** on those nodes: 100k/s across regions is a few
   dozen cores, horizontally scalable, sub-millisecond, no HSM round trip.

**Should every leaf signature occur inside the HSM? No.** It would cost an
order of magnitude more, add latency and a hard dependency on HSM availability
for every issuance, and buy little: for certificates that live minutes to
hours, the important properties — *who can mint an issuing CA*, *scope*, and
*how long a stolen key is useful* — are enforced by the HSM-protected
intermediate, name constraints and short lifetimes. HSM-per-leaf is warranted
only if a regulator or a relying party explicitly requires every end-entity
signature to come from certified hardware.

### Key wrapping vs software signing (and other options)

| option | how | pros | cons |
|---|---|---|---|
| **A. Ephemeral issuing key generated in TEE/memory** (recommended) | key born in the signer, cert from HSM intermediate after attestation | no key transport; compromise limited to one node × hours; trivially scalable | key in RAM while in use; needs good RNG and attestation plumbing |
| **B. HSM-generated, wrapped issuing keys** | HSM generates the issuing key, exports it wrapped (`C_WrapKey` under a KEK, ideally `CKA_WRAP_WITH_TRUSTED`); KEK/unwrap released to an attested enclave (e.g. KMS key policy bound to enclave measurements) | key provenance from a certified RNG; keys can survive restarts / be escrowed; central inventory | plaintext key still in enclave memory at use time; KEK becomes a high-value target; more moving parts |
| **C. Merkle-tree batch signing** | HSM signs the root of a Merkle tree over a batch of TBS certs; each leaf carries an inclusion proof | 1 HSM signature per batch (1,000 leaves → 100 HSM ops/s), every leaf HSM-anchored | **not standard X.509** — verifiers must understand it (cf. the IETF *Merkle Tree Certificates* work); adds batch latency (10–100 ms) and ~log₂(n)×32 B proofs; viable only where we control all relying parties |
| **D. HSM per leaf** | every signature via PKCS#11 | strongest per-signature assurance | ~35–60 HSMs, latency, cost, HSM outage = issuance outage |
| **E. Faster algorithms** | Ed25519 issuing keys | ~2× cheaper software signing | limited support in generic X.509 stacks (fine in a controlled mesh) |

Batching *calls* to HSMs (many sessions, vendor bulk APIs) improves HSM
utilization but not cost per signature; Merkle batching changes the math but
requires verifier support. A and B compose: B is the right choice when
issuing keys must be recoverable or centrally inventoried; A when per-node,
disposable keys are acceptable (usually the case for workload identity).

### Regional capacity and failover

* **Active-active in ≥3 regions**, each sized for ~50–60 % of global peak so
  the loss of one region is absorbed (N+1 at region level). Per region: e.g.
  6–10 issuing pods of ~4–8 vCPUs with autoscaling on CPU/queue depth, plus a
  2–3 HSM cluster for the intermediate (sized for HA, not throughput: issuing-CA
  certificates are ~#nodes × rotations/day ≈ a few hundred per day).
* **HSM outage tolerance**: signers hold issuing keys valid for hours and renew
  at half-life, so a regional HSM/intermediate outage does not stop issuance
  until the remaining validity runs out — RTO for the HSM tier just has to be
  well below that (e.g. < 3 h for 12 h issuing certs). Pre-provision the *next*
  issuing certificate ahead of time to widen the buffer.
* **Region failure**: clients fail over (global LB/anycast/DNS) to another
  region; all regional intermediates chain to the same root, so trust is
  unaffected. Intermediates are per region (separate compromise and failure
  domains), cloned across the HSMs *within* a region for HA.
* **Root** is offline and only needed for new intermediates; keep pre-signed
  successor intermediates ready so a regional intermediate compromise can be
  handled without an emergency ceremony.

### Security implications

* The **blast radius** of a compromised signer node is one issuing key, bounded
  by its name constraints and ≤24 h validity; response = stop renewing it,
  revoke its issuing-CA certificate via the intermediate's (HSM-signed) CRL,
  and let leaves expire. A compromised node cannot mint new issuing CAs — that
  requires the HSM-held intermediate key and a valid attestation.
* **Issuance policy before signing**: authenticate requesters (workload
  attestation/SPIFFE-style), enforce name/SAN policy and per-identity rate
  limits in the signer, so a stolen request credential cannot mint arbitrary
  names.
* **Audit**: every leaf (or at least its hash, serial, subject, issuing key) is
  appended asynchronously to an append-only issuance log (a private CT-style
  Merkle log or a WORM store) and monitored for unexpected names — off the hot
  path.
* **Revocation**: short-lived leaves are not revoked (no OCSP/CRL for leaves;
  expiry is the revocation mechanism — also the CA/B Forum short-lived-cert
  direction). Revocation happens at the issuing-CA level, which is rare and
  cheap. **CT**: 100k certs/s is a private-PKI workload (service mesh / workload
  identity); public CT logs neither require nor could absorb it. Publicly
  trusted certificates, if any, go through a separate, low-volume, CT-logged
  path.
* **Separation of duties**: distinct HSM partitions and roles for root,
  intermediates and KEKs; M-of-N for root and intermediate operations.

### Cost (rough, HSM-unit terms)

| design | HSM units | other |
|---|---|---|
| HSM per leaf | ~20 busy + N+1 per region × 3 regions ≈ **35–60 HSMs** | plus latency and an HSM-bound outage profile |
| Recommended (A/B) | 2 offline root HSMs + 2–3 per region × 3 regions ≈ **8–11 HSMs** | ~10 cores of signing at peak; ~50–100 vCPUs fleet-wide with headroom and HA |

At typical cloud-HSM pricing (on the order of $1–2k per HSM-month) that is
roughly **$50–100k/month vs $10–20k/month**, with the recommended design also
being faster (no network hop per certificate) and more available (issuance
survives HSM outages for hours). The HSM budget is spent where it matters: on
the keys whose compromise would be catastrophic and long-lived.
# rust-hsm-signer
