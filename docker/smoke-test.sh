#!/bin/bash
# End-to-end smoke test of the runtime image, executed by the Dockerfile's
# `smoke` stage (no `docker run` needed):
#
#   docker build --target smoke --progress=plain .
#
# Starts the real entrypoint (random PIN generation, token initialization,
# key provisioning), exercises every endpoint over HTTP, checks that secrets
# are not leaked, restarts to prove idempotency, and runs a short load test.
set -euo pipefail

BASE=http://127.0.0.1:8080
LOG=/tmp/server.log
BENCH_DURATION="${BENCH_DURATION:-5}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1,10,100,500}"
BENCH_ALGORITHM="${BENCH_ALGORITHM:-ECDSA_P256_SHA256}"
BENCH_KEY_ID="${BENCH_KEY_ID:-arkion-intermediate-prod}"

# Leave no token, PINs or logs behind in the image layer this runs in.
cleanup() { rm -rf /data/tokens/* /data/*.pin "$LOG" 2>/dev/null || true; }
trap cleanup EXIT

fail() { echo "SMOKE FAILED: $*" >&2; echo "--- server log (tail) ---" >&2; tail -n 8 "$LOG" >&2 || true; exit 1; }

start_server() {
    docker-entrypoint serve >>"$LOG" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 100); do
        curl -fsS "$BASE/readyz" >/dev/null 2>&1 && return 0
        kill -0 "$SERVER_PID" 2>/dev/null || fail "server exited during startup"
        sleep 0.1
    done
    fail "server not ready after 10s"
}

stop_server() {
    kill -TERM "$SERVER_PID"
    local status=0
    wait "$SERVER_PID" || status=$?
    [ "$status" -eq 0 ] || fail "server exited with status $status on SIGTERM"
}

post() { curl -sS -H 'content-type: application/json' -d "$2" "$BASE$1"; }

echo "== first start (token init + provisioning)"
start_server
curl -fsS "$BASE/healthz"; echo
curl -fsS "$BASE/readyz"; echo

PAYLOAD=$(printf 'hello from the smoke test' | base64 -w0)
for pair in arkion-intermediate-prod:ECDSA_P256_SHA256 arkion-ed25519-prod:ED25519 arkion-rsa-pss-prod:RSA_PSS_SHA256; do
    key=${pair%%:*}; alg=${pair##*:}
    resp=$(post /v1/sign "{\"key_id\":\"$key\",\"algorithm\":\"$alg\",\"payload\":\"$PAYLOAD\"}")
    sig=$(jq -er .signature <<<"$resp") || fail "sign $alg: $resp"
    for verifier in software hsm; do
        valid=$(post /v1/verify "{\"key_id\":\"$key\",\"algorithm\":\"$alg\",\"payload\":\"$PAYLOAD\",\"signature\":\"$sig\",\"verifier\":\"$verifier\"}" | jq -r .valid)
        [ "$valid" = true ] || fail "verify $alg/$verifier"
    done
    echo "sign+verify $alg: ok ($(jq -r .duration_ms <<<"$resp") ms)"
done

curl -fsS "$BASE/v1/keys/arkion-intermediate-prod/public" | jq -e '.public_key_pem | startswith("-----BEGIN PUBLIC KEY-----")' >/dev/null \
    || fail "public key"

enc=$(post /v1/encrypt "{\"key_id\":\"arkion-data-key\",\"plaintext\":\"$PAYLOAD\",\"aad\":\"$(printf ctx | base64 -w0)\"}")
dec=$(post /v1/decrypt "$(jq -c '{key_id, iv, ciphertext} + {aad: "Y3R4"}' <<<"$enc")")
[ "$(jq -r .plaintext <<<"$dec")" = "$PAYLOAD" ] || fail "AES-GCM round trip: $dec"
bad=$(post /v1/decrypt "$(jq -c '{key_id, iv, ciphertext} + {aad: "eHh4"}' <<<"$enc")")
[ "$(jq -r .error <<<"$bad")" = integrity_check_failed ] || fail "AES-GCM tamper detection: $bad"
echo "AES-256-GCM encrypt/decrypt/tamper: ok"

env=$(post /v1/envelope/encrypt "{\"wrapping_key_id\":\"arkion-wrapping-key\",\"plaintext\":\"$PAYLOAD\"}")
out=$(post /v1/envelope/decrypt "$(jq -c '{wrapping_key_id, wrapped_key, iv, ciphertext}' <<<"$env")")
[ "$(jq -r .plaintext <<<"$out")" = "$PAYLOAD" ] || fail "envelope round trip: $out"
echo "envelope wrap/unwrap: ok"

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
    -d "{\"key_id\":\"nope\",\"algorithm\":\"ECDSA_P256_SHA256\",\"payload\":\"$PAYLOAD\"}" "$BASE/v1/sign")
[ "$code" = 404 ] || fail "unknown key should be 404, got $code"

HSM_PIN_FILE=/data/user.pin hsm-signer keys 2>/dev/null | jq -e 'all(.[]; .attributes.extractable == false and .attributes.sensitive == true and .attributes.never_extractable == true)' >/dev/null \
    || fail "key attributes"
echo "non-exportable key attributes: ok"

curl -fsS "$BASE/metrics" | grep -q 'hsm_signer_sign_duration_seconds_count' || fail "metrics"

[ "$(stat -c '%a' /data/user.pin)" = 600 ] || fail "PIN file must be 0600"
grep -qF "$(cat /data/user.pin)" "$LOG" && fail "PIN value found in logs"
grep -q 'generated a random one' "$LOG" || fail "expected PIN generation notice"
stop_server

echo "== second start (must be idempotent)"
start_server
grep -q 'AlreadyInitialized' "$LOG" || fail "token re-initialized on restart"
[ "$(grep -c '"outcome":"AlreadyPresent"' "$LOG")" -ge 5 ] || fail "keys re-created on restart"
echo "restart idempotency: ok"

echo "== load test (${BENCH_DURATION}s per level)"
loadgen --url "$BASE" --concurrency "$BENCH_CONCURRENCY" --duration "$BENCH_DURATION" --warmup 2 \
    --algorithm "$BENCH_ALGORITHM" --key-id "$BENCH_KEY_ID" --label "docker pool=${HSM_POOL_SIZE:-8}"
stop_server
echo "SMOKE TEST PASSED"
