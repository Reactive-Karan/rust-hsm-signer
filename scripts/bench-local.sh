#!/usr/bin/env bash
# Run the load generator against a locally built (release) service backed by
# a throw-away SoftHSM2 token. All state lives under target/ (gitignored).
#
#   scripts/bench-local.sh                       # defaults: pool 8, 1/10/100/500 callers, 15 s
#   HSM_POOL_SIZE=4 CONCURRENCY=100 DURATION=10 scripts/bench-local.sh
#   ALGORITHM=ED25519 KEY_ID=arkion-ed25519-prod scripts/bench-local.sh
#
# Any HSM_* / RUST_LOG variable in the environment is passed to the service.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD/target/bench-softhsm"
PORT="${PORT:-18080}"
DURATION="${DURATION:-15}"
WARMUP="${WARMUP:-2}"
CONCURRENCY="${CONCURRENCY:-1,10,100,500}"
ALGORITHM="${ALGORITHM:-ECDSA_P256_SHA256}"
KEY_ID="${KEY_ID:-arkion-intermediate-prod}"
LABEL="${LABEL:-pool=${HSM_POOL_SIZE:-8}}"

if [ -z "${PKCS11_MODULE:-}" ]; then
    for candidate in /usr/lib/softhsm/libsofthsm2.so \
                     /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                     /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
                     /usr/local/lib/softhsm/libsofthsm2.so \
                     /opt/homebrew/lib/softhsm/libsofthsm2.so; do
        if [ -e "$candidate" ]; then PKCS11_MODULE="$candidate"; break; fi
    done
fi
: "${PKCS11_MODULE:?SoftHSM2 module not found; set PKCS11_MODULE}"
export PKCS11_MODULE

cargo build --release --locked --bins >&2

# Fresh token per run.
rm -rf "$ROOT" && mkdir -p "$ROOT/tokens" && chmod 700 "$ROOT"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$ROOT" > "$ROOT/softhsm2.conf"
(umask 077; od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > "$ROOT/user.pin"; od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > "$ROOT/so.pin")
export SOFTHSM2_CONF="$ROOT/softhsm2.conf" HSM_PIN_FILE="$ROOT/user.pin" HSM_SO_PIN_FILE="$ROOT/so.pin"
export LISTEN_ADDR="127.0.0.1:$PORT" RUST_LOG="${RUST_LOG:-info}"

ulimit -n 65536 2>/dev/null || ulimit -n 8192 2>/dev/null || true
./target/release/hsm-signer init-token 2>/dev/null
./target/release/hsm-signer serve --provision > "$ROOT/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1 && break
    sleep 0.1
done

./target/release/loadgen --url "http://127.0.0.1:$PORT" --concurrency "$CONCURRENCY" \
    --duration "$DURATION" --warmup "$WARMUP" --algorithm "$ALGORITHM" --key-id "$KEY_ID" --label "$LABEL" \
    ${LOADGEN_FORMAT:+--format "$LOADGEN_FORMAT"}
