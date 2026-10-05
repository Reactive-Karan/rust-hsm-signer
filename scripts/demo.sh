#!/usr/bin/env bash
# Walk through the API against a running service and cross-check signatures
# with OpenSSL (independent implementation, public key exported from the HSM).
#
#   scripts/demo.sh [base-url]        (default http://127.0.0.1:8080; needs curl, jq, openssl)
set -euo pipefail

BASE="${1:-http://127.0.0.1:8080}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

post() { curl -sS -H 'content-type: application/json' -d "$2" "$BASE$1"; }
b64() { base64 | tr -d '\n'; }

printf 'hello from the demo' > "$WORK/msg.bin"
PAYLOAD=$(b64 < "$WORK/msg.bin")

echo "# readiness";               curl -sS "$BASE/readyz"; echo
echo "# keys and their attributes"; curl -sS "$BASE/v1/keys" | jq -c '.keys[] | {key_id, key_type, usage, extractable: .attributes.extractable}'

for spec in "arkion-intermediate-prod ECDSA_P256_SHA256" "arkion-ed25519-prod ED25519" "arkion-rsa-pss-prod RSA_PSS_SHA256"; do
    set -- $spec
    echo "# sign with $1 ($2)"
    resp=$(post /v1/sign "{\"key_id\":\"$1\",\"algorithm\":\"$2\",\"payload\":\"$PAYLOAD\"}")
    echo "$resp" | jq -c '{key_id, algorithm, duration_ms, signature: (.signature[:32] + "...")}'
    jq -r .signature <<<"$resp" | base64 --decode > "$WORK/$1.sig"
    curl -sS "$BASE/v1/keys/$1/public" | jq -r .public_key_pem > "$WORK/$1.pem"
    echo -n "  service verify (software): "
    post /v1/verify "{\"key_id\":\"$1\",\"algorithm\":\"$2\",\"payload\":\"$PAYLOAD\",\"signature\":\"$(jq -r .signature <<<"$resp")\"}" | jq -c .valid
    echo -n "  openssl verify:             "
    case "$2" in
        ECDSA_P256_SHA256) openssl dgst -sha256 -verify "$WORK/$1.pem" -signature "$WORK/$1.sig" "$WORK/msg.bin" ;;
        ED25519) openssl pkeyutl -verify -pubin -inkey "$WORK/$1.pem" -rawin -in "$WORK/msg.bin" -sigfile "$WORK/$1.sig" ;;
        RSA_PSS_SHA256) openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
            -sigopt rsa_mgf1_md:sha256 -verify "$WORK/$1.pem" -signature "$WORK/$1.sig" "$WORK/msg.bin" ;;
    esac
done

echo "# AES-256-GCM with the non-extractable data key"
enc=$(post /v1/encrypt "{\"key_id\":\"arkion-data-key\",\"plaintext\":\"$PAYLOAD\",\"aad\":\"$(printf 'order-42' | b64)\"}")
echo "$enc" | jq -c .
post /v1/decrypt "$(jq -c '{key_id, iv, ciphertext, aad: "b3JkZXItNDI="}' <<<"$enc")" | jq -r .plaintext | base64 --decode; echo
echo -n "  tampered AAD → "
post /v1/decrypt "$(jq -c '{key_id, iv, ciphertext, aad: "b3JkZXItNDM="}' <<<"$enc")" | jq -c .

echo "# envelope encryption (DEK generated in the HSM, exported only wrapped)"
env=$(post /v1/envelope/encrypt "{\"wrapping_key_id\":\"arkion-wrapping-key\",\"plaintext\":\"$PAYLOAD\"}")
echo "$env" | jq -c .
post /v1/envelope/decrypt "$(jq -c '{wrapping_key_id, wrapped_key, iv, ciphertext}' <<<"$env")" | jq -r .plaintext | base64 --decode; echo

echo "# error mapping"
post /v1/sign "{\"key_id\":\"no-such-key\",\"algorithm\":\"ECDSA_P256_SHA256\",\"payload\":\"$PAYLOAD\"}"; echo
post /v1/sign "{\"key_id\":\"arkion-intermediate-prod\",\"algorithm\":\"HS256\",\"payload\":\"$PAYLOAD\"}"; echo
post /v1/sign "{\"key_id\":\"arkion-intermediate-prod\",\"algorithm\":\"ECDSA_P256_SHA256\",\"payload\":\"***\"}"; echo
