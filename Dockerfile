# syntax=docker/dockerfile:1.7
#
# Build:   docker build -t hsm-signer:latest .   (final stage = runtime image)
# Tests:   docker build --target test .         (unit + SoftHSM2 integration tests)
# Smoke:   docker build --target smoke --progress=plain .   (e2e test of the runtime image)
# Run:     docker compose up -d                 (see README)

ARG RUST_IMAGE=rust:1-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------- builder ---
FROM ${RUST_IMAGE} AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
COPY tests ./tests
COPY examples ./examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=hsm-signer-target \
    cargo build --release --locked --bins --example direct_bench \
 && mkdir -p /out \
 && cp target/release/hsm-signer target/release/loadgen /out/ \
 && cp target/release/examples/direct_bench /out/hsm-direct-bench

# ------------------------------------------------------------------- test ---
# `docker build --target test .` runs the whole suite against SoftHSM2 inside
# the container; HSM_TESTS_REQUIRED=1 turns "SoftHSM missing" into a failure.
FROM builder AS test
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    HSM_TESTS_REQUIRED=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=hsm-signer-test-target \
    cargo test --locked 2>&1 | tee /test-report.txt

# ----------------------------------------------------------- runtime-base ---
FROM ${RUNTIME_IMAGE} AS runtime-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin hsm \
 && mkdir -p /data/tokens /etc/hsm-signer \
 && chown -R hsm:hsm /data \
 && chmod 0700 /data /data/tokens

COPY docker/softhsm2.conf /etc/hsm-signer/softhsm2.conf
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint
COPY --from=builder /out/hsm-signer /out/loadgen /out/hsm-direct-bench /usr/local/bin/

ENV SOFTHSM2_CONF=/etc/hsm-signer/softhsm2.conf \
    PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    HSM_TOKEN_LABEL=arkion \
    HSM_DATA_DIR=/data \
    LISTEN_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json \
    RUST_LOG=info

USER hsm:hsm
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

# Readiness = a logged-in HSM session can be acquired (no curl needed).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /readyz HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["docker-entrypoint"]
CMD ["serve"]

# ------------------------------------------------------------------ smoke ---
# End-to-end test of the *runtime* image without `docker run`:
#   docker build --target smoke --progress=plain .
FROM runtime-base AS smoke
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY docker/smoke-test.sh /usr/local/bin/smoke-test
USER hsm:hsm
# Load-test knobs (`--build-arg BENCH_DURATION=15 --build-arg HSM_POOL_SIZE=4 ...`).
ARG BENCH_DURATION=5
ARG BENCH_CONCURRENCY=1,10,100,500
ARG BENCH_ALGORITHM=ECDSA_P256_SHA256
ARG BENCH_KEY_ID=arkion-intermediate-prod
ARG HSM_POOL_SIZE=
ARG HSM_MAX_WAITERS=
ARG HSM_ACQUIRE_TIMEOUT_MS=
RUN BENCH_DURATION=${BENCH_DURATION} BENCH_CONCURRENCY=${BENCH_CONCURRENCY} \
    BENCH_ALGORITHM=${BENCH_ALGORITHM} BENCH_KEY_ID=${BENCH_KEY_ID} \
    HSM_POOL_SIZE=${HSM_POOL_SIZE} HSM_MAX_WAITERS=${HSM_MAX_WAITERS} \
    HSM_ACQUIRE_TIMEOUT_MS=${HSM_ACQUIRE_TIMEOUT_MS} \
    smoke-test

# ---------------------------------------------------------------- runtime ---
# Last stage = default build target: `docker build -t hsm-signer:latest .`
FROM runtime-base AS runtime
