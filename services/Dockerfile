# syntax=docker/dockerfile:1.7
# Public Marty service image. Build context: marty-ui repository root.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS rust-service-base

RUN --mount=type=cache,id=marty-public-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=marty-public-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo install cargo-chef --locked --version 0.1.78

WORKDIR /build/rust

FROM rust-service-base AS rust-service-planner

COPY rust /build/rust
COPY proto /build/proto
RUN cargo chef prepare --recipe-path recipe.json

FROM rust-service-base AS rust-service-cache

ADD --checksum=sha256:aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588 https://github.com/mozilla/sccache/releases/download/v0.16.0/sccache-v0.16.0-x86_64-unknown-linux-musl.tar.gz /tmp/sccache.tar.gz
ADD --checksum=sha256:f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784 https://github.com/mozilla/sccache/releases/download/v0.16.0/sccache-v0.16.0-aarch64-unknown-linux-musl.tar.gz /tmp/sccache-aarch64.tar.gz
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) archive=/tmp/sccache.tar.gz; target=x86_64 ;; \
      arm64) archive=/tmp/sccache-aarch64.tar.gz; target=aarch64 ;; \
      *) echo "Unsupported public builder architecture: $TARGETARCH" >&2; exit 2 ;; \
    esac \
    && tar -xzf "$archive" -C /tmp \
    && install "/tmp/sccache-v0.16.0-${target}-unknown-linux-musl/sccache" /usr/local/bin/sccache \
    && rm /tmp/sccache.tar.gz /tmp/sccache-aarch64.tar.gz

COPY --chmod=755 scripts/ci/run-public-rust-build.sh /usr/local/bin/run-public-rust-build

FROM rust-service-cache AS rust-service-dependencies

COPY --from=rust-service-planner /build/rust/recipe.json recipe.json
COPY --from=rust-service-planner /build/rust/third_party /build/rust/third_party
COPY proto /build/proto
RUN --mount=type=cache,id=marty-public-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=marty-public-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=secret,id=sccache_token \
    --mount=type=secret,id=sccache_url \
    --mount=type=secret,id=sccache_mode \
    run-public-rust-build cargo chef cook --locked --release --workspace --recipe-path recipe.json

FROM rust-service-dependencies AS rust-service-builder

COPY rust /build/rust
COPY proto /build/proto
COPY contracts /build/contracts
COPY services/auth/assets /build/services/auth/assets
COPY --chmod=755 scripts/build-rust-service-binaries.sh /usr/local/bin/build-rust-service-binaries

# Preserve the exact public release binary list and KMS-only profile.
RUN --mount=type=cache,id=marty-public-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=marty-public-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=secret,id=sccache_token \
    --mount=type=secret,id=sccache_url \
    --mount=type=secret,id=sccache_mode \
    run-public-rust-build build-rust-service-binaries default

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown

LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && install -d -o appuser -g appuser -m 0700 /app/data

ENV MARTY_RELEASE_VERSION=${MARTY_RELEASE_VERSION} \
    MARTY_UI_SHA=${MARTY_UI_SHA}

COPY services/entrypoint.sh /app/services/entrypoint.sh
COPY scripts/load-secrets-env.sh /app/load-secrets-env.sh
COPY --from=rust-service-builder /build/rust/target/release/marty-event-stream /usr/local/bin/marty-event-stream
COPY --from=rust-service-builder /build/rust/target/release/marty-gateway /usr/local/bin/marty-gateway
COPY --from=rust-service-builder /build/rust/target/release/marty-revocation-profile /usr/local/bin/marty-revocation-profile
COPY --from=rust-service-builder /build/rust/target/release/marty-signing-keys /usr/local/bin/marty-signing-keys
COPY --from=rust-service-builder /build/rust/target/release/marty-passport-callback-signer /usr/local/bin/marty-passport-callback-signer
COPY --from=rust-service-builder /build/rust/target/release/marty-passport-callback-signer-supported /usr/local/bin/marty-passport-callback-signer-supported
COPY --from=rust-service-builder /build/rust/target/release/marty-notification /usr/local/bin/marty-notification
COPY --from=rust-service-builder /build/rust/target/release/marty-flow /usr/local/bin/marty-flow
COPY --from=rust-service-builder /build/rust/target/release/marty-organization /usr/local/bin/marty-organization
COPY --from=rust-service-builder /build/rust/target/release/marty-passport-acceptance-api-key /usr/local/bin/marty-passport-acceptance-api-key
COPY --from=rust-service-builder /build/rust/target/release/marty-auth /usr/local/bin/marty-auth
COPY --from=rust-service-builder /build/rust/target/release/marty-credential-template /usr/local/bin/marty-credential-template
COPY --from=rust-service-builder /build/rust/target/release/marty-presentation-policy /usr/local/bin/marty-presentation-policy
COPY --from=rust-service-builder /build/rust/target/release/marty-verifier-positive-gate /usr/local/bin/marty-verifier-positive-gate
COPY --from=rust-service-builder /build/rust/target/release/marty-trust-profile /usr/local/bin/marty-trust-profile
COPY --from=rust-service-builder /build/rust/target/release/marty-applicant /usr/local/bin/marty-applicant
COPY --from=rust-service-builder /build/rust/target/release/marty-device-registration /usr/local/bin/marty-device-registration
COPY --from=rust-service-builder /build/rust/target/release/marty-verification-service /usr/local/bin/marty-verification-service
COPY --from=rust-service-builder /build/rust/target/release/marty-issuance-service /usr/local/bin/marty-issuance-service
COPY --from=rust-service-builder /build/rust/target/release/marty-canvas-sync-worker /usr/local/bin/marty-canvas-sync-worker
COPY --from=rust-service-builder /build/rust/target/release/marty-passport-beta-bureau /usr/local/bin/marty-passport-beta-bureau
COPY --from=rust-service-builder /build/rust/target/release/marty-passport-provider-ingress /usr/local/bin/marty-passport-provider-ingress
COPY --from=rust-service-builder /build/rust/target/release/marty-deployment-profile /usr/local/bin/marty-deployment-profile
COPY --from=rust-service-builder /build/rust/target/release/marty-compliance-profile /usr/local/bin/marty-compliance-profile
RUN chmod +x /app/services/entrypoint.sh /app/load-secrets-env.sh

# Keep the only service-specific build argument after every filesystem layer.
# All service images contain the same binaries and select their entrypoint at
# runtime, so this preserves immutable per-service metadata without rebuilding
# or duplicating the shared Rust runtime for each Compose target.
ARG SERVICE_NAME
ENV SERVICE_NAME=${SERVICE_NAME}

USER 10001:10001
WORKDIR /app/services
CMD ["/app/services/entrypoint.sh"]
