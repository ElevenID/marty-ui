FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /build
COPY rust /build/rust
COPY proto /build/proto
WORKDIR /build/rust
RUN cargo build --locked --release -p marty-revocation-profile --bin marty-revocation-profile

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown
LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin marty

COPY --from=builder /build/rust/target/release/marty-revocation-profile /usr/local/bin/marty-revocation-profile
COPY scripts/load-secrets-env.sh /usr/local/bin/load-secrets-env.sh

ENV REVOCATION_PROFILE_SERVICE_PORT=8013 \
    RP_GRPC_ENABLED=true \
    RP_GRPC_PORT=9013 \
    MARTY_RELEASE_VERSION=${MARTY_RELEASE_VERSION} \
    MARTY_UI_SHA=${MARTY_UI_SHA} \
    RUST_LOG=info

USER 10001:10001
EXPOSE 8013 9013
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=5 \
    CMD ["curl", "--fail", "http://127.0.0.1:8013/health"]
ENTRYPOINT ["/bin/sh", "-c", ". /usr/local/bin/load-secrets-env.sh && exec /usr/local/bin/marty-revocation-profile"]
