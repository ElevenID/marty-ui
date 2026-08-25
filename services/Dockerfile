# Public Marty service image. Build context: marty-ui repository root.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS rust-service-builder

WORKDIR /build/rust
COPY rust /build/rust
COPY proto /build/proto
COPY contracts /build/contracts
COPY services/auth/assets /build/services/auth/assets
RUN cargo build --locked --release \
    -p marty-event-stream --bin marty-event-stream \
    -p marty-gateway --bin marty-gateway \
    -p marty-revocation-profile --bin marty-revocation-profile \
    -p marty-signing-keys --bin marty-signing-keys \
    -p marty-notification --bin marty-notification \
    -p marty-flow --bin marty-flow \
    -p marty-organization --bin marty-organization \
    -p marty-auth --bin marty-auth \
    -p marty-credential-template --bin marty-credential-template \
    -p marty-presentation-policy --bin marty-presentation-policy \
    -p marty-trust-profile --bin marty-trust-profile \
    -p marty-applicant --bin marty-applicant \
    -p marty-device-registration --bin marty-device-registration \
    -p marty-verification-service --bin marty-verification-service \
    -p marty-deployment-profile --bin marty-deployment-profile \
    -p marty-compliance-profile --bin marty-compliance-profile

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
COPY --from=rust-service-builder /build/rust/target/release/marty-notification /usr/local/bin/marty-notification
COPY --from=rust-service-builder /build/rust/target/release/marty-flow /usr/local/bin/marty-flow
COPY --from=rust-service-builder /build/rust/target/release/marty-organization /usr/local/bin/marty-organization
COPY --from=rust-service-builder /build/rust/target/release/marty-auth /usr/local/bin/marty-auth
COPY --from=rust-service-builder /build/rust/target/release/marty-credential-template /usr/local/bin/marty-credential-template
COPY --from=rust-service-builder /build/rust/target/release/marty-presentation-policy /usr/local/bin/marty-presentation-policy
COPY --from=rust-service-builder /build/rust/target/release/marty-trust-profile /usr/local/bin/marty-trust-profile
COPY --from=rust-service-builder /build/rust/target/release/marty-applicant /usr/local/bin/marty-applicant
COPY --from=rust-service-builder /build/rust/target/release/marty-device-registration /usr/local/bin/marty-device-registration
COPY --from=rust-service-builder /build/rust/target/release/marty-verification-service /usr/local/bin/marty-verification-service
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
