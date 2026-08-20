# Public Marty service image. Build context: marty-ui repository root.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS rust-service-builder

WORKDIR /build/rust
COPY rust /build/rust
COPY proto /build/proto
RUN cargo build --locked --release -p marty-event-stream --bin marty-event-stream
RUN cargo build --locked --release -p marty-gateway --bin marty-gateway
RUN cargo build --locked --release -p marty-revocation-profile --bin marty-revocation-profile
RUN cargo build --locked --release -p marty-signing-keys --bin marty-signing-keys
RUN cargo build --locked --release -p marty-notification --bin marty-notification

FROM python:3.12-slim

ARG SERVICE_NAME
ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown
ARG MARTY_RS_VERSION=0.1.0
ARG MARTY_RS_URI
ARG MARTY_RS_DIGEST
ARG MARTY_VERIFICATION_VERSION=0.1.0
ARG MARTY_VERIFICATION_URI
ARG MARTY_VERIFICATION_DIGEST
ARG MARTY_ISO18013_VERSION=0.1.0
ARG MARTY_ISO18013_URI
ARG MARTY_ISO18013_DIGEST
ARG MARTY_COMMON_VERSION=0.2.3
ARG MARTY_COMMON_URI
ARG MARTY_COMMON_DIGEST

LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app:/app/packages:/app/services \
    SERVICE_NAME=${SERVICE_NAME} \
    MARTY_RELEASE_VERSION=${MARTY_RELEASE_VERSION} \
    MARTY_UI_SHA=${MARTY_UI_SHA}

WORKDIR /app
COPY requirements-services.txt /tmp/requirements-services.txt
RUN test -n "$MARTY_RS_URI" \
    && test -n "$MARTY_RS_DIGEST" \
    && test -n "$MARTY_VERIFICATION_URI" \
    && test -n "$MARTY_VERIFICATION_DIGEST" \
    && test -n "$MARTY_ISO18013_URI" \
    && test -n "$MARTY_ISO18013_DIGEST" \
    && test -n "$MARTY_COMMON_URI" \
    && test -n "$MARTY_COMMON_DIGEST" \
    && MARTY_RS_WHEEL="/tmp/${MARTY_RS_URI##*/}" \
    && MARTY_VERIFICATION_WHEEL="/tmp/${MARTY_VERIFICATION_URI##*/}" \
    && MARTY_ISO18013_WHEEL="/tmp/${MARTY_ISO18013_URI##*/}" \
    && MARTY_COMMON_WHEEL="/tmp/${MARTY_COMMON_URI##*/}" \
    && curl --fail --location --silent --show-error "$MARTY_RS_URI" --output "$MARTY_RS_WHEEL" \
    && curl --fail --location --silent --show-error "$MARTY_VERIFICATION_URI" --output "$MARTY_VERIFICATION_WHEEL" \
    && curl --fail --location --silent --show-error "$MARTY_ISO18013_URI" --output "$MARTY_ISO18013_WHEEL" \
    && curl --fail --location --silent --show-error "$MARTY_COMMON_URI" --output "$MARTY_COMMON_WHEEL" \
    && echo "${MARTY_RS_DIGEST#sha256:}  $MARTY_RS_WHEEL" | sha256sum --check --strict \
    && echo "${MARTY_VERIFICATION_DIGEST#sha256:}  $MARTY_VERIFICATION_WHEEL" | sha256sum --check --strict \
    && echo "${MARTY_ISO18013_DIGEST#sha256:}  $MARTY_ISO18013_WHEEL" | sha256sum --check --strict \
    && echo "${MARTY_COMMON_DIGEST#sha256:}  $MARTY_COMMON_WHEEL" | sha256sum --check --strict \
    && pip install --no-cache-dir -r /tmp/requirements-services.txt "$MARTY_RS_WHEEL" "$MARTY_VERIFICATION_WHEEL" "$MARTY_ISO18013_WHEEL" "$MARTY_COMMON_WHEEL"

COPY packages/marty_proto /app/packages/marty_proto
COPY services /app/services
COPY scripts/load-secrets-env.sh /app/load-secrets-env.sh
COPY --from=rust-service-builder /build/rust/target/release/marty-event-stream /usr/local/bin/marty-event-stream
COPY --from=rust-service-builder /build/rust/target/release/marty-gateway /usr/local/bin/marty-gateway
COPY --from=rust-service-builder /build/rust/target/release/marty-revocation-profile /usr/local/bin/marty-revocation-profile
COPY --from=rust-service-builder /build/rust/target/release/marty-signing-keys /usr/local/bin/marty-signing-keys
COPY --from=rust-service-builder /build/rust/target/release/marty-notification /usr/local/bin/marty-notification
RUN chmod +x /app/services/entrypoint.sh /app/load-secrets-env.sh \
    && adduser --disabled-password --gecos '' appuser \
    && install -d -o appuser -g appuser -m 0700 /app/data

USER appuser
WORKDIR /app/services
CMD ["/app/services/entrypoint.sh"]
