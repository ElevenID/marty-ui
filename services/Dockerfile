# Public Marty service image. Build context: marty-ui repository root.
FROM python:3.12-slim

ARG SERVICE_NAME
ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown
ARG MARTY_RS_VERSION=0.1.0
ARG MARTY_RS_URI
ARG MARTY_RS_DIGEST
ARG MARTY_COMMON_VERSION=0.2.0
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
    && test -n "$MARTY_COMMON_URI" \
    && test -n "$MARTY_COMMON_DIGEST" \
    && MARTY_RS_WHEEL="/tmp/${MARTY_RS_URI##*/}" \
    && MARTY_COMMON_WHEEL="/tmp/${MARTY_COMMON_URI##*/}" \
    && curl --fail --location --silent --show-error "$MARTY_RS_URI" --output "$MARTY_RS_WHEEL" \
    && curl --fail --location --silent --show-error "$MARTY_COMMON_URI" --output "$MARTY_COMMON_WHEEL" \
    && echo "${MARTY_RS_DIGEST#sha256:}  $MARTY_RS_WHEEL" | sha256sum --check --strict \
    && echo "${MARTY_COMMON_DIGEST#sha256:}  $MARTY_COMMON_WHEEL" | sha256sum --check --strict \
    && pip install --no-cache-dir -r /tmp/requirements-services.txt "$MARTY_RS_WHEEL" "$MARTY_COMMON_WHEEL"

COPY packages/marty_proto /app/packages/marty_proto
COPY services /app/services
COPY scripts/load-secrets-env.sh /app/load-secrets-env.sh
RUN chmod +x /app/services/entrypoint.sh /app/load-secrets-env.sh \
    && adduser --disabled-password --gecos '' appuser

USER appuser
WORKDIR /app/services
CMD ["/app/services/entrypoint.sh"]
