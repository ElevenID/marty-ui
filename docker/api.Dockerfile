# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for OID4VC API Service
# Supports dual-mode: production (GitHub Packages) and development (local paths)

# Build arguments
ARG DEV_MODE=false
ARG GITHUB_TOKEN=""
ARG USE_BETA_PACKAGES=true

# =============================================================================
# Builder Stage - Install dependencies
# =============================================================================
FROM python:3.11-slim AS builder

ARG DEV_MODE
ARG GITHUB_TOKEN
ARG USE_BETA_PACKAGES

WORKDIR /app

# Install system dependencies (including git for setuptools-scm)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpq-dev \
    pkg-config \
    libssl-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain for DEV_MODE (needed for marty-rs editable install)
RUN if [ "$DEV_MODE" = "true" ]; then \
        curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable && \
        . $HOME/.cargo/env && \
        pip install --no-cache-dir maturin; \
    fi

ENV PATH="/root/.cargo/bin:${PATH}"

# Copy requirements first for layer caching
COPY src/requirements.txt .

# Copy wheels directory in DEV_MODE
COPY --chown=marty:marty wheels/ /app/wheels/

# Install dependencies based on mode
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$DEV_MODE" = "true" ]; then \
        echo "DEV MODE: Installing wheels and dependencies for local development"; \
        grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
        pip install --no-cache-dir -r requirements-filtered.txt; \
        if [ -f /app/wheels/marty_rs-*.whl ] && [ -f /app/wheels/marty_verification-*.whl ]; then \
            echo "Installing pre-built Rust wheels..."; \
            pip install --no-cache-dir /app/wheels/marty_rs-*.whl /app/wheels/marty_verification-*.whl; \
        else \
            echo "WARNING: No pre-built wheels found. Run 'make build-wheels' first."; \
        fi; \
    elif [ "$USE_BETA_PACKAGES" = "true" ]; then \
        echo "BETA MODE: Installing pre-built marty packages from GitHub Packages"; \
        grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
        pip install --no-cache-dir -r requirements-filtered.txt; \
        pip install --pre --no-cache-dir \
            marty-credentials \
            marty-common \
            marty-msf; \
    else \
        echo "PRODUCTION MODE: Installing all dependencies"; \
        pip install --no-cache-dir -r requirements.txt; \
    fi
# =============================================================================
# Runtime Stage - Minimal production image
# =============================================================================
FROM python:3.11-slim AS runtime

ARG DEV_MODE

WORKDIR /app

# Install runtime system dependencies (add build tools for DEV_MODE)
RUN if [ "$DEV_MODE" = "true" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            libpq5 \
            curl \
            gcc \
            libc6-dev \
            pkg-config \
            libssl-dev \
            git \
            && rm -rf /var/lib/apt/lists/* \
            && apt-get clean; \
    else \
        apt-get update && apt-get install -y --no-install-recommends \
            libpq5 \
            curl \
            && rm -rf /var/lib/apt/lists/* \
            && apt-get clean; \
    fi

# Create non-root user
RUN groupadd -r marty && useradd -r -g marty marty

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy Rust toolchain from builder if DEV_MODE
COPY --from=builder /root/.cargo /root/.cargo
ENV PATH="/root/.cargo/bin:${PATH}"
COPY --from=builder /usr/local/bin /usr/local/bin

# Note: In DEV_MODE, marty packages are mounted as volumes (see docker-compose.override.yml)
# In production, they're installed from GitHub Packages

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/

# Create entrypoint script for DEV_MODE (before switching user)
RUN if [ "$DEV_MODE" = "true" ]; then \
        echo '#!/bin/sh' > /app/entrypoint.sh && \
        echo 'set -e' >> /app/entrypoint.sh && \
        echo 'echo "DEV_MODE: Configuring Rust toolchain..."' >> /app/entrypoint.sh && \
        echo 'rustup default stable' >> /app/entrypoint.sh && \
        echo 'echo "DEV_MODE: Building and installing Rust extensions (Debug)..."' >> /app/entrypoint.sh && \
        echo 'cd /app/marty-credentials/rust/marty-rs && maturin build -i python3.11 && pip install target/wheels/*.whl --force-reinstall && cd /app/src || echo "marty-rs build failed"' >> /app/entrypoint.sh && \
        echo 'cd /app/marty-core/marty-verification && maturin build -i python3.11 --features python && pip install target/wheels/*.whl --force-reinstall && cd /app/src || echo "marty-verification build failed"' >> /app/entrypoint.sh && \
        echo 'echo "DEV_MODE: Installing editable Python packages from mounted volumes..."' >> /app/entrypoint.sh && \
        echo 'pip install -e /app/marty-credentials/python || echo "marty-credentials not mounted"' >> /app/entrypoint.sh && \
        echo 'pip install -e /app/marty-microservices-framework || echo "marty-msf not mounted"' >> /app/entrypoint.sh && \
        echo 'pip install -e /app/marty-common || echo "marty-common not mounted"' >> /app/entrypoint.sh && \
        echo 'echo "Starting application..."' >> /app/entrypoint.sh && \
        echo 'su -m marty -c "cd /app/src && exec \"\$@\""' >> /app/entrypoint.sh && \
        chmod +x /app/entrypoint.sh; \
    fi

# Set ownership
RUN chown -R marty:marty /app

# Note: DON'T switch to non-root user yet - entrypoint needs root for maturin develop
# The entrypoint script will su to marty user after building Rust

# Set working directory to src
WORKDIR /app/src

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application with entrypoint in DEV_MODE
CMD ["/bin/sh", "-c", "if [ \"$DEV_MODE\" = \"true\" ]; then /app/entrypoint.sh uvicorn oid4vc_api:app --host 0.0.0.0 --port 8000 --reload; else uvicorn oid4vc_api:app --host 0.0.0.0 --port 8000; fi"]
