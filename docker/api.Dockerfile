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

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpq-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Note: git and Rust NOT needed when using beta packages!
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy requirements first for layer caching
COPY src/requirements.txt .

# Install dependencies based on mode
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$DEV_MODE" = "true" ]; then \
        echo "DEV MODE: Installing dependencies (excluding marty packages, which will be mounted as volumes)"; \
        grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
        pip install --no-cache-dir -r requirements-filtered.txt && \
        echo "Installing maturin for Rust extension builds" && \
        pip install --no-cache-dir maturin; \
    else \
        echo "PRODUCTION MODE:  && [ "$USE_BETA_PACKAGES" = "true" ]; then \
        echo "DEV MODE with BETA PACKAGES: Installing pre-built marty packages"; \
        # Install non-marty dependencies first
        grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
        pip install --no-cache-dir -r requirements-filtered.txt; \
        # Install beta versions of marty packages (pre-built wheels, no Rust needed!)
        pip install --pre --no-cache-dir \
            marty-credentials \
            marty-common \
            marty-microservices-framework; \
    elif [ "$DEV_MODE" = "true" ]; then \
        echo "DEV MODE: Installing dependencies (marty packages will be mounted as volumes)"; \
        grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
        pip install --no-cache-dir -r requirements-filtered.txt
# =============================================================================
# Runtime Stage - Minimal production image
# =============================================================================
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r marty && useradd -r -g marty marty

# Copy installed packages from builder (including marty-rs wheel)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Note: In DEV_MODE, marty packages are mounted as volumes (see docker-compose.override.yml)
# In production, they're installed from GitHub Packages

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/

# Set ownership
RUN chown -R marty:marty /app

# Switch to non-root user
USER marty

# Set working directory to src
WORKDIR /app/src

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "oid4vc_api:app", "--host", "0.0.0.0", "--port", "8000"]
