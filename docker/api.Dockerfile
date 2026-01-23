# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for OID4VC API Service
# Supports dual-mode: production (GitHub Packages) and development (local paths)

# Build arguments
ARG DEV_MODE=false
ARG GITHUB_TOKEN=""

# =============================================================================
# Builder Stage - Install dependencies
# =============================================================================
FROM python:3.11-slim AS builder

ARG DEV_MODE
ARG GITHUB_TOKEN

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpq-dev \
    pkg-config \
    libssl-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY src/requirements.txt .

# Install dependencies based on mode
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$DEV_MODE" = "true" ]; then \
        echo "DEV MODE: Installing from local paths (volumes will be mounted at runtime)"; \
        pip install --no-cache-dir -r requirements.txt || true; \
    else \
        echo "PRODUCTION MODE: Installing from GitHub Packages"; \
        pip install --no-cache-dir -r requirements.txt \
            --extra-index-url "https://oauth2:${GITHUB_TOKEN}@ghcr.io/YOUR_ORG/simple"; \
    fi

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
