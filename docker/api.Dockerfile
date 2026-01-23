# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for OID4VC API Service
# Optimized with BuildKit cache mounts for faster rebuilds

# =============================================================================
# Builder Stage - Install dependencies
# =============================================================================
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies for building (add Rust toolchain and glibc-dev)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpq-dev \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}"

# Copy rust directory
COPY rust/ /build/rust/

# Build marty-rs Python wheel
WORKDIR /build/rust/marty-rs
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    pip install maturin && \
    maturin build --release --features python --strip && \
    pip install --no-cache-dir ../target/wheels/*.whl

WORKDIR /app

# Copy requirements first for layer caching
COPY marty-ui/src/requirements.txt .

# Install dependencies with BuildKit cache
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt

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

# Copy MMF framework
COPY marty-microservices-framework/ /app/marty-microservices-framework/

# Copy status_list module from main Marty/src
COPY src/status_list/ /app/status_list/

# Copy marty_plugin module from main Marty/src
COPY src/marty_plugin/ /app/marty_plugin/

ENV PYTHONPATH="${PYTHONPATH}:/app/marty-microservices-framework:/app"

# Copy application code
COPY marty-ui/src/ /app/src/
COPY marty-ui/config/ /app/config/

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
