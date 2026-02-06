# syntax=docker/dockerfile:1
# Optimized Dockerfile for LOCAL DEVELOPMENT
# Builds Rust extensions at build time to avoid runtime compilation

FROM python:3.11-slim AS runtime

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

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable && \
    . $HOME/.cargo/env && \
    pip install --no-cache-dir maturin

ENV PATH="/root/.cargo/bin:${PATH}"

# Create non-root user
RUN groupadd -r marty && useradd -r -g marty marty

# Copy Python requirements first
COPY marty-ui/src/requirements.txt .
RUN grep -v "^marty-" requirements.txt > requirements-filtered.txt && \
    pip install --no-cache-dir -r requirements-filtered.txt

# Copy Rust source code
COPY marty-credentials/rust /tmp/marty-credentials/rust
COPY marty-credentials/Cargo.toml /tmp/marty-credentials/
COPY marty-core /tmp/marty-core

# Build and install Rust extensions
WORKDIR /tmp/marty-credentials/rust/marty-rs
RUN . $HOME/.cargo/env && maturin build --release && \
    pip install /tmp/marty-credentials/target/wheels/*.whl

WORKDIR /tmp/marty-core/marty-verification
RUN . $HOME/.cargo/env && maturin build --release --features python && \
    pip install /tmp/marty-core/target/wheels/*.whl

# Clean up build artifacts
RUN rm -rf /tmp/marty-credentials /tmp/marty-core

# Copy application code
COPY marty-ui/src/ /app/src/
COPY marty-ui/config/ /app/config/

# Set ownership
RUN chown -R marty:marty /app

# Switch to non-root user
USER marty

# Set working directory
WORKDIR /app/src

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with auto-reload for development
CMD ["uvicorn", "oid4vc_api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]