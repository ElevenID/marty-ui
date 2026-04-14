# Dockerfile for Marty Microservices with Rust bindings
# 
# Multi-stage build: Rust compilation -> Python services
# Build context should be parent directory: docker build -f marty-ui/services/Dockerfile .
# Usage: docker build -f marty-ui/services/Dockerfile --build-arg SERVICE_NAME=auth -t marty-auth .

# Stage 1: Build Rust bindings for Python
# Using nightly because edition2024 is required by aligned-0.4.3 dependency
FROM rustlang/rust:nightly-slim AS rust-builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libzstd-dev \
    python3-dev \
    python3-pip \
    g++ \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Install maturin for building Python packages from Rust
RUN pip3 install --break-system-packages maturin

WORKDIR /build

# Copy marty-core first (dependency)
COPY marty-core ./marty-core

# Copy longfellow-zk C++ library (required by marty-zkp build.rs)
COPY longfellow-zk/lib ./longfellow-zk/lib

# Copy marty-credentials Rust workspace (preserving directory structure)
COPY marty-credentials/Cargo.toml ./marty-credentials/
COPY marty-credentials/Cargo.lock* ./marty-credentials/
COPY marty-credentials/rust ./marty-credentials/rust

# Rewrite marty-core git dependencies to local path dependencies so Docker
# builds do not require GitHub credentials.
RUN python3 - <<'PY'
from pathlib import Path

path = Path('/build/marty-credentials/Cargo.toml')
text = path.read_text()

replacements = {
    'marty-crypto = { git = "https://github.com/ElevenID/marty-core.git", branch = "main", features = ["sod-builder"] }': 'marty-crypto = { path = "../marty-core/marty-crypto", features = ["sod-builder"] }',
    'marty-crypto = { git = "https://github.com/ElevenID/marty-core.git", rev = "438d0f81", features = ["sod-builder"] }': 'marty-crypto = { path = "../marty-core/marty-crypto", features = ["sod-builder"] }',
    'marty-verification = { git = "https://github.com/ElevenID/marty-core.git", branch = "main" }': 'marty-verification = { path = "../marty-core/marty-verification" }',
    'marty-verification = { git = "https://github.com/ElevenID/marty-core.git", rev = "438d0f81" }': 'marty-verification = { path = "../marty-core/marty-verification" }',
    'marty-secure-storage = { git = "https://github.com/ElevenID/marty-core.git", branch = "main" }': 'marty-secure-storage = { path = "../marty-core/marty-secure-storage" }',
    'marty-secure-storage = { git = "https://github.com/ElevenID/marty-core.git", rev = "438d0f81" }': 'marty-secure-storage = { path = "../marty-core/marty-secure-storage" }',
    'marty-oid4vci = { git = "https://github.com/ElevenID/marty-core.git", branch = "main" }': 'marty-oid4vci = { path = "../marty-core/marty-oid4vci" }',
    'marty-oid4vci = { git = "https://github.com/ElevenID/marty-core.git", rev = "438d0f81" }': 'marty-oid4vci = { path = "../marty-core/marty-oid4vci" }',
}

for old, new in replacements.items():
    text = text.replace(old, new)

path.write_text(text)
PY

# Build the Python wheel for marty-rs bindings
WORKDIR /build/marty-credentials/rust/marty-rs
RUN CXX=clang++ CC=clang maturin build --release --features python --out /wheels

# Stage 2: Python base with dependencies  
FROM python:3.12-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install Rust-built Python wheel (marty-rs bindings)
COPY --from=rust-builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Install Python dependencies
COPY marty-ui/requirements-services.txt .
RUN pip install --no-cache-dir -r requirements-services.txt

# Copy shared packages
COPY marty-ui/packages/marty_common /app/packages/marty_common
COPY marty-ui/packages/marty_proto /app/packages/marty_proto

# Install shared package
RUN pip install -e /app/packages/marty_common

# Stage 3: Final service image
FROM base AS final

ARG SERVICE_NAME
ENV SERVICE_NAME=${SERVICE_NAME}

# Copy ALL services (needed for package structure)
COPY marty-ui/services /app/services

# Set Python path to include services parent
ENV PYTHONPATH=/app:/app/packages:/app/services

# Working directory
WORKDIR /app/services

# Copy entrypoint script
COPY marty-ui/services/entrypoint.sh /app/entrypoint.sh
COPY marty-ui/scripts/load-secrets-env.sh /app/load-secrets-env.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Use entrypoint script to handle service names
CMD ["/app/entrypoint.sh"]
