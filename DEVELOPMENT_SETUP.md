# Marty UI - Development Setup Guide

## Overview

Marty UI has been extracted from the main Marty monorepo into a standalone project. It now depends on three Marty packages:

- `marty-credentials` - Credential domain logic and Rust bindings (marty-rs)
- `marty-common` - Shared infrastructure (crypto_bridge, gRPC, database, observability)
- `marty-microservices-framework` - Microservices framework

## Quick Start (Recommended)

The fastest way to get started is using the Makefile with local development mode:

```bash
# Start all services with local development configuration
make dev

# ⚠️ FIRST TIME STARTUP: 5-7 minutes
# Rust extensions (marty-rs, marty-verification) will compile inside Docker
# This only happens once - subsequent startups take ~10 seconds

# Services will be available at:
# - API: http://localhost:8000
# - UI: http://localhost:3000
```

**What `make dev` does:**
1. Starts Docker containers with `DEV_MODE=true`
2. Compiles Rust extensions (`marty-rs`, `marty-verification`) on first start
3. Caches compiled Rust binaries for fast subsequent startups
4. Mounts sibling repos as volumes for live code changes
5. Installs packages in editable mode for hot reload

**Startup Times:**
- **Subsequent starts:** ~10 seconds (uses cached builds)

## Fast Path: Native Development (Best for iteration)

The fastest way to iterate is running infrastructure in Docker and the application code natively. This avoids container overhead and uses fast Rust debug builds.

```bash
# 1. Start infrastructure (DB, Redis, Keycloak)
make infra

# 2. Setup local environment (venv + dependencies - one time)
make setup-local

# 3. Start API (with hot-reload)
make run-api

# 4. Start UI (in another terminal)
make run-ui
```

**Benefits:**
- ✅ **Fastest startup**: No container rebuilds needed.
- ✅ **Fastest compilation**: Rust code is built in debug mode.
- ✅ **Best DX**: Direct access to local files and standard debugger support.

## Workspace Layout

Your workspace should have this structure:

```
Github/work/
├── Marty/                          # Main Marty repo
│   └── packages/
│       └── marty-common/           # Shared infrastructure
├── marty-core/                     # Core Rust crates
│   └── marty-verification/         # Open Badges FFI
├── marty-credentials/              # Credentials + marty-rs
│   └── rust/marty-rs/              # Python FFI for credentials
├── marty-microservices-framework/  # MSF framework
└── marty-ui/                       # This project
```

## Development Modes

### 1. Local Development Mode (Recommended)

Uses local editable installs with pre-built Rust wheels for fast iteration.

**Initial setup:**

**Initial setup:**

```bash
# Start services (first time takes 5-7 minutes for Rust compilation)
make dev

# View logs (including Rust build progress)
make logs

# Stop services
make down
```

**What gets mounted:**
- `../marty-credentials` → `/app/marty-credentials`
- `../marty-core` → `/app/marty-core`
- `../marty-microservices-framework` → `/app/marty-microservices-framework`
- `../Marty/packages/marty-common` → `/app/marty-common`
- `./src` → `/app/src` (your local UI source)

**Benefits:**
- ✅ Fast subsequent startups (~10 seconds using cached Rust builds)
- ✅ Hot reload for Python changes (uvicorn --reload)
- ✅ Changes in marty-common or marty-msf are immediately reflected
- ✅ Rust builds cached in Docker volume - no recompilation needed
- ✅ Works consistently across macOS, Linux, and Windows

**When Rust recompilation happens:**
- First time running `make dev` (one-time, 5-7 minutes)
- After `make clean` (removes cache)
- After pulling changes to `marty-credentials/rust/marty-rs`
- After pulling changes to `marty-core/marty-verification`

### 2. Production Mode (Not Yet Available)

Production mode uses published packages from GitHub Packages registry. **This is currently not working** and is why we're using local development mode.

Once the release pipeline is fixed, you'll be able to use:

```bash
# Build with production packages
docker-compose build --build-arg USE_BETA_PACKAGES=true --build-arg GITHUB_TOKEN=${GITHUB_TOKEN}
docker-compose up
```

## Available Make Targets

| Command | Description |
|---------|-------------|
| `make infra` | Start infrastructure only (DB, Redis, Keycloak) |
| `make setup-local` | Setup native local venv + dependencies |
| `make run-api` | Run API service natively |
| `make run-ui` | Run React UI natively |
| `make help` | Show all available targets |

## Open Badges FFI

Open Badges signing functions (`open_badge_ob2_issue`, `open_badge_ob3_verify`, etc.) are available via:

```python
from marty_common.crypto_bridge import (
    open_badge_ob2_issue,
    open_badge_ob2_verify,
    open_badge_ob3_issue,
    open_badge_ob3_verify,
)
```

These functions are implemented in `marty-core/marty-verification` and exposed to Python via PyO3 bindings. The `marty_common.crypto_bridge` module re-exports them for convenience.

**Note:** The `_marty_rs` module from `marty-credentials` does NOT include Open Badges functions (those are WASM-only for Flutter). Always import from `marty_common.crypto_bridge`.

## Dependency Updates

When updating Marty package imports in marty-ui code:

**Old imports (from monorepo):**
```python
from marty_plugin.common.crypto_bridge import verify_certificate
from status_list.application.services import StatusListService
```

**New imports (from packages):**
```python
from marty_common.crypto_bridge import verify_certificate
from status_list.application.services import StatusListService
```

## Manual Python Setup (Alternative to Docker)

If you prefer to run services natively without Docker:

```bash
# 1. Build and install Rust wheels
make build-wheels
pip install wheels/*.whl

# 2. Install Python packages in editable mode
pip install -e ../marty-credentials/python
pip install -e ../marty-microservices-framework
pip install -e ../Marty/packages/marty-common
pip install -r src/requirements.txt

# 3. Start services
cd src
uvicorn oid4vc_api:app --reload --port 8000
```

## Building & Publishing Marty Packages

See individual package READMEs:
- [marty-credentials/README.md](../marty-credentials/README.md)
- [marty-core/marty-verification](../marty-core/marty-verification/)
- [Marty/packages/marty-common/README.md](../Marty/packages/marty-common/README.md)
- [marty-microservices-framework/README.md](../marty-microservices-framework/README.md)

## Troubleshooting

### Import errors for Open Badges functions

```python
# Make sure to import from marty_common.crypto_bridge, not _marty_rs
from marty_common.crypto_bridge import open_badge_ob2_issue

# If you get ImportError, rebuild wheels:
make build-wheels
make restart
```

### Wheels not found

```bash
# Build wheels before starting services
make build-wheels

# Check that wheels exist
ls -lh wheels/

# Should see:
# - marty_rs-*.whl
# - marty_verification-*.whl
```

### Changes not reflected in container

```bash
# For Python changes: already auto-reloaded (no action needed)

# For Rust/FFI changes: rebuild wheels
make build-wheels
make restart

# For dependency changes: rebuild container
make down
docker-compose build --no-cache
make dev
```

### Container build fails with "wheels not found"

```bash
# Run make build-wheels first
make build-wheels

# Then start services
make up
```

### Port already in use

```bash
# Check what's using the port
lsof -i :8000

# Stop conflicting services or change ports in docker-compose.yml
```

### Import errors for marty packages (Development mode)

```bash
# Verify packages are installed in editable mode
pip list | grep marty

# Should show paths like:
# marty-common         0.1.0  /path/to/Marty/packages/marty-common
# marty-credentials    0.1.0  /path/to/marty-credentials
```

### Package version conflicts

```bash
# Clear pip cache
pip cache purge

# Rebuild wheels
make build-wheels

# Restart containers
make restart
```

## Next Steps

After setup, see:
- [QUICK_START.md](QUICK_START.md) - Common operations and workflows
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) - Code organization
- [tests/README.md](tests/README.md) - Running E2E tests
