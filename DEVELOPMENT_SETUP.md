# Marty UI - Development Setup Guide

## Overview

Marty UI has been extracted from the main Marty monorepo into a standalone project. It now depends on three published Marty packages:

- `marty-credentials` - Credential domain logic and Rust bindings (marty-rs)
- `marty-common` - Shared infrastructure (crypto_bridge, gRPC, database, observability)
- `marty-microservices-framework` - Microservices framework

## Two Development Modes

### 1. Production Mode (GitHub Packages)

Uses published packages from GitHub Packages registry.

**Setup:**

```bash
# Configure pip to use GitHub Packages
export GITHUB_TOKEN="your_token_here"  # Token with read:packages scope

# Install dependencies
pip install -r src/requirements.txt \
    --extra-index-url "https://oauth2:${GITHUB_TOKEN}@ghcr.io/YOUR_ORG/simple"
```

**Or use pip.conf:**

```bash
cp pip.conf.example ~/.config/pip/pip.conf
# Edit ~/.config/pip/pip.conf and add your GitHub token
pip install -r src/requirements.txt
```

**Docker:**

```bash
# Build with production mode (default)
docker-compose -f docker-compose.yml build --build-arg GITHUB_TOKEN=${GITHUB_TOKEN}
docker-compose -f docker-compose.yml up
```

### 2. Development Mode (Local Editable Installs)

Uses local editable installs of Marty packages for live development.

**Workspace Layout:**

```
Github/work/
├── Marty/                          # Main Marty repo
│   └── packages/
│       └── marty-common/           # Shared infrastructure
├── marty-credentials/              # Credentials + marty-rs
├── marty-microservices-framework/  # MSF framework
└── marty-ui/                       # This project
```

**Setup:**

```bash
# Install with local editable packages
pip install -r src/requirements.dev.txt

# Or manually:
pip install -e ../marty-credentials[ffi]
pip install -e ../marty-microservices-framework
pip install -e ../Marty/packages/marty-common
pip install -r src/requirements.txt
```

**Docker with Live Reload:**

```bash
# docker-compose.override.yml is automatically loaded
# It mounts local packages as volumes for live development

docker-compose up  # Uses override file automatically
```

The override file:
- Mounts local Marty packages as read-only volumes
- Installs them in editable mode at container startup
- Enables uvicorn auto-reload for Python changes
- Mounts UI source for React hot reload

**Benefits:**
- ✅ Changes in marty-credentials, marty-common, or MSF are immediately reflected
- ✅ No need to rebuild containers when changing Python code
- ✅ Fast iteration cycles for multi-package development

## Dependency Updates

When updating Marty package imports in marty-ui code:

**Old imports (from monorepo):**
```python
from marty_plugin.common.crypto_bridge import verify_certificate
from status_list.application.services import StatusListService
from marty_microservices_framework import MMFPlugin
```

**New imports (from packages):**
```python
from marty_common.crypto_bridge import verify_certificate
from status_list.application.services import StatusListService
from marty_microservices_framework import MMFPlugin
```

## Building & Publishing Marty Packages

See individual package READMEs:
- [marty-credentials/README.md](../marty-credentials/README.md)
- [Marty/packages/marty-common/README.md](../Marty/packages/marty-common/README.md)
- [marty-microservices-framework/README.md](../marty-microservices-framework/README.md)

## Troubleshooting

### Import errors for marty packages

**Development mode:**
```bash
# Verify packages are installed in editable mode
pip list | grep marty

# Should show paths like:
# marty-common         0.1.0  /path/to/Marty/packages/marty-common
# marty-credentials    0.1.0  /path/to/marty-credentials
```

**Production mode:**
```bash
# Verify GitHub Packages authentication
pip install marty-common --extra-index-url "https://oauth2:${GITHUB_TOKEN}@ghcr.io/YOUR_ORG/simple"
```

### Docker build fails

```bash
# Rebuild without cache
docker-compose build --no-cache

# Check build args
docker-compose config | grep -A5 "build:"
```

### Package version conflicts

```bash
# Clear pip cache
pip cache purge

# Reinstall from scratch
pip uninstall marty-common marty-credentials marty-microservices-framework
pip install -r src/requirements.dev.txt
```
