# Beta Release System for Marty Dependencies

This document describes the automated beta release system for Marty packages that enables rapid development and testing.

## Overview

All Marty packages now support automated beta releases that can be consumed in development environments without requiring local builds:

- **marty-credentials** (includes marty-rs Rust extension with pre-built wheels)
- **marty-microservices-framework** 
- **marty-common**

## Triggering Beta Releases

### Automatic Triggers

Beta releases are automatically created on every push to `main` or `dev` branches. The version format is:

```
{BASE_VERSION}-beta.{DATE}.{SHORT_SHA}
```

Example: `0.2.0-beta.20260125.a1b2c3d`

### Manual Triggers

You can also trigger beta releases manually via GitHub Actions:

1. Go to the repository's Actions tab
2. Select "Release Beta" workflow
3. Click "Run workflow"
4. Enter a specific beta version (e.g., `0.2.0-beta.1`) or leave blank for auto-generated version

## Using Beta Packages

### Option 1: Install Specific Beta Version

```bash
# Install marty-credentials beta (includes pre-built marty-rs)
pip install marty-credentials==0.2.0-beta.20260125.a1b2c3d

# Install marty-microservices-framework beta
pip install marty-microservices-framework==1.0.0-beta.20260125.a1b2c3d

# Install marty-common beta
pip install marty-common==0.1.0-beta.20260125.a1b2c3d
```

### Option 2: Install Latest Beta

```bash
# Allow pre-release versions
pip install --pre marty-credentials marty-common marty-microservices-framework
```

### Option 3: Use in requirements.txt

```txt
# requirements.txt - pin to specific beta
marty-credentials==0.2.0-beta.20260125.a1b2c3d
marty-common==0.1.0-beta.20260125.a1b2c3d
marty-microservices-framework==1.0.0-beta.20260125.a1b2c3d

# OR allow any beta version
marty-credentials>=0.2.0b0
marty-common>=0.1.0b0
marty-microservices-framework>=1.0.0b0
```

### Option 4: Docker Development Setup

For marty-ui development, update the Dockerfile to install beta packages:

```dockerfile
# In services/Dockerfile
RUN pip install --pre \
    marty-credentials \
    marty-common \
    marty-microservices-framework
```

Or use specific versions:

```dockerfile
RUN pip install \
    marty-credentials==0.2.0-beta.20260125.a1b2c3d \
    marty-common==0.1.0-beta.20260125.a1b2c3d \
    marty-microservices-framework==1.0.0-beta.20260125.a1b2c3d
```

## Beta Release Workflow

### marty-credentials (with marty-rs)

The beta workflow builds Python wheels with the marty-rs Rust extension for:
- Linux (x86_64, aarch64) - manylinux wheels
- macOS (x86_64, aarch64) - universal wheels
- Windows (x86_64) - Windows wheels

This means **no Rust toolchain is needed** in consuming environments - just install the wheel.

### marty-microservices-framework & marty-common

These are pure Python packages that build standard wheels and source distributions.

## Finding Available Beta Versions

### Via GitHub Actions

1. Go to repository → Actions
2. Find successful "Release Beta" workflows
3. Download artifacts to see `MANIFEST.md` with version details

### Via pip (if published to PyPI)

```bash
pip index versions marty-credentials --pre
```

### Via GitHub Packages

If published to GitHub Packages, configure pip:

```bash
# ~/.pypirc or pip.conf
[global]
extra-index-url = https://pypi.pkg.github.com/YOUR_ORG/simple/
```

## Example: marty-ui Development

### Before (required local builds)

```yaml
# legacy dev override example (retired approach)
volumes:
  - ../marty-credentials:/app/marty-credentials:ro
command: |
  pip install -e /app/marty-credentials  # Requires Rust toolchain!
```

### After (use beta packages)

```yaml
# compose dev overlay example (current approach)
command: |
  pip install --pre marty-credentials marty-common marty-microservices-framework
  uvicorn app:main --reload
```

Or in Dockerfile:

```dockerfile
# services/Dockerfile
ARG MARTY_CREDENTIALS_VERSION=0.2.0-beta.latest
ARG MARTY_COMMON_VERSION=0.1.0-beta.latest
ARG MARTY_MMF_VERSION=1.0.0-beta.latest

RUN pip install \
    marty-credentials==${MARTY_CREDENTIALS_VERSION} \
    marty-common==${MARTY_COMMON_VERSION} \
    marty-microservices-framework==${MARTY_MMF_VERSION}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install dependencies with beta packages
  run: |
    pip install --pre \
      marty-credentials \
      marty-common \
      marty-microservices-framework
```

### Docker Build

```dockerfile
FROM python:3.11-slim

# Install beta packages (no Rust needed!)
RUN pip install --pre --no-cache-dir \
    marty-credentials \
    marty-common \
    marty-microservices-framework
```

## Versioning Strategy

- **Stable releases**: `v1.2.3` (tags)
- **RC releases**: `v1.2.3-rc.1` (tags)
- **Beta releases**: `1.2.3-beta.YYYYMMDD.sha` (automatic)

Beta versions are:
- ✅ Perfect for development and testing
- ✅ Built from latest code
- ✅ Include all dependencies pre-built
- ⚠️ Not for production use
- ⚠️ May be unstable

## Troubleshooting

### "No matching distribution found"

If beta packages aren't found, ensure:
1. The beta workflow completed successfully
2. You're using `--pre` flag or specific beta version
3. GitHub token has package read permissions

### "marty-rs import error"

If you see marty-rs errors with beta packages:
1. Verify wheel platform matches your system
2. Check Python version (requires 3.11+)
3. Try reinstalling: `pip uninstall marty-credentials && pip install --pre marty-credentials`

### Docker build failing on marty-rs

If Docker still tries to build marty-rs:
1. Remove editable installs (`pip install -e`)
2. Use `pip install --pre marty-credentials` instead
3. Ensure Dockerfile doesn't mount local package directories

## Updating to Latest Betas

```bash
# Force reinstall to get latest betas
pip install --upgrade --force-reinstall --pre \
    marty-credentials \
    marty-common \
    marty-microservices-framework

# Or clear cache first
pip cache purge
pip install --pre marty-credentials marty-common marty-microservices-framework
```

## Status

| Package | Beta Workflow | Auto-trigger | Manual Trigger |
|---------|--------------|--------------|----------------|
| marty-credentials | ✅ Created | ✅ On push | ✅ Workflow dispatch |
| marty-microservices-framework | ✅ Created | ✅ On push | ✅ Workflow dispatch |
| marty-common | ✅ Created | ✅ On push | ✅ Workflow dispatch |

## Next Steps

1. **Commit and push** these workflows to trigger the first beta builds
2. **Wait for builds** to complete (check Actions tab)
3. **Update marty-ui** to use beta packages instead of local mounts
4. **Test** that marty-rs works without local Rust builds

## Questions?

- Check workflow logs in Actions tab for build details
- See `MANIFEST.md` in build artifacts for version info
- Review this README for consumption patterns
