# Beta Releases Quick Reference

## 🚀 Quick Start

```bash
# 1. Trigger beta builds (commit workflow files first!)
cd marty-credentials && git push origin main
cd marty-microservices-framework && git push origin main  
cd Marty && git push origin main

# 2. Wait 10-15 minutes for builds (check GitHub Actions)

# 3. Use beta packages in marty-ui
cd marty-ui
docker compose --profile dev build  # Uses pre-built beta packages
docker compose --profile dev up -d  # Start development environment
```

## 📦 Install Beta Packages

```bash
# In Dockerfile or requirements.txt
pip install --pre marty-credentials marty-common marty-microservices-framework

# Specific version
pip install marty-credentials==0.2.0-beta.20260125.abc123

# In requirements.txt
marty-credentials>=0.2.0b0  # Any beta 0.2.0+
```

## 🔧 Docker Development

### Using Beta Packages (Recommended)
```yaml
# docker-compose.yml
services:
  api:
    build:
      args:
        USE_BETA_PACKAGES: "true"  # Default
```

### Using Local Editable (Old Way)
```yaml
# docker-compose.override.yml
services:
  api:
    build:
      args:
        USE_BETA_PACKAGES: "false"
    volumes:
      - ../marty-credentials:/app/marty-credentials:ro
```

## 🎯 Workflow Files Created

| Repository | Workflow File | Trigger |
|-----------|---------------|---------|
| marty-credentials | `.github/workflows/release-beta.yml` | Push to main/dev |
| marty-microservices-framework | `.github/workflows/release-beta.yml` | Push to main/dev |
| Marty | `.github/workflows/publish-marty-common-beta.yml` | Push to main/dev + path filter |

## 🔍 Verify Installation

```bash
# Check beta versions in container
docker compose exec oid4vc-api pip list | grep marty

# Test marty-rs works
docker compose exec oid4vc-api python -c "import marty_rs; print('✅')"
```

## ⚡ Benefits

| Before | After |
|--------|-------|
| 10+ min builds | 2-3 min builds |
| Requires Rust toolchain | Just `pip install` |
| Platform-specific issues | Pre-built wheels |
| Complex volume mounts | Clean Docker setup |

## 📚 Full Documentation

- [BETA_RELEASES.md](./BETA_RELEASES.md) - Complete guide
- [BETA_RELEASE_IMPLEMENTATION.md](./BETA_RELEASE_IMPLEMENTATION.md) - Implementation details
- [trigger-beta-builds.sh](../scripts/trigger-beta-builds.sh) - Helper script

## 🆘 Troubleshooting

**Build still slow?**
```bash
# Verify using beta packages
docker compose config | grep USE_BETA_PACKAGES
# Should show: USE_BETA_PACKAGES: 'true'
```

**Beta packages not found?**
```bash
# Check workflow succeeded
gh run list --workflow=release-beta.yml --limit=1

# Try installing manually
pip install --pre --index-url https://pypi.org/simple/ marty-credentials
```

**marty-rs import error?**
```bash
# Reinstall with fresh wheels
docker compose build --no-cache
```
