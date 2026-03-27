# Marty UI - Development Setup Guide

## Overview

`marty-ui` now runs as a microservice-based local stack rather than the retired single-process `src/` monolith. The current backend is composed of independently built services behind the gateway, plus the React UI in `ui/`.

Primary sibling dependencies:

- `marty-credentials` - credential issuance services and Rust bindings
- `marty-common` - shared infrastructure, crypto bridge, gRPC, auth helpers
- `marty-microservices-framework` - shared microservice runtime pieces
- `marty-core` - Rust verification crates and related native components

## Recommended local workflow

For most development work, use the Make targets that orchestrate the current compose files.

```bash
# full backend stack
make dev

# stop everything
make down

# follow logs
make logs
```

Key endpoints once started:

- Gateway: http://localhost:8000
- Gateway docs: http://localhost:8000/docs
- Auth docs: http://localhost:8001/docs
- Keycloak: http://localhost:8180
- MailHog: http://localhost:9025

## Current compose layout

The local stack is defined by:

- `docker-compose.base.yml` - infrastructure + app services
- `docker-compose.profile.dev.yml` - local development overrides
- `docker-compose.profile.tunnel.yml` - optional Cloudflare tunnel routing
- `docker-compose.profile.obs.yml` - optional observability overlays

The legacy monolith Dockerfiles and demo-only compose entrypoints were retired and should not be referenced for new setup steps.

## Workspace layout

Typical sibling checkout layout:

```text
Github/work/
├── Marty/
│   └── packages/
│       └── marty-common/
├── marty-core/
├── marty-credentials/
├── marty-microservices-framework/
└── marty-ui/
```

## Common development modes

### 1. Full containerized backend

```bash
make dev
```

Use this when you want the current microservice topology locally.

### 2. Infrastructure only

```bash
make infra
```

Useful when iterating on the UI or when you want supporting services without the full app stack.

### 3. Backend stack + native UI

```bash
make run-api
make run-ui
```

This is the usual fast feedback loop for frontend and gateway work.

## Frequently used Make targets

| Command | Description |
|---------|-------------|
| `make dev` | Start infrastructure + app microservices |
| `make down` | Stop the full stack |
| `make infra` | Start only Postgres, Redis, Keycloak, MailHog |
| `make run-api` | Start infra + backend microservices |
| `make run-ui` | Run the Vite UI locally |
| `make services-build` | Build microservice images |
| `make services-restart` | Restart backend services |
| `make grpc-health` | Probe gRPC-enabled services |
| `make help` | Show all supported targets |

## Native Rust wheel workflow

If you need local native wheels for Rust-backed packages:

```bash
make build-wheels
```

That script writes wheels into `wheels/` using the sibling `marty-credentials` and `marty-core` repositories.

## Open Badges FFI

Open Badges functions continue to be imported from `marty_common.crypto_bridge`, not from retired monolith modules and not directly from `_marty_rs`.

```python
from marty_common.crypto_bridge import (
    open_badge_ob2_issue,
    open_badge_ob2_verify,
    open_badge_ob3_issue,
    open_badge_ob3_verify,
)
```

## Troubleshooting

### Services do not come up

```bash
make status
make logs
```

### Need only backend logs

```bash
make services-logs
```

### gRPC service reachability

```bash
make grpc-health
```

### Rust-backed package changes

```bash
make build-wheels
make services-restart
```

### Port conflicts

```bash
lsof -i :8000
lsof -i :8180
```

## Next steps

After setup, see:

- `QUICK_START.md` - common day-to-day commands
- `PROJECT_STRUCTURE.md` - current repo layout
- `tests/README.md` - test workflows
