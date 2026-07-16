# Project Structure Summary

## Marty UI

This repository now uses a microservice-oriented backend plus a Vite/React frontend. The retired `src/` monolith and its demo-specific Docker/K8s entrypoints have been removed.

### Directory structure

```text
marty-ui/
├── README.md
├── QUICK_START.md
├── DEVELOPMENT_SETUP.md
├── Makefile
├── cleanup.sh
├── docker-compose.base.yml
├── docker-compose.profile.dev.yml
├── docker-compose.profile.obs.yml
├── docker-compose.profile.tunnel.yml
├── docker/
│   ├── init-databases.sh
│   ├── nginx-proxy.conf.template
│   ├── nginx-proxy.conf
│   └── ui.Dockerfile
├── services/
│   ├── Dockerfile
│   ├── Dockerfile.migrations
│   ├── auth/
│   ├── organization/
│   ├── trust_profile/
│   ├── flow/
│   ├── notification/
│   ├── presentation_policy/
│   ├── deployment_profile/
│   ├── compliance_profile/
│   ├── applicant/
│   ├── gateway/
│   ├── verification/
│   ├── device_registration/
│   └── ...
├── packages/
│   ├── marty_common/
│   └── marty_proto/
├── proto/
├── ui/
│   ├── package.json
│   ├── tsconfig.json
│   ├── public/
│   └── src/
├── config/
├── scripts/
├── tests/
├── k8s/
│   └── oracle/
└── wheels/
```

### Key areas

- `services/` - active Python microservices and migrations
- `marty-common` - released shared Python infrastructure maintained in `ElevenID/Marty`
- `packages/marty_proto/` + `proto/` - gRPC definitions and generated stubs
- `ui/` - Vite/React frontend
- `docker-compose*.yml` - local stack orchestration
- `scripts/` - local tooling, setup, tunnel, and support workflows

### Local startup

Use the Makefile targets instead of retired one-off build or Kind deployment scripts:

1. `make dev` - start infrastructure + backend microservices
2. `make run-ui` - run the frontend locally if needed
3. `make down` - stop the stack

### Technologies used

- **Backend**: Python, FastAPI, gRPC, SQLAlchemy, PostgreSQL, Redis
- **Frontend**: React, Vite, TypeScript, Material UI
- **Local orchestration**: Docker Compose
- **Identity/Auth**: Keycloak + OIDC
- **Protocols**: OID4VCI, OID4VP, trust/revocation/profile services

For command examples, see `QUICK_START.md`. For setup details, see `DEVELOPMENT_SETUP.md`.
