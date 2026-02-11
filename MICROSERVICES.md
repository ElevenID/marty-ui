# Marty Microservices Architecture

This document describes the microservices architecture for the Marty platform.

## Services Overview

| Service | Port | Description |
|---------|------|-------------|
| Gateway | 8000 | API Gateway - routes requests, validates sessions |
| Auth | 8001 | Authentication & session management (OIDC) |
| Organization | 8002 | Organizations, members, API keys |
| Credential | 8003 | Credential type configuration |
| Trust | 8004 | Trusted issuers & verification policies |
| Issuance | 8005 | OID4VCI credential issuance |
| Applicant | 8006 | Applicant vetting & management |
| Notification | 8007 | Email & push notifications |

## Quick Start

```bash
# Start all services
make -f Makefile.services services-up

# View logs
make -f Makefile.services services-logs

# Open API Gateway Swagger UI
open http://localhost:8000/docs
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Gateway (:8000)                       │
│   • Route requests to services                                  │
│   • Session validation via Auth Service                         │
│   • Rate limiting, CORS                                         │
└────────────────────────────────────┬────────────────────────────┘
                                     │
       ┌─────────────────────────────┼─────────────────────────────┐
       │                             │                             │
       ▼                             ▼                             ▼
┌──────────────┐            ┌──────────────┐            ┌──────────────┐
│ Auth Service │            │  Org Service │            │ Cred Service │
│    (:8001)   │            │    (:8002)   │            │    (:8003)   │
│              │            │              │            │              │
│ • OIDC/PKCE  │            │ • Orgs       │            │ • Types      │
│ • Sessions   │            │ • Members    │            │ • Schemas    │
│ • Internal   │            │ • API Keys   │            │              │
│   validation │            │              │            │              │
└──────┬───────┘            └──────┬───────┘            └──────┬───────┘
       │                           │                           │
       └───────────────────────────┼───────────────────────────┘
                                   │
                         ┌─────────┴─────────┐
                         │                   │
                    ┌────▼────┐        ┌─────▼────┐
                    │  Redis  │        │ Postgres │
                    │(Sessions)│       │(All Data)│
                    └─────────┘        └──────────┘
```

## API Routes

### Gateway Routes

```
/v1/auth/*           → Auth Service (:8001)
/v1/organizations/*  → Organization Service (:8002)
/v1/credentials/*    → Credential Service (:8003)
/v1/trust/*          → Trust Service (:8004)
/v1/issuance/*       → Issuance Service (:8005)
/v1/applicants/*     → Applicant Service (:8006)
/v1/notifications/*  → Notification Service (:8007)
```

### Public Endpoints (No Auth Required)

```
GET  /health                    Gateway health check
GET  /v1/auth/login             Initiate OIDC login
GET  /v1/auth/callback          OIDC callback
POST /v1/issuance/token         OID4VCI token endpoint
POST /v1/issuance/credential    OID4VCI credential endpoint
```

### Protected Endpoints (Session Required)

```
GET  /v1/auth/me                Get current user
POST /v1/auth/logout            Logout

GET  /v1/organizations          List organizations
POST /v1/organizations          Create organization
GET  /v1/organizations/{id}     Get organization
...
```

## Hexagonal Architecture

Each service follows the hexagonal (ports & adapters) pattern:

```
service/
├── domain/
│   ├── entities.py      # Domain entities (Organization, Member, etc.)
│   └── events.py        # Domain events (OrganizationCreated, etc.)
├── application/
│   ├── ports.py         # Interface definitions (Repository ports)
│   └── use_cases.py     # Business logic (OrganizationUseCase)
├── infrastructure/
│   └── adapters/
│       ├── postgres_adapter.py  # Repository implementations
│       ├── http_adapter.py      # FastAPI routes
│       └── event_adapter.py     # RabbitMQ publisher
└── main.py              # Application entry point
```

## Database Schema

Each service has its own PostgreSQL schema:

- `auth_service` - Sessions (stored in Redis, not Postgres)
- `organization_service` - Organizations, members, API keys
- `credential_service` - Credential types and schemas
- `trust_service` - Trusted issuers, verification policies
- `issuance_service` - Issuance transactions, issued credentials
- `applicant_service` - Applicants and vetting data
- `notification_service` - Notifications and templates

## Event Bus (RabbitMQ)

Services communicate via domain events:

```
Exchange: marty.events (topic)

Events:
  user.authenticated
  session.created
  session.invalidated
  organization.created
  member.invited
  credential.issued
  applicant.approved
```

## Development

### Run Individual Service

```bash
# Start infrastructure only
docker-compose -f docker-compose.services.yml up postgres redis rabbitmq -d

# Run auth service locally
cd services/auth
uvicorn main:app --reload --port 8001
```

### Environment Variables

Each service uses environment variables for configuration:

```bash
# Auth Service
AUTH_SERVICE_PORT=8001
REDIS_URL=redis://localhost:6379/0
OIDC_ISSUER_URL=http://localhost:8180/realms/11id
OIDC_CLIENT_ID=marty-ui

# Organization Service
ORGANIZATION_SERVICE_PORT=8002
DATABASE_URL=postgresql+asyncpg://marty:password@localhost:5432/marty
```

### Testing

```bash
# Run all tests
make -f Makefile.services test

# Run specific service tests
pytest services/auth/tests -v
```

## Infrastructure URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Gateway API | http://localhost:8000/docs | - |
| Keycloak Admin | http://localhost:8180 | admin/admin |
| RabbitMQ Management | http://localhost:15672 | marty/marty_dev_password |
| Jaeger UI | http://localhost:16686 | - |
| Prometheus | http://localhost:9090 | - |
