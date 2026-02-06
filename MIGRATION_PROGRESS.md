# Database Migration Progress

## Overview
Migrating services from in-memory storage to PostgreSQL with Alembic migrations.

## Migration Status

### ✅ Completed Services

#### 1. Organization Service
- **Status**: ✅ Complete
- **Migration Location**: `services/organization/infrastructure/migrations/`
- **Tables**: 3
  - organizations
  - members
  - api_keys
- **Schema**: organization_service
- **Adapter**: PostgresOrganizationRepository, PostgresMemberRepository, PostgresApiKeyRepository
- **Tests**: Passing (integration tests)

#### 2. Trust-Profile Service
- **Status**: ✅ Complete
- **Migration Location**: `services/trust-profile/infrastructure/migrations/`
- **Tables**: 2
  - trust_profiles
  - trusted_issuers
- **Schema**: trust_profile_service
- **Indexes**:
  - trust_profiles: organization_id, status, composite (organization_id, status)
  - trusted_issuers: trust_profile_id, issuer_did, status
- **Adapter**: PostgresTrustProfileRepository
- **Migrations Applied**:
  - 20260203_0204_33f047612e9b - Initial trust profile schema
  - 20260203_0207_7d8b4b4ef634 - Update timestamp columns to timezone aware
- **Service**: Running and healthy on port 8004
- **API**: Tested successfully - CREATE trust profile working
- **Key Learning**: Use `DateTime(timezone=True)` in SQLAlchemy for timezone-aware timestamps

#### 3. Issuance Service
- **Status**: ✅ Complete
- **Migration Location**: `services/issuance/infrastructure/migrations/`
- **Tables**: 2
  - issuance_transactions
  - issued_credentials
- **Schema**: issuance_service
- **Indexes**:
  - issuance_transactions: organization_id, status, pre_auth_code, applicant_id
  - issued_credentials: transaction_id, organization_id, applicant_id, status, subject_did
- **Adapter**: PostgresIssuanceRepository
- **Migrations Applied**:
  - 20260203_0225_735160618517 - Initial issuance schema
- **Service**: Running and healthy on port 8005
- **API**: Tested successfully - POST /v1/issuance/initiate working, data persisted
- **Key Points**: Simple flat domain models, JSON column for claims, easy migration

#### 4. Presentation-Policy Service
- **Status**: ✅ Complete
- **Migration Location**: `services/presentation-policy/infrastructure/migrations/`
- **Tables**: 1
  - presentation_policies
- **Schema**: presentation_policy_service
- **Indexes**:
  - presentation_policies: organization_id, status, composite (organization_id, status)
- **Adapter**: PostgresPresentationPolicyRepository
- **Migrations Applied**:
  - 20260203_0240_cd86d0505323 - Initial presentation policy schema
- **Service**: Running and healthy on port 8009
- **API**: Tested successfully - POST /v1/presentation-policies working, data persisted
- **Key Points**: Complex nested structures (6 dataclasses) stored as JSON, similar to trust-profile pattern

#### 5. Flow Service
- **Status**: ✅ Complete
- **Migration Location**: `services/flow/infrastructure/migrations/`
- **Tables**: 2
  - flow_definitions (workflow blueprints)
  - flow_instances (runtime state)
- **Schema**: flow_service
- **Indexes**:
  - flow_definitions: organization_id, status, flow_type, composite (organization_id, status)
  - flow_instances: organization_id, flow_definition_id, status, subject_id, external_reference
- **Adapter**: PostgresFlowRepository
- **Migrations Applied**:
  - 20260203_0248_1854c4083445 - Initial flow schema
- **Service**: Running and healthy on port 8011
- **API**: Tested successfully - POST /v1/flows/definitions working, data persisted
- **Key Points**: Manages workflow orchestration with steps/transitions as JSON, dual-entity pattern (definitions + instances)

#### 6. Credential-Template Service
- **Status**: ✅ Complete
- **Migration Location**: `services/credential-template/infrastructure/migrations/`
- **Tables**: 1
  - credential_templates
- **Schema**: credential_template_service
- **Indexes**:
  - organization_id
  - status
  - credential_type
  - composite (organization_id, status)
- **Adapter**: PostgresCredentialTemplateRepository
- **Migration Applied**: 20260203_0143_1d669d3ded39_initial_credential_template_schema
- **Service**: Running and healthy on port 8003
- **API**: Tested successfully - POST /v1/credential-templates working, data persisted
- **Key Points**: Most complex domain model (18 fields, 5 enums, 4 nested dataclasses), all stored as JSON
- **Issues Resolved**: Migration applied, service rebuilt with correct imports

#### 7. Auth Service
- **Status**: ✅ Complete (Hybrid Architecture)
- **Migration Location**: `services/auth/infrastructure/migrations/`
- **Tables**: 2 (audit logging only)
  - audit_logs (audit trail for authentication events)
  - session_history (historical session records)
- **Schema**: auth_service
- **Architecture**: **Hybrid Redis + PostgreSQL**
  - **Redis (Hot Data)**: Active sessions, PKCE state (ephemeral, sub-second latency)
  - **PostgreSQL (Cold Data)**: Audit logs, session history (compliance, analytics)
- **Indexes**:
  - audit_logs: user_id, organization_id, event_type, created_at, success, composite (user_id + created_at)
  - session_history: session_id (unique), user_id, organization_id, created_at, expired_at, composite (user_id + created_at)
- **Adapter**: PostgresAuditRepository (audit logging only, sessions remain in Redis)
- **Migrations Applied**:
  - 20260203_0309_c32b18ad89df - Initial auth audit schema
- **Service**: Running and healthy on port 8001
- **Key Features**:
  - Non-blocking audit logging (try/catch wrapper, no impact on auth flow)
  - Tracks authentication events, session creation/revocation
  - Session history for compliance and security monitoring
  - Event metadata as JSONB for flexible audit data
- **Key Learning**: 
  - Renamed `metadata` column to `event_metadata` to avoid SQLAlchemy reserved word conflict
  - Use synchronous DB URL (psycopg2) for Alembic migrations while keeping asyncpg for runtime
  - Fixed entrypoint.sh to use `python -m service.main` for proper module imports
  - Hybrid architecture: Keep hot data in Redis, log cold data to PostgreSQL

### ❌ Pending Services

None - All backend services migrated!

### ~~❌ Pending Services~~

#### ~~4. Auth Service~~
- **Status**: ~~❌ Not Started (Uses Redis, may not need PostgreSQL)~~
- **Schema**: auth_service (created, empty)
- **Priority**: Low (sessions in Redis are appropriate)
- **Note**: Auth service stores sessions in Redis which is correct for ephemeral session data

#### 5. Credential-Template Service
- **Status**: ⚠️ Partially Complete (Migration applied, adapter needs fixes)
- **Migration Location**: `services/credential-template/infrastructure/migrations/`
- **Tables**: 1
  - credential_templates
- **Schema**: credential_template_service
- **Indexes**:
  - organization_id
  - status
  - credential_type
  - composite (organization_id, status)
- **Adapter**: PostgresCredentialTemplateRepository (needs refactoring)
- **Migration Applied**: 20260203_0143_1d669d3ded39_initial_credential_template_schema
- **Service**: Running and healthy on port 8003
- **Issues**:
  - Adapter needs to use `session_factory()` pattern like organization service
  - Import errors with relative imports (use absolute imports from main)
  - Complex domain model with many nested objects makes adapter challenging
- **Recommendation**: Complete simpler services first, return to this once pattern is established

### ❌ Pending Services

#### 6. Auth Service
- **Status**: ❌ Not Started (Uses Redis, may not need PostgreSQL)
- **Schema**: auth_service (created, empty)
- **Priority**: Low (sessions in Redis are appropriate)
- **Note**: Auth service stores sessions in Redis which is correct for ephemeral session data

## Completed Migrations Summary

Successfully migrated **7 out of 8 services** to PostgreSQL:

1. ✅ **Organization** - 3 tables, full CRUD operations
2. ✅ **Trust-Profile** - 2 tables with complex JSON structures
3. ✅ **Issuance** - 2 tables, flat structures with JSON claims
4. ✅ **Presentation-Policy** - 1 table with 6 nested dataclasses as JSON
5. ✅ **Flow** - 2 tables (definitions and instances) with workflow orchestration
6. ✅ **Credential-Template** - 1 table with most complex domain model (18 fields)
7. ✅ **Auth** - 2 tables for audit logging and session history (hybrid Redis + PostgreSQL)

**Total Database Objects Created:**
- Schemas: 7 (organization_service, trust_profile_service, issuance_service, presentation_policy_service, flow_service, credential_template_service, auth_service)
- Tables: 14 total (12 operational + 2 audit/history)
- Indexes: 40+ for query optimization
- Migrations: All applied and verified

**Migration Complete - All Backend Services Migrated! 🎉**

## Migration Pattern

For each service, follow these steps:

### 1. Create Models
```python
# services/<service>/infrastructure/models.py
from sqlalchemy import Column, String, DateTime, Table
from sqlalchemy.orm import registry

mapper_registry = registry()

<service>_table = Table(
    "<table_name>",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    # ... other columns
    schema="<service>_service"
)
```

### 2. Create PostgreSQL Adapter
```python
# services/<service>/infrastructure/adapters/postgres_adapter.py
class Postgres<Service>Repository:
    def __init__(self, session_factory):
        self._session_factory = session_factory
    
    async def save(self, entity) -> None:
        ...
    
    async def get(self, id: str) -> Entity | None:
        ...
    
    async def list(self, filters) -> list[Entity]:
        ...
    
    async def delete(self, id: str) -> None:
        ...
```

### 3. Create Migration Manager
```python
# services/<service>/manage_migrations.py
import asyncio
from mmf.framework.infrastructure.migration import AlembicMigrationAdapter

SERVICE_NAME = "<service>"  # Use underscore format

async def main():
    # CLI tool with commands: init, create, upgrade, downgrade, current, history, verify
    ...

if __name__ == "__main__":
    asyncio.run(main())
```

### 4. Initialize Migrations
```bash
cd services/<service>
DATABASE_URL="postgresql://marty:marty_dev@localhost:5432/marty_credentials" \
  python manage_migrations.py init
```

### 5. Create Initial Migration
```bash
DATABASE_URL="postgresql://marty:marty_dev@localhost:5432/marty_credentials" \
  python manage_migrations.py create -m "Initial <service> schema"
```

### 6. Apply Migration
```bash
DATABASE_URL="postgresql://marty:marty_dev@localhost:5432/marty_credentials" \
  python manage_migrations.py upgrade
```

### 7. Update Service main.py
```python
# Import PostgreSQL adapter
from infrastructure.adapters import Postgres<Service>Repository
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Update lifespan function
@asynccontextmanager
async def lifespan(app: FastAPI):
    config = get_config()
    engine = create_async_engine(config["database_url"])
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    repo = Postgres<Service>Repository(session_factory)
    # ... use repo
    yield
```

### 8. Export from __init__.py
```python
# services/<service>/infrastructure/adapters/__init__.py
from .postgres_adapter import Postgres<Service>Repository

__all__ = ["Postgres<Service>Repository"]
```

### 9. Rebuild and Test
```bash
docker compose -f docker-compose.integration.yml up -d --build <service>-service
docker compose -f docker-compose.integration.yml logs -f <service>-service
```

## Database Configuration

### Connection Details
- Host: localhost:5432
- Database: marty_credentials
- User: marty
- Password: marty_dev

### Schema Per Service Pattern
Each service has its own PostgreSQL schema:
- organization_service
- auth_service
- credential_template_service
- trust_profile_service
- issuance_service
- presentation_policy_service
- flow_service

### Alembic Version Tracking
Each schema has its own `alembic_version` table for migration tracking.

## Testing

### Integration Tests
```bash
cd /Volumes/Heart\ of\ Gold/Github/work/marty-credentials
source .venv_test/bin/activate
pytest tests/integration/ -v
```

### Current Test Status
- ✅ 9 tests passing (wallet setup + organization CRUD)
- ❌ Additional tests pending service migrations

## Next Steps

1. ✅ Complete credential-template service migration
2. ❌ Migrate auth service (high priority)
3. ❌ Migrate trust-profile service
4. ❌ Migrate issuance service
5. ❌ Migrate presentation-policy service
6. ❌ Migrate flow service
7. ❌ Update run_all_migrations.py to include all services
8. ❌ Add comprehensive integration tests for all services
9. ❌ Document API endpoints and usage

## Key Learnings

1. **Schema Naming**: Use underscores (credential_template_service) not hyphens
2. **Import Path**: Use absolute imports (from infrastructure.adapters) not relative (.infrastructure.adapters) when main.py is run directly
3. **Export Pattern**: Must export from __init__.py for imports to work
4. **Autogenerate**: Alembic's autogenerate correctly detects tables and indexes from SQLAlchemy metadata
5. **Connection String**: Use postgresql+asyncpg:// for async SQLAlchemy
6. **Entrypoint**: Docker services with hyphenated names need entrypoint.sh to cd into directory

## Files Created

### Credential-Template Service
- services/credential-template/infrastructure/models.py
- services/credential-template/infrastructure/adapters/postgres_adapter.py
- services/credential-template/infrastructure/adapters/__init__.py
- services/credential-template/infrastructure/__init__.py
- services/credential-template/manage_migrations.py
- services/credential-template/infrastructure/migrations/ (directory)
  - alembic.ini
  - env.py
  - script.py.mako
  - versions/20260203_0143_1d669d3ded39_initial_credential_template_schema.py

### Docker Infrastructure
- services/entrypoint.sh (handles hyphenated service names)

## MMF Framework

The migration system uses the MMF (Marty Microservices Framework) migration infrastructure:

- **Location**: marty-microservices-framework/mmf/framework/infrastructure/migration/
- **Components**:
  - ports.py: MigrationManagerPort interface
  - adapters.py: AlembicMigrationAdapter implementation
  - __init__.py: Exports

### Key Features
- Auto-generates alembic.ini with service-specific schema
- Creates env.py with proper async configuration
- Supports init, create, upgrade, downgrade, current, history, verify commands
- Handles schema namespacing automatically
