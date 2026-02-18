"""
Organization Service Main Application
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from marty_common import OrganizationClient
import redis.asyncio as aioredis

from .application.use_cases import (
    ApiKeyUseCase,
    ConsoleContextPreferenceUseCase,
    JoinUseCase,
    MemberUseCase,
    OrganizationUseCase,
)
from .application.rbac_use_cases import RoleUseCase
from .infrastructure.adapters.audit_adapter import router as audit_router
from .infrastructure.adapters.http_adapter import (
    configure_org_router,
    router as org_router,
    internal_router,
)
from .infrastructure.adapters.onboarding_adapter import router as onboarding_router
from .infrastructure.adapters.preferences_adapter import (
    configure_preferences_router,
    router as preferences_router,
)
from .infrastructure.adapters.rbac_http_adapter import (
    configure_rbac_router,
    router as rbac_router,
)
from .infrastructure.adapters.postgres_adapter import (
    PostgresApiKeyRepository,
    PostgresConsoleContextPreferenceRepository,
    PostgresJoinCodeRepository,
    PostgresMemberRepository,
    PostgresOrganizationRepository,
)
from .infrastructure.adapters.rbac_adapter import (
    PostgresPermissionRepository,
    PostgresRoleRepository,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Service configuration
SERVICE_NAME = "organization-service"
SERVICE_PORT = int(os.environ.get("ORGANIZATION_SERVICE_PORT", "8002"))


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5432/marty"
        ),
        "rabbitmq_url": os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"),
    }


class InMemoryEventPublisher:
    """Placeholder event publisher."""
    async def publish(self, event) -> None:
        logger.debug(f"Event published: {type(event).__name__}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize database
    engine = create_async_engine(config["database_url"], echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Initialize repositories
    org_repo = PostgresOrganizationRepository(session_factory)
    member_repo = PostgresMemberRepository(session_factory)
    api_key_repo = PostgresApiKeyRepository(session_factory)
    preference_repo = PostgresConsoleContextPreferenceRepository(session_factory)
    join_code_repo = PostgresJoinCodeRepository(session_factory)
    role_repo = PostgresRoleRepository(session_factory)
    permission_repo = PostgresPermissionRepository(session_factory)
    
    # Initialize event publisher
    event_publisher = InMemoryEventPublisher()
    
    # Initialize use cases
    org_use_case = OrganizationUseCase(
        organization_repo=org_repo,
        member_repo=member_repo,
        event_publisher=event_publisher,
    )
    
    member_use_case = MemberUseCase(
        member_repo=member_repo,
        organization_repo=org_repo,
        event_publisher=event_publisher,
    )
    
    api_key_use_case = ApiKeyUseCase(
        api_key_repo=api_key_repo,
        organization_repo=org_repo,
        event_publisher=event_publisher,
    )
    
    preference_use_case = ConsoleContextPreferenceUseCase(
        preference_repo=preference_repo,
    )
    
    join_use_case = JoinUseCase(
        join_code_repo=join_code_repo,
        organization_repo=org_repo,
        member_repo=member_repo,
        event_publisher=event_publisher,
    )
    
    role_use_case = RoleUseCase(
        role_repo=role_repo,
        permission_repo=permission_repo,
        member_repo=member_repo,
        event_publisher=event_publisher,
    )
    
    # Wire RBAC seeding into org creation
    org_use_case.role_use_case = role_use_case
    
    # Configure routers
    configure_org_router(
        organization_use_case=org_use_case,
        member_use_case=member_use_case,
        api_key_use_case=api_key_use_case,
        join_use_case=join_use_case,
    )
    
    configure_preferences_router(
        preference_use_case=preference_use_case,
    )
    
    configure_rbac_router(
        role_use_case=role_use_case,
    )
    
    # Store role use case in app state for the internal permissions endpoint
    app.state.role_use_case = role_use_case
    
    # Initialize Redis for membership cache invalidation
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_db = int(os.environ.get("REDIS_DB_GATEWAY", "2"))  # Use same DB as gateway
    logger.info(f"Connecting to Redis at {redis_url}/{redis_db} for cache invalidation")
    redis_client = aioredis.from_url(
        f"{redis_url}/{redis_db}",
        encoding="utf-8",
        decode_responses=True
    )
    
    # Initialize OrganizationClient for cache invalidation
    # Points to localhost since the org service needs to invalidate its own cache
    org_client = OrganizationClient(
        base_url=f"http://localhost:{SERVICE_PORT}",
        redis_client=redis_client,  # Enable Redis caching for cache invalidation
    )
    app.state.org_client = org_client
    app.state.redis_client = redis_client
    
    app.state.engine = engine
    
    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")
    
    yield
    
    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await org_client.close()
    await redis_client.aclose()
    await engine.dispose()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Organization Service",
        description="Organization management microservice",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add request middleware
    from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
    app.add_middleware(RequestLoggingMiddleware, service_name=SERVICE_NAME)
    app.add_middleware(RequestIdMiddleware)
    
    # Include routers
    app.include_router(org_router)
    app.include_router(internal_router)
    app.include_router(preferences_router)
    app.include_router(onboarding_router)
    app.include_router(audit_router)
    app.include_router(rbac_router)
    
    # Health check endpoint
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("organization.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
