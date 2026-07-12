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
from marty_common.system_ids import MARTY_DEFAULT_ORG_ID
from marty_common.service_setup import create_service_app
import redis.asyncio as aioredis

from .application.use_cases import (
    ApiKeyUseCase,
    ConsoleContextPreferenceUseCase,
    JoinUseCase,
    MemberUseCase,
    OrganizationUseCase,
)
from .application.rbac_use_cases import RoleUseCase
from .application.policy_set_use_cases import PolicySetUseCase
from .infrastructure.adapters.audit_adapter import (
    configure_audit_router,
    router as audit_router,
)
from .infrastructure.adapters.audit_publisher import AuditEventPublisher
from .infrastructure.adapters.grpc_adapter import OrganizationServiceGrpc
from .infrastructure.adapters.http_adapter import (
    configure_org_router,
    internal_router,
    router as org_router,
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
from .infrastructure.adapters.scim_http_adapter import (
    configure_scim_router,
    router as scim_router,
)
from .infrastructure.adapters.postgres_adapter import (
    PostgresApiKeyRepository,
    PostgresAuditEventRepository,
    PostgresConsoleContextPreferenceRepository,
    PostgresJoinCodeRepository,
    PostgresMemberRepository,
    PostgresOrganizationRepository,
)
from .infrastructure.adapters.rbac_adapter import (
    PostgresPermissionRepository,
    PostgresRoleRepository,
)
from .infrastructure.adapters.policy_set_adapter import PostgresPolicySetRepository
from .infrastructure.adapters.policy_set_http_adapter import (
    configure as configure_policy_set_router,
    router as policy_set_router,
)
from .domain.entities import Member, MemberStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Service configuration
SERVICE_NAME = "organization-service"
SERVICE_PORT = int(os.environ.get("ORGANIZATION_SERVICE_PORT", "8002"))
MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID)
MARTY_ORG_ADMIN_EMAIL = os.environ.get("MARTY_ORG_ADMIN_EMAIL", "").strip().lower()
MARTY_ORG_REVIEWER_EMAIL = os.environ.get("MARTY_ORG_REVIEWER_EMAIL", "").strip().lower()


async def _ensure_system_roles_for_existing_orgs(
    org_use_case: OrganizationUseCase,
    role_use_case: RoleUseCase,
) -> None:
    """Seed system roles for orgs created outside the current runtime path."""

    organizations = await org_use_case.list_organizations(limit=1000, offset=0)
    for organization in organizations:
        existing_roles = await role_use_case.list_roles(str(organization.id))
        if existing_roles:
            continue
        logger.info("Seeding missing system roles for existing org %s", organization.id)
        await role_use_case.seed_default_roles(str(organization.id))


async def _ensure_marty_bootstrap_memberships(
    member_repo: PostgresMemberRepository,
    role_use_case: RoleUseCase,
) -> None:
    """Pre-seed deterministic admin and reviewer memberships."""

    for email, role_name in (
        (MARTY_ORG_ADMIN_EMAIL, "admin"),
        (MARTY_ORG_REVIEWER_EMAIL, "reviewer"),
    ):
        if not email:
            continue
        role = await role_use_case.role_repo.get_by_name(MARTY_ORG_ID, role_name)
        if role is None:
            logger.warning("Marty %s role missing during bootstrap; skipping %s", role_name, email)
            continue
        member = await member_repo.get_by_email_and_org(email, MARTY_ORG_ID)
        if member is None:
            member = Member(
                organization_id=MARTY_ORG_ID,
                user_id="",
                email=email,
                status=MemberStatus.ACTIVE,
            )
            await member_repo.save(member)
        existing_role_ids = {item.id for item in member.roles}
        existing_role_names = {item.name for item in member.roles}
        if role.id in existing_role_ids:
            continue
        if not existing_role_names or existing_role_names <= {"applicant"}:
            await role_use_case.set_member_roles(
                SetMemberRolesCommand(
                    member_id=member.id,
                    organization_id=MARTY_ORG_ID,
                    role_ids=[role.id],
                    updated_by="system",
                )
            )
            continue
        await role_use_case.add_member_role(
            AddMemberRoleCommand(
                member_id=member.id,
                organization_id=MARTY_ORG_ID,
                role_id=role.id,
                updated_by="system",
            )
        )


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
        ),
    }


from common.grpc_event_bus import GrpcEventBusPublisher  # noqa: E402
from .application.ports import AddMemberRoleCommand, SetMemberRolesCommand  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize database
    engine = create_async_engine(
        config["database_url"],
        echo=False,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Initialize repositories
    org_repo = PostgresOrganizationRepository(session_factory)
    member_repo = PostgresMemberRepository(session_factory)
    api_key_repo = PostgresApiKeyRepository(session_factory)
    preference_repo = PostgresConsoleContextPreferenceRepository(session_factory)
    join_code_repo = PostgresJoinCodeRepository(session_factory)
    role_repo = PostgresRoleRepository(session_factory)
    permission_repo = PostgresPermissionRepository(session_factory)
    policy_set_repo = PostgresPolicySetRepository(session_factory)
    audit_event_repo = PostgresAuditEventRepository(session_factory)
    
    # Persist audit events, then fan out live events over the gRPC event bus.
    event_publisher = AuditEventPublisher(
        audit_repo=audit_event_repo,
        delegate=GrpcEventBusPublisher(),
    )
    
    # Initialize use cases
    org_use_case = OrganizationUseCase(
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
    
    member_use_case = MemberUseCase(
        member_repo=member_repo,
        organization_repo=org_repo,
        event_publisher=event_publisher,
        role_use_case=role_use_case,
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
        role_use_case=role_use_case,
    )
    
    # Wire RBAC seeding into org creation
    org_use_case.role_use_case = role_use_case
    await _ensure_system_roles_for_existing_orgs(org_use_case, role_use_case)
    await _ensure_marty_bootstrap_memberships(member_repo, role_use_case)
    
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
    configure_audit_router(
        audit_repo=audit_event_repo,
    )
    configure_scim_router(
        organization_use_case=org_use_case,
        member_use_case=member_use_case,
        role_use_case=role_use_case,
    )
    
    # Initialize Cedar engine and PolicySet use case
    from marty_common import CedarEngine
    cedar_engine = CedarEngine.with_defaults()
    policy_set_use_case = PolicySetUseCase(
        repo=policy_set_repo,
        cedar_engine=cedar_engine,
    )
    configure_policy_set_router(use_case=policy_set_use_case)
    
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
    
    app.state.redis_client = redis_client
    app.state.engine = engine
    
    # Wire Redis client into org use case for plan key sync
    org_use_case.redis_client = redis_client
    
    # Start gRPC server
    from common.grpc_factory import create_grpc_server, start_grpc_server_port, create_grpc_channel
    from marty_proto.v1.organization_service_pb2_grpc import (
        add_OrganizationServiceServicer_to_server,
    )

    grpc_port = int(os.environ.get("ORG_GRPC_PORT", "9002"))
    grpc_server, health_servicer = create_grpc_server("organization")
    org_servicer = OrganizationServiceGrpc(
        org_use_case=org_use_case,
        member_use_case=member_use_case,
        api_key_use_case=api_key_use_case,
        role_use_case=role_use_case,
    )
    add_OrganizationServiceServicer_to_server(org_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.organization.v1.OrganizationService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info("Organization gRPC server listening on port %d", grpc_port)

    # OrganizationClient for cache invalidation (loopback to own gRPC server)
    org_grpc_channel = create_grpc_channel(f"localhost:{grpc_port}", service_name="organization")
    org_client = OrganizationClient(
        grpc_channel=org_grpc_channel,
        redis_client=redis_client,
    )
    app.state.org_client = org_client

    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")
    
    yield
    
    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await org_grpc_channel.close()
    await redis_client.aclose()
    await engine.dispose()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = create_service_app(
        title="Organization Service",
        description="Organization management microservice",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[org_router, preferences_router, onboarding_router, audit_router, rbac_router, scim_router, policy_set_router, internal_router],
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("organization.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
