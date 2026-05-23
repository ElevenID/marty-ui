"""
Auth Service Main Application

FastAPI application for the Auth microservice.
Wires together all components following hexagonal architecture.
"""

from __future__ import annotations

import collections
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from marty_common.service_setup import create_service_app

from .application.use_cases import AuthenticateUseCase, SessionUseCase
from .infrastructure.adapters.grpc_adapter import AuthServiceGrpc
from .infrastructure.adapters.http_adapter import (
    configure_auth_router,
    internal_router,
    router as auth_router,
)
from .infrastructure.adapters.applicant_profile_adapter import ApplicantProfileProvisioningAdapter
from .infrastructure.adapters.keycloak_admin_adapter import build_keycloak_admin_adapter
from .infrastructure.adapters.oidc_adapter import KeycloakOIDCAdapter, OIDCConfig
from .infrastructure.adapters.postgres_audit_adapter import PostgresAuditRepository
from .infrastructure.adapters.redis_adapter import RedisPKCEStateRepository, RedisSessionRepository
from .infrastructure.adapters.user_provisioning_adapter import InMemoryUserProvisioningAdapter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Service configuration
SERVICE_NAME = "auth-service"
SERVICE_PORT = int(os.environ.get("AUTH_SERVICE_PORT", "8001"))


def get_config() -> dict:
    """Get service configuration from environment."""
    realm = os.environ.get("KEYCLOAK_REALM")
    if not realm:
        raise ValueError(
            "KEYCLOAK_REALM environment variable must be set "
            "(e.g. 'master' or your tenant realm name)"
        )
    ui_base_url = os.environ.get("UI_BASE_URL", "http://localhost:3000").rstrip("/")
    issuer_default = f"http://localhost:8180/realms/{realm}"
    external_default = os.environ.get("OIDC_ISSUER_URL", issuer_default)
    redirect_default = f"{ui_base_url}/v1/auth/callback"
    return {
        "ui_base_url": ui_base_url,
        "redis_url": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        "oidc": {
            "issuer_url": os.environ.get(
                "OIDC_ISSUER_URL",
                issuer_default,
            ),
            # External URL for browser redirects (defaults to issuer_url)
            "external_issuer_url": os.environ.get(
                "OIDC_EXTERNAL_ISSUER_URL",
                external_default,
            ),
            "client_id": os.environ.get("OIDC_CLIENT_ID", "marty-ui"),
            "client_secret": os.environ.get("OIDC_CLIENT_SECRET"),
            "redirect_uri": os.environ.get(
                "OIDC_REDIRECT_URI",
                redirect_default,
            ),
            "post_logout_redirect_uri": os.environ.get(
                "OIDC_POST_LOGOUT_REDIRECT_URI",
            ),
        },
        "session_ttl_seconds": int(os.environ.get("SESSION_TTL_SECONDS", "86400")),
        "cookie": {
            "key": "sessionId",
            "httponly": True,
            "secure": os.environ.get("COOKIE_SECURE", "true").lower() == "true",
            "samesite": os.environ.get("COOKIE_SAMESITE", "lax"),
            "max_age": int(os.environ.get("SESSION_TTL_SECONDS", "86400")),
            "path": "/",
        },
        "credential_login_policy_id": os.environ.get("CREDENTIAL_LOGIN_POLICY_ID", ""),
        "auth_service_internal_url": os.environ.get("AUTH_SERVICE_INTERNAL_URL", "http://auth:8001"),
        "issuance_service_url": os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005"),
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize Redis client
    redis_client = redis.from_url(config["redis_url"], decode_responses=True)
    
    # Initialize PostgreSQL for audit logging
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("auth"))
    async_session_factory = db.session_factory
    audit_repository = PostgresAuditRepository(async_session_factory)
    
    # Initialize adapters
    session_repository = RedisSessionRepository(redis_client)
    pkce_repository = RedisPKCEStateRepository(redis_client)
    
    oidc_config = OIDCConfig(
        issuer_url=config["oidc"]["issuer_url"],
        client_id=config["oidc"]["client_id"],
        client_secret=config["oidc"]["client_secret"],
        redirect_uri=config["oidc"]["redirect_uri"],
        external_issuer_url=config["oidc"]["external_issuer_url"],
    )
    oidc_provider = KeycloakOIDCAdapter(oidc_config)
    
    # gRPC channels
    from common.grpc_factory import create_grpc_channel
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
    org_grpc_channel = create_grpc_channel(org_grpc_target, service_name="auth")

    flow_grpc_target = os.environ.get("FLOW_GRPC_TARGET", "flow:9011")
    flow_grpc_channel = create_grpc_channel(flow_grpc_target, service_name="auth")
    app.state.flow_grpc_channel = flow_grpc_channel

    # Use in-memory provisioning for now (can swap to JIT adapter)
    user_provisioning = InMemoryUserProvisioningAdapter(org_grpc_channel=org_grpc_channel)
    applicant_profile_provisioner = ApplicantProfileProvisioningAdapter()
    
    # Initialize event publisher (gRPC event bus)
    from auth.infrastructure.adapters.event_adapter import GrpcEventBusPublisher
    event_publisher = GrpcEventBusPublisher()
    
    # Initialize use cases
    authenticate_use_case = AuthenticateUseCase(
        session_repository=session_repository,
        pkce_repository=pkce_repository,
        oidc_provider=oidc_provider,
        user_provisioning=user_provisioning,
        event_publisher=event_publisher,
        audit_repository=audit_repository,  # Add audit logging
        session_ttl_seconds=config["session_ttl_seconds"],
        post_logout_redirect_uri=config["oidc"]["post_logout_redirect_uri"],
    )
    
    session_use_case = SessionUseCase(
        session_repository=session_repository,
    )
    
    # Keycloak admin adapter (optional — for token exchange in credential login)
    kc_admin_adapter = build_keycloak_admin_adapter()

    # Configure router with use cases
    configure_auth_router(
        authenticate_use_case=authenticate_use_case,
        session_use_case=session_use_case,
        cookie_config=config["cookie"],
        ui_base_url=config["ui_base_url"],
        redis_client=redis_client,
        session_repository=session_repository,
        credential_login_policy_id=config["credential_login_policy_id"],
        auth_service_internal_url=config["auth_service_internal_url"],
        issuance_service_url=config["issuance_service_url"],
        kc_admin_adapter=kc_admin_adapter,
        user_provisioning=user_provisioning,
        applicant_profile_provisioner=applicant_profile_provisioner,
    )

    # Store in app state for access
    app.state.redis_client = redis_client
    app.state.async_engine = db.engine
    app.state.audit_repository = audit_repository
    app.state.authenticate_use_case = authenticate_use_case
    app.state.session_use_case = session_use_case
    app.state.kc_admin_adapter = kc_admin_adapter

    # Start gRPC server
    from common.grpc_factory import create_grpc_server, start_grpc_server_port
    from marty_proto.v1.auth_service_pb2_grpc import add_AuthServiceServicer_to_server

    grpc_port = int(os.environ.get("AUTH_GRPC_PORT", "9001"))
    grpc_server, health_servicer = create_grpc_server("auth")
    auth_servicer = AuthServiceGrpc(
        session_use_case=session_use_case,
        session_repository=session_repository,
        redis_client=redis_client,
        kc_admin_adapter=kc_admin_adapter,
        user_provisioning=user_provisioning,
        applicant_profile_provisioner=applicant_profile_provisioner,
    )
    add_AuthServiceServicer_to_server(auth_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.auth.v1.AuthService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info("Auth gRPC server listening on port %d", grpc_port)

    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")

    yield

    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await flow_grpc_channel.close()
    await org_grpc_channel.close()
    await redis_client.close()
    await db.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Disable API docs in production to prevent endpoint enumeration
    _env = os.environ.get("ENVIRONMENT", "production")
    _docs = "/docs" if _env in ("development", "test") else None
    _redoc = "/redoc" if _env in ("development", "test") else None
    _openapi = "/openapi.json" if _env in ("development", "test") else None
    app = create_service_app(
        title="Auth Service",
        description="Authentication and session management microservice",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[auth_router, internal_router],
        docs_url=_docs,
        redoc_url=_redoc,
        openapi_url=_openapi,
    )

    # In-memory sliding-window rate limiter for auth endpoints (brute-force mitigation).
    # Covers /login, /register, /callback, /credential-login/* — all unauthenticated flows.
    # Per-IP; configurable via AUTH_RATE_LIMIT_RPM (default 30 requests/minute).
    _rate_limit_rpm = int(os.environ.get("AUTH_RATE_LIMIT_RPM", "30"))
    _rate_window = 60  # seconds
    _rate_buckets: dict[str, collections.deque] = {}
    _RATE_LIMITED_PREFIXES = (
        "/v1/auth/login",
        "/v1/auth/register",
        "/v1/auth/callback",
        "/v1/auth/credential-login",
    )
    _RATE_LIMIT_EXCLUDED_PREFIXES = (
        "/v1/auth/credential-login/status",
        "/v1/auth/credential-login/assets/",
    )

    from fastapi.responses import JSONResponse

    @app.middleware("http")
    async def auth_rate_limit_middleware(request, call_next):
        path = request.url.path
        if any(path.startswith(prefix) for prefix in _RATE_LIMIT_EXCLUDED_PREFIXES):
            return await call_next(request)
        if not any(path.startswith(prefix) for prefix in _RATE_LIMITED_PREFIXES):
            return await call_next(request)

        client_ip = (request.client.host if request.client else None) or "unknown"
        now = time.monotonic()
        bucket = _rate_buckets.setdefault(client_ip, collections.deque())
        # Evict timestamps older than the window
        while bucket and bucket[0] < now - _rate_window:
            bucket.popleft()
        if len(bucket) >= _rate_limit_rpm:
            logger.warning(
                "Auth rate limit exceeded for %s on %s (%d/%d rpm)",
                client_ip,
                path,
                len(bucket),
                _rate_limit_rpm,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={"Retry-After": str(_rate_window)},
            )
        bucket.append(now)
        return await call_next(request)

    return app


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "auth.main:app",
        host="0.0.0.0",
        port=SERVICE_PORT,
        reload=True,
    )
