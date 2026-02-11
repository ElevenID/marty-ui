"""
Auth Service Main Application

FastAPI application for the Auth microservice.
Wires together all components following hexagonal architecture.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from .application.use_cases import AuthenticateUseCase, SessionUseCase
from .infrastructure.adapters.event_adapter import InMemoryEventPublisher, RabbitMQEventPublisher
from .infrastructure.adapters.http_adapter import (
    configure_auth_router,
    internal_router,
    router as auth_router,
)
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
    return {
        "ui_base_url": os.environ.get("UI_BASE_URL", "http://localhost:3000"),
        "redis_url": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        "rabbitmq_url": os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"),
        "oidc": {
            "issuer_url": os.environ.get(
                "OIDC_ISSUER_URL",
                "http://localhost:8180/realms/11id"
            ),
            # External URL for browser redirects (defaults to issuer_url)
            "external_issuer_url": os.environ.get(
                "OIDC_EXTERNAL_ISSUER_URL",
                os.environ.get("OIDC_ISSUER_URL", "http://localhost:8180/realms/11id")
            ),
            "client_id": os.environ.get("OIDC_CLIENT_ID", "marty-ui"),
            "client_secret": os.environ.get("OIDC_CLIENT_SECRET"),
            "redirect_uri": os.environ.get(
                "OIDC_REDIRECT_URI",
                "http://localhost:8001/v1/auth/callback"
            ),
            "post_logout_redirect_uri": os.environ.get(
                "OIDC_POST_LOGOUT_REDIRECT_URI",
                "http://localhost:3000/"
            ),
        },
        "session_ttl_seconds": int(os.environ.get("SESSION_TTL_SECONDS", "86400")),
        "cookie": {
            "key": "sessionId",
            "httponly": True,
            "secure": os.environ.get("COOKIE_SECURE", "false").lower() == "true",
            "samesite": os.environ.get("COOKIE_SAMESITE", "lax"),
            "max_age": int(os.environ.get("SESSION_TTL_SECONDS", "86400")),
            "path": "/",
        },
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize Redis client
    redis_client = redis.from_url(config["redis_url"], decode_responses=True)
    
    # Initialize PostgreSQL for audit logging
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
    )
    async_engine = create_async_engine(db_url, echo=False)
    async_session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
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
    
    # Use in-memory provisioning for now (can swap to JIT adapter)
    user_provisioning = InMemoryUserProvisioningAdapter()
    
    # Initialize event publisher
    try:
        event_publisher = RabbitMQEventPublisher(config["rabbitmq_url"])
    except Exception as e:
        logger.warning(f"RabbitMQ not available, using in-memory publisher: {e}")
        event_publisher = InMemoryEventPublisher()
    
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
    
    # Configure router with use cases
    configure_auth_router(
        authenticate_use_case=authenticate_use_case,
        session_use_case=session_use_case,
        cookie_config=config["cookie"],
        ui_base_url=config["ui_base_url"],
    )
    
    # Store in app state for access
    app.state.redis_client = redis_client
    app.state.async_engine = async_engine
    app.state.audit_repository = audit_repository
    app.state.authenticate_use_case = authenticate_use_case
    app.state.session_use_case = session_use_case
    
    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")
    
    yield
    
    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await redis_client.close()
    await async_engine.dispose()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Auth Service",
        description="Authentication and session management microservice",
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
    
    # Add request ID middleware
    from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
    app.add_middleware(RequestLoggingMiddleware, service_name=SERVICE_NAME)
    app.add_middleware(RequestIdMiddleware)
    
    # Include routers
    app.include_router(auth_router)
    app.include_router(internal_router)
    
    # Health check endpoint
    @app.get("/health")
    async def health_check() -> dict:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": SERVICE_NAME,
        }
    
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
