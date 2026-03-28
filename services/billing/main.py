"""
Billing Service Main Application
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .application.use_cases import BillingUseCase
from .infrastructure.adapters.http_adapter import configure_billing_router, router as billing_router
from .infrastructure.adapters.org_service_client import OrgServiceClient
from .infrastructure.adapters.postgres_adapter import (
    PostgresCustomerRepository,
    PostgresInvoiceRepository,
    PostgresPaymentMethodRepository,
    PostgresSubscriptionRepository,
)
from .infrastructure.adapters.square_adapter import SquarePaymentProvider
from .infrastructure.adapters.webhook_adapter import configure_webhook_router, webhook_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SERVICE_NAME = "billing-service"
SERVICE_PORT = int(os.environ.get("BILLING_SERVICE_PORT", "8016"))


class LogEventPublisher:
    """Simple event publisher that logs events. Replace with real bus later."""

    async def publish(self, event) -> None:
        logger.info(f"Domain event: {type(event).__name__} — {event}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(f"Starting {SERVICE_NAME}...")

    # Database
    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev_password@localhost:5432/marty",
    )
    engine = create_async_engine(database_url, echo=False, pool_size=5)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Repositories
    customer_repo = PostgresCustomerRepository(session_factory)
    subscription_repo = PostgresSubscriptionRepository(session_factory)
    invoice_repo = PostgresInvoiceRepository(session_factory)
    payment_method_repo = PostgresPaymentMethodRepository(session_factory)

    # External adapters
    payment_provider = SquarePaymentProvider()
    org_service = OrgServiceClient()
    event_publisher = LogEventPublisher()

    # Use case
    billing_use_case = BillingUseCase(
        customer_repo=customer_repo,
        subscription_repo=subscription_repo,
        invoice_repo=invoice_repo,
        payment_method_repo=payment_method_repo,
        payment_provider=payment_provider,
        org_service=org_service,
        event_publisher=event_publisher,
    )

    # Wire routers
    configure_billing_router(billing_use_case)
    configure_webhook_router(billing_use_case)

    app.state.engine = engine

    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")

    yield

    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await engine.dispose()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Billing Service",
        description="Subscription billing microservice",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware
    try:
        from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
        app.add_middleware(RequestLoggingMiddleware, service_name=SERVICE_NAME)
        app.add_middleware(RequestIdMiddleware)
    except ImportError:
        logger.warning("marty_common middleware not available")

    # Routers
    app.include_router(billing_router)
    app.include_router(webhook_router)

    # Health check
    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": SERVICE_NAME}

    return app


app = create_app()
