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
from marty_common.service_setup import create_service_app

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


from common.grpc_event_bus import GrpcEventBusPublisher  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(f"Starting {SERVICE_NAME}...")

    # Database
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("billing"))
    session_factory = db.session_factory

    # Repositories
    customer_repo = PostgresCustomerRepository(session_factory)
    subscription_repo = PostgresSubscriptionRepository(session_factory)
    invoice_repo = PostgresInvoiceRepository(session_factory)
    payment_method_repo = PostgresPaymentMethodRepository(session_factory)

    # External adapters
    payment_provider = SquarePaymentProvider()
    org_service = OrgServiceClient()
    event_publisher = GrpcEventBusPublisher()

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

    app.state.engine = db.engine

    logger.info(f"{SERVICE_NAME} started on port {SERVICE_PORT}")

    yield

    # Cleanup
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await db.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    return create_service_app(
        title="Billing Service",
        description="Subscription billing microservice",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[billing_router, webhook_router],
    )


app = create_app()
