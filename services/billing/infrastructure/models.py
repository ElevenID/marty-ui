"""
SQLAlchemy Table Definitions for Billing Service
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import registry

mapper_registry = registry()

SCHEMA = "billing_service"


customers_table = Table(
    "customers",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", String(36), nullable=False, unique=True, index=True),
    Column("square_customer_id", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


subscriptions_table = Table(
    "subscriptions",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("customer_id", PostgresUUID(as_uuid=True), ForeignKey(f"{SCHEMA}.customers.id"), nullable=False),
    Column("square_subscription_id", String(255), nullable=False, default=""),
    Column("plan_tier", String(50), nullable=False, default="free"),
    Column("status", String(50), nullable=False, default="pending"),
    Column("current_period_start", DateTime(timezone=True), nullable=True),
    Column("current_period_end", DateTime(timezone=True), nullable=True),
    Column("cancel_at_period_end", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


invoices_table = Table(
    "invoices",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("subscription_id", PostgresUUID(as_uuid=True), ForeignKey(f"{SCHEMA}.subscriptions.id"), nullable=False),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("square_invoice_id", String(255), nullable=False, default=""),
    Column("amount_cents", Integer, nullable=False, default=0),
    Column("currency", String(3), nullable=False, default="USD"),
    Column("status", String(50), nullable=False, default="pending"),
    Column("period_start", DateTime(timezone=True), nullable=True),
    Column("period_end", DateTime(timezone=True), nullable=True),
    Column("paid_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


payment_methods_table = Table(
    "payment_methods",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("square_card_id", String(255), nullable=False, default=""),
    Column("card_brand", String(50), nullable=False, default=""),
    Column("card_last4", String(4), nullable=False, default=""),
    Column("is_default", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)
