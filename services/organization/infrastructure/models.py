"""
SQLAlchemy Table Definitions for Organization Service

This module contains the database schema definitions (tables) for the organization service.
Following hexagonal architecture principles, these are infrastructure layer concerns.

The table definitions are separated from repository implementations to:
1. Allow migration tools (Alembic) to import metadata independently
2. Keep repository adapters focused on data access logic
3. Enable schema autogeneration without importing business logic
"""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PostgresUUID
from sqlalchemy.orm import registry

# SQLAlchemy registry for mapping
mapper_registry = registry()

# Schema name for organization service
SCHEMA = "organization_service"


# Organizations table
organizations_table = Table(
    "organizations",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("name", String(255), nullable=False),
    Column("display_name", String(255)),
    Column("description", Text),
    Column("logo_url", String(1024)),
    Column("website_url", String(1024)),
    Column("status", String(50), nullable=False, default="active"),
    Column("metadata", JSONB),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("created_by", String(255)),
    Column("updated_by", String(255)),
    Column("slug", String(255)),
    Column("org_type", String(50)),
    Column("contact_email", String(255)),
    Column("contact_phone", String(50)),
    Column("website", String(1024)),
    Column("settings", JSONB),
    schema=SCHEMA,
)


# Members table
members_table = Table(
    "members",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True), ForeignKey(f"{SCHEMA}.organizations.id"), nullable=False),
    Column("user_id", String(36)),
    Column("email", String(255)),
    Column("role", String(50), nullable=False, default="member"),
    Column("status", String(50), nullable=False, default="active"),
    Column("invited_by", String(36)),
    Column("invited_at", DateTime(timezone=True)),
    Column("joined_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


# API Keys table
api_keys_table = Table(
    "api_keys",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True), ForeignKey(f"{SCHEMA}.organizations.id"), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text),
    Column("key_prefix", String(20), nullable=False),
    Column("key_hash", String(64), nullable=False, unique=True),
    Column("scopes", ARRAY(String), default=list),
    Column("status", String(50), nullable=False, default="active"),
    Column("rate_limit", Integer),
    Column("created_by", String(36), nullable=False),
    Column("last_used_at", DateTime(timezone=True)),
    Column("last_used_ip", String(45)),
    Column("expires_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


# Export metadata for Alembic migrations
__all__ = [
    "mapper_registry",
    "organizations_table",
    "members_table",
    "api_keys_table",
    "SCHEMA",
]
