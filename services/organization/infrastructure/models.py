"""
SQLAlchemy Table Definitions for Organization Service

This module contains the database schema definitions (tables) for the organization service.
Following hexagonal architecture principles, these are infrastructure layer concerns.

The table definitions are separated from repository implementations to:
1. Allow migration tools (Alembic) to import metadata independently
2. Keep repository adapters focused on data access logic
3. Enable schema autogeneration without importing business logic
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Table, Text
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
    Column("owner_id", String(255)),
    Column("slug", String(255)),
    Column("org_type", String(50)),
    Column("contact_email", String(255)),
    Column("contact_phone", String(50)),
    Column("website", String(1024)),
    Column("settings", JSONB),
    Column("plan", String(50), nullable=False, default="free"),
    Column("plan_expires_at", DateTime(timezone=True), nullable=True),
    Column("join_mechanism", String(50), nullable=False, default="invite"),
    Column("requires_approval", Boolean, nullable=False, default=False),
    Column("is_discoverable", Boolean, nullable=False, default=False),
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
    Column("status", String(50), nullable=False, default="DRAFT"),
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


# Console Context Preferences table
console_context_preferences_table = Table(
    "console_context_preferences",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("user_id", String(255), nullable=False, unique=True),  # Unique constraint on user_id
    Column("last_view_mode", String(50), nullable=False, default="applicant"),
    Column("last_active_org_id", PostgresUUID(as_uuid=True)),  # Nullable
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


# Join Codes table
join_codes_table = Table(
    "join_codes",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True), ForeignKey(f"{SCHEMA}.organizations.id"), nullable=False),
    Column("code", String(8), nullable=False, unique=True),  # 8-character alphanumeric code
    Column("created_by", String(36), nullable=False),
    Column("expires_at", DateTime(timezone=True)),  # Nullable - optional expiration
    Column("max_uses", Integer),  # Nullable - optional use limit
    Column("use_count", Integer, nullable=False, default=0),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


# ─────────────────────────────────────────────────────────────────────────────
# RBAC Tables
# ─────────────────────────────────────────────────────────────────────────────

# Permissions catalog (global reference table)
permissions_table = Table(
    "permissions",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("resource", String(100), nullable=False),
    Column("action", String(100), nullable=False),
    Column("description", Text),
    schema=SCHEMA,
)


# Roles (per-organization)
roles_table = Table(
    "roles",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(100), nullable=False),
    Column("display_name", String(255)),
    Column("description", Text),
    Column("is_system", Boolean, nullable=False, default=False),
    Column("is_default_for_new_members", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


# Role ↔ Permission many-to-many
role_permissions_table = Table(
    "role_permissions",
    mapper_registry.metadata,
    Column("role_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.permissions.id", ondelete="CASCADE"), primary_key=True),
    schema=SCHEMA,
)


# Member ↔ Role many-to-many
member_roles_table = Table(
    "member_roles",
    mapper_registry.metadata,
    Column("member_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.members.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.roles.id", ondelete="CASCADE"), primary_key=True),
    schema=SCHEMA,
)


# ─────────────────────────────────────────────────────────────────────────────
# Cedar Policy Sets
# ─────────────────────────────────────────────────────────────────────────────

# Policy sets (per-organization Cedar policy collections)
policy_sets_table = Table(
    "policy_sets",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text),
    Column("policy_type", String(50), nullable=False, default="CUSTOM"),
    Column("status", String(50), nullable=False, default="DRAFT"),
    Column("cedar_policies", Text, nullable=False),
    Column("cedar_schema_version", String(50), nullable=False, default="MIP/1.0"),
    Column("created_by", String(36)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)


audit_events_table = Table(
    "audit_events",
    mapper_registry.metadata,
    Column("id", PostgresUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PostgresUUID(as_uuid=True),
           ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False),
    Column("event_type", String(120), nullable=False),
    Column("action", String(120), nullable=False),
    Column("category", String(100), nullable=False, default="settings"),
    Column("resource_type", String(100), nullable=False, default="settings"),
    Column("resource_id", String(255)),
    Column("resource_name", String(255)),
    Column("actor_id", String(255)),
    Column("actor_type", String(50), nullable=False, default="system"),
    Column("severity", String(50), nullable=False, default="info"),
    Column("message", Text, nullable=False, default=""),
    Column("changes", JSONB),
    Column("metadata", JSONB, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False),
    schema=SCHEMA,
)

Index("ix_audit_events_org_created_at", audit_events_table.c.organization_id, audit_events_table.c.created_at.desc())
Index("ix_audit_events_org_category", audit_events_table.c.organization_id, audit_events_table.c.category)
Index("ix_audit_events_org_resource", audit_events_table.c.organization_id, audit_events_table.c.resource_type, audit_events_table.c.resource_id)
Index("ix_audit_events_org_actor", audit_events_table.c.organization_id, audit_events_table.c.actor_id)
Index("ix_audit_events_org_severity", audit_events_table.c.organization_id, audit_events_table.c.severity)


# Export metadata for Alembic migrations
__all__ = [
    "mapper_registry",
    "organizations_table",
    "members_table",
    "api_keys_table",
    "console_context_preferences_table",
    "join_codes_table",
    "permissions_table",
    "roles_table",
    "role_permissions_table",
    "member_roles_table",
    "policy_sets_table",
    "audit_events_table",
    "SCHEMA",
]
