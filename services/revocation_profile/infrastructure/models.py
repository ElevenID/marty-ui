"""
SQLAlchemy models for Revocation Profile Service.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    SmallInteger,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    return datetime.now(timezone.utc)


revocation_profiles_table = Table(
    "revocation_profiles",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("name", String, nullable=False),
    Column("status", String, nullable=False, default="draft"),
    Column("issuer_config", JSON, nullable=False, default=dict),
    Column("verifier_config", JSON, nullable=False, default=dict),
    Column("automation_config", JSON, nullable=False, default=dict),
    Column("supported_formats", JSON, nullable=False, default=list),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    Index("ix_revocation_profiles_organization_id", "organization_id"),
    Index("ix_revocation_profiles_status", "status"),
    schema="revocation_profile_service",
)


cascade_revocation_operations_table = Table(
    "cascade_revocation_operations",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("operation_type", String, nullable=False),
    Column("trigger_entity_type", String, nullable=False),
    Column("trigger_entity_id", String, nullable=False),
    Column("status", String, nullable=False),
    Column("affected_credential_count", BigInteger, nullable=False),
    Column("affected_credential_ids", JSON, nullable=False, default=list),
    Column("requires_confirmation", Boolean, nullable=False),
    Column("confirmed_at", DateTime(timezone=True)),
    Column("confirmed_by", String),
    Column("max_cascade_depth", SmallInteger, nullable=False),
    Column("current_depth", SmallInteger, nullable=False),
    Column("circuit_breaker_threshold", BigInteger, nullable=False),
    Column("circuit_breaker_triggered", Boolean, nullable=False),
    Column("can_rollback", Boolean, nullable=False),
    Column("rollback_snapshot", JSON),
    Column("rolled_back_at", DateTime(timezone=True)),
    Column("rolled_back_by", String),
    Column("error_message", Text),
    Column("metadata", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("completed_at", DateTime(timezone=True)),
    Index(
        "ix_cascade_revocation_operations_org_created",
        "organization_id",
        "created_at",
    ),
    Index(
        "ix_cascade_revocation_operations_org_status",
        "organization_id",
        "status",
    ),
    schema="revocation_profile_service",
)


revocation_batches_table = Table(
    "revocation_batches",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column(
        "revocation_profile_id",
        String,
        ForeignKey(
            "revocation_profile_service.revocation_profiles.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    ),
    Column("batch_interval", String, nullable=False),
    Column("credential_format", String, nullable=False),
    Column("credential_ids", JSON, nullable=False, default=list),
    Column("status", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("published_at", DateTime(timezone=True)),
    Index("ix_revocation_batches_org_created", "organization_id", "created_at"),
    Index("ix_revocation_batches_org_status", "organization_id", "status"),
    schema="revocation_profile_service",
)
