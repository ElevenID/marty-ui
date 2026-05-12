"""
SQLAlchemy models for Revocation Profile Service.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer, JSON, Table, Index
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
