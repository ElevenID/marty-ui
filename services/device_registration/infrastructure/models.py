"""SQLAlchemy models for device registration service."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Index, String, Table
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    return datetime.now(timezone.utc)


device_registrations = Table(
    "device_registrations",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("user_id", String(255), nullable=False),
    Column("organization_id", String(36), nullable=True),
    Column("device_id", String(255), nullable=False),
    Column("platform", String(32), nullable=False),
    Column("fcm_token", String, nullable=False),
    Column("app_version", String(64), nullable=True),
    Column("os_version", String(128), nullable=True),
    Column("device_model", String(255), nullable=True),
    Column("preferences", JSON, nullable=False, default=dict),
    Column("public_key_der", String, nullable=True),
    Column("public_key_kid", String(255), nullable=True),
    Column("key_valid_from", DateTime(timezone=True), nullable=True),
    Column("key_valid_until", DateTime(timezone=True), nullable=True),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    Column("last_seen_at", DateTime(timezone=True), nullable=True),
    schema="device_registration_service",
)

Index("ix_device_registrations_user_id", device_registrations.c.user_id)
Index("ix_device_registrations_organization_id", device_registrations.c.organization_id)
Index("ix_device_registrations_device_id", device_registrations.c.device_id)
Index("ix_device_registrations_user_org", device_registrations.c.user_id, device_registrations.c.organization_id)
