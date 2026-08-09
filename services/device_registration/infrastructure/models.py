"""SQLAlchemy models for device registration service."""

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Table,
    UniqueConstraint,
    text,
)
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
    Column("key_version", BigInteger, nullable=True),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    ),
    Column("last_seen_at", DateTime(timezone=True), nullable=True),
    CheckConstraint(
        "(public_key_der IS NULL AND public_key_kid IS NULL "
        "AND key_valid_from IS NULL AND key_valid_until IS NULL "
        "AND key_version IS NULL) OR "
        "(public_key_der IS NOT NULL AND public_key_kid IS NOT NULL "
        "AND key_valid_from IS NOT NULL AND key_version IS NOT NULL)",
        name="ck_device_registration_current_key_projection",
    ),
    schema="device_registration_service",
)

Index("ix_device_registrations_user_id", device_registrations.c.user_id)
Index("ix_device_registrations_organization_id", device_registrations.c.organization_id)
Index("ix_device_registrations_device_id", device_registrations.c.device_id)
Index(
    "ix_device_registrations_user_org",
    device_registrations.c.user_id,
    device_registrations.c.organization_id,
)


device_registration_keys = Table(
    "device_registration_keys",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column(
        "registration_id",
        String(36),
        ForeignKey(
            "device_registration_service.device_registrations.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("key_version", BigInteger, nullable=False),
    Column("public_key_der", String, nullable=False),
    Column("public_key_kid", String(43), nullable=False),
    Column("state", String(16), nullable=False),
    Column("valid_from", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True), nullable=True),
    Column("rotated_at", DateTime(timezone=True), nullable=True),
    Column("retire_at", DateTime(timezone=True), nullable=True),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    CheckConstraint(
        "key_version BETWEEN 1 AND 9007199254740991",
        name="ck_device_key_version_range",
    ),
    CheckConstraint(
        "char_length(public_key_der) BETWEEN 1 AND 8192",
        name="ck_device_key_der_length",
    ),
    CheckConstraint(
        "char_length(public_key_kid) = 43",
        name="ck_device_key_kid_length",
    ),
    CheckConstraint(
        "state IN ('CURRENT', 'RETIRING', 'RETIRED', 'REVOKED')",
        name="ck_device_key_state",
    ),
    CheckConstraint(
        "(state = 'RETIRING' AND rotated_at IS NOT NULL AND retire_at IS NOT NULL) "
        "OR state <> 'RETIRING'",
        name="ck_device_key_retiring_deadline",
    ),
    CheckConstraint(
        "(state = 'REVOKED' AND revoked_at IS NOT NULL) OR state <> 'REVOKED'",
        name="ck_device_key_revoked_at",
    ),
    CheckConstraint(
        "valid_until IS NULL OR valid_until > valid_from",
        name="ck_device_key_validity_window",
    ),
    CheckConstraint(
        "retire_at IS NULL OR rotated_at IS NULL OR retire_at >= rotated_at",
        name="ck_device_key_retirement_window",
    ),
    UniqueConstraint(
        "registration_id",
        "key_version",
        name="uq_device_key_registration_version",
    ),
    schema="device_registration_service",
)

Index(
    "ux_device_key_one_current",
    device_registration_keys.c.registration_id,
    unique=True,
    postgresql_where=text("state = 'CURRENT'"),
)
Index(
    "ix_device_key_registration_kid",
    device_registration_keys.c.registration_id,
    device_registration_keys.c.public_key_kid,
)


device_key_transitions = Table(
    "device_key_transitions",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column(
        "registration_id",
        String(36),
        ForeignKey(
            "device_registration_service.device_registrations.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("event", String(32), nullable=False),
    Column("from_version", BigInteger, nullable=True),
    Column("to_version", BigInteger, nullable=True),
    Column("committed_at", DateTime(timezone=True), nullable=False),
    CheckConstraint(
        "event IN ('KEY_REGISTERED', 'KEY_ROTATED', 'KEYS_REVOKED')",
        name="ck_device_key_transition_event",
    ),
    schema="device_registration_service",
)

Index(
    "ix_device_key_transition_registration_time",
    device_key_transitions.c.registration_id,
    device_key_transitions.c.committed_at,
)
