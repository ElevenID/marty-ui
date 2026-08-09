"""Adopt Device Registration schema and version device keys.

Revision ID: 20260809_0001
Revises: None
Create Date: 2026-08-09 00:00:00+00:00

This first owned revision supports both clean databases and legacy installations
whose registration table was created by SQLAlchemy ``create_all``. Existing
complete key projections become version 1; no earlier history is invented.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "20260809_0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA = "device_registration_service"


def _registration_metadata() -> sa.MetaData:
    metadata = sa.MetaData()
    registration = sa.Table(
        "device_registrations",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(255), nullable=False),
        sa.Column("organization_id", sa.String(36)),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("fcm_token", sa.Text(), nullable=False),
        sa.Column("app_version", sa.String(64)),
        sa.Column("os_version", sa.String(128)),
        sa.Column("device_model", sa.String(255)),
        sa.Column("preferences", postgresql.JSON(), nullable=False),
        sa.Column("public_key_der", sa.Text()),
        sa.Column("public_key_kid", sa.String(255)),
        sa.Column("key_valid_from", sa.DateTime(timezone=True)),
        sa.Column("key_valid_until", sa.DateTime(timezone=True)),
        sa.Column("key_version", sa.BigInteger()),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        schema=SCHEMA,
    )
    sa.Index("ix_device_registrations_user_id", registration.c.user_id)
    sa.Index("ix_device_registrations_organization_id", registration.c.organization_id)
    sa.Index("ix_device_registrations_device_id", registration.c.device_id)
    sa.Index(
        "ix_device_registrations_user_org",
        registration.c.user_id,
        registration.c.organization_id,
    )
    return metadata


def _key_metadata() -> sa.MetaData:
    metadata = sa.MetaData()
    registration = sa.Table(
        "device_registrations",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        schema=SCHEMA,
    )
    keys = sa.Table(
        "device_registration_keys",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "registration_id",
            sa.String(36),
            sa.ForeignKey(registration.c.id, ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("key_version", sa.BigInteger(), nullable=False),
        sa.Column("public_key_der", sa.Text(), nullable=False),
        sa.Column("public_key_kid", sa.String(43), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
        sa.Column("retire_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "key_version BETWEEN 1 AND 9007199254740991",
            name="ck_device_key_version_range",
        ),
        sa.CheckConstraint(
            "char_length(public_key_der) BETWEEN 1 AND 8192",
            name="ck_device_key_der_length",
        ),
        sa.CheckConstraint(
            "char_length(public_key_kid) = 43",
            name="ck_device_key_kid_length",
        ),
        sa.CheckConstraint(
            "state IN ('CURRENT', 'RETIRING', 'RETIRED', 'REVOKED')",
            name="ck_device_key_state",
        ),
        sa.CheckConstraint(
            "(state = 'RETIRING' AND rotated_at IS NOT NULL AND retire_at IS NOT NULL) "
            "OR state <> 'RETIRING'",
            name="ck_device_key_retiring_deadline",
        ),
        sa.CheckConstraint(
            "(state = 'REVOKED' AND revoked_at IS NOT NULL) OR state <> 'REVOKED'",
            name="ck_device_key_revoked_at",
        ),
        sa.CheckConstraint(
            "valid_until IS NULL OR valid_until > valid_from",
            name="ck_device_key_validity_window",
        ),
        sa.CheckConstraint(
            "retire_at IS NULL OR rotated_at IS NULL OR retire_at >= rotated_at",
            name="ck_device_key_retirement_window",
        ),
        sa.UniqueConstraint(
            "registration_id",
            "key_version",
            name="uq_device_key_registration_version",
        ),
        schema=SCHEMA,
    )
    sa.Index(
        "ux_device_key_one_current",
        keys.c.registration_id,
        unique=True,
        postgresql_where=sa.text("state = 'CURRENT'"),
    )
    sa.Index(
        "ix_device_key_registration_kid",
        keys.c.registration_id,
        keys.c.public_key_kid,
    )
    transitions = sa.Table(
        "device_key_transitions",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "registration_id",
            sa.String(36),
            sa.ForeignKey(registration.c.id, ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("from_version", sa.BigInteger()),
        sa.Column("to_version", sa.BigInteger()),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event IN ('KEY_REGISTERED', 'KEY_ROTATED', 'KEYS_REVOKED')",
            name="ck_device_key_transition_event",
        ),
        schema=SCHEMA,
    )
    sa.Index(
        "ix_device_key_transition_registration_time",
        transitions.c.registration_id,
        transitions.c.committed_at,
    )
    return metadata


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
    bind = op.get_bind()
    _registration_metadata().create_all(bind=bind, checkfirst=True)
    op.execute(
        sa.text(
            f"ALTER TABLE {SCHEMA}.device_registrations "
            "ADD COLUMN IF NOT EXISTS key_version BIGINT"
        )
    )
    op.execute(
        sa.text(
            "DO $$ BEGIN "
            f"IF EXISTS (SELECT 1 FROM {SCHEMA}.device_registrations "
            "WHERE (public_key_der IS NULL) <> (public_key_kid IS NULL)) THEN "
            "RAISE EXCEPTION 'cannot migrate incomplete legacy device key projection'; "
            "END IF; END $$"
        )
    )
    _key_metadata().create_all(bind=bind, checkfirst=True)
    op.execute(
        sa.text(
            f"INSERT INTO {SCHEMA}.device_registration_keys "
            "(id, registration_id, key_version, public_key_der, public_key_kid, "
            "state, valid_from, valid_until, revoked_at, created_at) "
            "SELECT r.id, r.id, 1, r.public_key_der, r.public_key_kid, "
            "CASE WHEN r.is_active THEN 'CURRENT' ELSE 'REVOKED' END, "
            "COALESCE(r.key_valid_from, r.created_at), r.key_valid_until, "
            "CASE WHEN r.is_active THEN NULL ELSE r.updated_at END, r.created_at "
            f"FROM {SCHEMA}.device_registrations r "
            "WHERE r.public_key_der IS NOT NULL "
            f"AND NOT EXISTS (SELECT 1 FROM {SCHEMA}.device_registration_keys k "
            "WHERE k.registration_id = r.id)"
        )
    )
    op.execute(
        sa.text(
            f"UPDATE {SCHEMA}.device_registrations SET key_version = 1, "
            "key_valid_from = COALESCE(key_valid_from, created_at) "
            "WHERE public_key_der IS NOT NULL AND key_version IS NULL"
        )
    )
    op.execute(
        sa.text(
            f"INSERT INTO {SCHEMA}.device_key_transitions "
            "(id, registration_id, event, from_version, to_version, committed_at) "
            "SELECT r.id, r.id, "
            "CASE WHEN r.is_active THEN 'KEY_REGISTERED' ELSE 'KEYS_REVOKED' END, "
            "CASE WHEN r.is_active THEN NULL ELSE 1 END, "
            "CASE WHEN r.is_active THEN 1 ELSE NULL END, "
            "CASE WHEN r.is_active THEN r.created_at ELSE r.updated_at END "
            f"FROM {SCHEMA}.device_registrations r "
            "WHERE r.key_version = 1 "
            f"AND NOT EXISTS (SELECT 1 FROM {SCHEMA}.device_key_transitions t "
            "WHERE t.registration_id = r.id)"
        )
    )
    op.execute(
        sa.text(
            f"UPDATE {SCHEMA}.device_registrations SET "
            "public_key_der = NULL, public_key_kid = NULL, "
            "key_valid_from = NULL, key_valid_until = NULL, key_version = NULL "
            "WHERE NOT is_active AND key_version IS NOT NULL"
        )
    )
    op.execute(
        sa.text(
            "DO $$ BEGIN IF NOT EXISTS ("
            "SELECT 1 FROM pg_constraint WHERE conname = "
            "'ck_device_registration_current_key_projection') THEN "
            f"ALTER TABLE {SCHEMA}.device_registrations ADD CONSTRAINT "
            "ck_device_registration_current_key_projection CHECK ("
            "(public_key_der IS NULL AND public_key_kid IS NULL "
            "AND key_valid_from IS NULL AND key_valid_until IS NULL "
            "AND key_version IS NULL) OR "
            "(public_key_der IS NOT NULL AND public_key_kid IS NOT NULL "
            "AND key_valid_from IS NOT NULL AND key_version IS NOT NULL)); "
            "END IF; END $$"
        )
    )
    if context.is_offline_mode():
        return
    inspector = sa.inspect(bind)
    required = {
        "device_registrations",
        "device_registration_keys",
        "device_key_transitions",
    }
    actual = set(inspector.get_table_names(schema=SCHEMA))
    if not required.issubset(actual):
        raise RuntimeError(
            f"cannot adopt {SCHEMA}: missing tables={sorted(required - actual)}"
        )


def downgrade() -> None:
    raise RuntimeError("versioned device-key history cannot be safely discarded")
