"""Add organization audit events.

Revision ID: 20260710_0001
Revises: 20260709_0001
Create Date: 2026-07-10 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "20260710_0001"
down_revision = "20260709_0001"
branch_labels = None
depends_on = None


SCHEMA = "organization_service"
TABLE = "audit_events"


def _table_exists(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('organization_service.audit_events') IS NOT NULL")
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn):
        return

    op.create_table(
        TABLE,
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("category", sa.String(100), nullable=False, server_default="settings"),
        sa.Column("resource_type", sa.String(100), nullable=False, server_default="settings"),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("resource_name", sa.String(255), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("actor_type", sa.String(50), nullable=False, server_default="system"),
        sa.Column("severity", sa.String(50), nullable=False, server_default="info"),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("changes", JSONB, nullable=True),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_org_created_at",
        TABLE,
        ["organization_id", "created_at"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_org_category",
        TABLE,
        ["organization_id", "category"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_org_resource",
        TABLE,
        ["organization_id", "resource_type", "resource_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_org_actor",
        TABLE,
        ["organization_id", "actor_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_org_severity",
        TABLE,
        ["organization_id", "severity"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn):
        return

    op.drop_index("ix_audit_events_org_severity", table_name=TABLE, schema=SCHEMA)
    op.drop_index("ix_audit_events_org_actor", table_name=TABLE, schema=SCHEMA)
    op.drop_index("ix_audit_events_org_resource", table_name=TABLE, schema=SCHEMA)
    op.drop_index("ix_audit_events_org_category", table_name=TABLE, schema=SCHEMA)
    op.drop_index("ix_audit_events_org_created_at", table_name=TABLE, schema=SCHEMA)
    op.drop_table(TABLE, schema=SCHEMA)
