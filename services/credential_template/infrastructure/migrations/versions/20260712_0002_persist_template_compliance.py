"""Persist Credential Template compliance dependencies.

Revision ID: 20260712_0002
Revises: 20260712_0001
Create Date: 2026-07-12 19:05:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260712_0002"
down_revision = "20260712_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = "credential_templates"


def _has_column(connection, column_name: str) -> bool:
    inspector = sa.inspect(connection)
    return any(
        column["name"] == column_name
        for column in inspector.get_columns(TABLE, schema=SCHEMA)
    )


def upgrade() -> None:
    connection = op.get_bind()
    if not _has_column(connection, "compliance_profile"):
        op.add_column(
            TABLE,
            sa.Column("compliance_profile", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            schema=SCHEMA,
        )
    if not _has_column(connection, "compliance_profile_id"):
        op.add_column(
            TABLE,
            sa.Column("compliance_profile_id", sa.String(length=36), nullable=True),
            schema=SCHEMA,
        )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.{TABLE}
            SET compliance_profile = jsonb_build_object(
                'compliance_code', 'CUSTOM',
                'credential_format', CASE
                    WHEN lower(coalesce(credential_payload_format, '')) LIKE '%mdoc%' THEN 'mdoc'
                    ELSE 'sd_jwt_vc'
                END
            )
            WHERE compliance_profile IS NULL
            """
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    if _has_column(connection, "compliance_profile_id"):
        op.drop_column(TABLE, "compliance_profile_id", schema=SCHEMA)
    if _has_column(connection, "compliance_profile"):
        op.drop_column(TABLE, "compliance_profile", schema=SCHEMA)
