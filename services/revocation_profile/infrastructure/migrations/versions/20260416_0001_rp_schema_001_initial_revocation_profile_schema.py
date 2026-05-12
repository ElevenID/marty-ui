"""Initial revocation profile schema

Revision ID: rp_schema_001
Revises:
Create Date: 2026-04-16 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "rp_schema_001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS revocation_profile_service")

    op.create_table(
        "revocation_profiles",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="draft"),
        sa.Column("issuer_config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("verifier_config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("automation_config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("supported_formats", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_revocation_profiles_organization_id",
        "revocation_profiles",
        ["organization_id"],
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_revocation_profiles_status",
        "revocation_profiles",
        ["status"],
        schema="revocation_profile_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_revocation_profiles_status",
        table_name="revocation_profiles",
        schema="revocation_profile_service",
    )
    op.drop_index(
        "ix_revocation_profiles_organization_id",
        table_name="revocation_profiles",
        schema="revocation_profile_service",
    )
    op.drop_table("revocation_profiles", schema="revocation_profile_service")
