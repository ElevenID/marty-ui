"""Persist cascade and batch revocation operations.

Revision ID: rp_schema_004
Revises: rp_data_003
Create Date: 2026-08-12 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "rp_schema_004"
down_revision = "rp_data_003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cascade_revocation_operations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("operation_type", sa.String(), nullable=False),
        sa.Column("trigger_entity_type", sa.String(), nullable=False),
        sa.Column("trigger_entity_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("affected_credential_count", sa.BigInteger(), nullable=False),
        sa.Column("affected_credential_ids", sa.JSON(), nullable=False),
        sa.Column("requires_confirmation", sa.Boolean(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed_by", sa.String(), nullable=True),
        sa.Column("max_cascade_depth", sa.SmallInteger(), nullable=False),
        sa.Column("current_depth", sa.SmallInteger(), nullable=False),
        sa.Column("circuit_breaker_threshold", sa.BigInteger(), nullable=False),
        sa.Column("circuit_breaker_triggered", sa.Boolean(), nullable=False),
        sa.Column("can_rollback", sa.Boolean(), nullable=False),
        sa.Column("rollback_snapshot", sa.JSON(), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_by", sa.String(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_cascade_revocation_operations_org_created",
        "cascade_revocation_operations",
        ["organization_id", "created_at"],
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_cascade_revocation_operations_org_status",
        "cascade_revocation_operations",
        ["organization_id", "status"],
        schema="revocation_profile_service",
    )

    op.create_table(
        "revocation_batches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("revocation_profile_id", sa.String(), nullable=False),
        sa.Column("batch_interval", sa.String(), nullable=False),
        sa.Column("credential_format", sa.String(), nullable=False),
        sa.Column("credential_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["revocation_profile_id"],
            ["revocation_profile_service.revocation_profiles.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_revocation_batches_org_created",
        "revocation_batches",
        ["organization_id", "created_at"],
        schema="revocation_profile_service",
    )
    op.create_index(
        "ix_revocation_batches_org_status",
        "revocation_batches",
        ["organization_id", "status"],
        schema="revocation_profile_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_revocation_batches_org_status",
        table_name="revocation_batches",
        schema="revocation_profile_service",
    )
    op.drop_index(
        "ix_revocation_batches_org_created",
        table_name="revocation_batches",
        schema="revocation_profile_service",
    )
    op.drop_table("revocation_batches", schema="revocation_profile_service")
    op.drop_index(
        "ix_cascade_revocation_operations_org_status",
        table_name="cascade_revocation_operations",
        schema="revocation_profile_service",
    )
    op.drop_index(
        "ix_cascade_revocation_operations_org_created",
        table_name="cascade_revocation_operations",
        schema="revocation_profile_service",
    )
    op.drop_table(
        "cascade_revocation_operations",
        schema="revocation_profile_service",
    )
