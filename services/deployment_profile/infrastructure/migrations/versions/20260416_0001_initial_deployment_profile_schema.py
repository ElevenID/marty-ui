"""Initial deployment-profile schema

Revision ID: 20260416_0001
Revises:
Create Date: 2026-04-16 00:01:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260416_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deployment_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("environment", sa.String(length=50), nullable=False),
        sa.Column("site_id", sa.String(length=255), nullable=True),
        sa.Column("trust_profile_id", sa.String(length=36), nullable=True),
        sa.Column("presentation_policy_ids", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("credential_template_ids", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("default_policy_id", sa.String(length=36), nullable=True),
        sa.Column("default_trust_profile_id", sa.String(length=36), nullable=True),
        sa.Column("default_compliance_profile_id", sa.String(length=36), nullable=True),
        sa.Column("default_presentation_policy_id", sa.String(length=36), nullable=True),
        sa.Column("network_mode", sa.String(length=50), nullable=False),
        sa.Column("key_access_mode", sa.String(length=50), nullable=False),
        sa.Column("environment_config", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("ux_config", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("enabled_flow_ids", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("update_channel", sa.String(length=50), nullable=False),
        sa.Column("update_policy", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("offline_cache_ttl_hours", sa.Integer(), nullable=False),
        sa.Column("biometric_required", sa.Boolean(), nullable=False),
        sa.Column("audit_all_events", sa.Boolean(), nullable=False),
        sa.Column("api_key", sa.Text(), nullable=True),
        sa.Column("api_key_prefix", sa.String(length=255), nullable=False),
        sa.Column("callbacks", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("api_auth", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("rate_limits", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("feature_flags", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("branding", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="deployment_profile_service",
    )
    op.create_index(
        "ix_deployment_profiles_organization_id",
        "deployment_profiles",
        ["organization_id"],
        unique=False,
        schema="deployment_profile_service",
    )
    op.create_index(
        "ix_deployment_profiles_org_status",
        "deployment_profiles",
        ["organization_id", "status"],
        unique=False,
        schema="deployment_profile_service",
    )
    op.create_index(
        "ix_deployment_profiles_status",
        "deployment_profiles",
        ["status"],
        unique=False,
        schema="deployment_profile_service",
    )

    op.create_table(
        "lanes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("deployment_profile_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=50), nullable=False),
        sa.Column("default_policy_id", sa.String(length=36), nullable=True),
        sa.Column("metadata", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("device_ids", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="deployment_profile_service",
    )
    op.create_index(
        "ix_lanes_deployment_profile_id",
        "lanes",
        ["deployment_profile_id"],
        unique=False,
        schema="deployment_profile_service",
    )


def downgrade() -> None:
    op.drop_index("ix_lanes_deployment_profile_id", table_name="lanes", schema="deployment_profile_service")
    op.drop_table("lanes", schema="deployment_profile_service")
    op.drop_index("ix_deployment_profiles_status", table_name="deployment_profiles", schema="deployment_profile_service")
    op.drop_index("ix_deployment_profiles_org_status", table_name="deployment_profiles", schema="deployment_profile_service")
    op.drop_index("ix_deployment_profiles_organization_id", table_name="deployment_profiles", schema="deployment_profile_service")
    op.drop_table("deployment_profiles", schema="deployment_profile_service")
