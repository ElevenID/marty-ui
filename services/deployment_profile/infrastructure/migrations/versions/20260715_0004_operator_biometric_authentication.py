"""Clarify that Deployment Profile biometrics authenticate the operator.

Revision ID: 20260715_0004
Revises: 20260416_0003
Create Date: 2026-07-15 00:00:00+00:00
"""

from alembic import op


revision = "20260715_0004"
down_revision = "20260416_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "deployment_profiles",
        "biometric_required",
        new_column_name="operator_biometric_authentication_required",
        schema="deployment_profile_service",
    )


def downgrade() -> None:
    op.alter_column(
        "deployment_profiles",
        "operator_biometric_authentication_required",
        new_column_name="biometric_required",
        schema="deployment_profile_service",
    )
