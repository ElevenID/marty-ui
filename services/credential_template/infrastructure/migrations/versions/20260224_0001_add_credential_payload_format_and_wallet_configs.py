"""Add credential_payload_format and wallet_configs to credential_templates.

Revision ID: 20260224_0001
Revises: 20260218_0001
Create Date: 2026-02-24 00:01:00.000000+00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


# revision identifiers, used by Alembic.
revision = "20260224_0001"
down_revision = "20260218_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add credential_payload_format and wallet_configs columns to credential_templates."""
    op.add_column(
        "credential_templates",
        sa.Column(
            "credential_payload_format",
            sa.String(30),
            nullable=False,
            server_default="w3c_vcdm_v2_sd_jwt",
        ),
        schema="credential_template_service",
    )
    op.add_column(
        "credential_templates",
        sa.Column(
            "wallet_configs",
            JSON,
            nullable=True,
            server_default="[]",
        ),
        schema="credential_template_service",
    )


def downgrade() -> None:
    """Remove credential_payload_format and wallet_configs columns from credential_templates."""
    op.drop_column(
        "credential_templates",
        "wallet_configs",
        schema="credential_template_service",
    )
    op.drop_column(
        "credential_templates",
        "credential_payload_format",
        schema="credential_template_service",
    )
