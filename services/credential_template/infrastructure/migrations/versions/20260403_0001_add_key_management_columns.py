"""Add key management columns to credential_templates.

Revision ID: 20260403_0001
Revises: 20260323_0001
Create Date: 2026-04-03 00:01:00.000000+00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


# revision identifiers, used by Alembic.
revision = "20260403_0001"
down_revision = "20260323_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add BYOK key management columns to credential_templates."""
    op.add_column(
        "credential_templates",
        sa.Column("key_access_mode", sa.String(20), nullable=True),
        schema="credential_template_service",
    )
    op.add_column(
        "credential_templates",
        sa.Column("issuer_key_id", sa.String(255), nullable=True),
        schema="credential_template_service",
    )
    op.add_column(
        "credential_templates",
        sa.Column("issuer_algorithm", sa.String(20), nullable=True),
        schema="credential_template_service",
    )
    op.add_column(
        "credential_templates",
        sa.Column("remote_signing_config", JSON, nullable=True),
        schema="credential_template_service",
    )


def downgrade() -> None:
    """Remove key management columns from credential_templates."""
    op.drop_column("credential_templates", "remote_signing_config", schema="credential_template_service")
    op.drop_column("credential_templates", "issuer_algorithm", schema="credential_template_service")
    op.drop_column("credential_templates", "issuer_key_id", schema="credential_template_service")
    op.drop_column("credential_templates", "key_access_mode", schema="credential_template_service")
