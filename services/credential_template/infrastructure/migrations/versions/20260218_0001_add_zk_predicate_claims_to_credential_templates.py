"""Add zk_predicate_claims column to credential_templates.

Revision ID: 20260218_0001
Revises: 20260217_0003
Create Date: 2026-02-18 00:01:00.000000+00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


# revision identifiers, used by Alembic.
revision = "20260218_0001"
down_revision = "20260217_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add zk_predicate_claims column (nullable JSON list) to credential_templates."""
    op.add_column(
        "credential_templates",
        sa.Column("zk_predicate_claims", JSON, nullable=True, server_default="[]"),
        schema="credential_template_service",
    )


def downgrade() -> None:
    """Remove zk_predicate_claims column from credential_templates."""
    op.drop_column(
        "credential_templates",
        "zk_predicate_claims",
        schema="credential_template_service",
    )
