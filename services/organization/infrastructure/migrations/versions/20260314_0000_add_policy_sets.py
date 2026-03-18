"""Add policy_sets table for Cedar policy management

Revision ID: 20260314_0000
Revises: 20260308_0000
Create Date: 2026-03-14 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = '20260314_0000'
down_revision = '20260308_0000'
branch_labels = None
depends_on = None

SCHEMA = "organization_service"


def upgrade() -> None:
    op.create_table(
        "policy_sets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("policy_type", sa.String(50), nullable=False, server_default="CUSTOM"),
        sa.Column("status", sa.String(50), nullable=False, server_default="active"),
        sa.Column("cedar_policies", sa.Text(), nullable=False),
        sa.Column("cedar_schema_version", sa.String(50), nullable=False, server_default="1.0"),
        sa.Column("created_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "name", name="uq_policy_sets_org_name"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_policy_sets_organization_id",
        "policy_sets",
        ["organization_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_policy_sets_status",
        "policy_sets",
        ["status"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index("ix_policy_sets_status", table_name="policy_sets", schema=SCHEMA)
    op.drop_index("ix_policy_sets_organization_id", table_name="policy_sets", schema=SCHEMA)
    op.drop_table("policy_sets", schema=SCHEMA)
