"""Add preconditions column to flow_definitions

Revision ID: 2a3b4c5d6e7f
Revises: 1854c4083445
Create Date: 2026-04-10 01:30:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '2a3b4c5d6e7f'
down_revision = '1854c4083445'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'flow_definitions',
        sa.Column('preconditions', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        schema='flow_service',
    )


def downgrade() -> None:
    op.drop_column('flow_definitions', 'preconditions', schema='flow_service')
