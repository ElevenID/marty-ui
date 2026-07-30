"""Expand organization member identifiers for valid SCIM externalId values.

Revision ID: 20260730_0001
Revises: 20260720_0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260730_0001"
down_revision = "20260720_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "members",
        "user_id",
        schema="organization_service",
        existing_type=sa.String(length=36),
        type_=sa.String(length=255),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "members",
        "user_id",
        schema="organization_service",
        existing_type=sa.String(length=255),
        type_=sa.String(length=36),
        existing_nullable=True,
    )
