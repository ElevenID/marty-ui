"""Merge the alias-removal and operator-biometric migration branches.

Revision ID: 20260716_0001
Revises: 20260712_0001, 20260715_0004
Create Date: 2026-07-16 00:00:00+00:00
"""

revision = "20260716_0001"
down_revision = ("20260712_0001", "20260715_0004")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Join the two independently additive schema histories."""


def downgrade() -> None:
    """Split the history back into its two parent heads."""
