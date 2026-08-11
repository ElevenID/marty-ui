"""Merge the released and beta credential-template histories.

Revision ID: 20260811_ct_0001
Revises: 20260802_0001, 20260806_0002
Create Date: 2026-08-11 00:00:00.000000+00:00
"""

from __future__ import annotations


revision = "20260811_ct_0001"
down_revision = ("20260802_0001", "20260806_0002")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Join both data-migration branches without changing the schema."""


def downgrade() -> None:
    """Restore both branch heads without changing the schema."""
