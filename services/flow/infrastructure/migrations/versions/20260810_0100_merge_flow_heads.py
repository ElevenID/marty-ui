"""Merge callback outbox and durable application-offer branches.

Revision ID: 20260810_0100
Revises: 20260808_0002, 20260809_0001
Create Date: 2026-08-10 01:00:00
"""

from collections.abc import Sequence


revision: str = "20260810_0100"
down_revision: tuple[str, str] = ("20260808_0002", "20260809_0001")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Join the two schema-complete migration branches."""


def downgrade() -> None:
    """Restore both branch heads without changing either schema."""
