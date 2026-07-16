"""Stop advertising the Draft 13 walt.id community wallet.

Revision ID: 20260712_0001
Revises: 20260710_0002
Create Date: 2026-07-12 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260712_0001"
down_revision = "20260710_0002"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = f"{SCHEMA}.wallet_registry"
WALTID_WALLET_ID = "wr-waltid-001"


def _wallet_registry_exists(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :schema AND table_name = 'wallet_registry' LIMIT 1"
            ),
            {"schema": SCHEMA},
        ).scalar()
    )


def _set_active(conn, active: bool) -> None:
    conn.execute(
        sa.text(
            f"UPDATE {TABLE} SET is_active = :active, updated_at = NOW() "
            "WHERE id = :wallet_id"
        ),
        {"active": active, "wallet_id": WALTID_WALLET_ID},
    )


def upgrade() -> None:
    conn = op.get_bind()
    if _wallet_registry_exists(conn):
        _set_active(conn, False)


def downgrade() -> None:
    conn = op.get_bind()
    if _wallet_registry_exists(conn):
        _set_active(conn, True)
