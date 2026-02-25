"""Backfill format_variant on existing Marty wallet configs.

Migration 20260224_0002 seeded wallet_configs on demo templates but only
ran when wallet_configs was NULL or empty.  Templates that already had
wallet_configs set (e.g. from a previous deployment or manual update) were
not updated.  This migration adds ``format_variant: "spruce-vc+sd-jwt"`` to
any Marty wallet config entry that is missing the field.

Revision ID: 20260224_0003
Revises: 20260224_0002
Create Date: 2026-02-24 00:03:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260224_0003"
down_revision = "20260224_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Guard: skip if wallet_configs column doesn't exist yet.
    has_col = conn.execute(
        sa.text(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'credential_template_service'
                  AND table_name   = 'credential_templates'
                  AND column_name  = 'wallet_configs'
            )
            """
        )
    ).scalar_one()
    if not has_col:
        return

    # For every row that has a Marty wallet config without format_variant,
    # add "format_variant": "spruce-vc+sd-jwt" to that element.
    # The column is json not jsonb, so we cast as needed.
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
            SET wallet_configs = (
              SELECT jsonb_agg(
                CASE
                  WHEN elem->>'wallet_id' = 'marty'
                  THEN elem || '{"format_variant": "spruce-vc+sd-jwt"}'::jsonb
                  ELSE elem
                END
              )::json
              FROM jsonb_array_elements(wallet_configs::jsonb) AS elem
            ),
            updated_at = NOW()
            WHERE wallet_configs IS NOT NULL
              AND wallet_configs::text != '[]'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(wallet_configs::jsonb) AS elem
                WHERE elem->>'wallet_id' = 'marty'
              )
              AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(wallet_configs::jsonb) AS elem
                WHERE elem->>'wallet_id' = 'marty'
                  AND (elem::jsonb) ? 'format_variant'
              )
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    # Remove format_variant from Marty wallet config entries.
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
            SET wallet_configs = (
              SELECT jsonb_agg(
                CASE
                  WHEN elem->>'wallet_id' = 'marty'
                  THEN elem - 'format_variant'
                  ELSE elem
                END
              )::json
              FROM jsonb_array_elements(wallet_configs::jsonb) AS elem
            ),
            updated_at = NOW()
            WHERE wallet_configs IS NOT NULL
              AND wallet_configs::text != '[]'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(wallet_configs::jsonb) AS elem
                WHERE elem->>'wallet_id' = 'marty'
                  AND (elem::jsonb) ? 'format_variant'
              )
            """
        )
    )
