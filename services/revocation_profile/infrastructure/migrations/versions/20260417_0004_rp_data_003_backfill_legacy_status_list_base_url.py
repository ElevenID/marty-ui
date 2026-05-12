"""Backfill legacy status list base URLs to canonical org-scoped templates.

Revision ID: rp_data_003
Revises: rp_seed_002
Create Date: 2026-04-17 18:30:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "rp_data_003"
down_revision = "rp_seed_002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            WITH candidate_profiles AS (
                SELECT
                    id,
                    organization_id,
                    issuer_config::jsonb AS issuer_cfg,
                    issuer_config::jsonb ->> 'status_list_base_url' AS status_list_base_url
                FROM revocation_profile_service.revocation_profiles
            ),
            rewritten_profiles AS (
                SELECT
                    id,
                    jsonb_set(
                        issuer_cfg,
                        '{status_list_base_url}',
                        to_jsonb(
                            regexp_replace(status_list_base_url, '^(https?://[^/]+).*$','\\1')
                            || '/v1/organizations/' || organization_id
                            || '/revocation-profiles/' || id
                            || '/status-lists/{mechanism}/{purpose}'
                        ),
                        true
                    ) AS new_issuer_cfg
                FROM candidate_profiles
                WHERE status_list_base_url ~* '^https?://[^/]+/(lists|status-lists)/?$'
            )
            UPDATE revocation_profile_service.revocation_profiles AS target
            SET
                issuer_config = rewritten_profiles.new_issuer_cfg::json,
                updated_at = NOW()
            FROM rewritten_profiles
            WHERE target.id = rewritten_profiles.id
            """
        )
    )


def downgrade() -> None:
    # No safe automatic rollback; this migration intentionally normalizes legacy URLs.
    pass
