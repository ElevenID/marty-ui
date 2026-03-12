"""Add SpruceKit wallet config to MemberCredential templates.

Inserts an ``wr-spruce-001`` wallet config entry into the ``wallet_configs`` JSON
array of every credential template that already has a ``wr-default`` entry but
does not yet have a ``wr-spruce-001`` entry.  The SpruceKit config is identical
to ``wr-default`` (standard sd_jwt_vc format, standard issuer URL) but is labelled
"SpruceKit" so the UI renders a dedicated SpruceKit tab.

Revision ID: 20260309_0001
Revises: 20260308_0002
Create Date: 2026-03-09 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260309_0001"
down_revision = "20260308_0002"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"

SPRUCE_CONFIG = {
    "id": "member-wc-spruce",
    "wallet_id": "wr-spruce-001",
    "deep_link_scheme": "openid-credential-offer://",
    "format_variant": "spruce-vc+sd-jwt",
    "credential_configuration_id": "MemberCredential#spruce-sd-jwt",
    "display_name": "SpruceKit",
    "issuer_url_suffix": "/spruce",
    "custom_metadata": {},
}


def upgrade() -> None:
    conn = op.get_bind()

    # Add wr-spruce-001 after wr-default in every template that:
    #   - already has a wr-default entry (so it's a standard OID4VCI template)
    #   - does NOT already have a wr-spruce-001 entry (idempotent guard)
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = (
                   SELECT jsonb_agg(elem ORDER BY ord)
                   FROM (
                       SELECT elem, row_number() OVER () AS ord
                       FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
                       UNION ALL
                       SELECT CAST(:spruce_config AS jsonb),
                              (SELECT count(*) + 1 FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)))
                   ) sub
               )
             WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                       jsonb_build_object('wallet_id', 'wr-default')
                   )
               AND NOT (CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                       jsonb_build_object('wallet_id', 'wr-spruce-001')
                   ))
            """
        ),
        {"spruce_config": json.dumps(SPRUCE_CONFIG)},
    )


def downgrade() -> None:
    conn = op.get_bind()

    # Remove wr-spruce-001 entries from all templates
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = (
                   SELECT jsonb_agg(elem)
                   FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
                   WHERE elem->>'wallet_id' != 'wr-spruce-001'
               )
             WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                       jsonb_build_object('wallet_id', 'wr-spruce-001')
                   )
            """
        ),
    )
