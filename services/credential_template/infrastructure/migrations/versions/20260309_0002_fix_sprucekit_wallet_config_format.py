"""Fix wr-spruce-001 wallet config to use spruce-vc+sd-jwt format and /spruce issuer.

Migration 20260309_0001 inserted the SpruceKit wallet config with incorrect values:
  - format_variant: "sd_jwt_vc"  → should be "spruce-vc+sd-jwt"
  - credential_configuration_id: "MemberCredential#sd-jwt" → "MemberCredential#spruce-sd-jwt"
  - issuer_url_suffix: null → "/spruce"

SpruceKit's mobile-sdk-rs uses ProfilesCredentialConfiguration (untagged serde enum)
which only recognises "spruce-vc+sd-jwt" and "mso_mdoc" — any "vc+sd-jwt" entry in
the issuer metadata document causes the whole fetch to fail, resulting in
UndefinedCredential errors.  Pointing the offer at the /spruce issuer URL (which emits
only "spruce-vc+sd-jwt" entries for SD-JWT types) resolves this.

Revision ID: 20260309_0002
Revises: 20260309_0001
Create Date: 2026-03-09 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260309_0002"
down_revision = "20260309_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Patch every wr-spruce-001 wallet config entry across all credential templates
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = (
                   SELECT jsonb_agg(
                       CASE
                           WHEN elem->>'wallet_id' = 'wr-spruce-001'
                           THEN elem
                                || jsonb_build_object('format_variant', 'spruce-vc+sd-jwt')
                                || jsonb_build_object('credential_configuration_id', 'MemberCredential#spruce-sd-jwt')
                                || jsonb_build_object('issuer_url_suffix', '/spruce')
                           ELSE elem
                       END
                   )
                   FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
               )
             WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                       jsonb_build_object('wallet_id', 'wr-spruce-001')
                   )
            """
        ),
    )


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = (
                   SELECT jsonb_agg(
                       CASE
                           WHEN elem->>'wallet_id' = 'wr-spruce-001'
                           THEN elem
                                || jsonb_build_object('format_variant', 'sd_jwt_vc')
                                || jsonb_build_object('credential_configuration_id', 'MemberCredential#sd-jwt')
                                || jsonb_build_object('issuer_url_suffix', NULL)
                           ELSE elem
                       END
                   )
                   FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
               )
             WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                       jsonb_build_object('wallet_id', 'wr-spruce-001')
                   )
            """
        ),
    )
