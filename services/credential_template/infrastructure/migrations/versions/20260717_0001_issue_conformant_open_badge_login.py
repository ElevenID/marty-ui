"""Issue the Marty login badge as a conformant Open Badges 3.0 VC-JWT.

Revision ID: 20260717_0001
Revises: 20260712_0004
Create Date: 2026-07-17 23:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260717_0001"
down_revision = "20260712_0004"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET credential_payload_format = 'jwt_vc',
                   supported_formats = CAST('["jwt_vc"]' AS jsonb),
                   selective_disclosure_fields = CAST('[]' AS jsonb),
                   wallet_configs = (
                       SELECT jsonb_agg(
                           CASE WHEN elem->>'wallet_id' = 'wr-spruce-001'
                           THEN elem
                                || jsonb_build_object('format_variant', 'jwt_vc_json')
                                || jsonb_build_object('credential_configuration_id', 'OpenBadgeCredential#jwt-vc')
                                || jsonb_build_object('issuer_url_suffix', NULL)
                           ELSE elem END
                       )
                       FROM jsonb_array_elements(COALESCE(CAST(wallet_configs AS jsonb), CAST('[]' AS jsonb))) AS elem
                   ),
                   version = GREATEST(version, 4),
                   updated_at = NOW()
             WHERE id = :template_id
               AND organization_id = :organization_id
            """
        ),
        {"template_id": OPEN_BADGE_TEMPLATE_ID, "organization_id": MARTY_ORG_ID},
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET credential_payload_format = 'sd_jwt_vc',
                   supported_formats = CAST('["sd_jwt_vc"]' AS jsonb),
                   wallet_configs = (
                       SELECT jsonb_agg(
                           CASE WHEN elem->>'wallet_id' = 'wr-spruce-001'
                           THEN elem
                                || jsonb_build_object('format_variant', 'spruce-vc+sd-jwt')
                                || jsonb_build_object('credential_configuration_id', 'open_badge#spruce-sd-jwt')
                                || jsonb_build_object('issuer_url_suffix', '/spruce')
                           ELSE elem END
                       )
                       FROM jsonb_array_elements(COALESCE(CAST(wallet_configs AS jsonb), CAST('[]' AS jsonb))) AS elem
                   ),
                   updated_at = NOW()
             WHERE id = :template_id
               AND organization_id = :organization_id
            """
        ),
        {"template_id": OPEN_BADGE_TEMPLATE_ID, "organization_id": MARTY_ORG_ID},
    )
