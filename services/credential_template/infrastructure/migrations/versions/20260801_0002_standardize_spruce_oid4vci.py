"""Move SpruceKit wallet routing to current OID4VCI standard profiles.

Revision ID: 20260801_0002
Revises: 20260801_0001
Create Date: 2026-08-01 18:45:00.000000+00:00

Current Spruce ``oid4vci-rs`` supports the standard ``dc+sd-jwt`` and
``mso_mdoc`` profiles. Remove Marty's obsolete SDK-specific format, issuer
path, and credential-configuration suffix from current data.
"""

from __future__ import annotations

from alembic import op
from sqlalchemy import text


revision = "20260801_0002"
down_revision = "20260801_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        text(
            """
        UPDATE credential_template_service.wallet_registry
        SET supported_formats = '["dc+sd-jwt", "mso_mdoc"]'::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE id IN ('wr-spruce-001', 'wr-marty-001')
        """
        )
    )
    connection.execute(
        text(
            """
        WITH normalized AS (
            SELECT template.id,
                jsonb_agg(
                CASE
                    WHEN config->>'format_variant' = 'spruce-vc+sd-jwt'
                      OR config->>'credential_configuration_id' LIKE '%#spruce-sd-jwt'
                      OR config->>'issuer_url_suffix' = '/spruce'
                    THEN config
                        - 'format_variant'
                        - 'credential_configuration_id'
                        - 'issuer_url_suffix'
                    ELSE config
                END
                ORDER BY ordinal
            ) AS wallet_configs
            FROM credential_template_service.credential_templates AS template
            CROSS JOIN LATERAL jsonb_array_elements(CAST(template.wallet_configs AS jsonb))
                WITH ORDINALITY AS entry(config, ordinal)
            WHERE jsonb_typeof(CAST(template.wallet_configs AS jsonb)) = 'array'
            GROUP BY template.id
            HAVING bool_or(
                config->>'format_variant' = 'spruce-vc+sd-jwt'
                OR config->>'credential_configuration_id' LIKE '%#spruce-sd-jwt'
                OR config->>'issuer_url_suffix' = '/spruce'
            )
        )
        UPDATE credential_template_service.credential_templates AS template
        SET wallet_configs = normalized.wallet_configs,
            updated_at = CURRENT_TIMESTAMP
        FROM normalized
        WHERE template.id = normalized.id
        """
        )
    )


def downgrade() -> None:
    """The removed values were non-standard and are intentionally not restored."""

    raise RuntimeError("one-way protocol repair: obsolete Spruce aliases cannot be restored")
