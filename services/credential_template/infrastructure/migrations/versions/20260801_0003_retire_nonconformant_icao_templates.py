"""Retire demo templates that overstate ICAO eMRTD or DTC conformance.

Revision ID: 20260801_0003
Revises: 20260717_0001
Create Date: 2026-08-01 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260801_0003"
down_revision = "20260717_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET status = 'deprecated',
                   name = CASE id
                       WHEN '50000000-0000-0000-0000-000000000060' THEN 'Legacy ePassport Prototype'
                       ELSE 'Legacy Travel Credential Prototype'
                   END,
                   description = 'Legacy prototype retained for migration history. It is not an ICAO eMRTD or ICAO Digital Travel Credential implementation.',
                   wallet_configs = CAST('[]' AS jsonb),
                   updated_at = now()
             WHERE id IN (
                       '40000000-0000-0000-0000-000000000006',
                       '50000000-0000-0000-0000-000000000060',
                       '50000000-0000-0000-0000-000000000070',
                       '50000000-0000-0000-0000-000000000080'
                   )
                OR credential_type IN ('dtc', 'com.icao.mrv', 'com.icao.dtc.1', 'com.icao.dtc.2')
            """
        )
    )
    connection.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET name = 'Passport-style Credential (Demo)',
                   description = 'Demo passport-style application credential. It is not an ICAO eMRTD and does not represent ICAO conformance.',
                   doctype = NULL,
                   compliance_profile_id = NULL,
                   compliance_profile = jsonb_build_object(
                       'compliance_code', 'CUSTOM',
                       'credential_format', 'sd_jwt_vc'
                   ),
                   updated_at = now()
             WHERE credential_type = 'passport'
            """
        )
    )


def downgrade() -> None:
    # A downgrade must not revive templates carrying an invalid conformance claim.
    pass
