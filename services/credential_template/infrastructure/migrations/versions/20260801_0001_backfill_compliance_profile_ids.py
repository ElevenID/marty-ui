"""Bind legacy credential templates to real system compliance profiles.

Revision ID: 20260801_0001
Revises: 20260729_0001
Create Date: 2026-08-01 00:00:00.000000+00:00

Older seeded templates stored an inline ``CUSTOM`` hint before Marty Protocol
required a Compliance Profile resource reference. Preserve every credential
format while replacing that obsolete path with stable system profile IDs.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260801_0001"
down_revision = "20260729_0001"
branch_labels = None
depends_on = None

OID4VC_PROFILE_ID = "10000000-0000-0000-0000-000000000001"
MDOC_PROFILE_ID = "10000000-0000-0000-0000-000000000002"
OPEN_BADGES_PROFILE_ID = "10000000-0000-0000-0000-000000000003"
VDS_NC_PROFILE_ID = "10000000-0000-0000-0000-000000000004"
OPEN_BADGE_TEMPLATE_IDS = (
    "40000000-0000-0000-0000-000000000007",
    "50000000-0000-0000-0000-000000000040",
)


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET compliance_profile_id = CASE
                       WHEN id IN :open_badge_template_ids THEN :open_badges_profile_id
                       WHEN lower(coalesce(credential_payload_format, '')) IN ('mdoc', 'mso_mdoc')
                           THEN :mdoc_profile_id
                       WHEN lower(coalesce(credential_payload_format, '')) = 'vds_nc'
                           THEN :vds_nc_profile_id
                       ELSE :oid4vc_profile_id
                   END,
                   version = coalesce(version, 0) + 1,
                   updated_at = now()
             WHERE nullif(trim(compliance_profile_id), '') IS NULL
            """
        ).bindparams(sa.bindparam("open_badge_template_ids", expanding=True)),
        {
            "open_badge_template_ids": OPEN_BADGE_TEMPLATE_IDS,
            "open_badges_profile_id": OPEN_BADGES_PROFILE_ID,
            "mdoc_profile_id": MDOC_PROFILE_ID,
            "vds_nc_profile_id": VDS_NC_PROFILE_ID,
            "oid4vc_profile_id": OID4VC_PROFILE_ID,
        },
    )
    op.alter_column(
        "credential_templates",
        "compliance_profile_id",
        schema="credential_template_service",
        existing_type=sa.String(length=36),
        nullable=False,
    )


def downgrade() -> None:
    raise RuntimeError("Compliance Profile references are a one-way protocol repair.")
