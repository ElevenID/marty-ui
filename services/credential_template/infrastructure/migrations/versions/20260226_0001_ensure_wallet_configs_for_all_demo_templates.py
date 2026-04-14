"""Ensure all demo credential templates have Marty wallet config.

Idempotent migration that unconditionally sets the Marty wallet entry on
every demo org credential template, including open_badge.  Previous
migrations (20260224_0002/0003) only ran when wallet_configs was NULL or
empty — this migration overwrites any incomplete or missing config to
guarantee the full multi-wallet offer flow works on every deployment.

Revision ID: 20260226_0001
Revises: 20260224_0003
Create Date: 2026-02-26 00:01:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa
from marty_common.migration_profile import skip_demo_migrations


# revision identifiers, used by Alembic.
revision = "20260226_0001"
down_revision = "20260224_0003"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"

# All demo vendor template IDs (stable UUIDs from 20260216_0002).
DEMO_TEMPLATE_IDS = [
    "40000000-0000-0000-0000-000000000001",  # Passport
    "40000000-0000-0000-0000-000000000002",  # Driver's License
    "40000000-0000-0000-0000-000000000003",  # National ID
    "40000000-0000-0000-0000-000000000004",  # Travel Visa
    "40000000-0000-0000-0000-000000000005",  # Access Badge
    "40000000-0000-0000-0000-000000000006",  # Digital Travel Credential
    "40000000-0000-0000-0000-000000000007",  # Open Badge / Professional Development Certificate
]

# The Marty authenticator uses the SpruceID OID4VCI SDK which requires the
# spruce-vc+sd-jwt format variant to parse credential metadata correctly.
MARTY_WALLET_CONFIG = {
    "wallet_id": "marty",
    "deep_link_scheme": "openid-credential-offer://",
    "format_variant": "spruce-vc+sd-jwt",
}


def upgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    # Guard: skip entirely if the wallet_configs column doesn't exist yet.
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

    wallet_configs_json = json.dumps([MARTY_WALLET_CONFIG])

    # Unconditionally set the full wallet_configs for every demo template.
    # This replaces any partial/missing config from earlier migrations and
    # makes the demo catalog state deterministic regardless of migration history.
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = CAST(:wallet_configs AS jsonb),
                   updated_at     = NOW()
             WHERE organization_id = :organization_id
               AND id = ANY(CAST(:template_ids AS text[]))
            """
        ),
        {
            "wallet_configs": wallet_configs_json,
            "organization_id": DEMO_ORG_ID,
            "template_ids": "{" + ",".join(DEMO_TEMPLATE_IDS) + "}",
        },
    )


def downgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET wallet_configs = '[]'::jsonb,
                   updated_at     = NOW()
             WHERE organization_id = :organization_id
               AND id = ANY(CAST(:template_ids AS text[]))
            """
        ),
        {
            "organization_id": DEMO_ORG_ID,
            "template_ids": "{" + ",".join(DEMO_TEMPLATE_IDS) + "}",
        },
    )
