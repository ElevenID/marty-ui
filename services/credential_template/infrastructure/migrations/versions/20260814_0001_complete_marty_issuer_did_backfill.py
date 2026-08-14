"""Complete the public issuer-DID backfill for active Marty templates.

Revision ID: 20260814_ct_0001
Revises: 20260811_ct_0001
Create Date: 2026-08-14 00:00:00.000000+00:00

The original backfill selected legacy custody-routing columns. Some active
catalog rows never carried those columns, so they retained an empty
``issuer_did``. Once cached custody routing was removed, a single such row
made the complete public template collection fail closed with 409. Bind every
active default-organization template to the canonical public organization DID;
live DID resolution still selects and validates the compatible managed key.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "20260814_ct_0001"
down_revision = "20260811_ct_0001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = os.environ.get(
    "MARTY_ORG_ID",
    "00000000-0000-0000-0000-000000000001",
)


def _public_hostname() -> str:
    public_domain = str(os.environ.get("PUBLIC_DOMAIN") or "").strip()
    if public_domain:
        parsed = urlparse(
            public_domain if "://" in public_domain else f"https://{public_domain}"
        )
        if (
            parsed.hostname
            and parsed.path in {"", "/"}
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
        ):
            return parsed.hostname
        raise RuntimeError("PUBLIC_DOMAIN must contain only a public hostname")

    for name in ("PUBLIC_API_URL", "ISSUER_BASE_URL", "UI_BASE_URL"):
        value = str(os.environ.get(name) or "").strip()
        if not value:
            continue
        parsed = urlparse(value)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.path in {"", "/"}
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
        ):
            return parsed.hostname
        raise RuntimeError(f"{name} must be an absolute public origin")

    raise RuntimeError(
        "PUBLIC_DOMAIN or a public service origin is required to backfill issuer_did"
    )


def upgrade() -> None:
    issuer_did = f"did:web:{_public_hostname()}:orgs:marty"
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET issuer_did = :issuer_did,
                   version = coalesce(version, 0) + 1,
                   updated_at = now()
             WHERE organization_id = :organization_id
               AND lower(status) = 'active'
               AND nullif(trim(issuer_did), '') IS NULL
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "issuer_did": issuer_did,
        },
    )


def downgrade() -> None:
    raise RuntimeError("The corrective public issuer DID backfill is one-way.")
