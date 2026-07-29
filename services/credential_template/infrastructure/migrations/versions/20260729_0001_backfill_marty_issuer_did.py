"""Backfill the public issuer DID on Marty credential templates.

Revision ID: 20260729_0001
Revises: 20260712_0004
Create Date: 2026-07-29 00:00:00.000000+00:00

The artifact-pipeline migration populated legacy internal issuer-profile and
managed-key fields but did not populate ``issuer_did``.  That left catalog
templates able to reach the managed signing path without exposing the public
DID that is supposed to select it.  Bind every still-active Marty template
that lacks a DID to the same public DID used by its KMS-backed issuer profiles.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "20260729_0001"
down_revision = "20260712_0004"
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
               AND key_access_mode = 'REMOTE_SIGNING'
               AND nullif(trim(issuer_profile_id), '') IS NOT NULL
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "issuer_did": issuer_did,
        },
    )


def downgrade() -> None:
    raise RuntimeError("The public issuer DID backfill is one-way.")
