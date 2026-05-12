"""Align Marty trust profile with the KMS-backed issuer DID.

Revision ID: marty_trust_seed_004
Revises: marty_trust_seed_003
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "marty_trust_seed_004"
down_revision = "marty_trust_seed_003"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
MARTY_TRUSTED_ISSUER_ID = "60000000-0000-0000-0000-000000000011"
MARTY_DEFAULT_ORG_SLUG = "marty"


def _issuer_base_url() -> str:
    return (
        os.environ.get("MARTY_ISSUER_BASE_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_API_URL")
        or "https://beta.elevenidllc.com"
    ).rstrip("/")


def _issuer_did() -> str:
    configured = os.environ.get("MARTY_ISSUER_DID", "").strip()
    if configured:
        return configured
    public_domain = os.environ.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        public_domain = urlparse(_issuer_base_url()).netloc or "beta.elevenidllc.com"
    did_web_domain = public_domain.strip().strip("/").replace(":", "%3A").replace("/", ":")
    org_slug = os.environ.get("MARTY_ORG_SLUG", MARTY_DEFAULT_ORG_SLUG).strip().lower()
    org_slug = "".join(ch for ch in org_slug if ch.isalnum() or ch in "._-") or MARTY_DEFAULT_ORG_SLUG
    return f"did:web:{did_web_domain}:orgs:{org_slug}"


def _has_tables(conn) -> bool:
    trust_profiles = conn.execute(
        sa.text("SELECT to_regclass('trust_profile_service.trust_profiles') IS NOT NULL")
    ).scalar()
    trusted_issuers = conn.execute(
        sa.text("SELECT to_regclass('trust_profile_service.trusted_issuers') IS NOT NULL")
    ).scalar()
    return bool(trust_profiles and trusted_issuers)


def _managed_trust_source(issuer_did: str) -> dict:
    return {
        "id": "60000000-0000-0000-0000-000000000021",
        "name": "Marty Managed Issuer",
        "source_type": "PINNED_ISSUER",
        "issuer_did": issuer_did,
        "description": "Marty managed issuer DID",
        "enabled": True,
        "refresh_interval_hours": 24,
        "pinned_certificates": [],
    }


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_tables(conn):
        return

    issuer_did = _issuer_did()
    issuer_url = _issuer_base_url()

    row = conn.execute(
        sa.text(
            """
            SELECT trust_sources
              FROM trust_profile_service.trust_profiles
             WHERE id = :profile_id
               AND organization_id = :organization_id
            """
        ),
        {"profile_id": MARTY_TRUST_PROFILE_ID, "organization_id": MARTY_ORG_ID},
    ).fetchone()
    if row:
        sources = row[0] or []
        if isinstance(sources, str):
            sources = json.loads(sources)
        managed_source = _managed_trust_source(issuer_did)
        updated_sources = []
        replaced = False
        for source in sources if isinstance(sources, list) else []:
            if isinstance(source, dict) and (
                source.get("id") == managed_source["id"]
                or source.get("name") == managed_source["name"]
            ):
                updated_sources.append(managed_source)
                replaced = True
            else:
                updated_sources.append(source)
        if not replaced:
            updated_sources.append(managed_source)

        conn.execute(
            sa.text(
                """
                UPDATE trust_profile_service.trust_profiles
                   SET trust_sources = CAST(:trust_sources AS json),
                       updated_at = NOW()
                 WHERE id = :profile_id
                   AND organization_id = :organization_id
                """
            ),
            {
                "profile_id": MARTY_TRUST_PROFILE_ID,
                "organization_id": MARTY_ORG_ID,
                "trust_sources": json.dumps(updated_sources),
            },
        )

    conn.execute(
        sa.text(
            """
            UPDATE trust_profile_service.trusted_issuers
               SET issuer_did = :issuer_did,
                   issuer_url = :issuer_url,
                   updated_at = NOW()
             WHERE id = :issuer_id
               AND trust_profile_id = :profile_id
            """
        ),
        {
            "issuer_id": MARTY_TRUSTED_ISSUER_ID,
            "profile_id": MARTY_TRUST_PROFILE_ID,
            "issuer_did": issuer_did,
            "issuer_url": issuer_url,
        },
    )


def downgrade() -> None:
    # Keep the corrected DID binding; older values were environment-dependent and may
    # already be in active use by issued credentials.
    return