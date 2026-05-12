"""Ensure Marty trust profile is linked to the default revocation profile.

Revision ID: marty_trust_seed_002
Revises: marty_trust_seed_001
Create Date: 2026-04-16 00:30:00.000000+00:00
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "marty_trust_seed_002"
down_revision = "marty_trust_seed_001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
MARTY_REVOCATION_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_DEFAULT_ORG_SLUG = "marty"
NOW = "2026-04-16T00:30:00+00:00"


def _issuer_base_url() -> str:
    return (
        os.environ.get("MARTY_ISSUER_BASE_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_API_URL")
        or "https://beta.elevenidllc.com"
    ).rstrip("/")


def _issuer_did() -> str:
    configured = os.environ.get("MARTY_ISSUER_DID")
    if configured:
        return configured
    public_domain = os.environ.get("PUBLIC_DOMAIN")
    if not public_domain:
        public_domain = urlparse(_issuer_base_url()).netloc or "beta.elevenidllc.com"
    did_web_domain = public_domain.strip().strip("/").replace(":", "%3A").replace("/", ":")
    org_slug = os.environ.get("MARTY_ORG_SLUG", MARTY_DEFAULT_ORG_SLUG).strip().lower()
    org_slug = "".join(ch for ch in org_slug if ch.isalnum() or ch in "._-") or MARTY_DEFAULT_ORG_SLUG
    return f"did:web:{did_web_domain}:orgs:{org_slug}"


def _default_trust_sources() -> str:
    return json.dumps(
        [
            {
                "id": "60000000-0000-0000-0000-000000000021",
                "name": "Marty Managed Issuer",
                "source_type": "PINNED_ISSUER",
                "issuer_did": _issuer_did(),
                "description": "Marty managed issuer DID",
                "enabled": True,
                "refresh_interval_hours": 24,
                "pinned_certificates": [],
            }
        ]
    )


def _default_validation_rules() -> str:
    return json.dumps(
        {
            "allowed_algorithms": ["ES256", "EdDSA"],
            "min_key_size_rsa": 2048,
            "min_key_size_ec": 256,
            "require_key_usage": True,
            "max_chain_depth": 5,
            "allow_self_signed": False,
        }
    )


def _default_revocation_policy() -> str:
    return json.dumps(
        {
            "check_mode": "HARD_FAIL",
            "check_ocsp": True,
            "check_crl": True,
            "check_status_list": True,
            "offline_grace_period_hours": 12,
            "cache_duration_hours": 24,
        }
    )


def _default_time_policy() -> str:
    return json.dumps(
        {
            "max_clock_skew_seconds": 300,
            "credential_freshness_hours": 24,
            "require_not_before": True,
            "require_expiration": True,
        }
    )


def upgrade() -> None:
    conn = op.get_bind()

    # Ensure the canonical Marty login trust profile exists.
    conn.execute(
        sa.text(
            """
            INSERT INTO trust_profile_service.trust_profiles (
                id,
                organization_id,
                name,
                description,
                status,
                trust_sources,
                validation_rules,
                revocation_policy,
                revocation_profile_id,
                time_policy,
                supported_formats,
                registry_imports,
                created_at,
                updated_at
            )
            SELECT
                :id,
                :organization_id,
                :name,
                :description,
                :status,
                :trust_sources,
                :validation_rules,
                :revocation_policy,
                :revocation_profile_id,
                :time_policy,
                :supported_formats,
                :registry_imports,
                :created_at,
                :updated_at
            WHERE NOT EXISTS (
                SELECT 1
                FROM trust_profile_service.trust_profiles
                WHERE id = :id
            )
            """
        ),
        {
            "id": MARTY_TRUST_PROFILE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Marty Credential Login Trust",
            "description": "Default trust profile for Marty credential-login preview flows.",
            "status": "active",
            "trust_sources": _default_trust_sources(),
            "validation_rules": _default_validation_rules(),
            "revocation_policy": _default_revocation_policy(),
            "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
            "time_policy": _default_time_policy(),
            "supported_formats": json.dumps(["SD_JWT_VC", "MDOC"]),
            "registry_imports": json.dumps([]),
            "created_at": NOW,
            "updated_at": NOW,
        },
    )

    # Backfill old bootstrap data where the trust profile existed but had no revocation link.
    conn.execute(
        sa.text(
            """
            UPDATE trust_profile_service.trust_profiles
            SET revocation_profile_id = :revocation_profile_id,
                revocation_policy = COALESCE(revocation_policy, CAST(:revocation_policy AS json)),
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": MARTY_TRUST_PROFILE_ID,
            "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
            "revocation_policy": _default_revocation_policy(),
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            UPDATE trust_profile_service.trust_profiles
            SET revocation_profile_id = NULL,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": MARTY_TRUST_PROFILE_ID,
            "updated_at": NOW,
        },
    )
