"""Seed an active Marty trust profile for credential-login bootstrap.

Revision ID: marty_trust_seed_001
Revises: registry_001
Create Date: 2026-04-16 00:10:00.000000+00:00
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "marty_trust_seed_001"
down_revision = "registry_001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
MARTY_TRUSTED_ISSUER_ID = "60000000-0000-0000-0000-000000000011"
MARTY_REVOCATION_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_DEFAULT_ORG_SLUG = "marty"
NOW = "2026-04-16T00:00:00+00:00"


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


def upgrade() -> None:
    conn = op.get_bind()
    issuer_did = _issuer_did()
    issuer_url = _issuer_base_url()

    existing = conn.execute(
        sa.text(
            """
            SELECT id
            FROM trust_profile_service.trust_profiles
            WHERE id = :id
            """
        ),
        {"id": MARTY_TRUST_PROFILE_ID},
    ).fetchone()

    if not existing:
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
                ) VALUES (
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
                )
                """
            ),
            {
                "id": MARTY_TRUST_PROFILE_ID,
                "organization_id": MARTY_ORG_ID,
                "name": "Marty Credential Login Trust",
                "description": "Default trust profile for Marty credential-login preview flows.",
                "status": "active",
                "trust_sources": json.dumps([
                    {
                        "id": "60000000-0000-0000-0000-000000000021",
                        "name": "Marty Managed Issuer",
                        "source_type": "PINNED_ISSUER",
                        "issuer_did": issuer_did,
                        "description": "Marty managed issuer DID",
                        "enabled": True,
                        "refresh_interval_hours": 24,
                        "pinned_certificates": [],
                    }
                ]),
                "validation_rules": json.dumps(
                    {
                        "allowed_algorithms": ["ES256", "EdDSA"],
                        "min_key_size_rsa": 2048,
                        "min_key_size_ec": 256,
                        "require_key_usage": True,
                        "max_chain_depth": 5,
                        "allow_self_signed": False,
                    }
                ),
                "revocation_policy": json.dumps(
                    {
                        "check_mode": "HARD_FAIL",
                        "check_ocsp": True,
                        "check_crl": True,
                        "check_status_list": True,
                        "offline_grace_period_hours": 12,
                        "cache_duration_hours": 24,
                    }
                ),
                "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
                "time_policy": json.dumps(
                    {
                        "max_clock_skew_seconds": 300,
                        "credential_freshness_hours": 24,
                        "require_not_before": True,
                        "require_expiration": True,
                    }
                ),
                "supported_formats": json.dumps(["SD_JWT_VC", "MDOC"]),
                "registry_imports": json.dumps([]),
                "created_at": NOW,
                "updated_at": NOW,
            },
        )

    issuer = conn.execute(
        sa.text(
            """
            SELECT id
            FROM trust_profile_service.trusted_issuers
            WHERE id = :id
            """
        ),
        {"id": MARTY_TRUSTED_ISSUER_ID},
    ).fetchone()

    if issuer:
        return

    conn.execute(
        sa.text(
            """
            INSERT INTO trust_profile_service.trusted_issuers (
                id,
                trust_profile_id,
                name,
                description,
                issuer_did,
                issuer_url,
                status,
                credential_template_ids,
                verification_keys,
                valid_from,
                valid_until,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :trust_profile_id,
                :name,
                :description,
                :issuer_did,
                :issuer_url,
                :status,
                :credential_template_ids,
                :verification_keys,
                :valid_from,
                :valid_until,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": MARTY_TRUSTED_ISSUER_ID,
            "trust_profile_id": MARTY_TRUST_PROFILE_ID,
            "name": "Marty Managed Issuer",
            "description": "Default issuer for Marty credential-login bootstrap.",
            "issuer_did": issuer_did,
            "issuer_url": issuer_url,
            "status": "active",
            "credential_template_ids": json.dumps(
                [
                    "50000000-0000-0000-0000-000000000010",
                    "50000000-0000-0000-0000-000000000030",
                ]
            ),
            "verification_keys": json.dumps([]),
            "valid_from": NOW,
            "valid_until": None,
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            DELETE FROM trust_profile_service.trusted_issuers
            WHERE id = :id
            """
        ),
        {"id": MARTY_TRUSTED_ISSUER_ID},
    )
    conn.execute(
        sa.text(
            """
            DELETE FROM trust_profile_service.trust_profiles
            WHERE id = :id
            """
        ),
        {"id": MARTY_TRUST_PROFILE_ID},
    )
