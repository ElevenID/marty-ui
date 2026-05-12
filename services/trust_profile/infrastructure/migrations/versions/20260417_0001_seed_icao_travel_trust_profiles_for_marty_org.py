"""Seed ICAO travel document and mDL trust profiles for the Marty default organisation.

Adds two production-ready verification trust profiles:

  60000000-…-0002  ICAO Travel Document Trust (VDS-NC, mDoc, ePassport)
  60000000-…-0003  Mobile Driver's License / AAMVA Trust (mDoc, SD-JWT-VC)

Each profile carries the appropriate trust sources, validation rules, revocation
policy, and time policy to verify credentials produced by the VDSNC-RUST
signing pipeline and the existing mDoc issuance stack.

Trusted issuer rows are inserted for:
  • The Marty managed ICAO issuer (both VDS-NC and mDoc)
  • The Marty managed mDL issuer (mDoc + SD-JWT-VC)

Revision ID: marty_trust_seed_003
Revises: marty_trust_seed_002
Create Date: 2026-04-17 01:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "marty_trust_seed_003"
down_revision = "marty_trust_seed_002"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_REVOCATION_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
NOW = "2026-04-17T01:00:00+00:00"

# Trust profile IDs
ICAO_TRAVEL_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000002"
MDL_AAMVA_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000003"

# Trusted issuer IDs
ICAO_MARTY_ISSUER_ID = "60000000-0000-0000-0000-000000000031"
ICAO_PKD_REGISTRY_ID = "60000000-0000-0000-0000-000000000032"
MDL_MARTY_ISSUER_ID = "60000000-0000-0000-0000-000000000033"
MDL_AAMVA_REGISTRY_ID = "60000000-0000-0000-0000-000000000034"

# Credential template IDs for trusted issuer scope
EPASSPORT_TEMPLATE_ID = "50000000-0000-0000-0000-000000000060"
DTC1_TEMPLATE_ID = "50000000-0000-0000-0000-000000000070"
DTC2_TEMPLATE_ID = "50000000-0000-0000-0000-000000000080"
VISA_TEMPLATE_ID = "50000000-0000-0000-0000-000000000090"
ETD_TEMPLATE_ID = "50000000-0000-0000-0000-0000000000a0"
MDL_TEMPLATE_ID = "50000000-0000-0000-0000-000000000020"


# ---------------------------------------------------------------------------
# Trust profile row builders
# ---------------------------------------------------------------------------

def _icao_trust_profile() -> dict:
    return {
        "id": ICAO_TRAVEL_TRUST_PROFILE_ID,
        "organization_id": MARTY_ORG_ID,
        "name": "ICAO Travel Document Verification",
        "description": (
            "Verification trust profile for ICAO travel documents issued as "
            "VDS-NC barcodes or ISO 18013-5 mDoc (ePassport, DTC-1, DTC-2, "
            "visa, emergency travel document). Supports ICAO PKD registry "
            "trust anchor lookups and Marty managed issuer PIN."
        ),
        "status": "active",
        "trust_sources": json.dumps([
            {
                "id": ICAO_PKD_REGISTRY_ID,
                "name": "ICAO Public Key Directory",
                "source_type": "REGISTRY",
                "registry_url": "https://pkd.icao.int/",
                "description": (
                    "ICAO PKD master list. Country Signing Certificate "
                    "Authority (CSCA) certificates are fetched from this "
                    "registry to verify Document Signer Certificates (DSC) "
                    "used to sign VDS-NC payloads."
                ),
                "enabled": True,
                "refresh_interval_hours": 24,
                "pinned_certificates": [],
                "registry_namespace": "icao_pkd",
            },
            {
                "id": ICAO_MARTY_ISSUER_ID,
                "name": "Marty Managed ICAO Issuer",
                "source_type": "PINNED_ISSUER",
                "issuer_did": "did:web:beta.elevenidllc.com",
                "description": (
                    "Marty controlled issuer key used for VDS-NC ECDSA "
                    "signing during development and demo scenarios."
                ),
                "enabled": True,
                "refresh_interval_hours": 24,
                "pinned_certificates": [],
            },
        ]),
        "validation_rules": json.dumps({
            "allowed_algorithms": ["ES256", "ES384", "EdDSA"],
            "min_key_size_rsa": 2048,
            "min_key_size_ec": 256,
            "require_key_usage": True,
            "max_chain_depth": 5,
            "allow_self_signed": False,
            "require_icao_country_header": True,
            "allowed_vds_nc_header_prefixes": ["DC0"],
        }),
        "revocation_policy": json.dumps({
            "check_mode": "HARD_FAIL",
            "check_ocsp": True,
            "check_crl": True,
            "check_status_list": False,
            "offline_grace_period_hours": 72,
            "cache_duration_hours": 24,
        }),
        "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
        "time_policy": json.dumps({
            "max_clock_skew_seconds": 300,
            "credential_freshness_hours": 87600,  # 10 years — travel docs are long-lived
            "require_not_before": False,           # VDS-NC does not carry nbf
            "require_expiration": True,
        }),
        "supported_formats": json.dumps(["VDS_NC", "MDOC"]),
        "registry_imports": json.dumps([]),
        "created_at": NOW,
        "updated_at": NOW,
    }


def _mdl_trust_profile() -> dict:
    return {
        "id": MDL_AAMVA_TRUST_PROFILE_ID,
        "organization_id": MARTY_ORG_ID,
        "name": "Mobile Driver's License Verification (AAMVA)",
        "description": (
            "Verification trust profile for ISO 18013-5 mobile driver's "
            "licenses and AAMVA-aligned digital identity cards. Accepts "
            "both mso_mdoc and dc+sd-jwt formats. Trust anchors include "
            "the AAMVA registry and the Marty managed mDL issuer for "
            "development workflows."
        ),
        "status": "active",
        "trust_sources": json.dumps([
            {
                "id": MDL_AAMVA_REGISTRY_ID,
                "name": "AAMVA Digital Identity Trust Registry",
                "source_type": "REGISTRY",
                "registry_url": "https://registry.aamva.org/",
                "description": (
                    "AAMVA digital identity trust registry for mDL "
                    "issuing jurisdiction certificates."
                ),
                "enabled": True,
                "refresh_interval_hours": 24,
                "pinned_certificates": [],
                "registry_namespace": "aamva_mdl",
            },
            {
                "id": MDL_MARTY_ISSUER_ID,
                "name": "Marty Managed mDL Issuer",
                "source_type": "PINNED_ISSUER",
                "issuer_did": "did:web:beta.elevenidllc.com",
                "description": (
                    "Marty controlled mDL issuer key for development, "
                    "demo, and test mDL credentials."
                ),
                "enabled": True,
                "refresh_interval_hours": 24,
                "pinned_certificates": [],
            },
        ]),
        "validation_rules": json.dumps({
            "allowed_algorithms": ["ES256", "ES384", "EdDSA", "ES512"],
            "min_key_size_rsa": 2048,
            "min_key_size_ec": 256,
            "require_key_usage": True,
            "max_chain_depth": 5,
            "allow_self_signed": False,
            "require_mdoc_device_auth": True,  # ISO 18013-5 §9.1.3
        }),
        "revocation_policy": json.dumps({
            "check_mode": "HARD_FAIL",
            "check_ocsp": True,
            "check_crl": True,
            "check_status_list": True,
            "offline_grace_period_hours": 24,
            "cache_duration_hours": 12,
        }),
        "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
        "time_policy": json.dumps({
            "max_clock_skew_seconds": 300,
            "credential_freshness_hours": 43800,  # 5 years — typical DL validity
            "require_not_before": True,
            "require_expiration": True,
        }),
        "supported_formats": json.dumps(["MDOC", "SD_JWT_VC"]),
        "registry_imports": json.dumps([]),
        "created_at": NOW,
        "updated_at": NOW,
    }


# ---------------------------------------------------------------------------
# Trusted issuer row builders
# ---------------------------------------------------------------------------

TRUSTED_ISSUERS: list[dict] = [
    # --- ICAO profile trusted issuers ---
    {
        "id": ICAO_PKD_REGISTRY_ID,
        "trust_profile_id": ICAO_TRAVEL_TRUST_PROFILE_ID,
        "name": "ICAO PKD (master list)",
        "description": (
            "ICAO Public Key Directory CSCA certificates used to verify "
            "VDS-NC and ePassport document signer certificates."
        ),
        "issuer_did": None,
        "issuer_url": "https://pkd.icao.int/",
        "status": "active",
        "credential_template_ids": json.dumps([
            EPASSPORT_TEMPLATE_ID,
            DTC1_TEMPLATE_ID,
            DTC2_TEMPLATE_ID,
            VISA_TEMPLATE_ID,
            ETD_TEMPLATE_ID,
        ]),
        "verification_keys": json.dumps([]),
        "metadata": json.dumps({"registry_type": "icao_pkd", "trust_anchor": "csca"}),
        "created_at": NOW,
        "updated_at": NOW,
    },
    {
        "id": ICAO_MARTY_ISSUER_ID,
        "trust_profile_id": ICAO_TRAVEL_TRUST_PROFILE_ID,
        "name": "Marty Managed ICAO Issuer",
        "description": "Marty controlled ECDSA key for VDS-NC demo issuance.",
        "issuer_did": "did:web:beta.elevenidllc.com",
        "issuer_url": "https://beta.elevenidllc.com",
        "status": "active",
        "credential_template_ids": json.dumps([
            EPASSPORT_TEMPLATE_ID,
            DTC1_TEMPLATE_ID,
            DTC2_TEMPLATE_ID,
            VISA_TEMPLATE_ID,
            ETD_TEMPLATE_ID,
        ]),
        "verification_keys": json.dumps([]),
        "metadata": json.dumps({"managed_by": "marty", "key_purpose": "vdsnc_signing"}),
        "created_at": NOW,
        "updated_at": NOW,
    },
    # --- mDL profile trusted issuers ---
    {
        "id": MDL_AAMVA_REGISTRY_ID,
        "trust_profile_id": MDL_AAMVA_TRUST_PROFILE_ID,
        "name": "AAMVA mDL Registry",
        "description": "AAMVA digital identity trust registry for mDL jurisdiction certificates.",
        "issuer_did": None,
        "issuer_url": "https://registry.aamva.org/",
        "status": "active",
        "credential_template_ids": json.dumps([MDL_TEMPLATE_ID]),
        "verification_keys": json.dumps([]),
        "metadata": json.dumps({"registry_type": "aamva_mdl", "trust_anchor": "jurisdiction_ca"}),
        "created_at": NOW,
        "updated_at": NOW,
    },
    {
        "id": MDL_MARTY_ISSUER_ID,
        "trust_profile_id": MDL_AAMVA_TRUST_PROFILE_ID,
        "name": "Marty Managed mDL Issuer",
        "description": "Marty controlled mDL issuer key for dev / demo mDL credentials.",
        "issuer_did": "did:web:beta.elevenidllc.com",
        "issuer_url": "https://beta.elevenidllc.com",
        "status": "active",
        "credential_template_ids": json.dumps([MDL_TEMPLATE_ID]),
        "verification_keys": json.dumps([]),
        "metadata": json.dumps({"managed_by": "marty", "key_purpose": "mdoc_dsc"}),
        "created_at": NOW,
        "updated_at": NOW,
    },
]


# ---------------------------------------------------------------------------
# Migration helpers
# ---------------------------------------------------------------------------

def _trust_table_exists(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('trust_profile_service.trust_profiles') IS NOT NULL"
            )
        ).scalar()
    )


def _insert_trust_profile(conn, profile: dict) -> None:
    existing = conn.execute(
        sa.text(
            "SELECT id FROM trust_profile_service.trust_profiles WHERE id = :id"
        ),
        {"id": profile["id"]},
    ).fetchone()
    if existing:
        return

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
                CAST(:trust_sources AS jsonb),
                CAST(:validation_rules AS jsonb),
                CAST(:revocation_policy AS jsonb),
                :revocation_profile_id,
                CAST(:time_policy AS jsonb),
                CAST(:supported_formats AS jsonb),
                CAST(:registry_imports AS jsonb),
                :created_at,
                :updated_at
            )
            """
        ),
        profile,
    )


def _trusted_issuer_column_names(conn) -> set[str]:
    rows = conn.execute(
        sa.text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'trust_profile_service'
              AND table_name = 'trusted_issuers'
            """
        )
    )
    return {row[0] for row in rows}


def _build_trusted_issuer_insert(columns: set[str]) -> sa.TextClause:
    insert_columns = [
        "id",
        "trust_profile_id",
        "name",
        "description",
        "issuer_did",
        "issuer_url",
        "status",
        "credential_template_ids",
        "verification_keys",
    ]
    insert_values = [
        ":id",
        ":trust_profile_id",
        ":name",
        ":description",
        ":issuer_did",
        ":issuer_url",
        ":status",
        "CAST(:credential_template_ids AS jsonb)",
        "CAST(:verification_keys AS jsonb)",
    ]

    if "metadata" in columns:
        insert_columns.append("metadata")
        insert_values.append("CAST(:metadata AS jsonb)")

    for optional_column in ("valid_from", "valid_until"):
        if optional_column in columns:
            insert_columns.append(optional_column)
            insert_values.append(f":{optional_column}")

    insert_columns.extend(["created_at", "updated_at"])
    insert_values.extend([":created_at", ":updated_at"])

    return sa.text(
        f"""
        INSERT INTO trust_profile_service.trusted_issuers (
            {', '.join(insert_columns)}
        ) VALUES (
            {', '.join(insert_values)}
        )
        """
    )


def _build_trusted_issuer_params(issuer: dict, columns: set[str]) -> dict:
    params = dict(issuer)
    if params.get("issuer_did") is None and "issuer_did" in columns:
        params["issuer_did"] = params.get("issuer_url") or f"urn:trust-source:{issuer['id']}"
    if "valid_from" in columns and "valid_from" not in params:
        params["valid_from"] = None
    if "valid_until" in columns and "valid_until" not in params:
        params["valid_until"] = None
    return params


def upgrade() -> None:
    conn = op.get_bind()

    if not _trust_table_exists(conn):
        return

    _insert_trust_profile(conn, _icao_trust_profile())
    _insert_trust_profile(conn, _mdl_trust_profile())

    # Seed trusted issuers
    issuer_table_exists = bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('trust_profile_service.trusted_issuers') IS NOT NULL"
            )
        ).scalar()
    )
    if not issuer_table_exists:
        return

    trusted_issuer_columns = _trusted_issuer_column_names(conn)
    trusted_issuer_insert = _build_trusted_issuer_insert(trusted_issuer_columns)

    for issuer in TRUSTED_ISSUERS:
        existing = conn.execute(
            sa.text(
                "SELECT id FROM trust_profile_service.trusted_issuers WHERE id = :id"
            ),
            {"id": issuer["id"]},
        ).fetchone()
        if existing:
            continue
        conn.execute(
            trusted_issuer_insert,
            _build_trusted_issuer_params(issuer, trusted_issuer_columns),
        )


def downgrade() -> None:
    conn = op.get_bind()

    if not _trust_table_exists(conn):
        return

    issuer_ids = [r["id"] for r in TRUSTED_ISSUERS]
    for issuer_id in issuer_ids:
        conn.execute(
            sa.text(
                "DELETE FROM trust_profile_service.trusted_issuers WHERE id = :id"
            ),
            {"id": issuer_id},
        )

    for profile_id in [ICAO_TRAVEL_TRUST_PROFILE_ID, MDL_AAMVA_TRUST_PROFILE_ID]:
        conn.execute(
            sa.text(
                "DELETE FROM trust_profile_service.trust_profiles WHERE id = :id"
            ),
            {"id": profile_id},
        )
