"""Add credential-template artifact pipeline fields and Marty backfill.

Revision ID: 20260607_0001
Revises: 20260520_0001
Create Date: 2026-06-07 00:00:00.000000+00:00

The UI and gateway contracts expect Credential Templates to carry profile
references plus a concrete issuer artifact path (managed signing key,
certificate chain, or dev auto-generation). The HTTP model already had these
fields, but the credential-template database/repository pipeline did not.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "20260607_0001"
down_revision = "20260520_0001"
branch_labels = None
depends_on = None


SCHEMA = "credential_template_service"
TABLE = "credential_templates"
MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")

MARTY_LOGIN_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
MARTY_TRAVEL_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000002"
MARTY_MDOC_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000003"
MARTY_REVOCATION_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_VC_ISSUER_PROFILE_ID = "ip-marty-vc-jwt-issuer"
MARTY_MDOC_ISSUER_PROFILE_ID = "ip-marty-mdoc-dsc"
MARTY_VDSNC_ISSUER_PROFILE_ID = "ip-marty-vdsnc-issuer"

MANAGED_OPENBAO_SERVICE_ID = "managed-openbao-transit"
VC_ISSUER_KEY_ID = "cred-issuer-marty-es256"
DOCUMENT_SIGNER_KEY_ID = "cred-dsc-marty-primary"


def _public_hostname() -> str:
    public_domain = (os.environ.get("PUBLIC_DOMAIN") or "").strip()
    if public_domain:
        return public_domain

    for env_name in ("PUBLIC_API_URL", "ISSUER_BASE_URL", "UI_BASE_URL"):
        value = (os.environ.get(env_name) or "").strip()
        if value:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            if parsed.hostname:
                return parsed.hostname

    return "beta.elevenidllc.com"


def _marty_issuer_did() -> str:
    # The current Marty DID publication route is did:web:{host}:orgs:marty.
    return f"did:web:{_public_hostname()}:orgs:marty"


def _column_exists(conn: sa.Connection, column_name: str) -> bool:
    return bool(
        conn.execute(
            sa.text(
                """
                SELECT EXISTS (
                    SELECT 1
                      FROM information_schema.columns
                     WHERE table_schema = :schema
                       AND table_name = :table
                       AND column_name = :column_name
                )
                """
            ),
            {"schema": SCHEMA, "table": TABLE, "column_name": column_name},
        ).scalar()
    )


def _add_column_if_missing(conn: sa.Connection, column: sa.Column) -> None:
    if not _column_exists(conn, column.name):
        op.add_column(TABLE, column, schema=SCHEMA)


def _remote_signing_config(key_id: str, key_purpose: str) -> str:
    return json.dumps(
        {
            "provider": "openbao",
            "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
            "signing_key_reference": key_id,
            "verification_method_id": f"{_marty_issuer_did()}#{key_id}",
            "key_purpose": key_purpose,
        },
        separators=(",", ":"),
    )


def upgrade() -> None:
    conn = op.get_bind()
    _add_column_if_missing(conn, sa.Column("application_template_id", sa.String(36), nullable=True))
    _add_column_if_missing(conn, sa.Column("trust_profile_id", sa.String(36), nullable=True))
    _add_column_if_missing(conn, sa.Column("revocation_profile_id", sa.String(36), nullable=True))
    _add_column_if_missing(conn, sa.Column("issuer_profile_id", sa.String(128), nullable=True))
    _add_column_if_missing(conn, sa.Column("issuer_certificate_chain_pem", sa.Text(), nullable=True))
    _add_column_if_missing(conn, sa.Column("issuer_did", sa.Text(), nullable=True))
    _add_column_if_missing(
        conn,
        sa.Column(
            "auto_generate_artifacts",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    vc_config = _remote_signing_config(VC_ISSUER_KEY_ID, "vc_jwt_issuer")
    document_config = _remote_signing_config(DOCUMENT_SIGNER_KEY_ID, "document_signing")

    conn.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.{TABLE}
               SET trust_profile_id = COALESCE(
                       trust_profile_id,
                       CASE
                                                 WHEN credential_payload_format = 'mso_mdoc' THEN :mdoc_trust_profile_id
                                                 WHEN credential_payload_format = 'vds_nc' THEN :travel_trust_profile_id
                         ELSE :login_trust_profile_id
                       END
                   ),
                   revocation_profile_id = COALESCE(revocation_profile_id, :revocation_profile_id),
                                     issuer_profile_id = COALESCE(
                                             issuer_profile_id,
                                             CASE
                                                 WHEN credential_payload_format = 'mso_mdoc' THEN :mdoc_issuer_profile_id
                                                 WHEN credential_payload_format = 'vds_nc' THEN :vdsnc_issuer_profile_id
                                                 ELSE :vc_issuer_profile_id
                                             END
                                     ),
                   key_access_mode = COALESCE(key_access_mode, 'REMOTE_SIGNING'),
                   issuer_key_id = COALESCE(
                       issuer_key_id,
                       CASE
                                                 WHEN credential_payload_format IN ('mso_mdoc', 'vds_nc') THEN :document_signer_key_id
                         ELSE :vc_issuer_key_id
                       END
                   ),
                   issuer_algorithm = COALESCE(issuer_algorithm, 'ES256'),
                   remote_signing_config = COALESCE(
                       remote_signing_config,
                       CASE
                                                 WHEN credential_payload_format IN ('mso_mdoc', 'vds_nc') THEN CAST(:document_config AS json)
                         ELSE CAST(:vc_config AS json)
                       END
                   ),
                   updated_at = NOW()
             WHERE organization_id = :organization_id
               AND status <> 'archived'
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "login_trust_profile_id": MARTY_LOGIN_TRUST_PROFILE_ID,
            "travel_trust_profile_id": MARTY_TRAVEL_TRUST_PROFILE_ID,
            "mdoc_trust_profile_id": MARTY_MDOC_TRUST_PROFILE_ID,
            "revocation_profile_id": MARTY_REVOCATION_PROFILE_ID,
            "vc_issuer_profile_id": MARTY_VC_ISSUER_PROFILE_ID,
            "mdoc_issuer_profile_id": MARTY_MDOC_ISSUER_PROFILE_ID,
            "vdsnc_issuer_profile_id": MARTY_VDSNC_ISSUER_PROFILE_ID,
            "vc_issuer_key_id": VC_ISSUER_KEY_ID,
            "document_signer_key_id": DOCUMENT_SIGNER_KEY_ID,
            "vc_config": vc_config,
            "document_config": document_config,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    for column_name in (
        "auto_generate_artifacts",
        "issuer_did",
        "issuer_certificate_chain_pem",
        "issuer_profile_id",
        "revocation_profile_id",
        "trust_profile_id",
        "application_template_id",
    ):
        if _column_exists(conn, column_name):
            op.drop_column(TABLE, column_name, schema=SCHEMA)