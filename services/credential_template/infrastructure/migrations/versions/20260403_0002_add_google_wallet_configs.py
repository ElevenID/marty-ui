"""Add Google Wallet (CredentialManager) wallet_config entries to demo templates.

Adds a ``wr-google-001`` wallet_config entry to each demo credential template
that already has wallet_configs (Open Badge, Access Badge, Member Credential).
The new entry uses the ``credential-manager`` format variant which routes
offers through the ``/org/{id}/credential-manager`` metadata endpoint — the
only document that emits pure ``dc+sd-jwt`` entries compatible with Google's
Android CredentialManager SDK.

Also seeds the ``wr-google-001`` wallet registry row.

Revision ID: 20260403_0002
Revises: 20260403_0001
Create Date: 2026-04-03 01:00:00.000000+00:00
"""

from __future__ import annotations

import json
import uuid

from alembic import op
import sqlalchemy as sa


revision = "20260403_0002"
down_revision = "20260403_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
NOW = "2026-04-03T01:00:00+00:00"

# Template IDs that should gain a Google Wallet config.
# These must already have a wallet_configs JSONB column populated.
TEMPLATES_TO_UPDATE = {
    "50000000-0000-0000-0000-000000000040": "open_badge",       # Open Badge
    "50000000-0000-0000-0000-000000000050": "access_badge",     # Access Badge
}


def _google_wallet_config(credential_type: str) -> dict:
    """Return a single wallet_config dict for Google Wallet."""
    return {
        "id": f"marty-{credential_type[:8]}-wc-google",
        "wallet_id": "wr-google-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "credential-manager",
        "credential_configuration_id": f"{credential_type}#credential-manager",
        "display_name": "Google Wallet",
        "issuer_url_suffix": "/credential-manager",
        "custom_metadata": {},
    }


def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. Seed wallet registry row ──────────────────────────────────
    has_registry = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = :schema AND table_name = 'wallet_registry' LIMIT 1"
        ),
        {"schema": SCHEMA},
    ).scalar()

    if has_registry:
        exists = conn.execute(
            sa.text(f"SELECT 1 FROM {SCHEMA}.wallet_registry WHERE id = :id"),
            {"id": "wr-google-001"},
        ).scalar()
        if not exists:
            conn.execute(
                sa.text(
                    f"INSERT INTO {SCHEMA}.wallet_registry "
                    "(id, name, description, wallet_apps, specifications, "
                    " logo_url, supported_formats, supported_protocols, "
                    " platforms, deep_link_template, docs_url, "
                    " supports_qr, supports_deeplink, is_active, "
                    " created_at, updated_at) "
                    "VALUES "
                    "(:id, :name, :desc, :apps, :specs, "
                    " :logo, :fmts, :protos, "
                    " :plats, :dlt, :docs, "
                    " true, true, true, "
                    " :now, :now)"
                ),
                {
                    "id": "wr-google-001",
                    "name": "Google Wallet",
                    "desc": "Google Wallet via Android CredentialManager API.",
                    "apps": json.dumps(["Google Wallet"]),
                    "specs": json.dumps(["OID4VCI", "CredentialManager"]),
                    "logo": "https://wallet.google/favicon.ico",
                    "fmts": json.dumps(["dc+sd-jwt"]),
                    "protos": json.dumps(["CREDENTIAL_MANAGER"]),
                    "plats": json.dumps(["android"]),
                    "dlt": "openid-credential-offer://?credential_offer={offer}",
                    "docs": "https://developer.android.com/identity/digital-credentials",
                    "now": NOW,
                },
            )

    # ── 2. Append Google Wallet config to each demo template ─────────
    has_wallet_col = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = :schema AND table_name = 'credential_templates' "
            "  AND column_name = 'wallet_configs' LIMIT 1"
        ),
        {"schema": SCHEMA},
    ).scalar()

    if not has_wallet_col:
        return

    for template_id, ctype in TEMPLATES_TO_UPDATE.items():
        row = conn.execute(
            sa.text(
                f"SELECT wallet_configs FROM {SCHEMA}.credential_templates WHERE id = :id"
            ),
            {"id": template_id},
        ).fetchone()

        if row is None:
            continue

        raw = row[0]
        existing = json.loads(raw) if isinstance(raw, str) else (raw or [])

        # Skip if already present
        if any(wc.get("wallet_id") == "wr-google-001" for wc in existing):
            continue

        existing.append(_google_wallet_config(ctype))
        conn.execute(
            sa.text(
                f"UPDATE {SCHEMA}.credential_templates "
                "SET wallet_configs = CAST(:wc AS jsonb), updated_at = :now "
                "WHERE id = :id"
            ),
            {
                "id": template_id,
                "wc": json.dumps(existing),
                "now": NOW,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()

    # Remove Google Wallet configs from templates
    has_wallet_col = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = :schema AND table_name = 'credential_templates' "
            "  AND column_name = 'wallet_configs' LIMIT 1"
        ),
        {"schema": SCHEMA},
    ).scalar()

    if has_wallet_col:
        for template_id, _ in TEMPLATES_TO_UPDATE.items():
            row = conn.execute(
                sa.text(
                    f"SELECT wallet_configs FROM {SCHEMA}.credential_templates WHERE id = :id"
                ),
                {"id": template_id},
            ).fetchone()
            if row and row[0]:
                raw = row[0]
                configs = json.loads(raw) if isinstance(raw, str) else raw
                configs = [wc for wc in configs if wc.get("wallet_id") != "wr-google-001"]
                conn.execute(
                    sa.text(
                        f"UPDATE {SCHEMA}.credential_templates "
                        "SET wallet_configs = CAST(:wc AS jsonb) "
                        "WHERE id = :id"
                    ),
                    {"id": template_id, "wc": json.dumps(configs)},
                )

    # Remove wallet registry row
    has_registry = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = :schema AND table_name = 'wallet_registry' LIMIT 1"
        ),
        {"schema": SCHEMA},
    ).scalar()
    if has_registry:
        conn.execute(
            sa.text(f"DELETE FROM {SCHEMA}.wallet_registry WHERE id = :id"),
            {"id": "wr-google-001"},
        )
