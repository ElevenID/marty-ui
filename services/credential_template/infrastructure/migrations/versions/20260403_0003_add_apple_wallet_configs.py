"""Add Apple Wallet wallet_config entries to demo templates.

Adds a ``wr-apple-001`` wallet_config entry to each demo credential template
that already has wallet_configs (Open Badge, Access Badge).  The new entry
uses the ``apple-wallet`` format variant which routes offers through the
``/org/{id}/apple-wallet`` metadata endpoint — the only document that emits
pure ``mso_mdoc`` entries compatible with Apple Wallet's ISO 18013-5 path.

Also seeds the ``wr-apple-001`` wallet registry row.

Revision ID: 20260403_0003
Revises: 20260403_0002
Create Date: 2026-04-03 02:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260403_0003"
down_revision = "20260403_0002"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
NOW = "2026-04-03T02:00:00+00:00"

# Template IDs that should gain an Apple Wallet config.
TEMPLATES_TO_UPDATE = {
    "50000000-0000-0000-0000-000000000040": "open_badge",       # Open Badge
    "50000000-0000-0000-0000-000000000050": "access_badge",     # Access Badge
}


def _apple_wallet_config(credential_type: str) -> dict:
    """Return a single wallet_config dict for Apple Wallet."""
    return {
        "id": f"marty-{credential_type[:8]}-wc-apple",
        "wallet_id": "wr-apple-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "apple-wallet",
        "credential_configuration_id": f"{credential_type}#apple-wallet",
        "display_name": "Apple Wallet",
        "issuer_url_suffix": "/apple-wallet",
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
            {"id": "wr-apple-001"},
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
                    "id": "wr-apple-001",
                    "name": "Apple Wallet",
                    "desc": "Apple Wallet via Verify with Wallet / ISO 18013-5 issuance.",
                    "apps": json.dumps(["Apple Wallet"]),
                    "specs": json.dumps(["OID4VCI", "ISO 18013-5"]),
                    "logo": "https://www.apple.com/favicon.ico",
                    "fmts": json.dumps(["mso_mdoc"]),
                    "protos": json.dumps(["APPLE_WALLET"]),
                    "plats": json.dumps(["ios"]),
                    "dlt": "openid-credential-offer://?credential_offer={offer}",
                    "docs": "https://developer.apple.com/documentation/passkit/wallet",
                    "now": NOW,
                },
            )

    # ── 2. Append Apple Wallet config to each demo template ──────────
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
        if any(wc.get("wallet_id") == "wr-apple-001" for wc in existing):
            continue

        existing.append(_apple_wallet_config(ctype))
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

    # Remove Apple Wallet configs from templates
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
                configs = [wc for wc in configs if wc.get("wallet_id") != "wr-apple-001"]
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
            {"id": "wr-apple-001"},
        )
