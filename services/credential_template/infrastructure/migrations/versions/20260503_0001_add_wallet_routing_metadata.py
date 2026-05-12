"""Add wallet-specific routing metadata to wallet registry.

Persists same-device transport metadata used by the Marty UI to choose
Digital Credentials API, wallet-specific nested links, install fallbacks,
and standard OID4VC links without changing the inner protocol payload.

Revision ID: 20260503_0001
Revises: 20260417_0001
Create Date: 2026-05-03 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260503_0001"
down_revision = "20260417_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = f"{SCHEMA}.wallet_registry"


def _wallet_registry_exists(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :schema AND table_name = 'wallet_registry' LIMIT 1"
            ),
            {"schema": SCHEMA},
        ).scalar()
    )


def _has_column(conn, column_name: str) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = 'wallet_registry' "
                "AND column_name = :column_name LIMIT 1"
            ),
            {"schema": SCHEMA, "column_name": column_name},
        ).scalar()
    )


def _add_column_if_missing(conn, column: sa.Column) -> None:
    if not _has_column(conn, column.name):
        op.add_column("wallet_registry", column, schema=SCHEMA)


def upgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    _add_column_if_missing(conn, sa.Column("routing_templates", sa.JSON(), nullable=False, server_default="{}"))
    _add_column_if_missing(conn, sa.Column("install_urls", sa.JSON(), nullable=False, server_default="{}"))
    _add_column_if_missing(conn, sa.Column("ios_scheme", sa.String(128), nullable=True))
    _add_column_if_missing(conn, sa.Column("universal_link_template", sa.Text(), nullable=True))
    _add_column_if_missing(conn, sa.Column("android_package", sa.String(255), nullable=True))
    _add_column_if_missing(conn, sa.Column("supports_digital_credentials", sa.Boolean(), nullable=False, server_default="false"))
    _add_column_if_missing(conn, sa.Column("supports_haip", sa.Boolean(), nullable=False, server_default="false"))

    seed_updates = {
        "wr-spruce-001": {
            "routing_templates": {
                "generic": "openid-credential-offer://?credential_offer_uri={offer_uri_encoded}",
                "ios": "openid-credential-offer://?credential_offer_uri={offer_uri_encoded}",
                "android": "intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end",
            },
            "install_urls": {
                "ios": "https://apps.apple.com/search?term=SpruceKit",
                "android": "https://play.google.com/store/search?q=SpruceKit&c=apps",
            },
        },
        "wr-marty-001": {
            "routing_templates": {
                "generic": "marty-authenticator://open?inner={inner_uri_encoded}",
                "ios": "marty-authenticator://open?inner={inner_uri_encoded}",
                "android": "marty-authenticator://open?inner={inner_uri_encoded}",
            },
            "ios_scheme": "marty-authenticator",
        },
        "wr-google-001": {
            "routing_templates": {
                "generic": "openid-credential-offer://?credential_offer={offer_encoded}",
                "android": "openid-credential-offer://?credential_offer={offer_encoded}",
            },
            "android_package": "com.google.android.gms",
            "supports_digital_credentials": True,
        },
        "wr-apple-001": {
            "routing_templates": {
                "generic": "openid-credential-offer://?credential_offer={offer_encoded}",
                "ios": "openid-credential-offer://?credential_offer={offer_encoded}",
            },
            "supports_digital_credentials": True,
        },
    }

    for wallet_id, values in seed_updates.items():
        conn.execute(
            sa.text(
                f"""
                UPDATE {TABLE}
                   SET routing_templates = CAST(:routing_templates AS jsonb),
                       install_urls = CAST(:install_urls AS jsonb),
                       ios_scheme = COALESCE(:ios_scheme, ios_scheme),
                       android_package = COALESCE(:android_package, android_package),
                       supports_digital_credentials = :supports_digital_credentials,
                       updated_at = NOW()
                 WHERE id = :wallet_id
                """
            ),
            {
                "wallet_id": wallet_id,
                "routing_templates": json.dumps(values.get("routing_templates", {})),
                "install_urls": json.dumps(values.get("install_urls", {})),
                "ios_scheme": values.get("ios_scheme"),
                "android_package": values.get("android_package"),
                "supports_digital_credentials": bool(values.get("supports_digital_credentials", False)),
            },
        )


def downgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    for column_name in (
        "supports_haip",
        "supports_digital_credentials",
        "android_package",
        "universal_link_template",
        "ios_scheme",
        "install_urls",
        "routing_templates",
    ):
        if _has_column(conn, column_name):
            op.drop_column("wallet_registry", column_name, schema=SCHEMA)
