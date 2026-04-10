"""Create wallet_registry table and seed initial wallet profiles.

Moves the wallet registry from the service's in-memory defaults into a
persistent PostgreSQL table so wallets survive restarts and can be managed
via the /v1/wallet-registry API.

Seeded entries
--------------
  wr-spruce-001   SpruceKit (SpruceID iOS/Android — spruce-vc+sd-jwt)
  wr-marty-001    Marty Authenticator (SpruceID-based — spruce-vc+sd-jwt)
  wr-default      Any OID4VCI Wallet (generic sd_jwt_vc / jwt_vc_json)
  wr-lissi-001    LISSI Wallet
  wr-waltid-001   walt.id Wallet
  wr-sphereon-001 Sphereon Wallet
  wr-dc4eu-001    DC4EU Wallet

Revision ID: 20260308_0002
Revises: 20260308_0001
Create Date: 2026-03-08 00:00:00.000000+00:00
"""

from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260308_0002"
down_revision = "20260308_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = f"{SCHEMA}.wallet_registry"

NOW = datetime.now(timezone.utc)

SEED_WALLETS = [
    {
        "id": "wr-spruce-001",
        "name": "SpruceKit",
        "logo_url": "https://spruceid.com/favicon.ico",
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["spruce-vc+sd-jwt"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": "https://spruceid.com/products/sprucekit",
        "is_active": True,
    },
    {
        "id": "wr-marty-001",
        "name": "Marty Authenticator",
        "logo_url": None,
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["spruce-vc+sd-jwt"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": None,
        "is_active": True,
    },
    {
        "id": "wr-default",
        "name": "Any OID4VCI Wallet",
        "logo_url": None,
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["sd_jwt_vc", "jwt_vc_json"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android", "web"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": None,
        "is_active": True,
    },
    {
        "id": "wr-lissi-001",
        "name": "LISSI Wallet",
        "logo_url": "https://lissi.id/favicon.ico",
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["sd_jwt_vc", "jwt_vc_json"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": "https://lissi.id",
        "is_active": True,
    },
    {
        "id": "wr-waltid-001",
        "name": "walt.id Wallet",
        "logo_url": "https://walt.id/favicon.ico",
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["sd_jwt_vc", "jwt_vc_json", "mdoc"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android", "web"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": "https://docs.walt.id",
        "is_active": True,
    },
    {
        "id": "wr-sphereon-001",
        "name": "Sphereon Wallet",
        "logo_url": "https://sphereon.com/favicon.ico",
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["sd_jwt_vc", "jwt_vc_json"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": "https://sphereon.com",
        "is_active": True,
    },
    {
        "id": "wr-dc4eu-001",
        "name": "DC4EU Wallet",
        "logo_url": None,
        "deep_link_template": "openid-credential-offer://?credential_offer={OFFER}",
        "supported_formats": ["sd_jwt_vc", "mdoc"],
        "supported_protocols": ["oid4vci"],
        "platforms": ["ios", "android"],
        "supports_qr": True,
        "supports_deeplink": True,
        "docs_url": None,
        "is_active": True,
    },
]


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


def upgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        op.create_table(
            "wallet_registry",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("logo_url", sa.Text, nullable=True),
            sa.Column(
                "deep_link_template",
                sa.Text,
                nullable=False,
                server_default="openid-credential-offer://?credential_offer={OFFER}",
            ),
            sa.Column("supported_formats", sa.JSON, nullable=False, server_default="[]"),
            sa.Column("supported_protocols", sa.JSON, nullable=False, server_default='["oid4vci"]'),
            sa.Column("platforms", sa.JSON, nullable=False, server_default="[]"),
            sa.Column("supports_qr", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("supports_deeplink", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("docs_url", sa.Text, nullable=True),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            schema=SCHEMA,
        )

    import json
    for wallet in SEED_WALLETS:
        conn.execute(
            sa.text(
                f"""
                INSERT INTO {TABLE}
                    (id, name, logo_url, deep_link_template,
                     supported_formats, supported_protocols, platforms,
                     supports_qr, supports_deeplink, docs_url, is_active,
                     created_at, updated_at)
                VALUES
                    (:id, :name, :logo_url, :deep_link_template,
                     CAST(:supported_formats AS jsonb),
                     CAST(:supported_protocols AS jsonb),
                     CAST(:platforms AS jsonb),
                     :supports_qr, :supports_deeplink, :docs_url, :is_active,
                     :created_at, :updated_at)
                ON CONFLICT (id) DO NOTHING
                """
            ),
            {
                "id": wallet["id"],
                "name": wallet["name"],
                "logo_url": wallet["logo_url"],
                "deep_link_template": wallet["deep_link_template"],
                "supported_formats": json.dumps(wallet["supported_formats"]),
                "supported_protocols": json.dumps(wallet["supported_protocols"]),
                "platforms": json.dumps(wallet["platforms"]),
                "supports_qr": wallet["supports_qr"],
                "supports_deeplink": wallet["supports_deeplink"],
                "docs_url": wallet["docs_url"],
                "is_active": wallet["is_active"],
                "created_at": NOW,
                "updated_at": NOW,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _wallet_registry_exists(conn):
        op.drop_table("wallet_registry", schema=SCHEMA)
