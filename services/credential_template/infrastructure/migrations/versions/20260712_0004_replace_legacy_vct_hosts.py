"""Replace active placeholder VCT hosts with the configured public origin.

Revision ID: 20260712_0004
Revises: 20260712_0003
Create Date: 2026-07-12 20:35:00.000000+00:00
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from alembic import op
import sqlalchemy as sa


revision = "20260712_0004"
down_revision = "20260712_0003"
branch_labels = None
depends_on = None

LEGACY_PREFIX = "https://marty.example/credentials/"


def _public_api_url() -> str:
    value = str(
        os.environ.get("PUBLIC_API_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
        or ""
    ).strip().rstrip("/")
    parsed = urlparse(value)
    profile = str(os.environ.get("MARTY_MIGRATION_PROFILE") or "dev").lower()
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError("PUBLIC_API_URL must be an absolute public URL before legacy VCT migration")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise RuntimeError("PUBLIC_API_URL must be a public origin without a path, query, or fragment")
    if parsed.hostname in {"gateway", "marty.example"}:
        raise RuntimeError("PUBLIC_API_URL cannot use an internal or placeholder host")
    if profile in {"beta", "prod", "production"} and parsed.scheme != "https":
        raise RuntimeError("PUBLIC_API_URL must use HTTPS for beta and production migrations")
    return value


def upgrade() -> None:
    conn = op.get_bind()
    active_legacy = int(conn.execute(sa.text(
        """
        SELECT count(*)
        FROM credential_template_service.credential_templates
        WHERE lower(status) = 'active' AND vct LIKE :legacy_pattern
        """
    ), {"legacy_pattern": f"{LEGACY_PREFIX}%"}).scalar() or 0)
    if active_legacy == 0:
        return

    public_api_url = _public_api_url()
    conn.execute(sa.text(
        """
        UPDATE credential_template_service.credential_templates
        SET vct = :public_prefix || substring(vct from :suffix_start),
            version = coalesce(version, 0) + 1,
            updated_at = now()
        WHERE lower(status) = 'active' AND vct LIKE :legacy_pattern
        """
    ), {
        "public_prefix": f"{public_api_url}/credentials/",
        "suffix_start": len(LEGACY_PREFIX) + 1,
        "legacy_pattern": f"{LEGACY_PREFIX}%",
    })
    remaining = int(conn.execute(sa.text(
        """
        SELECT count(*)
        FROM credential_template_service.credential_templates
        WHERE lower(status) = 'active' AND vct LIKE :legacy_pattern
        """
    ), {"legacy_pattern": f"{LEGACY_PREFIX}%"}).scalar() or 0)
    if remaining:
        raise RuntimeError(f"Legacy VCT migration left {remaining} active templates unresolved")


def downgrade() -> None:
    raise RuntimeError("The MIP 0.3 public VCT migration is one-way.")
