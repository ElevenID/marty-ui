"""Protect registered webhook signing secrets with OpenBao Transit.

Revision ID: 20260808_0002
Revises: 20260808_0001
Create Date: 2026-08-08 23:40:00+00:00

This migration intentionally contains its own immutable envelope encoder.  It
never has a mixed-mode success state: every legacy plaintext row is wrapped
before the plaintext column is removed, or the transaction fails.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from alembic import context, op
import sqlalchemy as sa


revision = "20260808_0002"
down_revision = "20260808_0001"
branch_labels = None
depends_on = None

SCHEMA = "notification_service"
TABLE = "webhook_endpoints"
KEY_ID = "notification-webhook-envelope-marty-aes256"
ENVELOPE_SCHEMA = "marty.notification-webhook-secret/v1"
ENVELOPE_PURPOSE = "webhook_hmac_signing"


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name, "").strip()
    if direct:
        return direct
    file_name = os.environ.get(f"{name}_FILE", "").strip()
    if not file_name:
        return ""
    try:
        return Path(file_name).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("OpenBao service token file is unavailable") from exc


def _encode_bound_secret(*, organization_id: str, webhook_id: str, secret: str) -> str:
    if not organization_id or not webhook_id or not 32 <= len(secret) <= 128:
        raise RuntimeError("legacy webhook signing secret is invalid")
    document = {
        "schema": ENVELOPE_SCHEMA,
        "organization_id": organization_id,
        "webhook_id": webhook_id,
        "purpose": ENVELOPE_PURPOSE,
        "secret": secret,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(canonical).decode("ascii")


def _wrap_legacy_secret(
    *, organization_id: str, webhook_id: str, secret: str
) -> str:
    import httpx

    bao_addr = os.environ.get("BAO_ADDR", "").strip().rstrip("/")
    bao_token = _read_secret_value("OPENBAO_SERVICE_TOKEN") or _read_secret_value(
        "BAO_TOKEN"
    )
    if not bao_addr or not bao_token:
        raise RuntimeError("OpenBao webhook secret protection is not configured")
    plaintext = _encode_bound_secret(
        organization_id=organization_id, webhook_id=webhook_id, secret=secret
    )
    try:
        response = httpx.post(
            f"{bao_addr}/v1/transit/encrypt/{KEY_ID}",
            headers={"X-Vault-Token": bao_token},
            json={"plaintext": plaintext},
            timeout=8.0,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError("OpenBao could not protect a legacy webhook secret") from exc
    data = payload.get("data")
    ciphertext = data.get("ciphertext") if isinstance(data, dict) else None
    if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
        raise RuntimeError("OpenBao did not return a webhook secret ciphertext")
    return ciphertext


def _add_envelope_columns() -> None:
    op.add_column(
        TABLE,
        sa.Column("secret_envelope", sa.Text(), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        TABLE,
        sa.Column("secret_hint", sa.String(8), nullable=True),
        schema=SCHEMA,
    )


def _finish_plaintext_removal() -> None:
    op.alter_column(TABLE, "secret_envelope", nullable=False, schema=SCHEMA)
    op.alter_column(TABLE, "secret_hint", nullable=False, schema=SCHEMA)
    op.create_check_constraint(
        "ck_webhook_endpoints_secret_envelope",
        TABLE,
        "secret_envelope LIKE 'vault:%'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_webhook_endpoints_secret_hint",
        TABLE,
        "char_length(secret_hint) = 4",
        schema=SCHEMA,
    )
    op.drop_column(TABLE, "secret", schema=SCHEMA)


def upgrade() -> None:
    _add_envelope_columns()
    if context.is_offline_mode():
        # Offline SQL cannot call Transit.  It remains safe for clean installs,
        # and aborts before plaintext removal if legacy rows exist.
        op.execute(
            sa.text(
                "DO $$ BEGIN "
                "IF EXISTS (SELECT 1 FROM notification_service.webhook_endpoints) "
                "THEN RAISE EXCEPTION "
                "'online migration required to protect webhook secrets'; "
                "END IF; END $$"
            )
        )
        _finish_plaintext_removal()
        return

    bind = op.get_bind()
    legacy = sa.table(
        TABLE,
        sa.column("id", sa.String()),
        sa.column("organization_id", sa.String()),
        sa.column("secret", sa.String()),
        sa.column("secret_envelope", sa.Text()),
        sa.column("secret_hint", sa.String()),
        schema=SCHEMA,
    )
    rows = bind.execute(
        sa.select(legacy.c.id, legacy.c.organization_id, legacy.c.secret)
    ).mappings()
    for row in rows:
        secret = str(row["secret"] or "")
        ciphertext = _wrap_legacy_secret(
            organization_id=str(row["organization_id"] or ""),
            webhook_id=str(row["id"] or ""),
            secret=secret,
        )
        bind.execute(
            legacy.update()
            .where(legacy.c.id == row["id"])
            .values(secret_envelope=ciphertext, secret_hint=secret[:4])
        )
    _finish_plaintext_removal()


def downgrade() -> None:
    raise RuntimeError("plaintext webhook signing secret storage cannot be restored")
