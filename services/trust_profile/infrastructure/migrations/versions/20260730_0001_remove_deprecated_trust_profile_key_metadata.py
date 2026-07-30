"""Remove deprecated Organization Trust Profile custody metadata.

Revision ID: trust_kms_cleanup_001
Revises: marty_trust_seed_005
Create Date: 2026-07-30 00:01:00.000000+00:00

Organization Trust Profiles describe verification trust. Signing custody is
resolved from an issuer DID through an issuer profile and must not be selected
or disclosed through this public resource.
"""

from __future__ import annotations

import json
from typing import Any

from alembic import op
import sqlalchemy as sa


revision = "trust_kms_cleanup_001"
down_revision = "marty_trust_seed_005"
branch_labels = None
depends_on = None


_DEPRECATED_CUSTODY_FIELDS = {
    "key_binding",
    "key_management",
    "key_reference",
    "kms_arn",
    "kms_region",
    "managed_key_id",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitize(nested_value)
            for key, nested_value in value.items()
            if str(key).lower() not in _DEPRECATED_CUSTODY_FIELDS
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _has_table(conn, qualified_name: str) -> bool:
    return bool(
        conn.execute(sa.text(f"SELECT to_regclass('{qualified_name}') IS NOT NULL")).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    table = "trust_profile_service.organization_trust_profiles"
    if not _has_table(conn, table):
        return

    rows = list(
        conn.execute(
            sa.text(
                "SELECT id, metadata "
                "FROM trust_profile_service.organization_trust_profiles "
                "WHERE metadata IS NOT NULL"
            )
        ).mappings()
    )
    for row in rows:
        metadata = row["metadata"]
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        sanitized = _sanitize(metadata)
        if sanitized != metadata:
            conn.execute(
                sa.text(
                    "UPDATE trust_profile_service.organization_trust_profiles "
                    "SET metadata = CAST(:metadata AS json), updated_at = CURRENT_TIMESTAMP "
                    "WHERE id = :profile_id"
                ),
                {
                    "metadata": json.dumps(sanitized, separators=(",", ":")),
                    "profile_id": row["id"],
                },
            )


def downgrade() -> None:
    # Deprecated custody selectors may contain secrets and cannot be recreated.
    pass
