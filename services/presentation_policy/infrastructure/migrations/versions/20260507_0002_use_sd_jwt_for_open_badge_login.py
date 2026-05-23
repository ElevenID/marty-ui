"""Use SD-JWT primitives for Marty badge login policy.

Revision ID: 20260507_0002
Revises: 20260507_0001
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260507_0002"
down_revision = "20260507_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"
BADGE_NAME = "Marty Verified Member Badge"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('presentation_policy_service.presentation_policies') IS NOT NULL")
        ).scalar()
    )


def _as_json(value, default):
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    row = conn.execute(
        sa.text(
            """
            SELECT display_metadata, credential_requirements
              FROM presentation_policy_service.presentation_policies
             WHERE id = :policy_id
               AND organization_id = :organization_id
            """
        ),
        {"policy_id": OPEN_BADGE_POLICY_ID, "organization_id": MARTY_ORG_ID},
    ).fetchone()
    if not row:
        return

    display_metadata = _as_json(row[0], {})
    requirements = _as_json(row[1], [])

    if isinstance(display_metadata, dict):
        display_metadata.update(
            {
                "title": "Marty Badge Login",
                "purpose": "Present your Marty Verified Member Badge to sign in. Only your email address will be shared.",
                "verifier_name": "ElevenID LLC",
            }
        )
        protocol = display_metadata.get("protocol")
        if not isinstance(protocol, dict):
            protocol = {}
        protocol["freshness"] = {"require_not_revoked": True, "max_age_seconds": 86400}
        display_metadata["protocol"] = protocol

    patched_requirements = []
    for requirement in requirements if isinstance(requirements, list) else []:
        if not isinstance(requirement, dict):
            patched_requirements.append(requirement)
            continue
        item = dict(requirement)
        if item.get("id") == "req-marty-open-badge-login" or item.get("credential_template_id") == OPEN_BADGE_TEMPLATE_ID:
            item.update(
                {
                    "display_name": BADGE_NAME,
                    "description": "Present your Marty Verified Member Badge for passwordless sign-in.",
                    "credential_payload_format": "sd_jwt_vc",
                }
            )
        patched_requirements.append(item)

    conn.execute(
        sa.text(
            """
            UPDATE presentation_policy_service.presentation_policies
               SET name = 'MartyBadgeLogin',
                   description = :description,
                   display_metadata = CAST(:display_metadata AS json),
                   credential_requirements = CAST(:credential_requirements AS json),
                   updated_at = NOW()
             WHERE id = :policy_id
               AND organization_id = :organization_id
            """
        ),
        {
            "policy_id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "description": (
                "Marty organization credential-based login policy for the Marty Verified Member Badge. "
                "Requests only email and verifies the presented SD-JWT VC against the DID-backed issuer key."
            ),
            "display_metadata": json.dumps(display_metadata),
            "credential_requirements": json.dumps(patched_requirements),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    row = conn.execute(
        sa.text(
            """
            SELECT credential_requirements
              FROM presentation_policy_service.presentation_policies
             WHERE id = :policy_id
               AND organization_id = :organization_id
            """
        ),
        {"policy_id": OPEN_BADGE_POLICY_ID, "organization_id": MARTY_ORG_ID},
    ).fetchone()
    if not row:
        return

    requirements = _as_json(row[0], [])
    patched_requirements = []
    for requirement in requirements if isinstance(requirements, list) else []:
        if not isinstance(requirement, dict):
            patched_requirements.append(requirement)
            continue
        item = dict(requirement)
        if item.get("id") == "req-marty-open-badge-login" or item.get("credential_template_id") == OPEN_BADGE_TEMPLATE_ID:
            item.update(
                {
                    "display_name": "Verified Member Badge",
                    "description": "Present your Open Badge 3.0 verified membership badge.",
                    "credential_payload_format": "openbadge-v3",
                }
            )
        patched_requirements.append(item)

    conn.execute(
        sa.text(
            """
            UPDATE presentation_policy_service.presentation_policies
               SET name = 'OpenBadgeLogin',
                   credential_requirements = CAST(:credential_requirements AS json),
                   updated_at = NOW()
             WHERE id = :policy_id
               AND organization_id = :organization_id
            """
        ),
        {
            "policy_id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "credential_requirements": json.dumps(patched_requirements),
        },
    )
