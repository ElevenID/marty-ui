"""Seed default Marty revocation profile

Revision ID: rp_seed_001
Revises: rp_schema_001
Create Date: 2026-04-16 00:10:00.000000+00:00
"""

from __future__ import annotations

import json
import os

from alembic import op
import sqlalchemy as sa
from marty_common.system_ids import (
    MARTY_DEFAULT_ORG_ID,
    MARTY_DEFAULT_REVOCATION_PROFILE_ID,
)
from marty_common.system_urls import build_marty_status_list_base_url

revision = "rp_seed_001"
down_revision = "rp_schema_001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID)
MARTY_REVOCATION_PROFILE_ID = MARTY_DEFAULT_REVOCATION_PROFILE_ID
NOW = "2026-04-16T00:00:00+00:00"


def _issuer_config() -> str:
    return json.dumps({
        "status_list_strategy": "auto",
        "status_list_base_url": build_marty_status_list_base_url(
            organization_id=MARTY_ORG_ID,
            revocation_profile_id=MARTY_REVOCATION_PROFILE_ID,
        ),
        "status_list_size": 131072,
        "update_mode": "sync",
        "batch_interval_seconds": 300,
        "enable_rotation": True,
        "rotation_threshold_percent": 80,
        "enable_bitstring_status_list": True,
        "enable_token_status_list": True,
        "enable_legacy_revocation_list": False,
    })


def upgrade() -> None:
    conn = op.get_bind()

    existing = conn.execute(
        sa.text(
            "SELECT id FROM revocation_profile_service.revocation_profiles WHERE id = :id"
        ),
        {"id": MARTY_REVOCATION_PROFILE_ID},
    ).fetchone()

    if existing:
        return

    conn.execute(
        sa.text(
            """
            INSERT INTO revocation_profile_service.revocation_profiles (
                id,
                organization_id,
                name,
                status,
                issuer_config,
                verifier_config,
                automation_config,
                supported_formats,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :status,
                :issuer_config,
                :verifier_config,
                :automation_config,
                :supported_formats,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": MARTY_REVOCATION_PROFILE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Marty Default Revocation",
            "status": "active",
            "issuer_config": _issuer_config(),
            "verifier_config": json.dumps({
                "check_mode": "HARD_FAIL",
                "timing_mode": "ALWAYS",
                "mechanism_priority": ["BITSTRING_STATUS_LIST", "TOKEN_STATUS_LIST"],
                "cache_status_lists": True,
                "cache_ttl_seconds": 3600,
                "offline_grace_seconds": 43200,
                "check_timeout_seconds": 5,
                "max_retries": 2,
                "require_issuer_signature_on_status_list": True,
                "allow_third_party_registries": False,
            }),
            "automation_config": json.dumps({
                "auto_allocate_indices": True,
                "auto_publish": True,
                "auto_generate_status_list_credentials": True,
                "auto_discover_endpoints": True,
                "use_format_defaults": True,
            }),
            "supported_formats": json.dumps(["SD_JWT_VC", "MDOC", "VC_JWT"]),
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "DELETE FROM revocation_profile_service.revocation_profiles WHERE id = :id"
        ),
        {"id": MARTY_REVOCATION_PROFILE_ID},
    )
