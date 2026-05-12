"""Use OpenBadgeLogin artifacts in the Marty credential-login flow.

Revision ID: 20260505_0001
Revises: marty_flow_seed_001
Create Date: 2026-05-05 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260505_0001"
down_revision = "marty_flow_seed_001"
branch_labels = None
depends_on = None


MARTY_FLOW_ID = "71000000-0000-0000-0000-000000000001"
MARTY_DEPLOYMENT_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
LEGACY_MEMBER_POLICY_ID = "50000000-0000-0000-0000-000000000002"
LEGACY_MEMBER_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
NOW = "2026-05-05T00:00:00+00:00"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('flow_service.flow_definitions') IS NOT NULL")
        ).scalar()
    )


def _build_steps(policy_id: str, *, open_badge: bool) -> list[dict]:
    verify_name = "Verify Open Badge Membership Credential" if open_badge else "Verify Member Credential"
    verify_description = (
        "Evaluate holder credential against the OpenBadgeLogin policy"
        if open_badge
        else "Evaluate holder credential against MemberLogin policy"
    )
    return [
        {
            "id": "step-start",
            "name": "Start Login Verification",
            "description": "Initialize credential-login verification request",
            "step_type": "start",
            "config": {},
            "timeout_seconds": 300,
            "conditions": [],
            "approval_strategy": None,
        },
        {
            "id": "step-verify",
            "name": verify_name,
            "description": verify_description,
            "step_type": "verification",
            "config": {
                "presentation_policy_id": policy_id,
                "trust_profile_id": MARTY_TRUST_PROFILE_ID,
            },
            "timeout_seconds": 300,
            "conditions": [],
            "approval_strategy": None,
        },
        {
            "id": "step-end",
            "name": "Login Complete",
            "description": "Credential login completed",
            "step_type": "end",
            "config": {},
            "timeout_seconds": None,
            "conditions": [],
            "approval_strategy": None,
        },
    ]


def _apply_flow(conn, *, policy_id: str, template_id: str, open_badge: bool) -> None:
    conn.execute(
        sa.text(
            """
            UPDATE flow_service.flow_definitions
               SET name = :name,
                   description = :description,
                   steps = CAST(:steps AS json),
                   credential_template_id = :template_id,
                   presentation_policy_id = :policy_id,
                   updated_at = :updated_at
             WHERE id = :id
            """
        ),
        {
            "id": MARTY_FLOW_ID,
            "name": "Marty Open Badge Login Flow" if open_badge else "Marty Credential Login Flow",
            "description": (
                "Default flow for Marty Open Badge credential-based login."
                if open_badge
                else "Default flow for Marty credential-based login."
            ),
            "steps": json.dumps(_build_steps(policy_id, open_badge=open_badge)),
            "template_id": template_id,
            "policy_id": policy_id,
            "updated_at": NOW,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_flow(
        conn,
        policy_id=OPEN_BADGE_POLICY_ID,
        template_id=OPEN_BADGE_TEMPLATE_ID,
        open_badge=True,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_flow(
        conn,
        policy_id=LEGACY_MEMBER_POLICY_ID,
        template_id=LEGACY_MEMBER_TEMPLATE_ID,
        open_badge=False,
    )
