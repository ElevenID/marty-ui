"""Seed Marty login badge OID4VCI issuance flows.

Applicants can request a login badge from the Marty catalog, then claim it into
an OID4VCI-compatible wallet. The existing Marty login flow is an OID4VP
presentation flow used after the badge already exists. This migration adds the
separate issuance flows that the applicant issue endpoint searches for.

Revision ID: 20260710_0001
Revises: 20260505_0001
Create Date: 2026-07-10 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260710_0001"
down_revision = "20260505_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_DEPLOYMENT_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
LEGACY_MEMBER_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
FLOW_STATUS = "ACTIVE"
FLOW_TYPE = "oid4vci_pre_authorized"
NOW = "2026-07-10T00:00:00+00:00"


ISSUANCE_FLOWS = (
    {
        "id": "72000000-0000-0000-0000-000000000010",
        "credential_template_id": LEGACY_MEMBER_TEMPLATE_ID,
        "name": "Marty Member Login Credential Issuance",
        "description": "Issues the legacy Marty Member Login Credential to an applicant wallet.",
    },
    {
        "id": "72000000-0000-0000-0000-000000000040",
        "credential_template_id": OPEN_BADGE_TEMPLATE_ID,
        "name": "Marty Verified Member Badge Issuance",
        "description": "Issues the Marty Verified Member Badge to an applicant wallet.",
    },
)


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('flow_service.flow_definitions') IS NOT NULL")
        ).scalar()
    )


def _build_steps() -> list[dict]:
    return [
        {
            "id": "step-check-preconditions",
            "name": "Check Preconditions",
            "description": "Confirm the applicant application is approved before issuing.",
            "step_type": "approval",
            "config": {
                "required_preconditions": ["application_approved"],
                "auto_advance": True,
            },
            "timeout_seconds": 300,
            "conditions": [],
            "approval_strategy": "AUTO",
        },
        {
            "id": "step-create-offer",
            "name": "Create Credential Offer",
            "description": "Generate an OID4VCI pre-authorized credential offer.",
            "step_type": "issuance",
            "config": {
                "transport_method": "qr_code",
                "offer_validity_minutes": 15,
                "generate_qr": True,
            },
            "timeout_seconds": 60,
            "conditions": [],
            "approval_strategy": None,
        },
        {
            "id": "step-await-wallet",
            "name": "Await Wallet",
            "description": "Wait for the applicant wallet to redeem the credential offer.",
            "step_type": "wait",
            "config": {
                "wait_for_event": "credential_requested",
                "show_deep_link": True,
            },
            "timeout_seconds": 900,
            "conditions": [],
            "approval_strategy": None,
        },
        {
            "id": "step-issue-credential",
            "name": "Issue Credential",
            "description": "Wallet requests and receives the signed credential.",
            "step_type": "issuance",
            "config": {
                "endpoint": "/api/issuance/credential",
                "auto_advance": True,
            },
            "timeout_seconds": 60,
            "conditions": [],
            "approval_strategy": None,
        },
        {
            "id": "step-complete",
            "name": "Issuance Complete",
            "description": "Credential issuance completed.",
            "step_type": "end",
            "config": {
                "emit_event": "credential_issued",
            },
            "timeout_seconds": None,
            "conditions": [],
            "approval_strategy": None,
        },
    ]


def _build_transitions() -> list[dict]:
    return [
        {
            "id": "transition-preconditions-offer",
            "from_step_id": "step-check-preconditions",
            "to_step_id": "step-create-offer",
            "condition": "success",
            "condition_expression": None,
        },
        {
            "id": "transition-offer-await-wallet",
            "from_step_id": "step-create-offer",
            "to_step_id": "step-await-wallet",
            "condition": "success",
            "condition_expression": None,
        },
        {
            "id": "transition-wallet-issue",
            "from_step_id": "step-await-wallet",
            "to_step_id": "step-issue-credential",
            "condition": "success",
            "condition_expression": None,
        },
        {
            "id": "transition-issue-complete",
            "from_step_id": "step-issue-credential",
            "to_step_id": "step-complete",
            "condition": "success",
            "condition_expression": None,
        },
    ]


def _build_preconditions() -> dict:
    return {
        "items": ["application_approved"],
        "protocol": {
            "deployment_profile_ids": [MARTY_DEPLOYMENT_PROFILE_ID],
            "approval_strategy": "AUTO",
            "enabled": True,
            "hooks": {},
            "trigger": "application_approved",
        },
    }


def _upsert_flow(conn, flow: dict) -> None:
    conn.execute(
        sa.text(
            """
            INSERT INTO flow_service.flow_definitions (
                id,
                organization_id,
                name,
                description,
                status,
                flow_type,
                steps,
                transitions,
                start_step_id,
                credential_template_id,
                presentation_policy_id,
                deployment_profile_id,
                preconditions,
                default_timeout_seconds,
                max_retries,
                enable_resume,
                version,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :description,
                :status,
                :flow_type,
                CAST(:steps AS json),
                CAST(:transitions AS json),
                'step-check-preconditions',
                :credential_template_id,
                NULL,
                :deployment_profile_id,
                CAST(:preconditions AS json),
                600,
                3,
                TRUE,
                1,
                :created_at,
                :updated_at
            )
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                flow_type = EXCLUDED.flow_type,
                steps = EXCLUDED.steps,
                transitions = EXCLUDED.transitions,
                start_step_id = EXCLUDED.start_step_id,
                credential_template_id = EXCLUDED.credential_template_id,
                presentation_policy_id = EXCLUDED.presentation_policy_id,
                deployment_profile_id = EXCLUDED.deployment_profile_id,
                preconditions = EXCLUDED.preconditions,
                default_timeout_seconds = EXCLUDED.default_timeout_seconds,
                max_retries = EXCLUDED.max_retries,
                enable_resume = EXCLUDED.enable_resume,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "id": flow["id"],
            "organization_id": MARTY_ORG_ID,
            "name": flow["name"],
            "description": flow["description"],
            "status": FLOW_STATUS,
            "flow_type": FLOW_TYPE,
            "credential_template_id": flow["credential_template_id"],
            "deployment_profile_id": MARTY_DEPLOYMENT_PROFILE_ID,
            "steps": json.dumps(_build_steps()),
            "transitions": json.dumps(_build_transitions()),
            "preconditions": json.dumps(_build_preconditions()),
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    for flow in ISSUANCE_FLOWS:
        _upsert_flow(conn, flow)


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            DELETE FROM flow_service.flow_definitions
             WHERE id = ANY(:flow_ids)
            """
        ),
        {"flow_ids": [flow["id"] for flow in ISSUANCE_FLOWS]},
    )
