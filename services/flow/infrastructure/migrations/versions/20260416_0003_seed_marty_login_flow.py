"""Seed Marty credential-login flow definition and bootstrap instance.

Revision ID: marty_flow_seed_001
Revises: 2a3b4c5d6e7f
Create Date: 2026-04-16 00:20:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "marty_flow_seed_001"
down_revision = "2a3b4c5d6e7f"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_FLOW_ID = "71000000-0000-0000-0000-000000000001"
MARTY_FLOW_INSTANCE_ID = "71000000-0000-0000-0000-000000000101"
MARTY_DEPLOYMENT_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_LOGIN_POLICY_ID = "50000000-0000-0000-0000-000000000004"
MARTY_OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
NOW = "2026-04-16T00:00:00+00:00"


def _seed_flow_definition(connection) -> None:
    existing = connection.execute(
        sa.text(
            """
            SELECT id
            FROM flow_service.flow_definitions
            WHERE id = :id
            """
        ),
        {"id": MARTY_FLOW_ID},
    ).fetchone()

    if existing:
        return

    steps = [
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
            "name": "Verify Open Badge Membership Credential",
            "description": "Evaluate holder credential against the OpenBadgeLogin policy",
            "step_type": "verification",
            "config": {
                "presentation_policy_id": MARTY_LOGIN_POLICY_ID,
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

    transitions = [
        {
            "id": "transition-1",
            "from_step_id": "step-start",
            "to_step_id": "step-verify",
            "condition": "success",
            "condition_expression": None,
        },
        {
            "id": "transition-2",
            "from_step_id": "step-verify",
            "to_step_id": "step-end",
            "condition": "success",
            "condition_expression": None,
        },
    ]

    preconditions = {
        "items": ["organization_membership_active"],
        "protocol": {
            "trust_profile_id": MARTY_TRUST_PROFILE_ID,
            "deployment_profile_ids": [MARTY_DEPLOYMENT_PROFILE_ID],
            "approval_strategy": "AUTO",
            "enabled": True,
            "hooks": {},
            "trigger": "credential_login",
        },
    }

    connection.execute(
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
                :steps,
                :transitions,
                :start_step_id,
                :credential_template_id,
                :presentation_policy_id,
                :deployment_profile_id,
                :preconditions,
                :default_timeout_seconds,
                :max_retries,
                :enable_resume,
                :version,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": MARTY_FLOW_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Marty Open Badge Login Flow",
            "description": "Default flow for Marty Open Badge credential-based login.",
            "status": "ACTIVE",
            "flow_type": "oid4vp_presentation",
            "steps": json.dumps(steps),
            "transitions": json.dumps(transitions),
            "start_step_id": "step-start",
            "credential_template_id": MARTY_OPEN_BADGE_TEMPLATE_ID,
            "presentation_policy_id": MARTY_LOGIN_POLICY_ID,
            "deployment_profile_id": MARTY_DEPLOYMENT_PROFILE_ID,
            "preconditions": json.dumps(preconditions),
            "default_timeout_seconds": 600,
            "max_retries": 1,
            "enable_resume": True,
            "version": 1,
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def _seed_flow_instance(connection) -> None:
    existing = connection.execute(
        sa.text(
            """
            SELECT id
            FROM flow_service.flow_instances
            WHERE id = :id
            """
        ),
        {"id": MARTY_FLOW_INSTANCE_ID},
    ).fetchone()

    if existing:
        return

    connection.execute(
        sa.text(
            """
            INSERT INTO flow_service.flow_instances (
                id,
                flow_definition_id,
                organization_id,
                status,
                current_step_id,
                context,
                step_history,
                subject_id,
                subject_type,
                external_reference,
                started_at,
                completed_at,
                expires_at,
                result,
                error,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :flow_definition_id,
                :organization_id,
                :status,
                :current_step_id,
                :context,
                :step_history,
                :subject_id,
                :subject_type,
                :external_reference,
                :started_at,
                :completed_at,
                :expires_at,
                :result,
                :error,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": MARTY_FLOW_INSTANCE_ID,
            "flow_definition_id": MARTY_FLOW_ID,
            "organization_id": MARTY_ORG_ID,
            "status": "completed",
            "current_step_id": "step-end",
            "context": json.dumps({"seeded": True, "scenario": "bootstrap"}),
            "step_history": json.dumps(
                [
                    {
                        "step_id": "step-start",
                        "status": "completed",
                        "timestamp": NOW,
                    },
                    {
                        "step_id": "step-verify",
                        "status": "completed",
                        "timestamp": NOW,
                    },
                    {
                        "step_id": "step-end",
                        "status": "completed",
                        "timestamp": NOW,
                    },
                ]
            ),
            "subject_id": "marty-bootstrap-user",
            "subject_type": "applicant",
            "external_reference": "seed:marty-credential-login",
            "started_at": NOW,
            "completed_at": NOW,
            "expires_at": None,
            "result": json.dumps({"outcome": "success", "seeded": True}),
            "error": None,
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def _link_flow_to_deployment_profile(connection) -> None:
    current = connection.execute(
        sa.text(
            """
            SELECT enabled_flow_ids
            FROM deployment_profile_service.deployment_profiles
            WHERE id = :id
            """
        ),
        {"id": MARTY_DEPLOYMENT_PROFILE_ID},
    ).fetchone()

    if not current:
        return

    flow_ids = current.enabled_flow_ids or []
    if MARTY_FLOW_ID in flow_ids:
        return

    flow_ids.append(MARTY_FLOW_ID)
    connection.execute(
        sa.text(
            """
            UPDATE deployment_profile_service.deployment_profiles
            SET enabled_flow_ids = :enabled_flow_ids,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": MARTY_DEPLOYMENT_PROFILE_ID,
            "enabled_flow_ids": json.dumps(flow_ids),
            "updated_at": NOW,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()

    profile = conn.execute(
        sa.text(
            """
            SELECT id
            FROM deployment_profile_service.deployment_profiles
            WHERE id = :id
            """
        ),
        {"id": MARTY_DEPLOYMENT_PROFILE_ID},
    ).fetchone()

    if not profile:
        return

    _seed_flow_definition(conn)
    _seed_flow_instance(conn)
    _link_flow_to_deployment_profile(conn)


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            DELETE FROM flow_service.flow_instances
            WHERE id = :id
            """
        ),
        {"id": MARTY_FLOW_INSTANCE_ID},
    )
    conn.execute(
        sa.text(
            """
            UPDATE deployment_profile_service.deployment_profiles
            SET enabled_flow_ids = '[]'::json,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {"id": MARTY_DEPLOYMENT_PROFILE_ID, "updated_at": NOW},
    )
    conn.execute(
        sa.text(
            """
            DELETE FROM flow_service.flow_definitions
            WHERE id = :id
            """
        ),
        {"id": MARTY_FLOW_ID},
    )
