"""Adopt the MIP 0.3 draft-first flow contract.

Revision ID: 20260711_0001
Revises: 20260710_0001
"""

from __future__ import annotations

import json
import re
from typing import Any

import sqlalchemy as sa
from alembic import op


revision = "20260711_0001"
down_revision = "20260710_0001"
branch_labels = None
depends_on = None


FLOW_ALIASES = {
    "issuance": "oid4vci_pre_authorized",
    "issuance_oid4vci": "oid4vci_pre_authorized",
    "verification": "oid4vp_presentation",
    "verification_oid4vp": "oid4vp_presentation",
    "presentation": "oid4vp_presentation",
    "renewal": "credential_renewal",
    "revocation": "credential_revocation",
    "siop_v2": "siopv2",
}

SEQUENCES = {
    "oid4vci_pre_authorized": ["create_offer", "token_exchange", "credential_request", "issue_credential"],
    "oid4vci_authorization_code": ["create_offer", "authorization", "token_exchange", "credential_request", "issue_credential"],
    "mdl_issuance": ["application_submit", "validate_evidence", "approval_decision", "issue_mdl", "deliver_credential"],
    "oid4vp_presentation": ["create_request", "wallet_selection", "presentation_submission", "verify_presentation"],
    "mdl_presentation": ["device_engagement", "session_establishment", "request_items", "response_items", "session_termination"],
    "application_approval_issuance": ["accept_application", "validate_evidence", "approval_decision", "issue_credential", "deliver_credential"],
    "credential_renewal": ["validate_existing", "create_offer", "token_exchange", "credential_request", "issue_renewed_credential", "revoke_old_credential"],
    "credential_revocation": ["validate_revocation_request", "update_status_list", "notify_holder"],
    "physical_document_issuance": ["accept_application", "validate_evidence", "approval_decision", "generate_data_groups", "sign_sod", "submit_to_personalization", "track_production", "quality_verify", "activate_credential"],
    "combined": ["accept_application", "approval_decision", "issue_credential", "create_request", "presentation_submission", "verify_presentation"],
    "siopv2": ["create_request", "authentication_submission", "verify_id_token"],
}

OUTCOMES = {
    "success": "SUCCESS",
    "failure": "FAILURE",
    "approval_granted": "APPROVED",
    "approval_denied": "REJECTED",
    "timeout": "TIMEOUT",
}


def _metadata(payload: Any) -> tuple[list[str], dict[str, Any]]:
    if isinstance(payload, dict):
        return list(payload.get("items") or []), dict(payload.get("protocol") or {})
    return list(payload or []), {}


def _slug(value: str, fallback: str) -> str:
    normalized = re.sub(r"[^a-z0-9_.:-]+", "_", value.strip().lower()).strip("_")
    if not normalized or not normalized[0].isalpha():
        return fallback
    return normalized[:160]


def _step_name(step: dict[str, Any], index: int) -> str:
    config = step.get("config") if isinstance(step.get("config"), dict) else {}
    return _slug(str(config.get("protocol_step") or step.get("name") or ""), f"step_{index + 1}")


def _extension(flow_type: str, steps: list[dict[str, Any]], transitions: list[dict[str, Any]], preconditions: list[str]) -> dict[str, Any]:
    if not steps:
        steps = [{"id": "legacy_missing_step", "name": "legacy_missing_step", "config": {}}]
    step_ids: dict[str, str] = {}
    extension_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        step_id = f"step_{index + 1}"
        step_ids[str(step.get("id") or index)] = step_id
        extension_step = {
            "step_id": step_id,
            "action": _step_name(step, index),
            "config": step.get("config") if isinstance(step.get("config"), dict) else {},
        }
        if step.get("description"):
            extension_step["description"] = str(step["description"])[:512]
        if step.get("timeout_seconds"):
            extension_step["timeout_seconds"] = int(step["timeout_seconds"])
        extension_steps.append(extension_step)

    extension_transitions = []
    for transition in transitions:
        source = step_ids.get(str(transition.get("from_step_id")))
        destination = step_ids.get(str(transition.get("to_step_id")))
        if source and destination:
            outcome = OUTCOMES.get(str(transition.get("condition") or "success").lower(), "CUSTOM")
            item = {"from_step_id": source, "to_step_id": destination, "outcome": outcome}
            if transition.get("condition_expression"):
                item["condition"] = {"legacy_expression": transition["condition_expression"]}
            extension_transitions.append(item)

    return {
        "extension_uri": "urn:elevenid:flow-extension:legacy-orchestration:v1",
        "extension_version": "1.0.0",
        "extends_flow_type": flow_type,
        "entry_step_id": extension_steps[0]["step_id"],
        "steps": extension_steps,
        "transitions": extension_transitions,
        "config": {"legacy_preconditions": preconditions} if preconditions else {},
    }


def upgrade() -> None:
    columns = (
        sa.Column("application_template_id", sa.String(36), nullable=True),
        sa.Column("delivery_destination_profile_id", sa.String(128), nullable=True),
        sa.Column("deployment_profile_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("trust_profile_id", sa.String(36), nullable=True),
        sa.Column("approval_strategy", sa.String(50), nullable=False, server_default="AUTO"),
        sa.Column("hooks", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("trigger", sa.JSON(), nullable=True),
        sa.Column("extension", sa.JSON(), nullable=True),
    )
    for column in columns:
        op.add_column("flow_definitions", column, schema="flow_service")

    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT * FROM flow_service.flow_definitions")).mappings().all()
    for row in rows:
        steps = list(row.get("steps") or [])
        transitions = list(row.get("transitions") or [])
        preconditions, metadata = _metadata(row.get("preconditions"))
        flow_type = FLOW_ALIASES.get(str(row.get("flow_type") or "").lower(), str(row.get("flow_type") or ""))
        actual_sequence = [_step_name(step, index) for index, step in enumerate(steps)]
        canonical = flow_type in SEQUENCES and actual_sequence == SEQUENCES[flow_type] and not preconditions
        extension = None if canonical else _extension(flow_type, steps, transitions, preconditions)
        migrated_type = flow_type if canonical else "custom"

        raw_status = str(row.get("status") or "DRAFT").upper()
        raw_status = {"SUSPENDED": "PAUSED"}.get(raw_status, raw_status)
        if raw_status not in {"DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"}:
            raw_status = "DRAFT"
        if metadata.get("enabled") is False and raw_status == "ACTIVE":
            raw_status = "PAUSED"

        deployment_ids = list(metadata.get("deployment_profile_ids") or [])
        if row.get("deployment_profile_id") and row["deployment_profile_id"] not in deployment_ids:
            deployment_ids.insert(0, row["deployment_profile_id"])

        connection.execute(
            sa.text(
                """
                UPDATE flow_service.flow_definitions
                SET flow_type = :flow_type,
                    status = :status,
                    application_template_id = :application_template_id,
                    deployment_profile_ids = CAST(:deployment_profile_ids AS json),
                    trust_profile_id = :trust_profile_id,
                    approval_strategy = :approval_strategy,
                    hooks = CAST(:hooks AS json),
                    trigger = CAST(:trigger AS json),
                    extension = CAST(:extension AS json),
                    preconditions = CAST('[]' AS json)
                WHERE id = :id
                """
            ),
            {
                "id": row["id"],
                "flow_type": migrated_type,
                "status": raw_status,
                "application_template_id": metadata.get("application_template_id"),
                "deployment_profile_ids": json.dumps(deployment_ids),
                "trust_profile_id": metadata.get("trust_profile_id"),
                "approval_strategy": metadata.get("approval_strategy") or "AUTO",
                "hooks": json.dumps(metadata.get("hooks") or {}),
                "trigger": json.dumps(metadata.get("trigger")) if metadata.get("trigger") is not None else None,
                "extension": json.dumps(extension) if extension is not None else None,
            },
        )

    op.alter_column("flow_definitions", "deployment_profile_ids", server_default=None, schema="flow_service")
    op.alter_column("flow_definitions", "approval_strategy", server_default=None, schema="flow_service")
    op.alter_column("flow_definitions", "hooks", server_default=None, schema="flow_service")


def downgrade() -> None:
    for column_name in (
        "extension",
        "trigger",
        "hooks",
        "approval_strategy",
        "trust_profile_id",
        "deployment_profile_ids",
        "delivery_destination_profile_id",
        "application_template_id",
    ):
        op.drop_column("flow_definitions", column_name, schema="flow_service")
