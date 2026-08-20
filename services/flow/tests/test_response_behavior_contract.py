from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from flow.main import (
    ArtifactStatus,
    FlowDefinition,
    FlowInstance,
    FlowInstanceArtifact,
    FlowInstanceStatus,
    FlowStatus,
    FlowType,
    _artifact_to_response,
    _definition_to_response,
    _instance_to_response,
    _verification_result_to_response,
)


def _contract() -> dict:
    path = Path(__file__).resolve().parents[3] / "contracts" / "flow-response-behavior.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _timestamp(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def test_python_and_rust_public_projections_share_one_behavior_contract() -> None:
    contract = _contract()
    definition_input = contract["definition"]["input"]
    references = definition_input["references"]
    definition = FlowDefinition(
        id=definition_input["id"],
        organization_id=definition_input["organization_id"],
        name=definition_input["name"],
        description=definition_input["description"],
        status=FlowStatus(definition_input["status"]),
        flow_type=FlowType(definition_input["flow_type"]),
        extension=definition_input["extension"],
        trust_profile_id=references.get("trust_profile_id"),
        credential_template_id=references.get("credential_template_id"),
        application_template_id=references.get("application_template_id"),
        presentation_policy_id=references.get("presentation_policy_id"),
        delivery_destination_profile_id=references.get(
            "delivery_destination_profile_id"
        ),
        deployment_profile_ids=json.loads(
            references.get("deployment_profile_ids", "[]")
        ),
        approval_strategy=definition_input["approval_strategy"],
        hooks=definition_input["hooks"],
        trigger=definition_input["trigger"],
        version=definition_input["version"],
        created_at=_timestamp(definition_input["created_at"]),
        updated_at=_timestamp(definition_input["updated_at"]),
    )
    assert (
        _definition_to_response(definition).model_dump(mode="json", exclude_none=True)
        == contract["definition"]["expected"]
    )

    instance_input = contract["instance"]["input"]
    instance = FlowInstance(
        id=instance_input["id"],
        flow_definition_id=instance_input["flow_definition_id"],
        organization_id=instance_input["organization_id"],
        status=FlowInstanceStatus(instance_input["status"]),
        context=instance_input["context"],
        subject_id=instance_input["subject_id"],
        subject_type=instance_input["subject_type"],
        external_reference=instance_input["external_reference"],
        started_at=_timestamp(instance_input["started_at"]),
        completed_at=_timestamp(instance_input["completed_at"]),
        expires_at=_timestamp(instance_input["expires_at"]),
        result=instance_input["result"],
        error=instance_input["error"],
        state_history=instance_input["state_history"],
        created_at=_timestamp(instance_input["created_at"]),
        updated_at=_timestamp(instance_input["updated_at"]),
    )
    assert (
        _instance_to_response(instance).model_dump(mode="json", exclude_none=True)
        == contract["instance"]["expected"]
    )
    assert (
        _verification_result_to_response(instance).model_dump(
            mode="json", exclude_none=True
        )
        == contract["instance"]["verification_expected"]
    )

    artifact_input = contract["artifact"]["input"]
    artifact = FlowInstanceArtifact(
        id=artifact_input["id"],
        flow_instance_id=artifact_input["flow_instance_id"],
        credential_offer_uri=artifact_input["credential_offer_uri"],
        qr_payload=artifact_input["qr_payload"],
        pre_authorized_code=artifact_input["pre_authorized_code"],
        expires_at=_timestamp(artifact_input["expires_at"]),
        scanned_at=_timestamp(artifact_input["scanned_at"]),
        status=ArtifactStatus(artifact_input["status"]),
        state=artifact_input["state"],
        wallet_metadata=artifact_input["wallet_metadata"],
        attempt_number=artifact_input["attempt_number"],
        created_at=_timestamp(artifact_input["created_at"]),
        updated_at=_timestamp(artifact_input["updated_at"]),
    )
    assert (
        _artifact_to_response(artifact).model_dump(mode="json", exclude_none=True)
        == contract["artifact"]["expected"]
    )
