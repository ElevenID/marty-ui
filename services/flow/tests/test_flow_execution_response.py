from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from flow.main import (
    FlowDefinition,
    FlowInstance,
    FlowInstanceStatus,
    FlowStep,
    FlowType,
    InMemoryFlowRepository,
    StartSiopFlowRequest,
    StepType,
    _definition_to_response,
    _parse_flow_instance_status,
    _instance_to_response,
    _sync_protocol_context,
    start_siop_flow,
)


@pytest.mark.asyncio
async def test_instance_response_adds_protocol_execution_fields() -> None:
    repo = InMemoryFlowRepository()
    now = datetime.now(timezone.utc)
    create_offer = FlowStep(
        name="Create Offer",
        step_type=StepType.ISSUANCE,
        config={"protocol_step": "create_offer"},
    )
    token_exchange = FlowStep(
        name="Token Exchange",
        step_type=StepType.CALLBACK,
        config={"protocol_step": "token_exchange"},
    )
    flow_def = FlowDefinition(
        organization_id="org-1",
        name="OID4VCI issuance",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        steps=[create_offer, token_exchange],
        start_step_id=create_offer.id,
    )
    await repo.save_definition(flow_def)

    instance = FlowInstance(
        flow_definition_id=flow_def.id,
        organization_id="org-1",
        status=FlowInstanceStatus.IN_PROGRESS,
        current_step_id=token_exchange.id,
        context={"issued_credential_id": "cred-123"},
        step_history=[
            {
                "step_id": create_offer.id,
                "entered_at": now.isoformat(),
                "completed_at": now.isoformat(),
                "result": "success",
            },
            {
                "step_id": token_exchange.id,
                "entered_at": now.isoformat(),
                "status": "entered",
            },
        ],
        subject_type="holder",
        started_at=now,
    )
    instance.context["step_results"] = {
        "create_offer": {
            "result": "success",
            "completed_at": now.isoformat(),
        }
    }
    _sync_protocol_context(instance, flow_def)

    response = _instance_to_response(instance)

    assert response.flow_id == flow_def.id
    assert response.flow_type == FlowType.OID4VCI_PRE_AUTHORIZED.value
    assert response.status == "IN_PROGRESS"
    assert response.current_step == "token_exchange"
    assert response.current_step_index == 1
    assert response.step_results == {
        "create_offer": {
            "result": "success",
            "completed_at": now.isoformat(),
        }
    }
    assert response.context_data == {"issued_credential_id": "cred-123", "step_results": {"create_offer": {"result": "success", "completed_at": now.isoformat()}}, "protocol_flow_type": FlowType.OID4VCI_PRE_AUTHORIZED.value, "current_step_name": "token_exchange", "current_step_index": 1}
    assert response.issued_credential_id == "cred-123"
    assert response.metadata["subject_type"] == "holder"
    assert response.metadata["runtime_status"] == FlowInstanceStatus.IN_PROGRESS.value
    assert response.metadata["flow_definition_reference"] == flow_def.id
    assert not hasattr(response, "protocol_status")
    assert not hasattr(response, "flow_definition_id")
    assert not hasattr(response, "current_step_id")
    assert not hasattr(response, "context")
    assert not hasattr(response, "step_history")
    assert not hasattr(response, "subject_id")
    assert not hasattr(response, "external_reference")
    assert not hasattr(response, "result")
    assert not hasattr(response, "error")


def test_special_verification_instances_map_to_protocol_flow_type() -> None:
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.WAITING,
        context={
            "flow_type": "verification",
            "protocol_flow_type": FlowType.OID4VP_PRESENTATION.value,
            "current_step_name": "create_request",
            "current_step_index": 0,
            "step_results": {},
        },
    )

    response = _instance_to_response(instance)

    assert response.flow_id is None
    assert response.flow_type == FlowType.OID4VP_PRESENTATION.value
    assert response.status == "AWAITING_WALLET"
    assert response.current_step == "create_request"
    assert response.current_step_index == 0
    assert response.metadata["runtime_status"] == FlowInstanceStatus.WAITING.value
    assert response.metadata["flow_definition_reference"] == "__verification__"


def test_uuid_backed_ad_hoc_verification_instances_expose_protocol_flow_id() -> None:
    flow_definition_id = str(uuid.uuid4())
    instance = FlowInstance(
        flow_definition_id=flow_definition_id,
        organization_id="org-1",
        status=FlowInstanceStatus.WAITING,
        context={
            "flow_definition_reference": "__verification__",
            "flow_type": "verification",
            "protocol_flow_type": FlowType.OID4VP_PRESENTATION.value,
            "current_step_name": "create_request",
            "current_step_index": 0,
            "step_results": {},
        },
    )

    response = _instance_to_response(instance)

    assert response.flow_id == flow_definition_id
    assert response.flow_type == FlowType.OID4VP_PRESENTATION.value
    assert response.status == "AWAITING_WALLET"
    assert response.metadata["flow_definition_reference"] == "__verification__"


def test_parse_flow_instance_status_accepts_protocol_and_runtime_aliases() -> None:
    assert _parse_flow_instance_status("AWAITING_APPROVAL") is FlowInstanceStatus.WAITING_APPROVAL
    assert _parse_flow_instance_status("awaiting_wallet") is FlowInstanceStatus.WAITING
    assert _parse_flow_instance_status("cancelled") is FlowInstanceStatus.CANCELLED
    assert _parse_flow_instance_status("CANCELED") is FlowInstanceStatus.CANCELLED


def test_definition_response_normalizes_legacy_string_trigger() -> None:
    flow_def = FlowDefinition(
        organization_id="org-1",
        name="Legacy Trigger Flow",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
    )
    flow_def.trigger = "credential_login"

    response = _definition_to_response(flow_def)

    assert response.trigger == {"event": "credential_login"}


@pytest.mark.asyncio
async def test_start_siop_flow_uses_uuid_backed_definition_id() -> None:
    repo = InMemoryFlowRepository()

    response = await start_siop_flow(
        StartSiopFlowRequest(organization_id="org-1", expiry_minutes=5),
        user_id="user-1",
        repo=repo,
    )

    instance = await repo.get_instance(response["instance_id"])

    assert instance is not None
    uuid.UUID(instance.flow_definition_id)
    assert instance.context["flow_definition_reference"] == "__siop_v2__"