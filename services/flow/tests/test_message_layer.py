from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from marty_common.messages import MessageType
from flow.main import (
    FlowDefinition,
    FlowInstance,
    FlowInstanceStatus,
    FlowType,
    InMemoryFlowRepository,
    _create_oid4vci_artifact,
    get_verification_request_object,
    submit_verification_response,
)


def _jwt_segment(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()


@pytest.mark.asyncio
async def test_create_oid4vci_artifact_records_credential_offer_message(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://issuer.example")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="flow-1",
        organization_id="org-1",
        status=FlowInstanceStatus.PENDING,
    )
    await repo.save_instance(instance)

    flow_def = FlowDefinition(
        organization_id="org-1",
        name="OID4VCI issuance",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-123",
    )

    artifact = await _create_oid4vci_artifact(instance, flow_def, repo)

    assert artifact is not None
    message = instance.context["mip_messages"]["credential_offer"]
    assert message["message_type"] == MessageType.CREDENTIAL_OFFER.value
    assert message["correlation_id"] == instance.id
    assert message["payload"]["credential_issuer"] == "https://issuer.example"
    assert message["payload"]["credential_configuration_ids"] == ["template-123"]
    assert message["payload"]["mip_flow_instance_id"] == instance.id


@pytest.mark.asyncio
async def test_get_verification_request_object_records_presentation_request_message(monkeypatch):
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.WAITING,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}],
        }

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)

    response = await get_verification_request_object(instance.id, repo)

    assert response.media_type == "application/oauth-authz-req+jwt"
    message = instance.context["mip_messages"]["presentation_request"]
    assert message["message_type"] == MessageType.PRESENTATION_REQUEST.value
    assert message["nonce"] == "nonce-123"
    assert message["payload"]["mip_flow_instance_id"] == instance.id
    assert message["payload"]["mip_policy_id"] == "policy-1"
    assert message["payload"]["presentation_definition"]["id"] == "pd-1"


@pytest.mark.asyncio
async def test_submit_verification_response_records_verification_result_message():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.WAITING,
        context={"nonce": "nonce-xyz"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-xyz", "iss": "issuer.example", "given_name": "Marty"})
    vp_token = f"{header}.{payload}."

    response = await submit_verification_response(instance.id, vp_token, None, None, repo)

    assert response.result == "passed"
    message = instance.context["mip_messages"]["verification_result"]
    assert message["message_type"] == MessageType.VERIFICATION_RESULT.value
    assert message["correlation_id"] == instance.id
    assert message["payload"]["overall_result"] == "PASSED"
    assert message["payload"]["verifier_nonce"] == "nonce-xyz"
    assert message["payload"]["claim_results"][0]["claim_name"] == "given_name"