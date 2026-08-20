from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import (
    FlowDefinitionCreate,
    FlowDefinitionResponse,
    FlowDefinitionUpdate,
    FlowInstanceCreate,
    FlowInstanceResponse,
    VerificationResultResponse,
)
from gateway.routes import flows


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-flow-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_legacy_gateway_executes_shared_flow_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    create = FlowDefinitionCreate.model_validate(CONTRACT["definition_create_input"])
    assert json.loads(flows._validated_flow_body(create)) == CONTRACT["expected_definition_create"]
    update = FlowDefinitionUpdate.model_validate(CONTRACT["definition_update_input"])
    assert json.loads(flows._validated_flow_body(update, patch=True)) == CONTRACT["expected_definition_update"]
    instance = FlowInstanceCreate.model_validate(CONTRACT["instance_create_input"])
    assert json.loads(flows._validated_flow_body(instance)) == CONTRACT["expected_instance_create"]
    with pytest.raises(ValidationError):
        FlowInstanceCreate.model_validate(CONTRACT["invalid_instance"])
    definition = flows._sanitize_public_response(
        Response(content=json.dumps(CONTRACT["internal_definition"]), media_type="application/json"),
        FlowDefinitionResponse,
    )
    assert json.loads(definition.body) == CONTRACT["expected_definition"]
    projected_instance = flows._sanitize_public_response(
        Response(content=json.dumps(CONTRACT["internal_instance"]), media_type="application/json"),
        FlowInstanceResponse,
    )
    assert json.loads(projected_instance.body) == CONTRACT["expected_instance"]
    projected_result = flows._sanitize_public_response(
        Response(
            content=json.dumps(CONTRACT["internal_verification_result"]),
            media_type="application/json",
        ),
        VerificationResultResponse,
    )
    assert json.loads(projected_result.body) == CONTRACT["expected_verification_result"]
