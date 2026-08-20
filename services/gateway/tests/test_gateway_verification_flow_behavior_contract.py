from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import StartVerificationFlowRequest
from gateway.routes import flows


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-verification-flow-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_legacy_gateway_executes_shared_verification_flow_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    request = StartVerificationFlowRequest.model_validate(CONTRACT["valid_request"])
    assert request.model_dump(mode="json") == CONTRACT["expected_request"]
    for invalid in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            StartVerificationFlowRequest.model_validate(invalid)
    response = flows._sanitize_verification_start_response(
        Response(content=json.dumps(CONTRACT["internal_response"]), media_type="application/json")
    )
    assert json.loads(response.body) == CONTRACT["expected_response"]
