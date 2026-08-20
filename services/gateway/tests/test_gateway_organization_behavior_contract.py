from __future__ import annotations
import json
from pathlib import Path
import pytest
from fastapi import Response
from pydantic import ValidationError
from gateway.models import OrganizationCreate, OrganizationUpdate
from gateway.routes import organizations

CONTRACT = json.loads((Path(__file__).parents[3] / "contracts" / "gateway-organization-behavior.json").read_text(encoding="utf-8"))

def _model(case: dict):
    return OrganizationCreate if case["method"] == "POST" else OrganizationUpdate

def test_legacy_gateway_executes_shared_organization_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["request_cases"]:
        model = _model(case).model_validate(case["input"])
        actual = json.loads(organizations._validated_organization_payload(model, include_organization_id=case["method"] == "POST"))
        assert actual == case["expected"], case["name"]
    for case in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            _model(case).model_validate(case["input"])
    valid = organizations._sanitize_organization_response(Response(content=json.dumps(CONTRACT["valid_response"]), media_type="application/json"))
    assert json.loads(valid.body) == CONTRACT["expected_response"]
    private = dict(CONTRACT["valid_response"])
    private[CONTRACT["private_response_field"]] = {"private": True}
    assert organizations._sanitize_organization_response(Response(content=json.dumps(private), media_type="application/json")).status_code == 502
