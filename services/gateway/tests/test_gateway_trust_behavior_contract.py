from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import (
    IssuerEntityCreate,
    IssuerEntityUpdate,
    TrustProfileCreate,
    TrustProfileIssuerCreate,
    TrustProfileIssuerUpdate,
    TrustProfileResponse,
    TrustProfileUpdate,
)
from gateway.routes import trust


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-trust-behavior.json").read_text(
        encoding="utf-8"
    )
)


def _request_model(case: dict):
    if case["path"].startswith("/v1/issuer-entities"):
        return IssuerEntityCreate if case["method"] == "POST" else IssuerEntityUpdate
    if "/issuers" not in case["path"]:
        return TrustProfileCreate if case["method"] == "POST" else TrustProfileUpdate
    return (
        TrustProfileIssuerCreate
        if case["method"] == "POST"
        else TrustProfileIssuerUpdate
    )


def _request_payload(case: dict) -> dict:
    model = _request_model(case).model_validate(case["input"])
    if isinstance(model, (TrustProfileCreate, TrustProfileUpdate)):
        return model.model_dump(
            mode="json", exclude_unset=isinstance(model, TrustProfileUpdate)
        )
    serializer = (
        trust._validated_issuer_entity_payload
        if case["path"].startswith("/v1/issuer-entities")
        else trust._validated_trust_profile_issuer_payload
    )
    return json.loads(serializer(model))


def _response(case: dict) -> Response:
    response = Response(content=json.dumps(case["input"]), media_type="application/json")
    if case["kind"] == "trust_profile":
        raw = case["input"]
        if case["many"]:
            public = [
                TrustProfileResponse.model_validate(item).model_dump(
                    mode="json", exclude_none=True
                )
                for item in raw
            ]
        else:
            public = TrustProfileResponse.model_validate(raw).model_dump(
                mode="json", exclude_none=True
            )
        return Response(content=json.dumps(public), media_type="application/json")
    if case["kind"] == "registry_sync":
        return trust._sanitize_registry_sync_response(response)
    sanitizer = (
        trust._sanitize_issuer_entity_response
        if case["kind"] == "issuer_entity"
        else trust._sanitize_trust_profile_issuer_response
    )
    return sanitizer(response, many=case["many"])


def test_legacy_gateway_executes_shared_trust_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["request_cases"]:
        assert _request_payload(case) == case["expected"], case["name"]
    for case in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            _request_payload(case)
    for case in CONTRACT["response_cases"]:
        response = _response(case)
        assert response.status_code == 200, case["name"]
        assert json.loads(response.body) == case["expected"], case["name"]
    assert _response(CONTRACT["private_metadata_response"]).status_code == 502
