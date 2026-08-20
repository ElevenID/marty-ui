from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from gateway.routes import issuance


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-issuance-response-projection.json"
    ).read_text(encoding="utf-8")
)


def _projection(case: dict):
    path = case["path"]
    if path == "/v1/issuance" and case["method"] == "POST":
        return issuance.IssuanceResponse, False
    if path == "/v1/issuance":
        return issuance.IssuanceTransactionResponse, True
    if path.startswith("/v1/issuance/"):
        return issuance.IssuanceTransactionResponse, False
    if path == "/v1/issued-credentials":
        return issuance.IssuedCredentialRecordResponse, True
    if path.endswith("/renew"):
        return issuance.CredentialRenewalOfferResponse, False
    return issuance.IssuedCredentialRecordResponse, False


def test_legacy_gateway_executes_shared_issuance_projection_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["cases"]:
        model, many = _projection(case)
        response = issuance._sanitize_management_response(
            JSONResponse(case["input"]), model, many=many
        )
        assert json.loads(response.body) == case["expected"], case["name"]

    for case in CONTRACT["invalid_cases"]:
        model, many = _projection(case)
        with pytest.raises(HTTPException) as exc_info:
            issuance._sanitize_management_response(
                JSONResponse(case["input"]), model, many=many
            )
        assert exc_info.value.status_code == 502, case["name"]
