"""Run the language-neutral VC-API adapter contract against the Python baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from gateway.routes import vc_api
from starlette.requests import Request
from starlette.responses import Response


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "vc-api-adapter-behavior.json").read_text(
        encoding="utf-8"
    )
)


def _request() -> Request:
    request = Request(
        {"type": "http", "method": "POST", "path": "/v1/vc-api/credentials/verify", "headers": []}
    )
    request.state.organization_id = "org-1"
    return request


def test_python_serialization_and_offer_baseline_matches_shared_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["serialization"]:
        try:
            result = vc_api._token_or_unsupported(case["input"], case["field"])
        except HTTPException as exc:
            assert case["error"] is not None, case["name"]
            assert exc.status_code == 422
            assert exc.detail["error"] == case["error"], case["name"]
        else:
            assert case["error"] is None, case["name"]
            assert result == case["expected"], case["name"]

    for case in CONTRACT["offers"]:
        try:
            configuration_id, code = vc_api._parse_inline_credential_offer(
                case["uri"], expected_issuer=case["expected_issuer"]
            )
        except ValueError as exc:
            assert str(exc) == case["error"], case["name"]
        else:
            assert case["error"] is None, case["name"]
            assert configuration_id == case["configuration_id"], case["name"]
            assert code == case["pre_authorized_code"], case["name"]


@pytest.mark.asyncio
async def test_python_evaluation_baseline_matches_shared_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Registry:
        @staticmethod
        def get_service_url(_name: str) -> str:
            return "http://presentation-policy"

    monkeypatch.setattr(vc_api, "get_registry", lambda: Registry())
    for case in CONTRACT["evaluations"]:
        async def proxy(*_args, _payload=case["input"], **_kwargs):
            return Response(content=json.dumps(_payload), media_type="application/json")

        monkeypatch.setattr(vc_api, "proxy_request", proxy)
        try:
            response = await vc_api._evaluate(
                "header.payload.signature",
                {},
                _request(),
                organization_id="org-1",
                policy_id="policy-1",
            )
        except HTTPException as exc:
            assert case["error"] == "invalid_policy_response", case["name"]
            assert exc.status_code == case["status"]
        else:
            assert case["error"] is None, case["name"]
            assert response.status_code == case["status"], case["name"]
            assert json.loads(response.body) == case["output"], case["name"]
