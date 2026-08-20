"""Run issuer-context fixtures against the Python compatibility baseline."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from gateway.routes import signing_keys


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-issuer-context-behavior.json"
    ).read_text(encoding="utf-8")
)


def _request(organization_id: str) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/internal/signing-keys/issuer-context",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {"session_organization_id": organization_id},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=None)),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


@pytest.mark.asyncio
async def test_python_issuer_context_matches_shared_contract(monkeypatch) -> None:
    request_case = CONTRACT["request"]
    profile = CONTRACT["profile_document"]["profiles"][0]
    registry = CONTRACT["registry"]
    service = {**registry["services"][0], **CONTRACT["certificates"]["services"]["service-1"]}
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    monkeypatch.setattr(
        signing_keys, "find_native_issuer_profiles", AsyncMock(return_value=[profile])
    )
    monkeypatch.setattr(
        signing_keys,
        "_resolve_effective_service",
        AsyncMock(return_value=(registry, registry["services"][0], service, False)),
    )
    monkeypatch.setattr(
        signing_keys, "_assert_issuer_profile_compatible", AsyncMock(return_value=None)
    )
    monkeypatch.setattr(
        signing_keys, "_resolve_service_for_format", AsyncMock(return_value=service)
    )
    monkeypatch.setattr(
        signing_keys, "_service_x5c_chain", lambda value: value.get("x5c", [])
    )

    response = await signing_keys.internal_resolve_issuer_context(
        request=_request(request_case["organization_id"]),
        organization_id=request_case["organization_id"],
        issuer_did=request_case["issuer_did"],
        issuer_mode=request_case["issuer_mode"],
        credential_format=request_case["credential_format"],
        key_purpose=request_case["key_purpose"],
        algorithm=request_case["algorithm"],
        x_api_key="test-internal-key",
    )
    assert json.loads(response.body) == CONTRACT["expected"]
