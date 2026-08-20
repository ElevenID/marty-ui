"""Run service-sign authorization fixtures against the Python baseline."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gateway.routes import signing_keys


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-signing-authorization-behavior.json"
    ).read_text(encoding="utf-8")
)


def _request() -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/internal/signing-keys/services/service-1/sign",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {"session_organization_id": "org-1"},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=None)),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


class _Adapter:
    signature_encoding = "der"
    transcoded_signature = None

    async def sign(self, _config: dict, _payload: bytes) -> bytes:
        return b"signature"


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CONTRACT["cases"], ids=lambda case: case["name"])
async def test_python_service_signing_matches_shared_authorization_contract(
    monkeypatch, case
) -> None:
    service = {**CONTRACT["service"], "key_reference": case["request"].get("key_reference")}
    registry = {"services": [service], **case["registry"]}
    monkeypatch.setattr(
        signing_keys,
        "_resolve_effective_service",
        AsyncMock(return_value=(registry, service, service, False)),
    )
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda _service: _Adapter())
    monkeypatch.setattr(
        signing_keys, "_credential_issuer_key_references", AsyncMock(return_value=set())
    )

    if error := case.get("expected_error"):
        with pytest.raises(HTTPException) as exc_info:
            await signing_keys.sign_payload_with_service(
                _request(), "service-1", case["request"], "org-1"
            )
        assert exc_info.value.status_code == error["status"]
        assert error["contains"] in str(exc_info.value.detail)
        return

    response = await signing_keys.sign_payload_with_service(
        _request(), "service-1", case["request"], "org-1"
    )
    actual = json.loads(response.body)
    assert actual["algorithm"] == case["expected"]["algorithm"]
    assert bytes.fromhex(case["expected"]["payload_hex"]) == b"payload"
    assert actual["payload_length"] == 7
