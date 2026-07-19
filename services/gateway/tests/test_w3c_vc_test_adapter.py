"""Tests for the deliberately gated W3C VC v2 interop adapter."""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gateway.routes import w3c_vc_test_adapter as adapter


def _request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/__test__/vc-api/credentials/verify", "headers": []})


def test_adapter_is_disabled_without_explicit_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("W3C_VC_TEST_ADAPTER", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        adapter._enabled_policy_id()
    assert exc_info.value.status_code == 404


def test_adapter_rejects_unimplemented_json_ld_proofs() -> None:
    with pytest.raises(HTTPException) as exc_info:
        adapter._token_or_unsupported({"proof": {"cryptosuite": "eddsa-rdfc-2022"}}, "verifiableCredential")
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["error"] == "unsupported_serialization"


def test_adapter_extracts_a_w3c_jose_vc_envelope_without_trusting_it() -> None:
    token = adapter._token_or_unsupported(
        {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["EnvelopedVerifiableCredential"],
            "id": "data:application/vc%2Bjwt,header.payload.signature",
        },
        "verifiableCredential",
    )
    assert token == "header.payload.signature"


@pytest.mark.parametrize("identifier", [
    "data:application/vc+jwt,not-a-jws",
    "data:application/ld+json,header.payload.signature",
    "https://example.test/credential",
])
def test_adapter_rejects_invalid_or_unsupported_jose_envelopes(identifier: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        adapter._token_or_unsupported(
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["EnvelopedVerifiableCredential"],
                "id": identifier,
            },
            "verifiableCredential",
        )
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_adapter_forwards_supported_token_to_actual_policy_evaluator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_POLICY_ID", "fixture-policy")

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            assert name == "presentation-policies"
            return "http://presentation-policy"

    captured: dict[str, object] = {}

    async def fake_proxy(request, service_url, path, **kwargs):
        captured.update({"service_url": service_url, "path": path, **kwargs})
        return "actual-policy-response"

    monkeypatch.setattr(adapter, "get_registry", lambda: Registry())
    monkeypatch.setattr(adapter, "proxy_request", fake_proxy)

    response = await adapter._evaluate("header.payload.signature", {"challenge": "n", "domain": "aud"}, _request())

    assert response == "actual-policy-response"
    assert captured["path"] == "/v1/presentation-policies/fixture-policy/evaluate"
    assert json.loads(captured["body_override"]) == {
        "vp_token": "header.payload.signature", "nonce": "n", "audience": "aud"
    }
    assert captured["inject_headers"] == {"Content-Type": "application/json"}
