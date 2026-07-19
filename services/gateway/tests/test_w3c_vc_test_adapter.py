"""Tests for the deliberately gated W3C VC v2 interop adapter."""

from __future__ import annotations

import json
import sys
import types

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


def _valid_w3c_credential() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "https://issuer.example.test",
        "credentialSubject": {"id": "did:key:z6MkExample", "name": "Ada"},
    }


def test_issuer_adapter_keeps_only_supported_subject_claims() -> None:
    assert adapter._claims_from_w3c_credential(_valid_w3c_credential()) == {
        "id": "did:key:z6MkExample", "name": "Ada"
    }


def test_issuer_adapter_rejects_non_vcdm_input_before_issuance() -> None:
    invalid = _valid_w3c_credential()
    invalid["credentialSubject"] = []
    with pytest.raises(HTTPException) as exc_info:
        adapter._claims_from_w3c_credential(invalid)
    assert exc_info.value.status_code == 422


def test_issuer_adapter_requires_explicit_disposable_fixture_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_POLICY_ID", "fixture-policy")
    monkeypatch.delenv("W3C_VC_TEST_ORGANIZATION_ID", raising=False)
    monkeypatch.delenv("W3C_VC_TEST_TEMPLATE_ID", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        adapter._issuance_fixture_configuration()
    assert exc_info.value.status_code == 503


def test_issuer_adapter_wraps_only_a_compact_jwt_vc() -> None:
    envelope = adapter._jose_vc_envelope(_valid_w3c_credential(), "header.payload.signature")
    assert envelope["type"] == ["EnvelopedVerifiableCredential"]
    assert envelope["id"] == "data:application/vc+jwt,header.payload.signature"
    with pytest.raises(HTTPException):
        adapter._jose_vc_envelope(_valid_w3c_credential(), "not-a-jwt")


def test_issuer_adapter_source_defines_a_jwt_vc_fixture_contract() -> None:
    source = adapter._issue_jwt_vc.__code__.co_consts
    assert "W3C fixture template must issue JWT VC, not SD-JWT, mdoc, or JSON-LD" in source


def test_issuer_adapter_uses_the_released_oid4vci_proof_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def create_proof(issuer_url: str, nonce: str) -> str:
        captured.update({"issuer_url": issuer_url, "nonce": nonce})
        return "header.payload.signature"

    module = types.ModuleType("marty_rs")
    module._marty_rs = types.SimpleNamespace(oid4vci_create_proof_jwt=create_proof)
    monkeypatch.setitem(sys.modules, "marty_rs", module)

    proof = adapter._create_oid4vci_proof("https://issuer.example.test/org/fixture", "nonce-1")
    assert proof == "header.payload.signature"
    assert captured == {"issuer_url": "https://issuer.example.test/org/fixture", "nonce": "nonce-1"}


def test_issuer_adapter_generates_a_verifiable_oid4vci_proof() -> None:
    from marty_rs import _marty_rs as binding

    proof = adapter._create_oid4vci_proof("https://issuer.example.test/org/fixture", "nonce-1")
    verified = binding.oid4vci_verify_proof_jwt(
        proof, "nonce-1", "https://issuer.example.test/org/fixture"
    )
    holder_did, nonce = verified[:2]
    assert holder_did.startswith("did:key:")
    assert nonce == "nonce-1"


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
