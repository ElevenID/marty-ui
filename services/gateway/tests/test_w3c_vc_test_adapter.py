"""Tests for the deliberately gated W3C VC v2 interop adapter."""

from __future__ import annotations

import json
import sys
import types

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from gateway.routes import w3c_vc_test_adapter as adapter


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/__test__/vc-api/credentials/verify",
            "headers": [],
        }
    )


def test_adapter_is_disabled_without_explicit_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("W3C_VC_TEST_ADAPTER", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        adapter._enabled_policy_id(presentation=False)
    assert exc_info.value.status_code == 404


def test_adapter_rejects_unimplemented_json_ld_proofs() -> None:
    with pytest.raises(HTTPException) as exc_info:
        adapter._token_or_unsupported(
            {"proof": {"cryptosuite": "eddsa-rdfc-2022"}}, "verifiableCredential"
        )
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["error"] == "unsupported_serialization"


def _official_baseline_credential() -> dict:
    """Pinned-suite credential-ok.json before its client injects issuer."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "credentialSubject": {"id": "did:example:subject"},
    }


def test_issuer_adapter_has_no_test_owned_credential_semantic_validator() -> None:
    assert not hasattr(adapter, "_validate_w3c_vcdm_credential")
    assert not hasattr(adapter, "_validate_related_resource_digests")


def test_issuer_adapter_requires_explicit_disposable_fixture_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_CREDENTIAL_POLICY_ID", "fixture-policy")
    monkeypatch.delenv("W3C_VC_TEST_ORGANIZATION_ID", raising=False)
    monkeypatch.delenv("W3C_VC_TEST_TEMPLATE_ID", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        adapter._issuance_fixture_configuration()
    assert exc_info.value.status_code == 503


def test_issuer_adapter_source_defines_a_native_data_integrity_fixture_contract() -> (
    None
):
    source = adapter._issue_data_integrity_credential.__code__.co_consts
    assert (
        "W3C fixture template must issue native VCDM v2 Data Integrity credentials"
        in source
    )


def test_issuer_adapter_uses_the_released_oid4vci_proof_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    def create_proof(issuer_url: str, nonce: str) -> str:
        captured.update({"issuer_url": issuer_url, "nonce": nonce})
        return "header.payload.signature"

    module = types.ModuleType("marty_rs")
    module._marty_rs = types.SimpleNamespace(oid4vci_create_proof_jwt=create_proof)
    monkeypatch.setitem(sys.modules, "marty_rs", module)

    proof = adapter._create_oid4vci_proof(
        "https://issuer.example.test/org/fixture", "nonce-1"
    )
    assert proof == "header.payload.signature"
    assert captured == {
        "issuer_url": "https://issuer.example.test/org/fixture",
        "nonce": "nonce-1",
    }


@pytest.mark.asyncio
async def test_issuer_adapter_sends_complete_unsigned_document_to_production_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_CREDENTIAL_POLICY_ID", "fixture-policy")
    monkeypatch.setenv("W3C_VC_TEST_ORGANIZATION_ID", "fixture-org")
    monkeypatch.setenv("W3C_VC_TEST_TEMPLATE_ID", "fixture-template")
    credential = _official_baseline_credential()
    credential["credentialSubject"] = [
        {"id": "did:example:subject"},
        {"id": "did:example:other:subject"},
    ]
    credential["name"] = {"@value": "Official fixture", "@language": "en"}
    credential["validFrom"] = "2026-07-28T00:00:00Z"

    class Response:
        def __init__(self, body: dict) -> None:
            self.status_code = 200
            self._body = body
            self.text = json.dumps(body)

        def json(self) -> dict:
            return self._body

    captured: list[tuple[str, dict]] = []

    class Client:
        async def post(self, url: str, **kwargs):
            captured.append((url, kwargs))
            if url.endswith("/initiate"):
                return Response({"pre_auth_code": "pre-auth"})
            if url.endswith("/token"):
                return Response({"access_token": "access-token"})
            if url.endswith("/nonce"):
                return Response({"c_nonce": "nonce"})
            return Response(
                {
                    "credentials": [
                        {
                            "format": "ldp_vc",
                            "credential": {
                                "@context": ["https://www.w3.org/ns/credentials/v2"],
                                "type": ["VerifiableCredential"],
                                "issuer": "did:web:issuer.example",
                                "credentialSubject": credential["credentialSubject"],
                                "proof": {
                                    "type": "DataIntegrityProof",
                                    "cryptosuite": "eddsa-rdfc-2022",
                                    "verificationMethod": (
                                        "did:web:issuer.example#data-integrity"
                                    ),
                                    "proofPurpose": "assertionMethod",
                                    "proofValue": "zProof",
                                },
                            },
                        }
                    ]
                }
            )

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            assert name == "issuance"
            return "http://issuance"

    async def load_template(template_id: str, request: Request) -> dict:
        return {
            "id": template_id,
            "organization_id": "fixture-org",
            "credential_payload_format": "w3c_vcdm_v2_di",
            "issuer_did": "did:web:issuer.example",
        }

    async def resolve_identity(*args, **kwargs) -> dict:
        return {
            "issuer_profile_id": "issuer-profile",
            "signing_service_id": "signing-service",
            "issuer_did": "did:web:issuer.example",
            "algorithm": "EdDSA",
        }

    monkeypatch.setattr(adapter, "_load_credential_template", load_template)
    monkeypatch.setattr(adapter, "_resolve_issuer_identity", resolve_identity)
    monkeypatch.setattr(
        adapter, "_create_oid4vci_proof", lambda issuer, nonce: "proof.jwt.value"
    )
    monkeypatch.setattr(adapter, "get_registry", lambda: Registry())
    monkeypatch.setattr(adapter, "get_http_client", lambda: Client())

    issued = await adapter._issue_data_integrity_credential(
        credential,
        _request(),
    )
    assert issued["proof"]["cryptosuite"] == "eddsa-rdfc-2022"
    initiate_body = captured[0][1]["json"]
    assert "claims" not in initiate_body
    assert "credential_subject" not in initiate_body
    assert initiate_body["credential_document"] == credential
    assert initiate_body["issuer_did"] == "did:web:issuer.example"
    public_headers = {name.lower() for name in captured[0][1]["headers"]}
    assert {
        "x-issuer-profile-id",
        "x-issuer-did",
        "x-signing-service-id",
        "x-signing-key-reference",
    }.isdisjoint(public_headers)
    credential_request = captured[3][1]["json"]
    assert credential_request == {
        "format": "ldp_vc",
        "proofs": {"jwt": ["proof.jwt.value"]},
    }


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


def test_adapter_extracts_official_suite_scalar_context_envelope() -> None:
    token = adapter._token_or_unsupported(
        {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": "EnvelopedVerifiableCredential",
            "id": "data:application/vc+jwt,header.payload.signature",
        },
        "verifiableCredential",
    )
    assert token == "header.payload.signature"


def test_adapter_preserves_data_integrity_document_for_production_verifier() -> None:
    document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
        },
    }
    assert adapter._token_or_unsupported(document, "verifiableCredential") is document


@pytest.mark.parametrize(
    "identifier",
    [
        "data:application/vc+jwt,not-a-jws",
        "data:application/ld+json,header.payload.signature",
        "https://example.test/credential",
    ],
)
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
async def test_adapter_forwards_supported_token_to_actual_policy_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_CREDENTIAL_POLICY_ID", "fixture-policy")

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            assert name == "presentation-policies"
            return "http://presentation-policy"

    captured: dict[str, object] = {}

    async def fake_proxy(request, service_url, path, **kwargs):
        captured.update({"service_url": service_url, "path": path, **kwargs})
        return Response(
            content=json.dumps({"result": "passed", "decision": "allow"}),
            media_type="application/json",
        )

    monkeypatch.setattr(adapter, "get_registry", lambda: Registry())
    monkeypatch.setattr(adapter, "proxy_request", fake_proxy)

    response = await adapter._evaluate(
        "header.payload.signature",
        {"challenge": "n", "domain": "aud"},
        _request(),
        presentation=False,
    )

    assert response.status_code == 200
    assert json.loads(response.body)["verified"] is True
    assert captured["path"] == "/v1/presentation-policies/fixture-policy/evaluate"
    assert json.loads(captured["body_override"]) == {
        "vp_token": "header.payload.signature",
        "nonce": "n",
        "audience": "aud",
    }
    assert captured["inject_headers"] == {"Content-Type": "application/json"}


@pytest.mark.asyncio
async def test_adapter_forwards_data_integrity_document_without_stringifying_it_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_PRESENTATION_POLICY_ID", "fixture-policy")
    document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "proof": {"type": "DataIntegrityProof"},
    }

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            return "http://presentation-policy"

    captured: dict[str, object] = {}

    async def fake_proxy(request, service_url, path, **kwargs):
        captured.update(kwargs)
        return Response(
            content=json.dumps({"result": "passed", "decision": "allow"}),
            media_type="application/json",
        )

    monkeypatch.setattr(adapter, "get_registry", lambda: Registry())
    monkeypatch.setattr(adapter, "proxy_request", fake_proxy)

    response = await adapter._evaluate(
        document,
        {"challenge": "n", "domain": "aud"},
        _request(),
        presentation=True,
    )
    assert response.status_code == 200
    assert json.loads(response.body)["verified"] is True
    assert json.loads(captured["body_override"])["vp_token"] == document


@pytest.mark.asyncio
async def test_adapter_maps_policy_denial_to_vc_api_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("W3C_VC_TEST_ADAPTER", "1")
    monkeypatch.setenv("W3C_VC_TEST_CREDENTIAL_POLICY_ID", "fixture-policy")

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            return "http://presentation-policy"

    async def fake_proxy(*args, **kwargs):
        return Response(
            content=json.dumps({"result": "failed", "decision": "deny"}),
            media_type="application/json",
        )

    monkeypatch.setattr(adapter, "get_registry", lambda: Registry())
    monkeypatch.setattr(adapter, "proxy_request", fake_proxy)

    response = await adapter._evaluate("a.b.c", {}, _request(), presentation=False)
    assert response.status_code == 422
    assert json.loads(response.body) == {
        "verified": False,
        "errors": ["verification_failed"],
    }
