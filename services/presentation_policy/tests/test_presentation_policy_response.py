"""Protocol conformance tests for presentation-policy REST responses."""

from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import (
    OrganizationMembership,
    OrganizationRoleSummary,
)
import pytest

from services.presentation_policy import main as pp

# Protocol-allowed top-level keys (presentation-policy.json schema)
PROTOCOL_KEYS = {
    "id",
    "organization_id",
    "name",
    "status",
    "description",
    "purpose",
    "required_claims",
    "accepted_credential_types",
    "trust_profile_id",
    "holder_binding",
    "freshness",
    "prefer_predicates",
    "supported_circuits",
    "fallback_policy",
    "issuer_constraints",
    "credential_ranking_strategy",
    "credential_ranking_weights",
    "created_at",
    "updated_at",
}


def _build_client(
    repo: pp.InMemoryPresentationPolicyRepository,
) -> TestClient:
    app = FastAPI()
    app.include_router(pp.router)
    pp._repo = repo

    org_client = SimpleNamespace(
        get_membership=AsyncMock(
            return_value=OrganizationMembership(
                user_id="user-1",
                organization_id="org-1",
                status="active",
                roles=[
                    OrganizationRoleSummary(
                        id="role-admin", name="admin", display_name="Admin"
                    )
                ],
                permissions={
                    "presentation-policy:view",
                    "presentation-policy:create",
                    "presentation-policy:edit",
                    "presentation-policy:delete",
                    "presentation-policy:activate",
                    "presentation-policy:suspend",
                    "presentation-policy:version",
                    "presentation-policy:evaluate",
                },
                has_org_console_access=True,
            )
        )
    )
    app.state.org_client = org_client
    pp.app.state.org_client = org_client
    return TestClient(app, headers={"X-User-Id": "user-1"})


async def _save_policy(
    repo: pp.InMemoryPresentationPolicyRepository,
) -> pp.PresentationPolicy:
    policy = pp.PresentationPolicy(
        organization_id="org-1",
        name="Age Gate",
        description="Verify age for access",
        purpose="Age verification for entry",
    )
    policy.required_claims = [
        pp.RequestedClaim(
            claim_name="date_of_birth",
            display_name="Date of Birth",
            predicate_spec={
                "predicate_type": "RANGE_PROOF",
                "params": {"min_age": 21},
            },
        ),
    ]
    policy.accepted_credential_types = ["IdentityCredential"]
    policy.holder_binding = pp.HolderBinding(
        required=True,
        binding_methods=["CREDENTIAL_KEY"],
        proof_profiles=["SD_JWT_KEY_BINDING"],
        proof_freshness={
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    )
    policy.freshness = pp.FreshnessPolicy(
        max_age_seconds=3600, require_not_revoked=True
    )
    policy.issuer_constraints = pp.IssuerConstraints(
        min_trust_level=50,
        required_compliance_statuses=["COMPLIANT"],
    )
    policy.credential_ranking_strategy = "HIGHEST_TRUST_FIRST"
    policy.prefer_predicates = True
    policy.fallback_policy = "ACCEPT_RAW"
    policy.supported_circuits = ["ligero_age_over_21"]
    await repo.save(policy)
    return policy


def test_get_presentation_policy_returns_protocol_shape_only() -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_policy(repo))
    client = _build_client(repo)

    response = client.get(
        f"/v1/presentation-policies/{policy.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()

    # Every key must be protocol-allowed
    assert set(body.keys()) <= PROTOCOL_KEYS, (
        f"Extra keys: {set(body.keys()) - PROTOCOL_KEYS}"
    )

    # Required protocol fields present
    assert body["id"] == policy.id
    assert body["organization_id"] == "org-1"
    assert body["name"] == "Age Gate"
    assert body["status"] == "draft"
    assert body["description"] == "Verify age for access"
    assert body["purpose"] == "Age verification for entry"

    # required_claims round-trips with protocol shape
    claims = body["required_claims"]
    assert len(claims) == 1
    assert claims[0]["claim_name"] == "date_of_birth"
    assert claims[0]["credential_type"] == "IdentityCredential"
    assert claims[0]["predicate_spec"]["predicate_type"] == "RANGE_PROOF"

    # Nested protocol objects
    assert body["holder_binding"]["required"] is True
    assert "CREDENTIAL_KEY" in body["holder_binding"]["binding_methods"]
    assert body["holder_binding"]["proof_profiles"] == ["SD_JWT_KEY_BINDING"]
    assert body["holder_binding"]["proof_freshness"]["challenge_required"] is True
    assert body["freshness"]["max_age_seconds"] == 3600
    assert body["issuer_constraints"]["min_trust_level"] == 50
    assert body["credential_ranking_strategy"] == "HIGHEST_TRUST_FIRST"
    assert body["prefer_predicates"] is True
    assert body["fallback_policy"] == "ACCEPT_RAW"
    assert "ligero_age_over_21" in body["supported_circuits"]

    # Legacy fields must NOT be present
    for legacy_key in (
        "display_metadata",
        "credential_requirements",
        "alternative_requirements",
        "compliance_profile_id",
        "version",
    ):
        assert legacy_key not in body, (
            f"Legacy key {legacy_key!r} must not appear in protocol response"
        )


def test_create_presentation_policy_accepts_protocol_required_claims() -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    client = _build_client(repo)

    response = client.post(
        "/v1/presentation-policies",
        json={
            "organization_id": "org-1",
            "name": "Quick Check",
            "purpose": "License verification",
            "required_claims": [
                {"claim_name": "license_number", "credential_type": "DriversLicense"},
                {"claim_name": "expiry_date"},
            ],
            "accepted_credential_types": ["DriversLicense"],
            "holder_binding": {"required": False},
        },
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) <= PROTOCOL_KEYS

    claims = body["required_claims"]
    claim_names = [c["claim_name"] for c in claims]
    assert "license_number" in claim_names
    assert "expiry_date" in claim_names
    assert body["accepted_credential_types"] == ["DriversLicense"]


def test_activate_keeps_protocol_shape_stable() -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_policy(repo))

    # Activation needs credential_requirements internally
    cred_req = pp.CredentialRequirement(
        credential_template_id="IdentityCredential",
        display_name="Identity",
        requested_claims=list(policy.required_claims),
    )
    policy.credential_requirements = [cred_req]
    asyncio.run(repo.save(policy))

    client = _build_client(repo)

    response = client.post(
        f"/v1/presentation-policies/{policy.id}/activate",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) <= PROTOCOL_KEYS
    assert body["status"] == "active"
    assert "credential_requirements" not in body


def test_detect_credential_format_recognizes_json_open_badge_v3() -> None:
    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {
            "id": "did:example:holder",
            "achievement": {"name": "Marty Login Badge"},
        },
    }

    assert (
        pp._detect_credential_format(json.dumps({"credential": credential}))
        == "openbadge-v3"
    )


def test_detect_credential_format_recognizes_vcdm_data_integrity_object() -> None:
    document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
        },
    }
    assert pp._detect_credential_format(document) == "w3c-vcdm-di"


def test_vcdm_candidate_detection_leaves_context_acceptance_to_released_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = {
        "@context": ["https://example.invalid/not-the-vcdm-context"],
        "type": ["VerifiableCredential"],
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "proofValue": "zInvalid",
        },
    }
    requests: list[dict] = []

    def reject(request_json: str) -> str:
        requests.append(json.loads(request_json))
        return json.dumps(
            {
                "valid": False,
                "kind": "credential",
                "verified_proofs": 0,
                "verified_credentials": 0,
                "errors": ["invalid context"],
            }
        )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_data_integrity=reject),
    )

    credential_format = pp._detect_credential_format(document)
    result = pp._verify_credential_by_format(
        document,
        credential_format,
        None,
        None,
    )

    assert credential_format == "w3c-vcdm-di"
    assert result["verified"] is False
    assert result["claims"] == {}
    assert requests == [{"document": document}]


def test_detect_credential_format_recognizes_base64url_mdoc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed: list[bytes] = []
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(
            parse_device_response=lambda value: parsed.append(bytes(value))
        ),
    )
    token = base64.urlsafe_b64encode(b"\xa1aa\x01").rstrip(b"=").decode()

    assert pp._detect_credential_format(token) == "mdoc"
    assert parsed == [b"\xa1aa\x01"]


def test_mdoc_verification_requires_trust_and_verifier_session_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes, list[str], list[str]]] = []

    def verify_presentation(
        mdoc_bytes: bytes,
        transcript_bytes: bytes,
        roots: list[str],
        pinned_issuers: list[str],
    ) -> SimpleNamespace:
        calls.append(
            (bytes(mdoc_bytes), bytes(transcript_bytes), roots, pinned_issuers)
        )
        return SimpleNamespace(
            issuer_signature_valid=True,
            issuer_trusted=True,
            device_authentication_valid=True,
            document_types=["org.iso.18013.5.1.mDL"],
            error=None,
        )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(
            verify_mdoc_presentation=verify_presentation,
            verify_mdoc_cbor=lambda _value: {"given_name": "Ada"},
        ),
    )
    mdoc_bytes = b"\xa1aa\x01"
    transcript = b"\x83\xf6\xf6\x82qOpenID4VPHandoverX"
    result = pp._verify_mdoc(
        base64.urlsafe_b64encode(mdoc_bytes).rstrip(b"=").decode(),
        "nonce-1",
        "did:web:verifier.example",
        {
            "mdoc_session_transcript_b64url": base64.urlsafe_b64encode(transcript)
            .rstrip(b"=")
            .decode(),
            "oid4vp_client_id": "did:web:verifier.example",
        },
        ["-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"],
        ["-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----"],
    )

    assert result["verified"] is True
    assert result["claims"] == {"given_name": "Ada"}
    assert calls == [
        (
            mdoc_bytes,
            transcript,
            ["-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"],
            ["-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----"],
        )
    ]


def test_mdoc_trust_material_preserves_root_and_direct_pin_semantics() -> None:
    root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"
    pinned = "-----BEGIN CERTIFICATE-----\npinned\n-----END CERTIFICATE-----"
    ignored = "-----BEGIN CERTIFICATE-----\nignored\n-----END CERTIFICATE-----"

    roots, pinned_issuers = pp._mdoc_trust_certificates_pem(
        {
            "trust_sources": [
                {
                    "source_type": "ROOT_CA",
                    "certificate_pem": root,
                    "pinned_certificates": [root],
                },
                {
                    "source_type": "PINNED_ISSUER",
                    "certificate_pem": pinned,
                },
                {
                    "source_type": "TRUST_LIST",
                    "certificate_pem": ignored,
                },
                {
                    "source_type": "PINNED_ISSUER",
                    "certificate_pem": ignored,
                    "enabled": False,
                },
            ]
        }
    )

    assert roots == [root]
    assert pinned_issuers == [pinned]


def test_mdoc_evaluation_always_binds_nonce_and_audience(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    policy.credential_requirements[0].credential_payload_format = "mso_mdoc"
    policy.holder_binding = pp.HolderBinding(required=False)
    asyncio.run(repo.save(policy))
    _install_marty_trust_profile(
        monkeypatch,
        allowed_issuers=[],
        trust_sources=[
            {
                "source_type": "ROOT_CA",
                "certificate_pem": (
                    "-----BEGIN CERTIFICATE-----\nanchor\n-----END CERTIFICATE-----"
                ),
            }
        ],
    )
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "mdoc")
    captured: dict[str, object] = {}

    def _verify(*args, **_kwargs):
        captured.update(
            nonce=args[2],
            audience=args[3],
            context=args[5],
            anchors=args[6],
        )
        return {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "unknown",
            "format": "mdoc",
            "error": None,
        }

    monkeypatch.setattr(pp, "_verify_credential_by_format", _verify)
    context = {
        "mdoc_session_transcript_b64url": "gw",
        "oid4vp_client_id": "did:web:verifier.example",
    }
    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(
                vp_token="device-response",
                nonce="nonce-1",
                audience="did:web:verifier.example",
                context=context,
            ),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert captured == {
        "nonce": "nonce-1",
        "audience": "did:web:verifier.example",
        "context": context,
        "anchors": ["-----BEGIN CERTIFICATE-----\nanchor\n-----END CERTIFICATE-----"],
    }


def test_vcdm_data_integrity_uses_released_binding_and_extracts_verified_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict] = []

    def verify(request_json: str) -> str:
        requests.append(json.loads(request_json))
        return json.dumps(
            {
                "valid": True,
                "kind": "presentation",
                "verified_proofs": 1,
                "verified_credentials": 1,
                "errors": [],
            }
        )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_data_integrity=verify),
    )
    credential = {
        "type": ["VerifiableCredential"],
        "issuer": "did:key:issuer",
        "credentialSubject": {"id": "did:key:holder", "role": "member"},
    }
    document = {
        "type": ["VerifiablePresentation"],
        "holder": "did:key:holder",
        "verifiableCredential": [credential],
    }

    result = pp._verify_vcdm_data_integrity(document, "challenge", "verifier")

    assert result["verified"] is True
    assert result["issuer_did"] == "did:key:issuer"
    assert result["claims"] == {"id": "did:key:holder", "role": "member"}
    assert requests == [
        {
            "document": document,
            "expected_challenge": "challenge",
            "expected_domain": "verifier",
        }
    ]


def test_vcdm_data_integrity_resolves_exact_did_web_assertion_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "did:web:issuer.example:orgs:tenant-a"
    method_id = f"{issuer}#key-1"
    public_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYLefYxWxTqvCxbM9Apl1LrLJx8hHf9L8XvN4gk",
    }
    document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "credentialSubject": {"id": "did:example:holder", "role": "member"},
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": method_id,
            "proofValue": "zProof",
        },
    }
    did_document = {
        "id": issuer,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "Multikey",
                "controller": issuer,
                "publicKeyJwk": public_jwk,
            }
        ],
        "assertionMethod": [method_id],
    }
    captured: list[dict] = []

    monkeypatch.setattr(pp, "_resolve_did_document", lambda did: did_document)
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(
            verify_vcdm_data_integrity=lambda request: (
                captured.append(json.loads(request))
                or json.dumps(
                    {
                        "valid": True,
                        "kind": "credential",
                        "verified_proofs": 1,
                        "verified_credentials": 1,
                        "errors": [],
                    }
                )
            )
        ),
    )

    result = pp._verify_vcdm_data_integrity(document, None, None)

    assert result["verified"] is True
    assert captured == [
        {
            "document": document,
            "resolved_verification_methods": [
                {
                    "id": method_id,
                    "controller": issuer,
                    "public_jwk": public_jwk,
                }
            ],
        }
    ]


def test_did_resolver_skips_a_candidate_with_the_wrong_document_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did = "did:web:issuer.example:orgs:tenant-a"
    candidates = [
        "http://gateway:8000/orgs/tenant-a/did.json",
        "https://issuer.example/orgs/tenant-a/did.json",
    ]
    requested: list[str] = []

    class Response:
        status_code = 200

        def __init__(self, document: dict) -> None:
            self._document = document

        def json(self) -> dict:
            return self._document

    def get(url: str, **_kwargs) -> Response:
        requested.append(url)
        if url == candidates[0]:
            return Response({"id": "did:web:gateway.example:orgs:tenant-a"})
        return Response({"id": did, "verificationMethod": []})

    monkeypatch.setattr(pp, "_did_resolution_candidate_urls", lambda _did: candidates)
    monkeypatch.setattr("httpx.get", get)

    assert pp._resolve_did_document(did)["id"] == did
    assert requested == candidates


def test_vcdm_data_integrity_rejects_cross_tenant_proof_before_rust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "did:web:issuer.example:orgs:tenant-a"
    attacker = "did:web:issuer.example:orgs:tenant-b"
    binding_called = False

    def verify(_request: str) -> str:
        nonlocal binding_called
        binding_called = True
        return json.dumps({"valid": True, "errors": []})

    monkeypatch.setattr(
        pp,
        "_resolve_did_document",
        lambda _did: pytest.fail("cross-tenant DID must fail before resolution"),
    )
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_data_integrity=verify),
    )
    document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "credentialSubject": {"id": "did:example:holder"},
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{attacker}#key-1",
            "proofValue": "zProof",
        },
    }

    result = pp._verify_vcdm_data_integrity(document, None, None)

    assert result["verified"] is False
    assert result["claims"] == {}
    assert binding_called is False
    assert "tenant-b" not in result["error"]


def test_vcdm_data_integrity_fails_closed_without_leaking_engine_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = SimpleNamespace(
        verify_vcdm_data_integrity=lambda _request: json.dumps(
            {"valid": False, "errors": ["cryptographic implementation detail"]}
        )
    )
    monkeypatch.setattr(pp, "_load_marty_rs_binding", lambda: binding)

    result = pp._verify_vcdm_data_integrity(
        {"type": ["VerifiableCredential"]}, None, None
    )

    assert result["verified"] is False
    assert result["claims"] == {}
    assert "cryptographic implementation detail" not in result["error"]


def _jwt_segment(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_w3c_vc_uses_public_issuer_profile_did_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "did:web:issuer.example:profiles:university"
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "public-x",
        "y": "public-y",
    }
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "typ": "JWT", "kid": f"{issuer}#key-1"}),
            _jwt_segment(
                {
                    "iss": issuer,
                    "vc": {
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "type": ["VerifiableCredential"],
                        "issuer": issuer,
                        "credentialSubject": {
                            "id": "did:example:alice",
                            "role": "student",
                        },
                    },
                }
            ),
            "signature",
        ]
    )
    captured: dict[str, object] = {}

    def verify(request_json: str) -> str:
        captured.update(json.loads(request_json))
        return json.dumps(
            {
                "valid": True,
                "algorithm": "ES256",
                "issuer": issuer,
                "claims": {
                    "iss": issuer,
                    "jti": "urn:uuid:credential-123",
                    "vc": {
                        "id": "urn:uuid:credential-123",
                        "credentialSubject": {
                            "id": "did:example:alice",
                            "role": "student",
                        },
                    },
                },
                "errors": [],
            }
        )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_jwt=verify),
    )

    result = pp._verify_w3c_vc(token, None, None, public_jwk)

    assert result["verified"] is True
    assert result["issuer_did"] == issuer
    assert result["claims"] == {"id": "did:example:alice", "role": "student"}
    assert result["credential_id"] == "urn:uuid:credential-123"
    assert captured == {"token": token, "issuer_public_jwk": public_jwk}
    assert all(parameter not in json.dumps(captured) for parameter in ('"d"', '"k"'))


def test_w3c_vc_did_key_resolution_stays_inside_rust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "did:key:z6MkhIssuer"
    token = ".".join(
        [
            _jwt_segment({"alg": "EdDSA", "kid": f"{issuer}#z6MkhIssuer"}),
            _jwt_segment(
                {
                    "iss": issuer,
                    "vc": {"credentialSubject": {"id": "did:example:alice"}},
                }
            ),
            "signature",
        ]
    )
    captured: dict[str, object] = {}

    def verify(request_json: str) -> str:
        captured.update(json.loads(request_json))
        return json.dumps(
            {
                "valid": True,
                "issuer": issuer,
                "claims": {"vc": {"credentialSubject": {"id": "did:example:alice"}}},
                "errors": [],
            }
        )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_jwt=verify),
    )
    monkeypatch.setattr(
        pp,
        "_resolve_did_document",
        lambda _did: pytest.fail("did:key must be resolved by the Rust verifier"),
    )

    result = pp._verify_w3c_vc(token, None, None)

    assert result["verified"] is True
    assert captured == {"token": token}


def test_w3c_vc_does_not_expose_unverified_credential_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "did:web:issuer.example"
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "kid": f"{issuer}#key-1"}),
            _jwt_segment({"iss": issuer, "jti": "caller-controlled-id"}),
            "signature",
        ]
    )
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(
            verify_vcdm_jwt=lambda _request: json.dumps(
                {
                    "valid": False,
                    "issuer": issuer,
                    "claims": {
                        "jti": "caller-controlled-id",
                        "vc": {"id": "caller-controlled-vc-id"},
                    },
                    "errors": ["signature is invalid"],
                }
            )
        ),
    )
    monkeypatch.setattr(
        pp,
        "_resolve_did_document",
        lambda _issuer: {
            "id": issuer,
            "verificationMethod": [
                {
                    "id": f"{issuer}#key-1",
                    "controller": issuer,
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                    },
                }
            ],
        },
    )

    result = pp._verify_w3c_vc(token, None, None)

    assert result["verified"] is False
    assert result["credential_id"] is None
    assert result["claims"] == {}


def test_w3c_vc_fails_closed_without_profile_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "https://issuer.example"
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256"}),
            _jwt_segment(
                {
                    "iss": issuer,
                    "vc": {"credentialSubject": {"id": "did:example:alice"}},
                }
            ),
            "signature",
        ]
    )
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_vcdm_jwt=lambda _request: pytest.fail()),
    )

    def fail_resolution(_did: str) -> dict:
        raise RuntimeError("no issuer profile DID key")

    monkeypatch.setattr(pp, "_resolve_did_document", fail_resolution)

    result = pp._verify_w3c_vc(token, None, None)

    assert result["verified"] is False
    assert result["claims"] == {}
    assert "no issuer profile DID key" in result["error"]


def test_w3c_vc_logs_only_fixed_verifier_error_categories(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    issuer = "did:web:issuer.example:profiles:private"
    kid = f"{issuer}#secret-key-name"
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "kid": kid}),
            _jwt_segment(
                {
                    "iss": issuer,
                    "vc": {
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "type": ["VerifiableCredential"],
                        "issuer": issuer,
                        "credentialSubject": {"id": "did:example:alice"},
                    },
                }
            ),
            "signature",
        ]
    )
    errors = [
        f"VC-JWT signature is invalid for {kid}",
        f"issuer {issuer} does not match key controller",
    ]
    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(
            verify_vcdm_jwt=lambda _request: json.dumps(
                {
                    "valid": False,
                    "issuer": issuer,
                    "claims": None,
                    "errors": errors,
                }
            )
        ),
    )

    result = pp._verify_w3c_vc(
        token,
        None,
        None,
        {"kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y"},
    )

    assert result["verified"] is False
    assert "issuer-binding,signature" in caplog.text
    assert issuer not in caplog.text
    assert "secret-key-name" not in caplog.text


def test_open_badge_login_policy_format_accepts_sd_jwt_aliases() -> None:
    assert pp._credential_format_satisfies_requirement("sd-jwt", "sd_jwt_vc")
    assert pp._credential_format_satisfies_requirement("sd-jwt", "dc+sd-jwt")
    assert pp._credential_format_satisfies_requirement("sd-jwt", "ietf_sd_jwt")
    assert not pp._credential_format_satisfies_requirement("sd-jwt", "openbadge-v3")
    assert pp._credential_format_satisfies_requirement("w3c-vcdm-di", "w3c_vcdm_v2_di")
    assert pp._credential_format_satisfies_requirement("w3c-vcdm-di", "JSON_LD")
    assert pp._credential_format_satisfies_requirement("w3c-vcdm-di", "ldp_vc")
    assert pp._credential_format_satisfies_requirement("w3c-vc", "w3c_vcdm_v2_jwt_vc")
    assert pp._credential_format_satisfies_requirement("w3c-vc", "jwt_vc_json")


def test_trust_profile_service_url_defaults_to_compose_service_name(
    monkeypatch,
) -> None:
    monkeypatch.delenv("TRUST_PROFILE_SERVICE_URL", raising=False)

    assert pp._trust_profile_service_url() == "http://trust-profile:8004"


def test_trust_profile_service_url_honors_env_override(monkeypatch) -> None:
    monkeypatch.setenv(
        "TRUST_PROFILE_SERVICE_URL", "http://trust-profile.internal:8004"
    )

    assert pp._trust_profile_service_url() == "http://trust-profile.internal:8004"


def test_trust_profile_lookup_url_uses_internal_service_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004")

    assert (
        pp._trust_profile_lookup_url("profile-1")
        == "http://trust-profile:8004/internal/v1/trust-profiles/profile-1"
    )


def test_trust_profile_cache_ttl_defaults_to_five_minutes(monkeypatch) -> None:
    monkeypatch.delenv("TRUST_PROFILE_CACHE_TTL_SECONDS", raising=False)

    ttl = pp._trust_profile_cache_ttl_seconds(
        {"time_policy": {"freshness_window_seconds": 86400}}
    )

    assert ttl == 300


def test_trust_profile_cache_ttl_honors_smaller_freshness_window(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROFILE_CACHE_TTL_SECONDS", "300")

    ttl = pp._trust_profile_cache_ttl_seconds(
        {"time_policy": {"freshness_window_seconds": 60}}
    )

    assert ttl == 60


def test_credential_status_lookup_url_honors_mip_template(monkeypatch) -> None:
    monkeypatch.setenv(
        "MIP_CREDENTIAL_STATUS_URL_TEMPLATE",
        "http://status-resolver.internal/credentials/{credential_id}/status",
    )

    assert pp._credential_status_lookup_url("credential 123") == (
        "http://status-resolver.internal/credentials/credential%20123/status"
    )


def test_credential_status_identifier_candidates_use_explicit_ids_only() -> None:
    candidates = pp._credential_status_identifier_candidates(
        {
            "id": "did:example:holder",
            "credential_id": "credential-123",
        },
        {
            "credential": {"id": "credential-456"},
            "vc": {"id": "credential-789"},
        },
    )

    assert candidates == ["credential-123", "credential-789", "credential-456"]


def test_verify_sd_jwt_reports_did_resolution_failure(monkeypatch) -> None:
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "typ": "vc+sd-jwt", "kid": "#issuer-key"}),
            _jwt_segment(
                {
                    "iss": "did:web:example.com:orgs:marty",
                    "sub": "did:example:holder",
                    "email": "member@example.com",
                }
            ),
            "signature",
        ]
    )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_sd_jwt=lambda *_args, **_kwargs: "{}"),
    )

    def _fail_resolution(_did: str):
        raise RuntimeError(
            "DID resolution failed for did:web:example.com:orgs:marty: HTTP 404"
        )

    monkeypatch.setattr(pp, "_resolve_did_document", _fail_resolution)

    result = pp._verify_sd_jwt(token, nonce=None, audience=None)

    assert result["verified"] is False
    assert "DID resolution failed" in result["error"]
    assert result["claims"]["email"] == "member@example.com"


def test_resolve_did_jwk_without_network() -> None:
    public_jwk = {"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"}
    encoded = (
        base64.urlsafe_b64encode(json.dumps(public_jwk).encode()).decode().rstrip("=")
    )
    did = f"did:jwk:{encoded}"

    document = pp._resolve_did_document(did)

    assert document["id"] == did
    assert document["assertionMethod"] == [did]
    assert document["verificationMethod"][0]["publicKeyJwk"] == public_jwk


def test_verify_sd_jwt_resolves_did_jwk(monkeypatch) -> None:
    public_jwk = {"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"}
    encoded = (
        base64.urlsafe_b64encode(json.dumps(public_jwk).encode()).decode().rstrip("=")
    )
    did = f"did:jwk:{encoded}"
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "typ": "dc+sd-jwt", "kid": did}),
            _jwt_segment(
                {"iss": did, "sub": "did:example:holder", "email": "member@example.com"}
            ),
            "signature",
        ]
    )
    captured: dict[str, object] = {}

    def _verify(
        token: str, issuer_jwk: str, audience: str | None, nonce: str | None
    ) -> str:
        captured.update(
            token=token,
            issuer_jwk=json.loads(issuer_jwk),
            audience=audience,
            nonce=nonce,
        )
        return json.dumps({"given_name": "Marty"})

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_sd_jwt=_verify),
    )

    result = pp._verify_sd_jwt(
        token, nonce="nonce-123", audience="https://verifier.example"
    )

    assert result["verified"] is True
    assert result["issuer_did"] == did
    assert result["claims"]["email"] == "member@example.com"
    assert result["claims"]["given_name"] == "Marty"
    assert captured == {
        "token": token,
        "issuer_jwk": public_jwk,
        "audience": "https://verifier.example",
        "nonce": "nonce-123",
    }


def test_verify_open_badge_v3_uses_binding_and_flattens_claims(monkeypatch) -> None:
    credential = {
        "@context": ["https://purl.imsglobal.org/spec/ob/v3p0/context.json"],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": {"id": "did:example:issuer"},
        "credentialSubject": {
            "id": "did:example:holder",
            "email": "member@example.com",
            "member_id": "member-123",
            "organization_id": "org-123",
            "organization_name": "Marty Org",
            "role": "vendor",
            "given_name": "Marty",
            "family_name": "Member",
            "achievement": {
                "name": "Verified Member Badge",
                "description": "Verifiable proof of active organization membership",
            },
        },
    }
    document_store = {"did:example:issuer#key-1": {"id": "did:example:issuer#key-1"}}

    def _fake_verify(version, received_credential, received_document_store):
        assert version == "v3"
        assert received_credential == credential
        assert received_document_store == document_store
        return {
            "valid": True,
            "errors": [],
            "revocation_checked": True,
            "not_revoked": True,
            "normalized": {
                "credential_subject": credential["credentialSubject"],
            },
        }

    monkeypatch.setattr(pp, "_run_open_badge_verify", _fake_verify)

    result = pp._verify_open_badge_v3(
        json.dumps({"credential": credential, "document_store": document_store})
    )

    assert result["verified"] is True
    assert result["format"] == "openbadge-v3"
    assert result["issuer_did"] == "did:example:issuer"
    assert result["claims"]["recipient"] == "did:example:holder"
    assert result["claims"]["email"] == "member@example.com"
    assert result["claims"]["member_id"] == "member-123"
    assert result["claims"]["organization_id"] == "org-123"
    assert result["claims"]["organization_name"] == "Marty Org"
    assert result["claims"]["role"] == "vendor"
    assert result["claims"]["given_name"] == "Marty"
    assert result["claims"]["family_name"] == "Member"
    assert result["claims"]["name"] == "Verified Member Badge"
    assert (
        result["claims"]["description"]
        == "Verifiable proof of active organization membership"
    )
    assert result["revocation_checked"] is True
    assert result["not_revoked"] is True
    assert result["is_revoked"] is False
    assert result["error"] is None


async def _save_open_badge_login_policy(
    repo: pp.InMemoryPresentationPolicyRepository,
) -> pp.PresentationPolicy:
    policy = pp.PresentationPolicy(
        id="50000000-0000-0000-0000-000000000004",
        organization_id="org-1",
        name="OpenBadgeLogin",
        description="Verify a standards-based Open Badge membership credential for login",
        status=pp.PolicyStatus.ACTIVE,
    )
    policy.credential_requirements = [
        pp.CredentialRequirement(
            credential_template_id="50000000-0000-0000-0000-000000000040",
            display_name="Marty Verified Member Badge",
            credential_payload_format="sd_jwt_vc",
            trust_profile_id="60000000-0000-0000-0000-000000000001",
            requested_claims=[
                pp.RequestedClaim(
                    claim_name="email",
                    display_name="Email Address",
                    required=True,
                    selective_disclosure=True,
                )
            ],
        )
    ]
    await repo.save(policy)
    return policy


def _install_marty_trust_profile(
    monkeypatch,
    *,
    organization_id: object = "org-1",
    allowed_issuers: list[str] | None = None,
    denied_issuers: list[str] | None = None,
    trust_sources: list[dict[str, object]] | None = None,
) -> None:
    cache = pp.TrustProfileCache()
    cache.set(
        "60000000-0000-0000-0000-000000000001",
        {
            "organization_id": organization_id,
            "allowed_issuers": ["did:web:beta.elevenidllc.com:orgs:marty"]
            if allowed_issuers is None
            else allowed_issuers,
            "denied_issuers": denied_issuers or [],
            "trust_sources": trust_sources or [],
            "time_policy": {"freshness_window_seconds": 3600},
        },
        3600,
    )
    monkeypatch.setattr(pp, "_trust_profile_cache", cache)


def test_rest_evaluation_rejects_cross_org_trust_profile_override(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch, organization_id="org-other")
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")

    response = _build_client(repo).post(
        f"/v1/presentation-policies/{policy.id}/evaluate",
        json={
            "vp_token": "header.payload.signature",
            "trust_profile_id": "60000000-0000-0000-0000-000000000001",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "Trust Profile and Presentation Policy must belong to the same organization"
    )


@pytest.mark.parametrize(
    "ambiguous_organization_id", [None, "", ["org-1"], {"id": "org-1"}]
)
def test_evaluator_rejects_trust_profile_without_unambiguous_org(
    monkeypatch,
    ambiguous_organization_id: object,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(
        monkeypatch,
        organization_id=ambiguous_organization_id,
    )
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")

    with pytest.raises(pp.HTTPException) as exc_info:
        asyncio.run(
            pp.evaluate_presentation(
                policy.id,
                pp.EvaluatePresentationRequest(
                    vp_token="header.payload.signature",
                    trust_profile_id="60000000-0000-0000-0000-000000000001",
                ),
                repo=repo,
            )
        )

    assert exc_info.value.status_code == 503
    assert "no unambiguous organization_id" in exc_info.value.detail


def test_open_badge_login_policy_allows_verified_sd_jwt_badge(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {
                "email": "member@example.com",
                "member_id": "member-123",
                "organization_id": "org-1",
                "role": "applicant",
            },
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert response.decision == "allow"
    assert (
        response.credential_results[0].credential_template_id
        == "50000000-0000-0000-0000-000000000040"
    )
    assert response.verified_claims["email"] == "member@example.com"


def test_oid4vp_context_requires_sd_jwt_holder_binding_even_when_policy_does_not(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)
    captured: dict[str, object] = {}

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")

    def verify(
        _token,
        credential_format,
        nonce,
        audience,
        *_args,
        **_kwargs,
    ):
        captured.update(
            credential_format=credential_format,
            nonce=nonce,
            audience=audience,
        )
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "error": "invalid holder signature",
        }

    monkeypatch.setattr(pp, "_verify_credential_by_format", verify)

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(
                vp_token="issuer.payload.signature~holder.payload.signature",
                nonce="oid4vp-nonce",
                audience="https://verifier.example/callback",
                context={"oid4vp_verifier_context": True},
            ),
            repo=repo,
        )
    )

    assert captured == {
        "credential_format": "sd-jwt",
        "nonce": "oid4vp-nonce",
        "audience": "https://verifier.example/callback",
    }
    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.verified_claims == {}


def test_open_badge_login_policy_denies_untrusted_issuer(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "did:web:attacker.example:orgs:evil",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.credential_results[0].trust_check_passed is False
    assert "not in Trust Profile allowed_issuers" in response.decision_reason


def test_open_badge_login_policy_allows_issuer_url_alias(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(
        monkeypatch,
        allowed_issuers=["https://canvas.example.edu/issuers/issuer-123"],
    )

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "https://canvas.example.edu/issuers/issuer-123",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert response.decision == "allow"


def test_open_badge_login_policy_allows_did_web_issuer_by_domain_alias(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch, allowed_issuers=["beta.elevenidllc.com"])

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert response.decision == "allow"


def test_open_badge_login_policy_denies_issuer_by_domain_alias(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(
        monkeypatch,
        allowed_issuers=None,
        denied_issuers=["canvas.example.edu"],
    )

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "https://canvas.example.edu/issuers/issuer-123",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.credential_results[0].trust_check_passed is False
    assert "explicitly denied" in response.decision_reason


def test_open_badge_login_policy_allows_pinned_issuer_url_trust_source(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(
        monkeypatch,
        allowed_issuers=[],
        trust_sources=[
            {
                "source_type": "PINNED_ISSUER",
                "url": "https://canvas.example.edu/issuers/issuer-123",
            }
        ],
    )

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "https://canvas.example.edu/issuers/issuer-123",
            "format": "sd-jwt",
            "error": None,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert response.decision == "allow"


def test_open_badge_login_policy_uses_marty_trust_profile() -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))

    assert (
        policy.credential_requirements[0].trust_profile_id
        == "60000000-0000-0000-0000-000000000001"
    )


def test_open_badge_login_policy_denies_unverified_open_badge(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": False,
            "claims": {"email": "member@example.com"},
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "format": "sd-jwt",
            "error": "DID resolution failed: issuer key not found",
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.required_satisfied == 0
    assert response.verified_claims == {}
    assert response.credential_results[0].signature_valid is False
    assert "DID resolution failed" in response.decision_reason


def test_policy_freshness_denies_when_revocation_not_checked(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)
    policy.freshness = pp.FreshnessPolicy(require_not_revoked=True)
    asyncio.run(repo.save(policy))

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "format": "sd-jwt",
            "error": None,
            "revocation_checked": False,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.credential_results[0].freshness_check_passed is False
    assert "Revocation status was not checked" in response.decision_reason


def test_policy_freshness_denies_revoked_credential(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    _install_marty_trust_profile(monkeypatch)
    policy.freshness = pp.FreshnessPolicy(require_not_revoked=True)
    asyncio.run(repo.save(policy))

    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com"},
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "format": "sd-jwt",
            "error": None,
            "revocation_checked": True,
            "not_revoked": False,
            "is_revoked": True,
        },
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.credential_results[0].freshness_check_passed is False


def test_policy_freshness_accepts_managed_issuer_active_credential_status(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    issuer_did = "did:web:issuer.example:orgs:demo"
    _install_marty_trust_profile(monkeypatch, allowed_issuers=[issuer_did])
    policy.freshness = pp.FreshnessPolicy(require_not_revoked=True)
    policy.credential_requirements[0].credential_payload_format = "jwt_vc"
    asyncio.run(repo.save(policy))

    monkeypatch.setenv("MIP_MANAGED_ISSUER_DIDS", issuer_did)
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "w3c-vc")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {
                "email": "member@example.com",
                "credential_id": "credential-123",
            },
            "issuer_did": issuer_did,
            "format": "w3c-vc",
            "error": None,
        },
    )
    monkeypatch.setattr(
        pp,
        "_get_issued_credential_status",
        lambda credential_id: {"id": credential_id, "status": "active"},
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "passed"
    assert response.decision == "allow"
    assert response.verified_claims["email"] == "member@example.com"


def test_policy_freshness_denies_managed_issuer_revoked_credential_status(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    issuer_did = "did:web:issuer.example:orgs:demo"
    _install_marty_trust_profile(monkeypatch, allowed_issuers=[issuer_did])
    policy.freshness = pp.FreshnessPolicy(require_not_revoked=True)
    asyncio.run(repo.save(policy))

    monkeypatch.setenv("MIP_MANAGED_ISSUER_DIDS", issuer_did)
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com", "jti": "credential-123"},
            "issuer_did": issuer_did,
            "format": "sd-jwt",
            "error": None,
        },
    )
    monkeypatch.setattr(
        pp,
        "_get_issued_credential_status",
        lambda credential_id: {"id": credential_id, "status": "revoked"},
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert response.credential_results[0].freshness_check_passed is False
    assert "Credential is revoked" in response.decision_reason


def test_policy_freshness_reports_suspended_credential_status(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    issuer_did = "did:web:issuer.example:orgs:demo"
    _install_marty_trust_profile(monkeypatch, allowed_issuers=[issuer_did])
    policy.freshness = pp.FreshnessPolicy(require_not_revoked=True)
    asyncio.run(repo.save(policy))

    monkeypatch.setenv("MIP_MANAGED_ISSUER_DIDS", issuer_did)
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "sd-jwt")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"email": "member@example.com", "jti": "credential-123"},
            "issuer_did": issuer_did,
            "format": "sd-jwt",
            "error": None,
        },
    )
    monkeypatch.setattr(
        pp,
        "_get_issued_credential_status",
        lambda credential_id: {"id": credential_id, "status": "suspended"},
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="{}", nonce="nonce-1"),
            repo=repo,
        )
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert "Credential is suspended" in response.decision_reason


def test_status_lookup_accepts_record_bound_to_unconfigured_issuer(monkeypatch) -> None:
    issuer_did = "did:jwk:issuer-key"
    monkeypatch.delenv("MIP_MANAGED_ISSUER_DIDS", raising=False)
    monkeypatch.setattr(
        pp,
        "_get_issued_credential_status",
        lambda credential_id: {
            "id": credential_id,
            "issuer_did": issuer_did,
            "status": "active",
        },
    )

    assert pp._lookup_managed_issuer_credential_status_revocation_state(
        issuer_did=issuer_did,
        credential_ids=["credential-123"],
    ) == (True, True, "active")


def test_status_lookup_rejects_record_bound_to_different_issuer(monkeypatch) -> None:
    monkeypatch.delenv("MIP_MANAGED_ISSUER_DIDS", raising=False)
    monkeypatch.setattr(
        pp,
        "_get_issued_credential_status",
        lambda credential_id: {
            "id": credential_id,
            "issuer_did": "did:jwk:other-issuer",
            "status": "active",
        },
    )

    assert pp._lookup_managed_issuer_credential_status_revocation_state(
        issuer_did="did:jwk:presented-issuer",
        credential_ids=["credential-123"],
    ) == (None, None, None)


def _inline_evaluation_payload() -> dict:
    return {
        "organization_id": "org-1",
        "vp_token": "header.payload.signature",
        "credential_requirements": [
            {
                "credential_template_id": "inline-vc",
                "credential_payload_format": "jwt_vc_json",
                "requested_claims": [
                    {
                        "claim_name": "name",
                        "required": True,
                    }
                ],
            }
        ],
    }


def test_inline_evaluation_uses_real_verifier_output(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    client = _build_client(repo)
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "jwt-vc")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": True,
            "claims": {"name": "Alice"},
            "issuer_did": "did:web:issuer.example",
            "format": "jwt-vc",
            "error": None,
        },
    )

    response = client.post(
        "/v1/presentation-policies/evaluate",
        json=_inline_evaluation_payload(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert body["verified_claims"] == {"name": "Alice"}
    assert "[simulated]" not in response.text


def test_inline_evaluation_rejects_invalid_signature(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    client = _build_client(repo)
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "jwt-vc")
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: {
            "verified": False,
            "claims": {},
            "issuer_did": "did:web:issuer.example",
            "format": "jwt-vc",
            "error": "Invalid signature",
        },
    )

    response = client.post(
        "/v1/presentation-policies/evaluate",
        json=_inline_evaluation_payload(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "deny"
    assert body["result"] == "failed"
    assert "Invalid signature" in body["decision_reason"]


def test_saved_policy_evaluation_checks_membership_before_verification(
    monkeypatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))
    client = _build_client(repo)
    monkeypatch.setattr(
        pp,
        "ensure_membership_permission",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            pp.HTTPException(
                status_code=403,
                detail="Cross-tenant policy access denied",
            )
        ),
    )
    monkeypatch.setattr(
        pp,
        "_detect_credential_format",
        lambda _token: pytest.fail("verification must not run before authorization"),
    )

    response = client.post(
        f"/v1/presentation-policies/{policy.id}/evaluate",
        json={"vp_token": "header.payload.signature"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-tenant policy access denied"
