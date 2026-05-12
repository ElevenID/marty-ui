"""Protocol conformance tests for presentation-policy REST responses."""

from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.presentation_policy import main as pp

# Protocol-allowed top-level keys (presentation-policy.json schema)
PROTOCOL_KEYS = {
    "id",
    "organization_id",
    "name",
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
                roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
                permissions={
                    "presentation-policy:view",
                    "presentation-policy:create",
                    "presentation-policy:edit",
                    "presentation-policy:delete",
                    "presentation-policy:activate",
                    "presentation-policy:suspend",
                    "presentation-policy:version",
                },
                has_org_console_access=True,
            )
        )
    )
    app.state.org_client = org_client
    pp.app.state.org_client = org_client
    return TestClient(app)


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
        required=True, binding_methods=["NONCE"], nonce_required=True
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
    assert set(body.keys()) <= PROTOCOL_KEYS, f"Extra keys: {set(body.keys()) - PROTOCOL_KEYS}"

    # Required protocol fields present
    assert body["id"] == policy.id
    assert body["organization_id"] == "org-1"
    assert body["name"] == "Age Gate"
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
    assert "NONCE" in body["holder_binding"]["binding_methods"]
    assert body["freshness"]["max_age_seconds"] == 3600
    assert body["issuer_constraints"]["min_trust_level"] == 50
    assert body["credential_ranking_strategy"] == "HIGHEST_TRUST_FIRST"
    assert body["prefer_predicates"] is True
    assert body["fallback_policy"] == "ACCEPT_RAW"
    assert "ligero_age_over_21" in body["supported_circuits"]

    # Legacy fields must NOT be present
    for legacy_key in ("status", "display_metadata", "credential_requirements",
                       "alternative_requirements", "compliance_profile_id", "version"):
        assert legacy_key not in body, f"Legacy key {legacy_key!r} must not appear in protocol response"


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
    assert "status" not in body
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

    assert pp._detect_credential_format(json.dumps({"credential": credential})) == "openbadge-v3"


def _jwt_segment(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_open_badge_login_policy_format_accepts_sd_jwt_aliases() -> None:
    assert pp._credential_format_satisfies_requirement("sd-jwt", "sd_jwt_vc")
    assert pp._credential_format_satisfies_requirement("sd-jwt", "dc+sd-jwt")
    assert pp._credential_format_satisfies_requirement("sd-jwt", "ietf_sd_jwt")
    assert not pp._credential_format_satisfies_requirement("sd-jwt", "openbadge-v3")


def test_trust_profile_service_url_defaults_to_compose_service_name(monkeypatch) -> None:
    monkeypatch.delenv("TRUST_PROFILE_SERVICE_URL", raising=False)

    assert pp._trust_profile_service_url() == "http://trust-profile:8004"


def test_trust_profile_service_url_honors_env_override(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROFILE_SERVICE_URL", "http://trust-profile.internal:8004")

    assert pp._trust_profile_service_url() == "http://trust-profile.internal:8004"


def test_trust_profile_lookup_url_uses_internal_service_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004")

    assert pp._trust_profile_lookup_url("profile-1") == "http://trust-profile:8004/internal/v1/trust-profiles/profile-1"


def test_verify_sd_jwt_reports_did_resolution_failure(monkeypatch) -> None:
    token = ".".join(
        [
            _jwt_segment({"alg": "ES256", "typ": "vc+sd-jwt", "kid": "#issuer-key"}),
            _jwt_segment({"iss": "did:web:example.com:orgs:marty", "sub": "did:example:holder", "email": "member@example.com"}),
            "signature",
        ]
    )

    monkeypatch.setattr(
        pp,
        "_load_marty_rs_binding",
        lambda: SimpleNamespace(verify_sd_jwt=lambda *_args, **_kwargs: "{}"),
    )

    def _fail_resolution(_did: str):
        raise RuntimeError("DID resolution failed for did:web:example.com:orgs:marty: HTTP 404")

    monkeypatch.setattr(pp, "_resolve_did_document", _fail_resolution)

    result = pp._verify_sd_jwt(token, nonce=None, audience=None)

    assert result["verified"] is False
    assert "DID resolution failed" in result["error"]
    assert result["claims"]["email"] == "member@example.com"


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
    assert result["claims"]["description"] == "Verifiable proof of active organization membership"
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


def _install_marty_trust_profile(monkeypatch, *, allowed_issuers: list[str] | None = None) -> None:
    cache = pp.TrustProfileCache()
    cache.set(
        "60000000-0000-0000-0000-000000000001",
        {
            "allowed_issuers": allowed_issuers or ["did:web:beta.elevenidllc.com:orgs:marty"],
            "time_policy": {"freshness_window_seconds": 3600},
        },
        3600,
    )
    monkeypatch.setattr(pp, "_trust_profile_cache", cache)


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
    assert response.credential_results[0].credential_template_id == "50000000-0000-0000-0000-000000000040"
    assert response.verified_claims["email"] == "member@example.com"


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


def test_open_badge_login_policy_uses_marty_trust_profile() -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))

    assert policy.credential_requirements[0].trust_profile_id == "60000000-0000-0000-0000-000000000001"


def test_open_badge_login_policy_denies_unverified_open_badge(monkeypatch) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = asyncio.run(_save_open_badge_login_policy(repo))

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
    assert "Credential is revoked" in response.decision_reason
