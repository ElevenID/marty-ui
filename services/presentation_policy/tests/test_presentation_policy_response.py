"""Protocol conformance tests for presentation-policy REST responses."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrgRole

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
                role=OrgRole.ADMIN,
                status="active",
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
