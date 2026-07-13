from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.compliance_profile import main as compliance_profile


def _build_client(
    repo: compliance_profile.InMemoryComplianceProfileRepository,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(compliance_profile.router)

    compliance_profile._repo = repo

    get_membership = AsyncMock(
        return_value=OrganizationMembership(
            user_id="user-1",
            organization_id="org-1",
            status="active",
            roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
            has_org_console_access=True,
        )
    )
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    compliance_profile.app.state.org_client = org_client
    compliance_profile.get_organization_client = AsyncMock(return_value=org_client)
    return TestClient(app), get_membership


async def _save_profile(
    repo: compliance_profile.InMemoryComplianceProfileRepository,
) -> compliance_profile.ComplianceProfile:
    profile = compliance_profile.ComplianceProfile(
        organization_id="org-1",
        name="AAMVA mDL Compliance",
        description="Protocol-facing compliance profile",
        compliance_code="AAMVA_MDL",
        credential_format=compliance_profile.CredentialFormat.MDOC,
        issuance_protocol=compliance_profile.IssuanceProtocol.OID4VCI_PRE_AUTH,
        issuer_artifact_requirements=compliance_profile.IssuerArtifactRequirements(
            requires_x509_cert=True,
            cert_key_usage=["digitalSignature"],
            recommended_algorithms=["ES256"],
        ),
        verification_policy_set_id="policy-set-1",
        trust_profile_constraints=compliance_profile.TrustProfileConstraints(
            compatible_profile_types=["AAMVA", "CUSTOM"],
            required_source_types=["ROOT_CA"],
            required_formats=["MDOC"],
        ),
        api_surface=[
            compliance_profile.ApiSurfaceEndpoint(
                rel="openid-credential-issuer",
                path_template="/.well-known/openid-credential-issuer",
                method="GET",
                auth_required=False,
            )
        ],
        discoverable=True,
        is_system=True,
        frameworks=["AAMVA"],
    )
    profile.data_retention.retain_metadata_only = True
    profile.age_verification.enabled = True
    await repo.save(profile)
    return profile


def test_get_compliance_profile_returns_protocol_shape_only() -> None:
    repo = compliance_profile.InMemoryComplianceProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.get(
        f"/v1/compliance-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "id",
        "organization_id",
        "compliance_code",
        "name",
        "description",
        "credential_format",
        "issuance_protocol",
        "issuer_artifact_requirements",
        "verification_policy_set_id",
        "trust_profile_constraints",
        "api_surface",
        "discoverable",
        "status",
        "is_system",
        "created_at",
        "updated_at",
    }
    assert body["credential_format"] == "MDOC"
    assert body["issuance_protocol"] == "OID4VCI_PRE_AUTH"
    assert body["trust_profile_constraints"] == {
        "compatible_profile_types": ["AAMVA", "CUSTOM"],
        "required_source_types": ["ROOT_CA"],
        "required_formats": ["MDOC"],
    }
    assert body["status"] == "DRAFT"
    assert "frameworks" not in body
    assert "data_retention" not in body
    assert "system_profile" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_compliance_profile_returns_canonical_protocol_fields() -> None:
    repo = compliance_profile.InMemoryComplianceProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/compliance-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Enterprise SD-JWT VC",
            "description": "Enterprise issuance baseline",
            "compliance_code": "ENTERPRISE_VC",
            "credential_format": "sd_jwt_vc",
            "issuance_protocol": "OID4VCI_PRE_AUTH",
            "trust_profile_constraints": {
                "compatible_profile_types": ["CUSTOM"],
                "required_source_types": ["TRUST_LIST"],
                "required_formats": ["SD_JWT_VC"],
            },
            "frameworks": ["INTERNAL_POLICY"],
            "data_retention": {"retain_metadata_only": True},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["compliance_code"] == "ENTERPRISE_VC"
    assert body["credential_format"] == "SD_JWT_VC"
    assert body["discoverable"] is True
    assert body["status"] == "DRAFT"
    assert body["is_system"] is False
    assert body["trust_profile_constraints"]["required_formats"] == ["SD_JWT_VC"]
    assert "frameworks" not in body
    assert "data_retention" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_activate_compliance_profile_keeps_protocol_shape_stable() -> None:
    repo = compliance_profile.InMemoryComplianceProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.post(
        f"/v1/compliance-profiles/{profile.id}/activate",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == profile.id
    assert body["is_system"] is True
    assert body["status"] == "ACTIVE"
    assert body["created_at"] == profile.created_at.isoformat()
    assert body["updated_at"] == profile.updated_at.isoformat()
    assert "audit_configuration" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_rejects_removed_default_verification_rules() -> None:
    repo = compliance_profile.InMemoryComplianceProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/compliance-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Removed compatibility field",
            "default_verification_rules": {"audience": "wallet"},
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"
    get_membership.assert_not_awaited()


def test_system_seed_is_active_and_available_to_every_organization() -> None:
    repo = compliance_profile.InMemoryComplianceProfileRepository()
    asyncio.run(compliance_profile.seed_system_profiles(repo))
    client, get_membership = _build_client(repo)

    response = client.get(
        "/v1/compliance-profiles?organization_id=org-1",
        headers={"x-user-id": "user-1"},
    )
    discovery = client.get("/v1/compliance-profiles/system/discoverable")

    assert response.status_code == 200
    assert discovery.status_code == 200
    assert response.json()[0]["compliance_code"] == "OID4VC"
    assert response.json()[0]["status"] == "ACTIVE"
    assert discovery.json() == response.json()
    get_membership.assert_awaited_once_with("user-1", "org-1")
