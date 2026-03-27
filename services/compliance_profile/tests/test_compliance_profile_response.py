from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrgRole

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
            role=OrgRole.ADMIN,
            status="active",
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
        default_verification_rules={"holder_binding": True},
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
        "default_verification_rules",
        "verification_policy_set_id",
        "trust_profile_constraints",
        "api_surface",
        "discoverable",
        "is_system",
        "created_at",
    }
    assert body["credential_format"] == "MDOC"
    assert body["issuance_protocol"] == "OID4VCI_PRE_AUTH"
    assert body["trust_profile_constraints"] == {
        "compatible_profile_types": ["AAMVA", "CUSTOM"],
        "required_source_types": ["ROOT_CA"],
        "required_formats": ["MDOC"],
    }
    assert "status" not in body
    assert "updated_at" not in body
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
            "default_verification_rules": {"audience": "wallet"},
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
    assert body["is_system"] is False
    assert body["default_verification_rules"] == {"audience": "wallet"}
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
    assert body["created_at"] == profile.created_at.isoformat()
    assert "status" not in body
    assert "updated_at" not in body
    assert "audit_configuration" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")