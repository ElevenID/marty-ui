from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.trust_profile import main as trust_profile


class FakeMembership:
    def __init__(self, *, active: bool = True, roles: tuple[str, ...] = ("admin",)):
        self._active = active
        self._roles = set(roles)

    def is_active(self) -> bool:
        return self._active

    def has_role(self, *roles: str) -> bool:
        return any(role in self._roles for role in roles)


def _build_client(
    repo: trust_profile.InMemoryTrustProfileRepository,
    membership: FakeMembership | None = None,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(trust_profile.router)

    trust_profile._repo = repo
    get_membership = AsyncMock(return_value=membership or FakeMembership())
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    trust_profile.app.state.org_client = org_client
    trust_profile.get_organization_client = AsyncMock(return_value=org_client)
    return TestClient(app), get_membership


async def _save_profile(
    repo: trust_profile.InMemoryTrustProfileRepository,
) -> trust_profile.TrustProfile:
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="AAMVA Trust Profile",
        description="Protocol trust profile",
        profile_type=trust_profile.TrustProfileType.AAMVA,
        compliance_status=trust_profile.ComplianceStatus.COMPLIANT,
        trust_sources=[
            trust_profile.TrustSource(
                name="AAMVA root",
                source_type=trust_profile.TrustSourceType.ROOT_CA.value,
                certificate_pem="-----BEGIN CERTIFICATE-----AAMVA",
                description="Primary root",
            )
        ],
        allowed_issuers=["did:example:issuer-1"],
        denied_issuers=["did:example:issuer-2"],
        system_issuer_overrides={
            "did:example:issuer-3": {"action": "DOWNGRADE", "trust_level": 40, "reason": "Pilot issuer"}
        },
        compatible_compliance_codes=["AAMVA_MDL"],
        verification_policy_set_id="policy-set-1",
        auto_generated=True,
        revocation_profile_id="rev-prof-1",
        supported_formats=[trust_profile.CredentialFormat.MDOC],
    )
    profile.validation_rules.allowed_algorithms = ["ES256", "EdDSA"]
    profile.revocation_policy.check_mode = trust_profile.RevocationCheckMode.SOFT_FAIL
    profile.revocation_policy.check_ocsp = True
    profile.revocation_policy.check_crl = False
    profile.revocation_policy.check_status_list = True
    profile.revocation_policy.cache_duration_hours = 2
    profile.time_policy.max_clock_skew_seconds = 120
    profile.time_policy.credential_freshness_hours = 6
    await repo.save_profile(profile)
    return profile


def test_get_trust_profile_returns_protocol_shape_only() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.get(
        f"/v1/trust-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "id",
        "organization_id",
        "name",
        "description",
        "profile_type",
        "compliance_status",
        "trust_sources",
        "allowed_algorithms",
        "revocation_policy",
        "revocation_services",
        "revocation_profile_id",
        "time_policy",
        "supported_formats",
        "allowed_issuers",
        "denied_issuers",
        "system_issuer_overrides",
        "compatible_compliance_codes",
        "verification_policy_set_id",
        "auto_generated",
        "created_at",
        "updated_at",
    }
    assert body["profile_type"] == "AAMVA"
    assert body["allowed_algorithms"] == ["ES256", "EdDSA"]
    assert body["trust_sources"] == [
        {
            "source_type": "ROOT_CA",
            "url": None,
            "certificate_pem": "-----BEGIN CERTIFICATE-----AAMVA",
            "issuer_did": None,
            "description": "Primary root",
        }
    ]
    assert body["revocation_policy"] == {
        "check_mode": "SOFT_FAIL",
        "cache_ttl_seconds": 7200,
    }
    assert body["revocation_services"] == {
        "enabled_methods": ["OCSP", "STATUS_LIST"],
        "auto_discover": False,
        "merge_discovered": False,
    }
    assert body["time_policy"] == {
        "clock_skew_seconds": 120,
        "max_credential_age_seconds": 21600,
        "require_freshness": True,
        "freshness_window_seconds": 21600,
    }
    assert "status" not in body
    assert "validation_rules" not in body
    assert "revocation_check_enabled" not in body
    assert "trusted_issuers" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_trust_profile_returns_canonical_fields() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "EUDI Trust Profile",
            "description": "European trust baseline",
            "profile_type": "EUDI",
            "compliance_status": "COMPLIANT",
            "trust_sources": [
                {
                    "name": "EUDI trust list",
                    "source_type": "trust_list",
                    "url": "https://trust.example/eudi.json",
                    "description": "LOTL source"
                }
            ],
            "allowed_algorithms": ["ES256"],
            "revocation_policy": {
                "check_mode": "HARD_FAIL",
                "check_ocsp": True,
                "check_crl": True,
                "check_status_list": False,
                "cache_duration_hours": 1
            },
            "time_policy": {
                "max_clock_skew_seconds": 60,
                "credential_freshness_hours": 1,
                "require_not_before": True,
                "require_expiration": True
            },
            "supported_formats": ["mdoc", "SD_JWT_VC"],
            "allowed_issuers": ["did:example:eudi-1"],
            "verification_policy_set_id": "policy-set-2",
            "compatible_compliance_codes": ["EUDI_PID"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["profile_type"] == "EUDI"
    assert body["trust_sources"][0]["source_type"] == "TRUST_LIST"
    assert body["allowed_algorithms"] == ["ES256"]
    assert body["supported_formats"] == ["MDOC", "SD_JWT_VC"]
    assert body["revocation_policy"]["cache_ttl_seconds"] == 3600
    assert body["time_policy"]["require_freshness"] is True
    assert body["verification_policy_set_id"] == "policy-set-2"
    assert body["compatible_compliance_codes"] == ["EUDI_PID"]
    assert "status" not in body
    assert "min_key_size_rsa" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_activate_trust_profile_keeps_protocol_payload_stable() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.post(
        f"/v1/trust-profiles/{profile.id}/activate",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == profile.id
    assert body["compliance_status"] == "COMPLIANT"
    assert body["revocation_profile_id"] == "rev-prof-1"
    assert body["updated_at"] != ""
    assert "status" not in body
    assert "validation_rules" not in body
    assert "trusted_issuers" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")