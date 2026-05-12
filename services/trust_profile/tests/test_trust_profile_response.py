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

    def has_permission(self, resource: str, action: str | None = None) -> bool:
        if {"admin", "owner"} & self._roles:
            return True
        permission_key = resource if action is None else f"{resource}:{action}"
        return permission_key in set()


def _build_client(
    repo: trust_profile.InMemoryTrustProfileRepository,
    membership: FakeMembership | None = None,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(trust_profile.router)
    app.include_router(trust_profile.internal_router)

    trust_profile._repo = repo
    get_membership = AsyncMock(return_value=membership or FakeMembership())
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    trust_profile.app.state.org_client = org_client
    trust_profile.get_organization_client = AsyncMock(return_value=org_client)
    return TestClient(app), get_membership


def test_bootstrap_updates_marty_managed_issuer_did(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("MARTY_ORG_SLUG", "marty")

    repo = trust_profile.InMemoryTrustProfileRepository()
    stale_profile = trust_profile.TrustProfile(
        id=trust_profile.MARTY_TRUST_PROFILE_ID,
        organization_id=trust_profile.MARTY_ORG_ID,
        name="Marty Credential Login Trust",
        status=trust_profile.TrustProfileStatus.ACTIVE,
        trust_sources=[
            trust_profile.TrustSource(
                id="60000000-0000-0000-0000-000000000021",
                name="Marty Managed Issuer",
                source_type=trust_profile.TrustSourceType.PINNED_ISSUER.value,
                issuer_did="did:web:beta.elevenidllc.com",
            )
        ],
    )
    stale_issuer = trust_profile.TrustedIssuer(
        id=trust_profile.MARTY_TRUSTED_ISSUER_ID,
        trust_profile_id=trust_profile.MARTY_TRUST_PROFILE_ID,
        name="Marty Managed Issuer",
        issuer_did="did:web:beta.elevenidllc.com",
        issuer_url="https://beta.elevenidllc.com",
        status=trust_profile.IssuerStatus.ACTIVE,
    )
    asyncio.run(repo.save_profile(stale_profile))
    asyncio.run(repo.save_issuer(stale_issuer))

    asyncio.run(trust_profile._bootstrap_marty_login_trust_profile(repo))

    profile = asyncio.run(repo.get_profile(trust_profile.MARTY_TRUST_PROFILE_ID))
    issuer = asyncio.run(repo.get_issuer(trust_profile.MARTY_TRUSTED_ISSUER_ID))

    assert profile is not None
    assert profile.trust_sources[0].issuer_did == "did:web:beta.elevenidllc.com:orgs:marty"
    assert issuer is not None
    assert issuer.issuer_did == "did:web:beta.elevenidllc.com:orgs:marty"


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
        "status",
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
    assert body["status"] == "draft"
    assert "validation_rules" not in body
    assert "revocation_check_enabled" not in body
    assert "trusted_issuers" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_internal_get_trust_profile_skips_user_membership() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 200
    assert response.json()["id"] == profile.id
    assert get_membership.await_count == 0


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
    assert body["status"] == "draft"
    assert "min_key_size_rsa" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_empty_trust_profile_defaults_to_deny_all() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Empty Trust Profile",
            "supported_formats": ["SD_JWT_VC"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["trust_sources"] == []
    assert body["allowed_issuers"] == []
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_empty_trust_profile_can_explicitly_allow_all_issuers() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Open Trust Profile",
            "supported_formats": ["SD_JWT_VC"],
            "allowed_issuers": None,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["trust_sources"] == []
    assert "allowed_issuers" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_update_trust_profile_clears_to_deny_all_when_trust_sources_are_removed() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    profile.allowed_issuers = None
    asyncio.run(repo.save_profile(profile))
    client, get_membership = _build_client(repo)

    response = client.patch(
        f"/v1/trust-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
        json={
            "trust_sources": [],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["trust_sources"] == []
    assert body["allowed_issuers"] == []
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
    assert body["status"] == "active"
    assert "validation_rules" not in body
    assert "trusted_issuers" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")
