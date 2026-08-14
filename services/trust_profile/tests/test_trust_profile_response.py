from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from services.trust_profile import main as trust_profile
from trust_profile.registry_sync import (
    ImportedRegistryEntry,
    RegistryImportResult,
    RegistryImportState,
    RegistrySyncError,
)


def _registry_certificate_pem(*, expired: bool = False) -> str:
    now = datetime.now(timezone.utc)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Registry response test")]
    )
    not_after = now - timedelta(hours=1) if expired else now + timedelta(days=365)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


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
    app.include_router(trust_profile.resource_owner_router)

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
    stale_issuer = trust_profile.IssuerEntity(
        id=trust_profile.MARTY_ISSUER_ENTITY_ID,
        organization_id=trust_profile.MARTY_ORG_ID,
        issuer_id="did:web:beta.elevenidllc.com",
        display_name="Marty Managed Issuer",
        metadata={"issuer_url": "https://beta.elevenidllc.com"},
    )
    stale_link = trust_profile.TrustProfileIssuer(
        id=trust_profile.MARTY_TRUSTED_ISSUER_ID,
        trust_profile_id=trust_profile.MARTY_TRUST_PROFILE_ID,
        issuer_id=stale_issuer.id,
    )
    asyncio.run(repo.save_profile(stale_profile))
    asyncio.run(repo.save_issuer_entity(stale_issuer))
    asyncio.run(repo.save_profile_issuer(stale_link))

    asyncio.run(trust_profile._bootstrap_marty_login_trust_profile(repo))

    profile = asyncio.run(repo.get_profile(trust_profile.MARTY_TRUST_PROFILE_ID))
    issuer = asyncio.run(repo.get_issuer_entity(trust_profile.MARTY_ISSUER_ENTITY_ID))
    link = asyncio.run(repo.get_profile_issuer(trust_profile.MARTY_TRUSTED_ISSUER_ID))

    assert profile is not None
    assert (
        profile.trust_sources[0].issuer_did == "did:web:beta.elevenidllc.com:orgs:marty"
    )
    assert issuer is not None
    assert issuer.issuer_id == "did:web:beta.elevenidllc.com:orgs:marty"
    assert link is not None
    assert link.issuer_id == issuer.id


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
            "did:example:issuer-3": {
                "action": "DOWNGRADE",
                "trust_level": 40,
                "reason": "Pilot issuer",
            }
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
            "pinned_certificates": [],
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
    assert response.json()["issuer_relationships"] == []
    assert get_membership.await_count == 0


def test_internal_get_trust_profile_requires_production_service_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "a" * 48
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GRPC_SERVICE_TOKEN", token)
    monkeypatch.delenv("GRPC_SERVICE_TOKEN_FILE", raising=False)
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    assert client.get(f"/internal/v1/trust-profiles/{profile.id}").status_code == 401
    response = client.get(
        f"/internal/v1/trust-profiles/{profile.id}",
        headers={"x-service-token": token},
    )

    assert response.status_code == 200
    assert get_membership.await_count == 0


def test_registry_sync_uses_stored_organization_and_materializes_imported_anchors(
    monkeypatch,
) -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = trust_profile.TrustProfile(
        organization_id="org-2",
        name="External registry profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/v1/trust-registry/sync",
                registry_sync={
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 24,
                },
                refresh_interval_hours=24,
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, get_membership = _build_client(repo)
    imported_certificate = _registry_certificate_pem()

    async def fake_sync(url, previous, *, client, now):
        assert url == "https://registry.example/v1/trust-registry/sync"
        assert previous == RegistryImportState()
        entry = ImportedRegistryEntry(
            entry_id="c6d7e8f9-a0b1-4234-9678-901234abcdef",
            anchor_type="CSCA",
            country_code="US",
            certificate_pem=imported_certificate,
            source="MANUAL",
        )
        return RegistryImportResult(
            state=RegistryImportState(
                sync_token="8",
                sequence=8,
                entries={entry.entry_id: entry},
                synchronized_at=now,
            ),
            pages=1,
        )

    monkeypatch.setattr(trust_profile, "synchronize_registry", fake_sync)
    response = client.post(
        f"/v1/trust-profiles/{profile.id}/registry-sync",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    assert response.json()["sources"] == [
        {
            "url": "https://registry.example/v1/trust-registry/sync",
            "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
            "sequence": 8,
            "csca_entries": 1,
            "dsc_entries": 0,
            "synchronized_at": response.json()["synchronized_at"],
        }
    ]
    get_membership.assert_awaited_once_with("user-1", "org-2")

    stored = asyncio.run(repo.get_profile(profile.id))
    assert stored is not None
    assert stored.trust_sources[0].registry_sequence == 8
    assert set(stored.trust_sources[0].registry_entries) == {
        "c6d7e8f9-a0b1-4234-9678-901234abcdef"
    }

    internal = client.get(f"/internal/v1/trust-profiles/{profile.id}")
    assert internal.status_code == 200
    imported = [
        source
        for source in internal.json()["trust_sources"]
        if source["source_type"] == "ROOT_CA"
    ]
    assert imported == [
        {
            "source_type": "ROOT_CA",
            "certificate_pem": imported_certificate,
            "description": "Imported CSCA from https://registry.example/v1/trust-registry/sync",
            "pinned_certificates": [],
        }
    ]


def test_registry_sync_failure_is_atomic(monkeypatch) -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    sources = [
        trust_profile.TrustSource(
            source_type="TRUST_LIST",
            url=f"https://registry-{index}.example/v1/trust-registry/sync",
            registry_sync={
                "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                "refresh_interval_hours": 24,
            },
        )
        for index in (1, 2)
    ]
    profile = trust_profile.TrustProfile(
        organization_id="org-1", name="Atomic registry profile", trust_sources=sources
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)
    calls = 0

    async def partially_failing_sync(url, previous, *, client, now):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RegistrySyncError("second source rejected")
        return RegistryImportResult(
            state=RegistryImportState(sync_token="1", sequence=1, synchronized_at=now),
            pages=1,
        )

    monkeypatch.setattr(trust_profile, "synchronize_registry", partially_failing_sync)
    response = client.post(
        f"/v1/trust-profiles/{profile.id}/registry-sync",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 502
    stored = asyncio.run(repo.get_profile(profile.id))
    assert stored is not None
    assert [source.registry_sequence for source in stored.trust_sources] == [0, 0]
    assert all(source.registry_sync_token is None for source in stored.trust_sources)


def test_registry_sync_rejects_concurrent_profile_change(monkeypatch) -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="Concurrent registry profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/v1/trust-registry/sync",
                registry_sync={
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 24,
                },
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)

    async def concurrent_sync(url, previous, *, client, now):
        profile.updated_at = now + timedelta(seconds=1)
        return RegistryImportResult(
            state=RegistryImportState(sync_token="1", sequence=1, synchronized_at=now),
            pages=1,
        )

    monkeypatch.setattr(trust_profile, "synchronize_registry", concurrent_sync)
    response = client.post(
        f"/v1/trust-profiles/{profile.id}/registry-sync",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 409
    stored = asyncio.run(repo.get_profile(profile.id))
    assert stored is not None
    assert stored.trust_sources[0].registry_sequence == 0


def test_internal_trust_decision_rejects_unsynchronized_registry_source() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="Unsynchronized registry profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/v1/trust-registry/sync",
                registry_sync={
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 24,
                },
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Trust Profile registry source has never synchronized"
    )

    activation = client.post(
        f"/v1/trust-profiles/{profile.id}/activate",
        headers={"x-user-id": "user-1"},
    )
    assert activation.status_code == 409
    stored = asyncio.run(repo.get_profile(profile.id))
    assert stored is not None
    assert stored.status == trust_profile.TrustProfileStatus.DRAFT


def test_internal_trust_decision_rejects_stale_registry_source() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="Stale registry profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/v1/trust-registry/sync",
                registry_sync={
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 1,
                },
                refresh_interval_hours=1,
                registry_sync_token="1",
                registry_sequence=1,
                registry_last_synced_at=datetime.now(timezone.utc) - timedelta(hours=2),
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json()["detail"] == "Trust Profile registry source is stale"


def test_internal_trust_decision_revalidates_imported_certificate_state() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    entry = ImportedRegistryEntry(
        entry_id="c6d7e8f9-a0b1-4234-9678-901234abcdef",
        anchor_type="CSCA",
        country_code="US",
        certificate_pem=_registry_certificate_pem(expired=True),
        source="MANUAL",
    )
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="Expired imported certificate profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/v1/trust-registry/sync",
                registry_sync={
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 24,
                },
                registry_sync_token="1",
                registry_sequence=1,
                registry_entries={entry.entry_id: entry.to_storage()},
                registry_last_synced_at=datetime.now(timezone.utc),
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json()["detail"] == "Trust Profile registry state is invalid"


def test_internal_trust_decision_rejects_legacy_url_without_adapter() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = trust_profile.TrustProfile(
        organization_id="org-1",
        name="Legacy URL-only profile",
        trust_sources=[
            trust_profile.TrustSource(
                source_type="TRUST_LIST",
                url="https://registry.example/unknown-format",
            )
        ],
    )
    asyncio.run(repo.save_profile(profile))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Trust Profile registry source has no supported sync protocol"
    )


def test_registry_source_becomes_due_before_its_fail_closed_deadline() -> None:
    source = trust_profile.TrustSource(
        source_type="TRUST_LIST",
        url="https://registry.example/v1/trust-registry/sync",
        registry_sync={
            "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
            "refresh_interval_hours": 24,
        },
        registry_last_synced_at=datetime(2026, 8, 7, tzinfo=timezone.utc),
    )

    assert not trust_profile._registry_source_is_due(
        source, datetime(2026, 8, 7, 19, tzinfo=timezone.utc)
    )
    assert trust_profile._registry_source_is_due(
        source, datetime(2026, 8, 7, 20, tzinfo=timezone.utc)
    )


@pytest.mark.asyncio
async def test_scheduler_refreshes_only_due_registry_sources(monkeypatch) -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    now = datetime.now(timezone.utc)

    def profile(name: str, last_synced: datetime) -> trust_profile.TrustProfile:
        return trust_profile.TrustProfile(
            organization_id="org-1",
            name=name,
            trust_sources=[
                trust_profile.TrustSource(
                    source_type="TRUST_LIST",
                    url=f"https://registry.example/{name}/sync",
                    registry_sync={
                        "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                        "refresh_interval_hours": 24,
                    },
                    registry_sync_token="1",
                    registry_sequence=1,
                    registry_last_synced_at=last_synced,
                )
            ],
        )

    due = profile("due", now - timedelta(hours=20))
    fresh = profile("fresh", now - timedelta(hours=1))
    await repo.save_profile(due)
    await repo.save_profile(fresh)
    refreshed: list[str] = []

    async def successful_sync(url, previous, *, client, now):
        refreshed.append(url)
        return RegistryImportResult(
            state=RegistryImportState(
                sync_token="2",
                sequence=2,
                entries=previous.entries,
                synchronized_at=now,
            ),
            pages=1,
        )

    monkeypatch.setattr(trust_profile, "synchronize_registry", successful_sync)
    await trust_profile._synchronize_due_registry_sources(repo)

    stored_due = await repo.get_profile(due.id)
    stored_fresh = await repo.get_profile(fresh.id)
    assert stored_due is not None
    assert stored_fresh is not None
    assert refreshed == ["https://registry.example/due/sync"]
    assert stored_due.trust_sources[0].registry_sequence == 2
    assert stored_fresh.trust_sources[0].registry_sequence == 1


def test_internal_get_trust_profile_materializes_normalized_issuer_decision() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    issuer = trust_profile.IssuerEntity(
        organization_id=profile.organization_id,
        issuer_id="did:web:issuer.example",
        display_name="Example Issuer",
        compliance_status=trust_profile.IssuerEntityComplianceStatus.ACCREDITED,
        accreditation_body="Example Accreditation Authority",
        accreditations=["ISO27001", "FIPS140-2"],
        metadata={
            "verification_keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "public-x",
                    "y": "public-y",
                }
            ]
        },
    )
    relationship = trust_profile.TrustProfileIssuer(
        trust_profile_id=profile.id,
        issuer_id=issuer.id,
        trust_level=87,
        relationship_status=trust_profile.TrustRelationshipStatus.TRUSTED,
    )
    asyncio.run(repo.save_issuer_entity(issuer))
    asyncio.run(repo.save_profile_issuer(relationship))
    client, get_membership = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 200
    assert response.json()["issuer_relationships"] == [
        {
            "issuer_id": "did:web:issuer.example",
            "trust_level": 87,
            "relationship_status": "TRUSTED",
            "compliance_status": "ACCREDITED",
            "accreditation_body": "Example Accreditation Authority",
            "accreditations": ["ISO27001", "FIPS140-2"],
            "valid_from": issuer.valid_from.isoformat(),
            "verification_keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "public-x",
                    "y": "public-y",
                }
            ],
        }
    ]
    assert get_membership.await_count == 0


def test_internal_get_trust_profile_fails_closed_for_cross_org_relationship() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    issuer = trust_profile.IssuerEntity(
        organization_id="org-other",
        issuer_id="did:web:foreign.example",
        display_name="Foreign Issuer",
    )
    relationship = trust_profile.TrustProfileIssuer(
        trust_profile_id=profile.id,
        issuer_id=issuer.id,
    )
    asyncio.run(repo.save_issuer_entity(issuer))
    asyncio.run(repo.save_profile_issuer(relationship))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Trust Profile contains a cross-organization issuer relationship"
    }


def test_internal_get_trust_profile_fails_closed_for_invalid_verification_keys() -> (
    None
):
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    issuer = trust_profile.IssuerEntity(
        organization_id=profile.organization_id,
        issuer_id="https://issuer.example",
        display_name="Malformed Issuer",
        metadata={
            "verification_keys": [
                {"kty": "EC", "crv": "P-256", "d": "private-material"}
            ]
        },
    )
    relationship = trust_profile.TrustProfileIssuer(
        trust_profile_id=profile.id,
        issuer_id=issuer.id,
    )
    asyncio.run(repo.save_issuer_entity(issuer))
    asyncio.run(repo.save_profile_issuer(relationship))
    client, _ = _build_client(repo)

    response = client.get(f"/internal/v1/trust-profiles/{profile.id}")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Trust Profile contains invalid issuer verification keys"
    }


def test_resource_owner_lookup_is_minimal_and_service_authenticated(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "gateway-service-key")
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    unauthorized = client.get(
        f"/internal/v1/resource-owners/trust-profiles/{profile.id}"
    )
    response = client.get(
        f"/internal/v1/resource-owners/trust-profiles/{profile.id}",
        headers={"X-API-Key": "gateway-service-key"},
    )

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert response.json() == {"organization_id": profile.organization_id}
    assert get_membership.await_count == 0


def test_resource_owner_lookup_hides_missing_resources(monkeypatch) -> None:
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "gateway-service-key")
    client, _ = _build_client(trust_profile.InMemoryTrustProfileRepository())

    response = client.get(
        "/internal/v1/resource-owners/trust-profiles/missing",
        headers={"X-API-Key": "gateway-service-key"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Resource not found"}


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
                    "source_type": "trust_list",
                    "url": "https://trust.example/eudi.json",
                    "description": "LOTL source",
                    "registry_sync": {
                        "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                        "refresh_interval_hours": 24,
                    },
                }
            ],
            "allowed_algorithms": ["ES256"],
            "revocation_policy": {
                "check_mode": "HARD_FAIL",
                "check_ocsp": True,
                "check_crl": True,
                "check_status_list": False,
                "cache_duration_hours": 1,
            },
            "time_policy": {
                "clock_skew_seconds": 60,
                "require_freshness": True,
                "freshness_window_seconds": 3600,
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
    assert body["time_policy"] == {
        "clock_skew_seconds": 60,
        "max_credential_age_seconds": 3600,
        "require_freshness": True,
        "freshness_window_seconds": 3600,
    }
    assert body["verification_policy_set_id"] == "policy-set-2"
    assert body["compatible_compliance_codes"] == ["EUDI_PID"]
    assert body["status"] == "draft"
    assert "min_key_size_rsa" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_trust_profile_round_trips_canvas_issuer_aliases() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Canvas Badge Trust",
            "profile_type": "CUSTOM",
            "supported_formats": ["SD_JWT_VC"],
            "trust_sources": [
                {
                    "source_type": "PINNED_ISSUER",
                    "url": "https://canvas.example.edu/issuers/issuer-123",
                    "description": "Pinned Canvas Credentials issuer",
                }
            ],
            "allowed_issuers": [
                "https://canvas.example.edu/issuers/issuer-123",
                "canvas.example.edu",
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["allowed_issuers"] == [
        "https://canvas.example.edu/issuers/issuer-123",
        "canvas.example.edu",
    ]
    assert body["trust_sources"] == [
        {
            "source_type": "PINNED_ISSUER",
            "url": "https://canvas.example.edu/issuers/issuer-123",
            "certificate_pem": None,
            "issuer_did": None,
            "description": "Pinned Canvas Credentials issuer",
            "pinned_certificates": [],
        }
    ]
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


def test_update_trust_profile_clears_to_deny_all_when_trust_sources_are_removed() -> (
    None
):
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


def test_update_trust_profile_uses_public_time_policy_contract() -> None:
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.patch(
        f"/v1/trust-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
        json={
            "time_policy": {
                "clock_skew_seconds": 900,
                "require_freshness": False,
                "freshness_window_seconds": 21_600,
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["time_policy"] == {
        "clock_skew_seconds": 900,
        "max_credential_age_seconds": None,
        "require_freshness": False,
        "freshness_window_seconds": None,
    }
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
    with pytest.raises(ValidationError):
        trust_profile.TrustProfileResponse.model_validate({**body, "status": "ACTIVE"})
    get_membership.assert_awaited_once_with("user-1", "org-1")
