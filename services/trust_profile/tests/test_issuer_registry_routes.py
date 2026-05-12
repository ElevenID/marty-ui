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
    app.include_router(trust_profile.organization_trust_profile_router)
    app.include_router(trust_profile.framework_router)
    app.include_router(trust_profile.registry_router)
    app.include_router(trust_profile.issuer_router)

    trust_profile._repo = repo
    get_membership = AsyncMock(return_value=membership or FakeMembership())
    trust_profile.app.state.org_client = SimpleNamespace(get_membership=get_membership)
    return TestClient(app), get_membership


def _save_profile(repo: trust_profile.InMemoryTrustProfileRepository, organization_id: str = "org-1") -> trust_profile.TrustProfile:
    profile = trust_profile.TrustProfile(
        organization_id=organization_id,
        name="Default trust profile",
        trust_sources=[trust_profile.TrustSource(name="Example trust list")],
    )
    asyncio.run(repo.save_profile(profile))
    return profile


def _save_issuer_entity(
    repo: trust_profile.InMemoryTrustProfileRepository,
    organization_id: str | None,
    issuer_id: str,
    *,
    display_name: str = "Issuer",
    is_system_issuer: bool = False,
) -> trust_profile.IssuerEntity:
    issuer_entity = trust_profile.IssuerEntity(
        organization_id=organization_id,
        issuer_id=issuer_id,
        display_name=display_name,
        is_system_issuer=is_system_issuer,
    )
    asyncio.run(repo.save_issuer_entity(issuer_entity))
    return issuer_entity


def _save_registry_entry(
    repo: trust_profile.InMemoryTrustProfileRepository,
    *,
    sequence: int,
    anchor_type: trust_profile.TrustAnchorType,
    country_code: str,
    is_current: bool = True,
    operation: trust_profile.TrustRegistryOperation = trust_profile.TrustRegistryOperation.ADD,
) -> trust_profile.TrustRegistryEntry:
    entry = trust_profile.TrustRegistryEntry(
        sequence=sequence,
        anchor_type=anchor_type,
        operation=operation,
        country_code=country_code,
        certificate_pem=f"-----BEGIN CERTIFICATE-----{country_code}-{sequence}",
        source=trust_profile.TrustRegistrySource.MANUAL,
        is_current=is_current,
    )
    asyncio.run(repo.save_registry_entry(entry))
    return entry


def test_create_issuer_entity_creates_protocol_record():
    repo = trust_profile.InMemoryTrustProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/issuer-entities",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "issuer_id": "did:example:issuer-1",
            "display_name": "Acme Issuer",
            "issuer_type": "ORGANIZATION",
            "metadata": {"issuer_url": "https://issuer.example"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["organization_id"] == "org-1"
    assert body["issuer_id"] == "did:example:issuer-1"
    assert body["display_name"] == "Acme Issuer"
    assert body["metadata"] == {"issuer_url": "https://issuer.example"}
    get_membership.assert_awaited_once_with("user-1", "org-1")

    saved = asyncio.run(repo.find_issuer_entity_by_identifier("org-1", "did:example:issuer-1"))
    assert saved is not None
    assert saved.display_name == "Acme Issuer"


def test_create_issuer_entity_rejects_duplicate_identifier_within_scope():
    repo = trust_profile.InMemoryTrustProfileRepository()
    _save_issuer_entity(repo, "org-1", "did:example:issuer-1")
    client, _ = _build_client(repo)

    response = client.post(
        "/v1/issuer-entities",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "issuer_id": "did:example:issuer-1",
            "display_name": "Duplicate Issuer",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Issuer identifier already exists in this scope"


def test_add_trusted_issuer_creates_compatibility_link_to_issuer_entity():
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = _save_profile(repo)
    client, _ = _build_client(repo)

    response = client.post(
        f"/v1/trust-profiles/{profile.id}/issuers",
        headers={"x-user-id": "user-1"},
        json={
            "name": "Acme Issuer",
            "description": "Legacy compatibility issuer",
            "issuer_did": "did:example:issuer-compat",
            "issuer_url": "https://issuer.example",
            "credential_template_ids": ["tpl-1"],
            "verification_keys": [{"kid": "key-1"}],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["trust_profile_id"] == profile.id
    assert body["issuer_id"] is not None
    assert body["trust_level"] == 100
    assert body["relationship_status"] == "TRUSTED"
    assert body["cascade_revocation_policy"] == "NOTIFY_ONLY"
    assert body["metadata"]["credential_template_ids"] == ["tpl-1"]
    assert body["metadata"]["verification_keys"] == [{"kid": "key-1"}]
    # Denormalized fields removed — issuer_did, name now only on IssuerEntity
    assert "issuer_did" not in body
    assert "issuer_entity_id" not in body

    issuer_entity = asyncio.run(
        repo.find_issuer_entity_by_identifier(profile.organization_id, "did:example:issuer-compat")
    )
    assert issuer_entity is not None
    assert issuer_entity.display_name == "Acme Issuer"

    links = asyncio.run(repo.list_profile_issuers(profile.id))
    assert len(links) == 1
    assert links[0].issuer_id == issuer_entity.id


def test_update_trusted_issuer_updates_relationship_fields_and_metadata():
    repo = trust_profile.InMemoryTrustProfileRepository()
    profile = _save_profile(repo)
    issuer_entity = _save_issuer_entity(repo, profile.organization_id, "did:example:issuer-1", display_name="Acme")
    profile_issuer = trust_profile.TrustProfileIssuer(
        trust_profile_id=profile.id,
        issuer_id=issuer_entity.id,
        metadata={"legacy_name": "Acme", "issuer_url": "https://old.example"},
    )
    asyncio.run(repo.save_profile_issuer(profile_issuer))
    client, _ = _build_client(repo)

    response = client.put(
        f"/v1/trust-profiles/{profile.id}/issuers/{profile_issuer.id}",
        headers={"x-user-id": "user-1"},
        json={
            "name": "Acme Updated",
            "issuer_url": "https://new.example",
            "issuer_did": "did:example:issuer-2",
            "trust_level": 77,
            "relationship_status": "UNDER_REVIEW",
            "cascade_revocation_policy": "MANUAL",
            "credential_template_ids": ["tpl-2"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    # Protocol schema fields only
    assert body["trust_level"] == 77
    assert body["relationship_status"] == "UNDER_REVIEW"
    assert body["cascade_revocation_policy"] == "MANUAL"
    assert body["metadata"]["credential_template_ids"] == ["tpl-2"]
    # Denormalized fields removed from response
    assert "name" not in body
    assert "issuer_did" not in body
    assert "issuer_url" not in body

    saved_entity = asyncio.run(repo.get_issuer_entity(issuer_entity.id))
    assert saved_entity is not None
    assert saved_entity.display_name == "Acme Updated"
    assert saved_entity.issuer_id == "did:example:issuer-2"

    saved_link = asyncio.run(repo.get_profile_issuer(profile_issuer.id))
    assert saved_link is not None
    assert saved_link.trust_level == 77
    assert saved_link.relationship_status == trust_profile.TrustRelationshipStatus.UNDER_REVIEW
    assert saved_link.cascade_revocation_policy == trust_profile.CascadeRevocationPolicy.MANUAL


def test_revoked_issuer_entity_cannot_be_reinstated():
    repo = trust_profile.InMemoryTrustProfileRepository()
    issuer_entity = _save_issuer_entity(repo, "org-1", "did:example:issuer-1")
    client, _ = _build_client(repo)

    revoke_response = client.put(
        f"/v1/issuer-entities/{issuer_entity.id}",
        headers={"x-user-id": "user-1"},
        json={
            "compliance_status": "REVOKED",
            "revocation_reason": "Key compromise",
        },
    )

    assert revoke_response.status_code == 200
    revoke_body = revoke_response.json()
    assert revoke_body["compliance_status"] == "REVOKED"
    assert revoke_body["revocation_reason"] == "Key compromise"
    assert revoke_body["revoked_by"] == "user-1"
    assert revoke_body["revoked_at"] is not None

    reinstate_response = client.put(
        f"/v1/issuer-entities/{issuer_entity.id}",
        headers={"x-user-id": "user-1"},
        json={"compliance_status": "COMPLIANT"},
    )

    assert reinstate_response.status_code == 400
    assert reinstate_response.json()["detail"] == (
        "Revoked issuer cannot be reinstated; create a new IssuerEntity instead"
    )


def test_list_trust_frameworks_returns_seeded_system_frameworks():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    client, _ = _build_client(repo)

    response = client.get(
        "/v1/trust-frameworks",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert [framework["code"] for framework in body] == ["AAMVA", "EUDI", "ICAO"]
    assert all(framework["is_system"] is True for framework in body)
    assert body[0]["default_formats"]


def test_sync_trust_registry_returns_delta_entries_and_status_counts():
    repo = trust_profile.InMemoryTrustProfileRepository()
    removed_entry = _save_registry_entry(
        repo,
        sequence=1,
        anchor_type=trust_profile.TrustAnchorType.CSCA,
        country_code="US",
        is_current=False,
        operation=trust_profile.TrustRegistryOperation.REMOVE,
    )
    current_csca = _save_registry_entry(
        repo,
        sequence=2,
        anchor_type=trust_profile.TrustAnchorType.CSCA,
        country_code="US",
    )
    current_dsc = _save_registry_entry(
        repo,
        sequence=3,
        anchor_type=trust_profile.TrustAnchorType.DSC,
        country_code="CA",
    )
    client, _ = _build_client(repo)

    sync_response = client.get("/v1/trust-registry/sync", params={"since": "1"})

    assert sync_response.status_code == 200
    sync_body = sync_response.json()
    assert sync_body["sync_token"] == "3"
    assert sync_body["sequence"] == 3
    assert [entry["entry_id"] for entry in sync_body["entries"]] == [current_csca.id, current_dsc.id]
    assert removed_entry.id not in [entry["entry_id"] for entry in sync_body["entries"]]

    status_response = client.get("/v1/trust-registry/status")

    assert status_response.status_code == 200
    status_body = status_response.json()
    assert status_body["current_sequence"] == 3
    assert status_body["total_entries"] == 3
    assert status_body["current_entries"] == 2
    assert status_body["csca_entries"] == 1
    assert status_body["dsc_entries"] == 1


def test_list_country_csca_entries_filters_by_country_and_invalid_sync_token_is_rejected():
    repo = trust_profile.InMemoryTrustProfileRepository()
    us_entry = _save_registry_entry(
        repo,
        sequence=1,
        anchor_type=trust_profile.TrustAnchorType.CSCA,
        country_code="US",
    )
    _save_registry_entry(
        repo,
        sequence=2,
        anchor_type=trust_profile.TrustAnchorType.CSCA,
        country_code="CA",
    )
    _save_registry_entry(
        repo,
        sequence=3,
        anchor_type=trust_profile.TrustAnchorType.DSC,
        country_code="US",
    )
    client, _ = _build_client(repo)

    country_response = client.get("/v1/trust-registry/csca/us")

    assert country_response.status_code == 200
    country_body = country_response.json()
    assert [entry["entry_id"] for entry in country_body] == [us_entry.id]
    assert all(entry["country_code"] == "US" for entry in country_body)
    assert all(entry["anchor_type"] == "CSCA" for entry in country_body)

    invalid_response = client.get("/v1/trust-registry/sync", params={"since": "not-a-token"})

    assert invalid_response.status_code == 400
    assert invalid_response.json()["detail"] == "Invalid sync token"


def test_create_and_update_organization_trust_profile_uses_framework_overlay_fields():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    framework = asyncio.run(repo.get_framework_by_code("ICAO"))
    assert framework is not None
    client, get_membership = _build_client(repo)

    create_response = client.post(
        "/v1/organizations/org-1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "framework_id": framework.id,
            "name": "Org ICAO Overlay",
            "display_name": "Org ICAO",
            "description": "Organization overlay",
            "enabled": True,
            "use_case_tags": ["border", "travel"],
            "allowed_algorithms": ["ES256"],
            "allowed_formats": ["MDOC", "sd_jwt_vc"],
            "allowed_issuers": ["did:example:issuer-1"],
            "denied_issuers": ["did:example:issuer-2"],
            "jurisdiction_filter": ["us", "ca-bc"],
            "metadata": {"source": "test"},
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["organization_id"] == "org-1"
    assert created["framework_id"] == framework.id
    assert created["display_name"] == "Org ICAO"
    assert created["allowed_formats"] == ["MDOC", "SD_JWT_VC"]
    assert created["jurisdiction_filter"] == ["US", "CA-BC"]
    assert created["metadata"] == {"source": "test"}

    list_response = client.get(
        "/v1/organizations/org-1/trust-profiles",
        headers={"x-user-id": "user-1"},
    )

    assert list_response.status_code == 200
    listed = list_response.json()
    assert [profile["id"] for profile in listed] == [created["id"]]

    update_response = client.put(
        f"/v1/organizations/org-1/trust-profiles/{created['id']}",
        headers={"x-user-id": "user-1"},
        json={
            "enabled": False,
            "allowed_formats": ["mdoc"],
            "jurisdiction_filter": ["us-ca"],
            "use_case_tags": ["domestic"],
        },
    )

    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["enabled"] is False
    assert updated["allowed_formats"] == ["MDOC"]
    assert updated["jurisdiction_filter"] == ["US-CA"]
    assert updated["use_case_tags"] == ["domestic"]
    assert get_membership.await_count == 3


def test_create_organization_trust_profile_rejects_invalid_jurisdiction_code():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    framework = asyncio.run(repo.get_framework_by_code("EUDI"))
    assert framework is not None
    client, _ = _build_client(repo)

    response = client.post(
        "/v1/organizations/org-1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "framework_id": framework.id,
            "name": "Bad Jurisdiction Overlay",
            "jurisdiction_filter": ["USA-CA"],
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid jurisdiction code: USA-CA"


def test_update_organization_trust_profile_requires_admin_membership():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    framework = asyncio.run(repo.get_framework_by_code("AAMVA"))
    assert framework is not None

    profile = trust_profile.OrganizationTrustProfile(
        organization_id="org-1",
        framework_id=framework.id,
        name="Org AAMVA Overlay",
    )
    asyncio.run(repo.save_organization_trust_profile(profile))
    client, _ = _build_client(repo, membership=FakeMembership(roles=("member",)))

    response = client.put(
        f"/v1/organizations/org-1/trust-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
        json={"name": "Updated Overlay"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Missing required permission: trust-profile:edit"


def test_organization_trust_profile_key_management_round_trip_and_connection_test():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    framework = asyncio.run(repo.get_framework_by_code("ICAO"))
    assert framework is not None
    client, _ = _build_client(repo)

    create_response = client.post(
        "/v1/organizations/org-1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "framework_id": framework.id,
            "name": "Org ICAO Key Overlay",
            "key_management": {
                "source": "kms",
                "kms_arn": "arn:aws:kms:us-east-1:123456789012:key/test",
                "kms_region": "us-east-1",
                "algorithm": "ES256",
            },
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["key_management"]["source"] == "kms"
    assert created["metadata"]["key_management"]["kms_arn"].startswith("arn:aws:kms")

    connection_response = client.post(
        f"/v1/organizations/org-1/trust-profiles/{created['id']}/test-key-connection",
        headers={"x-user-id": "user-1"},
        json={
            "key_management": {
                "source": "kms",
                "kms_arn": "arn:aws:kms:us-east-1:123456789012:key/test",
                "kms_region": "us-east-1",
            }
        },
    )

    assert connection_response.status_code == 200
    connection = connection_response.json()
    assert connection["success"] is True
    assert connection["source"] == "kms"


def test_organization_trust_profile_create_or_associate_key_sets_binding_metadata():
    repo = trust_profile.InMemoryTrustProfileRepository()
    asyncio.run(trust_profile._seed_system_frameworks(repo))
    framework = asyncio.run(repo.get_framework_by_code("EUDI"))
    assert framework is not None
    client, _ = _build_client(repo)

    create_response = client.post(
        "/v1/organizations/org-1/trust-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "framework_id": framework.id,
            "name": "Org EUDI Key Overlay",
            "key_management": {
                "source": "signing_agent",
                "signing_agent_url": "https://signer.example",
                "signing_agent_auth": "mtls",
            },
        },
    )
    assert create_response.status_code == 200
    profile_id = create_response.json()["id"]

    key_action_response = client.post(
        f"/v1/organizations/org-1/trust-profiles/{profile_id}/create-or-associate-key",
        headers={"x-user-id": "user-1"},
        json={
            "algorithm": "EdDSA",
            "key_reference": "agent-key-123",
        },
    )

    assert key_action_response.status_code == 200
    payload = key_action_response.json()
    assert payload["success"] is True
    assert payload["action"] == "associated"
    assert payload["source"] == "signing_agent"
    assert payload["key_id"].startswith("key_")

    saved_profile = asyncio.run(repo.get_organization_trust_profile(profile_id))
    assert saved_profile is not None
    assert saved_profile.metadata["key_binding"]["associated_reference"] == "agent-key-123"
