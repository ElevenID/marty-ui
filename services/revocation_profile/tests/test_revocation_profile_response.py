from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.revocation_profile import main as revocation_profile


def _build_client(
    repo: revocation_profile.InMemoryRevocationProfileRepository,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(revocation_profile.router)

    revocation_profile._repo = repo

    get_membership = AsyncMock(
        return_value=OrganizationMembership(
            user_id="user-1",
            organization_id="org-1",
            status="active",
            roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
            permissions={
                "revocation-profile:view",
                "revocation-profile:create",
                "revocation-profile:delete",
                "revocation-profile:activate",
            },
            has_org_console_access=True,
        )
    )
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    revocation_profile.app.state.org_client = org_client
    return TestClient(app), get_membership


async def _save_profile(
    repo: revocation_profile.InMemoryRevocationProfileRepository,
) -> revocation_profile.RevocationProfile:
    profile = revocation_profile.RevocationProfile(
        organization_id="org-1",
        name="Protocol revocation profile",
        description="Legacy description not exposed publicly",
    )
    profile.issuer_config.status_list_base_url = "https://status.example.com/lists"
    profile.issuer_config.status_list_size = 262144
    profile.issuer_config.batch_interval_seconds = 900
    profile.issuer_config.enable_bitstring_status_list = True
    profile.issuer_config.enable_token_status_list = False
    profile.issuer_config.enable_legacy_revocation_list = True
    profile.verifier_config.mechanism_priority = [
        revocation_profile.RevocationMechanism.OCSP,
        revocation_profile.RevocationMechanism.BITSTRING_STATUS_LIST,
    ]
    profile.verifier_config.timing_mode = revocation_profile.RevocationTimingMode.CACHED
    profile.verifier_config.cache_ttl_seconds = 1800
    profile.automation_config.auto_allocate_indices = False
    await repo.save(profile)
    return profile


def test_get_revocation_profile_returns_protocol_shape_only() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.get(
        f"/v1/revocation-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "id",
        "organization_id",
        "name",
        "status",
        "revocation_mechanism",
        "mechanism_priority",
        "check_mode",
        "cache_ttl_seconds",
        "issuer_config",
        "status_list_url",
        "created_at",
        "updated_at",
    }
    assert body["revocation_mechanism"] == [
        "STATUS_LIST_2021",
        "BITSTRING_STATUS_LIST",
        "OCSP",
    ]
    assert body["status"] == "DRAFT"
    assert body["mechanism_priority"] == ["OCSP", "BITSTRING_STATUS_LIST"]
    assert body["check_mode"] == "CACHED"
    assert body["cache_ttl_seconds"] == 1800
    assert body["issuer_config"] == {
        "auto_allocate_index": False,
        "batch_update_interval_seconds": 900,
        "list_size": 262144,
        "uri_template": "https://status.example.com/lists",
    }
    assert body["status_list_url"] == (
        f"https://status.example.com/v1/organizations/org-1"
        f"/revocation-profiles/{profile.id}/status-lists/{{mechanism}}/{{purpose}}"
    )
    assert "description" not in body
    assert "verifier_config" not in body
    assert "automation_config" not in body
    assert "supported_formats" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_revocation_profile_accepts_protocol_fields() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/revocation-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Canonical revocation profile",
            "revocation_mechanism": ["OCSP", "BITSTRING_STATUS_LIST"],
            "mechanism_priority": ["OCSP", "BITSTRING_STATUS_LIST"],
            "check_mode": "OFFLINE_GRACE",
            "offline_grace_seconds": 7200,
            "issuer_config": {
                "auto_allocate_index": True,
                "batch_update_interval_seconds": 600,
                "list_size": 131072,
                "uri_template": "https://status.example.com/tenant-a"
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body["revocation_mechanism"]) == {"OCSP", "BITSTRING_STATUS_LIST"}
    assert body["mechanism_priority"] == ["OCSP", "BITSTRING_STATUS_LIST"]
    assert body["check_mode"] == "OFFLINE_GRACE"
    assert body["offline_grace_seconds"] == 7200
    assert body["issuer_config"] == {
        "auto_allocate_index": True,
        "batch_update_interval_seconds": 600,
        "list_size": 131072,
        "uri_template": "https://status.example.com/tenant-a",
    }
    assert body["status_list_url"] == (
        f"https://status.example.com/tenant-a/v1/organizations/org-1"
        f"/revocation-profiles/{body['id']}/status-lists/{{mechanism}}/{{purpose}}"
    )
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_activate_revocation_profile_keeps_protocol_shape_stable() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, get_membership = _build_client(repo)

    response = client.post(
        f"/v1/revocation-profiles/{profile.id}/activate",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == profile.id
    assert body["status"] == "ACTIVE"
    assert body["check_mode"] == "CACHED"
    assert body["cache_ttl_seconds"] == 1800
    assert "supported_formats" not in body
    assert "description" not in body
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_revocation_profile_rejects_legacy_mechanism_spelling() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    client, _ = _build_client(repo)

    response = client.post(
        "/v1/revocation-profiles",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Invalid legacy profile",
            "revocation_mechanism": ["StatusList2021"],
            "check_mode": "ALWAYS",
        },
    )

    assert response.status_code == 422


def test_internal_index_allocation_rejects_cross_org_profile() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    profile = asyncio.run(_save_profile(repo))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            revocation_profile.allocate_index(
                profile.id,
                revocation_profile.AllocateIndexRequest(
                    organization_id="org-2",
                    credential_format="sd_jwt_vc",
                ),
                repo=repo,
                status_mgr=AsyncMock(),
            )
        )

    assert exc_info.value.status_code == 403


def test_internal_lifecycle_update_rejects_cross_org_profile() -> None:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    profile = asyncio.run(_save_profile(repo))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            revocation_profile.process_revocation(
                profile.id,
                revocation_profile.ProcessRevocationRequest(
                    organization_id="org-2",
                    credential_id="credential-1",
                    index=1,
                    status="revoked",
                    credential_format="sd_jwt_vc",
                ),
                repo=repo,
                status_mgr=AsyncMock(),
            )
        )

    assert exc_info.value.status_code == 403
