from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from marty_common import OrganizationContext, require_org_membership
from services.organization.domain.entities import Member, MemberStatus, Permission, Role
from services.organization.infrastructure.adapters import scim_http_adapter as adapter


def _build_app(member_use_case, role_use_case) -> TestClient:
    app = FastAPI()
    app.include_router(adapter.router)

    async def _member_ctx():
        return OrganizationContext(user_id="user-1", organization_id="org-1")

    app.dependency_overrides[require_org_membership] = _member_ctx
    app.dependency_overrides[adapter.get_member_use_case] = lambda: member_use_case
    app.dependency_overrides[adapter.get_role_use_case] = lambda: role_use_case
    app.dependency_overrides[adapter.get_current_user_id] = lambda: "user-1"

    return TestClient(app)


def test_service_provider_config_exposes_patch_and_filter_support():
    client = _build_app(SimpleNamespace(), SimpleNamespace())

    response = client.get("/v1/organizations/org-1/scim/v2/ServiceProviderConfig")

    assert response.status_code == 200
    body = response.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True
    assert body["schemas"] == [adapter.SCIM_SERVICE_PROVIDER_SCHEMA]


def test_list_users_supports_required_scim_filter_and_extension_mapping():
    member = Member(
        id="member-1",
        organization_id="org-1",
        user_id="auth0|abc123",
        email="alice@example.com",
        roles=[],
        status=MemberStatus.ACTIVE,
    )
    owner_role = Role(id="role-owner", organization_id="org-1", name="owner", display_name="Owner")
    issuer_role = Role(
        id="role-issuer",
        organization_id="org-1",
        name="issuer",
        display_name="Issuer",
        permissions=[Permission(id="perm-1", resource="credentials", action="issue")],
    )

    member_use_case = SimpleNamespace(list_members=AsyncMock(return_value=[member]))
    member_use_case.member_repo = SimpleNamespace()
    role_use_case = SimpleNamespace(
        get_member_roles=AsyncMock(return_value=[owner_role, issuer_role]),
    )

    client = _build_app(member_use_case, role_use_case)
    response = client.get(
        "/v1/organizations/org-1/scim/v2/Users",
        params={"filter": 'emails.value eq "alice@example.com"'},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["totalResults"] == 1
    user = body["Resources"][0]
    assert user["externalId"] == "auth0|abc123"
    assert user[adapter.SCIM_USER_EXTENSION_SCHEMA]["is_owner"] is True
    assert sorted(user[adapter.SCIM_USER_EXTENSION_SCHEMA]["role_ids"]) == ["role-issuer", "role-owner"]


def test_patch_user_deprovisions_member_and_clears_roles():
    member = Member(
        id="member-1",
        organization_id="org-1",
        user_id="auth0|abc123",
        email="alice@example.com",
        roles=[],
        status=MemberStatus.ACTIVE,
    )
    member_repo = SimpleNamespace(
        get_by_id=AsyncMock(return_value=member),
        save=AsyncMock(),
    )
    member_use_case = SimpleNamespace(member_repo=member_repo)
    role_use_case = SimpleNamespace(
        get_member_roles=AsyncMock(return_value=[]),
        role_repo=SimpleNamespace(set_member_roles=AsyncMock()),
    )

    client = _build_app(member_use_case, role_use_case)
    response = client.patch(
        "/v1/organizations/org-1/scim/v2/Users/member-1",
        json={
            "schemas": [adapter.SCIM_PATCH_OP_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )

    assert response.status_code == 200
    assert response.json()["active"] is False
    assert member.status == MemberStatus.DEACTIVATED
    role_use_case.role_repo.set_member_roles.assert_awaited_once_with("member-1", [])
    member_repo.save.assert_awaited()


def test_create_group_validates_permissions_and_returns_scim_group():
    permission = Permission(id="perm-1", resource="credentials", action="issue")
    created_role = Role(
        id="role-1",
        organization_id="org-1",
        name="credential-issuer",
        display_name="Credential Issuer",
        permissions=[permission],
    )
    member_use_case = SimpleNamespace(member_repo=SimpleNamespace(get_by_id=AsyncMock(return_value=None)))
    role_use_case = SimpleNamespace(
        list_permissions=AsyncMock(return_value=[permission]),
        create_role=AsyncMock(return_value=created_role),
        role_repo=SimpleNamespace(get_members_with_role=AsyncMock(return_value=[]), add_member_role=AsyncMock()),
    )

    client = _build_app(member_use_case, role_use_case)
    response = client.post(
        "/v1/organizations/org-1/scim/v2/Groups",
        json={
            "displayName": "Credential Issuer",
            adapter.SCIM_ROLE_EXTENSION_SCHEMA: {
                "permissions": ["credentials:issue"],
                "description": "Can issue credentials",
            },
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["displayName"] == "Credential Issuer"
    assert body[adapter.SCIM_ROLE_EXTENSION_SCHEMA]["permissions"] == ["credentials:issue"]
