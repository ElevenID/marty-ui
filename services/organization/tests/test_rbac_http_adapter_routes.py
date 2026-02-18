from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from marty_common import OrganizationContext, require_org_admin, require_org_membership
from services.organization.domain.entities import Permission, Role
from services.organization.infrastructure.adapters import rbac_http_adapter as adapter


def _build_app(use_case) -> TestClient:
    app = FastAPI()
    app.include_router(adapter.router)

    async def _admin_ctx():
        return OrganizationContext(user_id="user-1", organization_id="org-1")

    async def _member_ctx():
        return OrganizationContext(user_id="user-1", organization_id="org-1")

    app.dependency_overrides[require_org_admin] = _admin_ctx
    app.dependency_overrides[require_org_membership] = _member_ctx
    app.dependency_overrides[adapter.get_role_use_case] = lambda: use_case

    return TestClient(app)


def test_create_role_route_accepts_permission_keys_and_resolves_ids():
    perms = [
        Permission(id="perm-team-view", resource="team", action="view"),
        Permission(id="perm-org-view", resource="organization", action="view"),
    ]
    created_role = Role(
        id="role-1",
        organization_id="org-1",
        name="auditor",
        display_name="Auditor",
        permissions=perms,
    )

    use_case = SimpleNamespace(
        list_permissions=AsyncMock(return_value=perms),
        create_role=AsyncMock(return_value=created_role),
    )

    client = _build_app(use_case)
    response = client.post(
        "/v1/organizations/org-1/roles",
        json={
            "name": "auditor",
            "display_name": "Auditor",
            "permission_keys": ["team:view", "organization:view"],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "auditor"
    assert sorted(f"{p['resource']}:{p['action']}" for p in body["permissions"]) == [
        "organization:view",
        "team:view",
    ]

    command = use_case.create_role.await_args.args[0]
    assert command.permission_ids == ["perm-team-view", "perm-org-view"]


def test_update_role_route_accepts_permission_keys_and_resolves_ids():
    catalog = [
        Permission(id="perm-team-view", resource="team", action="view"),
        Permission(id="perm-org-view", resource="organization", action="view"),
    ]
    updated_role = Role(
        id="role-1",
        organization_id="org-1",
        name="auditor",
        display_name="Auditor",
        permissions=catalog,
    )

    use_case = SimpleNamespace(
        list_permissions=AsyncMock(return_value=catalog),
        update_role=AsyncMock(return_value=updated_role),
        role_repo=SimpleNamespace(get_members_with_role=AsyncMock(return_value=[])),
    )

    client = _build_app(use_case)
    response = client.patch(
        "/v1/organizations/org-1/roles/role-1",
        json={"permission_keys": ["team:view", "organization:view"]},
    )

    assert response.status_code == 200
    command = use_case.update_role.await_args.args[0]
    assert command.permission_ids == ["perm-team-view", "perm-org-view"]


def test_create_role_route_rejects_unknown_permission_key():
    use_case = SimpleNamespace(
        list_permissions=AsyncMock(
            return_value=[Permission(id="perm-team-view", resource="team", action="view")]
        ),
        create_role=AsyncMock(),
    )

    client = _build_app(use_case)
    response = client.post(
        "/v1/organizations/org-1/roles",
        json={
            "name": "auditor",
            "permission_keys": ["team:manage"],
        },
    )

    assert response.status_code == 400
    assert "Unknown permission keys" in response.json()["detail"]
    use_case.create_role.assert_not_called()
