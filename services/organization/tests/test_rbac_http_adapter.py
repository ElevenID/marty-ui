from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from marty_common import OrganizationContext
from services.organization.domain.entities import Permission, Role
from services.organization.infrastructure.adapters import rbac_http_adapter as adapter


@pytest.mark.asyncio
async def test_resolve_permission_ids_combines_and_dedupes_ids_and_keys():
    use_case = SimpleNamespace(
        list_permissions=AsyncMock(
            return_value=[
                Permission(id="perm-team-view", resource="team", action="view"),
                Permission(id="perm-org-view", resource="organization", action="view"),
            ]
        )
    )

    result = await adapter._resolve_permission_ids(
        use_case,
        permission_ids=["perm-existing", "perm-team-view"],
        permission_keys=["team:view", "organization:view"],
    )

    assert result == ["perm-existing", "perm-team-view", "perm-org-view"]


@pytest.mark.asyncio
async def test_resolve_permission_ids_unknown_key_returns_400():
    use_case = SimpleNamespace(
        list_permissions=AsyncMock(
            return_value=[Permission(id="perm-team-view", resource="team", action="view")]
        )
    )

    with pytest.raises(HTTPException) as exc:
        await adapter._resolve_permission_ids(
            use_case,
            permission_ids=[],
            permission_keys=["team:manage"],
        )

    assert exc.value.status_code == 400
    assert "Unknown permission keys" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_create_role_accepts_permission_keys_and_passes_resolved_ids():
    org_ctx = OrganizationContext(user_id="user-1", organization_id="org-1")

    created_role = Role(
        id="role-1",
        organization_id="org-1",
        name="auditor",
        display_name="Auditor",
        permissions=[Permission(id="perm-team-view", resource="team", action="view")],
    )

    use_case = SimpleNamespace(
        list_permissions=AsyncMock(
            return_value=[Permission(id="perm-team-view", resource="team", action="view")]
        ),
        create_role=AsyncMock(return_value=created_role),
    )

    req = adapter.CreateRoleRequest(
        name="auditor",
        display_name="Auditor",
        permission_keys=["team:view"],
    )

    response = await adapter.create_role(
        organization_id="org-1",
        request=req,
        org_ctx=org_ctx,
        use_case=use_case,
    )

    assert response.name == "auditor"
    assert [f"{p.resource}:{p.action}" for p in response.permissions] == ["team:view"]

    command = use_case.create_role.await_args.args[0]
    assert command.organization_id == "org-1"
    assert command.created_by == "user-1"
    assert command.permission_ids == ["perm-team-view"]


@pytest.mark.asyncio
async def test_update_role_uses_permission_ids_when_keys_not_provided():
    org_ctx = OrganizationContext(user_id="user-1", organization_id="org-1")

    updated_role = Role(
        id="role-1",
        organization_id="org-1",
        name="auditor",
        display_name="Auditor",
        permissions=[Permission(id="perm-1", resource="team", action="view")],
    )

    use_case = SimpleNamespace(
        update_role=AsyncMock(return_value=updated_role),
        role_repo=SimpleNamespace(get_members_with_role=AsyncMock(return_value=[])),
    )

    req = adapter.UpdateRoleRequest(permission_ids=["perm-1", "perm-2"])

    response = await adapter.update_role(
        organization_id="org-1",
        role_id="role-1",
        request=req,
        org_ctx=org_ctx,
        use_case=use_case,
    )

    assert response.id == "role-1"
    command = use_case.update_role.await_args.args[0]
    assert command.permission_ids == ["perm-1", "perm-2"]


@pytest.mark.asyncio
async def test_update_role_resolves_permission_keys_when_provided():
    org_ctx = OrganizationContext(user_id="user-1", organization_id="org-1")

    updated_role = Role(
        id="role-1",
        organization_id="org-1",
        name="auditor",
        display_name="Auditor",
        permissions=[
            Permission(id="perm-team-view", resource="team", action="view"),
            Permission(id="perm-org-view", resource="organization", action="view"),
        ],
    )

    use_case = SimpleNamespace(
        list_permissions=AsyncMock(
            return_value=[
                Permission(id="perm-team-view", resource="team", action="view"),
                Permission(id="perm-org-view", resource="organization", action="view"),
            ]
        ),
        update_role=AsyncMock(return_value=updated_role),
        role_repo=SimpleNamespace(get_members_with_role=AsyncMock(return_value=[])),
    )

    req = adapter.UpdateRoleRequest(permission_keys=["team:view", "organization:view"])

    response = await adapter.update_role(
        organization_id="org-1",
        role_id="role-1",
        request=req,
        org_ctx=org_ctx,
        use_case=use_case,
    )

    assert response.id == "role-1"
    command = use_case.update_role.await_args.args[0]
    assert command.permission_ids == ["perm-team-view", "perm-org-view"]
