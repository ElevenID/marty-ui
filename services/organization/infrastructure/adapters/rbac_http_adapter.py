"""
RBAC HTTP Adapter (FastAPI)

API endpoints for role and permission management.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from marty_common import OrganizationContext, require_org_admin, require_org_membership

from ...application.ports import (
    AddMemberRoleCommand,
    CreateRoleCommand,
    DeleteRoleCommand,
    RemoveMemberRoleCommand,
    SetMemberRolesCommand,
    UpdateRoleCommand,
)
from ...application.rbac_use_cases import RoleUseCase

logger = logging.getLogger(__name__)

# Router mounts under /v1/organizations/{organization_id}
router = APIRouter(
    prefix="/v1/organizations/{organization_id}",
    tags=["roles"],
)


# =============================================================================
# Request / Response Models
# =============================================================================

class PermissionResponse(BaseModel):
    id: str
    resource: str
    action: str
    description: str | None = None


class RoleResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    display_name: str | None
    description: str | None
    is_system: bool
    is_default_for_new_members: bool
    permissions: list[PermissionResponse]
    member_count: int | None = None
    created_at: str
    updated_at: str


class RoleSummaryResponse(BaseModel):
    """Lightweight role representation (no permissions list)."""
    id: str
    name: str
    display_name: str | None


class CreateRoleRequest(BaseModel):
    name: str
    display_name: str | None = None
    description: str | None = None
    permission_ids: list[str] = []
    permission_keys: list[str] = []  # Backward compatibility: ["resource:action", ...]
    is_default_for_new_members: bool = False


class UpdateRoleRequest(BaseModel):
    display_name: str | None = None
    description: str | None = None
    permission_ids: list[str] | None = None
    permission_keys: list[str] | None = None  # Backward compatibility: ["resource:action", ...]
    is_default_for_new_members: bool | None = None


class SetMemberRolesRequest(BaseModel):
    role_ids: list[str]


class MemberPermissionsResponse(BaseModel):
    """Flattened permission set for the current user."""
    permissions: list[str]  # ["resource:action", ...]
    roles: list[RoleSummaryResponse]


class PermissionCatalogGroup(BaseModel):
    """Permissions grouped by resource."""
    resource: str
    permissions: list[PermissionResponse]


# =============================================================================
# Module-level use case holder
# =============================================================================

_role_use_case: RoleUseCase | None = None


def configure_rbac_router(role_use_case: RoleUseCase) -> None:
    """Configure the RBAC router with its use case."""
    global _role_use_case
    _role_use_case = role_use_case


def get_role_use_case() -> RoleUseCase:
    if _role_use_case is None:
        raise RuntimeError("RBAC router not configured")
    return _role_use_case


# Auth dependency
async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
) -> str:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return x_user_id


# =============================================================================
# Permission Catalog
# =============================================================================

@router.get("/permissions", response_model=list[PermissionCatalogGroup])
async def list_permissions(
    organization_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> list[PermissionCatalogGroup]:
    """List all available permissions, grouped by resource."""
    permissions = await use_case.list_permissions()
    groups: dict[str, list[PermissionResponse]] = {}
    for p in permissions:
        groups.setdefault(p.resource, []).append(
            PermissionResponse(
                id=p.id,
                resource=p.resource,
                action=p.action,
                description=p.description,
            )
        )
    return [
        PermissionCatalogGroup(resource=res, permissions=perms)
        for res, perms in sorted(groups.items())
    ]


# =============================================================================
# Role CRUD
# =============================================================================

@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    organization_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> list[RoleResponse]:
    """List all roles for the organization."""
    roles = await use_case.list_roles(organization_id)
    results = []
    for role in roles:
        member_ids = await use_case.role_repo.get_members_with_role(role.id)
        results.append(_role_to_response(role, member_count=len(member_ids)))
    return results


@router.post("/roles", response_model=RoleResponse, status_code=201)
async def create_role(
    organization_id: str,
    request: CreateRoleRequest,
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> RoleResponse:
    """Create a custom role."""
    try:
        permission_ids = await _resolve_permission_ids(
            use_case,
            request.permission_ids,
            request.permission_keys,
        )
        role = await use_case.create_role(
            CreateRoleCommand(
                organization_id=organization_id,
                name=request.name,
                created_by=org_ctx.user_id,
                display_name=request.display_name,
                description=request.description,
                permission_ids=permission_ids,
                is_default_for_new_members=request.is_default_for_new_members,
            )
        )
        return _role_to_response(role, member_count=0)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    organization_id: str,
    role_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> RoleResponse:
    """Get role details with permissions."""
    role = await use_case.get_role(role_id)
    if not role or role.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Role not found")
    member_ids = await use_case.role_repo.get_members_with_role(role.id)
    return _role_to_response(role, member_count=len(member_ids))


@router.patch("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    organization_id: str,
    role_id: str,
    request: UpdateRoleRequest,
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> RoleResponse:
    """Update a role's display name, description, or permissions."""
    try:
        permission_ids: list[str] | None = request.permission_ids
        if request.permission_keys is not None:
            permission_ids = await _resolve_permission_ids(
                use_case,
                request.permission_ids,
                request.permission_keys,
            )

        role = await use_case.update_role(
            UpdateRoleCommand(
                role_id=role_id,
                organization_id=organization_id,
                updated_by=org_ctx.user_id,
                display_name=request.display_name,
                description=request.description,
                permission_ids=permission_ids,
                is_default_for_new_members=request.is_default_for_new_members,
            )
        )
        member_ids = await use_case.role_repo.get_members_with_role(role.id)
        return _role_to_response(role, member_count=len(member_ids))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(
    organization_id: str,
    role_id: str,
    replacement_role_id: str | None = Query(default=None),
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> None:
    """Delete a custom role."""
    try:
        await use_case.delete_role(
            DeleteRoleCommand(
                role_id=role_id,
                organization_id=organization_id,
                deleted_by=org_ctx.user_id,
                replacement_role_id=replacement_role_id,
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Member ↔ Role Assignments
# =============================================================================

@router.put("/members/{member_id}/roles", response_model=list[RoleSummaryResponse])
async def set_member_roles(
    organization_id: str,
    member_id: str,
    request: SetMemberRolesRequest,
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> list[RoleSummaryResponse]:
    """Replace all roles for a member."""
    try:
        roles = await use_case.set_member_roles(
            SetMemberRolesCommand(
                member_id=member_id,
                organization_id=organization_id,
                role_ids=request.role_ids,
                updated_by=org_ctx.user_id,
            )
        )
        return [
            RoleSummaryResponse(id=r.id, name=r.name, display_name=r.display_name)
            for r in roles
        ]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/members/{member_id}/roles/{role_id}",
    status_code=204,
)
async def add_member_role(
    organization_id: str,
    member_id: str,
    role_id: str,
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> None:
    """Add a role to a member."""
    try:
        await use_case.add_member_role(
            AddMemberRoleCommand(
                member_id=member_id,
                organization_id=organization_id,
                role_id=role_id,
                updated_by=org_ctx.user_id,
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete(
    "/members/{member_id}/roles/{role_id}",
    status_code=204,
)
async def remove_member_role(
    organization_id: str,
    member_id: str,
    role_id: str,
    org_ctx: OrganizationContext = Depends(require_org_admin),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> None:
    """Remove a role from a member."""
    try:
        await use_case.remove_member_role(
            RemoveMemberRoleCommand(
                member_id=member_id,
                organization_id=organization_id,
                role_id=role_id,
                updated_by=org_ctx.user_id,
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Current User's Permissions
# =============================================================================

@router.get("/members/me/permissions", response_model=MemberPermissionsResponse)
async def get_my_permissions(
    organization_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: RoleUseCase = Depends(get_role_use_case),
) -> MemberPermissionsResponse:
    """Get the current user's flattened permissions in this organization.
    
    Used by the frontend to power the usePermissions hook.
    """
    # Look up the member record
    member = await use_case.member_repo.get_by_user_and_org(
        org_ctx.user_id, organization_id
    )
    if not member:
        raise HTTPException(status_code=404, detail="Membership not found")

    permissions = await use_case.get_member_permissions(member.id)
    roles = await use_case.get_member_roles(member.id)

    return MemberPermissionsResponse(
        permissions=[p.key for p in permissions],
        roles=[
            RoleSummaryResponse(id=r.id, name=r.name, display_name=r.display_name)
            for r in roles
        ],
    )


# =============================================================================
# Helpers
# =============================================================================

def _role_to_response(role, member_count: int | None = None) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        organization_id=role.organization_id,
        name=role.name,
        display_name=role.display_name,
        description=role.description,
        is_system=role.is_system,
        is_default_for_new_members=role.is_default_for_new_members,
        permissions=[
            PermissionResponse(
                id=p.id,
                resource=p.resource,
                action=p.action,
                description=p.description,
            )
            for p in role.permissions
        ],
        member_count=member_count,
        created_at=role.created_at.isoformat(),
        updated_at=role.updated_at.isoformat(),
    )


async def _resolve_permission_ids(
    use_case: RoleUseCase,
    permission_ids: list[str] | None,
    permission_keys: list[str] | None,
) -> list[str]:
    """Normalize permission inputs.

    Accepts IDs and/or keys and returns a deduplicated list of permission IDs.
    """
    resolved = list(permission_ids or [])
    keys = list(permission_keys or [])

    if not keys:
        return list(dict.fromkeys(resolved))

    catalog = await use_case.list_permissions()
    key_to_id = {p.key: p.id for p in catalog}

    unknown = [k for k in keys if k not in key_to_id]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown permission keys: {', '.join(sorted(unknown))}",
        )

    resolved.extend(key_to_id[k] for k in keys)
    return list(dict.fromkeys(resolved))
