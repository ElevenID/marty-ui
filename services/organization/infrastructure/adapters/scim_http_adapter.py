"""
SCIM HTTP Adapter (FastAPI)

Org-scoped SCIM 2.0 endpoints backed by Organization members and RBAC roles.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Annotated

from fastapi import APIRouter, Body, Depends, Header, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from marty_common import OrganizationContext, require_org_membership

from ...application.ports import CreateRoleCommand, DeleteRoleCommand, UpdateRoleCommand
from ...application.rbac_use_cases import RoleUseCase
from ...application.use_cases import MemberUseCase, OrganizationUseCase
from ...domain.entities import Member, MemberRole, MemberStatus, Role

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/organizations/{organization_id}/scim/v2",
    tags=["scim"],
)

SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_SERVICE_PROVIDER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_USER_EXTENSION_SCHEMA = "urn:mip:scim:schemas:extension:Organization:2.0:User"
SCIM_ROLE_EXTENSION_SCHEMA = "urn:mip:scim:schemas:extension:Organization:2.0:Role"

USER_FILTER_RE = re.compile(r'^\s*([A-Za-z0-9:._\-]+)\s+eq\s+(".*?"|true|false)\s*$')
GROUP_MEMBER_REMOVE_RE = re.compile(r'^members\[value eq "([^"]+)"\]$')

_organization_use_case: OrganizationUseCase | None = None
_member_use_case: MemberUseCase | None = None
_role_use_case: RoleUseCase | None = None


class ScimEmail(BaseModel):
    value: str
    primary: bool = False


class ScimPatchOperation(BaseModel):
    op: str
    path: str | None = None
    value: Any | None = None


class ScimPatchRequest(BaseModel):
    schemas: list[str]
    operations: list[ScimPatchOperation] = Field(alias="Operations")

    model_config = ConfigDict(populate_by_name=True)


class ScimUserPayload(BaseModel):
    """Validated SCIM 2.0 User resource payload (RFC 7643 §4.1)."""
    schemas: list[str] = Field(default_factory=lambda: [SCIM_USER_SCHEMA])
    userName: str | None = None
    externalId: str | None = None
    active: bool = True
    emails: list[dict[str, Any]] | None = None

    model_config = ConfigDict(extra="allow")


class ScimGroupPayload(BaseModel):
    """Validated SCIM 2.0 Group resource payload (RFC 7643 §4.2)."""
    schemas: list[str] = Field(default_factory=lambda: [SCIM_GROUP_SCHEMA])
    displayName: str | None = None
    members: list[dict[str, Any]] | None = None

    model_config = ConfigDict(extra="allow")


async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
) -> str:
    if not x_user_id:
        return "system"
    return x_user_id


def configure_scim_router(
    organization_use_case: OrganizationUseCase,
    member_use_case: MemberUseCase,
    role_use_case: RoleUseCase,
) -> None:
    global _organization_use_case, _member_use_case, _role_use_case
    _organization_use_case = organization_use_case
    _member_use_case = member_use_case
    _role_use_case = role_use_case


def get_organization_use_case() -> OrganizationUseCase:
    if _organization_use_case is None:
        raise RuntimeError("SCIM router not configured")
    return _organization_use_case


def get_member_use_case() -> MemberUseCase:
    if _member_use_case is None:
        raise RuntimeError("SCIM router not configured")
    return _member_use_case


def get_role_use_case() -> RoleUseCase:
    if _role_use_case is None:
        raise RuntimeError("SCIM router not configured")
    return _role_use_case


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _scim_error(status_code: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(status_code=status_code, content=body)


def _list_response(resources: list[dict[str, Any]], total: int, start_index: int, items_per_page: int) -> dict[str, Any]:
    return {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": items_per_page,
        "Resources": resources,
    }


def _paginate(items: list[Any], start_index: int, count: int) -> tuple[list[Any], int, int]:
    normalized_start = max(start_index, 1)
    normalized_count = max(count, 0)
    start_offset = normalized_start - 1
    end_offset = start_offset + normalized_count if normalized_count else len(items)
    page = items[start_offset:end_offset]
    return page, normalized_start, len(page)


def _resource_location(organization_id: str, resource_type: str, resource_id: str | None = None) -> str:
    base = f"/v1/organizations/{organization_id}/scim/v2/{resource_type}"
    if resource_id:
        return f"{base}/{resource_id}"
    return base


def _slugify_role_name(display_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (display_name or "role").strip().lower()).strip("-")
    return slug or "role"


def _member_is_active(member: Member) -> bool:
    return member.status == MemberStatus.ACTIVE


def _member_is_owner(member: Member, roles: list[Role]) -> bool:
    return member.role == MemberRole.OWNER or any(role.name == "owner" for role in roles)


def _member_display_name(member: Member) -> str:
    return member.email or member.user_id or member.id


def _extract_primary_email(payload: dict[str, Any]) -> str | None:
    emails = payload.get("emails") or []
    if isinstance(emails, list) and emails:
        primary = next((email for email in emails if email.get("primary")), emails[0])
        value = primary.get("value")
        if value:
            return str(value)
    user_name = payload.get("userName")
    return str(user_name) if user_name else None


async def _get_roles_by_member(role_use_case: RoleUseCase, members: list[Member]) -> dict[str, list[Role]]:
    roles_by_member: dict[str, list[Role]] = {}
    for member in members:
        roles_by_member[member.id] = await role_use_case.get_member_roles(member.id)
    return roles_by_member


async def _get_default_role_ids(role_use_case: RoleUseCase, organization_id: str) -> list[str]:
    roles = await role_use_case.list_roles(organization_id)
    defaults = [role.id for role in roles if role.is_default_for_new_members]
    if defaults:
        return defaults
    fallback = next((role.id for role in roles if role.name == "member"), None)
    return [fallback] if fallback else []


async def _validate_role_ids(role_use_case: RoleUseCase, organization_id: str, role_ids: list[str]) -> tuple[list[str], JSONResponse | None]:
    valid_role_ids: list[str] = []
    for role_id in role_ids:
        role = await role_use_case.get_role(role_id)
        if not role or role.organization_id != organization_id:
            return [], _scim_error(400, f"Unknown role id: {role_id}", "invalidValue")
        valid_role_ids.append(role_id)
    return list(dict.fromkeys(valid_role_ids)), None


async def _resolve_permission_ids(role_use_case: RoleUseCase, permission_keys: list[str]) -> tuple[list[str], JSONResponse | None]:
    catalog = await role_use_case.list_permissions()
    permission_map = {permission.key: permission.id for permission in catalog}
    unknown = [key for key in permission_keys if key not in permission_map]
    if unknown:
        return [], _scim_error(400, f"Unknown permissions: {', '.join(sorted(unknown))}", "invalidValue")
    return [permission_map[key] for key in dict.fromkeys(permission_keys)], None


def _user_matches_filter(member: Member, roles: list[Role], filter_expr: str) -> tuple[bool, JSONResponse | None]:
    match = USER_FILTER_RE.match(filter_expr)
    if not match:
        return False, _scim_error(400, "Unsupported SCIM filter syntax", "invalidFilter")

    attribute, raw_value = match.groups()
    parsed_value: Any
    if raw_value.lower() == "true":
        parsed_value = True
    elif raw_value.lower() == "false":
        parsed_value = False
    else:
        parsed_value = raw_value[1:-1]

    attribute_value_map: dict[str, Any] = {
        "userName": member.email,
        "emails.value": member.email,
        "externalId": member.user_id,
        "active": _member_is_active(member),
        f"{SCIM_USER_EXTENSION_SCHEMA}:is_owner": _member_is_owner(member, roles),
    }
    if attribute not in attribute_value_map:
        return False, _scim_error(400, f"Unsupported filter attribute: {attribute}", "invalidFilter")
    return attribute_value_map[attribute] == parsed_value, None


def _group_matches_filter(role: Role, filter_expr: str) -> tuple[bool, JSONResponse | None]:
    match = USER_FILTER_RE.match(filter_expr)
    if not match:
        return False, _scim_error(400, "Unsupported SCIM filter syntax", "invalidFilter")
    attribute, raw_value = match.groups()
    if not raw_value.startswith('"'):
        return False, _scim_error(400, "Group filters require a string value", "invalidFilter")
    parsed_value = raw_value[1:-1]
    if attribute not in {"displayName", f"{SCIM_ROLE_EXTENSION_SCHEMA}:description"}:
        return False, _scim_error(400, f"Unsupported filter attribute: {attribute}", "invalidFilter")
    actual = role.display_name if attribute == "displayName" else role.description
    return actual == parsed_value, None


def _member_to_scim_user(member: Member, roles: list[Role], organization_id: str) -> dict[str, Any]:
    return {
        "schemas": [SCIM_USER_SCHEMA, SCIM_USER_EXTENSION_SCHEMA],
        "id": member.id,
        "externalId": member.user_id,
        "userName": member.email,
        "displayName": _member_display_name(member),
        "emails": [{"value": member.email, "primary": True}] if member.email else [],
        "active": _member_is_active(member),
        SCIM_USER_EXTENSION_SCHEMA: {
            "role_ids": [role.id for role in roles],
            "is_owner": _member_is_owner(member, roles),
            "joined_at": _iso(member.joined_at),
        },
        "meta": {
            "resourceType": "User",
            "created": _iso(member.created_at),
            "lastModified": _iso(member.updated_at),
            "location": _resource_location(organization_id, "Users", member.id),
        },
    }


def _role_to_scim_group(role: Role, members: list[Member], organization_id: str) -> dict[str, Any]:
    return {
        "schemas": [SCIM_GROUP_SCHEMA, SCIM_ROLE_EXTENSION_SCHEMA],
        "id": role.id,
        "displayName": role.display_name or role.name,
        "members": [
            {"value": member.id, "display": _member_display_name(member)}
            for member in members
        ],
        SCIM_ROLE_EXTENSION_SCHEMA: {
            "permissions": sorted(permission.key for permission in role.permissions),
            "is_system_role": role.is_system,
            "description": role.description,
        },
        "meta": {
            "resourceType": "Group",
            "created": _iso(role.created_at),
            "lastModified": _iso(role.updated_at),
            "location": _resource_location(organization_id, "Groups", role.id),
        },
    }


async def _get_member_or_scim_404(member_use_case: MemberUseCase, member_id: str, organization_id: str) -> tuple[Member | None, JSONResponse | None]:
    member = await member_use_case.member_repo.get_by_id(member_id)
    if not member or member.organization_id != organization_id:
        return None, _scim_error(404, "User not found")
    return member, None


async def _get_role_or_scim_404(role_use_case: RoleUseCase, role_id: str, organization_id: str) -> tuple[Role | None, JSONResponse | None]:
    role = await role_use_case.get_role(role_id)
    if not role or role.organization_id != organization_id:
        return None, _scim_error(404, "Group not found")
    return role, None


async def _members_for_role(member_use_case: MemberUseCase, role_use_case: RoleUseCase, role_id: str, organization_id: str) -> list[Member]:
    member_ids = await role_use_case.role_repo.get_members_with_role(role_id)
    members: list[Member] = []
    for member_id in member_ids:
        member = await member_use_case.member_repo.get_by_id(member_id)
        if member and member.organization_id == organization_id:
            members.append(member)
    return members


async def _set_member_roles_for_scim(
    member: Member,
    organization_id: str,
    requested_role_ids: list[str] | None,
    role_use_case: RoleUseCase,
) -> JSONResponse | None:
    role_ids = requested_role_ids if requested_role_ids is not None else await _get_default_role_ids(role_use_case, organization_id)
    valid_role_ids, error = await _validate_role_ids(role_use_case, organization_id, role_ids)
    if error:
        return error
    await role_use_case.role_repo.set_member_roles(member.id, valid_role_ids)
    return None


@router.get("/ServiceProviderConfig")
async def service_provider_config() -> Any:
    return {
        "schemas": [SCIM_SERVICE_PROVIDER_SCHEMA],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": True},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token standard",
            }
        ],
    }


@router.get("/Schemas")
async def schemas() -> Any:
    resources = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": SCIM_USER_SCHEMA,
            "name": "User",
            "description": "SCIM core user resource",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "multiValued": False},
                {"name": "emails", "type": "complex", "required": False, "multiValued": True},
                {"name": "active", "type": "boolean", "required": False, "multiValued": False},
            ],
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "SCIM core group resource",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True, "multiValued": False},
                {"name": "members", "type": "complex", "required": False, "multiValued": True},
            ],
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": SCIM_USER_EXTENSION_SCHEMA,
            "name": "MIPUserExtension",
            "description": "MIP extension attributes for SCIM users",
            "attributes": [
                {"name": "role_ids", "type": "string", "required": False, "multiValued": True},
                {"name": "is_owner", "type": "boolean", "required": False, "multiValued": False},
                {"name": "joined_at", "type": "dateTime", "required": False, "multiValued": False},
            ],
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": SCIM_ROLE_EXTENSION_SCHEMA,
            "name": "MIPRoleExtension",
            "description": "MIP extension attributes for SCIM groups representing roles",
            "attributes": [
                {"name": "permissions", "type": "string", "required": False, "multiValued": True},
                {"name": "is_system_role", "type": "boolean", "required": False, "multiValued": False},
                {"name": "description", "type": "string", "required": False, "multiValued": False},
            ],
        },
    ]
    return _list_response(resources, len(resources), 1, len(resources))


@router.get("/ResourceTypes")
async def resource_types(organization_id: str) -> Any:
    resources = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCIM_USER_SCHEMA,
            "schemaExtensions": [{"schema": SCIM_USER_EXTENSION_SCHEMA, "required": False}],
            "meta": {"location": _resource_location(organization_id, "ResourceTypes") + "/User", "resourceType": "ResourceType"},
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": SCIM_GROUP_SCHEMA,
            "schemaExtensions": [{"schema": SCIM_ROLE_EXTENSION_SCHEMA, "required": False}],
            "meta": {"location": _resource_location(organization_id, "ResourceTypes") + "/Group", "resourceType": "ResourceType"},
        },
    ]
    return _list_response(resources, len(resources), 1, len(resources))


@router.get("/Users")
async def list_users(
    organization_id: str,
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=0, le=200),
    sortBy: str | None = Query(default=None),
    sortOrder: str = Query(default="ascending"),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    members = await member_use_case.list_members(organization_id)
    roles_by_member = await _get_roles_by_member(role_use_case, members)

    filtered: list[Member] = []
    for member in members:
        roles = roles_by_member.get(member.id, [])
        if filter:
            matched, error = _user_matches_filter(member, roles, filter)
            if error:
                return error
            if not matched:
                continue
        filtered.append(member)

    if sortBy in {"userName", "externalId", "active"}:
        reverse = sortOrder.lower() == "descending"
        filtered.sort(
            key=lambda member: {
                "userName": member.email or "",
                "externalId": member.user_id or "",
                "active": _member_is_active(member),
            }[sortBy],
            reverse=reverse,
        )

    page, normalized_start, item_count = _paginate(filtered, startIndex, count)
    return _list_response(
        [_member_to_scim_user(member, roles_by_member.get(member.id, []), organization_id) for member in page],
        len(filtered),
        normalized_start,
        item_count,
    )


@router.post("/Users", status_code=201)
async def create_user(
    organization_id: str,
    payload: ScimUserPayload,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    payload_dict = payload.model_dump(by_alias=True, exclude_unset=False)
    email = _extract_primary_email(payload_dict)
    if not email:
        return _scim_error(400, "userName is required", "invalidValue")

    existing = await member_use_case.member_repo.get_by_email_and_org(email, organization_id)
    if existing:
        return _scim_error(409, "userName already exists in this organization", "uniqueness")

    extension = payload_dict.get(SCIM_USER_EXTENSION_SCHEMA) or {}
    if extension.get("is_owner"):
        return _scim_error(400, "Ownership cannot be assigned via SCIM", "mutability")

    member = Member.create(
        organization_id=organization_id,
        user_id=str(payload_dict.get("externalId") or email),
        email=email,
        role=MemberRole.MEMBER,
        status=MemberStatus.ACTIVE if payload_dict.get("active", True) else MemberStatus.DEACTIVATED,
    )
    member.updated_at = _now()
    await member_use_case.member_repo.save(member)

    requested_role_ids = extension.get("role_ids") if isinstance(extension.get("role_ids"), list) else None
    if member.status == MemberStatus.DEACTIVATED:
        await role_use_case.role_repo.set_member_roles(member.id, [])
    else:
        error = await _set_member_roles_for_scim(member, organization_id, requested_role_ids, role_use_case)
        if error:
            return error

    roles = await role_use_case.get_member_roles(member.id)
    body = _member_to_scim_user(member, roles, organization_id)
    location = f"/v1/organizations/{organization_id}/scim/v2/Users/{member.id}"
    return JSONResponse(
        status_code=201,
        content=body,
        media_type="application/scim+json",
        headers={"Location": location},
    )


@router.get("/Users/{member_id}")
async def get_user(
    organization_id: str,
    member_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    member, error = await _get_member_or_scim_404(member_use_case, member_id, organization_id)
    if error:
        return error
    roles = await role_use_case.get_member_roles(member.id)
    return _member_to_scim_user(member, roles, organization_id)


@router.put("/Users/{member_id}")
async def replace_user(
    organization_id: str,
    member_id: str,
    payload: ScimUserPayload,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    member, error = await _get_member_or_scim_404(member_use_case, member_id, organization_id)
    if error:
        return error

    payload_dict = payload.model_dump(by_alias=True, exclude_unset=False)
    email = _extract_primary_email(payload_dict)
    if not email:
        return _scim_error(400, "userName is required", "invalidValue")

    existing = await member_use_case.member_repo.get_by_email_and_org(email, organization_id)
    if existing and existing.id != member.id:
        return _scim_error(409, "userName already exists in this organization", "uniqueness")

    extension = payload_dict.get(SCIM_USER_EXTENSION_SCHEMA) or {}
    if extension.get("is_owner"):
        return _scim_error(400, "Ownership cannot be assigned via SCIM", "mutability")

    requested_active = bool(payload_dict.get("active", True))
    current_roles = await role_use_case.get_member_roles(member.id)
    if _member_is_owner(member, current_roles) and not requested_active:
        return _scim_error(400, "Organization owner cannot be deprovisioned via SCIM", "mutability")

    member.email = email
    member.user_id = str(payload_dict.get("externalId") or member.user_id or email)
    member.status = MemberStatus.ACTIVE if requested_active else MemberStatus.DEACTIVATED
    member.updated_at = _now()
    await member_use_case.member_repo.save(member)

    requested_role_ids = extension.get("role_ids") if isinstance(extension.get("role_ids"), list) else None
    if member.status == MemberStatus.DEACTIVATED:
        await role_use_case.role_repo.set_member_roles(member.id, [])
    else:
        error = await _set_member_roles_for_scim(member, organization_id, requested_role_ids, role_use_case)
        if error:
            return error

    roles = await role_use_case.get_member_roles(member.id)
    return _member_to_scim_user(member, roles, organization_id)


@router.patch("/Users/{member_id}")
async def patch_user(
    organization_id: str,
    member_id: str,
    patch: ScimPatchRequest,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    member, error = await _get_member_or_scim_404(member_use_case, member_id, organization_id)
    if error:
        return error

    current_roles = await role_use_case.get_member_roles(member.id)
    requested_role_ids = [role.id for role in current_roles]
    active = _member_is_active(member)

    for operation in patch.operations:
        op = operation.op.lower()
        path = operation.path or ""

        if op not in {"add", "remove", "replace"}:
            return _scim_error(400, f"Unsupported PATCH op: {operation.op}", "invalidSyntax")

        if path in {"userName", "emails", "emails.value"}:
            if op == "remove":
                return _scim_error(400, "userName cannot be removed", "mutability")
            email = _extract_primary_email({"emails": operation.value} if path.startswith("emails") else {"userName": operation.value})
            if not email:
                return _scim_error(400, "A valid email value is required", "invalidValue")
            existing = await member_use_case.member_repo.get_by_email_and_org(email, organization_id)
            if existing and existing.id != member.id:
                return _scim_error(409, "userName already exists in this organization", "uniqueness")
            member.email = email
            continue

        if path == "externalId":
            if op == "remove":
                member.user_id = ""
            else:
                member.user_id = str(operation.value or "")
            continue

        if path == "active":
            next_active = bool(operation.value) if op != "remove" else False
            if _member_is_owner(member, current_roles) and not next_active:
                return _scim_error(400, "Organization owner cannot be deprovisioned via SCIM", "mutability")
            active = next_active
            continue

        if path == f"{SCIM_USER_EXTENSION_SCHEMA}:role_ids":
            values = operation.value or []
            if not isinstance(values, list):
                return _scim_error(400, "role_ids must be a list", "invalidValue")
            if op == "replace":
                requested_role_ids = [str(value) for value in values]
            elif op == "add":
                requested_role_ids = list(dict.fromkeys(requested_role_ids + [str(value) for value in values]))
            elif op == "remove":
                remove_ids = {str(value) for value in values}
                requested_role_ids = [role_id for role_id in requested_role_ids if role_id not in remove_ids]
            continue

        if path == f"{SCIM_USER_EXTENSION_SCHEMA}:is_owner":
            return _scim_error(400, "Ownership cannot be changed via SCIM", "mutability")

        return _scim_error(400, f"Unsupported PATCH path: {path}", "invalidPath")

    member.status = MemberStatus.ACTIVE if active else MemberStatus.DEACTIVATED
    member.updated_at = _now()
    await member_use_case.member_repo.save(member)

    if member.status == MemberStatus.DEACTIVATED:
        await role_use_case.role_repo.set_member_roles(member.id, [])
    else:
        error = await _set_member_roles_for_scim(member, organization_id, requested_role_ids, role_use_case)
        if error:
            return error

    roles = await role_use_case.get_member_roles(member.id)
    return _member_to_scim_user(member, roles, organization_id)


@router.delete("/Users/{member_id}")
async def delete_user(
    organization_id: str,
    member_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    member, error = await _get_member_or_scim_404(member_use_case, member_id, organization_id)
    if error:
        return error

    current_roles = await role_use_case.get_member_roles(member.id)
    if _member_is_owner(member, current_roles):
        return _scim_error(400, "Organization owner cannot be deprovisioned via SCIM", "mutability")

    member.status = MemberStatus.DEACTIVATED
    member.updated_at = _now()
    await member_use_case.member_repo.save(member)
    await role_use_case.role_repo.set_member_roles(member.id, [])
    return Response(status_code=204)


@router.get("/Groups")
async def list_groups(
    organization_id: str,
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=0, le=200),
    sortBy: str | None = Query(default=None),
    sortOrder: str = Query(default="ascending"),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    roles = await role_use_case.list_roles(organization_id)
    filtered: list[Role] = []
    for role in roles:
        if filter:
            matched, error = _group_matches_filter(role, filter)
            if error:
                return error
            if not matched:
                continue
        filtered.append(role)

    if sortBy in {"displayName"}:
        reverse = sortOrder.lower() == "descending"
        filtered.sort(key=lambda role: role.display_name or role.name, reverse=reverse)

    page, normalized_start, item_count = _paginate(filtered, startIndex, count)
    resources = []
    for role in page:
        members = await _members_for_role(member_use_case, role_use_case, role.id, organization_id)
        resources.append(_role_to_scim_group(role, members, organization_id))

    return _list_response(resources, len(filtered), normalized_start, item_count)


@router.post("/Groups", status_code=201)
async def create_group(
    organization_id: str,
    payload: ScimGroupPayload,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    payload_dict = payload.model_dump(by_alias=True, exclude_unset=False)
    display_name = payload_dict.get("displayName")
    if not display_name:
        return _scim_error(400, "displayName is required", "invalidValue")

    extension = payload_dict.get(SCIM_ROLE_EXTENSION_SCHEMA) or {}
    permission_keys = extension.get("permissions") or []
    if not isinstance(permission_keys, list):
        return _scim_error(400, "permissions must be a list", "invalidValue")
    permission_ids, error = await _resolve_permission_ids(role_use_case, [str(key) for key in permission_keys])
    if error:
        return error

    try:
        role = await role_use_case.create_role(
            CreateRoleCommand(
                organization_id=organization_id,
                name=_slugify_role_name(display_name),
                created_by=user_id,
                display_name=str(display_name),
                description=extension.get("description"),
                permission_ids=permission_ids,
            )
        )
    except ValueError as exc:
        return _scim_error(409, str(exc), "uniqueness")

    members_payload = payload_dict.get("members") or []
    for member_ref in members_payload:
        member = await member_use_case.member_repo.get_by_id(str(member_ref.get("value")))
        if not member or member.organization_id != organization_id:
            return _scim_error(400, f"Unknown member id: {member_ref.get('value')}", "invalidValue")
        await role_use_case.role_repo.add_member_role(member.id, role.id)

    members = await _members_for_role(member_use_case, role_use_case, role.id, organization_id)
    body = _role_to_scim_group(role, members, organization_id)
    location = f"/v1/organizations/{organization_id}/scim/v2/Groups/{role.id}"
    return JSONResponse(
        status_code=201,
        content=body,
        media_type="application/scim+json",
        headers={"Location": location},
    )


@router.get("/Groups/{role_id}")
async def get_group(
    organization_id: str,
    role_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    role, error = await _get_role_or_scim_404(role_use_case, role_id, organization_id)
    if error:
        return error
    members = await _members_for_role(member_use_case, role_use_case, role.id, organization_id)
    return _role_to_scim_group(role, members, organization_id)


@router.put("/Groups/{role_id}")
async def replace_group(
    organization_id: str,
    role_id: str,
    payload: ScimGroupPayload,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    role, error = await _get_role_or_scim_404(role_use_case, role_id, organization_id)
    if error:
        return error
    if role.is_system:
        return _scim_error(400, "System roles cannot be modified via SCIM", "mutability")

    payload_dict = payload.model_dump(by_alias=True, exclude_unset=False)
    display_name = payload_dict.get("displayName")
    if not display_name:
        return _scim_error(400, "displayName is required", "invalidValue")

    extension = payload_dict.get(SCIM_ROLE_EXTENSION_SCHEMA) or {}
    permission_keys = extension.get("permissions") or []
    if not isinstance(permission_keys, list):
        return _scim_error(400, "permissions must be a list", "invalidValue")
    permission_ids, error = await _resolve_permission_ids(role_use_case, [str(key) for key in permission_keys])
    if error:
        return error

    try:
        role = await role_use_case.update_role(
            UpdateRoleCommand(
                role_id=role.id,
                organization_id=organization_id,
                updated_by=user_id,
                display_name=str(display_name),
                description=extension.get("description"),
                permission_ids=permission_ids,
            )
        )
    except ValueError as exc:
        return _scim_error(400, str(exc), "invalidValue")

    existing_member_ids = set(await role_use_case.role_repo.get_members_with_role(role.id))
    desired_member_ids = {str(member_ref.get("value")) for member_ref in (payload_dict.get("members") or []) if member_ref.get("value")}

    for member_id in desired_member_ids - existing_member_ids:
        member = await member_use_case.member_repo.get_by_id(member_id)
        if not member or member.organization_id != organization_id:
            return _scim_error(400, f"Unknown member id: {member_id}", "invalidValue")
        await role_use_case.role_repo.add_member_role(member_id, role.id)
    for member_id in existing_member_ids - desired_member_ids:
        await role_use_case.role_repo.remove_member_role(member_id, role.id)

    members = await _members_for_role(member_use_case, role_use_case, role.id, organization_id)
    return _role_to_scim_group(role, members, organization_id)


@router.patch("/Groups/{role_id}")
async def patch_group(
    organization_id: str,
    role_id: str,
    patch: ScimPatchRequest,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    member_use_case: MemberUseCase = Depends(get_member_use_case),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    role, error = await _get_role_or_scim_404(role_use_case, role_id, organization_id)
    if error:
        return error
    if role.is_system:
        return _scim_error(400, "System roles cannot be modified via SCIM", "mutability")

    current_member_ids = set(await role_use_case.role_repo.get_members_with_role(role.id))
    permission_keys = sorted(permission.key for permission in role.permissions)
    display_name = role.display_name or role.name
    description = role.description

    for operation in patch.operations:
        op = operation.op.lower()
        path = operation.path or ""
        if op not in {"add", "remove", "replace"}:
            return _scim_error(400, f"Unsupported PATCH op: {operation.op}", "invalidSyntax")

        if path == "members":
            values = operation.value or []
            if not isinstance(values, list):
                return _scim_error(400, "members must be a list", "invalidValue")
            member_ids = {str(value.get("value")) for value in values if value.get("value")}
            if op == "replace":
                current_member_ids = member_ids
            elif op == "add":
                current_member_ids |= member_ids
            elif op == "remove":
                current_member_ids -= member_ids
            continue

        match = GROUP_MEMBER_REMOVE_RE.match(path)
        if match and op == "remove":
            current_member_ids.discard(match.group(1))
            continue

        if path in {"displayName", f"{SCIM_ROLE_EXTENSION_SCHEMA}:description"}:
            if op == "remove":
                if path == "displayName":
                    return _scim_error(400, "displayName cannot be removed", "mutability")
                description = None
            else:
                if path == "displayName":
                    display_name = str(operation.value)
                else:
                    description = str(operation.value) if operation.value is not None else None
            continue

        if path == f"{SCIM_ROLE_EXTENSION_SCHEMA}:permissions":
            values = operation.value or []
            if not isinstance(values, list):
                return _scim_error(400, "permissions must be a list", "invalidValue")
            normalized_values = [str(value) for value in values]
            if op == "replace":
                permission_keys = normalized_values
            elif op == "add":
                permission_keys = sorted(set(permission_keys) | set(normalized_values))
            elif op == "remove":
                permission_keys = [key for key in permission_keys if key not in set(normalized_values)]
            continue

        return _scim_error(400, f"Unsupported PATCH path: {path}", "invalidPath")

    permission_ids, error = await _resolve_permission_ids(role_use_case, permission_keys)
    if error:
        return error
    try:
        role = await role_use_case.update_role(
            UpdateRoleCommand(
                role_id=role.id,
                organization_id=organization_id,
                updated_by=user_id,
                display_name=display_name,
                description=description,
                permission_ids=permission_ids,
            )
        )
    except ValueError as exc:
        return _scim_error(400, str(exc), "invalidValue")

    for member_id in current_member_ids:
        member = await member_use_case.member_repo.get_by_id(member_id)
        if not member or member.organization_id != organization_id:
            return _scim_error(400, f"Unknown member id: {member_id}", "invalidValue")

    existing_member_ids = set(await role_use_case.role_repo.get_members_with_role(role.id))
    for member_id in current_member_ids - existing_member_ids:
        await role_use_case.role_repo.add_member_role(member_id, role.id)
    for member_id in existing_member_ids - current_member_ids:
        await role_use_case.role_repo.remove_member_role(member_id, role.id)

    members = await _members_for_role(member_use_case, role_use_case, role.id, organization_id)
    return _role_to_scim_group(role, members, organization_id)


@router.delete("/Groups/{role_id}")
async def delete_group(
    organization_id: str,
    role_id: str,
    user_id: str = Depends(get_current_user_id),
    org_ctx: OrganizationContext = Depends(require_org_membership),
    role_use_case: RoleUseCase = Depends(get_role_use_case),
) -> Any:
    role, error = await _get_role_or_scim_404(role_use_case, role_id, organization_id)
    if error:
        return error
    if role.is_system:
        return _scim_error(400, "System roles cannot be deleted via SCIM", "mutability")

    try:
        await role_use_case.delete_role(
            DeleteRoleCommand(
                role_id=role.id,
                organization_id=organization_id,
                deleted_by=user_id,
            )
        )
    except ValueError as exc:
        return _scim_error(400, str(exc), "invalidValue")

    return Response(status_code=204)