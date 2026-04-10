"""Organization, membership, RBAC, invites, SCIM, and preferences routes."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response

from gateway.models import (
    AuditEventResponse,
    InvitationAcceptRequest,
    InvitationAcceptResponse,
    InvitationValidateResponse,
    JoinByCodeRequest,
    JoinByCodeResponse,
    OrganizationCreate,
    OrganizationResponse,
    PreferencesResponse,
    UpdatePreferencesRequest,
    ValidateJoinCodeResponse,
)
from gateway.proxy import get_registry, proxy_request

organization_router = APIRouter(prefix="/v1/organizations", tags=["Organizations"])
preferences_router = APIRouter(prefix="/v1/me", tags=["User Preferences"])


# ── Organizations CRUD ───────────────────────────────────────────────

@organization_router.post("", response_model=OrganizationResponse, summary="Create Organization")
async def create_organization(body: OrganizationCreate, request: Request) -> Response:
    """Create a new Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("", response_model=list[OrganizationResponse], summary="List Organizations")
async def list_organizations(request: Request) -> Response:
    """List Organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("/discover", response_model=list[OrganizationResponse], summary="Discover Organizations")
async def discover_organizations(request: Request) -> Response:
    """Discover publicly available organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/discover")


@organization_router.get("/mine", response_model=list[dict], summary="My Organizations")
async def get_my_organizations(request: Request) -> Response:
    """Get organizations the current user belongs to with membership details."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/mine")


@organization_router.get("/{org_id}", response_model=OrganizationResponse, summary="Get Organization")
async def get_organization(org_id: str, request: Request) -> Response:
    """Get an Organization by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.put("/{org_id}", response_model=OrganizationResponse, summary="Update Organization")
async def update_organization(org_id: str, body: OrganizationCreate, request: Request) -> Response:
    """Update an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}", summary="Delete Organization")
async def delete_organization(org_id: str, request: Request) -> Response:
    """Delete an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


# ── Join by Code ─────────────────────────────────────────────────────

@organization_router.post("/join/code", response_model=JoinByCodeResponse, summary="Join Organization by Code", status_code=201)
async def join_by_code(body: JoinByCodeRequest, request: Request) -> Response:
    """Join an organization using a join code."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code")


@organization_router.get("/join/code/validate", response_model=ValidateJoinCodeResponse, summary="Validate Join Code")
async def validate_join_code(request: Request) -> Response:
    """Validate join/invitation code without joining."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code/validate")


@organization_router.post("/{org_id}/join", response_model=JoinByCodeResponse, summary="Join Organization", status_code=201)
async def join_organization(org_id: str, request: Request) -> Response:
    """Join/request to join an organization by ID (open join organizations)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/join", inject_params={"organization_id": org_id})


# ── Invitations ──────────────────────────────────────────────────────

@organization_router.get("/invitations/validate", response_model=InvitationValidateResponse, summary="Validate Invitation")
async def validate_organization_invitation(request: Request) -> Response:
    """Validate invitation token (public endpoint)."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/validate")


@organization_router.post("/invitations/accept", response_model=InvitationAcceptResponse, summary="Accept Invitation")
async def accept_organization_invitation(body: InvitationAcceptRequest, request: Request) -> Response:
    """Accept invitation and join organization."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/accept")


# ── Audit Events ─────────────────────────────────────────────────────

@organization_router.get("/{org_id}/audit-events", summary="List Audit Events")
async def list_audit_events(
    org_id: str,
    actor: str | None = Query(None, description="Filter by actor"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    resource_id: str | None = Query(None, description="Filter by resource ID"),
    action: str | None = Query(None, description="Filter by action"),
    search: str | None = Query(None, description="Free-text search"),
    severity: str | None = Query(None, description="Filter by severity"),
    ip_address: str | None = Query(None, description="Filter by IP address"),
    start_date: str | None = Query(None, description="Filter from date (ISO 8601)"),
    end_date: str | None = Query(None, description="Filter to date (ISO 8601)"),
    limit: int = Query(100, description="Max results", le=1000),
    offset: int = Query(0, description="Pagination offset", ge=0),
    request: Request = None,
) -> Response:
    """List Audit Events for an organization (immutable log)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    page = (offset // limit) + 1 if limit else 1
    inject_params = {
        "organization_id": org_id,
        "per_page": limit,
        "page": page,
    }

    if resource_type:
        inject_params["category"] = resource_type

    bridged_search = search or actor or resource_id or action or ip_address
    if bridged_search:
        inject_params["search"] = bridged_search

    return await proxy_request(request, service_url, "/v1/organizations/audit/events", inject_params=inject_params)


@organization_router.get("/{org_id}/audit-events/export", summary="Export Audit Events")
async def export_audit_events(
    org_id: str,
    actor: str | None = Query(None, description="Filter by actor"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    resource_id: str | None = Query(None, description="Filter by resource ID"),
    action: str | None = Query(None, description="Filter by action"),
    search: str | None = Query(None, description="Free-text search"),
    severity: str | None = Query(None, description="Filter by severity"),
    ip_address: str | None = Query(None, description="Filter by IP address"),
    start_date: str | None = Query(None, description="Filter from date (ISO 8601)"),
    end_date: str | None = Query(None, description="Filter to date (ISO 8601)"),
    format: str = Query("csv", description="Export format"),
    request: Request = None,
) -> Response:
    """Export Audit Events for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    inject_params = {
        "organization_id": org_id,
        "format": format,
    }

    if resource_type:
        inject_params["category"] = resource_type

    bridged_search = search or actor or resource_id or action or ip_address
    if bridged_search:
        inject_params["search"] = bridged_search

    return await proxy_request(request, service_url, "/v1/organizations/audit/events/export", inject_params=inject_params)


@organization_router.get("/{org_id}/audit-events/{event_id}", response_model=AuditEventResponse, summary="Get Audit Event")
async def get_audit_event(org_id: str, event_id: str, request: Request) -> Response:
    """Get an Audit Event by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/audit/events/{event_id}", inject_params={"organization_id": org_id})


# ── RBAC: Permissions ────────────────────────────────────────────────

@organization_router.get("/{org_id}/permissions", summary="List Permissions")
async def list_permissions(org_id: str, request: Request) -> Response:
    """List the available permission catalog for this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/permissions", inject_params={"organization_id": org_id})


# ── RBAC: Roles ──────────────────────────────────────────────────────

@organization_router.get("/{org_id}/roles", summary="List Roles")
async def list_roles(org_id: str, request: Request) -> Response:
    """List roles in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/roles", summary="Create Role", status_code=201)
async def create_role(org_id: str, request: Request) -> Response:
    """Create a custom role in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/roles/{role_id}", summary="Get Role")
async def get_role(org_id: str, role_id: str, request: Request) -> Response:
    """Get a role by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/roles/{role_id}", summary="Update Role")
async def update_role(org_id: str, role_id: str, request: Request) -> Response:
    """Update a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/roles/{role_id}", summary="Delete Role")
async def delete_role(org_id: str, role_id: str, request: Request) -> Response:
    """Delete a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# ── Members CRUD ─────────────────────────────────────────────────────

@organization_router.get("/{org_id}/members", summary="List Members")
async def list_members(org_id: str, request: Request) -> Response:
    """List members of an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/members", summary="Add Member", status_code=201)
async def add_member(org_id: str, request: Request) -> Response:
    """Add a member to an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/members/{member_id}", summary="Update Member")
async def update_member(org_id: str, member_id: str, request: Request) -> Response:
    """Update a member (e.g. change role)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/members/{member_id}", summary="Remove Member")
async def remove_member(org_id: str, member_id: str, request: Request) -> Response:
    """Remove a member from an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}", inject_params={"organization_id": org_id})


# ── Invites (pending invitations) ────────────────────────────────────

@organization_router.get("/{org_id}/invites", summary="List Invites")
async def list_invites(org_id: str, request: Request) -> Response:
    """List pending invites for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/invites", summary="Create Invite", status_code=201)
async def create_invite(org_id: str, request: Request) -> Response:
    """Create an invite for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/invites/{invite_id}/resend", summary="Resend Invite")
async def resend_invite(org_id: str, invite_id: str, request: Request) -> Response:
    """Resend an invite."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites/{invite_id}/resend", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/invites/{invite_id}", summary="Revoke Invite")
async def revoke_invite(org_id: str, invite_id: str, request: Request) -> Response:
    """Revoke a pending invite."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites/{invite_id}", inject_params={"organization_id": org_id})


# ── Transfer ownership ──────────────────────────────────────────────

@organization_router.post("/{org_id}/transfer-ownership", summary="Transfer Ownership")
async def transfer_ownership(org_id: str, request: Request) -> Response:
    """Transfer organization ownership to another member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/transfer-ownership", inject_params={"organization_id": org_id})


# ── Team snapshot ────────────────────────────────────────────────────

@organization_router.get("/{org_id}/team/snapshot", summary="Team Snapshot")
async def get_team_snapshot(org_id: str, request: Request) -> Response:
    """Get a team snapshot for dashboards."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/team/snapshot", inject_params={"organization_id": org_id})


# ── RBAC: Member role assignments ────────────────────────────────────

@organization_router.put("/{org_id}/members/{member_id}/roles", summary="Set Member Roles")
async def set_member_roles(org_id: str, member_id: str, request: Request) -> Response:
    """Replace all roles for a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/members/{member_id}/roles/{role_id}", summary="Add Role to Member")
async def add_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Add a role to a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/members/{member_id}/roles/{role_id}", summary="Remove Role from Member")
async def remove_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Remove a role from a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# ── RBAC: Current user permissions ───────────────────────────────────

@organization_router.get("/{org_id}/members/me/permissions", summary="Get My Permissions")
async def get_my_permissions(org_id: str, request: Request) -> Response:
    """Get the current user's permissions in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/me/permissions", inject_params={"organization_id": org_id})


# ── SCIM 2.0 Proxy ──────────────────────────────────────────────────

@organization_router.api_route(
    "/{org_id}/scim/v2/{scim_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    summary="SCIM 2.0 Proxy",
)
async def proxy_scim(org_id: str, scim_path: str, request: Request) -> Response:
    """Proxy org-scoped SCIM 2.0 requests to the organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    upstream_path = f"/v1/organizations/{org_id}/scim/v2/{scim_path}" if scim_path else f"/v1/organizations/{org_id}/scim/v2"
    return await proxy_request(request, service_url, upstream_path, inject_params={"organization_id": org_id})


# ── Preferences (Console Context) ───────────────────────────────────

@preferences_router.get("/preferences", response_model=PreferencesResponse, summary="Get Console Context Preferences")
async def get_preferences(request: Request) -> Response:
    """
    Get current user's console context preferences.

    Returns existing preferences or defaults if none exist.
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")


@preferences_router.put("/preferences", response_model=PreferencesResponse, summary="Update Console Context Preferences")
async def update_preferences(body: UpdatePreferencesRequest, request: Request) -> Response:
    """
    Update (upsert) current user's console context preferences.

    Partial update semantics:
    - Absent field: keep existing value
    - Field present as explicit null for last_active_org_id: set to null
    - Field present as null for last_view_mode: rejected with 400
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")
