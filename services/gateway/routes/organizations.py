"""Organization, membership, RBAC, invites, SCIM, and preferences routes."""
from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
import httpx
from typing import Any
from fastapi import APIRouter, Query, Request, Response

from gateway.middleware import mip_error_response
from gateway.models import (
    AuditEventResponse,
    HostedPilotPurgeResponse,
    InvitationAcceptRequest,
    InvitationAcceptResponse,
    InvitationValidateResponse,
    JoinByCodeRequest,
    JoinByCodeResponse,
    OrganizationLifecycleResponse,
    OrganizationCreate,
    OrganizationResponse,
    PreferencesResponse,
    UpdatePreferencesRequest,
    ValidateJoinCodeResponse,
)
from gateway.proxy import get_http_client, get_registry, proxy_request

organization_router = APIRouter(prefix="/v1/organizations", tags=["Organizations"])
preferences_router = APIRouter(prefix="/v1/me", tags=["User Preferences"])

logger = logging.getLogger(__name__)


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


@organization_router.get("/{org_id}/lifecycle", response_model=OrganizationLifecycleResponse, summary="Get Organization Lifecycle")
async def get_organization_lifecycle(org_id: str, request: Request) -> Response | dict:
    """Get aggregated lifecycle metadata for dashboard retention surfaces."""
    lifecycle_payload, error_response = await _load_organization_lifecycle_payload(
        org_id,
        headers=_forward_context_headers(request),
    )
    if error_response is not None:
        return error_response
    return lifecycle_payload


@organization_router.get("/{org_id}/runtime/status", summary="Runtime Status", response_model=None)
async def get_runtime_status(org_id: str, request: Request) -> Response | dict[str, Any]:
    """Return conservative runtime readiness derived from live org artifacts."""
    payload, error_response = await _load_runtime_status_payload(
        org_id,
        headers=_forward_context_headers(request),
    )
    if error_response is not None:
        return error_response
    return payload


@organization_router.get("/{org_id}/environment", summary="Organization Environment")
async def get_organization_environment(org_id: str, request: Request) -> Response:
    """Return the dashboard environment setting from the organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/environment", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/environment", summary="Update Organization Environment")
async def update_organization_environment(org_id: str, request: Request) -> Response:
    """Update the dashboard environment setting through the organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/environment", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/dashboard/applicant-stats", summary="Applicant Stats", response_model=None)
async def get_dashboard_applicant_stats(org_id: str, request: Request) -> Response | dict[str, int]:
    """Return applicant lifecycle counts from the applicant service."""
    payload, error_response = await _load_applicant_stats_payload(
        org_id,
        headers=_forward_context_headers(request),
    )
    if error_response is not None:
        return error_response
    return payload


@organization_router.get("/{org_id}/integration-info", summary="Integration Info")
async def get_organization_integration_info(org_id: str, request: Request) -> dict[str, str]:
    """Return real request/deployment-derived developer quick-start metadata."""
    base_url = _public_api_base_url(request)
    example_request = (
        f"curl -sS -X POST \"{base_url}/flows/instances\" \\\n"
        "  -H \"Content-Type: application/json\" \\\n"
        "  -H \"X-API-Key: <api-key>\" \\\n"
        f"  -H \"X-Organization-ID: {org_id}\" \\\n"
        "  -d '{\"flow_definition_id\":\"<flow-definition-id>\",\"subject_id\":\"<subject-id>\",\"initial_context\":{}}'"
    )
    return {
        "org_id": org_id,
        "base_url": base_url,
        "example_request": example_request,
    }


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
        inject_params["resource_type"] = resource_type
    if resource_id:
        inject_params["resource_id"] = resource_id
    if action:
        inject_params["action"] = action
    if actor:
        inject_params["actor"] = actor
    if severity:
        inject_params["severity"] = severity
    if ip_address:
        inject_params["ip_address"] = ip_address
    if start_date:
        inject_params["start_date"] = start_date
    if end_date:
        inject_params["end_date"] = end_date

    if search:
        inject_params["search"] = search

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
        inject_params["resource_type"] = resource_type
    if resource_id:
        inject_params["resource_id"] = resource_id
    if action:
        inject_params["action"] = action
    if actor:
        inject_params["actor"] = actor
    if severity:
        inject_params["severity"] = severity
    if ip_address:
        inject_params["ip_address"] = ip_address
    if start_date:
        inject_params["start_date"] = start_date
    if end_date:
        inject_params["end_date"] = end_date

    if search:
        inject_params["search"] = search

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


@organization_router.post("/{org_id}/lifecycle/purge", response_model=HostedPilotPurgeResponse, summary="Purge Hosted Pilot Data")
async def purge_hosted_pilot_data(org_id: str, request: Request) -> Response | dict:
    """Manually purge Hosted Pilot data that has aged past the retention window."""
    purge_payload, error_response = await run_hosted_pilot_purge(
        org_id,
        headers=_forward_context_headers(request),
    )
    if error_response is not None:
        return error_response
    return purge_payload


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


def _public_api_base_url(request: Request) -> str:
    configured = (
        os.environ.get("PUBLIC_API_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
    )
    if configured:
        origin = configured.strip().rstrip("/")
    else:
        forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        forwarded_proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
        host = forwarded_host.split(",", 1)[0].strip() if forwarded_host else request.url.netloc
        proto = forwarded_proto.split(",", 1)[0].strip().lower() if forwarded_proto else "https"
        origin = f"{proto}://{host}".rstrip("/")

    return origin if origin.endswith("/v1") else f"{origin}/v1"


def _forward_context_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    if hasattr(request.state, "user_id") and request.state.user_id:
        headers["X-User-Id"] = request.state.user_id
    if hasattr(request.state, "user_email") and request.state.user_email:
        headers["X-User-Email"] = request.state.user_email
    if hasattr(request.state, "user_domain") and request.state.user_domain:
        headers["X-User-Domain"] = request.state.user_domain
    if hasattr(request.state, "org_plan") and request.state.org_plan:
        headers["X-Org-Plan"] = request.state.org_plan
    if hasattr(request.state, "organization_id") and request.state.organization_id:
        headers["X-Organization-ID"] = request.state.organization_id
    org_permissions = getattr(request.state, "org_permissions", None)
    if org_permissions:
        headers["X-Org-Permissions"] = ",".join(sorted(str(value) for value in org_permissions))
    org_roles = getattr(request.state, "org_roles", None)
    if org_roles:
        headers["X-Org-Roles"] = ",".join(sorted(str(value) for value in org_roles))
    auth = request.headers.get("authorization")
    if auth:
        headers["Authorization"] = auth
    return headers


def _proxy_error_response(response: httpx.Response) -> Response:
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers={
            k: v for k, v in response.headers.items()
            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
        },
        media_type=response.headers.get("content-type"),
    )


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) == 10 and normalized[4] == "-" and normalized[7] == "-":
        normalized = f"{normalized}T00:00:00+00:00"
    normalized = normalized.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _retention_window_days(lifecycle_payload: dict[str, Any]) -> int:
    pilot_retention = lifecycle_payload.get("pilot_retention") or {}
    raw_value = pilot_retention.get("window_days") or lifecycle_payload.get("audit_retention_days") or 30
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return 30
    return parsed if parsed > 0 else 30


async def _request_service_json_with_headers(
    service_name: str,
    path: str,
    *,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> tuple[Any, Response | None]:
    registry = registry or get_registry()
    service_url = registry.get_service_url(service_name)
    if not service_url:
        return {}, mip_error_response(
            status_code=503,
            error="service_unavailable",
            message=f"{service_name} service unavailable",
            extra={"service": service_name},
        )
    client = client or get_http_client()
    url = f"{service_url}{path}"

    try:
        response = await client.request(
            method=method,
            url=url,
            headers=headers or {},
            params=params,
            json=json_body,
            timeout=30.0,
        )
    except httpx.ConnectError:
        return {}, mip_error_response(status_code=503, error="service_unavailable", message=f"{service_name} service unavailable")
    except httpx.TimeoutException:
        return {}, mip_error_response(status_code=504, error="service_timeout", message=f"{service_name} service timed out")
    except httpx.HTTPError as exc:
        return {}, mip_error_response(
            status_code=502,
            error="service_request_failed",
            message=f"{service_name} service request failed: {exc}",
            extra={"service": service_name},
        )

    if response.status_code >= 400:
        return {}, _proxy_error_response(response)

    try:
        return response.json(), None
    except ValueError:
        return {}, mip_error_response(
            status_code=502,
            error="invalid_upstream_response",
            message=f"{service_name} service returned invalid JSON",
            extra={"service": service_name},
        )


def _payload_items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _status_value(item: dict[str, Any]) -> str:
    return str(item.get("status") or item.get("state") or "").strip().lower()


def _is_active_artifact(item: dict[str, Any]) -> bool:
    status = _status_value(item)
    return not status or status in {"active", "enabled", "ready"}


async def _load_org_artifact_list(
    service_name: str,
    path: str,
    org_id: str,
    *,
    keys: tuple[str, ...],
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> tuple[list[dict[str, Any]], Response | None]:
    payload, error_response = await _request_service_json_with_headers(
        service_name,
        path,
        params={"organization_id": org_id},
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return [], error_response
    return _payload_items(payload, *keys), None


async def _load_runtime_status_payload(
    org_id: str,
    *,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> tuple[dict[str, Any], Response | None]:
    templates, error_response = await _load_org_artifact_list(
        "credential-templates",
        "/v1/credential-templates",
        org_id,
        keys=("templates", "credential_templates"),
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    policies, error_response = await _load_org_artifact_list(
        "presentation-policies",
        "/v1/presentation-policies",
        org_id,
        keys=("policies", "presentation_policies"),
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    deployments, error_response = await _load_org_artifact_list(
        "deployment-profiles",
        "/v1/deployment-profiles",
        org_id,
        keys=("profiles", "deployment_profiles"),
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    flows, error_response = await _load_org_artifact_list(
        "flows",
        "/v1/flows/definitions",
        org_id,
        keys=("flows", "definitions", "flow_definitions"),
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    active_templates = [item for item in templates if _is_active_artifact(item)]
    active_policies = [item for item in policies if _is_active_artifact(item)]
    active_deployments = [item for item in deployments if _is_active_artifact(item)]
    active_flows = [item for item in flows if _is_active_artifact(item)]
    kms_backed_templates = [
        item for item in active_templates
        if item.get("issuer_profile_id") and str(item.get("key_access_mode") or "").upper() == "REMOTE_SIGNING"
    ]

    issuer_active = bool(kms_backed_templates)
    issuer_keys_valid = issuer_active
    deployment_active = bool(active_deployments)
    policy_reachable = bool(active_policies)
    issuance_flow_active = any(
        item.get("credential_template_id") and _status_value(item) in {"active", "enabled", "ready", ""}
        for item in active_flows
    )

    return {
        "can_issue": bool(issuer_active and issuer_keys_valid and deployment_active and issuance_flow_active),
        "can_verify": bool(policy_reachable and deployment_active),
        "issuer_keys_valid": issuer_keys_valid,
        "issuer_active": issuer_active,
        "deployment_active": deployment_active,
        "policy_reachable": policy_reachable,
        "last_issuance_timestamp": None,
        "last_verification_timestamp": None,
        "artifact_counts": {
            "active_credential_templates": len(active_templates),
            "kms_backed_credential_templates": len(kms_backed_templates),
            "active_presentation_policies": len(active_policies),
            "active_deployment_profiles": len(active_deployments),
            "active_flows": len(active_flows),
        },
    }, None


async def _load_applicant_stats_payload(
    org_id: str,
    *,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> tuple[dict[str, int], Response | None]:
    payload, error_response = await _request_service_json_with_headers(
        "applicant",
        f"/v1/organizations/{org_id}/applicants",
        params={"limit": 500},
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    applications = _payload_items(payload, "items")
    pending_statuses = {"submitted", "under_review", "pending_information", "pending"}
    approved_statuses = {"approved"}
    issuable_statuses = {"approved", "offered"}

    return {
        "pending": sum(1 for item in applications if _status_value(item) in pending_statuses),
        "approved": sum(1 for item in applications if _status_value(item) in approved_statuses),
        "issuable": sum(1 for item in applications if _status_value(item) in issuable_statuses),
        "total": len(applications),
    }, None


async def _load_organization_lifecycle_payload(
    org_id: str,
    *,
    internal: bool = False,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> tuple[dict[str, Any], Response | None]:
    lifecycle_payload, error_response = await _request_service_json_with_headers(
        "organizations",
        (
            f"/internal/v1/organizations/{org_id}/lifecycle"
            if internal
            else f"/v1/organizations/{org_id}/lifecycle"
        ),
        params=None if internal else {"organization_id": org_id},
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        return {}, error_response

    pilot_retention = lifecycle_payload.get("pilot_retention") or None
    if not pilot_retention or not pilot_retention.get("enabled"):
        return lifecycle_payload, None

    summary_payload, summary_error = await _request_service_json_with_headers(
        "issuance",
        f"/v1/issuance/organizations/{org_id}/retention",
        params={"retention_days": _retention_window_days(lifecycle_payload)},
        headers=headers,
        client=client,
        registry=registry,
    )
    if summary_error is not None:
        logger.warning("Retention summary unavailable for org %s; preserving upstream error", org_id)
        return {}, summary_error

    lifecycle_payload["pilot_retention"] = {
        **pilot_retention,
        "cutoff_at": summary_payload.get("cutoff_at"),
        "next_expiry_at": summary_payload.get("next_expiry_at"),
        "oldest_retained_record_at": summary_payload.get("oldest_retained_record_at"),
        "eligible_for_purge": summary_payload.get("eligible_for_purge", {}),
        "tracked_scope": list(summary_payload.get("tracked_scope", [])),
    }
    return lifecycle_payload, None


async def _sync_hosted_pilot_purge_metadata(
    org_id: str,
    lifecycle_payload: dict[str, Any],
    purge_payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
) -> None:
    purged_at = purge_payload.get("purged_at")
    if not purged_at:
        return

    update_body: dict[str, Any] = {
        "plan_tier": lifecycle_payload.get("plan_tier") or "free",
        "settings_patch": {"pilot_retention_last_purged_at": purged_at},
    }
    if lifecycle_payload.get("plan_expires_at"):
        update_body["plan_expires_at"] = lifecycle_payload["plan_expires_at"]

    _, error_response = await _request_service_json_with_headers(
        "organizations",
        f"/internal/v1/organizations/{org_id}/plan",
        method="PUT",
        json_body=update_body,
        headers=headers,
        client=client,
        registry=registry,
    )
    if error_response is not None:
        logger.warning("Hosted Pilot purge metadata sync failed for org %s", org_id)


async def run_hosted_pilot_purge(
    org_id: str,
    *,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
    lifecycle_payload: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Response | None]:
    if lifecycle_payload is None:
        lifecycle_payload, error_response = await _load_organization_lifecycle_payload(
            org_id,
            headers=headers,
            client=client,
            registry=registry,
        )
        if error_response is not None:
            return {}, error_response

    pilot_retention = lifecycle_payload.get("pilot_retention") or {}
    if not pilot_retention.get("enabled"):
        return {}, mip_error_response(
            status_code=400,
            error="retention_not_enabled",
            message="Hosted Pilot retention is not enabled for this organization",
        )

    purge_payload, purge_error = await _request_service_json_with_headers(
        "issuance",
        f"/v1/issuance/organizations/{org_id}/retention/purge",
        method="POST",
        params={"retention_days": _retention_window_days(lifecycle_payload)},
        headers=headers,
        client=client,
        registry=registry,
    )
    if purge_error is not None:
        return {}, purge_error

    await _sync_hosted_pilot_purge_metadata(
        org_id,
        lifecycle_payload,
        purge_payload,
        headers=headers,
        client=client,
        registry=registry,
    )
    return purge_payload, None


async def run_hosted_pilot_auto_purge_sweep(
    *,
    client: httpx.AsyncClient | None = None,
    registry: Any | None = None,
    batch_size: int = 100,
) -> dict[str, int]:
    page_size = max(int(batch_size or 100), 1)
    stats = {
        "organizations_scanned": 0,
        "hosted_pilot_orgs": 0,
        "purge_requests": 0,
        "purged_records": 0,
    }
    offset = 0
    now = datetime.now(timezone.utc)

    while True:
        organizations_payload, error_response = await _request_service_json_with_headers(
            "organizations",
            "/v1/organizations",
            params={"limit": page_size, "offset": offset},
            client=client,
            registry=registry,
        )
        if error_response is not None:
            logger.warning("Hosted Pilot auto-purge sweep could not list organizations")
            return stats

        organizations = organizations_payload if isinstance(organizations_payload, list) else []
        if not organizations:
            return stats

        stats["organizations_scanned"] += len(organizations)
        for organization in organizations:
            org_id = organization.get("id")
            if not org_id:
                continue

            lifecycle_payload, lifecycle_error = await _load_organization_lifecycle_payload(
                org_id,
                internal=True,
                client=client,
                registry=registry,
            )
            if lifecycle_error is not None:
                logger.warning("Hosted Pilot auto-purge sweep could not load lifecycle for org %s", org_id)
                continue

            pilot_retention = lifecycle_payload.get("pilot_retention") or {}
            if not pilot_retention.get("enabled"):
                continue

            stats["hosted_pilot_orgs"] += 1
            eligible_total = int((pilot_retention.get("eligible_for_purge") or {}).get("total") or 0)
            next_expiry_at = _parse_iso_timestamp(pilot_retention.get("next_expiry_at"))
            if eligible_total <= 0 and (next_expiry_at is None or next_expiry_at > now):
                continue

            purge_payload, purge_error = await run_hosted_pilot_purge(
                org_id,
                client=client,
                registry=registry,
                lifecycle_payload=lifecycle_payload,
            )
            if purge_error is not None:
                logger.warning("Hosted Pilot auto-purge sweep failed for org %s", org_id)
                continue

            stats["purge_requests"] += 1
            stats["purged_records"] += int((purge_payload.get("purged_records") or {}).get("total") or 0)

        if len(organizations) < page_size:
            return stats
        offset += len(organizations)


async def _request_service_json(
    request: Request,
    service_name: str,
    path: str,
    method: str = "GET",
    params: dict | None = None,
) -> tuple[Any, Response | None]:
    return await _request_service_json_with_headers(
        service_name,
        path,
        method=method,
        params=params,
        headers=_forward_context_headers(request),
    )
