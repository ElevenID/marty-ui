"""
Organization Service HTTP Adapter (FastAPI)

FastAPI router providing the HTTP API for the Organization service.
"""

from __future__ import annotations

from datetime import datetime
import logging
import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr
from marty_common import OrganizationClient, OrganizationContext, require_org_membership, require_permission
from marty_common.system_ids import MARTY_DEFAULT_ORG_ID

from ...application.ports import (
    CreateApiKeyCommand,
    CreateOrganizationCommand,
    InviteMemberCommand,
    JoinByCodeCommand,
    JoinOrganizationCommand,
    RevokeApiKeyCommand,
    SetMemberRolesCommand,
    UpdateOrganizationCommand,
)
from ...application.use_cases import ApiKeyUseCase, JoinUseCase, MemberUseCase, OrganizationUseCase
from ...domain.entities import MemberStatus, OrganizationType

logger = logging.getLogger(__name__)

# Stable ID for the default Marty organization — users cannot be removed from it
MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID)

# Create router with versioned prefix
router = APIRouter(prefix="/v1/organizations", tags=["organizations"])

_ORG_TYPE_ALIASES: dict[str, OrganizationType] = {
    "vendor": OrganizationType.ENTERPRISE,
    "nonprofit": OrganizationType.INDIVIDUAL,
}

_DISABLED_ENV_VALUES = {"0", "false", "no", "off", "disabled"}
_DASHBOARD_ENVIRONMENTS = {"development", "staging", "production"}


def _organization_creation_enabled() -> bool:
    """Return whether end-user organization creation is enabled for this deployment."""
    return os.environ.get("ORGANIZATION_CREATION_ENABLED", "true").strip().lower() not in _DISABLED_ENV_VALUES


def _normalize_org_type(value: str) -> OrganizationType:
    """Normalize incoming organization type values to canonical enum values."""
    normalized = (value or "").strip().lower()
    if not normalized:
        return OrganizationType.STARTUP

    alias = _ORG_TYPE_ALIASES.get(normalized)
    if alias is not None:
        return alias

    return OrganizationType(normalized)


# =============================================================================
# Request/Response Models
# =============================================================================

class CreateOrganizationRequest(BaseModel):
    """Request to create an organization."""
    name: str
    display_name: str | None = None
    org_type: str = "startup"
    description: str | None = None
    contact_email: EmailStr | None = None


class UpdateOrganizationRequest(BaseModel):
    """Request to update an organization."""
    name: str | None = None
    description: str | None = None
    contact_email: EmailStr | None = None
    contact_phone: str | None = None
    website: str | None = None
    settings: dict[str, Any] | None = None


class OrganizationResponse(BaseModel):
    """Organization response."""
    id: str
    name: str
    display_name: str | None
    description: str | None = None
    join_code: str | None = None
    visibility: str = "PRIVATE"
    owner_id: str
    status: str
    created_at: str
    updated_at: str | None = None
    membership: dict[str, Any] | None = None


class InviteMemberRequest(BaseModel):
    """Request to invite a member."""
    email: EmailStr
    role_ids: list[str]


class RoleSummaryResponse(BaseModel):
    """Lightweight role representation."""
    id: str
    name: str
    display_name: str | None = None


class MemberResponse(BaseModel):
    """Member response."""
    id: str
    organization_id: str
    user_id: str | None
    email: str | None
    roles: list[RoleSummaryResponse]
    status: str
    permissions: list[str]
    has_org_console_access: bool
    is_owner: bool
    invited_at: str | None
    joined_at: str | None


class UpdateMemberRequest(BaseModel):
    """Request to update member role."""
    role_ids: list[str]


class JoinByCodeRequest(BaseModel):
    """Request to join an organization by code."""
    code: str


class JoinByCodeResponse(BaseModel):
    """Response after joining an organization by code."""
    organization: OrganizationResponse
    membership: MemberResponse


class ValidateJoinCodeResponse(BaseModel):
    """Response for validating join/invitation code."""
    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    expired: bool = False
    message: str | None = None


class MembershipDetails(BaseModel):
    """Membership details for the current user."""
    roles: list[RoleSummaryResponse]
    status: str
    permissions: list[str]
    has_org_console_access: bool
    is_owner: bool
    joined_at: str | None


class OrganizationWithMembership(BaseModel):
    """Organization with user's membership details."""
    id: str
    name: str
    display_name: str | None
    description: str | None = None
    visibility: str = "PRIVATE"
    owner_id: str
    status: str
    created_at: str
    updated_at: str | None = None
    membership: MembershipDetails


class CreateApiKeyRequest(BaseModel):
    """Request to create an API key."""
    name: str
    description: str | None = None
    scopes: list[str] | None = None
    is_test: bool = False


class ApiKeyResponse(BaseModel):
    """API key response."""
    id: str
    organization_id: str
    name: str
    description: str | None = None
    key_prefix: str
    scope_type: str = "ORGANIZATION"
    deployment_profile_id: str | None = None
    scopes: list[str]
    enabled: bool = True
    expires_at: str | None = None
    last_used_at: str | None = None
    created_at: str
    updated_at: str | None = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    """API key response with raw key (only at creation)."""
    key: str  # Only returned once!


class PilotRetentionResponse(BaseModel):
    """Hosted Pilot retention policy details."""
    enabled: bool = True
    window_days: int = 30
    scope_summary: str
    scope_items: list[str]
    access_behavior: str
    last_purged_at: str | None = None


class OrganizationLifecycleResponse(BaseModel):
    """Lifecycle and retention metadata for dashboard surfaces."""
    created_at: str
    compliance_profiles: list[str] = []
    data_retention_mode: str = "standard"
    audit_retention_days: int = 90
    pilot_retention: PilotRetentionResponse | None = None


class TeamSnapshotResponse(BaseModel):
    """Dashboard team snapshot sourced from organization memberships."""
    members: list[dict[str, Any]]
    pending_invites: list[dict[str, Any]]
    role_distribution: dict[str, int]


class OrganizationEnvironmentResponse(BaseModel):
    """Dashboard environment setting stored on the organization."""
    organization_id: str
    environment: str | None = None


class UpdateOrganizationEnvironmentRequest(BaseModel):
    """Request to update an organization's dashboard environment label."""
    environment: str


# =============================================================================
# Dependencies
# =============================================================================

_organization_use_case: OrganizationUseCase | None = None
_member_use_case: MemberUseCase | None = None
_api_key_use_case: ApiKeyUseCase | None = None
_join_use_case: JoinUseCase | None = None


def configure_org_router(
    organization_use_case: OrganizationUseCase,
    member_use_case: MemberUseCase,
    api_key_use_case: ApiKeyUseCase,
    join_use_case: JoinUseCase,
) -> None:
    """Configure router with use cases."""
    global _organization_use_case, _member_use_case, _api_key_use_case, _join_use_case
    _organization_use_case = organization_use_case
    _member_use_case = member_use_case
    _api_key_use_case = api_key_use_case
    _join_use_case = join_use_case


def get_org_use_case() -> OrganizationUseCase:
    if _organization_use_case is None:
        raise RuntimeError("Organization router not configured")
    return _organization_use_case


def get_member_use_case() -> MemberUseCase:
    if _member_use_case is None:
        raise RuntimeError("Organization router not configured")
    return _member_use_case


def get_api_key_use_case() -> ApiKeyUseCase:
    if _api_key_use_case is None:
        raise RuntimeError("Organization router not configured")
    return _api_key_use_case


def get_join_use_case() -> JoinUseCase:
    if _join_use_case is None:
        raise RuntimeError("Organization router not configured")
    return _join_use_case


# Auth dependency - extracts user ID from gateway-injected header
async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None
) -> str:
    """Get current user ID from gateway auth middleware."""
    if not x_user_id:
        logger.error("Missing X-User-Id header - gateway auth middleware not working")
        raise HTTPException(
            status_code=401,
            detail="Authentication required - missing user context",
        )
    return x_user_id


# =============================================================================
# Organization Endpoints
# =============================================================================

@router.post("", response_model=OrganizationResponse, response_model_exclude_none=True)
async def create_organization(
    request: CreateOrganizationRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationResponse:
    """Create a new organization."""
    if not _organization_creation_enabled():
        raise HTTPException(status_code=403, detail="Organization creation is disabled for this deployment")

    try:
        org = await use_case.create_organization(
            CreateOrganizationCommand(
                name=request.name,
                owner_id=user_id,
                org_type=_normalize_org_type(request.org_type),
                display_name=request.display_name,
                description=request.description,
                contact_email=request.contact_email,
            )
        )
        owner_membership = None
        member_repo = getattr(use_case, "member_repo", None)
        if member_repo is not None and hasattr(member_repo, "get_by_user_and_org"):
            owner_membership = await member_repo.get_by_user_and_org(user_id, str(org.id))
        return _org_to_response(org, membership=owner_membership)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[OrganizationResponse], response_model_exclude_none=True)
async def list_organizations(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> list[OrganizationResponse]:
    """List all organizations."""
    orgs = await use_case.list_organizations(limit=limit, offset=offset)
    return [_org_to_response(org) for org in orgs]


@router.get("/discover", response_model=list[OrganizationResponse], response_model_exclude_none=True)
async def discover_organizations(
    search: str | None = Query(default=None, description="Search by name or display name"),
    org_type: str | None = Query(default=None, description="Filter by organization type"),
    join_mechanism: str | None = Query(default=None, description="Filter by join mechanism (open, code, invite, domain)"),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> list[OrganizationResponse]:
    """Discover publicly available organizations."""
    try:
        orgs = await use_case.discover_organizations(
            search=search,
            org_type=org_type,
            join_mechanism=join_mechanism,
            limit=limit,
            offset=offset,
        )
        return [_org_to_response(org) for org in orgs]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/mine", response_model=list[OrganizationWithMembership], response_model_exclude_none=True)
async def get_my_organizations(
    user_id: str = Depends(get_current_user_id),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> list[OrganizationWithMembership]:
    """Get organizations the current user belongs to with membership details."""
    org_memberships = await use_case.get_user_organizations_with_memberships(user_id)
    
    results = []
    for org, membership in org_memberships:
        results.append(OrganizationWithMembership(
            id=str(org.id),
            name=org.name,
            display_name=org.display_name,
            description=org.description,
            visibility=org.visibility,
            owner_id=org.owner_id,
            status=org.status.value,
            created_at=org.created_at.isoformat(),
            updated_at=org.updated_at.isoformat() if org.updated_at else None,
            membership=MembershipDetails(
                roles=[
                    RoleSummaryResponse(
                        id=role.id,
                        name=role.name,
                        display_name=role.display_name,
                    )
                    for role in membership.roles
                ],
                status=membership.status.value,
                permissions=sorted(membership.effective_permissions),
                has_org_console_access=membership.has_org_console_access,
                is_owner=membership.is_owner,
                joined_at=membership.joined_at.isoformat() if membership.joined_at else None,
            ),
        ))
    
    return results


@router.get("/{org_id}", response_model=OrganizationResponse, response_model_exclude_none=True)
async def get_organization(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationResponse:
    """Get an organization by ID. Requires membership."""
    try:
        org = await use_case.get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return _org_to_response(org)
    except Exception as e:
        # Handle invalid UUID format or other database errors
        error_str = str(e).lower()
        if any(keyword in error_str for keyword in [
            "invalid input syntax for type uuid",
            "badly formed hexadecimal uuid",
            "invalid uuid",
            "invalid input for query argument",
            "length must be between 32..36 characters"
        ]):
            raise HTTPException(status_code=404, detail="Organization not found")
        # Re-raise if it's something else
        logger.error(f"Error getting organization {org_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{org_id}/lifecycle", response_model=OrganizationLifecycleResponse, response_model_exclude_none=True)
async def get_organization_lifecycle(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationLifecycleResponse:
    """Get organization lifecycle and retention metadata for dashboards."""
    org = await use_case.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _org_to_lifecycle_response(org)



@router.patch("/{org_id}", response_model=OrganizationResponse, response_model_exclude_none=True)
async def update_organization(
    org_id: str,
    request: UpdateOrganizationRequest,
    org_ctx: OrganizationContext = Depends(require_permission("organization", "edit")),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationResponse:
    """Update an organization."""
    try:
        org = await use_case.update_organization(
            UpdateOrganizationCommand(
                organization_id=org_id,
                name=request.name,
                description=request.description,
                contact_email=request.contact_email,
                contact_phone=request.contact_phone,
                website=request.website,
                settings=request.settings,
            )
        )
        return _org_to_response(org)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Join Endpoints
# =============================================================================

@router.post("/join/code", response_model=JoinByCodeResponse, response_model_exclude_none=True, status_code=201)
async def join_by_code(
    request: JoinByCodeRequest,
    user_id: str = Depends(get_current_user_id),
    x_user_email: Annotated[str | None, Header(alias="X-User-Email")] = None,
    use_case: JoinUseCase = Depends(get_join_use_case),
) -> JoinByCodeResponse:
    """Join an organization using a join code."""
    if not x_user_email:
        raise HTTPException(status_code=400, detail="User email not available")
    
    try:
        org, member = await use_case.join_by_code(
            JoinByCodeCommand(
                user_id=user_id,
                code=request.code.upper(),  # Normalize to uppercase
                email=x_user_email,
            )
        )
        return JoinByCodeResponse(
            organization=_org_to_response(org),
            membership=_member_to_response(member),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/join/code/validate", response_model=ValidateJoinCodeResponse, response_model_exclude_none=True)
async def validate_join_code(
    code: str = Query(..., description="Join/invitation code"),
    use_case: JoinUseCase = Depends(get_join_use_case),
) -> ValidateJoinCodeResponse:
    """Validate a join/invitation code without creating membership."""
    is_valid, org, message, expired = await use_case.validate_join_code(code)
    return ValidateJoinCodeResponse(
        valid=is_valid,
        organization_id=str(org.id) if org else None,
        organization_name=org.name if org else None,
        expired=expired,
        message=message,
    )


@router.post("/{org_id}/join", response_model=JoinByCodeResponse, response_model_exclude_none=True, status_code=201)
async def join_organization(
    org_id: str,
    user_id: str = Depends(get_current_user_id),
    x_user_email: Annotated[str | None, Header(alias="X-User-Email")] = None,
    use_case: JoinUseCase = Depends(get_join_use_case),
) -> JoinByCodeResponse:
    """Join/request to join an organization directly by ID (open join only)."""
    if not x_user_email:
        raise HTTPException(status_code=400, detail="User email not available")

    try:
        org, member = await use_case.join_organization(
            JoinOrganizationCommand(
                user_id=user_id,
                organization_id=org_id,
                email=x_user_email,
            )
        )
        return JoinByCodeResponse(
            organization=_org_to_response(org),
            membership=_member_to_response(member),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Dashboard Organization Endpoints
# =============================================================================

@router.get("/{org_id}/team/snapshot", response_model=TeamSnapshotResponse, response_model_exclude_none=True)
async def get_team_snapshot(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_permission("team", "view")),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> TeamSnapshotResponse:
    """Return a dashboard team snapshot from real organization memberships."""
    members = await use_case.list_members(org_id)
    active_members = [member for member in members if member.status == MemberStatus.ACTIVE]
    pending_members = [
        member for member in members
        if member.status in {MemberStatus.INVITED, MemberStatus.PENDING}
    ]

    return TeamSnapshotResponse(
        members=[_member_dashboard_summary(member) for member in active_members],
        pending_invites=[_member_dashboard_summary(member) for member in pending_members],
        role_distribution=_role_distribution(active_members),
    )


@router.get("/{org_id}/environment", response_model=OrganizationEnvironmentResponse)
async def get_organization_environment(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationEnvironmentResponse:
    """Return the stored dashboard environment label without inventing a default."""
    org = await use_case.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return OrganizationEnvironmentResponse(
        organization_id=org_id,
        environment=_normalize_dashboard_environment((org.settings or {}).get("environment")),
    )


@router.patch("/{org_id}/environment", response_model=OrganizationEnvironmentResponse, response_model_exclude_none=True)
async def update_organization_environment(
    org_id: str,
    body: UpdateOrganizationEnvironmentRequest,
    org_ctx: OrganizationContext = Depends(require_permission("organization", "edit")),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationEnvironmentResponse:
    """Update the dashboard environment label stored on the organization."""
    environment = _normalize_dashboard_environment(body.environment)
    if environment is None:
        raise HTTPException(
            status_code=400,
            detail="environment must be one of: development, staging, production",
        )

    await use_case.update_organization(
        UpdateOrganizationCommand(
            organization_id=org_id,
            settings={"environment": environment},
        )
    )
    return OrganizationEnvironmentResponse(organization_id=org_id, environment=environment)


# =============================================================================
# Member Endpoints
# =============================================================================

@router.get("/{org_id}/members", response_model=list[MemberResponse], response_model_exclude_none=True)
async def list_members(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_permission("team", "view")),
    use_case: MemberUseCase = Depends(get_member_use_case),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[MemberResponse]:
    """List all members of an organization. Requires membership."""
    members = await use_case.list_members(org_id)
    return [_member_to_response(m) for m in members[offset:offset + limit]]


@router.post("/{org_id}/members", response_model=MemberResponse, response_model_exclude_none=True)
async def invite_member(
    org_id: str,
    request: InviteMemberRequest,
    http_request: Request,
    org_ctx: OrganizationContext = Depends(require_permission("team", "invite")),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> MemberResponse:
    """Invite a new member to an organization."""
    try:
        member = await use_case.invite_member(
            InviteMemberCommand(
                organization_id=org_id,
                email=request.email,
                role_ids=request.role_ids,
                invited_by=org_ctx.user_id,
            )
        )
        
        # Invalidate cache for the invited user once they accept
        # Note: We can't invalidate yet since they don't have a user_id until they accept
        # Cache will be invalidated when they actually join
        
        return _member_to_response(member)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/{org_id}/members/{member_id}", response_model=MemberResponse, response_model_exclude_none=True)
async def update_member(
    org_id: str,
    member_id: str,
    request: UpdateMemberRequest,
    http_request: Request,
    org_ctx: OrganizationContext = Depends(require_permission("team", "manage")),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> MemberResponse:
    """Update a member's role assignments."""
    try:
        member = await use_case.set_member_roles(
            SetMemberRolesCommand(
                member_id=member_id,
                organization_id=org_id,
                role_ids=request.role_ids,
                updated_by=org_ctx.user_id,
            )
        )
        
        # Invalidate cache for the updated member
        if member.user_id and hasattr(http_request.app.state, "org_client"):
            org_client: OrganizationClient = http_request.app.state.org_client
            await org_client.invalidate_cache(member.user_id, org_id)
            logger.info(f"Invalidated membership cache for user {member.user_id} in org {org_id}")
        
        return _member_to_response(member)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{org_id}/members/{member_id}")
async def remove_member(
    org_id: str,
    member_id: str,
    http_request: Request,
    org_ctx: OrganizationContext = Depends(require_permission("team", "manage")),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> dict[str, bool]:
    """Remove a member from an organization."""
    if org_id == MARTY_ORG_ID:
        raise HTTPException(
            status_code=403,
            detail="Members cannot be removed from the Marty default organization.",
        )
    try:
        await use_case.remove_member(member_id, org_ctx.user_id)
        return {"success": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# API Key Endpoints
# =============================================================================

@router.get("/{org_id}/api-keys", response_model=list[ApiKeyResponse], response_model_exclude_none=True)
async def list_api_keys(
    org_id: str,
    org_ctx: OrganizationContext = Depends(require_permission("api-key", "view")),
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[ApiKeyResponse]:
    """List all API keys for an organization. Requires admin or owner role."""
    keys = await use_case.list_api_keys(org_id)
    return [_api_key_to_response(k) for k in keys[offset:offset + limit]]


@router.post("/{org_id}/api-keys", response_model=ApiKeyCreatedResponse, response_model_exclude_none=True)
async def create_api_key(
    org_id: str,
    request: CreateApiKeyRequest,
    org_ctx: OrganizationContext = Depends(require_permission("api-key", "create")),
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
) -> ApiKeyCreatedResponse:
    """
    Create a new API key. Requires admin or owner role.
    
    ⚠️ The key value is only returned once. Store it securely!
    """
    try:
        api_key, raw_key = await use_case.create_api_key(
            CreateApiKeyCommand(
                organization_id=org_id,
                name=request.name,
                created_by=org_ctx.user_id,
                scopes=request.scopes,
                description=request.description,
                is_test=request.is_test,
            )
        )
        
        response = _api_key_to_response(api_key)
        return ApiKeyCreatedResponse(
            **response.model_dump(),
            key=raw_key,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{org_id}/api-keys/{key_id}")
async def revoke_api_key(
    org_id: str,
    key_id: str,
    org_ctx: OrganizationContext = Depends(require_permission("api-key", "revoke")),
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
) -> dict[str, bool]:
    """Revoke an API key."""
    try:
        await use_case.revoke_api_key(
            RevokeApiKeyCommand(
                api_key_id=key_id,
                revoked_by=org_ctx.user_id,
            )
        )
        return {"success": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Internal Endpoints (service-to-service only, no user auth)
# =============================================================================

internal_router = APIRouter(prefix="/internal/v1/organizations", tags=["internal"])


class UpdateSettingsRequest(BaseModel):
    """Provider-neutral internal organization settings update."""
    settings_patch: dict[str, Any]


@internal_router.get("/{org_id}/lifecycle", response_model=OrganizationLifecycleResponse, response_model_exclude_none=True)
async def get_internal_organization_lifecycle(
    org_id: str,
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationLifecycleResponse:
    """Return lifecycle metadata to trusted service-to-service callers."""
    org = await use_case.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _org_to_lifecycle_response(org)


@internal_router.patch("/{org_id}/settings")
async def update_organization_settings(
    org_id: str,
    body: UpdateSettingsRequest,
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> dict:
    """Update non-secret organization settings for trusted internal services."""
    org = await use_case.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org.update_settings(body.settings_patch)
    await use_case.organization_repo.save(org)
    return {"organization_id": org_id, "updated": True}


# =============================================================================
# Response Helpers
# =============================================================================

def _normalize_dashboard_environment(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _DASHBOARD_ENVIRONMENTS else None


def _member_dashboard_summary(member) -> dict[str, Any]:
    return {
        "id": str(member.id),
        "user_id": str(member.user_id) if member.user_id else None,
        "email": member.email,
        "roles": [
            {
                "id": role.id,
                "name": role.name,
                "display_name": role.display_name,
            }
            for role in member.roles
        ],
        "status": member.status.value,
        "is_owner": member.is_owner,
        "has_org_console_access": member.has_org_console_access,
        "joined_at": member.joined_at.isoformat() if member.joined_at else None,
        "invited_at": member.invited_at.isoformat() if member.invited_at else None,
    }


def _role_distribution(members: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {
        "admin": 0,
        "developer": 0,
        "operator": 0,
    }
    role_aliases = {
        "owner": "admin",
        "admin": "admin",
        "access_admin": "admin",
        "developer": "developer",
        "access_developer": "developer",
        "operator": "operator",
        "access_operator": "operator",
    }

    for member in members:
        seen_buckets: set[str] = set()
        for role in member.roles:
            role_name = str(role.name or "").strip().lower()
            bucket = role_aliases.get(role_name, role_name)
            if not bucket:
                continue
            if bucket in seen_buckets:
                continue
            counts[bucket] = counts.get(bucket, 0) + 1
            seen_buckets.add(bucket)
    return counts


def _membership_to_summary(member) -> dict[str, Any] | None:
    if member is None:
        return None

    return {
        "id": str(member.id),
        "organization_id": str(member.organization_id),
        "user_id": str(member.user_id) if member.user_id else None,
        "email": member.email,
        "roles": [
            {
                "id": role.id,
                "name": role.name,
                "display_name": role.display_name,
            }
            for role in member.roles
        ],
        "status": member.status.value,
        "permissions": sorted(member.effective_permissions),
        "has_org_console_access": member.has_org_console_access,
        "is_owner": member.is_owner,
        "joined_at": member.joined_at.isoformat() if member.joined_at else None,
    }


def _org_to_response(org, membership=None) -> OrganizationResponse:
    return OrganizationResponse(
        id=str(org.id),
        name=org.name,
        display_name=org.display_name,
        description=org.description,
        join_code=org.join_code,
        visibility=org.visibility,
        owner_id=org.owner_id,
        status=org.status.value,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat() if org.updated_at else None,
        membership=_membership_to_summary(membership),
    )


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _org_to_lifecycle_response(org) -> OrganizationLifecycleResponse:
    settings = org.settings or {}
    compliance_profiles = settings.get("compliance_profiles") or []
    if not isinstance(compliance_profiles, list):
        compliance_profiles = []

    hosted_pilot_enabled = bool(settings.get("pilot_retention_enabled"))
    retention_days = _coerce_positive_int(settings.get("pilot_retention_days"), 30)
    data_retention_mode = "hosted_pilot_rolling_purge" if hosted_pilot_enabled else str(settings.get("data_retention_mode") or "standard")
    audit_retention_days = _coerce_positive_int(
        settings.get("audit_retention_days") if hosted_pilot_enabled or data_retention_mode != "standard" else None,
        retention_days if hosted_pilot_enabled else 90,
    )

    pilot_retention = None
    if hosted_pilot_enabled:
        pilot_retention = PilotRetentionResponse(
            enabled=True,
            window_days=retention_days,
            scope_summary=(
                f"Hosted Pilot data older than {retention_days} days is purge-eligible while admin access and deployment settings stay available."
            ),
            scope_items=[
                "Applications and uploaded evidence",
                "Issuance transactions and linked issued credentials",
                "Authorization sessions",
                "Issuance lifecycle events",
            ],
            access_behavior="Purge affects retained pilot data only. Organization access, configuration, and API setup remain available.",
            last_purged_at=settings.get("pilot_retention_last_purged_at"),
        )

    return OrganizationLifecycleResponse(
        created_at=org.created_at.isoformat(),
        compliance_profiles=[str(item) for item in compliance_profiles if item],
        data_retention_mode=data_retention_mode,
        audit_retention_days=audit_retention_days,
        pilot_retention=pilot_retention,
    )


def _member_to_response(member) -> MemberResponse:
    return MemberResponse(
        id=str(member.id),
        organization_id=str(member.organization_id),
        user_id=str(member.user_id) if member.user_id else None,
        email=member.email,
        roles=[
            RoleSummaryResponse(
                id=role.id,
                name=role.name,
                display_name=role.display_name,
            )
            for role in member.roles
        ],
        status=member.status.value,
        permissions=sorted(member.effective_permissions),
        has_org_console_access=member.has_org_console_access,
        is_owner=member.is_owner,
        invited_at=member.invited_at.isoformat() if member.invited_at else None,
        joined_at=member.joined_at.isoformat() if member.joined_at else None,
    )


def _api_key_to_response(api_key) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=str(api_key.id),
        organization_id=str(api_key.organization_id),
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        scope_type=api_key.scope_type,
        deployment_profile_id=str(api_key.deployment_profile_id) if api_key.deployment_profile_id else None,
        scopes=api_key.scopes,
        enabled=api_key.enabled,
        last_used_at=api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        created_at=api_key.created_at.isoformat(),
        updated_at=api_key.updated_at.isoformat() if api_key.updated_at else None,
    )
