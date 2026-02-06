"""
Organization Service HTTP Adapter (FastAPI)

FastAPI router providing the HTTP API for the Organization service.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr

from ...application.ports import (
    CreateApiKeyCommand,
    CreateOrganizationCommand,
    InviteMemberCommand,
    RevokeApiKeyCommand,
    UpdateMemberRoleCommand,
    UpdateOrganizationCommand,
)
from ...application.use_cases import ApiKeyUseCase, MemberUseCase, OrganizationUseCase
from ...domain.entities import MemberRole, OrganizationType

logger = logging.getLogger(__name__)

# Create router with versioned prefix
router = APIRouter(prefix="/v1/organizations", tags=["organizations"])


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
    slug: str
    description: str | None
    org_type: str
    status: str
    contact_email: str | None
    contact_phone: str | None
    website: str | None
    created_at: str
    updated_at: str


class InviteMemberRequest(BaseModel):
    """Request to invite a member."""
    email: EmailStr
    role: str = "member"


class MemberResponse(BaseModel):
    """Member response."""
    id: str
    organization_id: str
    user_id: str | None
    email: str | None
    role: str
    status: str
    invited_at: str | None
    joined_at: str | None


class UpdateMemberRequest(BaseModel):
    """Request to update member role."""
    role: str


class CreateApiKeyRequest(BaseModel):
    """Request to create an API key."""
    name: str
    description: str | None = None
    scopes: list[str] | None = None
    is_test: bool = False


class ApiKeyResponse(BaseModel):
    """API key response."""
    id: str
    name: str
    description: str | None
    key_prefix: str
    scopes: list[str]
    status: str
    last_used_at: str | None
    expires_at: str | None
    created_at: str


class ApiKeyCreatedResponse(ApiKeyResponse):
    """API key response with raw key (only at creation)."""
    key: str  # Only returned once!


# =============================================================================
# Dependencies
# =============================================================================

_organization_use_case: OrganizationUseCase | None = None
_member_use_case: MemberUseCase | None = None
_api_key_use_case: ApiKeyUseCase | None = None


def configure_org_router(
    organization_use_case: OrganizationUseCase,
    member_use_case: MemberUseCase,
    api_key_use_case: ApiKeyUseCase,
) -> None:
    """Configure router with use cases."""
    global _organization_use_case, _member_use_case, _api_key_use_case
    _organization_use_case = organization_use_case
    _member_use_case = member_use_case
    _api_key_use_case = api_key_use_case


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


# Placeholder for auth - will be replaced with actual middleware
async def get_current_user_id() -> str:
    """Get current user ID from auth context."""
    # This should be injected from auth middleware
    return "current-user-id"


# =============================================================================
# Organization Endpoints
# =============================================================================

@router.post("", response_model=OrganizationResponse)
async def create_organization(
    request: CreateOrganizationRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationResponse:
    """Create a new organization."""
    try:
        org = await use_case.create_organization(
            CreateOrganizationCommand(
                name=request.name,
                owner_id=user_id,
                org_type=OrganizationType(request.org_type),
                display_name=request.display_name,
                description=request.description,
                contact_email=request.contact_email,
            )
        )
        return _org_to_response(org)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> list[OrganizationResponse]:
    """List all organizations."""
    orgs = await use_case.list_organizations(limit=limit, offset=offset)
    return [_org_to_response(org) for org in orgs]


@router.get("/mine", response_model=list[OrganizationResponse])
async def get_my_organizations(
    user_id: str = Depends(get_current_user_id),
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> list[OrganizationResponse]:
    """Get organizations the current user belongs to."""
    orgs = await use_case.get_user_organizations(user_id)
    return [_org_to_response(org) for org in orgs]


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    use_case: OrganizationUseCase = Depends(get_org_use_case),
) -> OrganizationResponse:
    """Get an organization by ID."""
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



@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    request: UpdateOrganizationRequest,
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
# Member Endpoints
# =============================================================================

@router.get("/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    org_id: str,
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> list[MemberResponse]:
    """List all members of an organization."""
    members = await use_case.list_members(org_id)
    return [_member_to_response(m) for m in members]


@router.post("/{org_id}/members", response_model=MemberResponse)
async def invite_member(
    org_id: str,
    request: InviteMemberRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> MemberResponse:
    """Invite a new member to an organization."""
    try:
        member = await use_case.invite_member(
            InviteMemberCommand(
                organization_id=org_id,
                email=request.email,
                role=MemberRole(request.role),
                invited_by=user_id,
            )
        )
        return _member_to_response(member)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/{org_id}/members/{member_id}", response_model=MemberResponse)
async def update_member(
    org_id: str,
    member_id: str,
    request: UpdateMemberRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> MemberResponse:
    """Update a member's role."""
    try:
        member = await use_case.update_role(
            UpdateMemberRoleCommand(
                member_id=member_id,
                new_role=MemberRole(request.role),
                updated_by=user_id,
            )
        )
        return _member_to_response(member)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{org_id}/members/{member_id}")
async def remove_member(
    org_id: str,
    member_id: str,
    user_id: str = Depends(get_current_user_id),
    use_case: MemberUseCase = Depends(get_member_use_case),
) -> dict[str, bool]:
    """Remove a member from an organization."""
    try:
        await use_case.remove_member(member_id, user_id)
        return {"success": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# API Key Endpoints
# =============================================================================

@router.get("/{org_id}/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    org_id: str,
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
) -> list[ApiKeyResponse]:
    """List all API keys for an organization."""
    keys = await use_case.list_api_keys(org_id)
    return [_api_key_to_response(k) for k in keys]


@router.post("/{org_id}/api-keys", response_model=ApiKeyCreatedResponse)
async def create_api_key(
    org_id: str,
    request: CreateApiKeyRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
) -> ApiKeyCreatedResponse:
    """
    Create a new API key.
    
    ⚠️ The key value is only returned once. Store it securely!
    """
    try:
        api_key, raw_key = await use_case.create_api_key(
            CreateApiKeyCommand(
                organization_id=org_id,
                name=request.name,
                created_by=user_id,
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
    user_id: str = Depends(get_current_user_id),
    use_case: ApiKeyUseCase = Depends(get_api_key_use_case),
) -> dict[str, bool]:
    """Revoke an API key."""
    try:
        await use_case.revoke_api_key(
            RevokeApiKeyCommand(
                api_key_id=key_id,
                revoked_by=user_id,
            )
        )
        return {"success": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# Response Helpers
# =============================================================================

def _org_to_response(org) -> OrganizationResponse:
    return OrganizationResponse(
        id=str(org.id),
        name=org.name,
        display_name=org.display_name,
        slug=org.slug,
        description=org.description,
        org_type=org.org_type.value,
        status=org.status.value,
        contact_email=org.contact_email,
        contact_phone=org.contact_phone,
        website=org.website,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )


def _member_to_response(member) -> MemberResponse:
    return MemberResponse(
        id=str(member.id),
        organization_id=str(member.organization_id),
        user_id=str(member.user_id) if member.user_id else None,
        email=member.email,
        role=member.role.value,
        status=member.status.value,
        invited_at=member.invited_at.isoformat() if member.invited_at else None,
        joined_at=member.joined_at.isoformat() if member.joined_at else None,
    )


def _api_key_to_response(api_key) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        status=api_key.status.value,
        last_used_at=api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        created_at=api_key.created_at.isoformat(),
    )
