"""
Onboarding API Router

Handles post-registration user onboarding:
- GET /api/onboarding/status - Check if user needs onboarding
- GET /api/onboarding/organizations - List discoverable vendor organizations
- POST /api/onboarding/join-with-code - Join organization using invite code
- POST /api/onboarding/request-membership - Request to join an organization
- POST /api/onboarding/complete - Complete onboarding with role/org selection
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from subscription.models import (
    Organization,
    OrganizationInvitation,
    OrganizationMember,
    MembershipMode,
    MemberRole,
    MembershipRequest,
    MembershipRequestStatus,
    AuditEventType,
)
from subscription.database import get_db_session
from .config import AuthConfig
from .router import get_session_manager
from .keycloak_admin import KeycloakAdminClient, get_keycloak_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


# =============================================================================
# Request/Response Models
# =============================================================================


class OnboardingStatusResponse(BaseModel):
    """Onboarding status response."""
    
    needs_onboarding: bool
    user_type: str | None = None
    organization_id: str | None = None
    organization_name: str | None = None
    completed_at: str | None = None
    pending_request: dict | None = None  # If user has a pending membership request


class OrganizationInfo(BaseModel):
    """Organization info for listing."""
    
    id: str
    name: str
    description: str | None = None
    member_count: int = 0
    membership_mode: str = "invite_only"  # invite_only, approval, open
    is_discoverable: bool = True


class OrganizationsListResponse(BaseModel):
    """List of available organizations."""
    
    organizations: list[OrganizationInfo]


class JoinWithCodeRequest(BaseModel):
    """Request to join organization with invite code."""
    
    invite_code: str = Field(..., description="The invitation code provided by the organization")


class JoinWithCodeResponse(BaseModel):
    """Response after joining with invite code."""
    
    success: bool
    organization_id: str | None = None
    organization_name: str | None = None
    message: str


class RequestMembershipRequest(BaseModel):
    """Request to join an organization that requires approval."""
    
    organization_id: str = Field(..., description="Organization ID to request membership for")
    message: str | None = Field(None, description="Optional message to include with request")


class RequestMembershipResponse(BaseModel):
    """Response after submitting membership request."""
    
    success: bool
    request_id: str | None = None
    organization_name: str | None = None
    message: str


class CompleteOnboardingRequest(BaseModel):
    """Request to complete onboarding."""
    
    user_type: str = Field(..., description="User type: 'applicant' or 'vendor'")
    organization_id: str | None = Field(
        None, 
        description="Organization ID to associate with (for applicants selecting open org)"
    )
    # Vendor new organization fields
    organization_name: str | None = Field(
        None,
        description="Name for new organization (required for vendors creating new org)"
    )
    organization_description: str | None = Field(
        None,
        description="Description for new organization"
    )
    # New organization settings (for vendors creating org)
    is_discoverable: bool = Field(
        False,
        description="Whether organization should appear in public listings"
    )
    membership_mode: Literal["invite_only", "approval", "open"] = Field(
        "invite_only",
        description="How users can join: invite_only, approval (request), or open"
    )
    # Trust profile selection (for vendors)
    trust_framework_codes: list[str] | None = Field(
        None,
        description="Trust framework codes: icao, aamva, eudi, or custom (for vendors). Can select multiple."
    )
    # Explicit confirmation
    confirm_organization: bool = Field(
        False,
        description="User explicitly confirms they want to join this organization"
    )


class CompleteOnboardingResponse(BaseModel):
    """Response after completing onboarding."""
    
    success: bool
    user_type: str
    organization_id: str | None = None
    organization_name: str | None = None
    membership_status: str | None = None  # joined, pending_approval, none
    invite_code: str | None = None  # For vendors, their org's invite code
    message: str


# =============================================================================
# Organization Settings Storage (Database-backed)
# =============================================================================


async def get_org_settings(org_id: str, db: AsyncSession) -> dict:
    """Get organization settings from database."""
    result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = result.scalar_one_or_none()
    
    if not org:
        return {
            "is_discoverable": False,
            "membership_mode": "invite_only",
            "invite_code": None,
        }
    
    # Get the first active reusable invite code if any
    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.organization_id == org_id,
            OrganizationInvitation.is_reusable == True,
            OrganizationInvitation.is_active == True,
        ).limit(1)
    )
    invitation = result.scalar_one_or_none()
    
    return {
        "is_discoverable": org.is_discoverable,
        "membership_mode": org.membership_mode.value if org.membership_mode else "invite_only",
        "invite_code": invitation.code if invitation else None,
    }


def merge_org_claim(
    current_claim: Any,
    org_id: str | None,
    org_name: str | None,
) -> dict[str, Any]:
    """Merge an org into the Keycloak organization claim shape."""
    claim = current_claim if isinstance(current_claim, dict) else {}
    updated = dict(claim)
    if org_id:
        updated[org_id] = {"name": org_name or ""}
    return updated


async def set_org_settings(org_id: str, settings: dict, db: AsyncSession) -> None:
    """Update or create organization settings in database.
    
    If the organization doesn't exist (e.g., was just created in Keycloak),
    this will create a new Organization record in the local database.
    """
    import re
    
    result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = result.scalar_one_or_none()
    
    if not org:
        # Create new organization record in local database
        # This happens when org was just created in Keycloak
        org_name = settings.get("name", f"org-{org_id[:8]}")
        # Generate a slug from the name
        slug = re.sub(r'[^a-z0-9]+', '-', org_name.lower()).strip('-')
        # Ensure uniqueness by adding a suffix if needed
        slug = f"{slug}-{org_id[:8]}"
        
        org = Organization(
            id=org_id,
            name=org_name,
            slug=slug,
            is_active=True,
            is_discoverable=settings.get("is_discoverable", False),
            membership_mode=MembershipMode(settings.get("membership_mode", "invite_only")),
        )
        db.add(org)
        logger.info(f"Created local organization record: {org_id} ({org_name})")
    else:
        # Update existing organization
        if "is_discoverable" in settings:
            org.is_discoverable = settings["is_discoverable"]
        
        if "membership_mode" in settings:
            mode_value = settings["membership_mode"]
            if isinstance(mode_value, str):
                org.membership_mode = MembershipMode(mode_value)
            else:
                org.membership_mode = mode_value
    
    await db.commit()


async def generate_invite_code(org_id: str, db: AsyncSession, created_by: str | None = None) -> str:
    """Generate a new invite code for an organization."""
    # Deactivate any existing reusable codes
    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.organization_id == org_id,
            OrganizationInvitation.is_reusable == True,
            OrganizationInvitation.is_active == True,
        )
    )
    existing = result.scalars().all()
    for inv in existing:
        inv.is_active = False
    
    # Generate new code (8 characters, alphanumeric)
    new_code = secrets.token_urlsafe(6).upper()[:8]
    
    # Create new invitation
    invitation = OrganizationInvitation(
        id=str(uuid4()),
        organization_id=org_id,
        code=new_code,
        role=MemberRole.MEMBER,
        is_reusable=True,
        max_uses=None,  # Unlimited
        created_by=created_by,
    )
    
    db.add(invitation)
    await db.commit()
    
    return new_code


async def validate_invite_code(code: str, db: AsyncSession) -> str | None:
    """Validate an invite code and return the org_id if valid."""
    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.code == code.upper().strip(),
            OrganizationInvitation.is_active == True,
        )
    )
    invitation = result.scalar_one_or_none()
    
    if not invitation or not invitation.is_valid:
        return None
    
    return invitation.organization_id


async def use_invite_code(code: str, db: AsyncSession) -> bool:
    """Increment usage count for an invite code."""
    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.code == code.upper().strip(),
        )
    )
    invitation = result.scalar_one_or_none()
    
    if invitation:
        invitation.uses_count += 1
        await db.commit()
        return True
    return False


async def _create_organization_trust_profile(
    organization_id: str,
    framework_code: str,
    user_id: str,
    db: AsyncSession,
) -> None:
    """
    Store trust framework preference during onboarding.
    
    This saves the user's trust framework selection to organization settings.
    Actual trust configuration happens later in the Trust Registry UI.
    """
    from subscription.models import Organization
    
    # Get organization
    result = await db.execute(
        select(Organization).where(Organization.id == organization_id)
    )
    org = result.scalar_one_or_none()
    
    if not org:
        logger.warning(f"Organization '{organization_id}' not found - skipping profile creation")
        return
    
    # Store trust framework preference in org settings
    if not org.settings:
        org.settings = {}
    
    if 'trust_framework_preferences' not in org.settings:
        org.settings['trust_framework_preferences'] = []
    
    # Add framework code if not already present
    if framework_code not in org.settings['trust_framework_preferences']:
        org.settings['trust_framework_preferences'].append(framework_code)
    
    # Mark as updated (SQLAlchemy needs explicit flag for JSON column updates)
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(org, 'settings')
    
    await db.commit()
    
    logger.info(f"Stored trust framework preference for org {organization_id}: {framework_code}")


# =============================================================================
# Dependencies
# =============================================================================


async def get_current_user_id(request: Request) -> str:
    """Get current user ID from session."""
    config = AuthConfig.from_env()
    session_id = request.cookies.get(config.cookie.name)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session_manager = await get_session_manager()
    session = await session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    return session.user_id


async def get_session_data(request: Request) -> dict[str, Any]:
    """Get full session data using the session cookie."""
    config = AuthConfig.from_env()
    session_id = request.cookies.get(config.cookie.name)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session_manager = await get_session_manager()
    session = await session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")

    attributes = session.attributes or {}
    return {
        "user_id": session.user_id,
        **attributes,
        "_session_id": session_id,
    }


async def update_session_attributes(session_id: str, updates: dict[str, Any]) -> None:
    """Update session attributes in Redis."""
    if not session_id:
        return
    session_manager = await get_session_manager()
    session = await session_manager.get_session(session_id)
    if not session:
        return
    session.attributes.update({k: v for k, v in updates.items() if v is not None})
    await session_manager.update_session(session)


async def auto_accept_email_invites(
    *,
    user_id: str,
    user_email: str,
    session_id: str | None,
    keycloak: KeycloakAdminClient,
    db: AsyncSession,
    existing_org_claim: Any = None,
) -> tuple[str | None, str | None, dict[str, Any]]:
    """Auto-accept active email invitations for the user."""
    if not user_email:
        return None, None, merge_org_claim(existing_org_claim, None, None)

    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.email == user_email,
            OrganizationInvitation.is_active == True,
        )
    )
    invitations = [inv for inv in result.scalars().all() if inv.is_valid]
    if not invitations:
        return None, None, merge_org_claim(existing_org_claim, None, None)

    primary_org_id = None
    primary_org_name = None
    org_claim = merge_org_claim(existing_org_claim, None, None)

    for invitation in invitations:
        org_id = invitation.organization_id
        org = await keycloak.get_organization(org_id)
        if not org:
            continue

        org_name = org.get("name", "Unknown")
        org_claim = merge_org_claim(session.get("organization"), org_id, org_name)
        org_claim = merge_org_claim(session.get("organization"), org_id, org_name)
        await keycloak.add_user_to_organization(org_id, user_id)
        org_claim = merge_org_claim(org_claim, org_id, org_name)

        invitation.uses_count += 1
        if not invitation.is_reusable:
            invitation.is_active = False
        if invitation.max_uses and invitation.uses_count >= invitation.max_uses:
            invitation.is_active = False

        if not primary_org_id:
            primary_org_id = org_id
            primary_org_name = org_name

    await db.commit()

    if primary_org_id:
        attributes = {
            "organization_id": [primary_org_id],
            "organization_name": [primary_org_name or ""],
            "joined_via": ["email_invite"],
            "onboarding_completed": [datetime.utcnow().isoformat()],
        }
        await keycloak.update_user_attributes(user_id, attributes)
        await update_session_attributes(
            session_id,
            {
                "organization_id": primary_org_id,
                "organization_name": primary_org_name,
                "onboarding_completed": datetime.utcnow().isoformat(),
                "organization": org_claim,
            },
        )

    return primary_org_id, primary_org_name, org_claim


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/status", response_model=OnboardingStatusResponse)
async def get_onboarding_status(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> OnboardingStatusResponse:
    """
    Check if the current user needs onboarding.
    
    Uses session data stored during login - no Keycloak admin API calls needed.
    
    A user needs onboarding if:
    - They don't have an 'onboarding_completed' attribute
    - They have the default 'applicant' user_type
    """
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    user_type = session.get("user_type", "applicant")
    
    # Check for pending membership request in database
    pending_request = None
    try:
        result = await db.execute(
            select(MembershipRequest, Organization).join(
                Organization,
                Organization.id == MembershipRequest.organization_id
            ).where(
                MembershipRequest.user_id == user_id,
                MembershipRequest.status == MembershipRequestStatus.PENDING
            ).limit(1)
        )
        row = result.first()
        if row:
            req, org = row
            pending_request = {
                "request_id": req.id,
                "organization_id": req.organization_id,
                "organization_name": org.name,
                "submitted_at": req.created_at.isoformat(),
            }
    except Exception as e:
        logger.warning(f"Error checking pending membership requests: {e}")
    
    try:
        # Check onboarding status from session attributes (set during login)
        onboarding_completed = session.get("onboarding_completed")
        organization_id = session.get("organization_id")
        organization_name = session.get("organization_name")
        roles = session.get("roles", [])
        is_admin = "administrator" in roles or user_type == "administrator"
        is_vendor = "vendor" in roles or user_type == "vendor"
        resolved_user_type = "administrator" if is_admin else "vendor" if is_vendor else user_type

        # Auto-accept email invites for applicants without an org
        if not organization_id and user_type == "applicant":
            org_id, org_name, _org_claim = await auto_accept_email_invites(
                user_id=user_id,
                user_email=user_email,
                session_id=session.get("_session_id"),
                keycloak=keycloak,
                db=db,
                existing_org_claim=session.get("organization"),
            )
            if org_id:
                organization_id = org_id
                organization_name = org_name
                onboarding_completed = onboarding_completed or datetime.utcnow().isoformat()
        
        if onboarding_completed:
            return OnboardingStatusResponse(
                needs_onboarding=False,
                user_type=resolved_user_type,
                organization_id=organization_id,
                organization_name=organization_name,
                completed_at=onboarding_completed,
                pending_request=pending_request,
            )
        
        if is_admin:
            return OnboardingStatusResponse(
                needs_onboarding=False,
                user_type="administrator",
                organization_id=organization_id,
                organization_name=organization_name,
                pending_request=pending_request,
            )

        if is_vendor:
            return OnboardingStatusResponse(
                needs_onboarding=True,
                user_type="vendor",
                organization_id=organization_id,
                organization_name=organization_name,
                pending_request=pending_request,
            )
        
        # New users without onboarding_completed need onboarding
        return OnboardingStatusResponse(
            needs_onboarding=True,
            user_type=resolved_user_type,
            organization_id=organization_id,
            organization_name=organization_name,
            pending_request=pending_request,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking onboarding status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check onboarding status")


class SetIntentRequest(BaseModel):
    """Request to set user's role intent."""
    
    intent: Literal["apply_for_credentials", "manage_credentials"] = Field(
        ...,
        description="User's intent: apply_for_credentials (applicant) or manage_credentials (future vendor/issuer)"
    )


class SetIntentResponse(BaseModel):
    """Response after setting role intent."""
    
    success: bool
    intent: str
    message: str


@router.post("/set-intent", response_model=SetIntentResponse)
async def set_role_intent(
    body: SetIntentRequest,
    request: Request,
) -> SetIntentResponse:
    """
    Set the user's role intent preference.
    
    This helps route users to appropriate experiences:
    - "apply_for_credentials": Standard applicant flow (apply for documents)
    - "manage_credentials": Indicates potential future vendor/issuer (may become credential manager)
    
    The intent is stored in the session and can be used for personalization,
    analytics, and onboarding flow decisions.
    """
    try:
        session = await get_session_data(request)
        session_id = session.get("_session_id")
        
        if not session_id:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        # Store intent in session
        await update_session_attributes(
            session_id,
            {
                "role_intent": body.intent,
                "role_intent_set_at": datetime.utcnow().isoformat(),
            },
        )
        
        logger.info(f"User {session.get('user_id')} set role intent: {body.intent}")
        
        return SetIntentResponse(
            success=True,
            intent=body.intent,
            message=f"Role intent set to: {body.intent}",
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting role intent: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to set role intent")


@router.get("/organizations", response_model=OrganizationsListResponse)
async def list_organizations(
    user_id: str = Depends(get_current_user_id),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
    search: str | None = None,
    category: str | None = None,
    membership_mode: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> OrganizationsListResponse:
    """
    List discoverable vendor organizations.
    
    Only returns organizations that are:
    - Enabled
    - Marked as discoverable
    
    Optional filters:
    - search: Search in organization name and description
    - category: Filter by category tag
    - membership_mode: Filter by membership mode (open, approval, invite_only)
    - page: Page number (default 1)
    - page_size: Results per page (default 50, max 100)
    """
    try:
        # Validate pagination params
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        
        orgs = await keycloak.list_organizations()
        
        org_list = []
        for org in orgs:
            if not org.get("enabled", True):
                continue
            
            org_id = org["id"]
            settings = await get_org_settings(org_id, db)
            
            # Only show discoverable organizations
            if not settings.get("is_discoverable", False):
                continue
            
            org_name = org.get("name", "Unknown")
            org_description = org.get("description")
            org_membership_mode = settings.get("membership_mode", "invite_only")
            
            # Get categories from settings
            org_categories = settings.get("categories", [])
            if not isinstance(org_categories, list):
                org_categories = []
            
            # Apply search filter
            if search:
                search_lower = search.lower()
                name_match = search_lower in org_name.lower()
                desc_match = org_description and search_lower in org_description.lower()
                if not (name_match or desc_match):
                    continue
            
            # Apply category filter
            if category and category not in org_categories:
                continue
            
            # Apply membership mode filter
            if membership_mode and org_membership_mode != membership_mode:
                continue
            
            # Get member count
            try:
                members = await keycloak.get_organization_members(org_id)
                member_count = len(members)
            except Exception:
                member_count = 0
            
            org_list.append(OrganizationInfo(
                id=org_id,
                name=org_name,
                description=org_description,
                member_count=member_count,
                membership_mode=org_membership_mode,
                is_discoverable=True,
                categories=org_categories,
            ))
        
        # Apply pagination
        total = len(org_list)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_orgs = org_list[start_idx:end_idx]
        
        return OrganizationsListResponse(
            organizations=paginated_orgs,
            total=total,
            page=page,
            page_size=page_size,
        )
        
    except Exception as e:
        logger.error(f"Error listing organizations: {e}")
        raise HTTPException(status_code=500, detail="Failed to list organizations")


@router.post("/join-with-code", response_model=JoinWithCodeResponse)
async def join_with_invite_code(
    request_data: JoinWithCodeRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> JoinWithCodeResponse:
    """
    Join an organization using an invite code.
    
    This allows users to join organizations that aren't discoverable
    or that require a code even if they allow requests.
    """
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    session_id = session.get("_session_id")
    
    # Validate the invite code
    org_id = await validate_invite_code(request_data.invite_code, db)
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invite code. Please check the code and try again."
        )
    
    try:
        # Get organization info
        org = await keycloak.get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        org_name = org.get("name", "Unknown")
        
        # Add user to organization in Keycloak
        await keycloak.add_user_to_organization(org_id, user_id)
        
        # Update user attributes
        attributes = {
            "organization_id": [org_id],
            "organization_name": [org_name],
            "joined_via": ["invite_code"],
            "onboarding_completed": [datetime.utcnow().isoformat()],
        }
        await keycloak.update_user_attributes(user_id, attributes)
        await use_invite_code(request_data.invite_code, db)
        await update_session_attributes(
            session_id,
            {
                "organization_id": org_id,
                "organization_name": org_name,
                "onboarding_completed": datetime.utcnow().isoformat(),
                "organization": org_claim,
            },
        )
        
        logger.info(f"User {user_email} joined organization {org_name} via invite code")
        
        return JoinWithCodeResponse(
            success=True,
            organization_id=org_id,
            organization_name=org_name,
            message=f"Successfully joined {org_name}!",
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error joining with invite code: {e}")
        raise HTTPException(status_code=500, detail="Failed to join organization")


@router.post("/request-membership", response_model=RequestMembershipResponse)
async def request_membership(
    request_data: RequestMembershipRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> RequestMembershipResponse:
    """
    Request to join an organization that requires approval.
    
    Creates a pending membership request that org admins can review.
    """
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    
    org_id = request_data.organization_id
    settings = await get_org_settings(org_id, db)
    
    # Check if org allows membership requests
    if settings.get("membership_mode") == "invite_only":
        raise HTTPException(
            status_code=400,
            detail="This organization only accepts members via invitation. "
                   "Please contact the organization administrator."
        )
    
    # Check for existing pending request in database
    result = await db.execute(
        select(MembershipRequest).where(
            MembershipRequest.user_id == user_id,
            MembershipRequest.organization_id == org_id,
            MembershipRequest.status == MembershipRequestStatus.PENDING
        )
    )
    existing_request = result.scalar_one_or_none()
    if existing_request:
        raise HTTPException(
            status_code=400,
            detail="You already have a pending request for this organization."
        )
    
    try:
        # Get organization info
        org = await keycloak.get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        org_name = org.get("name", "Unknown")
        
        # If org is open, join directly
        if settings.get("membership_mode") == "open":
            await keycloak.add_user_to_organization(org_id, user_id)
            
            attributes = {
                "organization_id": [org_id],
                "organization_name": [org_name],
                "joined_via": ["open_join"],
            }
            await keycloak.update_user_attributes(user_id, attributes)
            
            return RequestMembershipResponse(
                success=True,
                request_id=None,
                organization_name=org_name,
                message=f"You have joined {org_name}!",
            )
        
        # Create membership request in database for approval-required orgs
        new_request = MembershipRequest(
            id=str(uuid4()),
            organization_id=org_id,
            user_id=user_id,
            user_email=user_email,
            message=request_data.message,
            status=MembershipRequestStatus.PENDING,
        )
        db.add(new_request)
        await db.commit()
        
        request_id = new_request.id
        logger.info(f"User {user_email} requested membership to {org_name}")
        
        return RequestMembershipResponse(
            success=True,
            request_id=request_id,
            organization_name=org_name,
            message=f"Your request to join {org_name} has been submitted. "
                    "You'll be notified when an administrator reviews your request.",
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error requesting membership: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit membership request")


@router.post("/complete", response_model=CompleteOnboardingResponse)
async def complete_onboarding(
    request_data: CompleteOnboardingRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> CompleteOnboardingResponse:
    """
    Complete the onboarding process.
    
    For applicants:
    - Optionally associate with a vendor organization (if open/approval mode)
    - Keep the 'applicant' role
    
    For vendors:
    - Switch role from 'applicant' to 'vendor'
    - Create new organization with specified settings
    - Set as organization owner
    """
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    session_id = session.get("_session_id")
    
    if request_data.user_type not in ("applicant", "vendor"):
        raise HTTPException(
            status_code=400, 
            detail="Invalid user type. Must be 'applicant' or 'vendor'"
        )
    
    try:
        org_id = None
        org_name = None
        membership_status = "none"
        invite_code = None
        
        if request_data.user_type == "vendor":
            # Vendor flow: create or complete organization setup
            if request_data.organization_id:
                org_id = request_data.organization_id
                session_org_id = session.get("organization_id")
                
                # DEBUG: Log authorization check details
                logger.info(f"🔍 Authorization check for org resume:")
                logger.info(f"  - Requested org_id: {org_id}")
                logger.info(f"  - Session org_id: {session_org_id}")
                logger.info(f"  - User ID: {user_id}")
                logger.info(f"  - Session has onboarding_completed: {session.get('onboarding_completed') is not None}")
                
                # Check authorization: allow if session org_id matches
                if session_org_id and session_org_id != org_id:
                    logger.warning(f"❌ Session org mismatch: {session_org_id} != {org_id}")
                    raise HTTPException(
                        status_code=403,
                        detail="Not authorized for this organization.",
                    )
                
                # Verify user is a member of this organization via Keycloak
                try:
                    user_orgs = await keycloak.get_user_organizations(user_id)
                    user_org_ids = [org["id"] for org in user_orgs if org.get("id")]
                    
                    logger.info(f"  - Keycloak user orgs: {user_org_ids}")
                    logger.info(f"  - Is member via Keycloak: {org_id in user_org_ids}")
                    logger.info(f"  - Session match allows: {session_org_id == org_id}")
                    
                    # Allow if user is a member OR if session_org_id matches (resuming onboarding)
                    if org_id not in user_org_ids and session_org_id != org_id:
                        logger.warning(f"❌ Not a member and session doesn't match")
                        raise HTTPException(
                            status_code=403,
                            detail="Not authorized for this organization.",
                        )
                    
                    logger.info(f"✅ Authorization passed")
                        
                except Exception as e:
                    logger.error(f"⚠️ Keycloak membership check failed: {e}")
                    # If we can't check org membership, fall back to session check
                    if not session_org_id or session_org_id != org_id:
                        logger.warning(f"❌ Fallback: session check failed")
                        raise HTTPException(
                            status_code=403,
                            detail="Not authorized for this organization.",
                        )
                    logger.info(f"✅ Authorization passed (fallback to session)")

                org = await keycloak.get_organization(org_id)
                if not org:
                    raise HTTPException(status_code=404, detail="Organization not found")

                org_name = org.get("name", "Unknown")

                await set_org_settings(
                    org_id,
                    {
                        "name": org_name,
                        "is_discoverable": request_data.is_discoverable,
                        "membership_mode": request_data.membership_mode,
                        "updated_by": user_id,
                        "updated_at": datetime.utcnow().isoformat(),
                    },
                    db,
                )

                settings = await get_org_settings(org_id, db)
                invite_code = settings.get("invite_code")
                if not invite_code:
                    invite_code = await generate_invite_code(org_id, db, created_by=user_id)

                await keycloak.add_user_to_organization(org_id, user_id)
                membership_status = "owner"
            else:
                if not request_data.organization_name:
                    raise HTTPException(
                        status_code=400,
                        detail="Organization name is required"
                    )

                # Check if organization name is available
                is_available = await keycloak.check_organization_name_available(
                    request_data.organization_name
                )
                if not is_available:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Organization name '{request_data.organization_name}' is already taken. Please choose a different name."
                    )

                # Create new organization in Keycloak
                new_org = await keycloak.create_organization(
                    name=request_data.organization_name,
                    description=request_data.organization_description,
                )
                org_id = new_org.get("id")
                org_name = request_data.organization_name

                # Store organization settings (also create Organization record in local DB)
                await set_org_settings(org_id, {
                    "name": org_name,  # Needed for creating local DB record
                    "is_discoverable": request_data.is_discoverable,
                    "membership_mode": request_data.membership_mode,
                    "created_by": user_id,
                    "created_at": datetime.utcnow().isoformat(),
                }, db)

                # Generate invite code for the organization
                invite_code = await generate_invite_code(org_id, db, created_by=user_id)
                logger.info(f"Created org '{org_name}' with invite code: {invite_code}")

                # Create trust profile(s) for the organization if framework(s) selected
                if request_data.trust_framework_codes:
                    for framework_code in request_data.trust_framework_codes:
                        await _create_organization_trust_profile(
                            organization_id=org_id,
                            framework_code=framework_code,
                            user_id=user_id,
                            db=db,
                        )
                    logger.info(f"Created {len(request_data.trust_framework_codes)} trust profile(s): {', '.join(request_data.trust_framework_codes)}")

                # Add user to organization as owner
                await keycloak.add_user_to_organization(org_id, user_id)

                membership_status = "owner"

            # Update role from applicant to vendor if needed
            current_roles = session.get("roles", []) or []
            if "vendor" not in current_roles:
                await keycloak.add_user_role(user_id, "vendor")
            if "applicant" in current_roles:
                await keycloak.remove_user_role(user_id, "applicant")
            
        elif request_data.user_type == "applicant":
            # Applicant flow
            if request_data.organization_id:
                # Require explicit confirmation
                if not request_data.confirm_organization:
                    raise HTTPException(
                        status_code=400,
                        detail="Please confirm your organization selection"
                    )
                
                org_id = request_data.organization_id
                settings = await get_org_settings(org_id, db)
                
                # Get org info
                org = await keycloak.get_organization(org_id)
                if not org:
                    raise HTTPException(status_code=404, detail="Organization not found")
                org_name = org.get("name")
                
                membership_mode = settings.get("membership_mode", "invite_only")
                
                if membership_mode == "invite_only":
                    raise HTTPException(
                        status_code=400,
                        detail="This organization only accepts members via invitation. "
                               "Please use an invite code or contact the administrator."
                    )
                elif membership_mode == "open":
                    # Join directly
                    await keycloak.add_user_to_organization(org_id, user_id)
                    membership_status = "joined"
                elif membership_mode == "approval":
                    # Create membership request
                    request_id = str(uuid4())
                    _membership_requests[request_id] = {
                        "id": request_id,
                        "organization_id": org_id,
                        "organization_name": org_name,
                        "user_id": user_id,
                        "user_email": user_email,
                        "status": "pending",
                        "created_at": datetime.utcnow().isoformat(),
                    }
                    membership_status = "pending_approval"
        
        org_id_for_attributes = org_id
        org_name_for_attributes = org_name
        if request_data.user_type == "applicant" and membership_status == "pending_approval":
            org_id_for_attributes = None
            org_name_for_attributes = None

        # Update user attributes
        attributes = {
            "user_type": [request_data.user_type],
            "onboarding_completed": [datetime.utcnow().isoformat()],
        }
        if org_id_for_attributes:
            attributes["organization_id"] = [org_id_for_attributes]
        if org_name_for_attributes:
            attributes["organization_name"] = [org_name_for_attributes]
        
        await keycloak.update_user_attributes(user_id, attributes)
        
        updated_roles = None
        if request_data.user_type == "vendor":
            updated_roles = list({*(session.get("roles", []) or []), "vendor"} - {"applicant"})
        elif request_data.user_type == "applicant":
            updated_roles = list({*(session.get("roles", []) or []), "applicant"})

        org_claim = (
            merge_org_claim(session.get("organization"), org_id_for_attributes, org_name_for_attributes)
            if org_id_for_attributes
            else session.get("organization")
        )
        await update_session_attributes(
            session_id,
            {
                "user_type": request_data.user_type,
                "organization_id": org_id_for_attributes or None,
                "organization_name": org_name_for_attributes or None,
                "onboarding_completed": datetime.utcnow().isoformat(),
                "roles": updated_roles or session.get("roles", []),
                "organization": org_claim,
            },
        )
        
        # Build response message
        if request_data.user_type == "vendor":
            if request_data.organization_id:
                message = f"Organization setup complete. Your invite code is: {invite_code}"
            else:
                message = f"Welcome! Your organization '{org_name}' has been created. Your invite code is: {invite_code}"
        elif membership_status == "joined":
            message = f"Welcome! You've joined {org_name}."
        elif membership_status == "pending_approval":
            message = f"Your request to join {org_name} is pending approval."
        else:
            message = "Welcome! Your account has been set up."
        
        logger.info(
            f"Completed onboarding for {user_email}: "
            f"type={request_data.user_type}, org={org_name}, status={membership_status}"
        )
        
        return CompleteOnboardingResponse(
            success=True,
            user_type=request_data.user_type,
            organization_id=org_id,
            organization_name=org_name,
            membership_status=membership_status,
            invite_code=invite_code,
            message=message,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error completing onboarding: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to complete onboarding: {str(e)}")


# =============================================================================
# Organization Management Endpoints (for vendors)
# =============================================================================


@router.get("/check-organization-name")
async def check_organization_name_availability(
    name: str,
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
) -> dict[str, bool]:
    """Check if an organization name is available.
    
    Public endpoint - no authentication required.
    Used during onboarding to provide real-time feedback on name availability.
    """
    if not name or len(name.strip()) < 2:
        raise HTTPException(
            status_code=400,
            detail="Organization name must be at least 2 characters"
        )
    
    is_available = await keycloak.check_organization_name_available(name)
    
    return {"available": is_available}


class OrgSettingsResponse(BaseModel):
    """Organization settings response."""
    
    organization_id: str
    organization_name: str
    is_discoverable: bool
    membership_mode: str
    invite_code: str | None = None
    # Email domain configuration
    allowed_email_domains: list[str] = []
    domain_join_policy: str | None = "approval"  # "auto", "approval", "closed"
    default_role: str | None = "member"


class UpdateOrgSettingsRequest(BaseModel):
    """Request to update organization settings."""
    
    is_discoverable: bool | None = None
    membership_mode: Literal["invite_only", "approval", "open"] | None = None
    regenerate_invite_code: bool = False
    # Email domain configuration
    allowed_email_domains: list[str] | None = None
    domain_join_policy: Literal["auto", "approval", "closed"] | None = None
    default_role: str | None = None
    # Device security configuration
    require_device_registration: bool | None = None
    allow_push_notifications: bool | None = None
    device_registration_prompt: Literal["onboarding", "first_action", "never"] | None = None


@router.get("/org-settings", response_model=OrgSettingsResponse)
async def get_organization_settings(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> OrgSettingsResponse:
    """Get current organization settings (for vendors)."""
    user_id = session.get("user_id")
    
    # Get user's organization
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org = orgs[0]
    org_id = org["id"]
    settings = await get_org_settings(org_id, db)
    
    return OrgSettingsResponse(
        organization_id=org_id,
        organization_name=org.get("name", "Unknown"),
        is_discoverable=settings.get("is_discoverable", False),
        membership_mode=settings.get("membership_mode", "invite_only"),
        invite_code=settings.get("invite_code"),
        allowed_email_domains=settings.get("allowed_email_domains", []),
        domain_join_policy=settings.get("domain_join_policy", "approval"),
        default_role=settings.get("default_role", "member"),
        require_device_registration=settings.get("require_device_registration", False),
        allow_push_notifications=settings.get("allow_push_notifications", True),
        device_registration_prompt=settings.get("device_registration_prompt", "first_action"),
    )


@router.put("/org-settings", response_model=OrgSettingsResponse)
async def update_organization_settings(
    request_data: UpdateOrgSettingsRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> OrgSettingsResponse:
    """Update organization settings (for vendors)."""
    user_id = session.get("user_id")
    
    # Get user's organization
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org = orgs[0]
    org_id = org["id"]
    
    # Update settings
    current_settings = await get_org_settings(org_id, db)
    
    if request_data.is_discoverable is not None:
        current_settings["is_discoverable"] = request_data.is_discoverable
    
    if request_data.membership_mode is not None:
        current_settings["membership_mode"] = request_data.membership_mode
    
    if request_data.allowed_email_domains is not None:
        # Validate and clean domains
        cleaned_domains = [d.strip().lower() for d in request_data.allowed_email_domains if d.strip()]
        current_settings["allowed_email_domains"] = cleaned_domains
    
    if request_data.domain_join_policy is not None:
        current_settings["domain_join_policy"] = request_data.domain_join_policy
    
    if request_data.default_role is not None:
        current_settings["default_role"] = request_data.default_role
    
    # Device security settings
    if request_data.require_device_registration is not None:
        current_settings["require_device_registration"] = request_data.require_device_registration
    
    if request_data.allow_push_notifications is not None:
        current_settings["allow_push_notifications"] = request_data.allow_push_notifications
    
    if request_data.device_registration_prompt is not None:
        current_settings["device_registration_prompt"] = request_data.device_registration_prompt
    
    if request_data.regenerate_invite_code:
        await generate_invite_code(org_id, db, created_by=user_id)
        current_settings = await get_org_settings(org_id, db)  # Refresh to get new code
    
    await set_org_settings(org_id, current_settings, db)
    
    logger.info(f"Updated settings for organization {org.get('name')}")
    
    return OrgSettingsResponse(
        organization_id=org_id,
        organization_name=org.get("name", "Unknown"),
        is_discoverable=current_settings.get("is_discoverable", False),
        membership_mode=current_settings.get("membership_mode", "invite_only"),
        invite_code=current_settings.get("invite_code"),
        allowed_email_domains=current_settings.get("allowed_email_domains", []),
        domain_join_policy=current_settings.get("domain_join_policy", "approval"),
        default_role=current_settings.get("default_role", "member"),
        require_device_registration=current_settings.get("require_device_registration", False),
        allow_push_notifications=current_settings.get("allow_push_notifications", True),
        device_registration_prompt=current_settings.get("device_registration_prompt", "first_action"),
    )


class MembershipRequestInfo(BaseModel):
    """Membership request info."""
    
    id: str
    user_email: str
    message: str | None = None
    status: str
    created_at: str


class PendingRequestsResponse(BaseModel):
    """List of pending membership requests."""
    
    requests: list[MembershipRequestInfo]


@router.get("/pending-requests", response_model=PendingRequestsResponse)
async def get_pending_requests(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> PendingRequestsResponse:
    """Get pending membership requests for vendor's organization."""
    user_id = session.get("user_id")
    
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org_id = orgs[0]["id"]
    
    # Get pending requests for this org from database
    result = await db.execute(
        select(MembershipRequest).where(
            MembershipRequest.organization_id == org_id,
            MembershipRequest.status == MembershipRequestStatus.PENDING
        ).order_by(MembershipRequest.created_at.desc())
    )
    requests = result.scalars().all()
    
    pending = [
        MembershipRequestInfo(
            id=req.id,
            user_email=req.user_email,
            message=req.message,
            status=req.status.value,
            created_at=req.created_at.isoformat(),
        )
        for req in requests
    ]
    
    return PendingRequestsResponse(requests=pending)


class ReviewRequestRequest(BaseModel):
    """Request to approve or reject a membership request."""
    
    request_id: str
    action: Literal["approve", "reject"]
    rejection_reason: str | None = None


class ReviewRequestResponse(BaseModel):
    """Response after reviewing a membership request."""
    
    success: bool
    message: str


@router.post("/review-request", response_model=ReviewRequestResponse)
async def review_membership_request(
    request_data: ReviewRequestRequest,
    request: Request,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> ReviewRequestResponse:
    """Approve or reject a membership request."""
    reviewer_id = session.get("user_id")
    reviewer_email = session.get("email", "")
    
    # Get IP address for audit log
    ip_address = request.client.host if request.client else None
    
    # Get the request from database
    result = await db.execute(
        select(MembershipRequest, Organization).join(
            Organization,
            Organization.id == MembershipRequest.organization_id
        ).where(
            MembershipRequest.id == request_data.request_id
        )
    )
    row = result.first()
    
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    
    membership_req, organization = row
    
    if membership_req.status != MembershipRequestStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request has already been processed")
    
    # Verify reviewer is in the organization
    orgs = await keycloak.get_user_organizations(reviewer_id)
    if not orgs or orgs[0]["id"] != membership_req.organization_id:
        raise HTTPException(status_code=403, detail="You cannot review requests for this organization")
    
    org_id = membership_req.organization_id
    org_name = organization.name
    user_id = membership_req.user_id
    user_email = membership_req.user_email
    
    if request_data.action == "approve":
        # Add user to organization
        await keycloak.add_user_to_organization(org_id, user_id)
        
        # Update user attributes
        await keycloak.update_user_attributes(user_id, {
            "organization_id": [org_id],
            "organization_name": [org_name],
            "joined_via": ["approval"],
        })
        
        # Update request status in database
        membership_req.status = MembershipRequestStatus.APPROVED
        membership_req.reviewed_by = reviewer_id
        membership_req.reviewed_at = datetime.utcnow()
        await db.commit()
        
        # Log audit event
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.MEMBERSHIP_APPROVED,
            user_id=reviewer_id,
            user_email=reviewer_email,
            organization_id=org_id,
            target_user_id=user_id,
            target_user_email=user_email,
            details={"request_id": request_data.request_id},
            ip_address=ip_address,
        )
        
        # Send email notification
        try:
            from notifications_service.email_notifications import send_membership_notification
            await send_membership_notification(
                user_email=user_email,
                organization_name=org_name,
                status="approved",
            )
        except Exception as e:
            logger.warning("Failed to send email notification: %s", e)
        
        logger.info(f"Approved membership request from {user_email} to {org_name}")
        
        return ReviewRequestResponse(
            success=True,
            message=f"{user_email} has been added to the organization.",
        )
    else:
        # Update request status in database
        membership_req.status = MembershipRequestStatus.REJECTED
        membership_req.reviewed_by = reviewer_id
        membership_req.reviewed_at = datetime.utcnow()
        membership_req.rejection_reason = request_data.rejection_reason
        await db.commit()
        
        # Log audit event
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.MEMBERSHIP_REJECTED,
            user_id=reviewer_id,
            user_email=reviewer_email,
            organization_id=org_id,
            target_user_id=user_id,
            target_user_email=user_email,
            details={
                "request_id": request_data.request_id,
                "rejection_reason": request_data.rejection_reason,
            },
            ip_address=ip_address,
        )
        
        # Send email notification
        try:
            from notifications_service.email_notifications import send_membership_notification
            await send_membership_notification(
                user_email=user_email,
                organization_name=org_name,
                status="rejected",
                rejection_reason=request_data.rejection_reason,
            )
        except Exception as e:
            logger.warning("Failed to send email notification: %s", e)
        
        logger.info(f"Rejected membership request from {user_email} to {org_name}")
        
        return ReviewRequestResponse(
            success=True,
            message=f"Request from {user_email} has been rejected.",
        )


# =============================================================================
# Invitation Link Endpoints
# =============================================================================


class ValidateInvitationResponse(BaseModel):
    """Response for invitation validation."""
    
    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    expired: bool = False
    message: str | None = None


class AcceptInvitationRequest(BaseModel):
    """Request to accept an invitation."""
    
    token: str = Field(..., description="The invitation token/code")


class AcceptInvitationResponse(BaseModel):
    """Response after accepting an invitation."""
    
    success: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    message: str


@router.get("/invitations/validate", response_model=ValidateInvitationResponse)
async def validate_invitation(
    token: str,
    db: AsyncSession = Depends(get_db_session),
) -> ValidateInvitationResponse:
    """
    Validate an invitation token without requiring authentication.
    
    Public endpoint to check if an invite code is valid before requiring login.
    """
    if not token or len(token.strip()) < 4:
        return ValidateInvitationResponse(
            valid=False,
            message="Invalid invitation code format",
        )
    
    try:
        # Look up the invitation by code
        result = await db.execute(
            select(OrganizationInvitation, Organization).join(
                Organization,
                Organization.id == OrganizationInvitation.organization_id
            ).where(
                OrganizationInvitation.code == token.strip()
            )
        )
        row = result.first()
        
        if not row:
            return ValidateInvitationResponse(
                valid=False,
                message="Invitation not found",
            )
        
        invitation, organization = row
        
        # Check if invitation is valid
        if not invitation.is_valid:
            expired = invitation.expires_at and invitation.expires_at < datetime.utcnow()
            max_uses_reached = invitation.max_uses and invitation.uses_count >= invitation.max_uses
            
            if expired:
                return ValidateInvitationResponse(
                    valid=False,
                    expired=True,
                    message="This invitation has expired",
                )
            elif max_uses_reached:
                return ValidateInvitationResponse(
                    valid=False,
                    message="This invitation has reached its maximum number of uses",
                )
            else:
                return ValidateInvitationResponse(
                    valid=False,
                    message="This invitation is no longer active",
                )
        
        return ValidateInvitationResponse(
            valid=True,
            organization_id=organization.id,
            organization_name=organization.name,
            role=invitation.role.value if invitation.role else "member",
            message=f"Valid invitation to join {organization.name}",
        )
        
    except Exception as e:
        logger.error(f"Error validating invitation: {e}")
        return ValidateInvitationResponse(
            valid=False,
            message="Failed to validate invitation",
        )


@router.post("/invitations/accept", response_model=AcceptInvitationResponse)
async def accept_invitation(
    request_data: AcceptInvitationRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> AcceptInvitationResponse:
    """
    Accept an invitation and join the organization.
    
    Requires authentication. Creates organization membership with the role
    specified in the invitation.
    """
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    session_id = session.get("_session_id")
    token = request_data.token.strip()
    
    if not token:
        raise HTTPException(status_code=400, detail="Invitation code is required")
    
    try:
        # Look up the invitation
        result = await db.execute(
            select(OrganizationInvitation, Organization).join(
                Organization,
                Organization.id == OrganizationInvitation.organization_id
            ).where(
                OrganizationInvitation.code == token
            )
        )
        row = result.first()
        
        if not row:
            raise HTTPException(status_code=404, detail="Invitation not found")
        
        invitation, organization = row
        
        # Validate invitation
        if not invitation.is_valid:
            expired = invitation.expires_at and invitation.expires_at < datetime.utcnow()
            if expired:
                raise HTTPException(status_code=400, detail="This invitation has expired")
            elif invitation.max_uses and invitation.uses_count >= invitation.max_uses:
                raise HTTPException(
                    status_code=400,
                    detail="This invitation has reached its maximum number of uses"
                )
            else:
                raise HTTPException(status_code=400, detail="This invitation is no longer active")
        
        # Check if email-specific invitation matches user's email
        if invitation.email and invitation.email.lower() != user_email.lower():
            raise HTTPException(
                status_code=403,
                detail="This invitation is for a different email address"
            )
        
        org_id = organization.id
        org_name = organization.name
        role = invitation.role if invitation.role else MemberRole.MEMBER
        
        # Check if user is already a member
        result = await db.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == user_id,
            )
        )
        existing_member = result.scalar_one_or_none()
        
        if existing_member:
            return AcceptInvitationResponse(
                success=True,
                organization_id=org_id,
                organization_name=org_name,
                role=existing_member.role.value,
                message=f"You are already a member of {org_name}",
            )
        
        # Create organization membership
        new_member = OrganizationMember(
            id=str(uuid4()),
            organization_id=org_id,
            user_id=user_id,
            role=role,
            joined_at=datetime.utcnow(),
        )
        db.add(new_member)
        
        # Update invitation usage
        invitation.uses_count += 1
        if not invitation.is_reusable:
            invitation.is_active = False
        if invitation.max_uses and invitation.uses_count >= invitation.max_uses:
            invitation.is_active = False
        
        await db.commit()
        
        # Add user to organization in Keycloak
        try:
            await keycloak.add_user_to_organization(org_id, user_id)
        except Exception as e:
            logger.warning(f"Failed to add user to organization in Keycloak: {e}")
        
        # Update session and Keycloak attributes
        org_claim = merge_org_claim(session.get("organization"), org_id, org_name)
        
        attributes = {
            "organization_id": [org_id],
            "organization_name": [org_name],
            "joined_via": ["invite_link"],
            "onboarding_completed": [datetime.utcnow().isoformat()],
        }
        
        try:
            await keycloak.update_user_attributes(user_id, attributes)
        except Exception as e:
            logger.warning(f"Failed to update user attributes in Keycloak: {e}")
        
        # Update session
        await update_session_attributes(
            session_id,
            {
                "organization_id": org_id,
                "organization_name": org_name,
                "onboarding_completed": datetime.utcnow().isoformat(),
                "organization": org_claim,
                "roles": [role.value],
            },
        )
        
        logger.info(f"User {user_email} accepted invitation to {org_name} with role {role.value}")
        
        return AcceptInvitationResponse(
            success=True,
            organization_id=org_id,
            organization_name=org_name,
            role=role.value,
            message=f"Successfully joined {org_name}",
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error accepting invitation: {e}")
        raise HTTPException(status_code=500, detail="Failed to accept invitation")


# =============================================================================
# Email Domain Matching Endpoints
# =============================================================================


class DomainMatchedOrganization(BaseModel):
    """Organization matched by email domain."""
    
    id: str
    name: str
    domain_join_policy: str  # "auto", "approval", "closed"
    default_role: str


class DomainMatchesResponse(BaseModel):
    """Response with organizations matching user's email domain."""
    
    matches: list[DomainMatchedOrganization]


class JoinDomainOrgRequest(BaseModel):
    """Request to join organization based on email domain."""
    
    organization_id: str = Field(..., description="ID of organization to join")


class JoinDomainOrgResponse(BaseModel):
    """Response after joining or requesting to join domain org."""
    
    success: bool
    action: str  # "joined" or "requested"
    organization_id: str
    organization_name: str
    message: str


@router.get("/domain-matches", response_model=DomainMatchesResponse)
async def get_domain_matches(
    request: Request,
) -> DomainMatchesResponse:
    """
    Get organizations matching the user's email domain.
    
    Returns organizations that:
    1. Have the user's email domain in allowed_email_domains
    2. Are discoverable (is_discoverable = true)
    
    The matched organizations are stored in the session during login/provisioning.
    """
    session_manager = await get_session_manager()
    session = await session_manager.get_session(request)
    
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get matched organizations from session
    matched_orgs = session.get("matched_organizations", [])
    
    if not matched_orgs:
        return DomainMatchesResponse(matches=[])
    
    # Convert to response model
    matches = [
        DomainMatchedOrganization(
            id=org["id"],
            name=org["name"],
            domain_join_policy=org["domain_join_policy"],
            default_role=org["default_role"],
        )
        for org in matched_orgs
    ]
    
    return DomainMatchesResponse(matches=matches)


@router.post("/join-domain-org", response_model=JoinDomainOrgResponse)
async def join_domain_organization(
    body: JoinDomainOrgRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
) -> JoinDomainOrgResponse:
    """
    Join or request to join an organization based on email domain matching.
    
    Behavior depends on the organization's domain_join_policy:
    - "auto": Automatically adds user as member with default_role
    - "approval": Creates a membership request for admin review
    - "closed": Returns error (should not be matched, but handled for safety)
    
    Only works if the organization was matched during login (stored in session).
    """
    session_manager = await get_session_manager()
    session = await session_manager.get_session(request)
    
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user_id = session.get("user_id")
    user_email = session.get("email")
    session_id = session.get("session_id")
    
    # Get matched organizations from session
    matched_orgs = session.get("matched_organizations", [])
    
    # Find the requested organization in the matches
    matched_org = next(
        (org for org in matched_orgs if org["id"] == body.organization_id),
        None,
    )
    
    if not matched_org:
        raise HTTPException(
            status_code=403,
            detail="Organization not available for domain-based join",
        )
    
    # Get organization details
    result = await db.execute(
        select(Organization).where(Organization.id == body.organization_id)
    )
    organization = result.scalar_one_or_none()
    
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    policy = matched_org["domain_join_policy"]
    default_role = matched_org["default_role"]
    
    try:
        # Parse role enum
        try:
            member_role = MemberRole(default_role)
        except ValueError:
            logger.warning(f"Invalid role {default_role}, defaulting to MEMBER")
            member_role = MemberRole.MEMBER
        
        if policy == "auto":
            # Auto-join: Create membership immediately
            membership = OrganizationMember(
                id=str(uuid4()),
                organization_id=organization.id,
                user_id=user_id,
                role=member_role,
                joined_at=datetime.utcnow(),
            )
            db.add(membership)
            await db.commit()
            
            # Add to Keycloak
            try:
                await keycloak.add_user_to_organization(organization.id, user_id)
            except Exception as e:
                logger.warning(f"Failed to add user to Keycloak org: {e}")
            
            # Update session and Keycloak attributes
            org_claim = merge_org_claim(
                session.get("organization"), organization.id, organization.name
            )
            
            attributes = {
                "organization_id": [organization.id],
                "organization_name": [organization.name],
                "joined_via": ["email_domain"],
                "onboarding_completed": [datetime.utcnow().isoformat()],
            }
            
            try:
                await keycloak.update_user_attributes(user_id, attributes)
            except Exception as e:
                logger.warning(f"Failed to update Keycloak attributes: {e}")
            
            # Update session
            await update_session_attributes(
                session_id,
                {
                    "organization_id": organization.id,
                    "organization_name": organization.name,
                    "onboarding_completed": datetime.utcnow().isoformat(),
                    "organization": org_claim,
                    "roles": [member_role.value],
                },
            )
            
            logger.info(
                f"User {user_email} auto-joined {organization.name} via email domain"
            )
            
            return JoinDomainOrgResponse(
                success=True,
                action="joined",
                organization_id=organization.id,
                organization_name=organization.name,
                message=f"Successfully joined {organization.name}",
            )
            
        elif policy == "approval":
            # Request approval: Create membership request
            # Check if request already exists
            existing_request = await db.execute(
                select(MembershipRequest).where(
                    MembershipRequest.organization_id == organization.id,
                    MembershipRequest.user_id == user_id,
                    MembershipRequest.status == MembershipRequestStatus.PENDING,
                )
            )
            if existing_request.scalar_one_or_none():
                return JoinDomainOrgResponse(
                    success=True,
                    action="requested",
                    organization_id=organization.id,
                    organization_name=organization.name,
                    message=f"You already have a pending request to join {organization.name}",
                )
            
            # Create new request
            request_record = MembershipRequest(
                id=str(uuid4()),
                organization_id=organization.id,
                user_id=user_id,
                user_email=user_email,
                requested_role=member_role,
                status=MembershipRequestStatus.PENDING,
                requested_at=datetime.utcnow(),
                metadata={"source": "email_domain"},
            )
            db.add(request_record)
            await db.commit()
            
            logger.info(
                f"User {user_email} requested to join {organization.name} via email domain"
            )
            
            return JoinDomainOrgResponse(
                success=True,
                action="requested",
                organization_id=organization.id,
                organization_name=organization.name,
                message=f"Your request to join {organization.name} has been submitted for approval",
            )
            
        else:  # policy == "closed" or unknown
            raise HTTPException(
                status_code=403,
                detail="This organization does not allow new members at this time",
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error joining domain organization: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process request")
