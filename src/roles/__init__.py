"""
Role Escalation API

Allows users to request role changes within their organization.
"""

import logging
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from subscription.models import (
    RoleEscalationRequest,
    RoleEscalationStatus,
    MemberRole,
    Organization,
    AuditEventType,
)
from subscription.database import get_db_session
from auth.router import get_session_manager
from auth.keycloak_admin import KeycloakAdminClient, get_keycloak_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/roles", tags=["roles"])


# =============================================================================
# Request/Response Models
# =============================================================================


class RequestRoleChangeRequest(BaseModel):
    """Request to escalate role."""
    
    requested_role: str
    message: str | None = None


class RequestRoleChangeResponse(BaseModel):
    """Response after submitting role change request."""
    
    success: bool
    request_id: str | None = None
    message: str


class RoleEscalationInfo(BaseModel):
    """Role escalation request info."""
    
    id: str
    user_email: str
    current_role: str
    requested_role: str
    message: str | None = None
    status: str
    created_at: str


class PendingRoleRequestsResponse(BaseModel):
    """List of pending role escalation requests."""
    
    requests: list[RoleEscalationInfo]


class ReviewRoleRequestRequest(BaseModel):
    """Request to approve or reject a role escalation request."""
    
    request_id: str
    action: str  # "approve" or "reject"
    rejection_reason: str | None = None


class ReviewRoleRequestResponse(BaseModel):
    """Response after reviewing a role escalation request."""
    
    success: bool
    message: str


def get_session_data(request: Request) -> dict:
    """Extract session data from request."""
    session_manager = get_session_manager()
    return session_manager.get(request) or {}


# =============================================================================
# API Endpoints
# =============================================================================


@router.post("/request-change", response_model=RequestRoleChangeResponse)
async def request_role_change(
    request_data: RequestRoleChangeRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> RequestRoleChangeResponse:
    """Request a role change within the organization."""
    user_id = session.get("user_id")
    user_email = session.get("email", "")
    
    # Get user's organization
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org_id = orgs[0]["id"]
    org_name = orgs[0].get("name", "Unknown")
    
    # Validate requested role
    try:
        requested_role_enum = MemberRole(request_data.requested_role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {request_data.requested_role}")
    
    # Get current role from session
    roles = session.get("roles", [])
    current_role_str = roles[0] if roles else "member"
    try:
        current_role_enum = MemberRole(current_role_str)
    except ValueError:
        current_role_enum = MemberRole.MEMBER
    
    # Check if there's already a pending request
    result = await db.execute(
        select(RoleEscalationRequest).where(
            and_(
                RoleEscalationRequest.user_id == user_id,
                RoleEscalationRequest.organization_id == org_id,
                RoleEscalationRequest.status == RoleEscalationStatus.PENDING
            )
        )
    )
    existing_request = result.scalar_one_or_none()
    
    if existing_request:
        raise HTTPException(
            status_code=400,
            detail="You already have a pending role change request."
        )
    
    # Create new request
    new_request = RoleEscalationRequest(
        id=str(uuid4()),
        organization_id=org_id,
        user_id=user_id,
        user_email=user_email,
        current_role=current_role_enum,
        requested_role=requested_role_enum,
        message=request_data.message,
        status=RoleEscalationStatus.PENDING,
    )
    db.add(new_request)
    await db.commit()
    
    logger.info(
        "User %s requested role change from %s to %s in org %s",
        user_email,
        current_role_str,
        request_data.requested_role,
        org_name,
    )
    
    return RequestRoleChangeResponse(
        success=True,
        request_id=new_request.id,
        message=f"Your request to change role to {request_data.requested_role} has been submitted. "
                "You'll be notified when an administrator reviews your request.",
    )


@router.get("/pending-requests", response_model=PendingRoleRequestsResponse)
async def get_pending_role_requests(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> PendingRoleRequestsResponse:
    """Get pending role escalation requests for organization."""
    user_id = session.get("user_id")
    
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org_id = orgs[0]["id"]
    
    # Get pending requests
    result = await db.execute(
        select(RoleEscalationRequest).where(
            and_(
                RoleEscalationRequest.organization_id == org_id,
                RoleEscalationRequest.status == RoleEscalationStatus.PENDING
            )
        ).order_by(RoleEscalationRequest.created_at.desc())
    )
    requests = result.scalars().all()
    
    pending = [
        RoleEscalationInfo(
            id=req.id,
            user_email=req.user_email,
            current_role=req.current_role.value,
            requested_role=req.requested_role.value,
            message=req.message,
            status=req.status.value,
            created_at=req.created_at.isoformat(),
        )
        for req in requests
    ]
    
    return PendingRoleRequestsResponse(requests=pending)


@router.post("/review-request", response_model=ReviewRoleRequestResponse)
async def review_role_request(
    request_data: ReviewRoleRequestRequest,
    request: Request,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
) -> ReviewRoleRequestResponse:
    """Approve or reject a role escalation request."""
    reviewer_id = session.get("user_id")
    reviewer_email = session.get("email", "")
    
    # Get IP for audit
    ip_address = request.client.host if request.client else None
    
    # Get the request
    result = await db.execute(
        select(RoleEscalationRequest, Organization).join(
            Organization,
            Organization.id == RoleEscalationRequest.organization_id
        ).where(
            RoleEscalationRequest.id == request_data.request_id
        )
    )
    row = result.first()
    
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    
    role_req, organization = row
    
    if role_req.status != RoleEscalationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request has already been processed")
    
    # Verify reviewer is in the organization (admin check could be added)
    orgs = await keycloak.get_user_organizations(reviewer_id)
    if not orgs or orgs[0]["id"] != role_req.organization_id:
        raise HTTPException(status_code=403, detail="You cannot review requests for this organization")
    
    org_id = role_req.organization_id
    org_name = organization.name
    user_id = role_req.user_id
    user_email = role_req.user_email
    new_role = role_req.requested_role
    
    if request_data.action == "approve":
        # Update user's role in Keycloak (simplified - actual implementation may vary)
        # This would need proper Keycloak role management
        logger.info(
            "Approved role change for %s to %s in org %s",
            user_email,
            new_role.value,
            org_name,
        )
        
        # Update request status
        role_req.status = RoleEscalationStatus.APPROVED
        role_req.reviewed_by = reviewer_id
        role_req.reviewed_at = datetime.utcnow()
        await db.commit()
        
        # Log audit event
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.ROLE_ESCALATION_APPROVED,
            user_id=reviewer_id,
            user_email=reviewer_email,
            organization_id=org_id,
            target_user_id=user_id,
            target_user_email=user_email,
            details={
                "request_id": request_data.request_id,
                "new_role": new_role.value,
            },
            ip_address=ip_address,
        )
        
        return ReviewRoleRequestResponse(
            success=True,
            message=f"Role change approved for {user_email}.",
        )
    else:
        # Reject
        role_req.status = RoleEscalationStatus.REJECTED
        role_req.reviewed_by = reviewer_id
        role_req.reviewed_at = datetime.utcnow()
        role_req.rejection_reason = request_data.rejection_reason
        await db.commit()
        
        # Log audit event
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.ROLE_ESCALATION_REJECTED,
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
        
        logger.info(
            "Rejected role change request from %s in org %s",
            user_email,
            org_name,
        )
        
        return ReviewRoleRequestResponse(
            success=True,
            message=f"Role change request from {user_email} has been rejected.",
        )
