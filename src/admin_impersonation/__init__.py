"""
Platform Admin Impersonation API

Allows platform admins to impersonate organizations for troubleshooting and support.
All actions are logged to audit trail.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth.router import get_session_manager
from auth.keycloak_admin import KeycloakAdminClient, get_keycloak_admin
from database import get_db
from subscription.models import Organization, OrganizationMember, AuditEventType
from audit import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin/impersonate", tags=["admin"])


# =============================================================================
# Request/Response Models
# =============================================================================


class ImpersonateOrgRequest(BaseModel):
    """Request to start impersonating an organization."""
    
    organization_id: str
    reason: str  # Reason for impersonation (for audit)


class ImpersonateOrgResponse(BaseModel):
    """Response when starting impersonation."""
    
    success: bool
    organization_id: str
    organization_name: str
    impersonation_started_at: str
    message: str


class StopImpersonationResponse(BaseModel):
    """Response when stopping impersonation."""
    
    success: bool
    message: str


class ImpersonationStatusResponse(BaseModel):
    """Current impersonation status."""
    
    is_impersonating: bool
    impersonated_org_id: Optional[str] = None
    impersonated_org_name: Optional[str] = None
    impersonation_started_at: Optional[str] = None
    admin_user_id: Optional[str] = None
    admin_email: Optional[str] = None


def get_session_data(request: Request) -> dict:
    """Extract session data from request."""
    session_manager = get_session_manager()
    return session_manager.get(request) or {}


async def is_platform_admin(
    user_id: str,
    keycloak: KeycloakAdminClient,
) -> bool:
    """Check if user is a platform admin."""
    try:
        user = await keycloak.get_user(user_id)
        roles = user.get("realmRoles", [])
        return "platform_admin" in roles
    except Exception as e:
        logger.error("Error checking platform admin status: %s", e)
        return False


# =============================================================================
# API Endpoints
# =============================================================================


@router.post("/start", response_model=ImpersonateOrgResponse)
async def start_impersonation(
    request: Request,
    impersonate_request: ImpersonateOrgRequest,
    db: Session = Depends(get_db),
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
) -> ImpersonateOrgResponse:
    """Start impersonating an organization.
    
    Requires platform_admin role. All actions are logged to audit trail.
    """
    user_id = session.get("user_id")
    user_email = session.get("email")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if user is platform admin
    if not await is_platform_admin(user_id, keycloak):
        raise HTTPException(
            status_code=403,
            detail="Only platform admins can impersonate organizations"
        )
    
    # Check if already impersonating
    if session.get("impersonating_org_id"):
        raise HTTPException(
            status_code=400,
            detail="Already impersonating an organization. Stop current impersonation first."
        )
    
    # Get organization
    org = db.query(Organization).filter(
        Organization.id == impersonate_request.organization_id
    ).first()
    
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Store impersonation state in session
    session_manager = get_session_manager()
    impersonation_started_at = datetime.utcnow().isoformat()
    
    session["impersonating_org_id"] = org.id
    session["impersonating_org_name"] = org.name
    session["impersonation_started_at"] = impersonation_started_at
    session["impersonation_reason"] = impersonate_request.reason
    session["admin_user_id"] = user_id
    session["admin_email"] = user_email
    session["impersonation_read_only"] = True  # Read-only by default for safety
    
    session_manager.set(request, session)
    
    # Log to audit trail
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    await log_audit_event(
        db=db,
        event_type=AuditEventType.ADMIN_IMPERSONATION_START,
        user_id=user_id,
        user_email=user_email,
        organization_id=org.id,
        details={
            "impersonated_org_id": org.id,
            "impersonated_org_name": org.name,
            "reason": impersonate_request.reason,
            "mode": "read_only",
        },
        ip_address=client_ip,
        user_agent=user_agent,
    )
    
    logger.warning(
        "Platform admin %s (%s) started impersonating organization %s (%s). Reason: %s",
        user_id,
        user_email,
        org.id,
        org.name,
        impersonate_request.reason,
    )
    
    return ImpersonateOrgResponse(
        success=True,
        organization_id=org.id,
        organization_name=org.name,
        impersonation_started_at=impersonation_started_at,
        message=f"Now impersonating {org.name} (read-only mode)",
    )


@router.post("/stop", response_model=StopImpersonationResponse)
async def stop_impersonation(
    request: Request,
    db: Session = Depends(get_db),
    session: dict = Depends(get_session_data),
) -> StopImpersonationResponse:
    """Stop impersonating the current organization."""
    user_id = session.get("user_id")
    user_email = session.get("email")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if impersonating
    impersonating_org_id = session.get("impersonating_org_id")
    if not impersonating_org_id:
        raise HTTPException(status_code=400, detail="Not currently impersonating")
    
    impersonated_org_name = session.get("impersonating_org_name")
    impersonation_started_at = session.get("impersonation_started_at")
    
    # Calculate duration
    if impersonation_started_at:
        started = datetime.fromisoformat(impersonation_started_at)
        duration_seconds = (datetime.utcnow() - started).total_seconds()
    else:
        duration_seconds = 0
    
    # Log to audit trail
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    await log_audit_event(
        db=db,
        event_type=AuditEventType.ADMIN_IMPERSONATION_END,
        user_id=user_id,
        user_email=user_email,
        organization_id=impersonating_org_id,
        details={
            "impersonated_org_id": impersonating_org_id,
            "impersonated_org_name": impersonated_org_name,
            "duration_seconds": duration_seconds,
        },
        ip_address=client_ip,
        user_agent=user_agent,
    )
    
    # Clear impersonation state
    session_manager = get_session_manager()
    session.pop("impersonating_org_id", None)
    session.pop("impersonating_org_name", None)
    session.pop("impersonation_started_at", None)
    session.pop("impersonation_reason", None)
    session.pop("admin_user_id", None)
    session.pop("admin_email", None)
    session.pop("impersonation_read_only", None)
    session_manager.set(request, session)
    
    logger.info(
        "Platform admin %s (%s) stopped impersonating organization %s. Duration: %.1f seconds",
        user_id,
        user_email,
        impersonated_org_name,
        duration_seconds,
    )
    
    return StopImpersonationResponse(
        success=True,
        message=f"Stopped impersonating {impersonated_org_name}",
    )


@router.get("/status", response_model=ImpersonationStatusResponse)
async def get_impersonation_status(
    session: dict = Depends(get_session_data),
) -> ImpersonationStatusResponse:
    """Get current impersonation status."""
    is_impersonating = bool(session.get("impersonating_org_id"))
    
    if is_impersonating:
        return ImpersonationStatusResponse(
            is_impersonating=True,
            impersonated_org_id=session.get("impersonating_org_id"),
            impersonated_org_name=session.get("impersonating_org_name"),
            impersonation_started_at=session.get("impersonation_started_at"),
            admin_user_id=session.get("admin_user_id"),
            admin_email=session.get("admin_email"),
        )
    else:
        return ImpersonationStatusResponse(is_impersonating=False)
