"""
Audit Trail API and Helper Functions

Provides audit logging functionality for governance and security events.
"""

import logging
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from subscription.models import AuditLog, AuditEventType
from subscription.database import get_db_session
from auth.router import get_session_manager
from auth.keycloak_admin import KeycloakAdminClient, get_keycloak_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit"])


# =============================================================================
# Audit Logging Helper
# =============================================================================


async def log_audit_event(
    db: AsyncSession,
    event_type: AuditEventType,
    user_id: str,
    user_email: str,
    organization_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    target_user_email: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """Log an audit event to the database.
    
    Args:
        db: Database session
        event_type: Type of event (from AuditEventType enum)
        user_id: User who performed the action
        user_email: Email of user performing action
        organization_id: Organization context (optional)
        target_user_id: Target user (optional, e.g., member being approved)
        target_user_email: Email of target user
        details: Additional event-specific details
        ip_address: IP address of request
        user_agent: Browser user agent
        
    Returns:
        The audit log entry ID
    """
    audit_entry = AuditLog(
        id=str(uuid4()),
        event_type=event_type,
        organization_id=organization_id,
        user_id=user_id,
        user_email=user_email,
        target_user_id=target_user_id,
        target_user_email=target_user_email,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        timestamp=datetime.utcnow(),
    )
    
    db.add(audit_entry)
    await db.commit()
    
    logger.info(
        "Audit: %s by %s (org=%s, target=%s)",
        event_type.value,
        user_email,
        organization_id,
        target_user_email or "N/A",
    )
    
    return audit_entry.id


# =============================================================================
# Request/Response Models
# =============================================================================


class AuditLogEntry(BaseModel):
    """Audit log entry response."""
    
    id: str
    event_type: str
    organization_id: str | None = None
    user_email: str
    target_user_email: str | None = None
    details: dict | None = None
    timestamp: str


class AuditLogsResponse(BaseModel):
    """List of audit log entries."""
    
    entries: list[AuditLogEntry]
    total: int
    page: int
    page_size: int


# =============================================================================
# API Endpoints
# =============================================================================


def get_session_data(request: Request) -> dict:
    """Extract session data from request."""
    session_manager = get_session_manager()
    return session_manager.get(request) or {}


@router.get("/logs", response_model=AuditLogsResponse)
async def get_audit_logs(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
    db: AsyncSession = Depends(get_db_session),
    event_type: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> AuditLogsResponse:
    """Get audit logs for the user's organization.
    
    Filters:
    - event_type: Filter by specific event type
    - start_date: ISO datetime string for start of range
    - end_date: ISO datetime string for end of range
    - page: Page number (1-indexed)
    - page_size: Number of entries per page
    """
    user_id = session.get("user_id")
    
    # Get user's organization
    orgs = await keycloak.get_user_organizations(user_id)
    if not orgs:
        raise HTTPException(status_code=404, detail="You are not a member of any organization")
    
    org_id = orgs[0]["id"]
    
    # Build query
    query = select(AuditLog).where(AuditLog.organization_id == org_id)
    
    # Apply filters
    if event_type:
        try:
            event_enum = AuditEventType(event_type)
            query = query.where(AuditLog.event_type == event_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event type: {event_type}")
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.where(AuditLog.timestamp >= start_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format")
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.where(AuditLog.timestamp <= end_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format")
    
    # Order by timestamp descending (newest first)
    query = query.order_by(desc(AuditLog.timestamp))
    
    # Get total count
    count_result = await db.execute(query)
    total = len(count_result.scalars().all())
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    logs = result.scalars().all()
    
    # Format response
    entries = [
        AuditLogEntry(
            id=log.id,
            event_type=log.event_type.value,
            organization_id=log.organization_id,
            user_email=log.user_email,
            target_user_email=log.target_user_email,
            details=log.details,
            timestamp=log.timestamp.isoformat(),
        )
        for log in logs
    ]
    
    return AuditLogsResponse(
        entries=entries,
        total=total,
        page=page,
        page_size=page_size,
    )
