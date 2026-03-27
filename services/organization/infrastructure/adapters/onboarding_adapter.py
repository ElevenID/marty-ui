"""
Onboarding HTTP Adapter

Provides onboarding status endpoints for post-login user experience.
This is a simplified version that returns the user's status based on their session.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Create router with /api/onboarding prefix to match existing UI expectations
router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


# =============================================================================
# Response Models
# =============================================================================


class OnboardingStatusResponse(BaseModel):
    """Onboarding status response."""
    
    needs_onboarding: bool
    user_type: str | None = None
    organization_id: str | None = None
    organization_name: str | None = None
    completed_at: str | None = None
    pending_request: dict | None = None


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/status", response_model=OnboardingStatusResponse, response_model_exclude_none=True)
async def get_onboarding_status(request: Request) -> OnboardingStatusResponse:
    """
    Check if the current user needs onboarding.
    
    Returns onboarding status based on user context from the gateway.
    In this simplified version, we return needs_onboarding=false and
    determine user_type from their roles.
    """
    # Get user context from gateway (set by X-User-Context header)
    user_context = None
    user_context_header = request.headers.get("X-User-Context")
    
    if user_context_header:
        try:
            user_context = json.loads(user_context_header)
        except json.JSONDecodeError:
            logger.warning("Failed to parse X-User-Context header")
    
    # Default response - no onboarding needed
    response = OnboardingStatusResponse(
        needs_onboarding=False,
        user_type="vendor",  # Default to vendor for now
        organization_id=None,
        organization_name=None,
        completed_at=None,
        pending_request=None,
    )
    
    if user_context:
        # Determine user type from roles
        roles = user_context.get("roles", [])
        
        if "administrator" in roles or "admin" in roles:
            response.user_type = "administrator"
        elif "vendor" in roles:
            response.user_type = "vendor"
        elif "applicant" in roles:
            response.user_type = "applicant"
        else:
            # Default to vendor for users without specific roles
            response.user_type = "vendor"
        
        # Get organization info if available
        org_id = user_context.get("organization_id")
        if org_id:
            response.organization_id = org_id
            response.organization_name = user_context.get("organization_name")
    
    logger.info(f"Onboarding status: user_type={response.user_type}, needs_onboarding={response.needs_onboarding}")
    
    return response
