"""
Notification Preferences API

Allows users to configure how they receive notifications (push, email, both).
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.router import get_session_manager
from auth.keycloak_admin import KeycloakAdminClient, get_keycloak_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications/preferences", tags=["notifications"])


# =============================================================================
# Request/Response Models
# =============================================================================


class NotificationPreferencesResponse(BaseModel):
    """User's notification preferences."""
    
    method: str  # "push", "email", or "both"
    email_for_applications: bool = True
    email_for_credentials: bool = True
    email_for_membership: bool = True


class UpdatePreferencesRequest(BaseModel):
    """Request to update notification preferences."""
    
    method: Literal["push", "email", "both"]
    email_for_applications: bool = True
    email_for_credentials: bool = True
    email_for_membership: bool = True


def get_session_data(request) -> dict:
    """Extract session data from request."""
    session_manager = get_session_manager()
    return session_manager.get(request) or {}


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
) -> NotificationPreferencesResponse:
    """Get user's notification preferences."""
    user_id = session.get("user_id")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get user attributes from Keycloak
    try:
        user = await keycloak.get_user(user_id)
        attributes = user.get("attributes", {})
        
        # Extract notification preferences
        notification_method = attributes.get("notification_method", ["both"])[0]
        email_for_applications = attributes.get("email_for_applications", ["true"])[0] == "true"
        email_for_credentials = attributes.get("email_for_credentials", ["true"])[0] == "true"
        email_for_membership = attributes.get("email_for_membership", ["true"])[0] == "true"
        
        return NotificationPreferencesResponse(
            method=notification_method,
            email_for_applications=email_for_applications,
            email_for_credentials=email_for_credentials,
            email_for_membership=email_for_membership,
        )
    except Exception as e:
        logger.error("Error fetching notification preferences: %s", e)
        # Return defaults
        return NotificationPreferencesResponse(
            method="both",
            email_for_applications=True,
            email_for_credentials=True,
            email_for_membership=True,
        )


@router.put("", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    preferences: UpdatePreferencesRequest,
    session: dict = Depends(get_session_data),
    keycloak: KeycloakAdminClient = Depends(get_keycloak_admin),
) -> NotificationPreferencesResponse:
    """Update user's notification preferences."""
    user_id = session.get("user_id")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Update user attributes in Keycloak
        await keycloak.update_user_attributes(user_id, {
            "notification_method": [preferences.method],
            "email_for_applications": [str(preferences.email_for_applications).lower()],
            "email_for_credentials": [str(preferences.email_for_credentials).lower()],
            "email_for_membership": [str(preferences.email_for_membership).lower()],
        })
        
        logger.info(
            "Updated notification preferences for user %s: method=%s",
            user_id,
            preferences.method,
        )
        
        return NotificationPreferencesResponse(
            method=preferences.method,
            email_for_applications=preferences.email_for_applications,
            email_for_credentials=preferences.email_for_credentials,
            email_for_membership=preferences.email_for_membership,
        )
    except Exception as e:
        logger.error("Error updating notification preferences: %s", e)
        raise HTTPException(status_code=500, detail="Failed to update preferences")
