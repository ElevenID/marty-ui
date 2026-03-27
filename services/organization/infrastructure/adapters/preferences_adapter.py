"""
Console Context Preferences HTTP Adapter

FastAPI router for user console context preferences (view mode + active org).
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from ...application.ports import UpsertConsoleContextPreferenceCommand
from ...application.use_cases import ConsoleContextPreferenceUseCase
from ...domain.entities import ViewMode

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/v1/me", tags=["preferences"])

# Global use case instance (configured via configure_preferences_router)
_preference_use_case: ConsoleContextPreferenceUseCase | None = None


def configure_preferences_router(preference_use_case: ConsoleContextPreferenceUseCase) -> None:
    """Configure the router with the preference use case."""
    global _preference_use_case
    _preference_use_case = preference_use_case


def get_preference_use_case() -> ConsoleContextPreferenceUseCase:
    """Get preference use case dependency."""
    if _preference_use_case is None:
        raise RuntimeError("Preferences router not configured")
    return _preference_use_case


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
# Request/Response Models
# =============================================================================

class PreferencesResponse(BaseModel):
    """Console context preferences response."""
    last_view_mode: str = Field(description="Last selected view mode: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(description="Last active organization ID (null if none)")


class UpdatePreferencesRequest(BaseModel):
    """Request to update console context preferences (partial update)."""
    last_view_mode: str | None = Field(None, description="View mode to set: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(None, description="Organization ID to set as active (explicit null allowed)")
    
    class Config:
        # Allow explicit None in JSON
        json_schema_extra = {
            "example": {
                "last_view_mode": "org_admin",
                "last_active_org_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/preferences", response_model=PreferencesResponse, response_model_exclude_none=True)
async def get_preferences(
    user_id: str = Depends(get_current_user_id),
    use_case: ConsoleContextPreferenceUseCase = Depends(get_preference_use_case),
) -> PreferencesResponse:
    """
    Get current user's console context preferences.
    
    Returns existing preferences or defaults if none exist:
    - last_view_mode: 'applicant' (default)
    - last_active_org_id: null (default)
    """
    try:
        preference = await use_case.get_preferences(user_id)
        return PreferencesResponse(
            last_view_mode=preference.last_view_mode.value,
            last_active_org_id=preference.last_active_org_id,
        )
    except Exception as e:
        logger.error(f"Error getting preferences for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving preferences")


@router.put("/preferences", response_model=PreferencesResponse, response_model_exclude_none=True)
async def update_preferences(
    request: UpdatePreferencesRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: ConsoleContextPreferenceUseCase = Depends(get_preference_use_case),
) -> PreferencesResponse:
    """
    Update (upsert) current user's console context preferences.
    
    Partial update semantics:
    - Absent field: keep existing value
    - Field present as explicit null:
      - last_active_org_id: set to null (valid - means no active org)
      - last_view_mode: REJECT with 400 (must be 'applicant' or 'org_admin')
    - Field present with value: set to that value
    
    Examples:
      - {"last_view_mode": "org_admin"} - change view mode, keep active org
      - {"last_active_org_id": null} - clear active org, keep view mode
      - {"last_view_mode": "applicant", "last_active_org_id": "..."} - update both
    """
    try:
        # Validate view mode if provided
        view_mode = None
        if request.last_view_mode is not None:
            if request.last_view_mode == "null":
                raise HTTPException(
                    status_code=400,
                    detail="last_view_mode must be 'applicant' or 'org_admin', not null",
                )
            try:
                view_mode = ViewMode(request.last_view_mode)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid view mode: {request.last_view_mode}. Must be 'applicant' or 'org_admin'",
                )
        
        # Build command
        command = UpsertConsoleContextPreferenceCommand(
            user_id=user_id,
            last_view_mode=view_mode,
        )
        
        # Handle explicit None for last_active_org_id
        # Pydantic's model includes the field even if None, so we check if it was provided
        if "last_active_org_id" in request.model_dump(exclude_unset=True):
            command.last_active_org_id = request.last_active_org_id
        
        preference = await use_case.upsert_preferences(command)
        
        return PreferencesResponse(
            last_view_mode=preference.last_view_mode.value,
            last_active_org_id=preference.last_active_org_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating preferences for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Error updating preferences")
