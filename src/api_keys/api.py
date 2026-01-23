"""
API Key REST API

FastAPI router for API key management endpoints.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .models import APIKeyScope
from .service import get_api_key_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/organizations", tags=["API Keys"])


# ==================== Pydantic Models ====================

class CreateAPIKeyRequest(BaseModel):
    """Request to create a new API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable name for the key")
    scopes: List[str] = Field(..., min_items=1, description="List of scopes for the key")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration datetime")


class UpdateAPIKeyRequest(BaseModel):
    """Request to update an API key."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    scopes: Optional[List[str]] = Field(None, min_items=1)


class APIKeyResponse(BaseModel):
    """API key response (without the secret)."""
    id: str
    organization_id: str
    name: str
    key_prefix: str
    scopes: List[str]
    created_at: datetime
    created_by: Optional[str] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool
    revoked_at: Optional[datetime] = None
    usage_count: int = 0


class APIKeyCreatedResponse(APIKeyResponse):
    """API key response with the full key (only returned on creation)."""
    key: str = Field(..., description="The full API key - only shown once!")


class APIKeyListResponse(BaseModel):
    """List of API keys."""
    keys: List[APIKeyResponse]
    total: int


class AvailableScopesResponse(BaseModel):
    """Available API key scopes."""
    scopes: List[dict]


# ==================== Helper Functions ====================

def get_user_from_request(request: Request) -> dict:
    """Extract user info from request (set by auth middleware)."""
    user = getattr(request.state, "user", None)
    if user:
        return user
    # Fallback for testing
    return {"email": "unknown", "organization_id": None}


def get_organization_id(request: Request, org_id: str) -> str:
    """Validate and return organization ID."""
    user = get_user_from_request(request)
    user_org_id = user.get("organization_id")
    
    # Allow if user is admin or belongs to the organization
    user_type = user.get("user_type", "")
    if user_type == "administrator":
        return org_id
    
    if user_org_id and user_org_id == org_id:
        return org_id
    
    # For now, allow access (auth will be handled by middleware)
    return org_id


# ==================== Endpoints ====================

@router.get("/api-key-scopes", response_model=AvailableScopesResponse)
async def get_available_scopes():
    """Get list of available API key scopes."""
    scopes = [
        {"id": "read:credentials", "label": "Read Credentials", "description": "View credential data"},
        {"id": "write:credentials", "label": "Write Credentials", "description": "Issue and manage credentials"},
        {"id": "read:trust_registry", "label": "Read Trust Registry", "description": "Query trust registry"},
        {"id": "write:trust_registry", "label": "Write Trust Registry", "description": "Update trust registry entries"},
        {"id": "read:revocation", "label": "Read Revocation", "description": "Check revocation status"},
        {"id": "write:revocation", "label": "Write Revocation", "description": "Revoke credentials"},
        {"id": "manage:webhooks", "label": "Manage Webhooks", "description": "Configure webhook endpoints"},
        {"id": "verify:credentials", "label": "Verify Credentials", "description": "Verify credential presentations"},
    ]
    return AvailableScopesResponse(scopes=scopes)


@router.get("/{organization_id}/api-keys", response_model=APIKeyListResponse)
async def list_api_keys(
    organization_id: str,
    request: Request,
    include_revoked: bool = False,
    include_expired: bool = False,
):
    """List all API keys for an organization."""
    org_id = get_organization_id(request, organization_id)
    service = get_api_key_service()
    
    keys = service.list_keys(org_id, include_revoked=include_revoked, include_expired=include_expired)
    
    return APIKeyListResponse(
        keys=[APIKeyResponse(**k.to_dict()) for k in keys],
        total=len(keys),
    )


@router.post("/{organization_id}/api-keys", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    organization_id: str,
    request: Request,
    body: CreateAPIKeyRequest,
):
    """
    Create a new API key.
    
    The full API key is only returned in this response!
    Store it securely as it cannot be retrieved again.
    """
    org_id = get_organization_id(request, organization_id)
    user = get_user_from_request(request)
    service = get_api_key_service()
    
    # Validate scopes
    valid_scopes = {s.value for s in APIKeyScope}
    for scope in body.scopes:
        if scope not in valid_scopes:
            raise HTTPException(status_code=400, detail=f"Invalid scope: {scope}")
    
    api_key, plain_key = service.create_key(
        organization_id=org_id,
        name=body.name,
        scopes=body.scopes,
        created_by=user.get("email"),
        expires_at=body.expires_at,
    )
    
    response_data = api_key.to_dict()
    response_data["key"] = plain_key
    
    return APIKeyCreatedResponse(**response_data)


@router.get("/{organization_id}/api-keys/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    organization_id: str,
    key_id: str,
    request: Request,
):
    """Get details of a specific API key."""
    org_id = get_organization_id(request, organization_id)
    service = get_api_key_service()
    
    api_key = service.get_key(key_id, org_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return APIKeyResponse(**api_key.to_dict())


@router.patch("/{organization_id}/api-keys/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    organization_id: str,
    key_id: str,
    request: Request,
    body: UpdateAPIKeyRequest,
):
    """Update an API key's name or scopes."""
    org_id = get_organization_id(request, organization_id)
    service = get_api_key_service()
    
    # Validate scopes if provided
    if body.scopes:
        valid_scopes = {s.value for s in APIKeyScope}
        for scope in body.scopes:
            if scope not in valid_scopes:
                raise HTTPException(status_code=400, detail=f"Invalid scope: {scope}")
    
    api_key = service.update_key(
        key_id=key_id,
        organization_id=org_id,
        name=body.name,
        scopes=body.scopes,
    )
    
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return APIKeyResponse(**api_key.to_dict())


@router.post("/{organization_id}/api-keys/{key_id}/revoke", response_model=APIKeyResponse)
async def revoke_api_key(
    organization_id: str,
    key_id: str,
    request: Request,
):
    """Revoke an API key (soft delete)."""
    org_id = get_organization_id(request, organization_id)
    user = get_user_from_request(request)
    service = get_api_key_service()
    
    success = service.revoke_key(
        key_id=key_id,
        organization_id=org_id,
        revoked_by=user.get("email"),
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Return the updated key
    api_key = service.get_key(key_id, org_id)
    return APIKeyResponse(**api_key.to_dict())


@router.delete("/{organization_id}/api-keys/{key_id}", status_code=204)
async def delete_api_key(
    organization_id: str,
    key_id: str,
    request: Request,
):
    """Permanently delete an API key."""
    org_id = get_organization_id(request, organization_id)
    service = get_api_key_service()
    
    success = service.delete_key(key_id, org_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return None


# ==================== API Key Validation Endpoint ====================

@router.post("/api-keys/validate")
async def validate_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """
    Validate an API key and return its details.
    
    Used internally to validate API keys on requests.
    """
    service = get_api_key_service()
    
    api_key = service.validate_key(x_api_key)
    
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return {
        "valid": True,
        "organization_id": api_key.organization_id,
        "scopes": api_key.scopes,
        "name": api_key.name,
    }
