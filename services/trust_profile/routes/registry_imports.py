"""
Registry Import API Routes

Endpoints for managing registry imports in trust profiles.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import logging

from trust_profile.domain.registry_config import (
    RegistryType,
    RegistryConfig,
    TrustFramework,
    KNOWN_REGISTRIES,
    get_registries_for_framework,
)

logger = logging.getLogger(__name__)

registry_router = APIRouter(prefix="/v1/registries", tags=["registries"])


# ============================================================================
# Pydantic Models for API Requests/Responses
# ============================================================================

class RegistrySourceCreate(BaseModel):
    """Create a new registry import source."""
    registry_type: RegistryType
    credential_format_filter: Optional[List[str]] = Field(
        None,
        description="Filter imported issuers by credential format (auto-set based on registry and framework)"
    )
    sync_enabled: bool = Field(default=True, description="Auto-sync this registry")
    sync_interval_hours: int = Field(default=24, description="Sync interval in hours")


class RegistrySourceResponse(BaseModel):
    """Registry source information."""
    id: str
    trust_profile_id: str
    registry_type: RegistryType
    registry_name: str
    registry_url: Optional[str]
    enabled: bool
    sync_enabled: bool
    last_synced_at: Optional[datetime]
    next_sync_at: Optional[datetime]
    sync_interval_hours: int
    credential_format_filter: List[str]
    issuer_count: int = Field(default=0, description="Number of imported issuers")
    created_at: datetime
    updated_at: datetime


class RegistryIssuerResponse(BaseModel):
    """Imported issuer from a registry."""
    id: str
    registry_source_id: str
    issuer_did: str
    issuer_name: Optional[str]
    country_code: Optional[str]
    issuer_type: Optional[str]
    status: str
    imported_at: datetime
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]


class AvailableRegistryResponse(BaseModel):
    """Available registry for a trust framework."""
    registry_type: RegistryType
    registry_name: str
    registry_url: str
    description: str
    supported_formats: List[str]


# ============================================================================
# Routes
# ============================================================================

@registry_router.get(
    "/available",
    response_model=List[AvailableRegistryResponse],
    summary="Get available registries for a framework"
)
async def get_available_registries(
    framework: str = Query(..., description="Trust framework (ICAO, EUDI, AAMVA, CUSTOM)")
):
    """
    Get list of available registries for a specific trust framework.
    
    Auto-filters credential formats based on the framework and registry capabilities.
    """
    try:
        framework_enum = TrustFramework[framework]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown trust framework: {framework}"
        )
    
    registries = get_registries_for_framework(framework_enum)
    
    return [
        AvailableRegistryResponse(
            registry_type=reg.registry_type,
            registry_name=reg.registry_name,
            registry_url=reg.registry_url,
            description=reg.description,
            supported_formats=[fmt.value for fmt in reg.supported_formats],
        )
        for reg in registries
    ]


@registry_router.get(
    "/registry-info",
    response_model=dict,
    summary="Get details about a specific registry"
)
async def get_registry_info(registry_type: str):
    """Get detailed information about a specific registry."""
    try:
        registry_enum = RegistryType[registry_type]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown registry type: {registry_type}"
        )
    
    config = KNOWN_REGISTRIES.get(registry_enum)
    
    if not config:
        raise HTTPException(status_code=404, detail="Registry not found")
    
    return {
        "registry_type": config.registry_type.value,
        "registry_name": config.registry_name,
        "registry_url": config.registry_url,
        "description": config.description,
        "supported_frameworks": [f.value for f in config.supported_frameworks],
        "supported_formats": [fmt.value for fmt in config.supported_formats],
        "sync_interval_hours": config.sync_interval_hours,
        "issuer_type_filter": config.issuer_type_filter,
    }


@registry_router.post(
    "/trust-profiles/{trust_profile_id}/import-source",
    response_model=RegistrySourceResponse,
    summary="Add a registry import source to a trust profile"
)
async def add_registry_import(
    trust_profile_id: str,
    source: RegistrySourceCreate,
):
    """
    Add a new registry import source to a trust profile.
    
    This enables importing issuers from the specified registry.
    The system will auto-sync based on the configured interval.
    """
    # Get registry config
    registry_config = KNOWN_REGISTRIES.get(source.registry_type)
    if not registry_config:
        raise HTTPException(status_code=400, detail="Unknown registry type")
    
    # Auto-set credential formats if not specified
    credential_formats = source.credential_format_filter or [
        fmt.value for fmt in registry_config.supported_formats
    ]
    
    # In a real implementation, this would:
    # 1. Verify trust profile exists and user has access
    # 2. Check for duplicate registry imports
    # 3. Store in database
    # 4. Trigger initial sync
    # 5. Schedule recurring syncs
    
    now = datetime.now(timezone.utc)
    
    response = RegistrySourceResponse(
        id=str(uuid.uuid4()),
        trust_profile_id=trust_profile_id,
        registry_type=source.registry_type,
        registry_name=registry_config.registry_name,
        registry_url=registry_config.registry_url,
        enabled=True,
        sync_enabled=source.sync_enabled,
        last_synced_at=None,
        next_sync_at=now,
        sync_interval_hours=source.sync_interval_hours,
        credential_format_filter=credential_formats,
        issuer_count=0,
        created_at=now,
        updated_at=now,
    )
    
    logger.info(
        f"Added registry import source {response.id} for trust profile {trust_profile_id}"
    )
    
    return response


@registry_router.get(
    "/trust-profiles/{trust_profile_id}/import-sources",
    response_model=List[RegistrySourceResponse],
    summary="List registry import sources for a trust profile"
)
async def list_registry_imports(trust_profile_id: str):
    """List all registry import sources configured for a trust profile."""
    # In a real implementation, fetch from database
    return []


@registry_router.delete(
    "/trust-profiles/{trust_profile_id}/import-sources/{source_id}",
    summary="Remove a registry import source"
)
async def remove_registry_import(trust_profile_id: str, source_id: str):
    """Remove a registry import source and its imported issuers."""
    # In a real implementation:
    # 1. Verify trust profile and source exist
    # 2. Delete from database
    # 3. Cancel scheduled syncs
    logger.info(f"Removed registry import source {source_id}")
    
    return {"status": "deleted", "source_id": source_id}


@registry_router.post(
    "/trust-profiles/{trust_profile_id}/import-sources/{source_id}/sync",
    summary="Manually trigger a sync of a registry import source"
)
async def trigger_registry_sync(trust_profile_id: str, source_id: str):
    """
    Manually trigger an immediate sync of a specific registry import source.
    
    This fetches the latest issuers from the registry and updates the local database.
    """
    # In a real implementation:
    # 1. Verify source exists
    # 2. Fetch from registry API
    # 3. Parse and validate issuers
    # 4. Store in trust_registry_issuers table
    # 5. Update last_synced_at
    
    logger.info(f"Triggered manual sync for registry source {source_id}")
    
    return {
        "status": "syncing",
        "source_id": source_id,
        "sync_started_at": datetime.now(timezone.utc),
    }


@registry_router.get(
    "/trust-profiles/{trust_profile_id}/import-sources/{source_id}/issuers",
    response_model=List[RegistryIssuerResponse],
    summary="List imported issuers from a registry source"
)
async def list_registry_issuers(
    trust_profile_id: str,
    source_id: str,
    skip: int = Query(0),
    limit: int = Query(50),
):
    """List issuers imported from a specific registry source."""
    # In a real implementation, fetch from trust_registry_issuers table
    return []
