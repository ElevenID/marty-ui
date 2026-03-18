"""Organization-scoped authorization for Marty microservices.

This module provides FastAPI dependencies and utilities for verifying that
authenticated users have the required membership and roles within organizations.
"""

from enum import Enum
from typing import Annotated, Optional
import json
import logging

from fastapi import Depends, HTTPException, Header, Request
from pydantic import BaseModel
import redis.asyncio as aioredis


logger = logging.getLogger(__name__)


class OrgRole(str, Enum):
    """Organization membership roles.
    
    Matches the role column in the members table of the organization service.
    """
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class OrganizationMembership(BaseModel):
    """User's membership in an organization."""
    user_id: str
    organization_id: str
    role: OrgRole
    status: str  # active|pending|invited|deactivated
    
    def is_active(self) -> bool:
        """Check if membership is active."""
        return self.status == "active"
    
    def has_role(self, *allowed_roles: OrgRole) -> bool:
        """Check if user has one of the allowed roles."""
        return self.role in allowed_roles


class OrganizationContext(BaseModel):
    """Context about the user's relationship to an organization."""
    user_id: str
    organization_id: str
    membership: Optional[OrganizationMembership] = None
    source: str = "session"  # "session" or "api_key"
    permissions: Optional[set] = None  # Populated by require_permission
    
    class Config:
        arbitrary_types_allowed = True
    
    @property
    def role(self) -> Optional[OrgRole]:
        """Get the user's role in the organization."""
        return self.membership.role if self.membership else None
    
    def is_admin(self) -> bool:
        """Check if user is an admin or owner."""
        return self.membership and self.membership.has_role(OrgRole.ADMIN, OrgRole.OWNER)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if user has a specific permission."""
        if self.permissions is None:
            # No permissions loaded – fall back to admin check
            return self.is_admin()
        return f"{resource}:{action}" in self.permissions


class ApiKeyContext(BaseModel):
    """Context for API key authentication."""
    api_key_id: str
    organization_id: str
    key_prefix: str
    scopes: list[str]
    
    def has_scope(self, *required_scopes: str) -> bool:
        """Check if API key has all required scopes."""
        return all(scope in self.scopes for scope in required_scopes)


class OrganizationClient:
    """Client for querying organization membership from the organization service via gRPC.
    
    Supports Redis caching to minimize RPC overhead on membership lookups.
    """
    
    def __init__(
        self,
        grpc_channel,
        redis_client: Optional[aioredis.Redis] = None,
        cache_ttl: int = 120,
        **_kwargs,
    ):
        """Initialize the organization client.
        
        Args:
            grpc_channel: grpc.aio.Channel to the organization service.
            redis_client: Optional Redis client for caching. If None, caching is disabled.
            cache_ttl: Cache TTL in seconds (default: 120)
        """
        self.redis_client = redis_client
        self.cache_ttl = cache_ttl
        from marty_proto.v1.organization_service_pb2_grpc import OrganizationServiceStub
        self._grpc_stub = OrganizationServiceStub(grpc_channel)
        self._grpc_channel = grpc_channel
    
    async def close(self):
        """Close the gRPC channel."""
        await self._grpc_channel.close()
    
    def _cache_key(self, user_id: str, organization_id: str) -> str:
        """Generate Redis cache key for a membership lookup."""
        return f"org_membership:{user_id}:{organization_id}"
    
    async def _get_from_cache(self, user_id: str, organization_id: str) -> Optional[OrganizationMembership]:
        """Retrieve membership from Redis cache."""
        if not self.redis_client:
            return None
        
        try:
            key = self._cache_key(user_id, organization_id)
            data = await self.redis_client.get(key)
            if data:
                logger.debug(f"Cache HIT for membership {user_id} in {organization_id}")
                return OrganizationMembership.model_validate_json(data)
        except Exception as e:
            logger.warning(f"Redis cache read error: {e}")
        
        return None
    
    async def _set_in_cache(self, membership: OrganizationMembership):
        """Store membership in Redis cache."""
        if not self.redis_client:
            return
        
        try:
            key = self._cache_key(membership.user_id, membership.organization_id)
            await self.redis_client.setex(
                key,
                self.cache_ttl,
                membership.model_dump_json()
            )
            logger.debug(f"Cached membership {membership.user_id} in {membership.organization_id}")
        except Exception as e:
            logger.warning(f"Redis cache write error: {e}")
    
    async def invalidate_cache(self, user_id: str, organization_id: str):
        """Invalidate cached membership for a user in an organization."""
        if not self.redis_client:
            return
        
        try:
            key = self._cache_key(user_id, organization_id)
            await self.redis_client.delete(key)
            logger.info(f"Invalidated cache for {user_id} in {organization_id}")
        except Exception as e:
            logger.warning(f"Redis cache invalidation error: {e}")
    
    async def get_membership(
        self, 
        user_id: str, 
        organization_id: str
    ) -> Optional[OrganizationMembership]:
        """Query user's membership in an organization.
        
        Checks Redis cache first, then queries the organization service via gRPC.
        """
        # Try cache first
        cached = await self._get_from_cache(user_id, organization_id)
        if cached:
            return cached
        
        import grpc
        from marty_proto.v1 import organization_service_pb2

        try:
            resp = await self._grpc_stub.GetMember(
                organization_service_pb2.GetMemberRequest(
                    organization_id=organization_id,
                    user_id=user_id,
                )
            )
            membership = OrganizationMembership(
                user_id=resp.user_id,
                organization_id=resp.organization_id,
                role=OrgRole(resp.role),
                status=resp.status,
            )
            await self._set_in_cache(membership)
            return membership
        except grpc.aio.AioRpcError as e:
            if e.code() in (grpc.StatusCode.NOT_FOUND, grpc.StatusCode.UNKNOWN, grpc.StatusCode.INVALID_ARGUMENT):
                return None
            logger.error(f"gRPC error fetching membership: {e}")
            raise HTTPException(
                status_code=503,
                detail="Organization service unavailable",
            )
    
    async def validate_api_key(self, api_key: str) -> Optional[ApiKeyContext]:
        """Validate an API key and return its context via gRPC."""
        from marty_proto.v1 import organization_service_pb2

        try:
            resp = await self._grpc_stub.ValidateApiKey(
                organization_service_pb2.ValidateApiKeyRequest(api_key=api_key)
            )
            if not resp.valid:
                return None
            return ApiKeyContext(
                api_key_id=resp.api_key_id,
                organization_id=resp.organization_id,
                key_prefix=resp.key_prefix,
                scopes=list(resp.scopes),
            )
        except Exception as e:
            logger.error(f"gRPC error validating API key: {e}")
            return None


# FastAPI dependency functions

async def get_organization_client(request: Request) -> OrganizationClient:
    """FastAPI dependency to get the organization client from app state."""
    if not hasattr(request.app.state, "org_client"):
        raise HTTPException(
            status_code=500,
            detail="Organization client not configured"
        )
    return request.app.state.org_client


async def require_org_membership(
    organization_id: str,
    request: Request,
    x_user_id: Annotated[Optional[str], Header(alias="X-User-Id")] = None,
) -> OrganizationContext:
    """Verify that the authenticated user is an active member of the organization.
    
    This is a FastAPI dependency that should be used on org-scoped endpoints.
    
    Args:
        organization_id: Organization ID from path parameter
        request: FastAPI request object
        x_user_id: User ID injected by gateway via X-User-Id header
        
    Returns:
        OrganizationContext with membership details
        
    Raises:
        HTTPException: 401 if not authenticated, 403 if not a member
    """
    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required - missing user context"
        )
    
    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(x_user_id, organization_id)
    
    if not membership:
        logger.warning(
            f"User {x_user_id} attempted to access organization {organization_id} "
            f"without membership"
        )
        raise HTTPException(
            status_code=403,
            detail="Not a member of this organization"
        )
    
    if not membership.is_active():
        logger.warning(
            f"User {x_user_id} attempted to access organization {organization_id} "
            f"with inactive membership (status: {membership.status})"
        )
        raise HTTPException(
            status_code=403,
            detail=f"Organization membership is {membership.status}"
        )
    
    return OrganizationContext(
        user_id=x_user_id,
        organization_id=organization_id,
        membership=membership
    )


def require_org_role(*allowed_roles: OrgRole):
    """Factory for creating a role-checking dependency.
    
    Usage:
        @router.post("/v1/organizations/{org_id}/settings")
        async def update_settings(
            org_ctx: Annotated[OrganizationContext, Depends(require_org_role(OrgRole.ADMIN, OrgRole.OWNER))]
        ):
            ...
    
    Args:
        *allowed_roles: One or more OrgRole values that are allowed
        
    Returns:
        FastAPI dependency function
    """
    async def _check_role(
        org_ctx: Annotated[OrganizationContext, Depends(require_org_membership)]
    ) -> OrganizationContext:
        if not org_ctx.membership or not org_ctx.membership.has_role(*allowed_roles):
            logger.warning(
                f"User {org_ctx.user_id} with role {org_ctx.role} attempted to access "
                f"endpoint requiring roles {allowed_roles}"
            )
            role_names = ", ".join(r.value for r in allowed_roles)
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of these roles: {role_names}"
            )
        return org_ctx
    
    return _check_role


# Convenience aliases for common role requirements

async def require_org_admin(
    org_ctx: Annotated[OrganizationContext, Depends(require_org_role(OrgRole.ADMIN, OrgRole.OWNER))]
) -> OrganizationContext:
    """Verify user is an admin or owner of the organization.
    
    This is a convenience dependency equivalent to:
        Depends(require_org_role(OrgRole.ADMIN, OrgRole.OWNER))
    """
    return org_ctx


async def require_org_owner(
    org_ctx: Annotated[OrganizationContext, Depends(require_org_role(OrgRole.OWNER))]
) -> OrganizationContext:
    """Verify user is the owner of the organization."""
    return org_ctx


# ─────────────────────────────────────────────────────────────────────────────
# Permission-based authorization (RBAC)
# ─────────────────────────────────────────────────────────────────────────────

async def _load_member_permissions(
    request: Request,
    user_id: str,
    organization_id: str,
) -> set[str]:
    """Load the effective permission set for a user in an organization.
    
    Checks Redis cache first, then queries the organization service via gRPC.
    """
    org_client: OrganizationClient = await get_organization_client(request)
    cache_key = f"member_permissions:{user_id}:{organization_id}"
    
    # Try cache
    if org_client.redis_client:
        try:
            cached = await org_client.redis_client.get(cache_key)
            if cached:
                return set(json.loads(cached))
        except Exception as e:
            logger.warning(f"Redis cache read error (permissions): {e}")
    
    from marty_proto.v1 import organization_service_pb2

    try:
        resp = await org_client._grpc_stub.GetMemberPermissions(
            organization_service_pb2.GetMemberPermissionsRequest(
                organization_id=organization_id,
                user_id=user_id,
            )
        )
        perms = set(resp.permissions)
    except Exception as e:
        logger.error(f"gRPC error loading member permissions: {e}")
        return set()

    # Cache for 60 seconds
    if org_client.redis_client and perms:
        try:
            await org_client.redis_client.setex(
                cache_key, 60, json.dumps(list(perms))
            )
        except Exception as e:
            logger.warning(f"Redis cache write error (permissions): {e}")
    return perms


def require_permission(resource: str, action: str):
    """Factory for creating a permission-checking dependency.
    
    Usage:
        @router.post("/v1/organizations/{organization_id}/credential-templates")
        async def create_template(
            org_ctx: Annotated[
                OrganizationContext,
                Depends(require_permission("credential-template", "create"))
            ]
        ):
            ...
    
    Falls back to admin check if permissions haven't been loaded
    (e.g. if the organization service's internal endpoint isn't available yet).
    """
    async def _check_permission(
        request: Request,
        org_ctx: Annotated[OrganizationContext, Depends(require_org_membership)],
    ) -> OrganizationContext:
        # Load permissions if not already loaded
        if org_ctx.permissions is None:
            perms = await _load_member_permissions(
                request, org_ctx.user_id, org_ctx.organization_id
            )
            org_ctx.permissions = perms
        
        required_key = f"{resource}:{action}"
        
        if required_key not in org_ctx.permissions:
            # Fall back: admins/owners always have access
            if org_ctx.is_admin():
                return org_ctx
            
            logger.warning(
                f"User {org_ctx.user_id} denied permission {required_key} "
                f"in org {org_ctx.organization_id}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Missing required permission: {resource}:{action}",
            )
        
        return org_ctx
    
    return _check_permission


# API Key authentication dependencies

async def require_api_key(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
) -> ApiKeyContext:
    """Require a valid API key for authentication.
    
    Checks for API key in Authorization header (Bearer <key>) or X-API-Key header.
    Returns ApiKeyContext if valid, raises HTTPException(401) if invalid.
    
    Example:
        @router.post("/api/v1/credentials")
        async def create_credential(
            request: CreateCredentialRequest,
            api_ctx: ApiKeyContext = Depends(require_api_key),
        ):
            # api_ctx.organization_id contains the org the key belongs to
            # api_ctx.scopes contains the key's permissions
            ...
    """
    # Extract key from Authorization header (Bearer token) or X-API-Key header
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]  # Remove "Bearer " prefix
    elif x_api_key:
        api_key = x_api_key
    
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide in Authorization header (Bearer <key>) or X-API-Key header.",
        )
    
    # Validate API key via organization client
    org_client = await get_organization_client(request)
    api_ctx = await org_client.validate_api_key(api_key)
    
    if not api_ctx:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key",
        )
    
    return api_ctx


async def require_api_key_with_scope(*required_scopes: str):
    """Factory for creating an API key dependency with scope checking.
    
    Usage:
        @router.post("/api/v1/credentials")
        async def create_credential(
            api_ctx: ApiKeyContext = Depends(require_api_key_with_scope("write:credentials")),
        ):
            ...
    
    Args:
        *required_scopes: One or more scope strings that must be present
        
    Returns:
        FastAPI dependency function
    """
    async def _check_scopes(
        api_ctx: Annotated[ApiKeyContext, Depends(require_api_key)]
    ) -> ApiKeyContext:
        if not api_ctx.has_scope(*required_scopes):
            logger.warning(
                f"API key {api_ctx.key_prefix} attempted to access endpoint "
                f"requiring scopes {required_scopes}, but only has {api_ctx.scopes}"
            )
            scope_names = ", ".join(required_scopes)
            raise HTTPException(
                status_code=403,
                detail=f"API key missing required scopes: {scope_names}"
            )
        return api_ctx
    
    return _check_scopes


async def require_api_key_or_session(
    organization_id: str,
    request: Request,
    # API key parameters
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    # Session parameters
    x_user_id: Annotated[Optional[str], Header(alias="X-User-Id")] = None,
) -> OrganizationContext:
    """Allow either API key or session-based authentication.
    
    Tries API key first, falls back to session authentication.
    Returns OrganizationContext with source indicating auth method.
    
    Example:
        @router.post("/v1/organizations/{organization_id}/credentials")
        async def create_credential(
            organization_id: str,
            req: CreateCredentialRequest,
            org_ctx: OrganizationContext = Depends(require_api_key_or_session),
        ):
            # org_ctx.source will be "api_key" or "session"
            # org_ctx.organization_id contains the org ID
            ...
    """
    # Try API key authentication first
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]
    elif x_api_key:
        api_key = x_api_key
    
    if api_key:
        # Validate API key
        org_client = await get_organization_client(request)
        api_ctx = await org_client.validate_api_key(api_key)
        
        if api_ctx:
            # Verify the API key belongs to the requested organization
            if api_ctx.organization_id != organization_id:
                logger.warning(
                    f"API key from org {api_ctx.organization_id} attempted to "
                    f"access resources in org {organization_id}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="API key does not have access to this organization"
                )
            
            # API key is valid - return context
            return OrganizationContext(
                user_id="api_key",  # No specific user for API keys
                organization_id=api_ctx.organization_id,
                membership=None,  # API keys don't have membership
                source="api_key",
            )
    
    # Fall back to session authentication
    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide API key or valid session.",
        )
    
    # Verify membership using existing require_org_membership logic
    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(x_user_id, organization_id)
    
    if not membership:
        logger.warning(
            f"User {x_user_id} attempted to access organization {organization_id} "
            f"without membership"
        )
        raise HTTPException(
            status_code=403,
            detail="Not a member of this organization"
        )
    
    if not membership.is_active():
        logger.warning(
            f"User {x_user_id} attempted to access organization {organization_id} "
            f"with inactive membership (status: {membership.status})"
        )
        raise HTTPException(
            status_code=403,
            detail=f"Organization membership is {membership.status}"
        )
    
    return OrganizationContext(
        user_id=x_user_id,
        organization_id=organization_id,
        membership=membership,
        source="session",
    )
