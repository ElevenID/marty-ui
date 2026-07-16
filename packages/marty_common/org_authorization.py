"""Organization-scoped authorization for Marty microservices."""

from __future__ import annotations

import json
import logging
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
import redis.asyncio as aioredis


logger = logging.getLogger(__name__)


class OrganizationRoleSummary(BaseModel):
    """Lightweight organization role summary."""

    id: str
    name: str
    display_name: str | None = None


class OrganizationMembership(BaseModel):
    """User membership context returned by the organization service."""

    user_id: str
    organization_id: str
    status: str
    roles: list[OrganizationRoleSummary] = Field(default_factory=list)
    permissions: set[str] = Field(default_factory=set)
    has_org_console_access: bool = False
    is_owner: bool = False

    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def role_names(self) -> set[str]:
        return {role.name for role in self.roles}

    def has_role(self, *allowed_roles: str) -> bool:
        return bool(self.role_names & set(allowed_roles))

    def has_permission(self, resource: str, action: str | None = None) -> bool:
        permission_key = resource if action is None else f"{resource}:{action}"
        return permission_key in self.permissions


class OrganizationContext(BaseModel):
    """Context about the user's relationship to an organization."""

    user_id: str
    organization_id: str
    membership: Optional[OrganizationMembership] = None
    source: str = "session"  # "session" or "api_key"
    permissions: set[str] | None = None

    model_config = {"arbitrary_types_allowed": True}

    @property
    def roles(self) -> list[OrganizationRoleSummary]:
        return self.membership.roles if self.membership else []

    @property
    def role_names(self) -> set[str]:
        return self.membership.role_names if self.membership else set()

    @property
    def has_org_console_access(self) -> bool:
        return bool(self.membership and self.membership.has_org_console_access)

    @property
    def is_owner(self) -> bool:
        return bool(self.membership and self.membership.is_owner)

    def has_permission(self, resource: str, action: str | None = None) -> bool:
        permission_key = resource if action is None else f"{resource}:{action}"
        effective_permissions = self.permissions
        if effective_permissions is None and self.membership is not None:
            effective_permissions = self.membership.permissions
        return permission_key in (effective_permissions or set())


class ApiKeyContext(BaseModel):
    """Context for API key authentication."""

    api_key_id: str
    organization_id: str
    key_prefix: str
    scopes: list[str]

    def has_scope(self, *required_scopes: str) -> bool:
        return all(scope in self.scopes for scope in required_scopes)


class OrganizationClient:
    """Client for querying organization membership from the organization service."""

    def __init__(
        self,
        grpc_channel,
        redis_client: Optional[aioredis.Redis] = None,
        cache_ttl: int = 120,
        **_kwargs,
    ):
        self.redis_client = redis_client
        self.cache_ttl = cache_ttl
        from marty_proto.v1.organization_service_pb2_grpc import OrganizationServiceStub

        self._grpc_stub = OrganizationServiceStub(grpc_channel)
        self._grpc_channel = grpc_channel

    async def close(self):
        await self._grpc_channel.close()

    def _cache_key(self, user_id: str, organization_id: str) -> str:
        return f"org_membership:{user_id}:{organization_id}"

    async def _get_from_cache(self, user_id: str, organization_id: str) -> Optional[OrganizationMembership]:
        if not self.redis_client:
            return None

        try:
            key = self._cache_key(user_id, organization_id)
            data = await self.redis_client.get(key)
            if data:
                logger.debug("Cache HIT for membership %s in %s", user_id, organization_id)
                return OrganizationMembership.model_validate_json(data)
        except Exception as exc:
            logger.warning("Redis cache read error: %s", exc)

        return None

    async def _set_in_cache(self, membership: OrganizationMembership):
        if not self.redis_client:
            return

        try:
            key = self._cache_key(membership.user_id, membership.organization_id)
            await self.redis_client.setex(key, self.cache_ttl, membership.model_dump_json())
            logger.debug("Cached membership %s in %s", membership.user_id, membership.organization_id)
        except Exception as exc:
            logger.warning("Redis cache write error: %s", exc)

    async def invalidate_cache(self, user_id: str, organization_id: str):
        if not self.redis_client:
            return

        try:
            key = self._cache_key(user_id, organization_id)
            await self.redis_client.delete(key)
            await self.redis_client.delete(f"member_permissions:{user_id}:{organization_id}")
            logger.info("Invalidated cache for %s in %s", user_id, organization_id)
        except Exception as exc:
            logger.warning("Redis cache invalidation error: %s", exc)

    async def get_membership(self, user_id: str, organization_id: str) -> Optional[OrganizationMembership]:
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
                status=resp.status,
                roles=[
                    OrganizationRoleSummary(
                        id=role.id,
                        name=role.name,
                        display_name=role.display_name or None,
                    )
                    for role in resp.roles
                ],
                permissions=set(resp.permissions),
                has_org_console_access=bool(resp.has_org_console_access),
                is_owner=bool(resp.is_owner),
            )
            await self._set_in_cache(membership)
            return membership
        except grpc.aio.AioRpcError as exc:
            if exc.code() in (
                grpc.StatusCode.NOT_FOUND,
                grpc.StatusCode.UNKNOWN,
                grpc.StatusCode.INVALID_ARGUMENT,
            ):
                return None
            logger.error("gRPC error fetching membership: %s", exc)
            raise HTTPException(status_code=503, detail="Organization service unavailable")

    async def validate_api_key(self, api_key: str) -> Optional[ApiKeyContext]:
        from marty_proto.v1 import organization_service_pb2
        import grpc

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
        except grpc.aio.AioRpcError as exc:
            logger.error("gRPC error validating API key: %s", exc)
            raise HTTPException(status_code=503, detail="Organization service unavailable")
        except Exception as exc:
            logger.error("Unexpected error validating API key: %s", exc)
            raise HTTPException(status_code=503, detail="Organization service unavailable")


async def get_organization_client(request: Request) -> OrganizationClient:
    if not hasattr(request.app.state, "org_client"):
        raise HTTPException(status_code=500, detail="Organization client not configured")
    return request.app.state.org_client


async def require_org_membership(
    organization_id: str,
    request: Request,
    x_user_id: Annotated[Optional[str], Header(alias="X-User-Id")] = None,
) -> OrganizationContext:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Authentication required - missing user context")

    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(x_user_id, organization_id)

    if not membership:
        logger.warning(
            "User %s attempted to access organization %s without membership",
            x_user_id,
            organization_id,
        )
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    if not membership.is_active():
        logger.warning(
            "User %s attempted to access organization %s with inactive membership (%s)",
            x_user_id,
            organization_id,
            membership.status,
        )
        raise HTTPException(status_code=403, detail=f"Organization membership is {membership.status}")

    return OrganizationContext(
        user_id=x_user_id,
        organization_id=organization_id,
        membership=membership,
        permissions=set(membership.permissions),
    )


def require_org_role(*allowed_roles: str):
    """Compatibility helper for role-name based checks inside services."""

    async def _check_role(
        org_ctx: Annotated[OrganizationContext, Depends(require_org_membership)],
    ) -> OrganizationContext:
        if not org_ctx.membership or not org_ctx.membership.has_role(*allowed_roles):
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of these roles: {', '.join(sorted(allowed_roles))}",
            )
        return org_ctx

    return _check_role


def ensure_active_membership(
    membership: OrganizationMembership | None,
    *,
    detail: str = "Not a member of this organization",
) -> OrganizationMembership:
    """Validate that a membership exists and is active."""

    if membership is None:
        raise HTTPException(status_code=403, detail=detail)
    if not membership.is_active():
        raise HTTPException(
            status_code=403,
            detail=f"Organization membership is {membership.status}",
        )
    return membership


def ensure_membership_permission(
    membership: OrganizationMembership | None,
    resource: str,
    action: str,
    *,
    detail: str | None = None,
) -> OrganizationMembership:
    """Validate an active membership and a specific permission key."""

    active_membership = ensure_active_membership(membership)
    if not active_membership.has_permission(resource, action):
        permission_key = f"{resource}:{action}"
        raise HTTPException(
            status_code=403,
            detail=detail or f"Missing required permission: {permission_key}",
        )
    return active_membership


async def _load_member_permissions(
    request: Request,
    user_id: str,
    organization_id: str,
) -> set[str]:
    org_client: OrganizationClient = await get_organization_client(request)
    cache_key = f"member_permissions:{user_id}:{organization_id}"

    if org_client.redis_client:
        try:
            cached = await org_client.redis_client.get(cache_key)
            if cached:
                return set(json.loads(cached))
        except Exception as exc:
            logger.warning("Redis cache read error (permissions): %s", exc)

    membership = await org_client.get_membership(user_id, organization_id)
    if membership is None:
        return set()

    perms = set(membership.permissions)
    if org_client.redis_client and perms:
        try:
            await org_client.redis_client.setex(cache_key, 60, json.dumps(sorted(perms)))
        except Exception as exc:
            logger.warning("Redis cache write error (permissions): %s", exc)
    return perms


def require_permission(resource: str, action: str):
    """Factory for creating a permission-checking dependency."""

    async def _check_permission(
        request: Request,
        org_ctx: Annotated[OrganizationContext, Depends(require_org_membership)],
    ) -> OrganizationContext:
        if org_ctx.permissions is None:
            org_ctx.permissions = await _load_member_permissions(
                request,
                org_ctx.user_id,
                org_ctx.organization_id,
            )

        required_key = f"{resource}:{action}"
        if required_key not in org_ctx.permissions:
            logger.warning(
                "User %s denied permission %s in org %s",
                org_ctx.user_id,
                required_key,
                org_ctx.organization_id,
            )
            raise HTTPException(status_code=403, detail=f"Missing required permission: {required_key}")

        return org_ctx

    return _check_permission


async def require_org_admin(
    org_ctx: Annotated[OrganizationContext, Depends(require_permission("organization", "edit"))],
) -> OrganizationContext:
    return org_ctx


async def require_org_owner(
    org_ctx: Annotated[OrganizationContext, Depends(require_org_membership)],
) -> OrganizationContext:
    if not org_ctx.is_owner:
        raise HTTPException(status_code=403, detail="Organization owner access required")
    return org_ctx


async def require_api_key(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
) -> ApiKeyContext:
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]
    elif x_api_key:
        api_key = x_api_key

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide in Authorization header (Bearer <key>) or X-API-Key header.",
        )

    org_client = await get_organization_client(request)
    api_ctx = await org_client.validate_api_key(api_key)

    if not api_ctx:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    return api_ctx


async def require_api_key_with_scope(*required_scopes: str):
    async def _check_scopes(
        api_ctx: Annotated[ApiKeyContext, Depends(require_api_key)],
    ) -> ApiKeyContext:
        if not api_ctx.has_scope(*required_scopes):
            raise HTTPException(
                status_code=403,
                detail=f"API key missing required scopes: {', '.join(required_scopes)}",
            )
        return api_ctx

    return _check_scopes


async def require_api_key_or_session(
    organization_id: str,
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    x_user_id: Annotated[Optional[str], Header(alias="X-User-Id")] = None,
) -> OrganizationContext:
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]
    elif x_api_key:
        api_key = x_api_key

    if api_key:
        org_client = await get_organization_client(request)
        api_ctx = await org_client.validate_api_key(api_key)

        if api_ctx:
            if api_ctx.organization_id != organization_id:
                raise HTTPException(status_code=403, detail="API key does not have access to this organization")
            return OrganizationContext(
                user_id="api_key",
                organization_id=api_ctx.organization_id,
                membership=None,
                source="api_key",
            )

    if not x_user_id:
        raise HTTPException(status_code=401, detail="Authentication required. Provide API key or valid session.")

    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(x_user_id, organization_id)

    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    if not membership.is_active():
        raise HTTPException(status_code=403, detail=f"Organization membership is {membership.status}")

    return OrganizationContext(
        user_id=x_user_id,
        organization_id=organization_id,
        membership=membership,
        source="session",
        permissions=set(membership.permissions),
    )
