"""Gateway middleware for organization-scoped permission enforcement."""

from __future__ import annotations

import logging
import os
import re

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .cedar_actions import extract_org_id, resolve_action_and_resource, resolve_resource_lookup
from .org_authorization import OrganizationClient

logger = logging.getLogger(__name__)


class CedarAuthMiddleware(BaseHTTPMiddleware):
    """Permission-based authorization for org-scoped gateway routes."""

    SKIP_PATTERNS = [
        r"^/v1/organizations$",
        r"^/v1/organizations/mine$",
        r"^/v1/organizations/discover",
        r"^/v1/organizations/join/",
        r"^/v1/organizations/[^/]+/join$",
        r"^/v1/organizations/invitations/",
        r"^/v1/organizations/[^/]+/revocation-profiles/[^/]+/status-lists/[^/]+/[^/]+$",
        r"^/health",
        r"^/.well-known/",
    ]

    def __init__(self, app):
        super().__init__(app)
        self._skip_patterns = [re.compile(pattern) for pattern in self.SKIP_PATTERNS]

    @staticmethod
    def _forward_headers(request: Request, service_name: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        user_id = getattr(request.state, "user_id", None)
        user_email = getattr(request.state, "user_email", None)
        user_domain = getattr(request.state, "user_domain", None)
        if user_id:
            headers["X-User-Id"] = user_id
        if user_email:
            headers["X-User-Email"] = user_email
        if user_domain:
            headers["X-User-Domain"] = user_domain

        auth = request.headers.get("authorization")
        if auth:
            headers["Authorization"] = auth

        if service_name == "issuance":
            issuance_api_key = os.environ.get("ISSUANCE_API_KEY", "")
            if issuance_api_key:
                headers["X-API-Key"] = issuance_api_key

        return headers

    async def _extract_body_org_id(self, request: Request) -> str | None:
        if request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return None

        content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/json", "application/scim+json"}:
            return None

        try:
            payload = await request.json()
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        org_id = payload.get("organization_id")
        return org_id if isinstance(org_id, str) and org_id else None

    async def _lookup_resource_org_id(self, request: Request, path: str) -> str | None:
        lookup = resolve_resource_lookup(path)
        if not lookup:
            return None

        service_registry = getattr(request.app.state, "service_registry", None)
        http_client = getattr(request.app.state, "http_client", None)
        if service_registry is None or http_client is None:
            return None

        service_name, lookup_path = lookup
        service_url = service_registry.get_service_url(service_name)
        if not service_url:
            return None

        try:
            response = await http_client.get(
                f"{service_url}{lookup_path}",
                timeout=10.0,
                headers=self._forward_headers(request, service_name),
            )
        except Exception:
            return None

        if response.status_code >= 400:
            return None

        try:
            payload = response.json()
        except Exception:
            return None

        org_id = payload.get("organization_id") if isinstance(payload, dict) else None
        return org_id if isinstance(org_id, str) and org_id else None

    async def _resolve_request_org_id(self, request: Request, path: str) -> str | None:
        org_id = extract_org_id(path)
        if org_id:
            return org_id

        org_id = await self._lookup_resource_org_id(request, path)
        if org_id:
            return org_id

        query_org_id = request.query_params.get("organization_id")
        if query_org_id:
            return query_org_id

        return await self._extract_body_org_id(request)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(pattern.match(path) for pattern in self._skip_patterns):
            return await call_next(request)

        resolved = resolve_action_and_resource(request.method, path)
        if not resolved:
            return await call_next(request)

        required_permission, resource_name = resolved
        org_id = await self._resolve_request_org_id(request, path)
        if not org_id:
            return await call_next(request)

        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

        org_client: OrganizationClient | None = getattr(request.app.state, "org_client", None)
        if not org_client:
            logger.error("OrganizationClient not configured in app state")
            return JSONResponse(status_code=500, content={"detail": "Organization client not configured"})

        try:
            membership = await org_client.get_membership(user_id, org_id)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        except Exception as exc:
            logger.error("Error fetching membership: %s", exc, exc_info=True)
            return JSONResponse(status_code=500, content={"detail": "Internal server error"})

        if not membership:
            return JSONResponse(status_code=403, content={"detail": "Not a member of this organization"})

        if not membership.is_active():
            return JSONResponse(
                status_code=403,
                content={"detail": f"Organization membership is {membership.status}"},
            )

        allowed = False
        if required_permission == "organization:transfer-ownership":
            allowed = membership.is_owner
        else:
            allowed = membership.has_permission(required_permission)

        if not allowed:
            logger.warning(
                "Gateway deny: user=%s org=%s permission=%s roles=%s",
                user_id,
                org_id,
                required_permission,
                sorted(membership.role_names),
            )
            return JSONResponse(status_code=403, content={"detail": "Action not authorized"})

        request.state.organization_id = org_id
        request.state.required_permission = required_permission
        request.state.org_roles = sorted(membership.role_names)
        request.state.org_permissions = sorted(membership.permissions)
        request.state.org_resource = resource_name

        return await call_next(request)
