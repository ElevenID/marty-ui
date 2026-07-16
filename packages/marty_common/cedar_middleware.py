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


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name)
    if direct:
        return direct

    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


class CedarAuthMiddleware(BaseHTTPMiddleware):
    """Permission-based authorization for org-scoped gateway routes."""

    SKIP_PATTERNS = [
        r"^/v1/flows/capabilities$",
        r"^/v1/issued-credentials/mine$",
        r"^/v1/organizations$",
        r"^/v1/organizations/mine$",
        r"^/v1/organizations/discover",
        r"^/v1/organizations/join/",
        r"^/v1/organizations/[^/]+/join$",
        r"^/v1/organizations/invitations/",
        r"^/v1/organizations/[^/]+/revocation-profiles/[^/]+/status-lists/[^/]+/[^/]+$",
        r"^/v1/integrations/canvas/lti/jwks/?$",
        r"^/v1/integrations/canvas/lti/config/[^/]+/?$",
        r"^/v1/integrations/canvas/lti/platforms/[^/]+/(?:login|experience-login|launch|experience)/?$",
        r"^/v1/integrations/canvas/oauth/callback/?$",
        r"^/v1/integrations/canvas/lti/experience-sessions/(?:exchange|current(?:/(?:bootstrap|evidence-sync|deep-linking-response))?)/?$",
        r"^/health",
        r"^/.well-known/",
    ]

    def __init__(self, app):
        super().__init__(app)
        self._skip_patterns = [re.compile(pattern) for pattern in self.SKIP_PATTERNS]

    @staticmethod
    def _api_key_allowed(required_permission: str, scopes: list[str]) -> bool:
        scope_set = set(scopes or [])
        if "admin:full" in scope_set:
            return True

        resource, _, action = required_permission.partition(":")
        read_action = action in {"view", "read", "list"}
        write_action = action in {"create", "edit", "delete", "write", "activate", "archive", "validate"}

        resource_scopes: dict[str, tuple[str, str]] = {
            "credential-template": ("templates:read", "templates:write"),
            "application-template": ("applications:read", "applications:write"),
            "application": ("applications:read", "applications:write"),
            "trust-profile": ("trust:read", "trust:write"),
            "issuer-entity": ("trust:read", "trust:write"),
            "presentation-policy": ("trust:read", "trust:write"),
            "compliance-profile": ("compliance:read", "compliance:write"),
            "deployment-profile": ("deployment:read", "deployment:write"),
            "webhook": ("webhooks:read", "webhooks:write"),
            "notification": ("notifications:read", "notifications:send"),
            "team": ("users:read", "users:invite"),
            "role": ("roles:read", "roles:write"),
            "policy-set": ("trust:read", "trust:admin"),
            "organization": ("users:read", "users:invite"),
            "integration-connector": ("integrations:read", "integrations:write"),
        }

        if resource == "flow-instance":
            return "flows:execute" in scope_set or "flows:write" in scope_set
        if resource == "flow-definition":
            if read_action:
                return bool(scope_set & {"flows:read", "flows:write", "flows:execute"})
            return "flows:write" in scope_set
        if resource == "api-key":
            return False
        if resource == "verification":
            return "flows:execute" in scope_set or "credentials:read" in scope_set
        if resource == "issued-credential":
            if action in {"issue", "create"}:
                return "credentials:issue" in scope_set
            if action in {"revoke", "delete"}:
                return "credentials:revoke" in scope_set
            return bool(scope_set & {"credentials:read", "credentials:issue"})
        if resource == "issuance":
            if action == "initiate":
                return "credentials:issue" in scope_set
            if action == "revoke":
                return "credentials:revoke" in scope_set
            return bool(scope_set & {"credentials:read", "credentials:issue"})

        mapped_scopes = resource_scopes.get(resource)
        if not mapped_scopes:
            return False
        read_scope, write_scope = mapped_scopes
        if read_action:
            return read_scope in scope_set or write_scope in scope_set
        if write_action:
            return write_scope in scope_set
        return False

    @staticmethod
    def _forward_headers(request: Request, service_name: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        user_id = getattr(request.state, "user_id", None)
        user_email = getattr(request.state, "user_email", None)
        user_domain = getattr(request.state, "user_domain", None)
        organization_id = getattr(request.state, "organization_id", None)
        api_key_id = getattr(request.state, "api_key_id", None)
        api_key_scopes = getattr(request.state, "api_key_scopes", None)
        if user_id:
            headers["X-User-Id"] = user_id
        if user_email:
            headers["X-User-Email"] = user_email
        if user_domain:
            headers["X-User-Domain"] = user_domain
        if organization_id:
            headers["X-Organization-ID"] = organization_id
        if api_key_id:
            headers["X-Api-Key-Id"] = api_key_id
        if api_key_scopes:
            headers["X-Api-Key-Scopes"] = ",".join(str(scope) for scope in api_key_scopes)

        auth = request.headers.get("authorization")
        if auth:
            headers["Authorization"] = auth

        if service_name == "issuance":
            issuance_api_key = _read_secret_value("ISSUANCE_API_KEY")
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

        body_org_id = await self._extract_body_org_id(request)
        if body_org_id:
            return body_org_id

        state_org_id = (
            getattr(request.state, "organization_id", None)
            or getattr(request.state, "session_organization_id", None)
            or getattr(request.state, "api_key_organization_id", None)
        )
        return state_org_id if isinstance(state_org_id, str) and state_org_id else None

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

        if getattr(request.state, "auth_source", None) == "api_key":
            api_key_org_id = getattr(request.state, "api_key_organization_id", None)
            if api_key_org_id != org_id:
                return JSONResponse(status_code=403, content={"detail": "API key does not have access to this organization"})

            api_key_scopes = list(getattr(request.state, "api_key_scopes", []) or [])
            if not self._api_key_allowed(required_permission, api_key_scopes):
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"API key missing required permission: {required_permission}"},
                )

            request.state.organization_id = org_id
            request.state.required_permission = required_permission
            request.state.org_roles = ["api_key"]
            request.state.org_permissions = sorted(api_key_scopes)
            request.state.org_resource = resource_name
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
