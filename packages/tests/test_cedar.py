"""Unit tests for permission-based gateway authorization helpers."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

from marty_common.cedar_actions import (
    GENERIC_RESOURCE_MAP,
    RESOURCE_LOOKUP_MAP,
    SPECIAL_ROUTE_RULES,
    extract_org_id,
    resolve_action,
    resolve_action_and_resource,
    resolve_resource_lookup,
)
from marty_common.cedar_engine import AuthzDecision, CedarEngine
from marty_common.cedar_entities import (
    build_apikey_entities,
    build_request_context,
    build_user_entities,
)
from marty_common.cedar_middleware import CedarAuthMiddleware


ORG_ID = "00000000-0000-0000-0000-000000000001"
ORG_PREFIX = f"/v1/organizations/{ORG_ID}/"


class FakeMembership:
    def __init__(
        self,
        *,
        permissions: set[str] | None = None,
        active: bool = True,
        is_owner: bool = False,
        role_names: set[str] | None = None,
    ) -> None:
        self.permissions = permissions or set()
        self._active = active
        self.is_owner = is_owner
        self.role_names = role_names or set()
        self.status = "active" if active else "invited"

    def is_active(self) -> bool:
        return self._active

    def has_permission(self, permission_key: str, action: str | None = None) -> bool:
        if action is not None:
            permission_key = f"{permission_key}:{action}"
        return permission_key in self.permissions


def _build_request(
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    app: object | None = None,
) -> Request:
    payload = body

    async def receive():
        nonlocal payload
        current = payload
        payload = b""
        return {"type": "http.request", "body": current, "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [
            (key.lower().encode(), value.encode())
            for key, value in (headers or {}).items()
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "app": app,
    }
    return Request(scope, receive)


class TestResolveAction:
    def test_generic_org_routes_map_to_permission_keys(self):
        assert resolve_action("GET", ORG_PREFIX + "flows") == "flow-definition:view"
        assert resolve_action("POST", ORG_PREFIX + "flow-instances") == "flow-instance:start"
        assert resolve_action("PATCH", ORG_PREFIX + "trust-profiles/profile-1") == "trust-profile:edit"
        assert resolve_action("DELETE", ORG_PREFIX + "deployment-profiles/profile-1") == "deployment-profile:delete"
        assert resolve_action("GET", ORG_PREFIX + "policy-sets") == "policy-set:view"
        assert resolve_action("POST", ORG_PREFIX + "policy-sets") == "policy-set:create"
        assert resolve_action("PATCH", ORG_PREFIX + "policy-sets/policy-1") == "policy-set:edit"
        assert resolve_action("DELETE", ORG_PREFIX + "policy-sets/policy-1") == "policy-set:delete"

    def test_policy_set_lifecycle_routes_map_to_specific_permissions(self):
        assert resolve_action("POST", ORG_PREFIX + "policy-sets/policy-1/activate") == "policy-set:activate"
        assert resolve_action("POST", ORG_PREFIX + "policy-sets/policy-1/archive") == "policy-set:archive"
        assert resolve_action("POST", ORG_PREFIX + "policy-sets/validate") == "policy-set:validate"
        assert resolve_action("POST", ORG_PREFIX + "policy-sets/policy-1/validate") == "policy-set:validate"
        assert resolve_action("POST", "/v1/policy-sets/validate") == "policy-set:validate"
        assert resolve_action("POST", "/v1/policy-sets/policy-1/activate") == "policy-set:activate"

    def test_special_routes_take_precedence(self):
        assert resolve_action("GET", ORG_PREFIX + "members") == "team:view"
        assert resolve_action("POST", ORG_PREFIX + "members") == "team:invite"
        assert resolve_action("GET", ORG_PREFIX + "roles") == "role:view"
        assert resolve_action("POST", ORG_PREFIX + "transfer-ownership") == "organization:transfer-ownership"
        assert resolve_action("GET", ORG_PREFIX + "dashboard/applicant-stats") == "application:review"

    def test_top_level_routes_use_same_permission_namespace(self):
        assert resolve_action("POST", "/v1/application-templates") == "application-template:create"
        assert resolve_action("GET", "/v1/application-templates/template-123") == "application-template:view"
        assert resolve_action("POST", "/v1/verification") == "verification:execute"
        assert resolve_action("POST", "/v1/integrations/canvas/platforms") == "integration-connector:create"
        assert resolve_action("GET", "/v1/integrations/canvas/platforms/platform-123") == "integration-connector:view"
        assert resolve_action("POST", "/v1/flows/instances") == "flow-instance:start"
        assert resolve_action("GET", "/v1/flows/instances") == "flow-instance:view"
        assert resolve_action("POST", "/v1/flows/definitions") == "flow-definition:create"
        assert resolve_action("POST", "/v1/flows/definitions/flow-1/activate") == "flow-definition:activate"
        assert resolve_action("POST", "/v1/flows/verify") == "verification:execute"
        assert resolve_action("GET", "/v1/issued-credentials") == "issuance:view"
        assert resolve_action("POST", "/v1/issued-credentials/credential-1/suspend") == "issuance:revoke"
        assert resolve_action("POST", "/v1/issued-credentials/credential-1/reinstate") == "issuance:revoke"
        assert resolve_action("POST", "/v1/issued-credentials/credential-1/revoke") == "issuance:revoke"
        assert resolve_action("POST", "/v1/issued-credentials/credential-1/renew") == "issuance:initiate"
        assert resolve_action("POST", "/v1/credential-templates/template-1/activate") == "credential-template:activate"
        assert resolve_action("POST", "/v1/credential-templates/template-1/deprecate") == "credential-template:deprecate"
        assert resolve_action("POST", "/v1/credential-templates/template-1/new-version") == "credential-template:version"
        assert resolve_action("POST", "/v1/revocation-profiles/profile-1/activate") == "revocation-profile:activate"

    def test_canvas_management_actions_use_connector_permissions(self):
        assert resolve_action("GET", "/v1/integrations/canvas/platforms/platform-1/readiness") == (
            "integration-connector:view"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/scope-discovery") == (
            "integration-connector:view"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/canvas-credentials/validate") == (
            "integration-connector:view"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/sandbox-probe") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/jwks-refresh") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/oauth/start") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/oauth/authorizations") == (
            "integration-connector:edit"
        )
        assert resolve_action("PUT", "/v1/integrations/canvas/platforms/platform-1/lti-installation") == (
            "integration-connector:edit"
        )
        assert resolve_action("DELETE", "/v1/integrations/canvas/platforms/platform-1/oauth") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/platforms/platform-1/program-bindings") == (
            "integration-connector:create"
        )
        assert resolve_action("PUT", "/v1/integrations/canvas/program-bindings/binding-1") == (
            "integration-connector:edit"
        )
        assert resolve_action("DELETE", "/v1/integrations/canvas/program-bindings/binding-1") == (
            "integration-connector:delete"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/program-bindings/binding-1/validate") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/program-bindings/binding-1/activate") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/canvas-sync-jobs/job-1/retry") == (
            "integration-connector:edit"
        )
        assert resolve_action("POST", "/v1/integrations/canvas/evidence-policy-reviews/review-1/resolve") == (
            "integration-connector:edit"
        )

    def test_head_and_options_count_as_view(self):
        assert resolve_action("HEAD", ORG_PREFIX + "flows") == "flow-definition:view"
        assert resolve_action("OPTIONS", ORG_PREFIX + "deployment-profiles") == "deployment-profile:view"

    def test_unknown_routes_return_none(self):
        assert resolve_action("GET", ORG_PREFIX + "unknown-thing") is None
        assert resolve_action("GET", "/health") is None


class TestResolveActionAndResource:
    def test_generic_resource_tuple(self):
        assert resolve_action_and_resource("POST", ORG_PREFIX + "trust-profiles") == (
            "trust-profile:create",
            "trust-profile",
        )

    def test_special_route_tuple(self):
        assert resolve_action_and_resource("GET", ORG_PREFIX + "members") == (
            "team:view",
            "team",
        )

    def test_detail_route_uses_top_level_segment(self):
        assert resolve_action_and_resource("POST", "/v1/deployment-profiles/profile-123/lanes") == (
            "deployment-profile:create",
            "deployment-profile",
        )

    def test_all_generic_segments_map_for_get(self):
        for segment in GENERIC_RESOURCE_MAP:
            result = resolve_action_and_resource("GET", ORG_PREFIX + segment)
            assert result is not None, f"GET {segment} should resolve"

    def test_special_route_rules_have_at_least_one_mapping(self):
        assert SPECIAL_ROUTE_RULES
        for _pattern, method_map, resource_name in SPECIAL_ROUTE_RULES:
            assert method_map
            assert resource_name


class TestExtractOrgId:
    def test_extracts_uuid(self):
        assert extract_org_id(ORG_PREFIX + "members") == ORG_ID

    def test_non_org_path(self):
        assert extract_org_id("/health") is None


class TestResolveResourceLookup:
    def test_application_template_lookup(self):
        assert resolve_resource_lookup("/v1/application-templates/template-123") == (
            "issuance",
            "/v1/application-templates/template-123",
        )

    def test_policy_set_lookup(self):
        assert resolve_resource_lookup("/v1/policy-sets/policy-123") == (
            "organizations",
            "/v1/policy-sets/policy-123",
        )

    def test_deployment_lane_lookup_uses_parent_profile(self):
        assert resolve_resource_lookup("/v1/deployment-profiles/profile-123/lanes") == (
            "deployment-profiles",
            "/v1/deployment-profiles/profile-123",
        )

    def test_reserved_subresource_has_no_lookup(self):
        assert resolve_resource_lookup("/v1/issuance/offers/tx-123") is None
        assert resolve_resource_lookup("/v1/flows/definitions") is None
        assert resolve_resource_lookup("/v1/flows/instances") is None
        assert resolve_resource_lookup("/v1/flows/verify") is None

    def test_nested_flow_resources_lookup_the_persisted_organization(self):
        assert resolve_resource_lookup("/v1/flows/definitions/flow-123/activate") == (
            "flows",
            "/v1/flows/definitions/flow-123",
        )
        assert resolve_resource_lookup("/v1/flows/instances/instance-123") == (
            "flows",
            "/v1/flows/instances/instance-123",
        )

    def test_canvas_resources_lookup_the_persisted_organization(self):
        assert resolve_resource_lookup("/v1/integrations/canvas/platforms/platform-123/readiness") == (
            "issuance",
            "/v1/integrations/canvas/platforms/platform-123",
        )
        assert resolve_resource_lookup("/v1/integrations/canvas/program-bindings/binding-123") == (
            "issuance",
            "/v1/integrations/canvas/program-bindings/binding-123",
        )

    def test_all_lookup_templates_have_paths(self):
        for service_name, lookup_template, _reserved_segments in RESOURCE_LOOKUP_MAP.values():
            assert service_name
            assert lookup_template.startswith("/v1/")


@pytest.mark.asyncio
async def test_cedar_middleware_authorizes_top_level_create_from_body_org():
    membership = FakeMembership(permissions={"application-template:create"}, role_names={"catalog_admin"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(
        "/v1/application-templates",
        method="POST",
        headers={"content-type": "application/json"},
        body=b'{"organization_id":"00000000-0000-0000-0000-000000000001","name":"Template"}',
        app=app,
    )
    request.state.user_id = "user-1"
    request.state.user_email = "user@example.com"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.organization_id == ORG_ID
    assert request.state.required_permission == "application-template:create"
    assert request.state.org_roles == ["catalog_admin"]
    assert request.state.org_permissions == ["application-template:create"]
    org_client.get_membership.assert_awaited_once_with("user-1", ORG_ID)


@pytest.mark.asyncio
async def test_cedar_middleware_looks_up_owner_org_for_top_level_detail_route():
    membership = FakeMembership(permissions={"application-template:view"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    service_registry = MagicMock()
    service_registry.get_service_url.return_value = "http://issuance-service:8005"

    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    http_client = MagicMock()
    http_client.get = AsyncMock(return_value=upstream_response)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = service_registry
    app.state.http_client = http_client

    request = _build_request("/v1/application-templates/template-123", method="GET", app=app)
    request.state.user_id = "user-1"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.organization_id == ORG_ID
    assert request.state.required_permission == "application-template:view"
    http_client.get.assert_awaited_once()
    org_client.get_membership.assert_awaited_once_with("user-1", ORG_ID)


@pytest.mark.asyncio
async def test_cedar_middleware_looks_up_canvas_platform_owner_org():
    membership = FakeMembership(permissions={"integration-connector:view"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    service_registry = MagicMock()
    service_registry.get_service_url.return_value = "http://issuance-service:8005"
    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    http_client = MagicMock()
    http_client.get = AsyncMock(return_value=upstream_response)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = service_registry
    app.state.http_client = http_client

    request = _build_request(
        "/v1/integrations/canvas/platforms/platform-123/readiness",
        method="GET",
        app=app,
    )
    request.state.user_id = "user-1"
    request.state.session_organization_id = "00000000-0000-0000-0000-000000000999"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.organization_id == ORG_ID
    assert request.state.required_permission == "integration-connector:view"
    service_registry.get_service_url.assert_called_with("issuance")
    http_client.get.assert_awaited_once()
    org_client.get_membership.assert_awaited_once_with("user-1", ORG_ID)


@pytest.mark.asyncio
async def test_cedar_middleware_authorizes_issued_credential_lifecycle_from_persisted_org():
    membership = FakeMembership(permissions={"issuance:revoke"}, role_names={"operator"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    service_registry = MagicMock()
    service_registry.get_service_url.return_value = "http://issuance-service:8005"
    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    http_client = MagicMock()
    http_client.get = AsyncMock(return_value=upstream_response)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = service_registry
    app.state.http_client = http_client

    request = _build_request(
        "/v1/issued-credentials/credential-123/suspend",
        method="POST",
        app=app,
    )
    request.state.user_id = "user-1"
    request.state.session_organization_id = "00000000-0000-0000-0000-000000000999"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.organization_id == ORG_ID
    assert request.state.required_permission == "issuance:revoke"
    service_registry.get_service_url.assert_called_with("issuance")
    http_client.get.assert_awaited_once()
    org_client.get_membership.assert_awaited_once_with("user-1", ORG_ID)


@pytest.mark.asyncio
async def test_cedar_middleware_denies_cross_org_issued_credential_lifecycle():
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=None)

    service_registry = MagicMock()
    service_registry.get_service_url.return_value = "http://issuance-service:8005"
    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    http_client = MagicMock()
    http_client.get = AsyncMock(return_value=upstream_response)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = service_registry
    app.state.http_client = http_client

    request = _build_request(
        "/v1/issued-credentials/credential-123/revoke",
        method="POST",
        app=app,
    )
    request.state.user_id = "user-1"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 403
    assert json.loads(response.body) == {"detail": "Not a member of this organization"}
    call_next.assert_not_awaited()


@pytest.mark.asyncio
async def test_cedar_middleware_maps_api_key_revoke_scope_to_lifecycle_permission():
    app = MagicMock()
    app.state.org_client = MagicMock()
    app.state.service_registry = MagicMock()
    app.state.service_registry.get_service_url.return_value = "http://issuance-service:8005"
    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    app.state.http_client = MagicMock()
    app.state.http_client.get = AsyncMock(return_value=upstream_response)

    request = _build_request(
        "/v1/issued-credentials/credential-123/revoke",
        method="POST",
        app=app,
    )
    request.state.auth_source = "api_key"
    request.state.api_key_id = "key-1"
    request.state.api_key_organization_id = ORG_ID
    request.state.organization_id = ORG_ID
    request.state.api_key_scopes = ["credentials:revoke"]

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.required_permission == "issuance:revoke"
    call_next.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_cedar_middleware_uses_flow_instance_org_instead_of_session_default():
    membership = FakeMembership(permissions={"flow-instance:view"}, role_names={"operator"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    service_registry = MagicMock()
    service_registry.get_service_url.return_value = "http://flow-service:8006"

    upstream_response = MagicMock()
    upstream_response.status_code = 200
    upstream_response.json.return_value = {"organization_id": ORG_ID}
    http_client = MagicMock()
    http_client.get = AsyncMock(return_value=upstream_response)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = service_registry
    app.state.http_client = http_client

    request = _build_request("/v1/flows/instances/instance-123", method="GET", app=app)
    request.state.user_id = "user-1"
    request.state.organization_id = "00000000-0000-0000-0000-000000000999"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.organization_id == ORG_ID
    assert request.state.required_permission == "flow-instance:view"
    service_registry.get_service_url.assert_called_with("flows")
    http_client.get.assert_awaited_once()
    org_client.get_membership.assert_awaited_once_with("user-1", ORG_ID)


@pytest.mark.asyncio
async def test_cedar_middleware_denies_missing_permission():
    membership = FakeMembership(permissions={"application-template:view"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(
        "/v1/application-templates",
        method="POST",
        headers={"content-type": "application/json"},
        body=b'{"organization_id":"00000000-0000-0000-0000-000000000001","name":"Template"}',
        app=app,
    )
    request.state.user_id = "user-1"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 403
    assert json.loads(response.body) == {"detail": "Action not authorized"}


@pytest.mark.asyncio
async def test_cedar_middleware_allows_scoped_api_key_flow_execution():
    org_client = MagicMock()
    org_client.get_membership = AsyncMock()

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request("/v1/flows/instances", method="POST", app=app)
    request.state.auth_source = "api_key"
    request.state.api_key_id = "key-1"
    request.state.api_key_organization_id = ORG_ID
    request.state.organization_id = ORG_ID
    request.state.api_key_scopes = ["flows:execute"]

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    assert request.state.required_permission == "flow-instance:start"
    assert request.state.org_permissions == ["flows:execute"]
    org_client.get_membership.assert_not_called()


@pytest.mark.asyncio
async def test_cedar_middleware_denies_api_key_missing_required_scope():
    app = MagicMock()
    app.state.org_client = MagicMock()
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request("/v1/flows/instances", method="POST", app=app)
    request.state.auth_source = "api_key"
    request.state.api_key_id = "key-1"
    request.state.api_key_organization_id = ORG_ID
    request.state.organization_id = ORG_ID
    request.state.api_key_scopes = ["flows:read"]

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 403
    assert "API key missing required permission" in json.loads(response.body)["detail"]


@pytest.mark.asyncio
async def test_cedar_middleware_denies_api_key_org_mismatch():
    app = MagicMock()
    app.state.org_client = MagicMock()
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(ORG_PREFIX + "flows", method="GET", app=app)
    request.state.auth_source = "api_key"
    request.state.api_key_id = "key-1"
    request.state.api_key_organization_id = "00000000-0000-0000-0000-000000000999"
    request.state.organization_id = "00000000-0000-0000-0000-000000000999"
    request.state.api_key_scopes = ["flows:read"]

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 403
    assert json.loads(response.body)["detail"] == "API key does not have access to this organization"


def test_cedar_middleware_maps_integration_connector_api_key_scopes():
    assert CedarAuthMiddleware._api_key_allowed(
        "integration-connector:view",
        ["integrations:read"],
    )
    assert CedarAuthMiddleware._api_key_allowed(
        "integration-connector:view",
        ["integrations:write"],
    )
    assert CedarAuthMiddleware._api_key_allowed(
        "integration-connector:create",
        ["integrations:write"],
    )
    assert not CedarAuthMiddleware._api_key_allowed(
        "integration-connector:edit",
        ["integrations:read"],
    )


def test_cedar_resource_lookup_reads_issuance_key_from_secret_file(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    secret_file = tmp_path / "issuance-api-key"
    secret_file.write_text("file-backed-secret\n", encoding="utf-8")
    monkeypatch.delenv("ISSUANCE_API_KEY", raising=False)
    monkeypatch.setenv("ISSUANCE_API_KEY_FILE", str(secret_file))

    request = _build_request("/v1/integrations/canvas/platforms/platform-1")

    assert CedarAuthMiddleware._forward_headers(request, "issuance") == {
        "X-API-Key": "file-backed-secret"
    }


@pytest.mark.asyncio
async def test_cedar_middleware_treats_flow_capabilities_as_org_neutral():
    org_client = MagicMock()
    org_client.get_membership = AsyncMock()

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request("/v1/flows/capabilities", method="GET", app=app)
    request.state.user_id = "user-1"
    request.state.organization_id = "00000000-0000-0000-0000-000000000999"

    call_next = AsyncMock(return_value=JSONResponse({"protocol_version": "0.3.1"}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    call_next.assert_awaited_once_with(request)
    org_client.get_membership.assert_not_called()


@pytest.mark.asyncio
async def test_cedar_middleware_requires_owner_for_transfer():
    membership = FakeMembership(is_owner=False, permissions={"organization:view"})
    org_client = MagicMock()
    org_client.get_membership = AsyncMock(return_value=membership)

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(ORG_PREFIX + "transfer-ownership", method="POST", app=app)
    request.state.user_id = "user-1"

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_cedar_middleware_skips_public_status_list_document():
    org_client = MagicMock()
    org_client.get_membership = AsyncMock()

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(
        ORG_PREFIX
        + "revocation-profiles/70000000-0000-0000-0000-000000000001"
        + "/status-lists/bitstring-status-list/revocation",
        method="GET",
        app=app,
    )

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    call_next.assert_awaited_once_with(request)
    org_client.get_membership.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/integrations/canvas/lti/jwks"),
        ("GET", "/v1/integrations/canvas/lti/config/revocable-registration-token"),
        ("POST", "/v1/integrations/canvas/lti/platforms/platform-1/login"),
        ("POST", "/v1/integrations/canvas/lti/platforms/platform-1/experience-login"),
        ("POST", "/v1/integrations/canvas/lti/platforms/platform-1/launch"),
        ("POST", "/v1/integrations/canvas/lti/platforms/platform-1/experience"),
        ("GET", "/v1/integrations/canvas/oauth/callback"),
        ("POST", "/v1/integrations/canvas/lti/experience-sessions/exchange"),
        ("GET", "/v1/integrations/canvas/lti/experience-sessions/current"),
        ("POST", "/v1/integrations/canvas/lti/experience-sessions/current/bootstrap"),
        ("POST", "/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync"),
        ("POST", "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response"),
    ],
)
async def test_cedar_middleware_skips_public_canvas_protocol_routes(method: str, path: str):
    org_client = MagicMock()
    org_client.get_membership = AsyncMock()

    app = MagicMock()
    app.state.org_client = org_client
    app.state.service_registry = None
    app.state.http_client = None

    request = _build_request(path, method=method, app=app)
    request.state.organization_id = ORG_ID

    call_next = AsyncMock(return_value=JSONResponse({"ok": True}))
    middleware = CedarAuthMiddleware(app=MagicMock())

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    call_next.assert_awaited_once_with(request)
    org_client.get_membership.assert_not_called()


class TestBuildUserEntities:
    def test_basic_user(self):
        entities = build_user_entities("u-1", "alice@test.com", "ACTIVE", "org-1", "member")
        assert len(entities) == 3

        user = next(e for e in entities if e["uid"]["type"] == "MIP::User")
        assert user["uid"]["id"] == "u-1"
        assert user["attrs"]["email"] == "alice@test.com"
        assert user["attrs"]["user_id"] == "u-1"
        assert {"type": "MIP::Organization", "id": "org-1"} in user["parents"]
        assert {"type": "MIP::Role", "id": "member"} in user["parents"]

    def test_role_entity_is_lowercased(self):
        entities = build_user_entities("u", "e", "ACTIVE", "org-1", "Owner")
        role = next(e for e in entities if e["uid"]["type"] == "MIP::Role")
        assert role["uid"]["id"] == "owner"


class TestBuildApiKeyEntities:
    def test_org_scoped_key(self):
        entities = build_apikey_entities("key-1", "org-1", "ORGANIZATION", enabled=True)
        assert len(entities) == 2
        key = next(e for e in entities if e["uid"]["type"] == "MIP::ApiKey")
        assert key["attrs"]["scope_type"] == "ORGANIZATION"
        assert key["attrs"]["enabled"] is True

    def test_deployment_scoped_key(self):
        entities = build_apikey_entities(
            "key-2",
            "org-1",
            "DEPLOYMENT",
            enabled=True,
            deployment_profile_id="dp-1",
        )
        assert len(entities) == 3
        key = next(e for e in entities if e["uid"]["type"] == "MIP::ApiKey")
        assert {"type": "MIP::DeploymentProfile", "id": "dp-1"} in key["parents"]


class TestBuildRequestContext:
    def test_minimal(self):
        ctx = build_request_context(ip_address="10.0.0.1")
        assert ctx["ip_address"] == {"__extn": {"fn": "ip", "arg": "10.0.0.1"}}
        assert isinstance(ctx["timestamp"], int)
        assert ctx["mfa_authenticated"] is False

    def test_timestamp_is_recent(self):
        before = int(time.time())
        ctx = build_request_context(ip_address="127.0.0.1")
        after = int(time.time())
        assert before <= ctx["timestamp"] <= after


class TestAuthzDecision:
    def test_defaults(self):
        d = AuthzDecision(allowed=True)
        assert d.reasons == []
        assert d.errors == []

    def test_immutable(self):
        d = AuthzDecision(allowed=True)
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]


class TestCedarEngine:
    def test_policies_property(self):
        engine = CedarEngine(schema="s", policies="p1")
        assert engine.policies == "p1"
        engine.policies = "p2"
        assert engine.policies == "p2"

    def test_append_policies(self):
        engine = CedarEngine(schema="s", policies="first")
        engine.append_policies("second")
        assert "first" in engine.policies
        assert "second" in engine.policies

    @patch("marty_common.cedar_engine.cedarpy")
    def test_is_authorized_allowed(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = ["policy-1"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = CedarEngine(schema="schema", policies="policies")
        decision = engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"x"',
            resource='MIP::Organization::"org-1"',
            context={},
            entities=[],
        )
        assert decision.allowed is True
        assert decision.reasons == ["policy-1"]

    @patch("marty_common.cedar_engine.cedarpy")
    def test_entities_serialized_as_json(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = []
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        entities = [{"uid": {"type": "MIP::User", "id": "u-1"}, "attrs": {}, "parents": []}]
        engine = CedarEngine(schema="s", policies="p")
        engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"x"',
            resource='MIP::Organization::"o"',
            context={},
            entities=entities,
        )

        call_args = mock_cedar.is_authorized.call_args[0]
        entities_arg = call_args[2]
        assert json.loads(entities_arg) == entities
