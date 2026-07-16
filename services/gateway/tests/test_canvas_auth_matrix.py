from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from gateway.middleware import AuthMiddleware, SessionCache
from gateway.registry import get_route_config, is_public_canvas_route
from gateway.routes.canvas_integrations import canvas_integration_router
from marty_common.cedar_actions import resolve_action


PUBLIC_CANVAS_ROUTES = [
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
    ("GET", "/v1/integrations/canvas/lti/experience-sessions/current/evidence-status"),
    ("POST", "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response"),
]

AUTHENTICATED_CANVAS_ROUTES = [
    ("GET", "/v1/integrations/canvas/platforms"),
    ("POST", "/v1/integrations/canvas/platforms"),
    ("GET", "/v1/integrations/canvas/platforms/platform-1"),
    ("GET", "/v1/integrations/canvas/platforms/platform-1/readiness"),
    ("GET", "/v1/integrations/canvas/platforms/platform-1/registration-config"),
    ("PUT", "/v1/integrations/canvas/platforms/platform-1/lti-installation"),
    ("POST", "/v1/integrations/canvas/platforms/platform-1/oauth/start"),
    ("POST", "/v1/integrations/canvas/platforms/platform-1/oauth/authorizations"),
    ("DELETE", "/v1/integrations/canvas/platforms/platform-1/oauth"),
    ("POST", "/v1/integrations/canvas/platforms/platform-1/scope-discovery"),
    ("GET", "/v1/integrations/canvas/program-bindings"),
    ("PUT", "/v1/integrations/canvas/program-bindings/binding-1"),
    ("POST", "/v1/integrations/canvas/program-bindings/binding-1/validate"),
    ("POST", "/v1/integrations/canvas/program-bindings/binding-1/activate"),
    ("POST", "/v1/integrations/canvas/applications/application-1/approve"),
    ("POST", "/v1/integrations/canvas/applications/application-1/canvas-sync"),
    ("GET", "/v1/integrations/canvas/canvas-sync-jobs/job-1"),
    ("POST", "/v1/integrations/canvas/canvas-sync-jobs/job-1/retry"),
    ("POST", "/v1/integrations/canvas/canvas-sync-jobs/job-1/resolve"),
    ("GET", "/v1/integrations/canvas/canvas-award-candidates"),
    ("GET", "/v1/integrations/canvas/evidence-policy-reviews"),
    ("POST", "/v1/integrations/canvas/evidence-policy-reviews/review-1/resolve"),
    ("POST", "/v1/integrations/canvas/canvas-credentials/validate"),
    ("GET", "/v1/integrations/canvas/integration-secrets"),
    ("DELETE", "/v1/integrations/canvas/integration-secrets/secret-1"),
    ("POST", "/v1/integrations/canvas/evidence-events"),
    ("POST", "/v1/integrations/canvas/ags/score-events"),
    ("POST", "/v1/integrations/canvas/nrps/membership-events"),
    ("GET", "/v1/integrations/canvas/evidence-events/account-1/event-1"),
    ("GET", "/v1/integrations/canvas/lti/jwks/extra"),
    ("GET", "/v1/integrations/canvas/platforms/platform-1/registration-config/extra"),
    ("GET", "/v1/integrations/canvas/oauth/callback/extra"),
    ("GET", "/v1/integrations/canvas/lti/experience-sessions/opaque-state"),
    ("POST", "/v1/integrations/canvas/lti/experience-sessions/opaque-state/unknown"),
    ("GET", "/v1/integrations/canvas/lti/experience-sessions/current/evidence-status/foreign-application"),
    ("GET", "/v1/integrations/canvas/lti/experience-sessions/foreign-session/evidence-status"),
    ("GET", "/v1/integrations/canvas/lti/current/evidence-status"),
]


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def reachable_route(path: str):
        return {"path": path}

    app.add_middleware(AuthMiddleware, session_cache=SessionCache())
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), PUBLIC_CANVAS_ROUTES)
async def test_canvas_protocol_allowlist_is_public(method: str, path: str) -> None:
    route_config = get_route_config(path)
    assert route_config == {"service": "issuance", "requires_auth": False}

    transport = httpx.ASGITransport(app=_build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.request(method, path)

    assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), AUTHENTICATED_CANVAS_ROUTES)
async def test_canvas_management_and_allowlist_lookalikes_require_auth(method: str, path: str) -> None:
    route_config = get_route_config(path)
    assert route_config == {"service": "issuance", "requires_auth": True}

    transport = httpx.ASGITransport(app=_build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.request(method, path)

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_every_canvas_management_route_has_connector_permission_and_auth_default() -> None:
    allowed_permissions = {
        "integration-connector:view",
        "integration-connector:create",
        "integration-connector:edit",
        "integration-connector:delete",
    }

    for route in canvas_integration_router.routes:
        for method in route.methods or set():
            if is_public_canvas_route(route.path):
                assert get_route_config(route.path) == {"service": "issuance", "requires_auth": False}
                continue

            assert get_route_config(route.path) == {"service": "issuance", "requires_auth": True}
            assert resolve_action(method, route.path) in allowed_permissions, (method, route.path)


def test_canvas_application_approval_requires_connector_edit_permission() -> None:
    assert (
        resolve_action(
            "POST",
            "/v1/integrations/canvas/applications/application-1/approve",
        )
        == "integration-connector:edit"
    )
