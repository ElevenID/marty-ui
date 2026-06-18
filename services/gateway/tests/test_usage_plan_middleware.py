from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import Response

from gateway.plan_middleware import UsageTrackingMiddleware


def _build_request(*, tracker, plan: str, path: str = "/v1/issuance", method: str = "POST") -> Request:
    app = SimpleNamespace(state=SimpleNamespace(usage_tracker=tracker))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "app": app,
        "state": {},
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.organization_id = "org-1"
    request.state.org_plan = plan
    return request


@pytest.mark.asyncio
async def test_professional_plan_skips_sandbox_fair_use_enforcement():
    tracker = SimpleNamespace(
        get=AsyncMock(return_value=6000),
        increment=AsyncMock(),
        increment_gauge=AsyncMock(),
    )
    request = _build_request(tracker=tracker, plan="professional")
    middleware = UsageTrackingMiddleware(app=request.app)

    async def call_next(_request: Request) -> Response:
        return Response(status_code=200)

    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 200
    tracker.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_sandbox_plan_still_applies_fair_use_cap():
    tracker = SimpleNamespace(
        get=AsyncMock(return_value=6000),
        increment=AsyncMock(),
        increment_gauge=AsyncMock(),
    )
    request = _build_request(tracker=tracker, plan="sandbox")
    middleware = UsageTrackingMiddleware(app=request.app)

    async def call_next(_request: Request) -> Response:
        return Response(status_code=200)

    response = await middleware.dispatch(request, call_next)
    body = json.loads(response.body)

    assert response.status_code == 429
    assert body["error"] == "sandbox_fair_use_exceeded"
    tracker.get.assert_awaited_once_with("org-1", "sandbox_monthly_activity")
