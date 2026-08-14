"""Marty-owned gateway tests for standalone Verification routing and auth."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from gateway.middleware import AuthMiddleware, SessionCache
from gateway.registry import get_route_config
from gateway.routes.verification import (
    _bind_verification_management_context,
    verification_session_router,
)


def test_verification_route_is_authenticated_by_default() -> None:
    expected = {"service": "verification", "requires_auth": True}
    for path in (
        "/v1/verify",
        "/v1/verify/sessions",
        "/v1/verify/evaluate",
        "/v1/verify/session-a",
        "/v1/verify/session-a/inspection",
        "/v1/verify/session-a/request",
        "/v1/verify/session-a/submit",
    ):
        assert get_route_config(path) == expected


@pytest.mark.asyncio
async def test_only_exact_wallet_capability_paths_bypass_session_auth() -> None:
    app = FastAPI()
    app.state.auth_grpc_stub = SimpleNamespace()
    app.add_middleware(AuthMiddleware, session_cache=SessionCache())

    @app.get("/v1/verify/{session_id}/request")
    async def request_object(session_id: str):
        return {"session_id": session_id}

    @app.post("/v1/verify/{session_id}/submit")
    async def submit(session_id: str):
        return {"session_id": session_id}

    @app.get("/v1/verify/{session_id}")
    async def read(session_id: str):
        return {"session_id": session_id}

    @app.get("/v1/verify/sessions")
    async def sessions():
        return {"sessions": []}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        request_response = await client.get("/v1/verify/session-a/request")
        submit_response = await client.post("/v1/verify/session-a/submit")
        read_response = await client.get("/v1/verify/session-a")
        list_response = await client.get("/v1/verify/sessions")
        lookalike = await client.get("/v1/verify/session-a/request/extra")

    assert request_response.status_code == 200
    assert submit_response.status_code == 200
    assert read_response.status_code == 401
    assert list_response.status_code == 401
    assert lookalike.status_code == 401


def test_api_key_management_context_requires_verification_scope() -> None:
    accepted = Request(
        {"type": "http", "method": "POST", "path": "/v1/verify", "headers": []}
    )
    accepted.state.auth_source = "api_key"
    accepted.state.api_key_organization_id = "org-a"
    accepted.state.api_key_scopes = ["flows:execute"]

    _bind_verification_management_context(accepted)

    assert accepted.state.organization_id == "org-a"
    assert accepted.state.required_permission == "verification:execute"

    denied = Request(
        {"type": "http", "method": "POST", "path": "/v1/verify", "headers": []}
    )
    denied.state.auth_source = "api_key"
    denied.state.api_key_organization_id = "org-a"
    denied.state.api_key_scopes = ["credentials:issue"]

    with pytest.raises(HTTPException) as exc_info:
        _bind_verification_management_context(denied)
    assert exc_info.value.status_code == 403


def test_gateway_exposes_every_supported_verification_http_operation() -> None:
    routes = {
        (method, route.path)
        for route in verification_session_router.routes
        for method in (route.methods or set())
    }
    assert {
        ("POST", "/v1/verify"),
        ("GET", "/v1/verify/sessions"),
        ("POST", "/v1/verify/evaluate"),
        ("POST", "/v1/verify/zkp"),
        ("GET", "/v1/verify/{session_id}/request"),
        ("POST", "/v1/verify/{session_id}/submit"),
        ("GET", "/v1/verify/{session_id}/inspection"),
        ("GET", "/v1/verify/{session_id}"),
    } <= routes
