from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from marty_common.middleware import ETagMiddleware


@pytest.mark.asyncio
async def test_etag_middleware_skips_cookie_authenticated_get_requests():
    app = FastAPI()
    app.add_middleware(ETagMiddleware)

    @app.get("/v1/auth/me")
    async def current_user():
        return JSONResponse({"authenticated": True, "user": {"user_id": "user-1"}})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/v1/auth/me",
            cookies={"sessionId": "session-1"},
            headers={"If-None-Match": 'W/"stale"'},
        )

    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert "etag" not in {key.lower(): value for key, value in response.headers.items()}


@pytest.mark.asyncio
async def test_etag_middleware_respects_no_store_cache_control():
    app = FastAPI()
    app.add_middleware(ETagMiddleware)

    @app.get("/v1/me/preferences")
    async def preferences():
        return JSONResponse(
            {"last_view_mode": "applicant", "last_active_org_id": None},
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/v1/me/preferences",
            headers={"If-None-Match": 'W/"stale"'},
        )

    assert response.status_code == 200
    assert response.json()["last_view_mode"] == "applicant"
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert "etag" not in {key.lower(): value for key, value in response.headers.items()}
