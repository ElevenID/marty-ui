"""Tests for gateway.middleware — SessionCache, AuthMiddleware, RateLimitMiddleware."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gateway.middleware import (
    AuthMiddleware,
    RateLimitMiddleware,
    SessionCache,
    _RATE_LIMIT_RPM,
)

# ---------------------------------------------------------------------------
# Helpers: fake gRPC response objects
# ---------------------------------------------------------------------------

def _make_grpc_user(**overrides):
    defaults = {
        "user_id": "u-123",
        "email": "alice@example.com",
        "username": "alice",
        "given_name": "Alice",
        "family_name": "Smith",
        "user_type": "admin",
        "applicant_id": "a-456",
        "roles": ["org_admin"],
        "organization_id": "org-789",
        "organization_name": "Acme",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_validate_response(valid: bool = True, **user_overrides):
    user = _make_grpc_user(**user_overrides)
    return SimpleNamespace(valid=valid, user=user)


# ---------------------------------------------------------------------------
# Route-config patch: only /v1/organizations requires auth here
# ---------------------------------------------------------------------------

_FAKE_ROUTES: dict[str, dict] = {
    "/v1/organizations": {"service": "organizations", "requires_auth": True},
    "/v1/auth": {"service": "auth", "requires_auth": False},
}


def _fake_get_route_config(path: str):
    for prefix in sorted(_FAKE_ROUTES, key=lambda p: -len(p)):
        if path.startswith(prefix):
            return _FAKE_ROUTES[prefix]
    return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def session_cache():
    return SessionCache(ttl_seconds=5, maxsize=4)


@pytest.fixture()
def grpc_stub():
    stub = AsyncMock()
    stub.ValidateSession = AsyncMock(return_value=_make_validate_response())
    return stub


@pytest.fixture()
def auth_app(session_cache, grpc_stub):
    """FastAPI app with AuthMiddleware and a protected + public endpoint."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware, session_cache=session_cache)

    app.state.auth_grpc_stub = grpc_stub

    @app.get("/v1/organizations")
    async def orgs(request: Request):
        return JSONResponse({
            "user_id": request.state.user_id,
            "email": request.state.user_email,
        })

    @app.get("/v1/auth/login")
    async def login():
        return JSONResponse({"ok": True})

    @app.get("/health")
    async def health():
        return JSONResponse({"status": "ok"})

    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"status": "ok"})

    @app.get("/.well-known/openid-configuration")
    async def well_known():
        return JSONResponse({"issuer": "https://example.com"})

    return app


@pytest.fixture()
def rate_app():
    """FastAPI app with RateLimitMiddleware only."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)
    app.state.redis_client = None  # no Redis by default

    @app.get("/v1/test")
    async def test_endpoint():
        return JSONResponse({"ok": True})

    @app.get("/health")
    async def health():
        return JSONResponse({"status": "ok"})

    return app


# ---------------------------------------------------------------------------
# SessionCache tests
# ---------------------------------------------------------------------------

class TestSessionCache:
    def test_cache_set_get(self, session_cache: SessionCache):
        session_cache.set("s1", {"user_id": "u1"})
        assert session_cache.get("s1") == {"user_id": "u1"}

    def test_cache_ttl_expiry(self, session_cache: SessionCache):
        session_cache.set("s1", {"user_id": "u1"})
        # Advance past TTL
        with patch("gateway.middleware.time") as mock_time:
            # set was called with real time; now fake .time() to return future
            mock_time.time.return_value = time.time() + 10
            assert session_cache.get("s1") is None

    def test_cache_clear(self, session_cache: SessionCache):
        session_cache.set("s1", {"user_id": "u1"})
        session_cache.clear("s1")
        assert session_cache.get("s1") is None

    def test_cache_miss(self, session_cache: SessionCache):
        assert session_cache.get("nonexistent") is None

    def test_cache_maxsize_eviction(self):
        cache = SessionCache(ttl_seconds=300, maxsize=3)
        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.set("c", {"v": 3})
        # Cache is full — adding a 4th should evict the oldest
        cache.set("d", {"v": 4})
        assert cache.get("d") == {"v": 4}
        # At least one of the earlier entries must have been evicted
        remaining = [cache.get(k) for k in ("a", "b", "c")]
        assert None in remaining


# ---------------------------------------------------------------------------
# AuthMiddleware tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAuthMiddleware:
    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_public_route_bypass(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get("/v1/auth/login")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_health_endpoint_bypass(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_well_known_bypass(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_missing_session_cookie(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get("/v1/organizations")
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_valid_session_from_cache(self, _mock, auth_app, session_cache):
        session_cache.set("cached-sess", {
            "user_id": "u-cached",
            "email": "cached@example.com",
        })
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "cached-sess"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == "u-cached"
        assert body["email"] == "cached@example.com"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_valid_session_from_grpc_fallback(self, _mock, auth_app, grpc_stub):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "new-sess"},
            )
        assert resp.status_code == 200
        grpc_stub.ValidateSession.assert_awaited_once()
        body = resp.json()
        assert body["user_id"] == "u-123"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_invalid_session_grpc(self, _mock, auth_app, grpc_stub):
        grpc_stub.ValidateSession.return_value = _make_validate_response(valid=False)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "bad-sess"},
            )
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_grpc_unavailable(self, _mock, auth_app, grpc_stub):
        grpc_stub.ValidateSession.side_effect = Exception("connection refused")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "any-sess"},
            )
        assert resp.status_code == 502
        assert resp.json()["error"] == "auth_service_error"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_session_cached_after_grpc_hit(
        self, _mock, auth_app, grpc_stub, session_cache
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            # First request — cache miss, hits gRPC
            resp1 = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "sess-to-cache"},
            )
            assert resp1.status_code == 200
            assert grpc_stub.ValidateSession.await_count == 1

            # Second request — should be served from cache
            resp2 = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "sess-to-cache"},
            )
            assert resp2.status_code == 200
            # gRPC should NOT have been called a second time
            assert grpc_stub.ValidateSession.await_count == 1

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_user_state_injected(self, _mock, auth_app, grpc_stub):
        """After auth, request.state.user_id / user_email / user_domain are set."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "state-sess"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == "u-123"
        assert body["email"] == "alice@example.com"


# ---------------------------------------------------------------------------
# RateLimitMiddleware tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRateLimitMiddleware:
    async def test_rate_limit_within_budget(self, rate_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=rate_app), base_url="http://test"
        ) as client:
            resp = await client.get("/v1/test")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers

    async def test_rate_limit_exceeded_local(self, rate_app):
        transport = httpx.ASGITransport(app=rate_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Burn through the entire budget
            for _ in range(_RATE_LIMIT_RPM):
                r = await client.get("/v1/test")
                assert r.status_code == 200
            # Next request should be 429
            resp = await client.get("/v1/test")
        assert resp.status_code == 429
        assert resp.json()["error"] == "rate_limit_exceeded"

    async def test_rate_limit_redis_fallback(self, rate_app):
        """When Redis is present but raises, middleware falls back to local."""
        redis_mock = AsyncMock()
        redis_mock.eval = AsyncMock(side_effect=Exception("redis down"))
        rate_app.state.redis_client = redis_mock

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=rate_app), base_url="http://test"
        ) as client:
            resp = await client.get("/v1/test")
        # Should succeed via local fallback, not 500
        assert resp.status_code == 200

    async def test_health_skips_rate_limit(self, rate_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=rate_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        # Health responses should not have rate limit headers
        assert "X-RateLimit-Limit" not in resp.headers
