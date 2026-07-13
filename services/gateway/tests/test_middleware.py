"""Tests for gateway.middleware — SessionCache, AuthMiddleware, RateLimitMiddleware."""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from marty_common.middleware import IdempotencyMiddleware

from gateway import main as gateway_main
from gateway.middleware import (
    AuthMiddleware,
    ContentTypeEnforcementMiddleware,
    MIPVersionMiddleware,
    RateLimitMiddleware,
    SessionCache,
    _RATE_LIMIT_RPM,
    mip_error_response,
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
    "/credentials": {"service": "gateway", "requires_auth": True},
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

    @app.get("/credentials/marty-verified-member-badge")
    async def credential_metadata():
        return JSONResponse({"name": "Marty Verified Member Badge"})

    @app.get(
        "/v1/organizations/00000000-0000-0000-0000-000000000001"
        "/revocation-profiles/70000000-0000-0000-0000-000000000001"
        "/status-lists/bitstring-status-list/revocation"
    )
    async def status_list_document():
        return JSONResponse({"type": "BitstringStatusListCredential"})

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


@pytest.fixture()
def content_type_app():
    """FastAPI app with ContentTypeEnforcementMiddleware only."""
    app = FastAPI()
    app.add_middleware(ContentTypeEnforcementMiddleware)

    @app.post("/v1/issuance/nonce")
    async def nonce_endpoint():
        return JSONResponse({"ok": True})

    @app.post("/v1/example")
    async def example_endpoint():
        return JSONResponse({"ok": True})

    return app


class FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def setex(self, key: str, ttl: int, value: str):
        self.store[key] = value
        return True

    async def delete(self, key: str):
        self.store.pop(key, None)
        return 1


@pytest.mark.asyncio
async def test_idempotency_middleware_replays_successful_redis_create_and_rejects_conflict():
    redis = FakeRedis()
    app = FastAPI()
    app.state.redis_client = redis
    app.add_middleware(IdempotencyMiddleware)
    creates = 0

    @app.post("/v1/artifacts")
    async def create_artifact(payload: dict):
        nonlocal creates
        creates += 1
        return JSONResponse({"id": f"artifact-{creates}", "name": payload["name"]}, status_code=201)

    @app.post("/v1/other-artifacts")
    async def create_other_artifact(payload: dict):
        nonlocal creates
        creates += 1
        return JSONResponse({"id": f"other-{creates}", "name": payload["name"]}, status_code=201)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/v1/artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        )
        replay = await client.post(
            "/v1/artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        )
        conflict = await client.post(
            "/v1/artifacts",
            json={"name": "Beta"},
            headers={"Idempotency-Key": "create-alpha"},
        )
        cross_endpoint_conflict = await client.post(
            "/v1/other-artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        )

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert conflict.status_code == 409
    assert conflict.json()["error"] == "idempotency_conflict"
    assert cross_endpoint_conflict.status_code == 409
    assert cross_endpoint_conflict.json()["error"] == "idempotency_conflict"
    assert creates == 1


@pytest.mark.asyncio
async def test_idempotency_middleware_rejects_concurrent_same_key_redis_create():
    redis = FakeRedis()
    app = FastAPI()
    app.state.redis_client = redis
    app.add_middleware(IdempotencyMiddleware)
    started = asyncio.Event()
    finish = asyncio.Event()
    creates = 0

    @app.post("/v1/artifacts")
    async def create_artifact(payload: dict):
        nonlocal creates
        creates += 1
        started.set()
        await finish.wait()
        return JSONResponse({"id": f"artifact-{creates}", "name": payload["name"]}, status_code=201)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first_task = asyncio.create_task(client.post(
            "/v1/artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        ))
        await started.wait()

        in_progress = await client.post(
            "/v1/artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        )

        finish.set()
        first = await first_task
        replay = await client.post(
            "/v1/artifacts",
            json={"name": "Alpha"},
            headers={"Idempotency-Key": "create-alpha"},
        )

    assert in_progress.status_code == 409
    assert in_progress.json()["error"] == "idempotency_in_progress"
    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert creates == 1


def test_gateway_idempotency_runs_after_current_authorization_checks():
    app = gateway_main.create_app()
    middleware_names = [middleware.cls.__name__ for middleware in app.user_middleware]

    assert middleware_names.index("CedarAuthMiddleware") < middleware_names.index("IdempotencyMiddleware")
    assert middleware_names.index("BillingAuthMiddleware") < middleware_names.index("IdempotencyMiddleware")
    assert middleware_names.index("IdempotencyMiddleware") < middleware_names.index("UsageTrackingMiddleware")


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
    async def test_credential_metadata_bypass(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get("/credentials/marty-verified-member-badge")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Marty Verified Member Badge"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_get_route_config)
    async def test_status_list_document_bypass(self, _mock, auth_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=auth_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations/00000000-0000-0000-0000-000000000001"
                "/revocation-profiles/70000000-0000-0000-0000-000000000001"
                "/status-lists/bitstring-status-list/revocation"
            )
        assert resp.status_code == 200
        assert resp.json()["type"] == "BitstringStatusListCredential"

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


@pytest.mark.asyncio
class TestContentTypeEnforcementMiddleware:
    async def test_nonce_endpoint_allows_wallet_media_type(self, content_type_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=content_type_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/issuance/nonce",
                headers={"Content-Type": "application/octet-stream"},
                content=b"",
            )

        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    async def test_unknown_media_type_still_rejected_for_non_exempt_paths(self, content_type_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=content_type_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/example",
                headers={"Content-Type": "application/octet-stream"},
                content=b"",
            )

        assert resp.status_code == 415
        assert resp.json()["error"] == "unsupported_media_type"


# ---------------------------------------------------------------------------
# MIP Compliance tests (MIP 10, 17.7)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mip_app():
    """FastAPI app with MIPVersionMiddleware for compliance header testing."""
    app = FastAPI()
    app.add_middleware(MIPVersionMiddleware)

    @app.get("/v1/test")
    async def test_endpoint():
        return JSONResponse({"ok": True})

    @app.get("/health")
    async def health():
        return JSONResponse({"status": "ok"})

    return app


class TestMIPCompliance:
    """MIP 10 - Discovery, MIP 17.7 - Error envelope, MIP 20 - Headers."""

    async def test_mip_version_header_on_all_responses(self, mip_app):
        """MIP 20 - Every response MUST include X-MIP-Version header."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mip_app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/v1/test")
        assert resp.headers.get("X-MIP-Version") == "0.3.1"

    async def test_mip_version_header_on_health(self, mip_app):
        """MIP 20 - Health endpoints also carry MIP version."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mip_app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/health")
        assert resp.headers.get("X-MIP-Version") == "0.3.1"

    def test_mip_error_response_format(self):
        """MIP 17.7 - Error responses MUST include error, error_description, message_id."""
        resp = mip_error_response(400, "bad_request", "Missing required field", field="email")
        body = resp.body
        import json as _json
        data = _json.loads(body)
        assert data["error"] == "bad_request"
        assert data["error_description"] == "Missing required field"
        assert "message_id" in data
        assert data["field"] == "email"
        assert resp.headers.get("X-MIP-Version") == "0.3.1"

    def test_mip_error_response_503_format(self):
        """MIP 17.7 - Service unavailable errors follow the same envelope."""
        resp = mip_error_response(503, "service_unavailable", "Auth service unreachable")
        import json as _json
        data = _json.loads(resp.body)
        assert data["error"] == "service_unavailable"
        assert "message_id" in data
        assert resp.status_code == 503
        assert resp.headers.get("X-MIP-Version") == "0.3.1"

    def test_mip_error_response_includes_details(self):
        """MIP 17.7 - Validation errors include details array."""
        resp = mip_error_response(
            422,
            "validation_error",
            "Constraint violations",
            details=[
                {"field": "email", "message": "Email is required"},
                {"field": "role", "message": "Role must be one of: admin, vendor, applicant"},
            ],
        )
        import json as _json
        data = _json.loads(resp.body)
        assert data["error"] == "validation_error"
        assert len(data["details"]) == 2
        assert data["details"][0]["field"] == "email"
        assert resp.headers.get("X-MIP-Version") == "0.3.1"
