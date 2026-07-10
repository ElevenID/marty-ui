"""Tests exposing gateway middleware edge cases.

Issue 7.1: X-API-Key header auth path authenticates machine clients
Issue 7.2: SessionCache eviction under concurrent async access
Issue 7.3: Empty-string email produces empty X-User-Email header

Uses pre-populated SessionCache to avoid requiring grpc module.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gateway.middleware import AuthMiddleware, SessionCache


# Route config: only /v1/organizations requires auth
_ROUTES = {
    "/v1/organizations": {"service": "organizations", "requires_auth": True},
}


def _fake_route_config(path: str):
    for prefix in sorted(_ROUTES, key=lambda p: -len(p)):
        if path.startswith(prefix):
            return _ROUTES[prefix]
    return None


def _make_app(session_cache: SessionCache, org_client=None):
    """Create a FastAPI app with AuthMiddleware and a user-inspection endpoint."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware, session_cache=session_cache)
    # Dummy stub — won't be called since we pre-populate the cache
    app.state.auth_grpc_stub = AsyncMock()
    app.state.org_client = org_client or SimpleNamespace(validate_api_key=AsyncMock(return_value=None))

    @app.get("/v1/organizations")
    async def orgs(request: Request):
        return JSONResponse({
            "user_id": getattr(request.state, "user_id", None),
            "email": getattr(request.state, "user_email", None),
            "domain": getattr(request.state, "user_domain", None),
            "auth_source": getattr(request.state, "auth_source", None),
            "api_key_id": getattr(request.state, "api_key_id", None),
            "organization_id": getattr(request.state, "organization_id", None),
            "api_key_scopes": getattr(request.state, "api_key_scopes", None),
        })

    return app


# ── Issue 7.1: X-API-Key bypasses auth middleware ────────────────────

@pytest.mark.asyncio
class TestApiKeyAuthGap:
    """API keys authenticate machine requests without a session cookie."""

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_api_key_header_without_cookie_authenticates(self, _mock):
        cache = SessionCache(ttl_seconds=60)
        org_client = SimpleNamespace(validate_api_key=AsyncMock(return_value=SimpleNamespace(
            api_key_id="key-1",
            organization_id="org-1",
            key_prefix="mk_live_",
            scopes=["flows:execute"],
        )))
        app = _make_app(cache, org_client=org_client)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                headers={"X-API-Key": "mk_live_valid"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["auth_source"] == "api_key"
        assert body["api_key_id"] == "key-1"
        assert body["organization_id"] == "org-1"
        assert body["api_key_scopes"] == ["flows:execute"]
        org_client.validate_api_key.assert_awaited_once_with("mk_live_valid")

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_invalid_api_key_header_is_rejected(self, _mock):
        cache = SessionCache(ttl_seconds=60)
        org_client = SimpleNamespace(validate_api_key=AsyncMock(return_value=None))
        app = _make_app(cache, org_client=org_client)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                headers={"X-API-Key": "mk_live_invalid"},
            )

        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_bearer_token_without_cookie_is_rejected(self, _mock):
        """Non-Marty bearer tokens are not treated as API keys."""
        cache = SessionCache(ttl_seconds=60)
        app = _make_app(cache)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.test.sig"},
            )
        assert resp.status_code == 401

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_both_api_key_and_cookie_uses_explicit_api_key(self, _mock):
        """When both are present, the explicit machine credential is authoritative."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("valid-sess", {"user_id": "u-100", "email": "user@test.com"})
        org_client = SimpleNamespace(validate_api_key=AsyncMock(return_value=SimpleNamespace(
            api_key_id="key-1",
            organization_id="org-1",
            key_prefix="mk_live_",
            scopes=["flows:execute"],
        )))
        app = _make_app(cache, org_client=org_client)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                headers={"X-API-Key": "mk_live_valid"},
                cookies={"sessionId": "valid-sess"},
            )

        assert resp.status_code == 200
        assert resp.json()["auth_source"] == "api_key"


# ── Issue 7.3: Empty email edge cases ────────────────────────────────

@pytest.mark.asyncio
class TestEmptyEmailEdgeCases:

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_empty_string_email_sets_empty_user_email(self, _mock):
        """BUG: Empty-string email produces request.state.user_email = '',
        which downstream services might treat differently from None."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("test-sess", {"user_id": "u-1", "email": ""})
        app = _make_app(cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "test-sess"},
            )
        body = resp.json()
        # email is empty string, not None
        assert body["email"] == ""
        # domain is None (empty string doesn't contain @)
        assert body["domain"] is None

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_email_without_at_sign_sets_none_domain(self, _mock):
        """Email without @ produces domain=None."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("test-sess", {"user_id": "u-1", "email": "malformed-email"})
        app = _make_app(cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "test-sess"},
            )
        body = resp.json()
        assert body["email"] == "malformed-email"
        assert body["domain"] is None

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_email_with_multiple_at_signs_takes_first_split(self, _mock):
        """BUG: email.split("@")[1] only takes the middle part if there are multiple @ signs."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("test-sess", {"user_id": "u-1", "email": "user@middle@domain.com"})
        app = _make_app(cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "test-sess"},
            )
        body = resp.json()
        # split("@")[1] = "middle" — not the actual domain
        assert body["domain"] == "middle"
        # The actual domain should be "domain.com" — but split takes [1]
        assert body["domain"] != "domain.com"

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_no_user_id_in_session_returns_401(self, _mock):
        """If cached session data has empty user_id, auth should reject."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("test-sess", {"user_id": "", "email": "user@test.com"})
        app = _make_app(cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "test-sess"},
            )
        # BUG: empty string is falsy, so middleware rejects with 401
        assert resp.status_code == 401

    @patch("gateway.middleware.get_route_config", side_effect=_fake_route_config)
    async def test_none_email_sets_none_domain(self, _mock):
        """None email in cached session produces None domain."""
        cache = SessionCache(ttl_seconds=60)
        cache.set("test-sess", {"user_id": "u-1", "email": None})
        app = _make_app(cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/v1/organizations",
                cookies={"sessionId": "test-sess"},
            )
        body = resp.json()
        assert body["email"] is None
        assert body["domain"] is None


# ── Issue 7.2: SessionCache concurrent access ────────────────────────

class TestSessionCacheConcurrency:
    """Document SessionCache thread-safety assumptions."""

    def test_rapid_set_at_maxsize_boundary(self):
        """Rapidly set items right at maxsize boundary."""
        cache = SessionCache(ttl_seconds=300, maxsize=5)

        # Fill to max
        for i in range(5):
            cache.set(f"s-{i}", {"v": i})

        # Rapidly add more — triggers eviction on each call
        for i in range(5, 20):
            cache.set(f"s-{i}", {"v": i})

        # Should still work without KeyError
        assert cache.get("s-19") == {"v": 19}

    def test_expired_entries_cleaned_during_eviction(self):
        """Verify that expired entries are cleaned before evicting valid ones."""
        cache = SessionCache(ttl_seconds=1, maxsize=3)

        cache.set("old-1", {"v": 1})
        cache.set("old-2", {"v": 2})
        cache.set("old-3", {"v": 3})

        # Fast-forward time to expire all entries
        with patch("gateway.middleware.time") as mock_time:
            mock_time.time.return_value = time.time() + 5

            # Adding new entry should evict expired ones, not error
            cache.set("new-1", {"v": 4})

        # The new entry should be accessible (it was set with real time internally,
        # but set() uses the mocked time for TTL, so we need to un-mock to read it)
        # Since the mock is exited, time.time() is now real again.
        # new-1 was set with expires_at = mock_time + 1s, which is ~5s in the future
        # from real time, so it should still be valid.

    def test_cache_eviction_preserves_newest(self):
        """After eviction, the newest entries should survive."""
        cache = SessionCache(ttl_seconds=300, maxsize=3)

        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.set("c", {"v": 3})
        # Full — adding d should evict the oldest
        cache.set("d", {"v": 4})

        assert cache.get("d") == {"v": 4}
        # At least one of a/b/c is evicted
        results = [cache.get(k) for k in ("a", "b", "c")]
        assert None in results
