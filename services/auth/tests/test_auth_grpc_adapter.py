"""Tests for the Auth Service gRPC adapter."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import grpc

from auth.domain.entities import AuthenticatedUser, Session, UserType
from auth.infrastructure.adapters.grpc_adapter import AuthServiceGrpc
from marty_proto.v1 import auth_service_pb2


def _make_user(**overrides) -> AuthenticatedUser:
    defaults = dict(
        user_id="user-1",
        email="alice@example.com",
        username="alice",
        given_name="Alice",
        family_name="Smith",
        user_type=UserType.ADMINISTRATOR,
        roles=["admin"],
        organization_id="org-1",
        organization_name="Acme Corp",
    )
    defaults.update(overrides)
    return AuthenticatedUser(**defaults)


def _make_session(user=None, **overrides) -> Session:
    user = user or _make_user()
    now = datetime.now(timezone.utc)
    defaults = dict(
        session_id="sess-abc",
        user=user,
        created_at=now,
        expires_at=now + timedelta(hours=24),
    )
    defaults.update(overrides)
    return Session(**defaults)


def _build_servicer(**overrides) -> AuthServiceGrpc:
    defaults = dict(
        session_use_case=MagicMock(),
        session_repository=MagicMock(),
        redis_client=AsyncMock(),
        user_provisioning=None,
        applicant_profile_provisioner=None,
    )
    defaults.update(overrides)
    return AuthServiceGrpc(**defaults)


# ── ValidateSession ─────────────────────────────────────────────────


class TestValidateSession:
    async def test_valid_session(self, ctx):
        session = _make_session()
        use_case = MagicMock()
        use_case.validate_session = AsyncMock(return_value=session)
        servicer = _build_servicer(session_use_case=use_case)

        req = auth_service_pb2.ValidateSessionRequest(session_id="sess-abc")
        resp = await servicer.ValidateSession(req, ctx)

        assert resp.valid is True
        assert resp.user.user_id == "user-1"
        assert resp.user.email == "alice@example.com"
        assert resp.user.organization_id == "org-1"
        assert resp.expires_at != ""
        use_case.validate_session.assert_awaited_once()

    async def test_invalid_session(self, ctx):
        use_case = MagicMock()
        use_case.validate_session = AsyncMock(return_value=None)
        servicer = _build_servicer(session_use_case=use_case)

        req = auth_service_pb2.ValidateSessionRequest(session_id="expired")
        resp = await servicer.ValidateSession(req, ctx)

        assert resp.valid is False
        assert resp.user.user_id == ""


# ── CreateSession ────────────────────────────────────────────────────


class TestCreateSession:
    async def test_retired_rpc_rejects_arbitrary_session_minting_without_side_effects(self, ctx):
        repo = MagicMock()
        repo.save = AsyncMock()
        redis = AsyncMock()
        servicer = _build_servicer(session_repository=repo, redis_client=redis)

        req = auth_service_pb2.CreateSessionRequest(
            user_id="user-2",
            email="bob@example.com",
            user_type="administrator",
            roles=["admin"],
            ttl_seconds=3600,
        )
        resp = await servicer.CreateSession(req, ctx)

        assert resp.session_id == ""
        assert resp.expires_at == ""
        assert ctx.code == grpc.StatusCode.UNIMPLEMENTED
        assert "authoritative login flow" in ctx.details
        repo.save.assert_not_awaited()
        assert redis.mock_calls == []


# ── InvalidateSession ───────────────────────────────────────────────


class TestInvalidateSession:
    async def test_existing_session(self, ctx):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=_make_session())
        repo.delete = AsyncMock()
        servicer = _build_servicer(session_repository=repo)

        req = auth_service_pb2.InvalidateSessionRequest(session_id="sess-abc")
        resp = await servicer.InvalidateSession(req, ctx)

        assert resp.success is True
        repo.delete.assert_awaited_once_with("sess-abc")

    async def test_nonexistent_session(self, ctx):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        servicer = _build_servicer(session_repository=repo)

        req = auth_service_pb2.InvalidateSessionRequest(session_id="nope")
        resp = await servicer.InvalidateSession(req, ctx)

        assert resp.success is False


# ── GetAuthStatus ────────────────────────────────────────────────────


class TestGetAuthStatus:
    async def test_authenticated(self, ctx):
        session = _make_session()
        use_case = MagicMock()
        use_case.validate_session = AsyncMock(return_value=session)
        servicer = _build_servicer(session_use_case=use_case)

        req = auth_service_pb2.GetAuthStatusRequest(session_id="sess-abc")
        resp = await servicer.GetAuthStatus(req, ctx)

        assert resp.authenticated is True
        assert resp.user.email == "alice@example.com"

    async def test_unauthenticated(self, ctx):
        use_case = MagicMock()
        use_case.validate_session = AsyncMock(return_value=None)
        servicer = _build_servicer(session_use_case=use_case)

        req = auth_service_pb2.GetAuthStatusRequest(session_id="gone")
        resp = await servicer.GetAuthStatus(req, ctx)

        assert resp.authenticated is False


# ── CredentialVerified ───────────────────────────────────────────────


class TestCredentialVerified:
    async def test_retired_rpc_rejects_callback_without_side_effects(self, ctx):
        redis = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        kc_admin = MagicMock()
        kc_admin.get_or_create_user = AsyncMock()
        user_provisioning = MagicMock()
        user_provisioning.provision_user = AsyncMock()
        profile_provisioner = AsyncMock()
        servicer = _build_servicer(
            session_repository=repo,
            redis_client=redis,
            kc_admin_adapter=kc_admin,
            user_provisioning=user_provisioning,
            applicant_profile_provisioner=profile_provisioner,
        )

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-123",
            decision="allow",
            result="success",
            verified_claims={
                "email": "alice@example.com",
                "roles": "administrator",
            },
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is False
        assert resp.status == ""
        assert ctx.code == grpc.StatusCode.UNIMPLEMENTED
        assert "authenticated internal HTTP callback" in ctx.details
        repo.save.assert_not_awaited()
        assert redis.mock_calls == []
        kc_admin.get_or_create_user.assert_not_awaited()
        user_provisioning.provision_user.assert_not_awaited()
        profile_provisioner.assert_not_awaited()


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = auth_service_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
