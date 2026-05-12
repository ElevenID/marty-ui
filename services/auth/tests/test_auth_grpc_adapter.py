"""Tests for the Auth Service gRPC adapter."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest

from auth.domain.entities import AuthenticatedUser, OIDCUserInfo, Session, UserType
from auth.application.ports import ValidateSessionQuery
from auth.infrastructure.adapters.grpc_adapter import AuthServiceGrpc
from auth.infrastructure.adapters.user_provisioning_adapter import MARTY_ORG_ID
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
    async def test_creates_session(self, ctx):
        repo = MagicMock()
        repo.save = AsyncMock()
        servicer = _build_servicer(session_repository=repo)

        req = auth_service_pb2.CreateSessionRequest(
            user_id="user-2",
            email="bob@example.com",
            user_type="administrator",
            roles=["admin"],
            ttl_seconds=3600,
        )
        resp = await servicer.CreateSession(req, ctx)

        assert resp.session_id != ""
        assert resp.expires_at != ""
        repo.save.assert_awaited_once()

    async def test_default_ttl_when_zero(self, ctx):
        repo = MagicMock()
        repo.save = AsyncMock()
        servicer = _build_servicer(session_repository=repo)

        req = auth_service_pb2.CreateSessionRequest(
            user_id="user-3",
            email="carol@example.com",
            ttl_seconds=0,
        )
        resp = await servicer.CreateSession(req, ctx)

        assert resp.session_id != ""
        saved_session = repo.save.call_args[0][0]
        ttl = (saved_session.expires_at - saved_session.created_at).total_seconds()
        assert ttl == pytest.approx(86400, abs=5)


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
    async def test_successful_verification(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        servicer = _build_servicer(session_repository=repo, redis_client=redis)

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-123",
            decision="allow",
            result="success",
            verified_claims={"email": "alice@example.com", "given_name": "Alice"},
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        assert resp.status == "completed"
        repo.save.assert_awaited_once()
        redis.delete.assert_awaited()

    async def test_successful_verification_enriches_user_with_provisioned_org(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        provisioned_user = _make_user(
            user_id="prov-user-1",
            user_type=UserType.APPLICANT,
            roles=["applicant", "admin"],
            organization_id=MARTY_ORG_ID,
            organization_name="Marty Identity Platform",
            applicant_id="prov-app-1",
        )
        user_provisioning = MagicMock()
        user_provisioning.provision_user = AsyncMock(return_value=provisioned_user)
        servicer = _build_servicer(
            session_repository=repo,
            redis_client=redis,
            user_provisioning=user_provisioning,
        )

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-124",
            decision="allow",
            result="success",
            verified_claims={
                "email": "alice@example.com",
                "given_name": "Alice",
                "member_id": "member-123",
            },
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        saved_session = repo.save.call_args[0][0]
        assert saved_session.user.organization_id == MARTY_ORG_ID
        assert saved_session.user.organization_name == "Marty Identity Platform"
        assert saved_session.user.applicant_id == "member-123"
        assert "admin" in saved_session.user.roles

    async def test_successful_verification_uses_keycloak_admin_fallback_when_token_exchange_unavailable(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        kc_admin = MagicMock()
        kc_admin.get_existing_verified_user_id = AsyncMock(return_value="kc-user-1")
        kc_admin.get_or_create_user = AsyncMock(return_value="created-user-should-not-be-used")
        kc_admin.exchange_token_for_user = AsyncMock(return_value=None)
        kc_admin.get_user_info = AsyncMock(return_value=OIDCUserInfo(
            sub="kc-user-1",
            email="alice@example.com",
            preferred_username="kc-alice",
            organization={MARTY_ORG_ID: {"name": "Marty Identity Platform"}},
            organization_id=MARTY_ORG_ID,
            organization_name="Marty Identity Platform",
            roles=["administrator", "organization-admin"],
        ))
        servicer = _build_servicer(
            session_repository=repo,
            redis_client=redis,
            kc_admin_adapter=kc_admin,
        )

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-125",
            decision="allow",
            result="success",
            verified_claims={
                "email": "alice@example.com",
                "preferred_username": "badge-alice",
            },
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        saved_session = repo.save.call_args[0][0]
        assert saved_session.user.username == "badge-alice"
        assert saved_session.user.organization_id == MARTY_ORG_ID
        assert saved_session.user.organization == {MARTY_ORG_ID: {"name": "Marty Identity Platform"}}
        assert "administrator" in saved_session.user.roles
        kc_admin.get_existing_verified_user_id.assert_awaited_once_with(
            email="alice@example.com",
            username="badge-alice",
        )
        kc_admin.get_or_create_user.assert_not_awaited()
        kc_admin.get_user_info.assert_awaited_once_with("kc-user-1")

    async def test_verification_denies_when_existing_keycloak_user_required_but_missing(self, ctx, monkeypatch):
        monkeypatch.setenv("CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER", "true")
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        kc_admin = MagicMock()
        kc_admin.get_existing_verified_user_id = AsyncMock(return_value=None)
        kc_admin.get_or_create_user = AsyncMock(return_value="created-user-should-not-be-used")
        servicer = _build_servicer(
            session_repository=repo,
            redis_client=redis,
            kc_admin_adapter=kc_admin,
        )

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-127",
            decision="allow",
            result="success",
            verified_claims={"email": "alice@example.com"},
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        assert resp.status == "denied"
        repo.save.assert_not_awaited()
        kc_admin.get_or_create_user.assert_not_awaited()
        redis.setex.assert_awaited_once()
        assert json.loads(redis.setex.call_args.args[2])["reason"] == "keycloak_user_not_found"

    async def test_successful_verification_defaults_to_marty_org_and_syncs_applicant_profile(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        repo = MagicMock()
        repo.save = AsyncMock()
        applicant_profile_provisioner = AsyncMock(return_value="applicant-42")
        servicer = _build_servicer(
            session_repository=repo,
            redis_client=redis,
            applicant_profile_provisioner=applicant_profile_provisioner,
        )

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-126",
            decision="allow",
            result="success",
            verified_claims={
                "email": "alice@example.com",
                "given_name": "Alice",
                "family_name": "Smith",
            },
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        saved_session = repo.save.call_args[0][0]
        assert saved_session.user.organization_id == MARTY_ORG_ID
        assert saved_session.user.applicant_id == "applicant-42"
        applicant_profile_provisioner.assert_awaited_once()

    async def test_expired_nonce(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        servicer = _build_servicer(redis_client=redis)

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="expired",
            decision="allow",
            result="success",
            verified_claims={"email": "x@y.z"},
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is False
        assert ctx.code == grpc.StatusCode.NOT_FOUND

    async def test_denied_decision(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        redis.setex = AsyncMock()
        redis.delete = AsyncMock()
        servicer = _build_servicer(redis_client=redis)

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-456",
            decision="deny",
            decision_reason="untrusted issuer",
            result="failed",
            verified_claims={},
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is True
        assert resp.status == "denied"

    async def test_missing_email_claim(self, ctx):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps({"state": "pending"}))
        servicer = _build_servicer(redis_client=redis)

        req = auth_service_pb2.CredentialVerifiedRequest(
            nonce="nonce-789",
            decision="allow",
            result="success",
            verified_claims={"given_name": "NoEmail"},
        )
        resp = await servicer.CredentialVerified(req, ctx)

        assert resp.ok is False
        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = auth_service_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
