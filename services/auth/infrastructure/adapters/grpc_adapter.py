"""
Auth Service gRPC Adapter (Inbound)

Implements the AuthService gRPC servicer, delegating to the same
use cases that back the internal REST endpoints.  Runs alongside
the existing FastAPI application (hybrid mode).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

import grpc

from marty_proto.v1 import auth_service_pb2, auth_service_pb2_grpc

from ...application.ports import ValidateSessionQuery
from ...application.use_cases import SessionUseCase
from ...domain.entities import AuthenticatedUser, Session, UserType

logger = logging.getLogger(__name__)

# Redis key prefixes (must match http_adapter.py)
_PENDING_KEY = "marty:cred_login:pending:"
_COMPLETE_KEY = "marty:cred_login:complete:"
_COMPLETE_TTL = 300


def _user_to_pb(user: AuthenticatedUser) -> auth_service_pb2.UserInfo:
    """Map domain AuthenticatedUser → protobuf UserInfo."""
    return auth_service_pb2.UserInfo(
        user_id=user.user_id,
        email=user.email,
        username=user.username or "",
        given_name=user.given_name or "",
        family_name=user.family_name or "",
        user_type=user.user_type.value,
        applicant_id=user.applicant_id or "",
        roles=user.roles,
        organization_id=user.organization_id or "",
        organization_name=user.organization_name or "",
        onboarding_completed=user.onboarding_completed is not None,
        picture=user.picture or "",
    )


class AuthServiceGrpc(auth_service_pb2_grpc.AuthServiceServicer):
    """gRPC inbound adapter for the auth service.

    Each RPC delegates to the same use-case / repository layer that
    the REST internal endpoints use.
    """

    def __init__(
        self,
        session_use_case: SessionUseCase,
        session_repository: Any,
        redis_client: Any,
        kc_admin_adapter: Any | None = None,
    ) -> None:
        self._session_use_case = session_use_case
        self._session_repository = session_repository
        self._redis = redis_client
        self._kc_admin = kc_admin_adapter

    # ------------------------------------------------------------------
    # ValidateSession — hot path, called on every authenticated request
    # ------------------------------------------------------------------

    async def ValidateSession(
        self,
        request: auth_service_pb2.ValidateSessionRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.ValidateSessionResponse:
        session = await self._session_use_case.validate_session(
            ValidateSessionQuery(session_id=request.session_id)
        )
        if not session:
            return auth_service_pb2.ValidateSessionResponse(valid=False)
        return auth_service_pb2.ValidateSessionResponse(
            valid=True,
            user=_user_to_pb(session.user),
            expires_at=session.expires_at.isoformat(),
        )

    # ------------------------------------------------------------------
    # CreateSession
    # ------------------------------------------------------------------

    async def CreateSession(
        self,
        request: auth_service_pb2.CreateSessionRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.CreateSessionResponse:
        role_map = {"administrator": UserType.ADMINISTRATOR, "vendor": UserType.VENDOR}
        user = AuthenticatedUser(
            user_id=request.user_id,
            email=request.email,
            username=request.username or None,
            given_name=request.given_name or None,
            family_name=request.family_name or None,
            user_type=role_map.get(request.user_type, UserType.APPLICANT),
            roles=list(request.roles),
        )
        ttl = request.ttl_seconds if request.ttl_seconds > 0 else 86400
        session = Session.create(user=user, ttl_seconds=ttl)
        await self._session_repository.save(session)
        return auth_service_pb2.CreateSessionResponse(
            session_id=session.session_id,
            expires_at=session.expires_at.isoformat(),
        )

    # ------------------------------------------------------------------
    # InvalidateSession
    # ------------------------------------------------------------------

    async def InvalidateSession(
        self,
        request: auth_service_pb2.InvalidateSessionRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.InvalidateSessionResponse:
        session = await self._session_repository.get(request.session_id)
        if session:
            await self._session_repository.delete(request.session_id)
            return auth_service_pb2.InvalidateSessionResponse(success=True)
        return auth_service_pb2.InvalidateSessionResponse(success=False)

    # ------------------------------------------------------------------
    # GetAuthStatus
    # ------------------------------------------------------------------

    async def GetAuthStatus(
        self,
        request: auth_service_pb2.GetAuthStatusRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.AuthStatusResponse:
        session = await self._session_use_case.validate_session(
            ValidateSessionQuery(session_id=request.session_id)
        )
        if not session:
            return auth_service_pb2.AuthStatusResponse(authenticated=False)
        return auth_service_pb2.AuthStatusResponse(
            authenticated=True,
            user=_user_to_pb(session.user),
        )

    # ------------------------------------------------------------------
    # CredentialVerified  (OID4VP callback from the flow service)
    # ------------------------------------------------------------------

    async def CredentialVerified(
        self,
        request: auth_service_pb2.CredentialVerifiedRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.CredentialVerifiedResponse:
        nonce = request.nonce

        # Look up pending login state
        pending_raw = await self._redis.get(f"{_PENDING_KEY}{nonce}")
        if not pending_raw:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Login session expired or not found")
            return auth_service_pb2.CredentialVerifiedResponse(ok=False)

        if request.decision != "allow" or request.result == "failed":
            await self._redis.setex(
                f"{_COMPLETE_KEY}{nonce}",
                _COMPLETE_TTL,
                json.dumps({"status": "failed", "reason": request.decision_reason}),
            )
            await self._redis.delete(f"{_PENDING_KEY}{nonce}")
            return auth_service_pb2.CredentialVerifiedResponse(ok=True, status="denied")

        # Extract identity claims
        claims = dict(request.verified_claims)
        email = claims.get("email", "")
        if not email:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Credential missing email claim")
            return auth_service_pb2.CredentialVerifiedResponse(ok=False)

        user_id = claims.get("sub") or claims.get("subject") or ""
        if not user_id:
            user_id = str(uuid.UUID(bytes=hashlib.sha256(email.lower().encode()).digest()[:16]))

        role = claims.get("role", "applicant")
        role_map = {"administrator": UserType.ADMINISTRATOR, "vendor": UserType.VENDOR}
        user = AuthenticatedUser(
            user_id=user_id,
            email=email,
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            user_type=role_map.get(role, UserType.APPLICANT),
            roles=[role],
            organization_id=claims.get("organization_id"),
            applicant_id=claims.get("member_id"),
        )
        session = Session.create(user=user)

        # Optional KC token exchange
        if self._kc_admin is not None:
            try:
                kc_user_id = await self._kc_admin.get_or_create_user(
                    email=email,
                    given_name=claims.get("given_name"),
                    family_name=claims.get("family_name"),
                    role=role,
                )
                if kc_user_id:
                    kc_tokens = await self._kc_admin.exchange_token_for_user(kc_user_id)
                    if kc_tokens:
                        session.id_token = kc_tokens.get("id_token")
                        session.refresh_token = kc_tokens.get("refresh_token")
            except Exception as exc:
                logger.warning("KC token exchange optional step failed: %s", exc)

        await self._session_repository.save(session)
        logger.info("Credential login via gRPC: user=%s session=%s...", email, session.session_id[:8])

        await self._redis.setex(
            f"{_COMPLETE_KEY}{nonce}",
            _COMPLETE_TTL,
            json.dumps({"status": "completed", "session_id": session.session_id}),
        )
        await self._redis.delete(f"{_PENDING_KEY}{nonce}")

        return auth_service_pb2.CredentialVerifiedResponse(ok=True, status="completed")

    # ------------------------------------------------------------------
    # HealthCheck
    # ------------------------------------------------------------------

    async def HealthCheck(
        self,
        request: auth_service_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.HealthCheckResponse:
        return auth_service_pb2.HealthCheckResponse(status="serving")
