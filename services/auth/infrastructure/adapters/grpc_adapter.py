"""
Auth Service gRPC Adapter (Inbound)

Implements the AuthService gRPC servicer, delegating to the same
use cases that back the internal REST endpoints.  Runs alongside
the existing FastAPI application (hybrid mode).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import grpc

from marty_proto.v1 import auth_service_pb2, auth_service_pb2_grpc

from ...application.ports import UserProvisioningPort, ValidateSessionQuery
from ...application.use_cases import SessionUseCase
from ...domain.entities import AuthenticatedUser, Session, UserType
from .applicant_profile_adapter import apply_credential_login_defaults
from .credential_login_enricher import build_credential_login_user
from .keycloak_admin_adapter import merge_oidc_user_info
from .oidc_adapter import build_oidc_user_info

logger = logging.getLogger(__name__)

# Redis key prefixes (must match http_adapter.py)
_PENDING_KEY = "marty:cred_login:pending:"
_COMPLETE_KEY = "marty:cred_login:complete:"
_COMPLETE_TTL = 300


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


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
        user_provisioning: UserProvisioningPort | None = None,
        applicant_profile_provisioner: Any | None = None,
    ) -> None:
        self._session_use_case = session_use_case
        self._session_repository = session_repository
        self._redis = redis_client
        self._kc_admin = kc_admin_adapter
        self._user_provisioning = user_provisioning
        self._applicant_profile_provisioner = applicant_profile_provisioner
        self._credential_login_require_existing_keycloak_user = _env_bool(
            "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER",
            False,
        )
        self._credential_login_create_users = _env_bool("CREDENTIAL_LOGIN_CREATE_USERS", False)

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

        role = claims.get("role", "applicant")
        given_name = claims.get("given_name") if isinstance(claims.get("given_name"), str) else None
        family_name = claims.get("family_name") if isinstance(claims.get("family_name"), str) else None
        preferred_username = claims.get("preferred_username") if isinstance(claims.get("preferred_username"), str) else email
        keycloak_user = None
        kc_tokens: dict[str, str] | None = None

        if self._kc_admin is not None:
            try:
                kc_user_id = None
                get_existing_verified_user_id = getattr(self._kc_admin, "get_existing_verified_user_id", None)
                if callable(get_existing_verified_user_id):
                    kc_user_id = await get_existing_verified_user_id(email=email, username=preferred_username)
                elif self._credential_login_create_users:
                    kc_user_id = await self._kc_admin.get_or_create_user(
                        email=email,
                        username=preferred_username,
                        given_name=given_name,
                        family_name=family_name,
                        role=role,
                    )
                # Keep credential-login session parity with OIDC login:
                # when Keycloak admin integration is enabled and user creation is
                # disabled, require an existing Keycloak user and deny fallback to
                # synthetic claim-only identities.
                require_existing_kc_user = self._credential_login_require_existing_keycloak_user or not self._credential_login_create_users
                if not kc_user_id and require_existing_kc_user:
                    await self._redis.setex(
                        f"{_COMPLETE_KEY}{nonce}",
                        _COMPLETE_TTL,
                        json.dumps({"status": "failed", "reason": "keycloak_user_not_found"}),
                    )
                    await self._redis.delete(f"{_PENDING_KEY}{nonce}")
                    return auth_service_pb2.CredentialVerifiedResponse(ok=True, status="denied")
                if kc_user_id:
                    kc_tokens = await self._kc_admin.exchange_token_for_user(kc_user_id)
                    if kc_tokens and (kc_tokens.get("id_token") or kc_tokens.get("access_token")):
                        try:
                            keycloak_user = build_oidc_user_info(
                                id_token=kc_tokens.get("id_token"),
                                access_token=kc_tokens.get("access_token"),
                            )
                        except ValueError as kc_claim_exc:
                            logger.warning(
                                "KC token claim parsing failed during gRPC credential login for %s: %s",
                                email,
                                kc_claim_exc,
                            )
                    admin_keycloak_user = None
                    get_user_info = getattr(self._kc_admin, "get_user_info", None)
                    if callable(get_user_info):
                        admin_keycloak_user = await get_user_info(kc_user_id)
                    keycloak_user = merge_oidc_user_info(keycloak_user, admin_keycloak_user)
            except Exception as kc_exc:
                logger.warning("KC enrichment failed during gRPC credential login for %s: %s", email, kc_exc)
                require_existing_kc_user = self._credential_login_require_existing_keycloak_user or not self._credential_login_create_users
                if require_existing_kc_user:
                    await self._redis.setex(
                        f"{_COMPLETE_KEY}{nonce}",
                        _COMPLETE_TTL,
                        json.dumps({"status": "failed", "reason": "keycloak_user_not_eligible"}),
                    )
                    await self._redis.delete(f"{_PENDING_KEY}{nonce}")
                    return auth_service_pb2.CredentialVerifiedResponse(ok=True, status="denied")
        elif self._credential_login_require_existing_keycloak_user:
            await self._redis.setex(
                f"{_COMPLETE_KEY}{nonce}",
                _COMPLETE_TTL,
                json.dumps({"status": "failed", "reason": "keycloak_admin_unavailable"}),
            )
            await self._redis.delete(f"{_PENDING_KEY}{nonce}")
            return auth_service_pb2.CredentialVerifiedResponse(ok=True, status="denied")

        user = await build_credential_login_user(
            claims,
            self._user_provisioning,
            keycloak_user=keycloak_user,
        )
        user = apply_credential_login_defaults(user)
        if self._applicant_profile_provisioner is not None:
            try:
                applicant_id = await self._applicant_profile_provisioner(user)
                if applicant_id:
                    user.applicant_id = applicant_id
            except Exception as exc:
                logger.warning(
                    "Applicant profile provisioning failed during gRPC credential login for %s: %s",
                    email,
                    exc,
                )
        session = Session.create(user=user)

        if kc_tokens:
            session.id_token = kc_tokens.get("id_token")
            session.refresh_token = kc_tokens.get("refresh_token")

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
