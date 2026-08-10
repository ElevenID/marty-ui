"""
Auth Service gRPC Adapter (Inbound)

Implements the AuthService gRPC servicer, delegating to the same
use cases that back the internal REST endpoints.  Runs alongside
the existing FastAPI application (hybrid mode).
"""

from __future__ import annotations

from typing import Any

import grpc

from marty_proto.v1 import auth_service_pb2, auth_service_pb2_grpc

from ...application.ports import UserProvisioningPort, ValidateSessionQuery
from ...application.use_cases import SessionUseCase
from ...domain.entities import AuthenticatedUser


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
        # Retain the constructor shape while deployed callers migrate away from
        # the retired mutation RPC dependencies.
        del (
            redis_client,
            kc_admin_adapter,
            user_provisioning,
            applicant_profile_provisioner,
        )
        self._session_use_case = session_use_case
        self._session_repository = session_repository

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
        del request
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details(
            "Direct session creation is retired; use an authoritative login flow"
        )
        return auth_service_pb2.CreateSessionResponse()

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
        del request
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details(
            "The gRPC credential callback is retired; use the authenticated internal HTTP callback"
        )
        return auth_service_pb2.CredentialVerifiedResponse(ok=False)

    # ------------------------------------------------------------------
    # HealthCheck
    # ------------------------------------------------------------------

    async def HealthCheck(
        self,
        request: auth_service_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> auth_service_pb2.HealthCheckResponse:
        return auth_service_pb2.HealthCheckResponse(status="serving")
