"""
Organization Service gRPC Adapter (Inbound)

Implements the OrganizationService gRPC servicer, delegating to the same
use cases that back the internal REST endpoints.  Runs alongside
the existing FastAPI application (hybrid mode).
"""

from __future__ import annotations

import logging
from typing import Any

import grpc

from marty_proto.v1 import organization_service_pb2, organization_service_pb2_grpc

from ...application.use_cases import ApiKeyUseCase, MemberUseCase, OrganizationUseCase
from ...domain.entities import MemberRole

logger = logging.getLogger(__name__)


def _org_to_pb(org: Any) -> organization_service_pb2.OrganizationResponse:
    """Map domain Organization → protobuf OrganizationResponse."""
    return organization_service_pb2.OrganizationResponse(
        id=str(org.id),
        name=org.name,
        display_name=org.display_name or "",
        slug=org.slug,
        description=org.description or "",
        org_type=org.org_type.value,
        status=org.status.value,
        contact_email=org.contact_email or "",
        contact_phone=org.contact_phone or "",
        website=org.website or "",
        join_mechanism=org.join_mechanism.value,
        requires_approval=org.requires_approval,
        is_discoverable=org.is_discoverable,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )


def _member_to_pb(member: Any) -> organization_service_pb2.MemberResponse:
    """Map domain Member → protobuf MemberResponse."""
    return organization_service_pb2.MemberResponse(
        id=str(member.id),
        organization_id=str(member.organization_id),
        user_id=str(member.user_id) if member.user_id else "",
        email=member.email or "",
        role=member.role.value,
        status=member.status.value,
        invited_at=member.invited_at.isoformat() if member.invited_at else "",
        joined_at=member.joined_at.isoformat() if member.joined_at else "",
    )


class OrganizationServiceGrpc(organization_service_pb2_grpc.OrganizationServiceServicer):
    """gRPC inbound adapter for the organization service."""

    def __init__(
        self,
        org_use_case: OrganizationUseCase,
        member_use_case: MemberUseCase,
        api_key_use_case: ApiKeyUseCase,
        role_use_case: Any,
    ) -> None:
        self._org_uc = org_use_case
        self._member_uc = member_use_case
        self._api_key_uc = api_key_use_case
        self._role_uc = role_use_case

    # ------------------------------------------------------------------
    # GetOrganization
    # ------------------------------------------------------------------

    async def GetOrganization(self, request, context):
        org = await self._org_uc.get_organization(request.organization_id)
        if not org:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Organization not found")
            return organization_service_pb2.OrganizationResponse()
        return _org_to_pb(org)

    # ------------------------------------------------------------------
    # GetMember — hot path, called on every authorized request
    # ------------------------------------------------------------------

    async def GetMember(self, request, context):
        try:
            member = await self._member_uc.get_membership(
                request.user_id, request.organization_id
            )
        except ValueError as exc:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(exc))
            return organization_service_pb2.MemberResponse()

        if not member:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Membership not found")
            return organization_service_pb2.MemberResponse()
        return _member_to_pb(member)

    # ------------------------------------------------------------------
    # AddMember
    # ------------------------------------------------------------------

    async def AddMember(self, request, context):
        try:
            member = await self._member_uc.add_member_direct(
                organization_id=request.organization_id,
                user_id=request.user_id,
                email=request.email or None,
                role=MemberRole(request.role) if request.role else MemberRole.MEMBER,
            )
            return _member_to_pb(member)
        except ValueError as exc:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(exc))
            return organization_service_pb2.MemberResponse()

    # ------------------------------------------------------------------
    # ListMembers
    # ------------------------------------------------------------------

    async def ListMembers(self, request, context):
        members = await self._member_uc.list_members(request.organization_id)
        return organization_service_pb2.ListMembersResponse(
            members=[_member_to_pb(m) for m in members],
        )

    # ------------------------------------------------------------------
    # ValidateApiKey — hot path, called on every API-key-authenticated request
    # ------------------------------------------------------------------

    async def ValidateApiKey(self, request, context):
        api_key = await self._api_key_uc.validate_api_key(request.api_key)
        if not api_key:
            return organization_service_pb2.ValidateApiKeyResponse(valid=False)
        return organization_service_pb2.ValidateApiKeyResponse(
            valid=True,
            api_key_id=api_key.id,
            organization_id=api_key.organization_id,
            key_prefix=api_key.key_prefix,
            scopes=api_key.scopes or [],
        )

    # ------------------------------------------------------------------
    # GetMemberPermissions
    # ------------------------------------------------------------------

    async def GetMemberPermissions(self, request, context):
        member = await self._member_uc.get_membership(
            request.user_id, request.organization_id
        )
        if not member:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Membership not found")
            return organization_service_pb2.GetMemberPermissionsResponse()

        permissions = await self._role_uc.get_member_permissions(member.id)
        return organization_service_pb2.GetMemberPermissionsResponse(
            permissions=[p.key for p in permissions],
        )

    # ------------------------------------------------------------------
    # HealthCheck
    # ------------------------------------------------------------------

    async def HealthCheck(self, request, context):
        return organization_service_pb2.HealthCheckResponse(status="serving")
