"""
User Provisioning Adapter

Implements UserProvisioningPort for JIT (Just-In-Time) user provisioning.
"""

from __future__ import annotations

import logging
import os
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

import grpc
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from marty_common.system_ids import MARTY_DEFAULT_ORG_ID

from ...infrastructure.applicant_record_model import ApplicantRecord
from ...application.ports import UserProvisioningPort
from ...domain.entities import AuthenticatedUser, OIDCUserInfo, UserType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Marty default organization ID (must match migration)
MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID)
MARTY_ORG_SLUG = os.environ.get("MARTY_ORG_SLUG", "marty")
MARTY_ORG_NAME = os.environ.get("MARTY_ORG_NAME", "Marty")
UNKNOWN_DATE_OF_BIRTH = date(1900, 1, 1)
UNKNOWN_NATIONALITY = "UNK"


def _marty_organization_summary(
    org_id: str | None,
    org_name: str | None,
    role_names: list[str],
    has_org_console_access: bool,
) -> list[dict[str, object]]:
    """Build the org-membership shape the browser auth session expects."""
    if not org_id:
        return []

    return [{
        "id": org_id,
        "name": MARTY_ORG_SLUG,
        "display_name": org_name or MARTY_ORG_NAME,
        "membership": {
            "roles": [{"name": role_name, "display_name": role_name} for role_name in role_names],
            "status": "active",
            "permissions": [],
            "has_org_console_access": has_org_console_access,
            "is_owner": "owner" in set(role_names),
        },
    }]


class JITUserProvisioningAdapter(UserProvisioningPort):
    """
    Just-In-Time user provisioning adapter.
    
    Creates or updates users in the database when they authenticate
    via OIDC. This ensures the user exists in our system after
    successful authentication.
    
    Also automatically adds new users to the default Marty organization.
    """
    
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        org_grpc_channel=None,
    ):
        self.session_factory = session_factory
        self._org_stub = None
        if org_grpc_channel is not None:
            from marty_proto.v1.organization_service_pb2_grpc import OrganizationServiceStub
            self._org_stub = OrganizationServiceStub(org_grpc_channel)

    @staticmethod
    def _extract_names(oidc_user: OIDCUserInfo) -> tuple[str | None, str | None]:
        """Extract applicant-style names from OIDC claims."""
        given_names = (oidc_user.given_name or "").strip() or None
        surname = (oidc_user.family_name or "").strip() or None

        if not given_names and not surname and oidc_user.name:
            parts = oidc_user.name.strip().split(None, 1)
            if parts:
                given_names = parts[0] or None
                surname = parts[1].strip() or None if len(parts) > 1 else None

        return given_names, surname

    def _build_new_applicant_record(self, oidc_user: OIDCUserInfo) -> ApplicantRecord:
        """Build a new ApplicantRecord using the modern applicants table shape."""
        given_names, surname = self._extract_names(oidc_user)
        now = datetime.now(timezone.utc)
        return ApplicantRecord(
            id=str(uuid4()),
            account_id=oidc_user.sub,
            email=oidc_user.email,
            surname=surname or "Unknown",
            given_names=given_names or "Unknown",
            date_of_birth=UNKNOWN_DATE_OF_BIRTH,
            nationality=UNKNOWN_NATIONALITY,
            identity_proofing_completed=False,
            active=True,
            suspended=False,
            extra_data={
                "provisioned_via": "jit",
                "oidc_claims_incomplete": not (given_names and surname),
                "last_login_at": now.isoformat(),
            },
            created_at=now,
            updated_at=now,
        )

    def _update_applicant_record_from_oidc(
        self,
        applicant: ApplicantRecord,
        oidc_user: OIDCUserInfo,
    ) -> None:
        """Apply mutable OIDC fields to an existing ApplicantRecord."""
        given_names, surname = self._extract_names(oidc_user)
        applicant.account_id = oidc_user.sub
        applicant.email = oidc_user.email
        if given_names:
            applicant.given_names = given_names
        if surname:
            applicant.surname = surname
        applicant.updated_at = datetime.now(timezone.utc)
        extra_data = dict(applicant.extra_data or {})
        extra_data.update(
            {
                "provisioned_via": "jit",
                "oidc_claims_incomplete": not (given_names and surname),
                "last_login_at": applicant.updated_at.isoformat(),
            }
        )
        applicant.extra_data = extra_data

    @staticmethod
    def _to_authenticated_name_parts(applicant: ApplicantRecord) -> tuple[str | None, str | None]:
        given_name = (applicant.given_names or "").strip() or None
        family_name = (applicant.surname or "").strip() or None
        if given_name == "Unknown":
            given_name = None
        if family_name == "Unknown":
            family_name = None
        return given_name, family_name
    
    async def _add_to_marty_organization(self, user_id: str, email: str) -> bool:
        """
        Add a new user to the default Marty organization via gRPC.
        Best-effort — failures are logged but don't block provisioning.
        """
        if self._org_stub is None:
            logger.warning("No org gRPC channel — skipping auto-add to Marty org")
            return False
        try:
            from marty_proto.v1 import organization_service_pb2
            await self._org_stub.AddMember(
                organization_service_pb2.AddMemberRequest(
                    organization_id=MARTY_ORG_ID,
                    user_id=user_id,
                    email=email,
                ),
                timeout=5.0,
            )
            logger.info(f"Successfully added user {user_id} to Marty organization")
            return True
        except Exception as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: {e}",
                exc_info=True
            )
            return False

    async def _resolve_marty_organization_context(
        self,
        user_id: str,
    ) -> tuple[str | None, str | None, list[str], bool, bool]:
        """Resolve the user's default organization context through gRPC.

        This replaces the legacy direct join against the retired monolith
        subscription tables so auth no longer depends on that codepath just to
        enrich the authenticated user object.
        """
        if self._org_stub is None:
            return None, None, [], False, True

        from marty_proto.v1 import organization_service_pb2

        try:
            member = await self._org_stub.GetMember(
                organization_service_pb2.GetMemberRequest(
                    organization_id=MARTY_ORG_ID,
                    user_id=user_id,
                ),
                timeout=5.0,
            )
        except grpc.RpcError as exc:
            if exc.code() == grpc.StatusCode.NOT_FOUND:
                return None, None, [], False, False
            logger.warning(
                "Failed to resolve Marty org membership for %s: %s",
                user_id,
                exc,
            )
            return None, None, [], False, True
        except Exception as exc:
            logger.warning(
                "Unexpected error resolving Marty org membership for %s: %s",
                user_id,
                exc,
            )
            return None, None, [], False, True

        org_id = member.organization_id or None
        member_role_names = [role.name for role in member.roles]
        has_org_console_access = bool(member.has_org_console_access)
        if not org_id:
            return None, None, [], False, False

        org_name = None
        try:
            org = await self._org_stub.GetOrganization(
                organization_service_pb2.GetOrganizationRequest(
                    organization_id=org_id,
                ),
                timeout=5.0,
            )
            org_name = org.display_name or org.name or None
        except grpc.RpcError as exc:
            logger.warning(
                "Failed to resolve Marty org details for %s (%s): %s",
                user_id,
                org_id,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error resolving Marty org details for %s (%s): %s",
                user_id,
                org_id,
                exc,
            )

        return org_id, org_name, member_role_names, has_org_console_access, False
    
    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        """
        Provision or update user from OIDC info.
        
        1. Look up user by OIDC subject ID
        2. If not found, create new user
        3. If found, update user info
        4. Return AuthenticatedUser domain entity
        """
        async with self.session_factory() as session:
            # Look up existing applicant by OIDC subject/account linkage or email.
            result = await session.execute(
                select(ApplicantRecord).where(
                    ApplicantRecord.deleted_at.is_(None),
                    or_(
                        ApplicantRecord.account_id == oidc_user.sub,
                        ApplicantRecord.email == oidc_user.email,
                    ),
                )
            )
            applicant = result.scalar_one_or_none()
            
            if applicant:
                # Update existing user.
                self._update_applicant_record_from_oidc(applicant, oidc_user)
                await session.commit()
                await session.refresh(applicant)
            else:
                # Create new user.
                applicant = self._build_new_applicant_record(oidc_user)
                session.add(applicant)
                await session.commit()
                await session.refresh(applicant)
            
            user_id = str(applicant.id)
            given_name, family_name = self._to_authenticated_name_parts(applicant)
            
            # Ensure user is in the default Marty organization (idempotent - safe for all users)
            marty_add_succeeded = await self._add_to_marty_organization(user_id, applicant.email)
            
            # Resolve organization membership via the organization service.
            org_id, org_name, member_role_names, has_org_console_access, org_context_unavailable = (
                await self._resolve_marty_organization_context(user_id)
            )
            org_context_unavailable = org_context_unavailable or not marty_add_succeeded
            roles = list(oidc_user.roles)
            for member_role_name in member_role_names:
                if member_role_name not in roles:
                    roles.append(member_role_name)
            
            # Determine user type
            user_type = UserType.APPLICANT
            if "admin" in roles or "administrator" in roles:
                user_type = UserType.ADMINISTRATOR
            elif has_org_console_access or "vendor" in roles:
                user_type = UserType.VENDOR
            
            return AuthenticatedUser(
                user_id=str(applicant.id),
                email=applicant.email,
                username=oidc_user.preferred_username,
                given_name=given_name,
                family_name=family_name,
                user_type=user_type,
                applicant_id=str(applicant.id),
                roles=roles,
                organization_id=org_id or oidc_user.organization_id,
                organization_name=org_name or oidc_user.organization_name,
                organization=oidc_user.organization,
                default_organization_id=org_id or oidc_user.organization_id,
                default_organization_name=org_name or oidc_user.organization_name,
                organizations=_marty_organization_summary(
                    org_id,
                    org_name,
                    member_role_names,
                    has_org_console_access,
                ),
                organization_context_unavailable=org_context_unavailable,
                organization_context_error=(
                    "marty_organization_context_unavailable"
                    if org_context_unavailable else None
                ),
                onboarding_completed=(
                    applicant.identity_proofing_date
                    if applicant.identity_proofing_completed
                    else None
                ),
                picture=oidc_user.picture,
            )


class InMemoryUserProvisioningAdapter(UserProvisioningPort):
    """
    In-memory user provisioning adapter for testing.
    
    Creates AuthenticatedUser directly from OIDC info without
    database persistence.  Still calls the organization service to
    ensure every authenticated user is added to the default Marty
    organisation (best-effort, idempotent).
    """
    
    def __init__(
        self,
        org_grpc_channel=None,
    ):
        self._users: dict[str, AuthenticatedUser] = {}
        self._org_stub = None
        if org_grpc_channel is not None:
            from marty_proto.v1.organization_service_pb2_grpc import OrganizationServiceStub
            self._org_stub = OrganizationServiceStub(org_grpc_channel)

    async def _add_to_marty_organization(self, user_id: str, email: str) -> bool:
        """Add user to the default Marty organisation via gRPC (idempotent, best-effort)."""
        if self._org_stub is None:
            logger.warning("No org gRPC channel — skipping auto-add to Marty org")
            return False
        try:
            from marty_proto.v1 import organization_service_pb2
            await self._org_stub.AddMember(
                organization_service_pb2.AddMemberRequest(
                    organization_id=MARTY_ORG_ID,
                    user_id=user_id,
                    email=email,
                ),
                timeout=5.0,
            )
            logger.info(f"Successfully added user {user_id} to Marty organization")
            return True
        except Exception as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: {e}",
                exc_info=True,
            )
            return False

    async def _resolve_marty_organization_context(
        self,
        user_id: str,
    ) -> tuple[str | None, str | None, list[str], bool, bool]:
        """Resolve the user's Marty membership and org display name via gRPC."""
        if self._org_stub is None:
            return None, None, [], False, True

        from marty_proto.v1 import organization_service_pb2

        try:
            member = await self._org_stub.GetMember(
                organization_service_pb2.GetMemberRequest(
                    organization_id=MARTY_ORG_ID,
                    user_id=user_id,
                ),
                timeout=5.0,
            )
        except grpc.RpcError as exc:
            if exc.code() == grpc.StatusCode.NOT_FOUND:
                return None, None, [], False, False
            logger.warning(
                "Failed to resolve Marty org membership for %s: %s",
                user_id,
                exc,
            )
            return None, None, [], False, True
        except Exception as exc:
            logger.warning(
                "Unexpected error resolving Marty org membership for %s: %s",
                user_id,
                exc,
            )
            return None, None, [], False, True

        org_id = member.organization_id or None
        member_role_names = [role.name for role in member.roles]
        has_org_console_access = bool(member.has_org_console_access)
        if not org_id:
            return None, None, [], False, False

        org_name = None
        try:
            org = await self._org_stub.GetOrganization(
                organization_service_pb2.GetOrganizationRequest(
                    organization_id=org_id,
                ),
                timeout=5.0,
            )
            org_name = org.display_name or org.name or None
        except grpc.RpcError as exc:
            logger.warning(
                "Failed to resolve Marty org details for %s (%s): %s",
                user_id,
                org_id,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error resolving Marty org details for %s (%s): %s",
                user_id,
                org_id,
                exc,
            )

        return org_id, org_name, member_role_names, has_org_console_access, False

    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        """Create or update user in memory."""
        org_id = None
        org_name = None
        roles = list(oidc_user.roles)

        # Check if user exists
        if oidc_user.sub in self._users:
            user = self._users[oidc_user.sub]
            # Update mutable fields
            user = AuthenticatedUser(
                user_id=user.user_id,
                email=oidc_user.email,
                username=oidc_user.preferred_username,
                given_name=oidc_user.given_name,
                family_name=oidc_user.family_name,
                user_type=user.user_type,
                applicant_id=user.applicant_id,
                roles=roles,
                organization_id=oidc_user.organization_id or user.organization_id,
                organization_name=oidc_user.organization_name or user.organization_name,
                organization=oidc_user.organization or user.organization,
                picture=oidc_user.picture,
            )
        else:
            # Create new user
            user = AuthenticatedUser(
                user_id=oidc_user.sub,
                email=oidc_user.email,
                username=oidc_user.preferred_username,
                given_name=oidc_user.given_name,
                family_name=oidc_user.family_name,
                user_type=UserType.APPLICANT,
                applicant_id=oidc_user.sub,
                roles=roles,
                organization_id=oidc_user.organization_id,
                organization_name=oidc_user.organization_name,
                organization=oidc_user.organization,
                picture=oidc_user.picture,
            )

        # Ensure user is in the default Marty organisation (idempotent)
        marty_add_succeeded = await self._add_to_marty_organization(oidc_user.sub, oidc_user.email)

        # Resolve organization membership after the add so the session includes it.
        org_id, org_name, member_role_names, has_org_console_access, org_context_unavailable = (
            await self._resolve_marty_organization_context(oidc_user.sub)
        )
        org_context_unavailable = org_context_unavailable or not marty_add_succeeded
        for member_role_name in member_role_names:
            if member_role_name not in roles:
                roles.append(member_role_name)

        user_type = UserType.APPLICANT
        if "admin" in roles or "administrator" in roles:
            user_type = UserType.ADMINISTRATOR
        elif has_org_console_access or "vendor" in roles:
            user_type = UserType.VENDOR

        user = AuthenticatedUser(
            user_id=user.user_id,
            email=oidc_user.email,
            username=oidc_user.preferred_username,
            given_name=oidc_user.given_name,
            family_name=oidc_user.family_name,
            user_type=user_type,
            applicant_id=user.applicant_id,
            roles=roles,
            organization_id=org_id or oidc_user.organization_id,
            organization_name=org_name or oidc_user.organization_name,
            organization=oidc_user.organization,
            default_organization_id=org_id or oidc_user.organization_id,
            default_organization_name=org_name or oidc_user.organization_name,
            organizations=_marty_organization_summary(
                org_id,
                org_name,
                member_role_names,
                has_org_console_access,
            ),
            organization_context_unavailable=org_context_unavailable,
            organization_context_error=(
                "marty_organization_context_unavailable"
                if org_context_unavailable else None
            ),
            picture=oidc_user.picture,
        )

        self._users[oidc_user.sub] = user

        return user
