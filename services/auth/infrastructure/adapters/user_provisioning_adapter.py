"""
User Provisioning Adapter

Implements UserProvisioningPort for JIT (Just-In-Time) user provisioning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...application.ports import UserProvisioningPort
from ...domain.entities import AuthenticatedUser, OIDCUserInfo, UserType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class JITUserProvisioningAdapter(UserProvisioningPort):
    """
    Just-In-Time user provisioning adapter.
    
    Creates or updates users in the database when they authenticate
    via OIDC. This ensures the user exists in our system after
    successful authentication.
    """
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        """
        Provision or update user from OIDC info.
        
        1. Look up user by OIDC subject ID
        2. If not found, create new user
        3. If found, update user info
        4. Return AuthenticatedUser domain entity
        """
        # Import models here to avoid circular imports
        from src.applicant_service.models import Applicant
        from src.subscription.models import Organization, OrganizationMember
        
        async with self.session_factory() as session:
            # Look up existing applicant by OIDC subject or email
            result = await session.execute(
                select(Applicant).where(
                    (Applicant.oidc_subject == oidc_user.sub) |
                    (Applicant.email == oidc_user.email)
                )
            )
            applicant = result.scalar_one_or_none()
            
            if applicant:
                # Update existing user
                applicant.oidc_subject = oidc_user.sub
                applicant.email = oidc_user.email
                if oidc_user.given_name:
                    applicant.given_name = oidc_user.given_name
                if oidc_user.family_name:
                    applicant.family_name = oidc_user.family_name
                applicant.last_login = datetime.now(timezone.utc)
                await session.commit()
                await session.refresh(applicant)
            else:
                # Create new user
                applicant = Applicant(
                    oidc_subject=oidc_user.sub,
                    email=oidc_user.email,
                    given_name=oidc_user.given_name,
                    family_name=oidc_user.family_name,
                    created_at=datetime.now(timezone.utc),
                    last_login=datetime.now(timezone.utc),
                )
                session.add(applicant)
                await session.commit()
                await session.refresh(applicant)
            
            # Look up organization membership
            org_id = None
            org_name = None
            roles = list(oidc_user.roles)
            
            if applicant.id:
                result = await session.execute(
                    select(OrganizationMember, Organization)
                    .join(Organization)
                    .where(OrganizationMember.applicant_id == str(applicant.id))
                )
                membership = result.first()
                if membership:
                    member, org = membership
                    org_id = str(org.id)
                    org_name = org.name
                    roles.append(member.role.value)
            
            # Determine user type
            user_type = UserType.APPLICANT
            if "admin" in roles or "administrator" in roles:
                user_type = UserType.ADMINISTRATOR
            elif "vendor" in roles:
                user_type = UserType.VENDOR
            
            return AuthenticatedUser(
                user_id=str(applicant.id),
                email=applicant.email,
                username=oidc_user.preferred_username,
                given_name=applicant.given_name,
                family_name=applicant.family_name,
                user_type=user_type,
                applicant_id=str(applicant.id),
                roles=roles,
                organization_id=org_id,
                organization_name=org_name,
                onboarding_completed=getattr(applicant, 'onboarding_completed', None),
            )


class InMemoryUserProvisioningAdapter(UserProvisioningPort):
    """
    In-memory user provisioning adapter for testing.
    
    Creates AuthenticatedUser directly from OIDC info without
    database persistence.
    """
    
    def __init__(self):
        self._users: dict[str, AuthenticatedUser] = {}
    
    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        """Create or update user in memory."""
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
                roles=list(oidc_user.roles),
                organization_id=user.organization_id,
                organization_name=user.organization_name,
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
                roles=list(oidc_user.roles),
            )
        
        self._users[oidc_user.sub] = user
        return user
