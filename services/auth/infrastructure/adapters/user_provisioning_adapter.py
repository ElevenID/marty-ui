"""
User Provisioning Adapter

Implements UserProvisioningPort for JIT (Just-In-Time) user provisioning.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...application.ports import UserProvisioningPort
from ...domain.entities import AuthenticatedUser, OIDCUserInfo, UserType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Marty default organization ID (must match migration)
MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")


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
        organization_service_url: str | None = None,
    ):
        self.session_factory = session_factory
        self.organization_service_url = organization_service_url or os.environ.get(
            "ORGANIZATION_SERVICE_URL",
            "http://organization:8002"
        )
    
    async def _add_to_marty_organization(self, user_id: str, email: str) -> None:
        """
        Add a new user to the default Marty organization.
        
        This is a best-effort operation - if it fails, we log the error but
        don't fail the user provisioning process.
        """
        try:
            url = f"{self.organization_service_url}/internal/v1/organizations/{MARTY_ORG_ID}/members"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    url,
                    json={
                        "user_id": user_id,
                        "email": email,
                        "role": "member",
                    }
                )
                response.raise_for_status()
                logger.info(f"Successfully added user {user_id} to Marty organization")
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: "
                f"HTTP {e.response.status_code} - {e.response.text}"
            )
        except Exception as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: {e}",
                exc_info=True
            )
    
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
                is_new_user = False
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
                is_new_user = True
            
            user_id = str(applicant.id)
            
            # Ensure user is in the default Marty organization (idempotent - safe for all users)
            await self._add_to_marty_organization(user_id, applicant.email)
            
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
        organization_service_url: str | None = None,
    ):
        self._users: dict[str, AuthenticatedUser] = {}
        self.organization_service_url = organization_service_url or os.environ.get(
            "ORGANIZATION_SERVICE_URL",
            "http://organization:8002"
        )

    async def _add_to_marty_organization(self, user_id: str, email: str) -> None:
        """Add user to the default Marty organisation (idempotent, best-effort)."""
        try:
            url = f"{self.organization_service_url}/internal/v1/organizations/{MARTY_ORG_ID}/members"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    url,
                    json={"user_id": user_id, "email": email, "role": "member"},
                )
                response.raise_for_status()
                logger.info(f"Successfully added user {user_id} to Marty organization")
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: "
                f"HTTP {e.response.status_code} - {e.response.text}"
            )
        except Exception as e:
            logger.error(
                f"Failed to add user {user_id} to Marty organization: {e}",
                exc_info=True,
            )

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
                roles=list(oidc_user.roles),
                picture=oidc_user.picture,
            )
        
        self._users[oidc_user.sub] = user

        # Ensure user is in the default Marty organisation (idempotent)
        await self._add_to_marty_organization(oidc_user.sub, oidc_user.email)

        return user
