"""
Organization and subscription services.

Business logic for organization management including email domain matching,
membership management, and subscription operations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def find_organizations_by_email_domain(
    session: AsyncSession, email: str
) -> list[dict[str, str]]:
    """
    Find organizations that match the email domain.

    Checks the allowed_email_domains setting in each organization's
    settings JSON column. Returns organizations where:
    1. The email domain is in the allowed_email_domains list
    2. The organization is discoverable (is_discoverable = true)

    Args:
        session: Database session
        email: User's email address

    Returns:
        List of dicts with organization info: id, name, domain_join_policy, default_role
    """
    from sqlalchemy import select
    from subscription.models import Organization

    # Extract domain from email
    if "@" not in email:
        logger.warning(f"Invalid email format: {email}")
        return []

    domain = email.split("@")[1].lower()
    logger.info(f"Looking for organizations matching email domain: {domain}")

    # Query all discoverable organizations
    # We have to filter in Python since JSON querying varies by database
    result = await session.execute(
        select(Organization).where(Organization.is_active == True)
    )
    organizations = result.scalars().all()

    matched_orgs = []
    for org in organizations:
        settings = org.settings or {}

        # Check if discoverable
        if not settings.get("is_discoverable", False):
            continue

        # Check if domain matches
        allowed_domains = settings.get("allowed_email_domains", [])
        if domain not in allowed_domains:
            continue

        # Organization matches!
        domain_join_policy = settings.get("domain_join_policy", "approval")
        default_role = settings.get("default_role", "member")

        matched_orgs.append({
            "id": org.id,
            "name": org.name,
            "domain_join_policy": domain_join_policy,
            "default_role": default_role,
        })

        logger.info(
            f"Matched organization: {org.name} (policy: {domain_join_policy}, role: {default_role})"
        )

    return matched_orgs


async def auto_join_organization(
    session: AsyncSession, org_id: str, user_id: str, role: str = "member"
) -> bool:
    """
    Automatically add a user to an organization based on email domain policy.

    Args:
        session: Database session
        org_id: Organization ID
        user_id: User ID (OIDC sub)
        role: Member role to assign

    Returns:
        True if user was added, False otherwise
    """
    from datetime import datetime, timezone
    from uuid import uuid4
    from subscription.models import OrganizationMember, MemberRole

    try:
        # Parse role enum
        try:
            member_role = MemberRole(role)
        except ValueError:
            logger.warning(f"Invalid role: {role}, defaulting to MEMBER")
            member_role = MemberRole.MEMBER

        # Create membership
        membership = OrganizationMember(
            id=str(uuid4()),
            organization_id=org_id,
            user_id=user_id,
            role=member_role,
            joined_at=datetime.now(timezone.utc),
        )

        session.add(membership)
        await session.commit()
        logger.info(f"Auto-joined user {user_id} to organization {org_id} as {role}")
        return True

    except Exception as e:
        logger.error(f"Failed to auto-join user to organization: {e}", exc_info=True)
        await session.rollback()
        return False
