"""
Organization Service Use Cases
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..domain.entities import ApiKey, ConsoleContextPreference, JoinMechanism, Member, MemberRole, MemberStatus, Organization, ViewMode
from ..domain.events import (
    ApiKeyCreatedEvent,
    ApiKeyRevokedEvent,
    MemberAddedEvent,
    MemberInvitedEvent,
    MemberRemovedEvent,
    OrganizationCreatedEvent,
    OrganizationUpdatedEvent,
)
from .ports import (
    ApiKeyRepositoryPort,
    ConsoleContextPreferenceRepositoryPort,
    CreateApiKeyCommand,
    CreateOrganizationCommand,
    EventPublisherPort,
    InviteMemberCommand,
    JoinByCodeCommand,
    JoinOrganizationCommand,
    JoinCodeRepositoryPort,
    MemberRepositoryPort,
    OrganizationRepositoryPort,
    RevokeApiKeyCommand,
    UpdateMemberRoleCommand,
    UpdateOrganizationCommand,
    UpsertConsoleContextPreferenceCommand,
)

logger = logging.getLogger(__name__)

_ORG_TYPE_ALIASES: dict[str, str] = {
    "vendor": "enterprise",
    "nonprofit": "individual",
}


def _normalize_org_type(value: str | None) -> str | None:
    """Normalize external org type aliases to canonical OrganizationType values."""
    if not value:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    return _ORG_TYPE_ALIASES.get(normalized, normalized)


@dataclass
class OrganizationUseCase:
    """Use cases for organization management."""
    
    organization_repo: OrganizationRepositoryPort
    member_repo: MemberRepositoryPort
    event_publisher: EventPublisherPort
    role_use_case: Any = None  # Optional[RoleUseCase] — avoids circular import
    
    async def create_organization(self, command: CreateOrganizationCommand) -> Organization:
        """Create a new organization with owner."""
        # Create organization and owner membership
        org, owner = Organization.create(
            name=command.name,
            owner_id=command.owner_id,
            org_type=command.org_type,
            display_name=command.display_name,
            description=command.description,
        )
        
        if command.contact_email:
            org.contact_email = command.contact_email
        
        # Save both
        await self.organization_repo.save(org)
        await self.member_repo.save(owner)
        
        # Seed default RBAC roles and assign owner role
        if self.role_use_case is not None:
            try:
                created_roles = await self.role_use_case.seed_default_roles(org.id)
                # Assign the "owner" role to the creating user
                if "owner" in created_roles:
                    from .ports import AddMemberRoleCommand
                    await self.role_use_case.add_member_role(
                        AddMemberRoleCommand(
                            organization_id=org.id,
                            member_id=owner.id,
                            role_id=created_roles["owner"].id,
                            assigned_by=command.owner_id,
                        )
                    )
            except Exception as e:
                logger.warning(f"Failed to seed RBAC roles for org {org.id}: {e}")
        
        # Publish event
        await self.event_publisher.publish(
            OrganizationCreatedEvent(
                organization_id=org.id,
                name=org.name,
                owner_user_id=command.owner_id,
            )
        )
        
        logger.info(f"Organization {org.name} created with owner {command.owner_id}")
        return org
    
    async def update_organization(self, command: UpdateOrganizationCommand) -> Organization:
        """Update an organization."""
        org = await self.organization_repo.get_by_id(command.organization_id)
        if not org:
            raise ValueError(f"Organization {command.organization_id} not found")
        
        updated_fields = []
        
        if command.name is not None:
            org.name = command.name
            updated_fields.append("name")
        if command.description is not None:
            org.description = command.description
            updated_fields.append("description")
        if command.contact_email is not None:
            org.contact_email = command.contact_email
            updated_fields.append("contact_email")
        if command.contact_phone is not None:
            org.contact_phone = command.contact_phone
            updated_fields.append("contact_phone")
        if command.website is not None:
            org.website = command.website
            updated_fields.append("website")
        if command.settings is not None:
            org.update_settings(command.settings)
            updated_fields.append("settings")
        
        await self.organization_repo.save(org)
        
        await self.event_publisher.publish(
            OrganizationUpdatedEvent(
                organization_id=org.id,
                updated_fields=updated_fields,
            )
        )
        
        return org
    
    async def get_organization(self, org_id: str) -> Organization | None:
        """Get organization by ID."""
        return await self.organization_repo.get_by_id(org_id)
    
    async def list_organizations(self, limit: int = 100, offset: int = 0) -> list[Organization]:
        """List all organizations."""
        return await self.organization_repo.list_all(limit, offset)
    
    async def get_user_organizations(self, user_id: str) -> list[Organization]:
        """Get all organizations a user belongs to."""
        memberships = await self.member_repo.list_by_user(user_id)
        orgs = []
        for membership in memberships:
            if membership.status == MemberStatus.ACTIVE:
                org = await self.organization_repo.get_by_id(membership.organization_id)
                if org:
                    orgs.append(org)
        return orgs
    
    async def get_user_organizations_with_memberships(self, user_id: str) -> list[tuple[Organization, Member]]:
        """Get all organizations a user belongs to with membership details."""
        memberships = await self.member_repo.list_by_user(user_id)
        results = []
        for membership in memberships:
            if membership.status == MemberStatus.ACTIVE:
                org = await self.organization_repo.get_by_id(membership.organization_id)
                if org:
                    results.append((org, membership))
        return results
    
    async def discover_organizations(
        self,
        search: str | None = None,
        org_type: str | None = None,
        join_mechanism: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Organization]:
        """Discover publicly available organizations with optional filters."""
        from ..domain.entities import OrganizationType
        
        # Convert org_type string/alias to enum if provided
        org_type_enum = None
        normalized_org_type = _normalize_org_type(org_type)
        if normalized_org_type:
            try:
                org_type_enum = OrganizationType(normalized_org_type)
            except ValueError:
                raise ValueError(f"Invalid organization type: {org_type}")
        
        return await self.organization_repo.list_discoverable(
            search=search,
            org_type=org_type_enum,
            join_mechanism=join_mechanism,
            limit=limit,
            offset=offset,
        )


@dataclass
class MemberUseCase:
    """Use cases for member management."""
    
    member_repo: MemberRepositoryPort
    organization_repo: OrganizationRepositoryPort
    event_publisher: EventPublisherPort
    
    async def invite_member(self, command: InviteMemberCommand) -> Member:
        """Invite a new member to an organization."""
        # Verify organization exists
        org = await self.organization_repo.get_by_id(command.organization_id)
        if not org:
            raise ValueError(f"Organization {command.organization_id} not found")
        
        # Check for existing invitation
        existing = await self.member_repo.get_by_email_and_org(
            command.email, command.organization_id
        )
        if existing:
            raise ValueError(f"User {command.email} already invited or is a member")
        
        # Create invitation
        member = Member.create_invitation(
            organization_id=command.organization_id,
            email=command.email,
            role=command.role,
            invited_by=command.invited_by,
        )
        
        await self.member_repo.save(member)
        
        await self.event_publisher.publish(
            MemberInvitedEvent(
                organization_id=command.organization_id,
                member_id=member.id,
                email=command.email,
                invited_by=command.invited_by,
            )
        )
        
        logger.info(f"Invited {command.email} to organization {org.name}")
        return member
    
    async def accept_invitation(self, member_id: str, user_id: str) -> Member:
        """Accept an invitation."""
        member = await self.member_repo.get_by_id(member_id)
        if not member:
            raise ValueError(f"Invitation {member_id} not found")
        
        member.accept_invitation(user_id)
        await self.member_repo.save(member)
        
        await self.event_publisher.publish(
            MemberAddedEvent(
                organization_id=member.organization_id,
                member_id=member.id,
                user_id=user_id,
                role=member.role.value,
            )
        )
        
        return member
    
    async def update_role(self, command: UpdateMemberRoleCommand) -> Member:
        """Update a member's role."""
        member = await self.member_repo.get_by_id(command.member_id)
        if not member:
            raise ValueError(f"Member {command.member_id} not found")
        
        # Cannot demote the last owner
        if member.role == MemberRole.OWNER and command.new_role != MemberRole.OWNER:
            members = await self.member_repo.list_by_organization(member.organization_id)
            owners = [m for m in members if m.role == MemberRole.OWNER]
            if len(owners) <= 1:
                raise ValueError("Cannot demote the only owner")
        
        member.change_role(command.new_role)
        await self.member_repo.save(member)
        
        return member
    
    async def remove_member(self, member_id: str, removed_by: str) -> None:
        """Remove a member from an organization."""
        member = await self.member_repo.get_by_id(member_id)
        if not member:
            raise ValueError(f"Member {member_id} not found")
        
        # Cannot remove the last owner
        if member.role == MemberRole.OWNER:
            members = await self.member_repo.list_by_organization(member.organization_id)
            owners = [m for m in members if m.role == MemberRole.OWNER]
            if len(owners) <= 1:
                raise ValueError("Cannot remove the only owner")
        
        await self.member_repo.delete(member_id)
        
        await self.event_publisher.publish(
            MemberRemovedEvent(
                organization_id=member.organization_id,
                member_id=member.id,
                user_id=member.user_id,
            )
        )
    
    async def list_members(self, org_id: str) -> list[Member]:
        """List all members of an organization."""
        return await self.member_repo.list_by_organization(org_id)
    
    async def get_membership(self, user_id: str, org_id: str) -> Member | None:
        """Get a user's membership in an organization."""
        return await self.member_repo.get_by_user_and_org(user_id, org_id)

    async def add_member_direct(
        self,
        organization_id: str,
        user_id: str,
        email: str | None = None,
        role: MemberRole = MemberRole.MEMBER,
    ) -> Member:
        """Directly add an active member to an organization (idempotent).

        Used by internal service-to-service calls (e.g. auth provisioning)
        to bypass the invitation flow and add a user as an active member
        immediately.

        Lookup order:
        1. Exact match by user_id + org (normal case — returning users).
        2. Match by email + org with blank user_id (pre-seeded admin row from
           migration).  In this case the row's user_id is updated to link the
           authenticated user and the pre-assigned role is preserved.
        3. No match — create a new member with the supplied role.
        """
        # 1. Check by user_id (covers all returning users)
        existing = await self.member_repo.get_by_user_and_org(user_id, organization_id)
        if existing:
            return existing

        # 2. Check by email for a pre-seeded row (e.g. admin seeded by migration)
        if email:
            email_match = await self.member_repo.get_by_email_and_org(email, organization_id)
            if email_match and not email_match.user_id:
                # Link the authenticated user to the pre-seeded record,
                # preserving whatever role the migration assigned.
                email_match.user_id = user_id
                email_match.joined_at = datetime.now(timezone.utc)
                email_match.updated_at = datetime.now(timezone.utc)
                await self.member_repo.save(email_match)
                logger.info(
                    f"Linked user {user_id} to pre-seeded member record for {email} "
                    f"in org {organization_id} (role={email_match.role.value})"
                )
                return email_match

        # 3. Create new member
        member = Member.create(
            organization_id=organization_id,
            user_id=user_id,
            email=email,
            role=role,
            status=MemberStatus.ACTIVE,
        )
        await self.member_repo.save(member)

        await self.event_publisher.publish(
            MemberAddedEvent(
                organization_id=organization_id,
                member_id=member.id,
                user_id=user_id,
                role=role.value,
            )
        )

        logger.info(f"Directly added user {user_id} to organization {organization_id} as {role.value}")
        return member


@dataclass
class ApiKeyUseCase:
    """Use cases for API key management."""
    
    api_key_repo: ApiKeyRepositoryPort
    organization_repo: OrganizationRepositoryPort
    event_publisher: EventPublisherPort
    
    async def create_api_key(self, command: CreateApiKeyCommand) -> tuple[ApiKey, str]:
        """
        Create a new API key.
        
        Returns the API key and the raw key value.
        The raw key is only returned once at creation.
        """
        # Verify organization exists
        org = await self.organization_repo.get_by_id(command.organization_id)
        if not org:
            raise ValueError(f"Organization {command.organization_id} not found")
        
        # Create API key
        api_key, raw_key = ApiKey.create(
            organization_id=command.organization_id,
            name=command.name,
            created_by=command.created_by,
            scopes=command.scopes,
            description=command.description,
            is_test=command.is_test,
        )
        
        await self.api_key_repo.save(api_key)
        
        await self.event_publisher.publish(
            ApiKeyCreatedEvent(
                organization_id=command.organization_id,
                api_key_id=api_key.id,
                name=command.name,
                created_by=command.created_by,
            )
        )
        
        logger.info(f"Created API key {api_key.name} for organization {org.name}")
        return api_key, raw_key
    
    async def revoke_api_key(self, command: RevokeApiKeyCommand) -> ApiKey:
        """Revoke an API key."""
        api_key = await self.api_key_repo.get_by_id(command.api_key_id)
        if not api_key:
            raise ValueError(f"API key {command.api_key_id} not found")
        
        api_key.revoke()
        await self.api_key_repo.save(api_key)
        
        await self.event_publisher.publish(
            ApiKeyRevokedEvent(
                organization_id=api_key.organization_id,
                api_key_id=api_key.id,
                revoked_by=command.revoked_by,
            )
        )
        
        return api_key
    
    async def validate_api_key(self, raw_key: str) -> ApiKey | None:
        """Validate an API key and return it if valid."""
        key_hash = ApiKey.hash_key(raw_key)
        api_key = await self.api_key_repo.get_by_hash(key_hash)
        
        if not api_key or not api_key.is_valid:
            return None
        
        return api_key
    
    async def list_api_keys(self, org_id: str) -> list[ApiKey]:
        """List all API keys for an organization."""
        return await self.api_key_repo.list_by_organization(org_id)
    
    async def get_api_key(self, key_id: str) -> ApiKey | None:
        """Get API key by ID."""
        return await self.api_key_repo.get_by_id(key_id)


@dataclass
class ConsoleContextPreferenceUseCase:
    """Use cases for console context preferences."""
    
    preference_repo: ConsoleContextPreferenceRepositoryPort
    
    async def get_preferences(self, user_id: str) -> ConsoleContextPreference:
        """Get user's console context preferences, return defaults if none exist."""
        preference = await self.preference_repo.get_by_user_id(user_id)
        
        if not preference:
            # Return default preferences
            preference = ConsoleContextPreference(
                user_id=user_id,
                last_view_mode=ViewMode.APPLICANT,
                last_active_org_id=None,
            )
        
        return preference
    
    async def upsert_preferences(
        self,
        command: UpsertConsoleContextPreferenceCommand,
    ) -> ConsoleContextPreference:
        """Upsert user's console context preferences."""
        # Get existing or create new
        preference = await self.preference_repo.get_by_user_id(command.user_id)
        
        if not preference:
            preference = ConsoleContextPreference(
                user_id=command.user_id,
                last_view_mode=ViewMode.APPLICANT,
                last_active_org_id=None,
            )
        
        # Apply updates (partial update semantics)
        if command.last_view_mode is not None:
            preference.last_view_mode = command.last_view_mode
        
        # Explicit None handling for last_active_org_id
        if hasattr(command, 'last_active_org_id'):
            preference.last_active_org_id = command.last_active_org_id
        
        # Save
        await self.preference_repo.save(preference)
        
        logger.info(f"Console context preferences updated for user {command.user_id}")
        return preference

@dataclass
class JoinUseCase:
    """Use cases for joining organizations."""
    
    join_code_repo: JoinCodeRepositoryPort
    organization_repo: OrganizationRepositoryPort
    member_repo: MemberRepositoryPort
    event_publisher: EventPublisherPort
    
    async def join_by_code(self, command: JoinByCodeCommand) -> tuple[Organization, Member]:
        """Join an organization using a join code."""
        # Find the join code
        join_code = await self.join_code_repo.get_by_code(command.code)
        if not join_code:
            raise ValueError("Invalid join code")
        
        # Validate the code
        if not join_code.is_valid():
            if not join_code.is_active:
                raise ValueError("Join code is no longer active")
            if join_code.expires_at:
                raise ValueError("Join code has expired")
            if join_code.max_uses is not None:
                raise ValueError("Join code has reached maximum uses")
            raise ValueError("Invalid join code")
        
        # Get the organization
        org = await self.organization_repo.get_by_id(join_code.organization_id)
        if not org:
            raise ValueError("Organization not found")
        
        # Check if user is already a member
        existing = await self.member_repo.get_by_user_and_org(command.user_id, org.id)
        if existing:
            raise ValueError("You are already a member of this organization")
        
        # Create membership
        # If org requires approval, create as PENDING, otherwise ACTIVE
        status = MemberStatus.PENDING if org.requires_approval else MemberStatus.ACTIVE
        member = Member.create(
            organization_id=org.id,
            user_id=command.user_id,
            email=command.email,
            role=MemberRole.MEMBER,
            status=status,
        )
        
        # Increment join code usage
        join_code.increment_usage()
        
        # Save both
        await self.member_repo.save(member)
        await self.join_code_repo.save(join_code)
        
        # Publish event
        await self.event_publisher.publish(
            MemberAddedEvent(
                organization_id=org.id,
                member_id=member.id,
                user_id=command.user_id,
                role=member.role.value,
            )
        )
        
        logger.info(
            f"User {command.user_id} joined organization {org.id} via code {command.code} "
            f"with status {status.value}"
        )
        return org, member

    async def validate_join_code(self, code: str) -> tuple[bool, Organization | None, str, bool]:
        """Validate a join code and return org context if valid.

        Returns:
            (is_valid, organization, message, expired)
        """
        normalized = (code or "").strip().upper()
        if not normalized:
            return False, None, "Join code is required", False

        join_code = await self.join_code_repo.get_by_code(normalized)
        if not join_code:
            return False, None, "Invitation code not found", False

        if not join_code.is_valid():
            if not join_code.is_active:
                return False, None, "This invitation is no longer active", False
            if join_code.expires_at:
                return False, None, "This invitation has expired", True
            if join_code.max_uses is not None:
                return False, None, "This invitation has reached its maximum uses", False
            return False, None, "Invalid invitation code", False

        org = await self.organization_repo.get_by_id(join_code.organization_id)
        if not org:
            return False, None, "Organization not found", False

        return True, org, f"Valid invitation to join {org.name}", False

    async def join_organization(self, command: JoinOrganizationCommand) -> tuple[Organization, Member]:
        """Join/request to join an organization directly by ID (open join only)."""
        org = await self.organization_repo.get_by_id(command.organization_id)
        if not org:
            raise ValueError("Organization not found")

        if org.join_mechanism != JoinMechanism.OPEN:
            raise ValueError("This organization does not support direct join. Use an invite code or invitation")

        existing = await self.member_repo.get_by_user_and_org(command.user_id, org.id)
        if existing:
            if existing.status == MemberStatus.PENDING:
                raise ValueError("Your join request is already pending approval")
            raise ValueError("You are already a member of this organization")

        status = MemberStatus.PENDING if org.requires_approval else MemberStatus.ACTIVE
        member = Member.create(
            organization_id=org.id,
            user_id=command.user_id,
            email=command.email,
            role=MemberRole.MEMBER,
            status=status,
        )

        await self.member_repo.save(member)

        await self.event_publisher.publish(
            MemberAddedEvent(
                organization_id=org.id,
                member_id=member.id,
                user_id=command.user_id,
                role=member.role.value,
            )
        )

        logger.info(
            f"User {command.user_id} joined/requested organization {org.id} with status {status.value}"
        )
        return org, member