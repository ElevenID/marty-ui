"""
Organization Service Use Cases
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..domain.entities import ApiKey, Member, MemberRole, MemberStatus, Organization
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
    CreateApiKeyCommand,
    CreateOrganizationCommand,
    EventPublisherPort,
    InviteMemberCommand,
    MemberRepositoryPort,
    OrganizationRepositoryPort,
    RevokeApiKeyCommand,
    UpdateMemberRoleCommand,
    UpdateOrganizationCommand,
)

logger = logging.getLogger(__name__)


@dataclass
class OrganizationUseCase:
    """Use cases for organization management."""
    
    organization_repo: OrganizationRepositoryPort
    member_repo: MemberRepositoryPort
    event_publisher: EventPublisherPort
    
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
