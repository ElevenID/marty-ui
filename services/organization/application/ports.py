"""
Organization Service Application Ports
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..domain.entities import ApiKey, Member, MemberRole, Organization, OrganizationType


# =============================================================================
# Commands & Queries
# =============================================================================

@dataclass
class CreateOrganizationCommand:
    """Command to create an organization."""
    name: str
    owner_id: str
    org_type: OrganizationType = OrganizationType.STARTUP
    display_name: str | None = None
    description: str | None = None
    contact_email: str | None = None


@dataclass
class UpdateOrganizationCommand:
    """Command to update an organization."""
    organization_id: str
    name: str | None = None
    description: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    website: str | None = None
    settings: dict[str, Any] | None = None


@dataclass
class InviteMemberCommand:
    """Command to invite a member."""
    organization_id: str
    email: str
    role: MemberRole
    invited_by: str


@dataclass
class UpdateMemberRoleCommand:
    """Command to update member's role."""
    member_id: str
    new_role: MemberRole
    updated_by: str


@dataclass
class CreateApiKeyCommand:
    """Command to create an API key."""
    organization_id: str
    name: str
    created_by: str
    scopes: list[str] | None = None
    description: str | None = None
    is_test: bool = False


@dataclass
class RevokeApiKeyCommand:
    """Command to revoke an API key."""
    api_key_id: str
    revoked_by: str


# =============================================================================
# Outbound Ports
# =============================================================================

class OrganizationRepositoryPort(ABC):
    """Port for organization persistence."""
    
    @abstractmethod
    async def save(self, organization: Organization) -> None:
        """Save an organization."""
        ...
    
    @abstractmethod
    async def get_by_id(self, org_id: str) -> Organization | None:
        """Get organization by ID."""
        ...
    
    @abstractmethod
    async def get_by_slug(self, slug: str) -> Organization | None:
        """Get organization by slug."""
        ...
    
    @abstractmethod
    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Organization]:
        """List all organizations."""
        ...
    
    @abstractmethod
    async def delete(self, org_id: str) -> None:
        """Delete an organization."""
        ...


class MemberRepositoryPort(ABC):
    """Port for member persistence."""
    
    @abstractmethod
    async def save(self, member: Member) -> None:
        """Save a member."""
        ...
    
    @abstractmethod
    async def get_by_id(self, member_id: str) -> Member | None:
        """Get member by ID."""
        ...
    
    @abstractmethod
    async def get_by_user_and_org(self, user_id: str, org_id: str) -> Member | None:
        """Get member by user ID and organization ID."""
        ...
    
    @abstractmethod
    async def list_by_organization(self, org_id: str) -> list[Member]:
        """List all members of an organization."""
        ...
    
    @abstractmethod
    async def list_by_user(self, user_id: str) -> list[Member]:
        """List all memberships for a user."""
        ...
    
    @abstractmethod
    async def get_by_email_and_org(self, email: str, org_id: str) -> Member | None:
        """Get member invitation by email."""
        ...
    
    @abstractmethod
    async def delete(self, member_id: str) -> None:
        """Delete a member."""
        ...


class ApiKeyRepositoryPort(ABC):
    """Port for API key persistence."""
    
    @abstractmethod
    async def save(self, api_key: ApiKey) -> None:
        """Save an API key."""
        ...
    
    @abstractmethod
    async def get_by_id(self, key_id: str) -> ApiKey | None:
        """Get API key by ID."""
        ...
    
    @abstractmethod
    async def get_by_hash(self, key_hash: str) -> ApiKey | None:
        """Get API key by hash (for validation)."""
        ...
    
    @abstractmethod
    async def list_by_organization(self, org_id: str) -> list[ApiKey]:
        """List all API keys for an organization."""
        ...
    
    @abstractmethod
    async def delete(self, key_id: str) -> None:
        """Delete an API key."""
        ...


class EventPublisherPort(ABC):
    """Port for publishing domain events."""
    
    @abstractmethod
    async def publish(self, event: Any) -> None:
        """Publish a domain event."""
        ...
