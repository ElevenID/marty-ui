"""
Organization Service Application Ports
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..domain.entities import (
    ApiKey,
    AuditEvent,
    ConsoleContextPreference,
    JoinCode,
    Member,
    Organization,
    OrganizationType,
    Permission,
    Role,
    ViewMode,
)


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
    role_ids: list[str]
    invited_by: str


@dataclass
class SetMemberRolesCommand:
    """Command to replace a member's roles."""
    member_id: str
    organization_id: str
    role_ids: list[str]
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


@dataclass
class UpsertConsoleContextPreferenceCommand:
    """Command to upsert console context preference."""
    user_id: str
    last_view_mode: ViewMode | None = None
    last_active_org_id: str | None = None


@dataclass
class JoinByCodeCommand:
    """Command to join an organization by code."""
    user_id: str
    code: str
    email: str  # User email for membership record


@dataclass
class JoinOrganizationCommand:
    """Command to join/request to join an organization directly by ID."""
    user_id: str
    organization_id: str
    email: str  # User email for membership record


# ── RBAC Commands ────────────────────────────────────────────────────────────

@dataclass
class AuditEventQuery:
    """Query parameters for organization audit events."""

    organization_id: str
    page: int = 1
    per_page: int = 50
    category: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str | None = None
    actor: str | None = None
    severity: str | None = None
    search: str | None = None
    ip_address: str | None = None
    start_date: str | None = None
    end_date: str | None = None


@dataclass
class CreateRoleCommand:
    """Command to create a custom role."""
    organization_id: str
    name: str
    created_by: str
    display_name: str | None = None
    description: str | None = None
    permission_ids: list[str] = field(default_factory=list)
    is_default_for_new_members: bool = False


@dataclass
class UpdateRoleCommand:
    """Command to update an existing role."""
    role_id: str
    organization_id: str
    updated_by: str
    display_name: str | None = None
    description: str | None = None
    permission_ids: list[str] | None = None
    is_default_for_new_members: bool | None = None


@dataclass
class DeleteRoleCommand:
    """Command to delete a custom role."""
    role_id: str
    organization_id: str
    deleted_by: str
    replacement_role_id: str | None = None


@dataclass
class AddMemberRoleCommand:
    """Command to add a single role to a member."""
    member_id: str
    organization_id: str
    role_id: str
    updated_by: str


@dataclass
class RemoveMemberRoleCommand:
    """Command to remove a single role from a member."""
    member_id: str
    organization_id: str
    role_id: str
    updated_by: str


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
    async def list_discoverable(
        self,
        search: str | None = None,
        org_type: OrganizationType | None = None,
        join_mechanism: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Organization]:
        """List discoverable organizations with optional filters."""
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


class ConsoleContextPreferenceRepositoryPort(ABC):
    """Port for console context preference persistence."""
    
    @abstractmethod
    async def get_by_user_id(self, user_id: str) -> ConsoleContextPreference | None:
        """Get preference by user ID."""
        ...
    
    @abstractmethod
    async def save(self, preference: ConsoleContextPreference) -> None:
        """Save a preference (insert or update)."""
        ...


class JoinCodeRepositoryPort(ABC):
    """Port for join code persistence."""
    
    @abstractmethod
    async def save(self, join_code: JoinCode) -> None:
        """Save a join code (insert or update)."""
        ...
    
    @abstractmethod
    async def get_by_code(self, code: str) -> JoinCode | None:
        """Get join code by code string."""
        ...
    
    @abstractmethod
    async def list_by_organization(self, org_id: str) -> list[JoinCode]:
        """List all join codes for an organization."""
        ...
    
    @abstractmethod
    async def delete(self, code_id: str) -> None:
        """Delete a join code."""
        ...


# ── RBAC Repository Ports ────────────────────────────────────────────────────

class RoleRepositoryPort(ABC):
    """Port for role persistence."""

    @abstractmethod
    async def save(self, role: Role) -> None:
        """Save a role (insert or update), including its permissions."""
        ...

    @abstractmethod
    async def get_by_id(self, role_id: str) -> Role | None:
        """Get role by ID with its permissions loaded."""
        ...

    @abstractmethod
    async def get_by_name(self, organization_id: str, name: str) -> Role | None:
        """Get role by name within an organization."""
        ...

    @abstractmethod
    async def list_by_organization(self, org_id: str) -> list[Role]:
        """List all roles for an organization with permissions."""
        ...

    @abstractmethod
    async def delete(self, role_id: str) -> None:
        """Delete a role and its permission associations."""
        ...

    @abstractmethod
    async def get_member_roles(self, member_id: str) -> list[Role]:
        """Get all roles assigned to a member, with permissions loaded."""
        ...

    @abstractmethod
    async def set_member_roles(self, member_id: str, role_ids: list[str]) -> None:
        """Replace a member's role assignments."""
        ...

    @abstractmethod
    async def add_member_role(self, member_id: str, role_id: str) -> None:
        """Add a single role to a member."""
        ...

    @abstractmethod
    async def remove_member_role(self, member_id: str, role_id: str) -> None:
        """Remove a single role from a member."""
        ...

    @abstractmethod
    async def get_member_permissions(self, member_id: str) -> list[Permission]:
        """Get the flattened list of unique permissions for a member."""
        ...

    @abstractmethod
    async def get_members_with_role(self, role_id: str) -> list[str]:
        """Get member IDs that have a specific role."""
        ...


class PermissionRepositoryPort(ABC):
    """Port for permission catalog persistence."""

    @abstractmethod
    async def list_all(self) -> list[Permission]:
        """List all permissions in the catalog."""
        ...

    @abstractmethod
    async def get_by_ids(self, permission_ids: list[str]) -> list[Permission]:
        """Get permissions by their IDs."""
        ...

    @abstractmethod
    async def get_by_resource(self, resource: str) -> list[Permission]:
        """Get all permissions for a specific resource."""
        ...

    @abstractmethod
    async def get_by_key(self, resource: str, action: str) -> Permission | None:
        """Get a permission by its resource + action key."""
        ...


class AuditEventRepositoryPort(ABC):
    """Port for organization audit-event persistence."""

    @abstractmethod
    async def save(self, event: AuditEvent) -> None:
        """Persist an audit event."""
        ...

    @abstractmethod
    async def get(self, organization_id: str, event_id: str) -> AuditEvent | None:
        """Get an audit event by ID inside an organization."""
        ...

    @abstractmethod
    async def list(self, query: AuditEventQuery) -> tuple[list[AuditEvent], int]:
        """List audit events and return events plus total count."""
        ...


class EventPublisherPort(ABC):
    """Port for publishing domain events."""
    
    @abstractmethod
    async def publish(self, event: Any) -> None:
        """Publish a domain event."""
        ...
