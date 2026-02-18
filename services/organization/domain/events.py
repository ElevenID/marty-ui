"""
Organization Service Domain Events
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from marty_common.events import DomainEvent


@dataclass
class OrganizationCreatedEvent(DomainEvent):
    """Emitted when an organization is created."""
    
    source_service: str = "organization"
    organization_id: str = ""
    name: str = ""
    owner_user_id: str = ""


@dataclass
class OrganizationUpdatedEvent(DomainEvent):
    """Emitted when an organization is updated."""
    
    source_service: str = "organization"
    organization_id: str = ""
    updated_fields: list[str] = field(default_factory=list)


@dataclass
class MemberAddedEvent(DomainEvent):
    """Emitted when a member is added to an organization."""
    
    source_service: str = "organization"
    organization_id: str = ""
    member_id: str = ""
    user_id: str = ""
    role: str = ""


@dataclass
class MemberRemovedEvent(DomainEvent):
    """Emitted when a member is removed from an organization."""
    
    source_service: str = "organization"
    organization_id: str = ""
    member_id: str = ""
    user_id: str = ""


@dataclass
class MemberInvitedEvent(DomainEvent):
    """Emitted when a member is invited to an organization."""
    
    source_service: str = "organization"
    organization_id: str = ""
    member_id: str = ""
    email: str = ""
    invited_by: str = ""


@dataclass
class ApiKeyCreatedEvent(DomainEvent):
    """Emitted when an API key is created."""
    
    source_service: str = "organization"
    organization_id: str = ""
    api_key_id: str = ""
    name: str = ""
    created_by: str = ""


@dataclass
class ApiKeyRevokedEvent(DomainEvent):
    """Emitted when an API key is revoked."""
    
    source_service: str = "organization"
    organization_id: str = ""
    api_key_id: str = ""
    revoked_by: str = ""


# ── RBAC Events ──────────────────────────────────────────────────────────────

@dataclass
class RoleCreatedEvent(DomainEvent):
    """Emitted when a role is created."""

    source_service: str = "organization"
    organization_id: str = ""
    role_id: str = ""
    role_name: str = ""
    created_by: str = ""


@dataclass
class RoleUpdatedEvent(DomainEvent):
    """Emitted when a role is updated (permissions changed, etc.)."""

    source_service: str = "organization"
    organization_id: str = ""
    role_id: str = ""
    role_name: str = ""
    updated_by: str = ""


@dataclass
class RoleDeletedEvent(DomainEvent):
    """Emitted when a role is deleted."""

    source_service: str = "organization"
    organization_id: str = ""
    role_id: str = ""
    role_name: str = ""
    deleted_by: str = ""


@dataclass
class RoleAssignedEvent(DomainEvent):
    """Emitted when a role is assigned to a member."""

    source_service: str = "organization"
    organization_id: str = ""
    member_id: str = ""
    role_id: str = ""
    role_name: str = ""
    assigned_by: str = ""


@dataclass
class RoleRemovedFromMemberEvent(DomainEvent):
    """Emitted when a role is removed from a member."""

    source_service: str = "organization"
    organization_id: str = ""
    member_id: str = ""
    role_id: str = ""
    role_name: str = ""
    removed_by: str = ""
