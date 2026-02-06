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
