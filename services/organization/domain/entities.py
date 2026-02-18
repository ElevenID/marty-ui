"""
Organization Service Domain Entities

Core domain entities for organization management.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# RBAC: Permission & Role entities
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Permission:
    """
    A single permission definition.
    
    Permissions follow the pattern ``resource:action`` and are defined
    once globally in the ``permissions`` table.  They are assigned to
    roles via the ``role_permissions`` join table.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    resource: str = ""
    action: str = ""
    description: str | None = None

    @property
    def key(self) -> str:
        """Return the canonical ``resource:action`` string."""
        return f"{self.resource}:{self.action}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "resource": self.resource,
            "action": self.action,
            "description": self.description,
        }


@dataclass
class Role:
    """
    An organisation-scoped role that bundles a set of permissions.
    
    Each organisation gets its own copy of the system roles
    (owner, admin, member, viewer) and may create any number of
    custom roles on top.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    display_name: str | None = None
    description: str | None = None
    is_system: bool = False
    is_default_for_new_members: bool = False
    permissions: list[Permission] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── helpers ──────────────────────────────────────────────────────────

    def has_permission(self, resource: str, action: str) -> bool:
        """Check whether this role grants a specific permission."""
        return any(p.resource == resource and p.action == action for p in self.permissions)

    @property
    def permission_keys(self) -> set[str]:
        """Return the set of ``resource:action`` strings."""
        return {p.key for p in self.permissions}

    def add_permission(self, permission: Permission) -> None:
        if permission.key not in self.permission_keys:
            self.permissions.append(permission)
            self.updated_at = datetime.now(timezone.utc)

    def remove_permission(self, resource: str, action: str) -> None:
        self.permissions = [
            p for p in self.permissions
            if not (p.resource == resource and p.action == action)
        ]
        self.updated_at = datetime.now(timezone.utc)

    def set_permissions(self, permissions: list[Permission]) -> None:
        """Replace the permission set entirely."""
        self.permissions = list(permissions)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "is_system": self.is_system,
            "is_default_for_new_members": self.is_default_for_new_members,
            "permissions": [p.to_dict() for p in self.permissions],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class OrganizationStatus(str, Enum):
    """Organization status values."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"


class OrganizationType(str, Enum):
    """Organization type values."""
    ENTERPRISE = "enterprise"
    STARTUP = "startup"
    INDIVIDUAL = "individual"
    GOVERNMENT = "government"
    EDUCATION = "education"


class MemberRole(str, Enum):
    """Organization member role values."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class MemberStatus(str, Enum):
    """Member status values."""
    ACTIVE = "active"
    PENDING = "pending"
    INVITED = "invited"
    DEACTIVATED = "deactivated"


class ApiKeyStatus(str, Enum):
    """API key status values."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ViewMode(str, Enum):
    """Console view mode values."""
    APPLICANT = "applicant"
    ORG_ADMIN = "org_admin"


class JoinMechanism(str, Enum):
    """How users can discover and join an organization."""
    OPEN = "open"  # Discoverable, anyone can join
    CODE = "code"  # Join via invite code
    INVITE = "invite"  # Email invitation only
    DOMAIN = "domain"  # Domain-based suggestions (future)


@dataclass
class ConsoleContextPreference:
    """
    User preferences for console context (view mode + active org).
    
    MVP placement: preferences live here for pragmatism;
    conceptually belongs in auth/identity service.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""  # From auth service
    last_view_mode: ViewMode = ViewMode.APPLICANT
    last_active_org_id: str | None = None  # Nullable - valid for applicant mode
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "last_view_mode": self.last_view_mode.value,
            "last_active_org_id": self.last_active_org_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class JoinCode:
    """
    Join code for organizations.
    
    Allows users to join organizations via short, memorable codes.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    code: str = ""  # 8-character alphanumeric code
    created_by: str = ""  # User ID who created the code
    expires_at: datetime | None = None  # Optional expiration
    max_uses: int | None = None  # Optional use limit
    use_count: int = 0  # Current usage count
    is_active: bool = True  # Can be deactivated without deletion
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @staticmethod
    def generate_code() -> str:
        """Generate a random 8-character alphanumeric code."""
        # Use uppercase letters and digits, excluding ambiguous characters (0, O, I, 1)
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return ''.join(secrets.choice(alphabet) for _ in range(8))
    
    def is_valid(self) -> bool:
        """Check if the code is currently valid for use."""
        if not self.is_active:
            return False
        
        # Check expiration
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        
        # Check usage limit
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        
        return True
    
    def increment_usage(self) -> None:
        """Increment the usage counter."""
        self.use_count += 1
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for API responses."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "code": self.code,
            "created_by": self.created_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_uses": self.max_uses,
            "use_count": self.use_count,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Organization:
    """
    Organization aggregate root.
    
    Represents an organization that can have members,
    credentials, and API keys.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    display_name: str | None = None
    slug: str = ""
    description: str | None = None
    org_type: OrganizationType = OrganizationType.STARTUP
    status: OrganizationStatus = OrganizationStatus.PENDING
    
    # Join settings
    join_mechanism: JoinMechanism = JoinMechanism.INVITE  # Default to invite-only
    requires_approval: bool = False  # Whether joining requires admin approval
    is_discoverable: bool = False  # Whether shown in org browser
    
    # Contact info
    contact_email: str | None = None
    contact_phone: str | None = None
    website: str | None = None
    
    # Settings
    settings: dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def create(
        cls,
        name: str,
        owner_id: str,
        org_type: OrganizationType = OrganizationType.STARTUP,
        display_name: str | None = None,
        description: str | None = None,
    ) -> tuple[Organization, Member]:
        """
        Factory method to create an organization with owner.
        
        Returns organization and owner membership.
        """
        org = cls(
            name=name,
            display_name=display_name or name,  # Default to name if not provided
            slug=cls._generate_slug(name),
            description=description,
            org_type=org_type,
            status=OrganizationStatus.ACTIVE,
        )
        
        # Create owner membership
        owner = Member(
            organization_id=org.id,
            user_id=owner_id,
            role=MemberRole.OWNER,
            status=MemberStatus.ACTIVE,
        )
        
        return org, owner
    
    @staticmethod
    def _generate_slug(name: str) -> str:
        """Generate URL-safe slug from name."""
        import re
        slug = name.lower()
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        slug = slug.strip('-')
        # Add random suffix for uniqueness
        suffix = secrets.token_hex(4)
        return f"{slug}-{suffix}"
    
    def activate(self) -> None:
        """Activate the organization."""
        self.status = OrganizationStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        """Suspend the organization."""
        self.status = OrganizationStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)
    
    def update_settings(self, settings: dict[str, Any]) -> None:
        """Update organization settings."""
        self.settings.update(settings)
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "org_type": self.org_type.value,
            "status": self.status.value,
            "join_mechanism": self.join_mechanism.value,
            "requires_approval": self.requires_approval,
            "is_discoverable": self.is_discoverable,
            "contact_email": self.contact_email,
            "contact_phone": self.contact_phone,
            "website": self.website,
            "settings": self.settings,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Member:
    """
    Organization member entity.
    
    Represents a user's membership in an organization.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    user_id: str = ""
    email: str | None = None  # For invitations
    role: MemberRole = MemberRole.MEMBER  # Legacy – kept for backward compat
    status: MemberStatus = MemberStatus.ACTIVE
    
    # RBAC roles (populated from member_roles join table)
    roles: list[Role] = field(default_factory=list)
    
    # Invitation tracking
    invited_by: str | None = None
    invited_at: datetime | None = None
    joined_at: datetime | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── RBAC helpers ─────────────────────────────────────────────────────

    @property
    def effective_permissions(self) -> set[str]:
        """Union of ``resource:action`` keys across all assigned roles."""
        perms: set[str] = set()
        for r in self.roles:
            perms |= r.permission_keys
        return perms

    def has_permission(self, resource: str, action: str) -> bool:
        """Check whether the member has a specific permission via any role."""
        key = f"{resource}:{action}"
        return key in self.effective_permissions

    def has_any_role(self, *role_names: str) -> bool:
        """Check if the member holds any of the given role names."""
        member_role_names = {r.name for r in self.roles}
        return bool(member_role_names & set(role_names))

    @classmethod
    def create(
        cls,
        organization_id: str,
        user_id: str,
        email: str | None = None,
        role: MemberRole = MemberRole.MEMBER,
        status: MemberStatus = MemberStatus.ACTIVE,
    ) -> Member:
        """Create a direct membership (non-invitation flow)."""
        now = datetime.now(timezone.utc)
        return cls(
            organization_id=organization_id,
            user_id=user_id,
            email=email,
            role=role,
            status=status,
            joined_at=now,
            created_at=now,
            updated_at=now,
        )
    
    @classmethod
    def create_invitation(
        cls,
        organization_id: str,
        email: str,
        role: MemberRole,
        invited_by: str,
    ) -> Member:
        """Create a member invitation."""
        return cls(
            organization_id=organization_id,
            user_id="",  # Set when user accepts
            email=email,
            role=role,
            status=MemberStatus.INVITED,
            invited_by=invited_by,
            invited_at=datetime.now(timezone.utc),
        )
    
    def accept_invitation(self, user_id: str) -> None:
        """Accept the invitation."""
        if self.status != MemberStatus.INVITED:
            raise ValueError("Can only accept pending invitations")
        
        self.user_id = user_id
        self.status = MemberStatus.ACTIVE
        self.joined_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def change_role(self, new_role: MemberRole) -> None:
        """Change member's role."""
        self.role = new_role
        self.updated_at = datetime.now(timezone.utc)
    
    def deactivate(self) -> None:
        """Deactivate the membership."""
        self.status = MemberStatus.DEACTIVATED
        self.updated_at = datetime.now(timezone.utc)
    
    @property
    def is_admin(self) -> bool:
        """Check if member has admin privileges."""
        return self.role in (MemberRole.OWNER, MemberRole.ADMIN)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role.value,
            "roles": [{"id": r.id, "name": r.name, "display_name": r.display_name} for r in self.roles],
            "status": self.status.value,
            "invited_by": self.invited_by,
            "invited_at": self.invited_at.isoformat() if self.invited_at else None,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class ApiKey:
    """
    API key entity.
    
    Represents an API key for programmatic access.
    The key_hash stores the hashed value, the actual key
    is only returned once at creation.
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    
    # Key is prefix + hash for display, actual key only on creation
    key_prefix: str = ""  # e.g., "mk_live_" or "mk_test_"
    key_hash: str = ""  # Hashed key for verification
    
    # Permissions
    scopes: list[str] = field(default_factory=list)  # e.g., ["read:credentials", "write:issuance"]
    
    # Status and limits
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE
    rate_limit: int | None = None  # Requests per minute
    
    # Tracking
    created_by: str = ""
    last_used_at: datetime | None = None
    last_used_ip: str | None = None
    
    # Expiration
    expires_at: datetime | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def create(
        cls,
        organization_id: str,
        name: str,
        created_by: str,
        scopes: list[str] | None = None,
        description: str | None = None,
        is_test: bool = False,
        expires_at: datetime | None = None,
    ) -> tuple[ApiKey, str]:
        """
        Factory method to create an API key.
        
        Returns the ApiKey entity and the raw key value.
        The raw key is only available at creation time.
        """
        import hashlib
        
        # Generate key
        prefix = "mk_test_" if is_test else "mk_live_"
        raw_key = f"{prefix}{secrets.token_urlsafe(32)}"
        
        # Hash for storage
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        api_key = cls(
            organization_id=organization_id,
            name=name,
            description=description,
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=scopes or ["read:credentials", "write:issuance"],
            status=ApiKeyStatus.ACTIVE,
            created_by=created_by,
            expires_at=expires_at,
        )
        
        return api_key, raw_key
    
    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Hash a raw key for comparison."""
        import hashlib
        return hashlib.sha256(raw_key.encode()).hexdigest()
    
    def verify(self, raw_key: str) -> bool:
        """Verify a raw key matches this API key."""
        return self.key_hash == self.hash_key(raw_key)
    
    def record_usage(self, ip_address: str | None = None) -> None:
        """Record API key usage."""
        self.last_used_at = datetime.now(timezone.utc)
        self.last_used_ip = ip_address
    
    def revoke(self) -> None:
        """Revoke the API key."""
        self.status = ApiKeyStatus.REVOKED
    
    @property
    def is_valid(self) -> bool:
        """Check if API key is valid for use."""
        if self.status != ApiKeyStatus.ACTIVE:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True
    
    def has_scope(self, scope: str) -> bool:
        """Check if API key has a specific scope."""
        return scope in self.scopes or "*" in self.scopes
    
    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "organization_id": self.organization_id,
            "name": self.name,
            "description": self.description,
            "key_prefix": self.key_prefix,
            "scopes": self.scopes,
            "status": self.status.value,
            "rate_limit": self.rate_limit,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }
        
        if include_sensitive:
            data["key_hash"] = self.key_hash
            data["created_by"] = self.created_by
            data["last_used_ip"] = self.last_used_ip
        
        return data
