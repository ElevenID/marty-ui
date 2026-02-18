"""
RBAC Use Cases

Manages role lifecycle, permission assignment, and member ↔ role mappings.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from ..domain.entities import Permission, Role
from ..domain.events import (
    RoleAssignedEvent,
    RoleCreatedEvent,
    RoleDeletedEvent,
    RoleRemovedFromMemberEvent,
    RoleUpdatedEvent,
)
from .ports import (
    AddMemberRoleCommand,
    CreateRoleCommand,
    DeleteRoleCommand,
    EventPublisherPort,
    MemberRepositoryPort,
    PermissionRepositoryPort,
    RemoveMemberRoleCommand,
    RoleRepositoryPort,
    SetMemberRolesCommand,
    UpdateRoleCommand,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# System role templates  (used when seeding roles for a new org)
# ─────────────────────────────────────────────────────────────────────────────

# Resources that only admins/owners can manage
_ADMIN_ONLY_RESOURCES = {"team", "role", "organization"}

# Resources where viewers only get "view"
_VIEW_ONLY_ACTIONS = {"view"}


@dataclass
class RoleUseCase:
    """Use cases for RBAC role management."""

    role_repo: RoleRepositoryPort
    permission_repo: PermissionRepositoryPort
    member_repo: MemberRepositoryPort
    event_publisher: EventPublisherPort

    # ── Role CRUD ────────────────────────────────────────────────────────

    async def create_role(self, command: CreateRoleCommand) -> Role:
        """Create a custom role."""
        # Validate uniqueness
        existing = await self.role_repo.get_by_name(
            command.organization_id, command.name
        )
        if existing:
            raise ValueError(
                f"Role '{command.name}' already exists in this organization"
            )

        # Resolve permissions
        permissions: list[Permission] = []
        if command.permission_ids:
            permissions = await self.permission_repo.get_by_ids(command.permission_ids)
            if len(permissions) != len(command.permission_ids):
                found_ids = {p.id for p in permissions}
                missing = [pid for pid in command.permission_ids if pid not in found_ids]
                raise ValueError(f"Unknown permission IDs: {missing}")

        now = datetime.now(timezone.utc)
        role = Role(
            id=str(uuid.uuid4()),
            organization_id=command.organization_id,
            name=command.name,
            display_name=command.display_name or command.name,
            description=command.description,
            is_system=False,
            is_default_for_new_members=command.is_default_for_new_members,
            permissions=permissions,
            created_at=now,
            updated_at=now,
        )

        # If this role should be the default, clear any other defaults
        if role.is_default_for_new_members:
            await self._clear_default_flag(command.organization_id)

        await self.role_repo.save(role)

        await self.event_publisher.publish(
            RoleCreatedEvent(
                organization_id=command.organization_id,
                role_id=role.id,
                role_name=role.name,
                created_by=command.created_by,
            )
        )

        logger.info(
            f"Role '{role.name}' created in org {command.organization_id} "
            f"with {len(permissions)} permissions"
        )
        return role

    async def update_role(self, command: UpdateRoleCommand) -> Role:
        """Update an existing role."""
        role = await self.role_repo.get_by_id(command.role_id)
        if not role:
            raise ValueError(f"Role {command.role_id} not found")

        if role.organization_id != command.organization_id:
            raise ValueError("Role does not belong to this organization")

        # System roles: allow changing description + permissions,
        # block name changes
        if role.is_system and command.display_name and command.display_name != role.display_name:
            # Allow display_name changes for system roles
            pass

        if command.display_name is not None:
            role.display_name = command.display_name
        if command.description is not None:
            role.description = command.description

        if command.permission_ids is not None:
            permissions = await self.permission_repo.get_by_ids(command.permission_ids)
            if len(permissions) != len(command.permission_ids):
                found_ids = {p.id for p in permissions}
                missing = [pid for pid in command.permission_ids if pid not in found_ids]
                raise ValueError(f"Unknown permission IDs: {missing}")
            role.set_permissions(permissions)

        if command.is_default_for_new_members is not None:
            if command.is_default_for_new_members:
                await self._clear_default_flag(command.organization_id)
            role.is_default_for_new_members = command.is_default_for_new_members

        role.updated_at = datetime.now(timezone.utc)
        await self.role_repo.save(role)

        await self.event_publisher.publish(
            RoleUpdatedEvent(
                organization_id=command.organization_id,
                role_id=role.id,
                role_name=role.name,
                updated_by=command.updated_by,
            )
        )

        logger.info(f"Role '{role.name}' updated in org {command.organization_id}")
        return role

    async def delete_role(self, command: DeleteRoleCommand) -> None:
        """Delete a custom role."""
        role = await self.role_repo.get_by_id(command.role_id)
        if not role:
            raise ValueError(f"Role {command.role_id} not found")

        if role.organization_id != command.organization_id:
            raise ValueError("Role does not belong to this organization")

        if role.is_system:
            raise ValueError("System roles cannot be deleted")

        # Reassign members that only have this role
        affected_member_ids = await self.role_repo.get_members_with_role(command.role_id)
        if affected_member_ids:
            # Find a replacement role
            replacement_id = command.replacement_role_id
            if not replacement_id:
                # Fall back to the default role for new members
                org_roles = await self.role_repo.list_by_organization(
                    command.organization_id
                )
                default = next(
                    (r for r in org_roles if r.is_default_for_new_members), None
                )
                if default:
                    replacement_id = default.id
                else:
                    # Last resort: find the "member" system role
                    member_role = next(
                        (r for r in org_roles if r.name == "member" and r.is_system),
                        None,
                    )
                    if member_role:
                        replacement_id = member_role.id

            if replacement_id:
                for mid in affected_member_ids:
                    # Check if member has other roles
                    member_role_list = await self.role_repo.get_member_roles(mid)
                    other_roles = [r for r in member_role_list if r.id != command.role_id]
                    if not other_roles:
                        await self.role_repo.add_member_role(mid, replacement_id)

        await self.role_repo.delete(command.role_id)

        await self.event_publisher.publish(
            RoleDeletedEvent(
                organization_id=command.organization_id,
                role_id=command.role_id,
                role_name=role.name,
                deleted_by=command.deleted_by,
            )
        )

        logger.info(
            f"Role '{role.name}' deleted from org {command.organization_id}"
        )

    async def get_role(self, role_id: str) -> Role | None:
        """Get a role by ID."""
        return await self.role_repo.get_by_id(role_id)

    async def list_roles(self, organization_id: str) -> list[Role]:
        """List all roles for an organization."""
        return await self.role_repo.list_by_organization(organization_id)

    async def list_permissions(self) -> list[Permission]:
        """List all available permissions (the catalog)."""
        return await self.permission_repo.list_all()

    # ── Member ↔ Role assignments ────────────────────────────────────────

    async def set_member_roles(self, command: SetMemberRolesCommand) -> list[Role]:
        """Replace all roles for a member."""
        if not command.role_ids:
            raise ValueError("A member must have at least one role")

        # Validate all roles exist and belong to the org
        for rid in command.role_ids:
            role = await self.role_repo.get_by_id(rid)
            if not role:
                raise ValueError(f"Role {rid} not found")
            if role.organization_id != command.organization_id:
                raise ValueError(f"Role {rid} does not belong to this organization")

        member = await self.member_repo.get_by_id(command.member_id)
        if not member:
            raise ValueError(f"Member {command.member_id} not found")

        await self.role_repo.set_member_roles(command.member_id, command.role_ids)

        # Return the updated roles
        updated_roles = await self.role_repo.get_member_roles(command.member_id)

        logger.info(
            f"Set {len(command.role_ids)} roles for member {command.member_id} "
            f"in org {command.organization_id}"
        )
        return updated_roles

    async def add_member_role(self, command: AddMemberRoleCommand) -> None:
        """Add a single role to a member."""
        role = await self.role_repo.get_by_id(command.role_id)
        if not role:
            raise ValueError(f"Role {command.role_id} not found")
        if role.organization_id != command.organization_id:
            raise ValueError("Role does not belong to this organization")

        await self.role_repo.add_member_role(command.member_id, command.role_id)

        await self.event_publisher.publish(
            RoleAssignedEvent(
                organization_id=command.organization_id,
                member_id=command.member_id,
                role_id=command.role_id,
                role_name=role.name,
                assigned_by=command.updated_by,
            )
        )

    async def remove_member_role(self, command: RemoveMemberRoleCommand) -> None:
        """Remove a single role from a member."""
        # Ensure member keeps at least one role
        current_roles = await self.role_repo.get_member_roles(command.member_id)
        if len(current_roles) <= 1:
            raise ValueError("Cannot remove the last role from a member")

        role = await self.role_repo.get_by_id(command.role_id)

        await self.role_repo.remove_member_role(command.member_id, command.role_id)

        if role:
            await self.event_publisher.publish(
                RoleRemovedFromMemberEvent(
                    organization_id=command.organization_id,
                    member_id=command.member_id,
                    role_id=command.role_id,
                    role_name=role.name,
                    removed_by=command.updated_by,
                )
            )

    async def get_member_permissions(self, member_id: str) -> list[Permission]:
        """Get the flattened permission set for a member."""
        return await self.role_repo.get_member_permissions(member_id)

    async def get_member_roles(self, member_id: str) -> list[Role]:
        """Get all roles assigned to a member."""
        return await self.role_repo.get_member_roles(member_id)

    # ── Org lifecycle helpers ────────────────────────────────────────────

    async def seed_default_roles(self, organization_id: str) -> dict[str, Role]:
        """
        Create the four system roles for a newly created organization.
        
        Returns a mapping of role name → Role entity.
        """
        all_perms = await self.permission_repo.list_all()
        perm_by_key: dict[str, Permission] = {p.key: p for p in all_perms}

        now = datetime.now(timezone.utc)
        created_roles: dict[str, Role] = {}

        for tmpl in _SYSTEM_ROLE_TEMPLATES:
            perms = [
                perm_by_key[key]
                for key in tmpl["permission_keys"]
                if key in perm_by_key
            ]
            role = Role(
                id=str(uuid.uuid4()),
                organization_id=organization_id,
                name=tmpl["name"],
                display_name=tmpl["display_name"],
                description=tmpl["description"],
                is_system=True,
                is_default_for_new_members=tmpl["name"] == "member",
                permissions=perms,
                created_at=now,
                updated_at=now,
            )
            await self.role_repo.save(role)
            created_roles[tmpl["name"]] = role

        logger.info(
            f"Seeded {len(created_roles)} system roles for org {organization_id}"
        )
        return created_roles

    # ── internals ────────────────────────────────────────────────────────

    async def _clear_default_flag(self, organization_id: str) -> None:
        """Clear is_default_for_new_members on all existing roles in the org."""
        roles = await self.role_repo.list_by_organization(organization_id)
        for r in roles:
            if r.is_default_for_new_members:
                r.is_default_for_new_members = False
                r.updated_at = datetime.now(timezone.utc)
                await self.role_repo.save(r)


# ─────────────────────────────────────────────────────────────────────────────
# System role template definitions
# ─────────────────────────────────────────────────────────────────────────────
# Permission keys are built lazily — if a key doesn't exist in the catalog it
# is silently skipped (forward-compat for new resources added later).

def _build_system_templates() -> list[dict]:
    """Build the system role templates from the permission catalog spec.
    
    Not used at runtime — templates are hard-coded below.
    """
    pass


# Hard-coded for reliability — mirrors the migration seed data.
_ALL_RESOURCES = [
    "trust-profile", "trusted-issuer", "credential-template",
    "compliance-profile", "presentation-policy", "revocation-profile",
    "deployment-profile", "flow-definition", "flow-instance",
    "issuance", "application-template", "application",
    "organization", "team", "role", "api-key", "signing-key",
    "webhook", "notification", "audit", "verification",
]

_ALL_ACTIONS = [
    "view", "create", "edit", "delete", "activate", "suspend",
    "deprecate", "version", "evaluate", "start", "advance",
    "cancel", "initiate", "approve", "reject", "invite", "manage",
    "assign", "revoke", "test", "send", "export", "execute",
]

# We build the "all permissions" set from the migration seed data pattern.
# Any key that doesn't exist in the DB will be ignored at runtime.
_ALL_PERMISSION_KEYS: list[str] = []
_MEMBER_PERMISSION_KEYS: list[str] = []
_VIEWER_PERMISSION_KEYS: list[str] = []

# Import the canonical list to stay in sync
from .._migration_permissions import PERMISSION_CATALOG as _CATALOG

for resource, action, _desc in _CATALOG:
    key = f"{resource}:{action}"
    _ALL_PERMISSION_KEYS.append(key)

    if resource not in _ADMIN_ONLY_RESOURCES or action == "view":
        _MEMBER_PERMISSION_KEYS.append(key)

    if action == "view":
        _VIEWER_PERMISSION_KEYS.append(key)


_SYSTEM_ROLE_TEMPLATES = [
    {
        "name": "owner",
        "display_name": "Owner",
        "description": "Full access. Can transfer ownership.",
        "permission_keys": _ALL_PERMISSION_KEYS,
    },
    {
        "name": "admin",
        "display_name": "Administrator",
        "description": "Full access to all resources and settings.",
        "permission_keys": _ALL_PERMISSION_KEYS,
    },
    {
        "name": "member",
        "display_name": "Member",
        "description": "Can create and manage resources. No team or org management.",
        "permission_keys": _MEMBER_PERMISSION_KEYS,
    },
    {
        "name": "viewer",
        "display_name": "Viewer",
        "description": "Read-only access to all resources.",
        "permission_keys": _VIEWER_PERMISSION_KEYS,
    },
]
