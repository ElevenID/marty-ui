"""
PostgreSQL Repository Adapters for RBAC

Implements RoleRepositoryPort and PermissionRepositoryPort
using PostgreSQL with SQLAlchemy.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...application.ports import PermissionRepositoryPort, RoleRepositoryPort
from ...domain.entities import Permission, Role
from ..models import (
    member_roles_table,
    permissions_table,
    role_permissions_table,
    roles_table,
)

logger = logging.getLogger(__name__)


class PostgresRoleRepository(RoleRepositoryPort):
    """PostgreSQL role repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    # ── Role CRUD ────────────────────────────────────────────────────────

    async def save(self, role: Role) -> None:
        """Save a role (insert or update), including its permission links."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(roles_table.c.id).where(roles_table.c.id == role.id)
            )
            exists = result.scalar_one_or_none() is not None

            if exists:
                await session.execute(
                    roles_table.update()
                    .where(roles_table.c.id == role.id)
                    .values(
                        name=role.name,
                        display_name=role.display_name,
                        description=role.description,
                        is_system=role.is_system,
                        is_default_for_new_members=role.is_default_for_new_members,
                        updated_at=role.updated_at,
                    )
                )
                # Replace permission links
                await session.execute(
                    delete(role_permissions_table).where(
                        role_permissions_table.c.role_id == role.id
                    )
                )
            else:
                await session.execute(
                    roles_table.insert().values(
                        id=role.id,
                        organization_id=role.organization_id,
                        name=role.name,
                        display_name=role.display_name,
                        description=role.description,
                        is_system=role.is_system,
                        is_default_for_new_members=role.is_default_for_new_members,
                        created_at=role.created_at,
                        updated_at=role.updated_at,
                    )
                )

            # Insert permission links
            if role.permissions:
                await session.execute(
                    role_permissions_table.insert(),
                    [
                        {"role_id": role.id, "permission_id": p.id}
                        for p in role.permissions
                    ],
                )

            await session.commit()

    async def get_by_id(self, role_id: str) -> Role | None:
        """Get role by ID with permissions loaded."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(roles_table).where(roles_table.c.id == role_id)
            )
            row = result.first()
            if not row:
                return None

            permissions = await self._load_role_permissions(session, role_id)
            return self._row_to_entity(row, permissions)

    async def get_by_name(self, organization_id: str, name: str) -> Role | None:
        """Get role by name within an organization."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(roles_table).where(
                    (roles_table.c.organization_id == organization_id)
                    & (roles_table.c.name == name)
                )
            )
            row = result.first()
            if not row:
                return None

            permissions = await self._load_role_permissions(session, str(row.id))
            return self._row_to_entity(row, permissions)

    async def list_by_organization(self, org_id: str) -> list[Role]:
        """List all roles for an organization with permissions."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(roles_table)
                .where(roles_table.c.organization_id == org_id)
                .order_by(roles_table.c.is_system.desc(), roles_table.c.name)
            )
            roles = []
            for row in result:
                permissions = await self._load_role_permissions(session, str(row.id))
                roles.append(self._row_to_entity(row, permissions))
            return roles

    async def delete(self, role_id: str) -> None:
        """Delete a role – cascading deletes remove permission + member links."""
        async with self.session_factory() as session:
            await session.execute(
                roles_table.delete().where(roles_table.c.id == role_id)
            )
            await session.commit()

    # ── Member ↔ Role assignments ────────────────────────────────────────

    async def get_member_roles(self, member_id: str) -> list[Role]:
        """Get all roles assigned to a member, with permissions loaded."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(roles_table)
                .join(
                    member_roles_table,
                    member_roles_table.c.role_id == roles_table.c.id,
                )
                .where(member_roles_table.c.member_id == member_id)
            )
            roles = []
            for row in result:
                permissions = await self._load_role_permissions(session, str(row.id))
                roles.append(self._row_to_entity(row, permissions))
            return roles

    async def set_member_roles(self, member_id: str, role_ids: list[str]) -> None:
        """Replace a member's role assignments."""
        async with self.session_factory() as session:
            await session.execute(
                delete(member_roles_table).where(
                    member_roles_table.c.member_id == member_id
                )
            )
            if role_ids:
                await session.execute(
                    member_roles_table.insert(),
                    [{"member_id": member_id, "role_id": rid} for rid in role_ids],
                )
            await session.commit()

    async def add_member_role(self, member_id: str, role_id: str) -> None:
        """Add a single role to a member (idempotent)."""
        async with self.session_factory() as session:
            existing = await session.execute(
                select(member_roles_table).where(
                    (member_roles_table.c.member_id == member_id)
                    & (member_roles_table.c.role_id == role_id)
                )
            )
            if existing.first() is None:
                await session.execute(
                    member_roles_table.insert().values(
                        member_id=member_id, role_id=role_id
                    )
                )
            await session.commit()

    async def remove_member_role(self, member_id: str, role_id: str) -> None:
        """Remove a single role from a member."""
        async with self.session_factory() as session:
            await session.execute(
                delete(member_roles_table).where(
                    (member_roles_table.c.member_id == member_id)
                    & (member_roles_table.c.role_id == role_id)
                )
            )
            await session.commit()

    async def get_member_permissions(self, member_id: str) -> list[Permission]:
        """Get the flattened, deduplicated list of permissions for a member."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(permissions_table)
                .join(
                    role_permissions_table,
                    role_permissions_table.c.permission_id == permissions_table.c.id,
                )
                .join(
                    member_roles_table,
                    member_roles_table.c.role_id == role_permissions_table.c.role_id,
                )
                .where(member_roles_table.c.member_id == member_id)
                .distinct()
            )
            return [self._perm_row_to_entity(row) for row in result]

    async def get_members_with_role(self, role_id: str) -> list[str]:
        """Get member IDs that have a specific role."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(member_roles_table.c.member_id).where(
                    member_roles_table.c.role_id == role_id
                )
            )
            return [str(row[0]) for row in result]

    # ── internals ────────────────────────────────────────────────────────

    async def _load_role_permissions(
        self, session: AsyncSession, role_id: str
    ) -> list[Permission]:
        result = await session.execute(
            select(permissions_table)
            .join(
                role_permissions_table,
                role_permissions_table.c.permission_id == permissions_table.c.id,
            )
            .where(role_permissions_table.c.role_id == role_id)
        )
        return [self._perm_row_to_entity(row) for row in result]

    @staticmethod
    def _row_to_entity(row: Any, permissions: list[Permission]) -> Role:
        return Role(
            id=str(row.id),
            organization_id=str(row.organization_id),
            name=row.name,
            display_name=row.display_name,
            description=row.description,
            is_system=bool(row.is_system),
            is_default_for_new_members=bool(row.is_default_for_new_members),
            permissions=permissions,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _perm_row_to_entity(row: Any) -> Permission:
        return Permission(
            id=str(row.id),
            resource=row.resource,
            action=row.action,
            description=row.description,
        )


class PostgresPermissionRepository(PermissionRepositoryPort):
    """PostgreSQL permission catalog repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def list_all(self) -> list[Permission]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(permissions_table).order_by(
                    permissions_table.c.resource, permissions_table.c.action
                )
            )
            return [self._row_to_entity(row) for row in result]

    async def get_by_ids(self, permission_ids: list[str]) -> list[Permission]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(permissions_table).where(
                    permissions_table.c.id.in_(permission_ids)
                )
            )
            return [self._row_to_entity(row) for row in result]

    async def get_by_resource(self, resource: str) -> list[Permission]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(permissions_table).where(
                    permissions_table.c.resource == resource
                )
            )
            return [self._row_to_entity(row) for row in result]

    async def get_by_key(self, resource: str, action: str) -> Permission | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(permissions_table).where(
                    (permissions_table.c.resource == resource)
                    & (permissions_table.c.action == action)
                )
            )
            row = result.first()
            return self._row_to_entity(row) if row else None

    @staticmethod
    def _row_to_entity(row: Any) -> Permission:
        return Permission(
            id=str(row.id),
            resource=row.resource,
            action=row.action,
            description=row.description,
        )
