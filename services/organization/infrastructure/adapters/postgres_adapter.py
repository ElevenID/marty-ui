"""
PostgreSQL Repository Adapters

Implements repository ports using PostgreSQL with SQLAlchemy.
Uses the organization_service schema.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...application.ports import (
    ApiKeyRepositoryPort,
    ConsoleContextPreferenceRepositoryPort,
    JoinCodeRepositoryPort,
    MemberRepositoryPort,
    OrganizationRepositoryPort,
)
from ...domain.entities import (
    ApiKey,
    ApiKeyStatus,
    ConsoleContextPreference,
    JoinCode,
    JoinMechanism,
    Member,
    MemberStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    Permission,
    Role,
    ViewMode,
)
from ..models import (
    api_keys_table,
    console_context_preferences_table,
    join_codes_table,
    member_roles_table,
    members_table,
    organizations_table,
    permissions_table,
    role_permissions_table,
    roles_table,
)

logger = logging.getLogger(__name__)


class PostgresOrganizationRepository(OrganizationRepositoryPort):
    """PostgreSQL organization repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def save(self, organization: Organization) -> None:
        """Save an organization."""
        async with self.session_factory() as session:
            # Check if exists
            result = await session.execute(
                select(organizations_table.c.id).where(
                    organizations_table.c.id == organization.id
                )
            )
            exists = result.scalar_one_or_none() is not None
            
            if exists:
                # Update
                await session.execute(
                    organizations_table.update()
                    .where(organizations_table.c.id == organization.id)
                    .values(
                        name=organization.name,
                        display_name=organization.display_name,
                        owner_id=organization.owner_id,
                        slug=organization.slug,
                        description=organization.description,
                        org_type=organization.org_type.value,
                        status=organization.status.value,
                        join_mechanism=organization.join_mechanism.value,
                        requires_approval=organization.requires_approval,
                        is_discoverable=organization.is_discoverable,
                        contact_email=organization.contact_email,
                        contact_phone=organization.contact_phone,
                        website=organization.website,
                        plan=organization.plan,
                        plan_expires_at=organization.plan_expires_at,
                        settings=organization.settings,
                        updated_at=organization.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    organizations_table.insert().values(
                        id=organization.id,
                        name=organization.name,
                        display_name=organization.display_name,
                        owner_id=organization.owner_id,
                        slug=organization.slug,
                        description=organization.description,
                        org_type=organization.org_type.value,
                        status=organization.status.value,
                        join_mechanism=organization.join_mechanism.value,
                        requires_approval=organization.requires_approval,
                        is_discoverable=organization.is_discoverable,
                        contact_email=organization.contact_email,
                        contact_phone=organization.contact_phone,
                        website=organization.website,
                        plan=organization.plan,
                        plan_expires_at=organization.plan_expires_at,
                        settings=organization.settings,
                        created_at=organization.created_at,
                        updated_at=organization.updated_at,
                    )
                )
            
            await session.commit()
    
    async def get_by_id(self, org_id: str) -> Organization | None:
        """Get organization by ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(organizations_table).where(organizations_table.c.id == org_id)
            )
            row = result.first()
            
            if not row:
                return None
            
            return self._row_to_entity(row)
    
    async def get_by_slug(self, slug: str) -> Organization | None:
        """Get organization by slug."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(organizations_table).where(organizations_table.c.slug == slug)
            )
            row = result.first()
            
            if not row:
                return None
            
            return self._row_to_entity(row)
    
    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Organization]:
        """List all organizations."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(organizations_table)
                .order_by(organizations_table.c.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            
            return [self._row_to_entity(row) for row in result]
    
    async def list_discoverable(
        self,
        search: str | None = None,
        org_type: OrganizationType | None = None,
        join_mechanism: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Organization]:
        """List discoverable organizations with optional filters."""
        async with self.session_factory() as session:
            # Build query with base filters
            query = select(organizations_table).where(
                organizations_table.c.is_discoverable == True,
                organizations_table.c.status == OrganizationStatus.ACTIVE.value,
            )
            
            # Apply optional filters
            if search:
                search_pattern = f"%{search}%"
                from sqlalchemy import or_
                query = query.where(
                    or_(
                        organizations_table.c.name.ilike(search_pattern),
                        organizations_table.c.display_name.ilike(search_pattern),
                    )
                )
            
            if org_type:
                query = query.where(organizations_table.c.org_type == org_type.value)
            
            if join_mechanism:
                query = query.where(organizations_table.c.join_mechanism == join_mechanism)
            
            # Order by created_at descending (newest first)
            query = query.order_by(organizations_table.c.created_at.desc()).limit(limit).offset(offset)
            
            result = await session.execute(query)
            return [self._row_to_entity(row) for row in result]
    
    async def delete(self, org_id: str) -> None:
        """Delete an organization."""
        async with self.session_factory() as session:
            await session.execute(
                organizations_table.delete().where(organizations_table.c.id == org_id)
            )
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> Organization:
        """Convert database row to entity."""
        org_type_value = row.org_type if getattr(row, "org_type", None) else OrganizationType.STARTUP.value
        try:
            org_type = OrganizationType(org_type_value)
        except ValueError:
            org_type = OrganizationType.STARTUP

        status_value = row.status if getattr(row, "status", None) else OrganizationStatus.PENDING.value
        try:
            status = OrganizationStatus(status_value)
        except ValueError:
            status = OrganizationStatus.PENDING

        return Organization(
            id=row.id,
            name=row.name,
            display_name=row.display_name,
            slug=row.slug,
            description=row.description,
            org_type=org_type,
            status=status,
            owner_id=getattr(row, "owner_id", "") or "",
            join_mechanism=JoinMechanism(row.join_mechanism) if row.join_mechanism else JoinMechanism.INVITE,
            requires_approval=bool(row.requires_approval) if hasattr(row, 'requires_approval') else False,
            is_discoverable=bool(row.is_discoverable) if hasattr(row, 'is_discoverable') else False,
            contact_email=row.contact_email,
            contact_phone=row.contact_phone,
            website=row.website,
            plan=getattr(row, 'plan', None) or 'free',
            plan_expires_at=getattr(row, 'plan_expires_at', None),
            settings=row.settings or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class PostgresMemberRepository(MemberRepositoryPort):
    """PostgreSQL member repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def save(self, member: Member) -> None:
        """Save a member."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table.c.id).where(members_table.c.id == member.id)
            )
            exists = result.scalar_one_or_none() is not None
            
            if exists:
                await session.execute(
                    members_table.update()
                    .where(members_table.c.id == member.id)
                    .values(
                        user_id=member.user_id,
                        email=member.email,
                        status=member.status.value,
                        invited_by=member.invited_by,
                        invited_at=member.invited_at,
                        joined_at=member.joined_at,
                        updated_at=member.updated_at,
                    )
                )
            else:
                await session.execute(
                    members_table.insert().values(
                        id=member.id,
                        organization_id=member.organization_id,
                        user_id=member.user_id,
                        email=member.email,
                        status=member.status.value,
                        invited_by=member.invited_by,
                        invited_at=member.invited_at,
                        joined_at=member.joined_at,
                        created_at=member.created_at,
                        updated_at=member.updated_at,
                    )
                )
            
            await session.commit()
    
    async def get_by_id(self, member_id: str) -> Member | None:
        """Get member by ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(members_table.c.id == member_id)
            )
            row = result.first()
            return await self._row_to_entity(session, row) if row else None
    
    async def get_by_user_and_org(self, user_id: str, org_id: str) -> Member | None:
        """Get member by user ID and organization ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(
                    (members_table.c.user_id == user_id) &
                    (members_table.c.organization_id == org_id)
                )
            )
            row = result.first()
            return await self._row_to_entity(session, row) if row else None
    
    async def list_by_organization(self, org_id: str) -> list[Member]:
        """List all members of an organization."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(members_table.c.organization_id == org_id)
            )
            return [await self._row_to_entity(session, row) for row in result]
    
    async def list_by_user(self, user_id: str) -> list[Member]:
        """List all memberships for a user."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(members_table.c.user_id == user_id)
            )
            return [await self._row_to_entity(session, row) for row in result]
    
    async def get_by_email_and_org(self, email: str, org_id: str) -> Member | None:
        """Get member by email and organization ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(
                    (members_table.c.email == email) &
                    (members_table.c.organization_id == org_id)
                )
            )
            row = result.first()
            return await self._row_to_entity(session, row) if row else None
    
    async def delete(self, member_id: str) -> None:
        """Delete a member."""
        async with self.session_factory() as session:
            await session.execute(
                members_table.delete().where(members_table.c.id == member_id)
            )
            await session.commit()
    
    async def _load_role_permissions(self, session: AsyncSession, role_id: str) -> list[Permission]:
        result = await session.execute(
            select(permissions_table)
            .join(
                role_permissions_table,
                role_permissions_table.c.permission_id == permissions_table.c.id,
            )
            .where(role_permissions_table.c.role_id == role_id)
        )
        return [self._permission_row_to_entity(row) for row in result]

    async def _load_member_roles(self, session: AsyncSession, member_id: str) -> list[Role]:
        result = await session.execute(
            select(roles_table)
            .join(
                member_roles_table,
                member_roles_table.c.role_id == roles_table.c.id,
            )
            .where(member_roles_table.c.member_id == member_id)
            .order_by(roles_table.c.is_system.desc(), roles_table.c.name)
        )
        roles: list[Role] = []
        for row in result:
            permissions = await self._load_role_permissions(session, str(row.id))
            roles.append(self._role_row_to_entity(row, permissions))
        return roles

    async def _row_to_entity(self, session: AsyncSession, row: Any) -> Member:
        """Convert database row to entity."""
        roles = await self._load_member_roles(session, str(row.id))
        return Member(
            id=row.id,
            organization_id=row.organization_id,
            user_id=row.user_id,
            email=row.email,
            status=MemberStatus(row.status),
            roles=roles,
            invited_by=row.invited_by,
            invited_at=row.invited_at,
            joined_at=row.joined_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _role_row_to_entity(row: Any, permissions: list[Permission]) -> Role:
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
    def _permission_row_to_entity(row: Any) -> Permission:
        return Permission(
            id=str(row.id),
            resource=row.resource,
            action=row.action,
            description=row.description,
        )


class PostgresApiKeyRepository(ApiKeyRepositoryPort):
    """PostgreSQL API key repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def save(self, api_key: ApiKey) -> None:
        """Save an API key."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(api_keys_table.c.id).where(api_keys_table.c.id == api_key.id)
            )
            exists = result.scalar_one_or_none() is not None
            
            if exists:
                await session.execute(
                    api_keys_table.update()
                    .where(api_keys_table.c.id == api_key.id)
                    .values(
                        name=api_key.name,
                        description=api_key.description,
                        scopes=api_key.scopes,
                        status=api_key.status.value,
                        rate_limit=api_key.rate_limit,
                        last_used_at=api_key.last_used_at,
                        last_used_ip=api_key.last_used_ip,
                    )
                )
            else:
                await session.execute(
                    api_keys_table.insert().values(
                        id=api_key.id,
                        organization_id=api_key.organization_id,
                        name=api_key.name,
                        description=api_key.description,
                        key_prefix=api_key.key_prefix,
                        key_hash=api_key.key_hash,
                        scopes=api_key.scopes,
                        status=api_key.status.value,
                        rate_limit=api_key.rate_limit,
                        created_by=api_key.created_by,
                        last_used_at=api_key.last_used_at,
                        last_used_ip=api_key.last_used_ip,
                        expires_at=api_key.expires_at,
                        created_at=api_key.created_at,
                    )
                )
            
            await session.commit()
    
    async def get_by_id(self, key_id: str) -> ApiKey | None:
        """Get API key by ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(api_keys_table).where(api_keys_table.c.id == key_id)
            )
            row = result.first()
            return self._row_to_entity(row) if row else None
    
    async def get_by_hash(self, key_hash: str) -> ApiKey | None:
        """Get API key by hash."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(api_keys_table).where(api_keys_table.c.key_hash == key_hash)
            )
            row = result.first()
            return self._row_to_entity(row) if row else None
    
    async def list_by_organization(self, org_id: str) -> list[ApiKey]:
        """List all API keys for an organization."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(api_keys_table).where(api_keys_table.c.organization_id == org_id)
            )
            return [self._row_to_entity(row) for row in result]
    
    async def delete(self, key_id: str) -> None:
        """Delete an API key."""
        async with self.session_factory() as session:
            await session.execute(
                api_keys_table.delete().where(api_keys_table.c.id == key_id)
            )
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> ApiKey:
        """Convert database row to entity."""
        return ApiKey(
            id=row.id,
            organization_id=row.organization_id,
            name=row.name,
            description=row.description,
            key_prefix=row.key_prefix,
            key_hash=row.key_hash,
            scopes=row.scopes or [],
            status=ApiKeyStatus(row.status),
            rate_limit=row.rate_limit,
            created_by=row.created_by,
            last_used_at=row.last_used_at,
            last_used_ip=row.last_used_ip,
            expires_at=row.expires_at,
            created_at=row.created_at,
        )


class PostgresConsoleContextPreferenceRepository(ConsoleContextPreferenceRepositoryPort):
    """PostgreSQL console context preference repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def get_by_user_id(self, user_id: str) -> ConsoleContextPreference | None:
        """Get preference by user ID."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(console_context_preferences_table).where(
                    console_context_preferences_table.c.user_id == user_id
                )
            )
            row = result.one_or_none()
            if row:
                return self._row_to_entity(row)
            return None
    
    async def save(self, preference: ConsoleContextPreference) -> None:
        """Save a preference (upsert)."""
        async with self.session_factory() as session:
            # Check if exists
            result = await session.execute(
                select(console_context_preferences_table.c.id).where(
                    console_context_preferences_table.c.user_id == preference.user_id
                )
            )
            exists = result.scalar_one_or_none() is not None
            
            if exists:
                # Update
                await session.execute(
                    console_context_preferences_table.update()
                    .where(console_context_preferences_table.c.user_id == preference.user_id)
                    .values(
                        last_view_mode=preference.last_view_mode.value,
                        last_active_org_id=preference.last_active_org_id,
                        updated_at=preference.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    console_context_preferences_table.insert().values(
                        id=preference.id,
                        user_id=preference.user_id,
                        last_view_mode=preference.last_view_mode.value,
                        last_active_org_id=preference.last_active_org_id,
                        created_at=preference.created_at,
                        updated_at=preference.updated_at,
                    )
                )
            
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> ConsoleContextPreference:
        """Convert database row to entity."""
        return ConsoleContextPreference(
            id=str(row.id),
            user_id=row.user_id,
            last_view_mode=ViewMode(row.last_view_mode),
            last_active_org_id=str(row.last_active_org_id) if row.last_active_org_id else None,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class PostgresJoinCodeRepository(JoinCodeRepositoryPort):
    """PostgreSQL join code repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
    
    async def save(self, join_code: JoinCode) -> None:
        """Save a join code (upsert)."""
        async with self.session_factory() as session:
            # Check if exists
            result = await session.execute(
                select(join_codes_table.c.id).where(
                    join_codes_table.c.id == join_code.id
                )
            )
            exists = result.scalar_one_or_none() is not None
            
            if exists:
                # Update
                await session.execute(
                    join_codes_table.update()
                    .where(join_codes_table.c.id == join_code.id)
                    .values(
                        organization_id=join_code.organization_id,
                        code=join_code.code,
                        created_by=join_code.created_by,
                        expires_at=join_code.expires_at,
                        max_uses=join_code.max_uses,
                        use_count=join_code.use_count,
                        is_active=join_code.is_active,
                        updated_at=join_code.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    join_codes_table.insert().values(
                        id=join_code.id,
                        organization_id=join_code.organization_id,
                        code=join_code.code,
                        created_by=join_code.created_by,
                        expires_at=join_code.expires_at,
                        max_uses=join_code.max_uses,
                        use_count=join_code.use_count,
                        is_active=join_code.is_active,
                        created_at=join_code.created_at,
                        updated_at=join_code.updated_at,
                    )
                )
            
            await session.commit()
    
    async def get_by_code(self, code: str) -> JoinCode | None:
        """Get join code by code string."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(join_codes_table).where(
                    join_codes_table.c.code == code
                )
            )
            row = result.fetchone()
            if row:
                return self._row_to_entity(row)
            return None
    
    async def list_by_organization(self, org_id: str) -> list[JoinCode]:
        """List all join codes for an organization."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(join_codes_table).where(
                    join_codes_table.c.organization_id == org_id
                ).order_by(join_codes_table.c.created_at.desc())
            )
            rows = result.fetchall()
            return [self._row_to_entity(row) for row in rows]
    
    async def delete(self, code_id: str) -> None:
        """Delete a join code."""
        async with self.session_factory() as session:
            await session.execute(
                join_codes_table.delete().where(
                    join_codes_table.c.id == code_id
                )
            )
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> JoinCode:
        """Convert database row to entity."""
        return JoinCode(
            id=str(row.id),
            organization_id=str(row.organization_id),
            code=row.code,
            created_by=row.created_by,
            expires_at=row.expires_at,
            max_uses=row.max_uses,
            use_count=row.use_count,
            is_active=bool(row.is_active),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

