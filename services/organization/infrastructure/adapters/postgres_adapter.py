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
    MemberRepositoryPort,
    OrganizationRepositoryPort,
)
from ...domain.entities import (
    ApiKey,
    ApiKeyStatus,
    Member,
    MemberRole,
    MemberStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
)
from ..models import (
    api_keys_table,
    members_table,
    organizations_table,
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
                        slug=organization.slug,
                        description=organization.description,
                        org_type=organization.org_type.value,
                        status=organization.status.value,
                        contact_email=organization.contact_email,
                        contact_phone=organization.contact_phone,
                        website=organization.website,
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
                        slug=organization.slug,
                        description=organization.description,
                        org_type=organization.org_type.value,
                        status=organization.status.value,
                        contact_email=organization.contact_email,
                        contact_phone=organization.contact_phone,
                        website=organization.website,
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
    
    async def delete(self, org_id: str) -> None:
        """Delete an organization."""
        async with self.session_factory() as session:
            await session.execute(
                organizations_table.delete().where(organizations_table.c.id == org_id)
            )
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> Organization:
        """Convert database row to entity."""
        return Organization(
            id=row.id,
            name=row.name,
            display_name=row.display_name,
            slug=row.slug,
            description=row.description,
            org_type=OrganizationType(row.org_type),
            status=OrganizationStatus(row.status),
            contact_email=row.contact_email,
            contact_phone=row.contact_phone,
            website=row.website,
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
                        role=member.role.value,
                        status=member.status.value,
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
                        role=member.role.value,
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
            return self._row_to_entity(row) if row else None
    
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
            return self._row_to_entity(row) if row else None
    
    async def list_by_organization(self, org_id: str) -> list[Member]:
        """List all members of an organization."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(members_table.c.organization_id == org_id)
            )
            return [self._row_to_entity(row) for row in result]
    
    async def list_by_user(self, user_id: str) -> list[Member]:
        """List all memberships for a user."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(members_table).where(members_table.c.user_id == user_id)
            )
            return [self._row_to_entity(row) for row in result]
    
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
            return self._row_to_entity(row) if row else None
    
    async def delete(self, member_id: str) -> None:
        """Delete a member."""
        async with self.session_factory() as session:
            await session.execute(
                members_table.delete().where(members_table.c.id == member_id)
            )
            await session.commit()
    
    def _row_to_entity(self, row: Any) -> Member:
        """Convert database row to entity."""
        return Member(
            id=row.id,
            organization_id=row.organization_id,
            user_id=row.user_id,
            email=row.email,
            role=MemberRole(row.role),
            status=MemberStatus(row.status),
            invited_by=row.invited_by,
            invited_at=row.invited_at,
            joined_at=row.joined_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
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
