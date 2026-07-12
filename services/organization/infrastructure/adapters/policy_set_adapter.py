"""PostgreSQL repository adapter for Cedar PolicySets."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...domain.policy_set import PolicySet, PolicySetStatus, PolicySetType
from ..models import policy_sets_table

logger = logging.getLogger(__name__)


class PostgresPolicySetRepository:
    """CRUD operations for Cedar PolicySets in PostgreSQL."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def save(self, policy_set: PolicySet) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(policy_sets_table.c.id).where(
                    policy_sets_table.c.id == policy_set.id
                )
            )
            exists = result.scalar_one_or_none() is not None

            if exists:
                await session.execute(
                    policy_sets_table.update()
                    .where(policy_sets_table.c.id == policy_set.id)
                    .values(
                        name=policy_set.name,
                        description=policy_set.description,
                        policy_type=policy_set.policy_type.value,
                        status=policy_set.status.value,
                        cedar_policies=policy_set.cedar_policies,
                        cedar_schema_version=policy_set.cedar_schema_version,
                        updated_at=policy_set.updated_at,
                    )
                )
            else:
                await session.execute(
                    policy_sets_table.insert().values(
                        id=policy_set.id,
                        organization_id=policy_set.organization_id,
                        name=policy_set.name,
                        description=policy_set.description,
                        policy_type=policy_set.policy_type.value,
                        status=policy_set.status.value,
                        cedar_policies=policy_set.cedar_policies,
                        cedar_schema_version=policy_set.cedar_schema_version,
                        created_by=policy_set.created_by,
                        created_at=policy_set.created_at,
                        updated_at=policy_set.updated_at,
                    )
                )
            await session.commit()

    async def get_by_id(
        self, policy_set_id: str, organization_id: str
    ) -> Optional[PolicySet]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(policy_sets_table).where(
                    policy_sets_table.c.id == policy_set_id,
                    policy_sets_table.c.organization_id == organization_id,
                )
            )
            row = result.mappings().first()
            return self._to_entity(row) if row else None

    async def list_by_org(
        self,
        organization_id: str,
        status: Optional[str] = None,
    ) -> list[PolicySet]:
        async with self.session_factory() as session:
            query = select(policy_sets_table).where(
                policy_sets_table.c.organization_id == organization_id
            )
            if status:
                query = query.where(policy_sets_table.c.status == status)
            query = query.order_by(policy_sets_table.c.created_at.desc())

            result = await session.execute(query)
            return [self._to_entity(row) for row in result.mappings()]

    async def get_active_by_org(self, organization_id: str) -> list[PolicySet]:
        return await self.list_by_org(organization_id, status=PolicySetStatus.ACTIVE.value)

    async def delete(self, policy_set_id: str, organization_id: str) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(policy_sets_table).where(
                    policy_sets_table.c.id == policy_set_id,
                    policy_sets_table.c.organization_id == organization_id,
                )
            )
            await session.commit()
            return result.rowcount > 0

    @staticmethod
    def _to_entity(row) -> PolicySet:
        return PolicySet(
            id=str(row["id"]),
            organization_id=str(row["organization_id"]),
            name=row["name"],
            description=row["description"],
            policy_type=PolicySetType(row["policy_type"]),
            status=PolicySetStatus(row["status"]),
            cedar_policies=row["cedar_policies"],
            cedar_schema_version=row["cedar_schema_version"],
            created_by=row.get("created_by"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
