"""PolicySet use cases for Cedar policy management."""

from __future__ import annotations

import logging
from typing import Optional

from marty_common import CedarEngine

from ..domain.policy_set import PolicySet, PolicySetStatus, PolicySetType
from ..infrastructure.adapters.policy_set_adapter import PostgresPolicySetRepository

logger = logging.getLogger(__name__)


class PolicySetUseCase:
    """Application layer for PolicySet CRUD and validation."""

    def __init__(
        self,
        repo: PostgresPolicySetRepository,
        cedar_engine: CedarEngine,
    ):
        self.repo = repo
        self.cedar_engine = cedar_engine

    async def create(
        self,
        organization_id: str,
        name: str,
        cedar_policies: str,
        policy_type: str = "CUSTOM",
        description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> PolicySet:
        policy_set = PolicySet.create(
            organization_id=organization_id,
            name=name,
            cedar_policies=cedar_policies,
            policy_type=PolicySetType(policy_type),
            description=description,
            created_by=created_by,
        )
        await self.repo.save(policy_set)
        logger.info(
            f"Created PolicySet {policy_set.id} ({name}) for org {organization_id}"
        )
        return policy_set

    async def get(
        self, policy_set_id: str, organization_id: str
    ) -> Optional[PolicySet]:
        return await self.repo.get_by_id(policy_set_id, organization_id)

    async def list_for_org(
        self, organization_id: str, status: Optional[str] = None
    ) -> list[PolicySet]:
        return await self.repo.list_by_org(organization_id, status=status)

    async def update(
        self,
        policy_set_id: str,
        organization_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        cedar_policies: Optional[str] = None,
    ) -> Optional[PolicySet]:
        policy_set = await self.repo.get_by_id(policy_set_id, organization_id)
        if not policy_set:
            return None

        if name is not None:
            policy_set.name = name
        if description is not None:
            policy_set.description = description
        if cedar_policies is not None:
            policy_set.update_policies(cedar_policies)

        await self.repo.save(policy_set)
        logger.info(f"Updated PolicySet {policy_set_id}")
        return policy_set

    async def archive(
        self, policy_set_id: str, organization_id: str
    ) -> Optional[PolicySet]:
        policy_set = await self.repo.get_by_id(policy_set_id, organization_id)
        if not policy_set:
            return None
        policy_set.archive()
        await self.repo.save(policy_set)
        logger.info(f"Archived PolicySet {policy_set_id}")
        return policy_set

    async def activate(
        self, policy_set_id: str, organization_id: str
    ) -> Optional[PolicySet]:
        policy_set = await self.repo.get_by_id(policy_set_id, organization_id)
        if not policy_set:
            return None
        policy_set.activate()
        await self.repo.save(policy_set)
        logger.info(f"Activated PolicySet {policy_set_id}")
        return policy_set

    async def delete(
        self, policy_set_id: str, organization_id: str
    ) -> bool:
        return await self.repo.delete(policy_set_id, organization_id)

    def validate_policies(self, cedar_policies: str) -> list[str]:
        """Validate Cedar policy text against the MIP schema.

        Returns a list of validation errors (empty if valid).
        """
        try:
            import cedarpy

            result = cedarpy.validate_policies(
                cedar_policies, self.cedar_engine._schema
            )
            if hasattr(result, "errors") and result.errors:
                return [str(e) for e in result.errors]
            return []
        except Exception as e:
            return [str(e)]
