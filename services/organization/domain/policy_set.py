"""PolicySet domain entity for Cedar policy management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class PolicySetStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class PolicySetType(str, Enum):
    ACCESS_CONTROL = "ACCESS_CONTROL"
    CREDENTIAL_VERIFICATION = "CREDENTIAL_VERIFICATION"
    APPROVAL_RULES = "APPROVAL_RULES"
    # Backward-compatible aliases used by early organization-service policy sets.
    RBAC = "RBAC"
    ABAC = "ABAC"
    CUSTOM = "CUSTOM"


@dataclass
class PolicySet:
    """A named collection of Cedar policies scoped to an organization.

    Maps to the MIP protocol PolicySet entity (§16). Each organization
    can have multiple policy sets, but only one active set of each type
    at a time.
    """

    id: str
    organization_id: str
    name: str
    description: Optional[str]
    policy_type: PolicySetType
    status: PolicySetStatus
    cedar_policies: str
    cedar_schema_version: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def create(
        organization_id: str,
        name: str,
        cedar_policies: str,
        policy_type: PolicySetType = PolicySetType.CUSTOM,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
        cedar_schema_version: str = "1.0",
    ) -> PolicySet:
        now = datetime.now(timezone.utc)
        return PolicySet(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            name=name,
            description=description,
            policy_type=policy_type,
            status=PolicySetStatus.ACTIVE,
            cedar_policies=cedar_policies,
            cedar_schema_version=cedar_schema_version,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )

    def archive(self):
        self.status = PolicySetStatus.ARCHIVED
        self.updated_at = datetime.now(timezone.utc)

    def activate(self):
        self.status = PolicySetStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)

    def update_policies(self, cedar_policies: str):
        self.cedar_policies = cedar_policies
        self.updated_at = datetime.now(timezone.utc)
