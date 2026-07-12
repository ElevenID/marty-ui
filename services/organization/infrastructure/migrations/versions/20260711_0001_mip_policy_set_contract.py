"""Normalize Policy Sets to the MIP wire contract.

Revision ID: 20260711_0001
Revises: 20260710_0001
"""

import json
import re

import sqlalchemy as sa
from alembic import op


revision = "20260711_0001"
down_revision = "20260710_0001"
branch_labels = None
depends_on = None


def _policies(value: str) -> list[dict]:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list) and parsed:
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    effect = re.search(r"\b(permit|forbid)\s*\(", value or "")
    return [{
        "policy_id": "legacy_policy",
        "effect": effect.group(1) if effect else "permit",
        "cedar_text": value or "permit(principal, action, resource);",
        "description": "Migrated from the legacy Policy Set text field.",
        "enabled": True,
    }]


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, policy_type, status, cedar_policies FROM organization_service.policy_sets"
    )).mappings().all()
    for row in rows:
        policy_type = str(row["policy_type"] or "CUSTOM").upper()
        if policy_type in {"RBAC", "ABAC"}:
            policy_type = "ACCESS_CONTROL"
        if policy_type not in {"ACCESS_CONTROL", "CREDENTIAL_VERIFICATION", "APPROVAL_RULES", "CUSTOM"}:
            policy_type = "CUSTOM"
        status = str(row["status"] or "DRAFT").upper()
        if status not in {"DRAFT", "ACTIVE", "ARCHIVED"}:
            status = "DRAFT"
        connection.execute(
            sa.text(
                """
                UPDATE organization_service.policy_sets
                SET policy_type = :policy_type,
                    status = :status,
                    cedar_policies = :cedar_policies,
                    cedar_schema_version = 'MIP/1.0'
                WHERE id = :id
                """
            ),
            {
                "id": row["id"],
                "policy_type": policy_type,
                "status": status,
                "cedar_policies": json.dumps(_policies(row["cedar_policies"])),
            },
        )


def downgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, status, cedar_policies FROM organization_service.policy_sets"
    )).mappings().all()
    for row in rows:
        policies = _policies(row["cedar_policies"])
        connection.execute(
            sa.text(
                """
                UPDATE organization_service.policy_sets
                SET status = :status,
                    cedar_policies = :cedar_policies,
                    cedar_schema_version = '1.0'
                WHERE id = :id
                """
            ),
            {
                "id": row["id"],
                "status": str(row["status"]).lower(),
                "cedar_policies": "\n\n".join(policy["cedar_text"] for policy in policies),
            },
        )
