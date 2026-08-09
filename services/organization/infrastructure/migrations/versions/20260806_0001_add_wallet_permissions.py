"""Add wallet-registry RBAC permissions and backfill system roles.

Revision ID: 20260806_0001
Revises: 20260730_0001
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "20260806_0001"
down_revision = "20260730_0001"
branch_labels = None
depends_on = None


PERMISSIONS = (
    ("view", "View wallet registry and compatibility entries"),
    ("write", "Create and manage organization wallet registry overrides"),
)


def upgrade() -> None:
    connection = op.get_bind()
    if not connection.execute(
        sa.text(
            "SELECT to_regclass('organization_service.permissions') IS NOT NULL"
        )
    ).scalar():
        return

    for action, description in PERMISSIONS:
        connection.execute(
            sa.text(
                """
                INSERT INTO organization_service.permissions
                    (id, resource, action, description)
                VALUES (:id, 'wallet', :action, :description)
                ON CONFLICT (resource, action)
                DO UPDATE SET description = EXCLUDED.description
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "action": action,
                "description": description,
            },
        )

    connection.execute(
        sa.text(
            """
            INSERT INTO organization_service.role_permissions
                (role_id, permission_id)
            SELECT role.id, permission.id
              FROM organization_service.roles role
              JOIN (VALUES
                    ('owner', 'view'),
                    ('owner', 'write'),
                    ('admin', 'view'),
                    ('admin', 'write'),
                    ('catalog_admin', 'view'),
                    ('catalog_admin', 'write'),
                    ('reviewer', 'view'),
                    ('operator', 'view'),
                    ('viewer', 'view')
              ) AS allowed(role_name, action)
                ON allowed.role_name = role.name
              JOIN organization_service.permissions permission
                ON permission.resource = 'wallet'
               AND permission.action = allowed.action
            ON CONFLICT DO NOTHING
            """
        )
    )


def downgrade() -> None:
    # Wallet scopes are part of the published API-key contract. Retaining the
    # catalog rows avoids corrupting existing custom roles on code rollback.
    pass
