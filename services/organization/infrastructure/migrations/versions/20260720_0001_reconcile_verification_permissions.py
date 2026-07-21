"""Reconcile verification permissions for databases upgraded from early RBAC.

Revision ID: 20260720_0001
Revises: 20260712_0003
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "20260720_0001"
down_revision = "20260712_0003"
branch_labels = None
depends_on = None


PERMISSIONS = (
    ("view", "View verification results"),
    ("execute", "Execute verification flows"),
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
                VALUES (:id, 'verification', :action, :description)
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
                    ('owner', 'execute'),
                    ('admin', 'view'),
                    ('admin', 'execute'),
                    ('operator', 'view'),
                    ('operator', 'execute'),
                    ('viewer', 'view')
              ) AS allowed(role_name, action)
                ON allowed.role_name = role.name
              JOIN organization_service.permissions permission
                ON permission.resource = 'verification'
               AND permission.action = allowed.action
            ON CONFLICT DO NOTHING
            """
        )
    )


def downgrade() -> None:
    # Data reconciliation is intentionally retained. Both permissions belong
    # to the original RBAC contract, so removing them would corrupt databases
    # that received them from the initial migration.
    pass
