"""Add the MIP 0.3 application review permission.

Revision ID: 20260711_0002
Revises: 20260711_0001
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "20260711_0002"
down_revision = "20260711_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if not connection.execute(
        sa.text("SELECT to_regclass('organization_service.permissions') IS NOT NULL")
    ).scalar():
        return
    connection.execute(
        sa.text(
            """
            INSERT INTO organization_service.permissions (id, resource, action, description)
            VALUES (:id, 'application', 'review', :description)
            ON CONFLICT (resource, action)
            DO UPDATE SET description = EXCLUDED.description
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "description": "Review applications, checks, and reviewer locks",
        },
    )
    connection.execute(
        sa.text(
            """
            INSERT INTO organization_service.role_permissions (role_id, permission_id)
            SELECT role.id, permission.id
              FROM organization_service.roles role
              JOIN organization_service.permissions permission
                ON permission.resource = 'application'
               AND permission.action = 'review'
             WHERE role.name IN ('owner', 'admin', 'reviewer')
            ON CONFLICT DO NOTHING
            """
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            DELETE FROM organization_service.role_permissions role_permission
             USING organization_service.permissions permission
             WHERE role_permission.permission_id = permission.id
               AND permission.resource = 'application'
               AND permission.action = 'review'
            """
        )
    )
    connection.execute(
        sa.text(
            """
            DELETE FROM organization_service.permissions
             WHERE resource = 'application' AND action = 'review'
            """
        )
    )
