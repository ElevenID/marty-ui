"""Grant applicants read-only access to the wallet compatibility catalog.

Revision ID: 20260811_0001
Revises: 20260806_0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260811_0001"
down_revision = "20260806_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            INSERT INTO organization_service.role_permissions
                (role_id, permission_id)
            SELECT role.id, permission.id
              FROM organization_service.roles role
              JOIN organization_service.permissions permission
                ON permission.resource = 'wallet'
               AND permission.action = 'view'
             WHERE role.name = 'applicant'
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
             USING organization_service.roles role,
                   organization_service.permissions permission
             WHERE role_permission.role_id = role.id
               AND role_permission.permission_id = permission.id
               AND role.name = 'applicant'
               AND permission.resource = 'wallet'
               AND permission.action = 'view'
            """
        )
    )
