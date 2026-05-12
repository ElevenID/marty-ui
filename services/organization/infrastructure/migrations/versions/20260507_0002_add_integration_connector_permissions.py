"""Add integration connector RBAC permissions.

Revision ID: 20260507_0002
Revises: 20260507_0001
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "20260507_0002"
down_revision = "20260507_0001"
branch_labels = None
depends_on = None


SCHEMA = "organization_service"
RESOURCE = "integration-connector"
PERMISSIONS = [
    ("view", "View external protocol connectors"),
    ("create", "Create external protocol connectors"),
    ("edit", "Edit external protocol connectors"),
    ("delete", "Delete external protocol connectors"),
]
ROLE_ACTIONS = {
    "owner": {"view", "create", "edit", "delete"},
    "admin": {"view", "create", "edit", "delete"},
    "access_admin": {"view", "create", "edit", "delete"},
    "catalog_admin": {"view", "create", "edit", "delete"},
    "viewer": {"view"},
}


def _has_rbac_tables(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('organization_service.permissions') IS NOT NULL")
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_rbac_tables(conn):
        return

    for action, description in PERMISSIONS:
        conn.execute(
            sa.text(
                """
                INSERT INTO organization_service.permissions (id, resource, action, description)
                VALUES (:id, :resource, :action, :description)
                ON CONFLICT (resource, action)
                DO UPDATE SET description = EXCLUDED.description
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "resource": RESOURCE,
                "action": action,
                "description": description,
            },
        )

    for role_name, actions in ROLE_ACTIONS.items():
        for action in actions:
            conn.execute(
                sa.text(
                    """
                    INSERT INTO organization_service.role_permissions (role_id, permission_id)
                    SELECT r.id, p.id
                      FROM organization_service.roles r
                      JOIN organization_service.permissions p
                        ON p.resource = :resource
                       AND p.action = :action
                     WHERE r.name = :role_name
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "resource": RESOURCE,
                    "action": action,
                    "role_name": role_name,
                },
            )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_rbac_tables(conn):
        return

    conn.execute(
        sa.text(
            """
            DELETE FROM organization_service.role_permissions rp
             USING organization_service.permissions p
             WHERE rp.permission_id = p.id
               AND p.resource = :resource
            """
        ),
        {"resource": RESOURCE},
    )
    conn.execute(
        sa.text(
            """
            DELETE FROM organization_service.permissions
             WHERE resource = :resource
            """
        ),
        {"resource": RESOURCE},
    )
