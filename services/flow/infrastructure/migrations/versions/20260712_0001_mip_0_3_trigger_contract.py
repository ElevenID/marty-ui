"""Enforce the structured MIP 0.3 flow trigger contract.

Revision ID: 20260712_0001
Revises: 20260711_0001
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op


revision = "20260712_0001"
down_revision = "20260711_0001"
branch_labels = None
depends_on = None


TRIGGER_MIGRATIONS = {
    "application_approved": {
        "trigger_type": "WEBHOOK",
        "config": {"event_type": "APPLICATION_APPROVED"},
    },
    "credential_login": {
        "trigger_type": "API_CALL",
        "config": {"event_type": "CREDENTIAL_LOGIN"},
    },
}
ALLOWED_TRIGGER_TYPES = {"API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"}


def _validate_trigger(flow_id: str, trigger: object) -> None:
    if trigger is None:
        return
    if not isinstance(trigger, dict):
        raise RuntimeError(f"Flow {flow_id} has an unsupported trigger value: {trigger!r}")
    if set(trigger) - {"trigger_type", "config"}:
        raise RuntimeError(f"Flow {flow_id} has unsupported trigger fields")
    if trigger.get("trigger_type") not in ALLOWED_TRIGGER_TYPES:
        raise RuntimeError(f"Flow {flow_id} has an unsupported trigger_type")
    if not isinstance(trigger.get("config", {}), dict):
        raise RuntimeError(f"Flow {flow_id} has a non-object trigger config")


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id, trigger FROM flow_service.flow_definitions WHERE trigger IS NOT NULL")
    ).mappings()

    for row in rows:
        trigger = row["trigger"]
        if isinstance(trigger, str) and trigger in TRIGGER_MIGRATIONS:
            trigger = TRIGGER_MIGRATIONS[trigger]
            connection.execute(
                sa.text(
                    """
                    UPDATE flow_service.flow_definitions
                    SET trigger = CAST(:trigger AS json)
                    WHERE id = :id
                    """
                ),
                {"id": row["id"], "trigger": json.dumps(trigger)},
            )
        _validate_trigger(row["id"], trigger)


def downgrade() -> None:
    connection = op.get_bind()
    for legacy_value, trigger in TRIGGER_MIGRATIONS.items():
        connection.execute(
            sa.text(
                """
                UPDATE flow_service.flow_definitions
                SET trigger = CAST(:legacy_value AS json)
                WHERE trigger = CAST(:trigger AS json)
                """
            ),
            {
                "legacy_value": json.dumps(legacy_value),
                "trigger": json.dumps(trigger),
            },
        )
