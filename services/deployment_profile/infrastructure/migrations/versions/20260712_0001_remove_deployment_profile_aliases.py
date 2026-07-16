"""Remove deployment-profile compatibility aliases.

Revision ID: 20260712_0001
Revises: 20260505_0001
Create Date: 2026-07-12 21:30:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260712_0001"
down_revision = "20260505_0001"
branch_labels = None
depends_on = None


SCHEMA = "deployment_profile_service"
TABLE = "deployment_profiles"


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE deployment_profile_service.deployment_profiles
               SET trust_profile_id = COALESCE(trust_profile_id, default_trust_profile_id),
                   default_policy_id = COALESCE(default_policy_id, default_presentation_policy_id),
                   environment_config = (
                       COALESCE(ux_config, '{}'::json)::jsonb
                       || COALESCE(environment_config, '{}'::json)::jsonb
                   )::json
            """
        )
    )
    op.drop_column(TABLE, "default_trust_profile_id", schema=SCHEMA)
    op.drop_column(TABLE, "default_compliance_profile_id", schema=SCHEMA)
    op.drop_column(TABLE, "default_presentation_policy_id", schema=SCHEMA)
    op.drop_column(TABLE, "ux_config", schema=SCHEMA)


def downgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("default_trust_profile_id", sa.String(length=36), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        TABLE,
        sa.Column("default_compliance_profile_id", sa.String(length=36), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        TABLE,
        sa.Column("default_presentation_policy_id", sa.String(length=36), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        TABLE,
        sa.Column(
            "ux_config",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            """
            UPDATE deployment_profile_service.deployment_profiles
               SET default_trust_profile_id = trust_profile_id,
                   default_presentation_policy_id = default_policy_id,
                   ux_config = environment_config
            """
        )
    )
    op.alter_column(TABLE, "ux_config", server_default=None, schema=SCHEMA)
