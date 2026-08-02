"""Drop cached issuer-profile and KMS routing from credential templates.

Revision ID: 20260802_0001
Revises: 20260801_0002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260802_0001"
down_revision = "20260801_0002"
branch_labels = None
depends_on = None


_SCHEMA = "credential_template_service"
_TABLE = "credential_templates"


def upgrade() -> None:
    # issuer_did + issuer_algorithm are the complete template-side selector.
    # The gateway resolves the current profile, service, and KMS key for every
    # validation/signing operation so rotation cannot leave stale routing here.
    op.drop_column(_TABLE, "auto_generate_artifacts", schema=_SCHEMA)
    op.drop_column(_TABLE, "issuer_certificate_chain_pem", schema=_SCHEMA)
    op.drop_column(_TABLE, "remote_signing_config", schema=_SCHEMA)
    op.drop_column(_TABLE, "issuer_key_id", schema=_SCHEMA)
    op.drop_column(_TABLE, "key_access_mode", schema=_SCHEMA)
    op.drop_column(_TABLE, "issuer_profile_id", schema=_SCHEMA)


def downgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column("issuer_certificate_chain_pem", sa.Text(), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _TABLE,
        sa.Column(
            "auto_generate_artifacts",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        schema=_SCHEMA,
    )
    op.add_column(
        _TABLE,
        sa.Column("issuer_profile_id", sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _TABLE,
        sa.Column("key_access_mode", sa.String(length=20), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _TABLE,
        sa.Column("issuer_key_id", sa.String(length=255), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _TABLE,
        sa.Column("remote_signing_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        schema=_SCHEMA,
    )
