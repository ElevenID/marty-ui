"""Add first-class issuer accreditation identifiers.

Revision ID: issuer_accreditations_001
Revises: trust_kms_cleanup_001
Create Date: 2026-08-07 00:01:00.000000+00:00

The certifying authority (accreditation_body) and certifications held by an
issuer (accreditations) are distinct public trust facts. Existing issuers get
an explicit empty accreditation set and therefore fail closed when a policy
requires an accreditation.
"""

from alembic import op
import sqlalchemy as sa


revision = "issuer_accreditations_001"
down_revision = "trust_kms_cleanup_001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuer_entities",
        sa.Column(
            "accreditations",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
        schema="trust_profile_service",
    )


def downgrade() -> None:
    op.drop_column(
        "issuer_entities",
        "accreditations",
        schema="trust_profile_service",
    )
