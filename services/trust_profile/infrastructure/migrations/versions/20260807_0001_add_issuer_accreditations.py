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


_SCHEMA = "trust_profile_service"
_TABLE = "issuer_entities"
_COLUMN = "accreditations"


def _has_table(conn: sa.engine.Connection) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass(:qualified_name) IS NOT NULL"),
            {"qualified_name": f"{_SCHEMA}.{_TABLE}"},
        ).scalar()
    )


def _has_column(conn: sa.engine.Connection) -> bool:
    return bool(
        conn.execute(
            sa.text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = :schema
                      AND table_name = :table
                      AND column_name = :column
                )
                """
            ),
            {"schema": _SCHEMA, "table": _TABLE, "column": _COLUMN},
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    # Fresh artifact-only installations run Alembic before service startup.
    # issuer_entities is a runtime-model table there, so create_all will create
    # it with the current non-null column after this revision is recorded. An
    # existing deployment already has the table and needs the additive ALTER.
    if not _has_table(conn) or _has_column(conn):
        return

    op.add_column(
        _TABLE,
        sa.Column(
            _COLUMN,
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn) or not _has_column(conn):
        return

    op.drop_column(
        _TABLE,
        _COLUMN,
        schema=_SCHEMA,
    )
