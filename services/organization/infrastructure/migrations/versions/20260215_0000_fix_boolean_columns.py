"""Fix boolean columns to use proper BOOLEAN type

Revision ID: 20260215_0000
Revises: 20260213_0003
Create Date: 2026-02-15 00:00:00.000000+00:00
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260215_0000'
down_revision = '20260213_0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Convert requires_approval from STRING to BOOLEAN
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN requires_approval DROP DEFAULT
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN requires_approval TYPE BOOLEAN 
            USING CASE WHEN requires_approval IN ('true', 't', '1', 'yes') THEN true ELSE false END
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN requires_approval SET DEFAULT false
            """
        )
    )
    
    # Convert is_discoverable from STRING to BOOLEAN
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN is_discoverable DROP DEFAULT
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN is_discoverable TYPE BOOLEAN 
            USING CASE WHEN is_discoverable IN ('true', 't', '1', 'yes') THEN true ELSE false END
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN is_discoverable SET DEFAULT false
            """
        )
    )
    
    # Convert is_active in join_codes from STRING to BOOLEAN
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.join_codes 
            ALTER COLUMN is_active DROP DEFAULT
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.join_codes 
            ALTER COLUMN is_active TYPE BOOLEAN 
            USING CASE WHEN is_active IN ('true', 't', '1', 'yes') THEN true ELSE false END
            """
        )
    )
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.join_codes 
            ALTER COLUMN is_active SET DEFAULT true
            """
        )
    )


def downgrade() -> None:
    # Revert requires_approval to STRING
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN requires_approval TYPE VARCHAR(10) 
            USING CASE WHEN requires_approval THEN 'true' ELSE 'false' END
            """
        )
    )
    
    # Revert is_discoverable to STRING
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.organizations 
            ALTER COLUMN is_discoverable TYPE VARCHAR(10) 
            USING CASE WHEN is_discoverable THEN 'true' ELSE 'false' END
            """
        )
    )
    
    # Revert is_active in join_codes to STRING
    op.execute(
        sa.text(
            """
            ALTER TABLE organization_service.join_codes 
            ALTER COLUMN is_active TYPE VARCHAR(10) 
            USING CASE WHEN is_active THEN 'true' ELSE 'false' END
            """
        )
    )
