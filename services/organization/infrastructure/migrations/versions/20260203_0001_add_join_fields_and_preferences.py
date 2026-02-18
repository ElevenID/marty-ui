"""Add join fields and console preferences

Revision ID: 20260203_0001
Revises: 20260203_0000
Create Date: 2026-02-03 00:01:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = '20260203_0001'
down_revision = '20260203_0000'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add join mechanism fields to organizations table
    op.add_column('organizations', 
        sa.Column('join_mechanism', sa.String(length=50), nullable=False, server_default='invite'),
        schema='organization_service'
    )
    op.add_column('organizations',
        sa.Column('requires_approval', sa.String(length=10), nullable=False, server_default='false'),
        schema='organization_service'
    )
    op.add_column('organizations',
        sa.Column('is_discoverable', sa.String(length=10), nullable=False, server_default='false'),
        schema='organization_service'
    )
    
    # Create console context preferences table
    op.create_table('console_context_preferences',
        sa.Column('id', UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('last_view_mode', sa.String(length=50), nullable=False),
        sa.Column('last_active_org_id', UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', name='uq_console_context_preferences_user_id'),
        schema='organization_service'
    )
    op.create_index(
        op.f('ix_organization_service_console_context_preferences_user_id'),
        'console_context_preferences',
        ['user_id'],
        unique=True,
        schema='organization_service'
    )
    
    # Create join codes table
    op.create_table('join_codes',
        sa.Column('id', UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', UUID(as_uuid=True), nullable=False),
        sa.Column('code', sa.String(length=8), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('max_uses', sa.Integer(), nullable=True),
        sa.Column('use_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.String(length=10), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organization_service.organizations.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code', name='uq_join_codes_code'),
        schema='organization_service'
    )
    op.create_index(
        op.f('ix_organization_service_join_codes_code'),
        'join_codes',
        ['code'],
        unique=True,
        schema='organization_service'
    )
    op.create_index(
        op.f('ix_organization_service_join_codes_organization_id'),
        'join_codes',
        ['organization_id'],
        unique=False,
        schema='organization_service'
    )


def downgrade() -> None:
    # Drop join codes table
    op.drop_index(
        op.f('ix_organization_service_join_codes_organization_id'),
        table_name='join_codes',
        schema='organization_service'
    )
    op.drop_index(
        op.f('ix_organization_service_join_codes_code'),
        table_name='join_codes',
        schema='organization_service'
    )
    op.drop_table('join_codes', schema='organization_service')
    
    # Drop console context preferences table
    op.drop_index(
        op.f('ix_organization_service_console_context_preferences_user_id'),
        table_name='console_context_preferences',
        schema='organization_service'
    )
    op.drop_table('console_context_preferences', schema='organization_service')
    
    # Remove join mechanism fields from organizations table
    op.drop_column('organizations', 'is_discoverable', schema='organization_service')
    op.drop_column('organizations', 'requires_approval', schema='organization_service')
    op.drop_column('organizations', 'join_mechanism', schema='organization_service')
