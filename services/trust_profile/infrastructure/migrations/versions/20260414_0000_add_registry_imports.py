"""Add registry import tables and columns

Revision ID: registry_001
Revises: 7d8b4b4ef634
Create Date: 2026-04-14 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'registry_001'
down_revision = '7d8b4b4ef634'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create trust_registry_sources table
    op.create_table(
        'trust_registry_sources',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('trust_profile_id', sa.String(), nullable=False),
        sa.Column('registry_type', sa.String(), nullable=False),  # ICAO_PKD, EU_TRUST_LIST, AAMVA
        sa.Column('registry_name', sa.String(), nullable=False),
        sa.Column('registry_url', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('sync_enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sync_interval_hours', sa.Integer(), nullable=False, default=24),
        sa.Column('credential_format_filter', sa.JSON(), nullable=False, default=list),
        sa.Column('metadata', sa.JSON(), nullable=False, default=dict),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['trust_profile_id'], ['trust_profile_service.trust_profiles.id']),
        sa.Index('ix_registry_sources_trust_profile', 'trust_profile_id'),
        sa.Index('ix_registry_sources_type', 'registry_type'),
        sa.Index('ix_registry_sources_enabled', 'enabled'),
        schema='trust_profile_service'
    )

    # Create trust_registry_issuers table (imported issuers from registries)
    op.create_table(
        'trust_registry_issuers',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('registry_source_id', sa.String(), nullable=False),
        sa.Column('trust_profile_id', sa.String(), nullable=False),
        sa.Column('issuer_did', sa.String(), nullable=False),
        sa.Column('issuer_name', sa.String(), nullable=True),
        sa.Column('country_code', sa.String(), nullable=True),
        sa.Column('issuer_type', sa.String(), nullable=True),
        sa.Column('verification_keys', sa.JSON(), nullable=False, default=list),
        sa.Column('credential_templates', sa.JSON(), nullable=False, default=list),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('imported_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['registry_source_id'], ['trust_profile_service.trust_registry_sources.id']),
        sa.ForeignKeyConstraint(['trust_profile_id'], ['trust_profile_service.trust_profiles.id']),
        sa.Index('ix_registry_issuers_registry_source', 'registry_source_id'),
        sa.Index('ix_registry_issuers_trust_profile', 'trust_profile_id'),
        sa.Index('ix_registry_issuers_did', 'issuer_did'),
        sa.Index('ix_registry_issuers_status', 'status'),
        schema='trust_profile_service'
    )

    # Add registry_imports column to trust_profiles table to track import configuration
    op.add_column(
        'trust_profiles',
        sa.Column('registry_imports', sa.JSON(), nullable=False, server_default='[]'),
        schema='trust_profile_service'
    )


def downgrade() -> None:
    # Drop columns and tables in reverse order
    op.drop_column('trust_profiles', 'registry_imports', schema='trust_profile_service')
    
    op.drop_table(
        'trust_registry_issuers',
        schema='trust_profile_service'
    )
    
    op.drop_table(
        'trust_registry_sources',
        schema='trust_profile_service'
    )
