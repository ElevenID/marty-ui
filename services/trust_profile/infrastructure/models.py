"""
SQLAlchemy models for Trust Profile Service.

Defines database schema for trust profiles and trusted issuers.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer, Boolean, JSON, Table, Index
from sqlalchemy.orm import registry

mapper_registry = registry()

# Helper function for timezone-aware timestamps
def utcnow():
    return datetime.now(timezone.utc)

# Trust Profiles table
trust_profiles_table = Table(
    "trust_profiles",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("name", String, nullable=False),
    Column("description", String, nullable=True),
    Column("status", String, nullable=False, default="draft"),
    
    # Trust configuration (stored as JSON)
    Column("trust_sources", JSON, nullable=False, default=list),
    Column("validation_rules", JSON, nullable=False, default=dict),
    Column("revocation_policy", JSON, nullable=False, default=dict),
    Column("revocation_profile_id", String, nullable=True),
    Column("time_policy", JSON, nullable=False, default=dict),
    Column("supported_formats", JSON, nullable=False, default=list),
    
    # Timestamps - timezone aware
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    
    # Indexes for efficient querying
    Index("ix_trust_profiles_organization_id", "organization_id"),
    Index("ix_trust_profiles_status", "status"),
    Index("ix_trust_profiles_org_status", "organization_id", "status"),
    
    schema="trust_profile_service"
)

# Trusted Issuers table
trusted_issuers_table = Table(
    "trusted_issuers",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("trust_profile_id", String, nullable=False),
    Column("name", String, nullable=False),
    Column("description", String, nullable=True),
    
    # Issuer identity
    Column("issuer_did", String, nullable=False),
    Column("issuer_url", String, nullable=True),
    
    # Trust settings
    Column("status", String, nullable=False, default="active"),
    Column("credential_template_ids", JSON, nullable=False, default=list),
    Column("verification_keys", JSON, nullable=False, default=list),
    
    # Constraints
    Column("valid_from", DateTime(timezone=True), nullable=True),
    Column("valid_until", DateTime(timezone=True), nullable=True),
    
    # Timestamps - timezone aware
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    
    # Indexes
    Index("ix_trusted_issuers_trust_profile_id", "trust_profile_id"),
    Index("ix_trusted_issuers_issuer_did", "issuer_did"),
    Index("ix_trusted_issuers_status", "status"),
    
    schema="trust_profile_service"
)
