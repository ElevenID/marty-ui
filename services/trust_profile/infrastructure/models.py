"""
SQLAlchemy models for Trust Profile Service.

Defines database schema for trust profiles, trust frameworks, trust registry,
issuer registry, and legacy trusted issuer compatibility.
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


trust_frameworks_table = Table(
    "trust_frameworks",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("code", String, nullable=False, unique=True),
    Column("display_name", String, nullable=False),
    Column("description", String, nullable=True),
    Column("pkd_endpoints", JSON, nullable=False, default=list),
    Column("default_algorithms", JSON, nullable=False, default=list),
    Column("default_formats", JSON, nullable=False, default=list),
    Column("validation_ruleset", JSON, nullable=False, default=dict),
    Column("sync_config", JSON, nullable=False, default=dict),
    Column("is_system", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),

    Index("ix_trust_frameworks_code", "code"),
    Index("ix_trust_frameworks_system", "is_system"),

    schema="trust_profile_service"
)


organization_trust_profiles_table = Table(
    "organization_trust_profiles",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("framework_id", String, nullable=False),
    Column("name", String, nullable=False),
    Column("display_name", String, nullable=True),
    Column("description", String, nullable=True),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("use_case_tags", JSON, nullable=False, default=list),
    Column("compliance_status", String, nullable=False),
    Column("auto_generated", Boolean, nullable=False, default=False),
    Column("revocation_policy", JSON, nullable=True),
    Column("time_policy", JSON, nullable=True),
    Column("allowed_algorithms", JSON, nullable=True),
    Column("allowed_formats", JSON, nullable=True),
    Column("allowed_issuers", JSON, nullable=True),
    Column("denied_issuers", JSON, nullable=True),
    Column("jurisdiction_filter", JSON, nullable=True),
    Column("metadata", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),

    Index("ix_org_trust_profiles_org", "organization_id"),
    Index("ix_org_trust_profiles_framework", "framework_id"),
    Index("ix_org_trust_profiles_compliance_status", "compliance_status"),
    Index("ix_org_trust_profiles_org_name", "organization_id", "name"),

    schema="trust_profile_service"
)


trust_registry_entries_table = Table(
    "trust_registry_entries",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("anchor_type", String, nullable=False),
    Column("operation", String, nullable=False, default="ADD"),
    Column("country_code", String, nullable=False),
    Column("certificate_pem", String, nullable=True),
    Column("subject_key_id", String, nullable=True),
    Column("not_before", DateTime(timezone=True), nullable=True),
    Column("not_after", DateTime(timezone=True), nullable=True),
    Column("source", String, nullable=False),
    Column("framework_code", String, nullable=True),
    Column("sequence", Integer, nullable=False, default=0),
    Column("is_current", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),

    Index("ix_trust_registry_entries_anchor_type", "anchor_type"),
    Index("ix_trust_registry_entries_country_code", "country_code"),
    Index("ix_trust_registry_entries_sequence", "sequence"),
    Index("ix_trust_registry_entries_current", "is_current"),
    Index("ix_trust_registry_entries_source", "source"),

    schema="trust_profile_service"
)


issuer_entities_table = Table(
    "issuer_entities",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=True),
    Column("issuer_id", String, nullable=False),
    Column("issuer_type", String, nullable=False),
    Column("display_name", String, nullable=False),
    Column("description", String, nullable=True),
    Column("is_system_issuer", Boolean, nullable=False, default=False),
    Column("compliance_status", String, nullable=False),
    Column("accreditation_body", String, nullable=True),
    Column("accreditation_date", DateTime(timezone=True), nullable=True),
    Column("valid_from", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True), nullable=True),
    Column("trust_anchor_id", String, nullable=True),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Column("revocation_reason", String, nullable=True),
    Column("revoked_by", String, nullable=True),
    Column("metadata", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),

    Index("ix_issuer_entities_org", "organization_id"),
    Index("ix_issuer_entities_identifier", "issuer_id"),
    Index("ix_issuer_entities_status", "compliance_status"),
    Index("ix_issuer_entities_system", "is_system_issuer"),
    Index("ix_issuer_entities_org_identifier", "organization_id", "issuer_id"),

    schema="trust_profile_service"
)


trust_profile_issuers_table = Table(
    "trust_profile_issuers",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("trust_profile_id", String, nullable=False),
    Column("issuer_id", String, nullable=False),
    Column("trust_level", Integer, nullable=False, default=100),
    Column("relationship_status", String, nullable=False),
    Column("cascade_revocation_policy", String, nullable=False),
    Column("metadata", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),

    Index("ix_trust_profile_issuers_profile", "trust_profile_id"),
    Index("ix_trust_profile_issuers_issuer", "issuer_id"),
    Index("ix_trust_profile_issuers_relationship", "relationship_status"),
    Index("ix_trust_profile_issuers_profile_issuer", "trust_profile_id", "issuer_id"),

    schema="trust_profile_service"
)
