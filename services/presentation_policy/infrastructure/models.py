"""
SQLAlchemy models for presentation-policy service.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Index, Table
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    """Helper to get current UTC time with timezone."""
    return datetime.now(timezone.utc)


# Presentation Policies table
presentation_policies = Table(
    "presentation_policies",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(255), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("status", String(50), nullable=False, default="draft"),
    
    # Display metadata (JSON)
    Column("display_metadata", JSON, nullable=False, default=dict),
    
    # Requirements (JSON arrays)
    Column("credential_requirements", JSON, nullable=False, default=list),
    Column("alternative_requirements", JSON, nullable=False, default=list),
    
    # Compliance
    Column("compliance_profile_id", String(36), nullable=True),
    
    # Version tracking
    Column("version", Integer, nullable=False, default=1),
    
    # Timestamps (timezone-aware)
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    
    schema="presentation_policy_service",
)

# Indexes for efficient querying
Index("ix_presentation_policies_organization_id", presentation_policies.c.organization_id)
Index("ix_presentation_policies_status", presentation_policies.c.status)
Index("ix_presentation_policies_org_status", presentation_policies.c.organization_id, presentation_policies.c.status)
