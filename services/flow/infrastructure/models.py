"""
SQLAlchemy models for flow service.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, Index, Table
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    """Helper to get current UTC time with timezone."""
    return datetime.now(timezone.utc)


# Flow Definitions table
flow_definitions = Table(
    "flow_definitions",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(255), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("status", String(50), nullable=False, default="draft"),
    Column("flow_type", String(50), nullable=False),
    
    # Steps and transitions (JSON arrays)
    Column("steps", JSON, nullable=False, default=list),
    Column("transitions", JSON, nullable=False, default=list),
    Column("start_step_id", String(36), nullable=True),
    
    # Linked configurations
    Column("credential_template_id", String(36), nullable=True),
    Column("presentation_policy_id", String(36), nullable=True),
    Column("deployment_profile_id", String(36), nullable=True),
    Column("preconditions", JSON, nullable=False, server_default="[]"),
    
    # Flow settings
    Column("default_timeout_seconds", Integer, nullable=False, default=3600),
    Column("max_retries", Integer, nullable=False, default=3),
    Column("enable_resume", Boolean, nullable=False, default=True),
    
    # Version tracking
    Column("version", Integer, nullable=False, default=1),
    
    # Timestamps (timezone-aware)
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    
    schema="flow_service",
)

# Flow Instances table
flow_instances = Table(
    "flow_instances",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("flow_definition_id", String(36), nullable=False),
    Column("organization_id", String(255), nullable=False),
    Column("status", String(50), nullable=False, default="created"),
    Column("current_step_id", String(36), nullable=True),
    
    # Context and history (JSON)
    Column("context", JSON, nullable=False, default=dict),
    Column("step_history", JSON, nullable=False, default=list),
    
    # Subject
    Column("subject_id", String(255), nullable=True),
    Column("subject_type", String(50), nullable=False, default="applicant"),
    
    # External references
    Column("external_reference", String(255), nullable=True),
    
    # Timing
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    
    # Result
    Column("result", JSON, nullable=True),
    Column("error", Text, nullable=True),
    
    # Timestamps (timezone-aware)
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    
    schema="flow_service",
)

# Indexes for efficient querying
Index("ix_flow_definitions_organization_id", flow_definitions.c.organization_id)
Index("ix_flow_definitions_status", flow_definitions.c.status)
Index("ix_flow_definitions_flow_type", flow_definitions.c.flow_type)
Index("ix_flow_definitions_org_status", flow_definitions.c.organization_id, flow_definitions.c.status)

Index("ix_flow_instances_organization_id", flow_instances.c.organization_id)
Index("ix_flow_instances_flow_definition_id", flow_instances.c.flow_definition_id)
Index("ix_flow_instances_status", flow_instances.c.status)
Index("ix_flow_instances_subject_id", flow_instances.c.subject_id)
Index("ix_flow_instances_external_reference", flow_instances.c.external_reference)
