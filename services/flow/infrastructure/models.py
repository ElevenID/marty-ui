"""
SQLAlchemy models for flow service.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
)
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
    Column("status", String(50), nullable=False, default="DRAFT"),
    Column("flow_type", String(50), nullable=False),
    
    # Steps and transitions (JSON arrays)
    Column("steps", JSON, nullable=False, default=list),
    Column("transitions", JSON, nullable=False, default=list),
    Column("start_step_id", String(36), nullable=True),
    
    # Linked configurations
    Column("credential_template_id", String(36), nullable=True),
    Column("application_template_id", String(36), nullable=True),
    Column("presentation_policy_id", String(36), nullable=True),
    Column("delivery_destination_profile_id", String(128), nullable=True),
    Column("deployment_profile_id", String(36), nullable=True),
    Column("deployment_profile_ids", JSON, nullable=False, default=list),
    Column("trust_profile_id", String(36), nullable=True),
    Column("approval_strategy", String(50), nullable=False, default="AUTO"),
    Column("hooks", JSON, nullable=False, default=dict),
    Column("trigger", JSON, nullable=True),
    Column("extension", JSON, nullable=True),
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
    Column("application_flow_key_hash", String(64), nullable=True),
    
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
    CheckConstraint(
        "application_flow_key_hash IS NULL OR "
        "application_flow_key_hash ~ '^[0-9a-f]{64}$'",
        name="ck_flow_instances_application_flow_key_hash",
    ),
    
    schema="flow_service",
)

flow_instance_artifacts = Table(
    "flow_instance_artifacts",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column(
        "flow_instance_id",
        String(36),
        ForeignKey("flow_service.flow_instances.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("issuance_transaction_id", String(36), nullable=True),
    Column("credential_offer_uri", Text, nullable=True),
    Column("credential_offer_uris", JSON, nullable=False, default=dict),
    Column("credential_offer_labels", JSON, nullable=False, default=dict),
    Column("pre_authorized_code", String(255), nullable=True),
    Column("issuance_status", String(50), nullable=True),
    Column("qr_payload", Text, nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("scanned_at", DateTime(timezone=True), nullable=True),
    Column("status", String(50), nullable=False),
    Column("state", String(255), nullable=True),
    Column("wallet_metadata", JSON, nullable=False, default=dict),
    Column("attempt_number", Integer, nullable=False, default=1),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
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
Index(
    "ux_flow_instances_org_application_flow_key",
    flow_instances.c.organization_id,
    flow_instances.c.application_flow_key_hash,
    unique=True,
)
Index(
    "ix_flow_instance_artifacts_pre_authorized_code",
    flow_instance_artifacts.c.pre_authorized_code,
)
Index(
    "ux_flow_instance_artifacts_issuance_transaction_id",
    flow_instance_artifacts.c.issuance_transaction_id,
    unique=True,
)
