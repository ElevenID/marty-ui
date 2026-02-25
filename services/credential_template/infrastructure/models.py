"""
SQLAlchemy table definitions for Credential Template Service.

Following hexagonal architecture: infrastructure layer defines persistence schema.
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, 
    JSON, MetaData, String, Table, Text
)
from sqlalchemy.orm import registry

# Schema namespace for this service
SCHEMA = "credential_template_service"

# Create mapper registry
mapper_registry = registry()
metadata = MetaData(schema=SCHEMA)

# =============================================================================
# Templates Table
# =============================================================================

credential_templates_table = Table(
    "credential_templates",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("status", String(20), nullable=False, default="draft", index=True),
    
    # Type identifiers
    Column("credential_type", String(255), nullable=False),
    Column("vct", Text, nullable=False),
    Column("doctype", Text, nullable=True),
    
    # Schema - stored as JSON array of claim definitions
    Column("claims", JSON, nullable=False, default=list),
    
    # Privacy
    Column("privacy_posture", String(30), nullable=False, default="selective_disclosure"),
    Column("selective_disclosure_fields", JSON, nullable=False, default=list),
    Column("zk_predicate_claims", JSON, nullable=True, default=list),
    Column("derived_attributes", JSON, nullable=False, default=list),
    
    # Display - stored as JSON object
    Column("display_style", JSON, nullable=False, default=dict),
    
    # Validity - stored as JSON object
    Column("validity_rules", JSON, nullable=False, default=dict),
    
    # Issuer Constraints - stored as JSON object
    Column("issuer_requirements", JSON, nullable=False, default=dict),
    
    # Supported formats
    Column("supported_formats", JSON, nullable=False, default=list),
    
    # SD-JWT payload structure: "ietf_sd_jwt" or "w3c_vcdm_v2_sd_jwt" (default)
    Column("credential_payload_format", String(30), nullable=False, server_default="w3c_vcdm_v2_sd_jwt"),
    
    # Per-wallet configuration: [{wallet_id, deep_link_scheme}, ...]
    Column("wallet_configs", JSON, nullable=True, server_default="[]"),
    
    # Version control
    Column("version", Integer, nullable=False, default=1),
    
    # Timestamps
    Column("created_at", DateTime(timezone=True), nullable=False, default=datetime.utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow),
    
    schema=SCHEMA
)

# Create indexes for common queries
from sqlalchemy import Index

Index("ix_credential_templates_org_status", 
      credential_templates_table.c.organization_id, 
      credential_templates_table.c.status)
Index("ix_credential_templates_credential_type", 
      credential_templates_table.c.credential_type)
