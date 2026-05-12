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
    
    # Key management (BYOK support)
    Column("key_access_mode", String(20), nullable=True),  # KEY_VAULT | HSM | LOCAL | REMOTE_SIGNING
    Column("issuer_key_id", String(255), nullable=True),
    Column("issuer_algorithm", String(20), nullable=True),  # ES256 | EdDSA | RS256 | ES384
    Column("remote_signing_config", JSON, nullable=True),   # {provider, key_name, key_version, ...}
    
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


# =============================================================================
# Wallet Registry Table
# =============================================================================

wallet_registry_table = Table(
    "wallet_registry",
    metadata,
    Column("id", String(64), primary_key=True),          # e.g. "wr-marty-001"
    Column("organization_id", String(64), nullable=True, index=True),
    Column("is_override", Boolean, nullable=False, server_default="false"),
    Column("override_precedence", Integer, nullable=False, server_default="50"),
    Column("merge_strategy", String(16), nullable=False, server_default="APPEND"),
    Column("credential_format", String(64), nullable=True, index=True),
    Column("issuance_protocol", String(64), nullable=True, index=True),
    Column("compliance_profile_code", String(128), nullable=True, index=True),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("wallet_apps", JSON, nullable=False, server_default="[]"),
    Column("specifications", JSON, nullable=False, server_default="[]"),
    Column("logo_url", Text, nullable=True),
    Column("deep_link_template", Text, nullable=False,
        server_default="openid-credential-offer://?credential_offer_uri={offer_uri}"),
    Column("routing_templates", JSON, nullable=False, server_default="{}"),
    Column("install_urls", JSON, nullable=False, server_default="{}"),
    Column("ios_scheme", String(128), nullable=True),
    Column("universal_link_template", Text, nullable=True),
    Column("android_package", String(255), nullable=True),
    Column("supported_formats", JSON, nullable=False, server_default="[]"),
    Column("supported_protocols", JSON, nullable=False, server_default='["OID4VCI_PRE_AUTH"]'),
    Column("platforms", JSON, nullable=False, server_default="[]"),
    Column("supports_qr", Boolean, nullable=False, server_default="true"),
    Column("supports_deeplink", Boolean, nullable=False, server_default="true"),
    Column("supports_digital_credentials", Boolean, nullable=False, server_default="false"),
    Column("supports_haip", Boolean, nullable=False, server_default="false"),
    Column("docs_url", Text, nullable=True),
    Column("is_active", Boolean, nullable=False, server_default="true"),
    Column("created_at", DateTime(timezone=True), nullable=False, default=datetime.utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=datetime.utcnow,
           onupdate=datetime.utcnow),

    schema=SCHEMA,
)
