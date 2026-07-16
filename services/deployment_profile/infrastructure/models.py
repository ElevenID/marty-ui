"""
SQLAlchemy models for deployment-profile service.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Table, Text, Index
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    return datetime.now(timezone.utc)


deployment_profiles = Table(
    "deployment_profiles",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(255), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("status", String(50), nullable=False),
    Column("environment", String(50), nullable=False),
    Column("site_id", String(255), nullable=True),
    Column("trust_profile_id", String(36), nullable=True),
    Column("presentation_policy_ids", JSON, nullable=False, default=list),
    Column("credential_template_ids", JSON, nullable=False, default=list),
    Column("default_policy_id", String(36), nullable=True),
    Column("network_mode", String(50), nullable=False),
    Column("key_access_mode", String(50), nullable=False),
    Column("environment_config", JSON, nullable=False, default=dict),
    Column("enabled_flow_ids", JSON, nullable=False, default=list),
    Column("update_channel", String(50), nullable=False, default="stable"),
    Column("update_policy", JSON, nullable=False, default=dict),
    Column("offline_cache_ttl_hours", Integer, nullable=False, default=24),
    Column("operator_biometric_authentication_required", Boolean, nullable=False, default=False),
    Column("audit_all_events", Boolean, nullable=False, default=True),
    Column("api_key", Text, nullable=True),
    Column("api_key_prefix", String(255), nullable=False, default=""),
    Column("callbacks", JSON, nullable=False, default=dict),
    Column("api_auth", JSON, nullable=False, default=dict),
    Column("rate_limits", JSON, nullable=False, default=dict),
    Column("feature_flags", JSON, nullable=False, default=dict),
    Column("branding", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    schema="deployment_profile_service",
)

lanes = Table(
    "lanes",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("deployment_profile_id", String(36), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("location", String(255), nullable=True),
    Column("device_type", String(50), nullable=False, default="kiosk"),
    Column("default_policy_id", String(36), nullable=True),
    Column("metadata", JSON, nullable=False, default=dict),
    Column("device_ids", JSON, nullable=False, default=list),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    schema="deployment_profile_service",
)

Index("ix_deployment_profiles_organization_id", deployment_profiles.c.organization_id)
Index("ix_deployment_profiles_org_status", deployment_profiles.c.organization_id, deployment_profiles.c.status)
Index("ix_deployment_profiles_status", deployment_profiles.c.status)
Index("ix_lanes_deployment_profile_id", lanes.c.deployment_profile_id)
