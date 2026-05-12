"""Ensure Marty login deployment profile exists for credential auth presentation.

Revision ID: 20260416_0003
Revises: 20260416_0002
Create Date: 2026-04-16 12:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260416_0003"
down_revision = "20260416_0002"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_DEPLOYMENT_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
MARTY_LOGIN_POLICY_ID = "50000000-0000-0000-0000-000000000004"
MARTY_OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
NOW = "2026-04-16T12:00:00+00:00"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            INSERT INTO deployment_profile_service.deployment_profiles (
                id,
                organization_id,
                name,
                description,
                status,
                environment,
                site_id,
                trust_profile_id,
                presentation_policy_ids,
                credential_template_ids,
                default_policy_id,
                default_trust_profile_id,
                default_compliance_profile_id,
                default_presentation_policy_id,
                network_mode,
                key_access_mode,
                environment_config,
                ux_config,
                enabled_flow_ids,
                update_channel,
                update_policy,
                offline_cache_ttl_hours,
                biometric_required,
                audit_all_events,
                api_key,
                api_key_prefix,
                callbacks,
                api_auth,
                rate_limits,
                feature_flags,
                branding,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :description,
                :status,
                :environment,
                :site_id,
                :trust_profile_id,
                :presentation_policy_ids,
                :credential_template_ids,
                :default_policy_id,
                :default_trust_profile_id,
                :default_compliance_profile_id,
                :default_presentation_policy_id,
                :network_mode,
                :key_access_mode,
                :environment_config,
                :ux_config,
                :enabled_flow_ids,
                :update_channel,
                :update_policy,
                :offline_cache_ttl_hours,
                :biometric_required,
                :audit_all_events,
                :api_key,
                :api_key_prefix,
                :callbacks,
                :api_auth,
                :rate_limits,
                :feature_flags,
                :branding,
                :created_at,
                :updated_at
            )
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                environment = EXCLUDED.environment,
                site_id = EXCLUDED.site_id,
                trust_profile_id = EXCLUDED.trust_profile_id,
                presentation_policy_ids = EXCLUDED.presentation_policy_ids,
                credential_template_ids = EXCLUDED.credential_template_ids,
                default_policy_id = EXCLUDED.default_policy_id,
                default_trust_profile_id = EXCLUDED.default_trust_profile_id,
                default_compliance_profile_id = EXCLUDED.default_compliance_profile_id,
                default_presentation_policy_id = EXCLUDED.default_presentation_policy_id,
                network_mode = EXCLUDED.network_mode,
                key_access_mode = EXCLUDED.key_access_mode,
                environment_config = EXCLUDED.environment_config,
                ux_config = EXCLUDED.ux_config,
                enabled_flow_ids = EXCLUDED.enabled_flow_ids,
                update_channel = EXCLUDED.update_channel,
                update_policy = EXCLUDED.update_policy,
                offline_cache_ttl_hours = EXCLUDED.offline_cache_ttl_hours,
                biometric_required = EXCLUDED.biometric_required,
                audit_all_events = EXCLUDED.audit_all_events,
                api_key = EXCLUDED.api_key,
                api_key_prefix = EXCLUDED.api_key_prefix,
                callbacks = EXCLUDED.callbacks,
                api_auth = EXCLUDED.api_auth,
                rate_limits = EXCLUDED.rate_limits,
                feature_flags = EXCLUDED.feature_flags,
                branding = EXCLUDED.branding,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "id": MARTY_DEPLOYMENT_PROFILE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Marty Credential Login Deployment",
            "description": "Default deployment profile used for Marty credential-based login preview flows.",
            "status": "active",
            "environment": "production",
            "site_id": "marty-login",
            "trust_profile_id": MARTY_TRUST_PROFILE_ID,
            "presentation_policy_ids": json.dumps([MARTY_LOGIN_POLICY_ID]),
            "credential_template_ids": json.dumps([MARTY_OPEN_BADGE_TEMPLATE_ID]),
            "default_policy_id": MARTY_LOGIN_POLICY_ID,
            "default_trust_profile_id": MARTY_TRUST_PROFILE_ID,
            "default_compliance_profile_id": None,
            "default_presentation_policy_id": MARTY_LOGIN_POLICY_ID,
            "network_mode": "ONLINE",
            "key_access_mode": "KEY_VAULT",
            "environment_config": json.dumps({"language": "en-US", "offline_cache_ttl_seconds": 86400}),
            "ux_config": json.dumps({"language": "en-US", "operator_mode": False, "accessibility_mode": False}),
            "enabled_flow_ids": json.dumps([]),
            "update_channel": "stable",
            "update_policy": json.dumps({"channel": "stable", "auto_update": True}),
            "offline_cache_ttl_hours": 24,
            "biometric_required": False,
            "audit_all_events": True,
            "api_key": None,
            "api_key_prefix": "",
            "callbacks": json.dumps({}),
            "api_auth": json.dumps({"auth_method": "api_key", "api_key_header": "X-API-Key"}),
            "rate_limits": json.dumps(
                {
                    "enabled": True,
                    "requests_per_minute": 300,
                    "requests_per_hour": 5000,
                    "requests_per_day": 50000,
                    "burst_size": 50,
                    "endpoint_limits": {},
                }
            ),
            "feature_flags": json.dumps(
                {
                    "enable_selective_disclosure": True,
                    "enable_derived_attributes": True,
                    "enable_batch_issuance": False,
                    "enable_deferred_issuance": True,
                    "enable_credential_refresh": True,
                    "enable_qr_code_generation": True,
                    "enable_push_notifications": False,
                    "enable_biometric_binding": False,
                    "custom_flags": {},
                }
            ),
            "branding": json.dumps({"organization_name": "Marty", "primary_color": "#1a1a2e", "secondary_color": "#4a4a6a"}),
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text(
            """
            DELETE FROM deployment_profile_service.deployment_profiles
            WHERE id = :id
            """
        ),
        {"id": MARTY_DEPLOYMENT_PROFILE_ID},
    )
