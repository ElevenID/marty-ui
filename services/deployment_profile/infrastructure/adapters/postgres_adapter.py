"""
PostgreSQL adapters for deployment-profile repositories.
"""

from typing import TYPE_CHECKING

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from deployment_profile.infrastructure.models import deployment_profiles, lanes

if TYPE_CHECKING:
    from deployment_profile.main import (
        ApiAuthConfiguration,
        AuthMethod,
        BrandingConfiguration,
        CallbackConfiguration,
        DeploymentProfile,
        Environment,
        FeatureFlags,
        Lane,
        ProfileStatus,
        RateLimitConfiguration,
    )


class PostgresDeploymentProfileRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def save(self, profile: "DeploymentProfile") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(deployment_profiles.c.id).where(deployment_profiles.c.id == profile.id)
            )
            exists = result.scalar_one_or_none()

            values = {
                "organization_id": profile.organization_id,
                "name": profile.name,
                "description": profile.description,
                "status": profile.status.value if hasattr(profile.status, "value") else str(profile.status),
                "environment": profile.environment.value if hasattr(profile.environment, "value") else str(profile.environment),
                "site_id": profile.site_id,
                "trust_profile_id": profile.trust_profile_id,
                "presentation_policy_ids": list(profile.presentation_policy_ids),
                "credential_template_ids": list(profile.credential_template_ids),
                "default_policy_id": profile.default_policy_id,
                "default_trust_profile_id": profile.default_trust_profile_id,
                "default_compliance_profile_id": profile.default_compliance_profile_id,
                "default_presentation_policy_id": profile.default_presentation_policy_id,
                "network_mode": profile.network_mode,
                "key_access_mode": profile.key_access_mode,
                "environment_config": dict(profile.environment_config),
                "ux_config": dict(profile.ux_config),
                "enabled_flow_ids": list(profile.enabled_flow_ids),
                "update_channel": profile.update_channel,
                "update_policy": dict(profile.update_policy),
                "offline_cache_ttl_hours": profile.offline_cache_ttl_hours,
                "biometric_required": profile.biometric_required,
                "audit_all_events": profile.audit_all_events,
                "api_key": profile.api_key,
                "api_key_prefix": profile.api_key_prefix,
                "callbacks": {
                    "issuance_complete_url": profile.callbacks.issuance_complete_url,
                    "issuance_failed_url": profile.callbacks.issuance_failed_url,
                    "verification_complete_url": profile.callbacks.verification_complete_url,
                    "verification_failed_url": profile.callbacks.verification_failed_url,
                    "credential_revoked_url": profile.callbacks.credential_revoked_url,
                    "signing_key_id": profile.callbacks.signing_key_id,
                    "require_signature_verification": profile.callbacks.require_signature_verification,
                    "max_retries": profile.callbacks.max_retries,
                    "retry_delay_seconds": profile.callbacks.retry_delay_seconds,
                },
                "api_auth": {
                    "auth_method": profile.api_auth.auth_method.value
                    if hasattr(profile.api_auth.auth_method, "value")
                    else str(profile.api_auth.auth_method),
                    "api_key_header": profile.api_auth.api_key_header,
                    "oauth2_issuer": profile.api_auth.oauth2_issuer,
                    "oauth2_audience": profile.api_auth.oauth2_audience,
                    "oauth2_scopes": list(profile.api_auth.oauth2_scopes),
                    "jwt_issuer": profile.api_auth.jwt_issuer,
                    "jwt_audience": profile.api_auth.jwt_audience,
                },
                "rate_limits": {
                    "enabled": profile.rate_limits.enabled,
                    "requests_per_minute": profile.rate_limits.requests_per_minute,
                    "requests_per_hour": profile.rate_limits.requests_per_hour,
                    "requests_per_day": profile.rate_limits.requests_per_day,
                    "burst_size": profile.rate_limits.burst_size,
                    "endpoint_limits": dict(profile.rate_limits.endpoint_limits),
                },
                "feature_flags": {
                    "enable_selective_disclosure": profile.feature_flags.enable_selective_disclosure,
                    "enable_derived_attributes": profile.feature_flags.enable_derived_attributes,
                    "enable_batch_issuance": profile.feature_flags.enable_batch_issuance,
                    "enable_deferred_issuance": profile.feature_flags.enable_deferred_issuance,
                    "enable_credential_refresh": profile.feature_flags.enable_credential_refresh,
                    "enable_qr_code_generation": profile.feature_flags.enable_qr_code_generation,
                    "enable_push_notifications": profile.feature_flags.enable_push_notifications,
                    "enable_biometric_binding": profile.feature_flags.enable_biometric_binding,
                    "enable_canvas_evidence": profile.feature_flags.enable_canvas_evidence,
                    "enable_canvas_lti": profile.feature_flags.enable_canvas_lti,
                    "enable_canvas_mirror_publish": profile.feature_flags.enable_canvas_mirror_publish,
                    "enable_canvas_mirror_ops": profile.feature_flags.enable_canvas_mirror_ops,
                    "enable_canvas_deep_linking": profile.feature_flags.enable_canvas_deep_linking,
                    "enable_canvas_ags": profile.feature_flags.enable_canvas_ags,
                    "enable_canvas_nrps": profile.feature_flags.enable_canvas_nrps,
                    "custom_flags": dict(profile.feature_flags.custom_flags),
                },
                "branding": {
                    "organization_name": profile.branding.organization_name,
                    "logo_url": profile.branding.logo_url,
                    "favicon_url": profile.branding.favicon_url,
                    "primary_color": profile.branding.primary_color,
                    "secondary_color": profile.branding.secondary_color,
                    "custom_css_url": profile.branding.custom_css_url,
                    "email_from_name": profile.branding.email_from_name,
                    "email_from_address": profile.branding.email_from_address,
                    "custom_domain": profile.branding.custom_domain,
                    "custom_issuer_domain": profile.branding.custom_issuer_domain,
                    "qr_size": profile.branding.qr_size,
                    "qr_foreground_color": profile.branding.qr_foreground_color,
                    "qr_background_color": profile.branding.qr_background_color,
                    "qr_logo_url": profile.branding.qr_logo_url,
                    "qr_logo_size_percent": profile.branding.qr_logo_size_percent,
                    "qr_border_color": profile.branding.qr_border_color,
                    "qr_border_width": profile.branding.qr_border_width,
                    "qr_error_correction": profile.branding.qr_error_correction,
                    "qr_show_instructions": profile.branding.qr_show_instructions,
                    "qr_custom_instruction_text": profile.branding.qr_custom_instruction_text,
                },
                "updated_at": profile.updated_at,
            }

            if exists:
                await session.execute(
                    deployment_profiles.update()
                    .where(deployment_profiles.c.id == profile.id)
                    .values(**values)
                )
            else:
                await session.execute(
                    deployment_profiles.insert().values(
                        id=profile.id,
                        created_at=profile.created_at,
                        **values,
                    )
                )

            await session.commit()

    async def get(self, profile_id: str) -> "DeploymentProfile | None":
        from deployment_profile.main import (
            ApiAuthConfiguration,
            AuthMethod,
            BrandingConfiguration,
            CallbackConfiguration,
            DeploymentProfile,
            Environment,
            FeatureFlags,
            ProfileStatus,
            RateLimitConfiguration,
        )

        async with self._session_factory() as session:
            result = await session.execute(
                select(deployment_profiles).where(deployment_profiles.c.id == profile_id)
            )
            row = result.first()
            if not row:
                return None

            callback_data = row.callbacks or {}
            api_auth_data = row.api_auth or {}
            rate_limit_data = row.rate_limits or {}
            feature_flag_data = row.feature_flags or {}
            branding_data = row.branding or {}

            try:
                status = ProfileStatus(row.status)
            except Exception:
                status = ProfileStatus.DRAFT

            try:
                environment = Environment(row.environment)
            except Exception:
                environment = Environment.DEVELOPMENT

            auth_method_value = api_auth_data.get("auth_method", AuthMethod.API_KEY.value)
            try:
                auth_method = AuthMethod(auth_method_value)
            except Exception:
                auth_method = AuthMethod.API_KEY

            return DeploymentProfile(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                status=status,
                environment=environment,
                callbacks=CallbackConfiguration(
                    issuance_complete_url=callback_data.get("issuance_complete_url"),
                    issuance_failed_url=callback_data.get("issuance_failed_url"),
                    verification_complete_url=callback_data.get("verification_complete_url"),
                    verification_failed_url=callback_data.get("verification_failed_url"),
                    credential_revoked_url=callback_data.get("credential_revoked_url"),
                    signing_key_id=callback_data.get("signing_key_id"),
                    require_signature_verification=callback_data.get("require_signature_verification", True),
                    max_retries=callback_data.get("max_retries", 3),
                    retry_delay_seconds=callback_data.get("retry_delay_seconds", 30),
                ),
                api_auth=ApiAuthConfiguration(
                    auth_method=auth_method,
                    api_key_header=api_auth_data.get("api_key_header", "X-API-Key"),
                    oauth2_issuer=api_auth_data.get("oauth2_issuer"),
                    oauth2_audience=api_auth_data.get("oauth2_audience"),
                    oauth2_scopes=api_auth_data.get("oauth2_scopes", []),
                    jwt_issuer=api_auth_data.get("jwt_issuer"),
                    jwt_audience=api_auth_data.get("jwt_audience"),
                ),
                rate_limits=RateLimitConfiguration(
                    enabled=rate_limit_data.get("enabled", True),
                    requests_per_minute=rate_limit_data.get("requests_per_minute", 100),
                    requests_per_hour=rate_limit_data.get("requests_per_hour", 1000),
                    requests_per_day=rate_limit_data.get("requests_per_day", 10000),
                    burst_size=rate_limit_data.get("burst_size", 20),
                    endpoint_limits=rate_limit_data.get("endpoint_limits", {}),
                ),
                feature_flags=FeatureFlags(
                    enable_selective_disclosure=feature_flag_data.get("enable_selective_disclosure", True),
                    enable_derived_attributes=feature_flag_data.get("enable_derived_attributes", True),
                    enable_batch_issuance=feature_flag_data.get("enable_batch_issuance", False),
                    enable_deferred_issuance=feature_flag_data.get("enable_deferred_issuance", True),
                    enable_credential_refresh=feature_flag_data.get("enable_credential_refresh", True),
                    enable_qr_code_generation=feature_flag_data.get("enable_qr_code_generation", True),
                    enable_push_notifications=feature_flag_data.get("enable_push_notifications", False),
                    enable_biometric_binding=feature_flag_data.get("enable_biometric_binding", False),
                    enable_canvas_evidence=feature_flag_data.get("enable_canvas_evidence", False),
                    enable_canvas_lti=feature_flag_data.get("enable_canvas_lti", False),
                    enable_canvas_mirror_publish=feature_flag_data.get("enable_canvas_mirror_publish", False),
                    enable_canvas_mirror_ops=feature_flag_data.get("enable_canvas_mirror_ops", False),
                    enable_canvas_deep_linking=feature_flag_data.get("enable_canvas_deep_linking", False),
                    enable_canvas_ags=feature_flag_data.get("enable_canvas_ags", False),
                    enable_canvas_nrps=feature_flag_data.get("enable_canvas_nrps", False),
                    custom_flags=feature_flag_data.get("custom_flags", {}),
                ),
                branding=BrandingConfiguration(
                    organization_name=branding_data.get("organization_name", ""),
                    logo_url=branding_data.get("logo_url"),
                    favicon_url=branding_data.get("favicon_url"),
                    primary_color=branding_data.get("primary_color", "#1a1a2e"),
                    secondary_color=branding_data.get("secondary_color", "#4a4a6a"),
                    custom_css_url=branding_data.get("custom_css_url"),
                    email_from_name=branding_data.get("email_from_name", ""),
                    email_from_address=branding_data.get("email_from_address"),
                    custom_domain=branding_data.get("custom_domain"),
                    custom_issuer_domain=branding_data.get("custom_issuer_domain"),
                    qr_size=branding_data.get("qr_size", 256),
                    qr_foreground_color=branding_data.get("qr_foreground_color", "#000000"),
                    qr_background_color=branding_data.get("qr_background_color", "#FFFFFF"),
                    qr_logo_url=branding_data.get("qr_logo_url"),
                    qr_logo_size_percent=branding_data.get("qr_logo_size_percent", 20),
                    qr_border_color=branding_data.get("qr_border_color"),
                    qr_border_width=branding_data.get("qr_border_width", 2),
                    qr_error_correction=branding_data.get("qr_error_correction", "H"),
                    qr_show_instructions=branding_data.get("qr_show_instructions", True),
                    qr_custom_instruction_text=branding_data.get("qr_custom_instruction_text"),
                ),
                trust_profile_id=row.trust_profile_id,
                presentation_policy_ids=row.presentation_policy_ids or [],
                credential_template_ids=row.credential_template_ids or [],
                default_policy_id=row.default_policy_id,
                default_trust_profile_id=row.default_trust_profile_id,
                default_compliance_profile_id=row.default_compliance_profile_id,
                default_presentation_policy_id=row.default_presentation_policy_id,
                site_id=row.site_id,
                network_mode=row.network_mode,
                key_access_mode=row.key_access_mode,
                environment_config=row.environment_config or {},
                ux_config=row.ux_config or {},
                update_channel=row.update_channel,
                update_policy=row.update_policy or {},
                offline_cache_ttl_hours=row.offline_cache_ttl_hours,
                biometric_required=row.biometric_required,
                audit_all_events=row.audit_all_events,
                enabled_flow_ids=row.enabled_flow_ids or [],
                api_key=row.api_key,
                api_key_prefix=row.api_key_prefix or "",
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list(self, org_id: str) -> list["DeploymentProfile"]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(deployment_profiles.c.id)
                .where(deployment_profiles.c.organization_id == org_id)
                .order_by(deployment_profiles.c.created_at.desc())
            )
            ids = [row.id for row in result]

        profiles: list["DeploymentProfile"] = []
        for profile_id in ids:
            profile = await self.get(profile_id)
            if profile:
                profiles.append(profile)
        return profiles

    async def delete(self, profile_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(deployment_profiles).where(deployment_profiles.c.id == profile_id))
            await session.commit()


class PostgresLaneRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def save(self, lane: "Lane") -> None:
        async with self._session_factory() as session:
            result = await session.execute(select(lanes.c.id).where(lanes.c.id == lane.id))
            exists = result.scalar_one_or_none()

            values = {
                "deployment_profile_id": lane.deployment_profile_id,
                "name": lane.name,
                "description": lane.description,
                "location": lane.location,
                "device_type": lane.device_type,
                "default_policy_id": lane.default_policy_id,
                "metadata": dict(lane.metadata),
                "device_ids": list(lane.device_ids),
                "updated_at": lane.updated_at,
            }

            if exists:
                await session.execute(
                    lanes.update().where(lanes.c.id == lane.id).values(**values)
                )
            else:
                await session.execute(
                    lanes.insert().values(
                        id=lane.id,
                        created_at=lane.created_at,
                        **values,
                    )
                )

            await session.commit()

    async def get(self, lane_id: str) -> "Lane | None":
        from deployment_profile.main import Lane

        async with self._session_factory() as session:
            result = await session.execute(select(lanes).where(lanes.c.id == lane_id))
            row = result.first()
            if not row:
                return None

            return Lane(
                id=row.id,
                deployment_profile_id=row.deployment_profile_id,
                name=row.name,
                description=row.description,
                location=row.location,
                device_type=row.device_type,
                default_policy_id=row.default_policy_id,
                metadata=row.metadata or {},
                device_ids=row.device_ids or [],
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list(self, profile_id: str) -> list["Lane"]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(lanes.c.id)
                .where(lanes.c.deployment_profile_id == profile_id)
                .order_by(lanes.c.created_at.asc())
            )
            ids = [row.id for row in result]

        lane_rows: list["Lane"] = []
        for lane_id in ids:
            lane = await self.get(lane_id)
            if lane:
                lane_rows.append(lane)
        return lane_rows

    async def delete(self, lane_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(lanes).where(lanes.c.id == lane_id))
            await session.commit()
