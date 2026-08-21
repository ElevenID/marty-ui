use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileStatus {
    #[default]
    Draft,
    Active,
    Suspended,
    Archived,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentEnvironment {
    #[default]
    Development,
    Staging,
    Production,
    Sandbox,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    #[default]
    ApiKey,
    Oauth2,
    Mtls,
    Jwt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CallbackConfiguration {
    pub issuance_complete_url: Option<String>,
    pub issuance_failed_url: Option<String>,
    pub verification_complete_url: Option<String>,
    pub verification_failed_url: Option<String>,
    pub credential_revoked_url: Option<String>,
    pub signing_key_id: Option<String>,
    pub require_signature_verification: bool,
    pub max_retries: i32,
    pub retry_delay_seconds: i32,
}

impl Default for CallbackConfiguration {
    fn default() -> Self {
        Self {
            issuance_complete_url: None,
            issuance_failed_url: None,
            verification_complete_url: None,
            verification_failed_url: None,
            credential_revoked_url: None,
            signing_key_id: None,
            require_signature_verification: true,
            max_retries: 3,
            retry_delay_seconds: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiAuthConfiguration {
    pub auth_method: AuthMethod,
    pub api_key_header: String,
    pub oauth2_issuer: Option<String>,
    pub oauth2_audience: Option<String>,
    pub oauth2_scopes: Vec<String>,
    pub mtls_ca_certificate: Option<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
}

impl Default for ApiAuthConfiguration {
    fn default() -> Self {
        Self {
            auth_method: AuthMethod::ApiKey,
            api_key_header: "X-API-Key".into(),
            oauth2_issuer: None,
            oauth2_audience: None,
            oauth2_scopes: Vec::new(),
            mtls_ca_certificate: None,
            jwt_issuer: None,
            jwt_audience: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfiguration {
    pub enabled: bool,
    pub requests_per_minute: i32,
    pub requests_per_hour: i32,
    pub requests_per_day: i32,
    pub burst_size: i32,
    pub endpoint_limits: BTreeMap<String, i32>,
}

impl Default for RateLimitConfiguration {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 100,
            requests_per_hour: 1_000,
            requests_per_day: 10_000,
            burst_size: 20,
            endpoint_limits: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeatureFlags {
    pub enable_selective_disclosure: bool,
    pub enable_derived_attributes: bool,
    pub enable_batch_issuance: bool,
    pub enable_deferred_issuance: bool,
    pub enable_credential_refresh: bool,
    pub enable_qr_code_generation: bool,
    pub enable_push_notifications: bool,
    pub enable_biometric_binding: bool,
    pub enable_canvas_evidence: bool,
    pub enable_canvas_lti: bool,
    pub enable_canvas_mirror_publish: bool,
    pub enable_canvas_mirror_ops: bool,
    pub enable_canvas_deep_linking: bool,
    pub enable_canvas_ags: bool,
    pub enable_canvas_nrps: bool,
    pub custom_flags: BTreeMap<String, bool>,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            enable_selective_disclosure: true,
            enable_derived_attributes: true,
            enable_batch_issuance: false,
            enable_deferred_issuance: true,
            enable_credential_refresh: true,
            enable_qr_code_generation: true,
            enable_push_notifications: false,
            enable_biometric_binding: false,
            enable_canvas_evidence: false,
            enable_canvas_lti: false,
            enable_canvas_mirror_publish: false,
            enable_canvas_mirror_ops: false,
            enable_canvas_deep_linking: false,
            enable_canvas_ags: false,
            enable_canvas_nrps: false,
            custom_flags: BTreeMap::new(),
        }
    }
}

impl FeatureFlags {
    #[must_use]
    pub fn canvas_flags(&self) -> BTreeMap<String, bool> {
        BTreeMap::from([
            ("enable_canvas_evidence".into(), self.enable_canvas_evidence),
            ("enable_canvas_lti".into(), self.enable_canvas_lti),
            (
                "enable_canvas_mirror_publish".into(),
                self.enable_canvas_mirror_publish,
            ),
            (
                "enable_canvas_mirror_ops".into(),
                self.enable_canvas_mirror_ops,
            ),
            (
                "enable_canvas_deep_linking".into(),
                self.enable_canvas_deep_linking,
            ),
            ("enable_canvas_ags".into(), self.enable_canvas_ags),
            ("enable_canvas_nrps".into(), self.enable_canvas_nrps),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandingConfiguration {
    pub organization_name: String,
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: String,
    pub secondary_color: String,
    pub custom_css_url: Option<String>,
    pub email_from_name: String,
    pub email_from_address: Option<String>,
    pub custom_domain: Option<String>,
    pub custom_issuer_domain: Option<String>,
    pub qr_size: i32,
    pub qr_foreground_color: String,
    pub qr_background_color: String,
    pub qr_logo_url: Option<String>,
    pub qr_logo_size_percent: i32,
    pub qr_border_color: Option<String>,
    pub qr_border_width: i32,
    pub qr_error_correction: String,
    pub qr_show_instructions: bool,
    pub qr_custom_instruction_text: Option<String>,
}

impl Default for BrandingConfiguration {
    fn default() -> Self {
        Self {
            organization_name: String::new(),
            logo_url: None,
            favicon_url: None,
            primary_color: "#1a1a2e".into(),
            secondary_color: "#4a4a6a".into(),
            custom_css_url: None,
            email_from_name: String::new(),
            email_from_address: None,
            custom_domain: None,
            custom_issuer_domain: None,
            qr_size: 256,
            qr_foreground_color: "#000000".into(),
            qr_background_color: "#FFFFFF".into(),
            qr_logo_url: None,
            qr_logo_size_percent: 20,
            qr_border_color: None,
            qr_border_width: 2,
            qr_error_correction: "H".into(),
            qr_show_instructions: true,
            qr_custom_instruction_text: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeploymentProfile {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: ProfileStatus,
    pub environment: DeploymentEnvironment,
    pub callbacks: CallbackConfiguration,
    pub api_auth: ApiAuthConfiguration,
    pub rate_limits: RateLimitConfiguration,
    pub feature_flags: FeatureFlags,
    pub branding: BrandingConfiguration,
    pub trust_profile_id: Option<String>,
    pub presentation_policy_ids: Vec<String>,
    pub credential_template_ids: Vec<String>,
    pub default_policy_id: Option<String>,
    pub site_id: Option<String>,
    pub network_mode: String,
    pub key_access_mode: String,
    pub environment_config: Map<String, Value>,
    pub update_channel: String,
    pub update_policy: Map<String, Value>,
    pub offline_cache_ttl_hours: i32,
    pub operator_biometric_authentication_required: bool,
    pub audit_all_events: bool,
    pub enabled_flow_ids: Vec<String>,
    pub api_key: Option<String>,
    pub api_key_prefix: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Lane {
    pub id: String,
    pub deployment_profile_id: String,
    pub name: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub device_type: String,
    pub default_policy_id: Option<String>,
    pub metadata: Map<String, Value>,
    pub device_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDeploymentProfileRequest {
    pub organization_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<ProfileStatus>,
    #[serde(default)]
    pub activate_immediately: Option<bool>,
    #[serde(default)]
    pub environment: DeploymentEnvironment,
    #[serde(default)]
    pub trust_profile_id: Option<String>,
    #[serde(default)]
    pub presentation_policy_ids: Vec<String>,
    #[serde(default)]
    pub credential_template_ids: Vec<String>,
    #[serde(default)]
    pub default_policy_id: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default = "online")]
    pub network_mode: String,
    #[serde(default = "key_vault")]
    pub key_access_mode: String,
    #[serde(default)]
    pub environment_config: Option<Map<String, Value>>,
    #[serde(default)]
    pub enabled_flow_ids: Vec<String>,
    #[serde(default = "stable")]
    pub update_channel: String,
    #[serde(default)]
    pub update_policy: Option<Map<String, Value>>,
    #[serde(default = "default_cache_hours")]
    pub offline_cache_ttl_hours: i32,
    #[serde(default, alias = "biometric_required")]
    pub operator_biometric_authentication_required: bool,
    #[serde(default = "yes")]
    pub audit_all_events: bool,
    #[serde(default)]
    pub callbacks: Option<CallbackConfiguration>,
    #[serde(default)]
    pub api_auth: Option<ApiAuthConfiguration>,
    #[serde(default)]
    pub rate_limits: Option<RateLimitConfiguration>,
    #[serde(default)]
    pub feature_flags: Option<FeatureFlags>,
    #[serde(default)]
    pub branding: Option<BrandingConfiguration>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDeploymentProfileRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<ProfileStatus>,
    pub trust_profile_id: Option<String>,
    pub presentation_policy_ids: Option<Vec<String>>,
    pub credential_template_ids: Option<Vec<String>>,
    pub default_policy_id: Option<String>,
    pub network_mode: Option<String>,
    pub key_access_mode: Option<String>,
    #[serde(default, alias = "biometric_required")]
    pub operator_biometric_authentication_required: Option<bool>,
    pub audit_all_events: Option<bool>,
    pub offline_cache_ttl_hours: Option<i32>,
    pub environment_config: Option<Map<String, Value>>,
    pub enabled_flow_ids: Option<Vec<String>>,
    pub update_channel: Option<String>,
    pub update_policy: Option<Map<String, Value>>,
    pub callbacks: Option<CallbackConfiguration>,
    pub api_auth: Option<ApiAuthConfiguration>,
    pub rate_limits: Option<RateLimitConfiguration>,
    pub feature_flags: Option<FeatureFlags>,
    pub branding: Option<BrandingConfiguration>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLaneRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default = "kiosk")]
    pub device_type: String,
    #[serde(default)]
    pub default_policy_id: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateLaneRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    pub device_type: Option<String>,
    pub default_policy_id: Option<String>,
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignDeviceRequest {
    pub device_id: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeploymentProfileResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: ProfileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_profile_id: Option<String>,
    pub presentation_policy_ids: Vec<String>,
    pub credential_template_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy_id: Option<String>,
    pub network_mode: String,
    pub key_access_mode: String,
    pub environment_config: Map<String, Value>,
    pub enabled_flow_ids: Vec<String>,
    pub update_channel: String,
    pub update_policy: Map<String, Value>,
    pub offline_cache_ttl_hours: i32,
    pub operator_biometric_authentication_required: bool,
    pub audit_all_events: bool,
    pub canvas_feature_flags: BTreeMap<String, bool>,
    pub lanes: Vec<LaneResponse>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LaneResponse {
    pub id: String,
    pub name: String,
    pub deployment_profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub device_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy_id: Option<String>,
    pub device_ids: Vec<String>,
    pub metadata: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiKeyResponse {
    pub api_key: String,
    pub api_key_prefix: String,
    pub environment: DeploymentEnvironment,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DeploymentError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Dependency(String),
    #[error("{0}")]
    Persistence(String),
}

impl DeploymentProfile {
    pub fn new(
        request: CreateDeploymentProfileRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, DeploymentError> {
        validate_create(&request)?;
        let policies = stable_dedupe(if request.presentation_policy_ids.is_empty() {
            request.default_policy_id.clone().into_iter().collect()
        } else {
            request.presentation_policy_ids
        });
        validate_policy_binding(
            request.trust_profile_id.as_deref(),
            &policies,
            request.default_policy_id.as_deref(),
        )?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            organization_id: request.organization_id,
            name: request.name,
            description: request.description,
            status: request.status.unwrap_or_else(|| {
                if request.activate_immediately == Some(true) {
                    ProfileStatus::Active
                } else {
                    ProfileStatus::Draft
                }
            }),
            environment: request.environment,
            callbacks: request.callbacks.unwrap_or_default(),
            api_auth: request.api_auth.unwrap_or_default(),
            rate_limits: request.rate_limits.unwrap_or_default(),
            feature_flags: request.feature_flags.unwrap_or_default(),
            branding: request.branding.unwrap_or_default(),
            trust_profile_id: request.trust_profile_id,
            presentation_policy_ids: policies,
            credential_template_ids: stable_dedupe(request.credential_template_ids),
            default_policy_id: request.default_policy_id,
            site_id: request.site_id,
            network_mode: normalize_network_mode(&request.network_mode)?,
            key_access_mode: normalize_key_access_mode(&request.key_access_mode)?,
            environment_config: environment_config(
                request.environment_config,
                Some(request.offline_cache_ttl_hours),
            ),
            update_channel: request.update_channel.clone(),
            update_policy: update_policy(&request.update_channel, request.update_policy),
            offline_cache_ttl_hours: request.offline_cache_ttl_hours,
            operator_biometric_authentication_required: request
                .operator_biometric_authentication_required,
            audit_all_events: request.audit_all_events,
            enabled_flow_ids: stable_dedupe(request.enabled_flow_ids),
            api_key: None,
            api_key_prefix: String::new(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn apply(
        &mut self,
        request: UpdateDeploymentProfileRequest,
        now: DateTime<Utc>,
    ) -> Result<(), DeploymentError> {
        validate_update(&request)?;
        if let Some(value) = request.name {
            self.name = value;
        }
        if let Some(value) = request.description {
            self.description = Some(value);
        }
        if let Some(value) = request.status {
            self.status = value;
        }
        if let Some(value) = request.trust_profile_id {
            self.trust_profile_id = Some(value);
        }
        if let Some(value) = request.presentation_policy_ids {
            self.presentation_policy_ids = stable_dedupe(value);
        }
        if let Some(value) = request.credential_template_ids {
            self.credential_template_ids = stable_dedupe(value);
        }
        if let Some(value) = request.default_policy_id {
            self.default_policy_id = Some(value);
        }
        if let Some(value) = request.network_mode {
            self.network_mode = normalize_network_mode(&value)?;
        }
        if let Some(value) = request.key_access_mode {
            self.key_access_mode = normalize_key_access_mode(&value)?;
        }
        if let Some(value) = request.operator_biometric_authentication_required {
            self.operator_biometric_authentication_required = value;
        }
        if let Some(value) = request.audit_all_events {
            self.audit_all_events = value;
        }
        if let Some(value) = request.offline_cache_ttl_hours {
            self.offline_cache_ttl_hours = value;
        }
        if request.offline_cache_ttl_hours.is_some() || request.environment_config.is_some() {
            self.environment_config = environment_config(
                request
                    .environment_config
                    .or_else(|| Some(self.environment_config.clone())),
                Some(self.offline_cache_ttl_hours),
            );
        }
        if let Some(value) = request.enabled_flow_ids {
            self.enabled_flow_ids = stable_dedupe(value);
        }
        if let Some(value) = request.update_channel {
            self.update_channel = value;
        }
        if request.update_policy.is_some()
            || self.update_policy.get("channel").and_then(Value::as_str)
                != Some(&self.update_channel)
        {
            self.update_policy = update_policy(
                &self.update_channel,
                request
                    .update_policy
                    .or_else(|| Some(self.update_policy.clone())),
            );
        }
        if let Some(value) = request.callbacks {
            self.callbacks = value;
        }
        if let Some(value) = request.api_auth {
            self.api_auth = value;
        }
        if let Some(value) = request.rate_limits {
            self.rate_limits = value;
        }
        if let Some(value) = request.feature_flags {
            self.feature_flags = value;
        }
        if let Some(value) = request.branding {
            self.branding = value;
        }
        validate_policy_binding(
            self.trust_profile_id.as_deref(),
            &self.presentation_policy_ids,
            self.default_policy_id.as_deref(),
        )?;
        self.updated_at = now;
        Ok(())
    }

    pub fn generate_api_key(&mut self) -> ApiKeyResponse {
        let prefix = if self.environment == DeploymentEnvironment::Production {
            "mk_live_"
        } else {
            "mk_test_"
        };
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let token = URL_SAFE_NO_PAD.encode(random);
        let key = format!("{prefix}{token}");
        self.api_key_prefix = format!("{prefix}{}...", &token[..8]);
        self.api_key = Some(key.clone());
        self.updated_at = Utc::now();
        ApiKeyResponse {
            api_key: key,
            api_key_prefix: self.api_key_prefix.clone(),
            environment: self.environment,
        }
    }

    #[must_use]
    pub fn response(&self, lanes: Vec<Lane>) -> DeploymentProfileResponse {
        DeploymentProfileResponse {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            status: self.status,
            site_id: self.site_id.clone(),
            trust_profile_id: self.trust_profile_id.clone(),
            presentation_policy_ids: self.presentation_policy_ids.clone(),
            credential_template_ids: self.credential_template_ids.clone(),
            default_policy_id: self.default_policy_id.clone(),
            network_mode: self.network_mode.clone(),
            key_access_mode: self.key_access_mode.clone(),
            environment_config: self.environment_config.clone(),
            enabled_flow_ids: self.enabled_flow_ids.clone(),
            update_channel: self.update_channel.clone(),
            update_policy: self.update_policy.clone(),
            offline_cache_ttl_hours: self.offline_cache_ttl_hours,
            operator_biometric_authentication_required: self
                .operator_biometric_authentication_required,
            audit_all_events: self.audit_all_events,
            canvas_feature_flags: self.feature_flags.canvas_flags(),
            lanes: lanes.into_iter().map(|lane| lane.response()).collect(),
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
        }
    }
}

impl Lane {
    pub fn new(
        profile_id: &str,
        request: CreateLaneRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, DeploymentError> {
        validate_lane_name(&request.name)?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            deployment_profile_id: profile_id.into(),
            name: request.name,
            description: request.description,
            location: request.location,
            device_type: request.device_type,
            default_policy_id: request.default_policy_id,
            metadata: request.metadata,
            device_ids: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn apply(
        &mut self,
        request: UpdateLaneRequest,
        now: DateTime<Utc>,
    ) -> Result<(), DeploymentError> {
        if let Some(value) = request.name {
            validate_lane_name(&value)?;
            self.name = value;
        }
        if let Some(value) = request.description {
            self.description = Some(value);
        }
        if let Some(value) = request.location {
            self.location = Some(value);
        }
        if let Some(value) = request.device_type {
            self.device_type = value;
        }
        if let Some(value) = request.default_policy_id {
            self.default_policy_id = Some(value);
        }
        if let Some(value) = request.metadata {
            self.metadata = value;
        }
        self.updated_at = now;
        Ok(())
    }

    #[must_use]
    pub fn response(&self) -> LaneResponse {
        LaneResponse {
            id: self.id.clone(),
            name: self.name.clone(),
            deployment_profile_id: self.deployment_profile_id.clone(),
            description: self.description.clone(),
            location: self.location.clone(),
            device_type: self.device_type.clone(),
            default_policy_id: self.default_policy_id.clone(),
            device_ids: self.device_ids.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

fn validate_create(request: &CreateDeploymentProfileRequest) -> Result<(), DeploymentError> {
    validate_text(&request.organization_id, 1, 255, "organization_id")?;
    validate_text(&request.name, 1, 255, "name")?;
    if let Some(value) = &request.description {
        validate_text(value, 0, 2_000, "description")?;
    }
    if !(1..=8_760).contains(&request.offline_cache_ttl_hours) {
        return Err(DeploymentError::BadRequest(
            "offline_cache_ttl_hours is invalid".into(),
        ));
    }
    validate_configuration(&request.callbacks, &request.rate_limits, &request.branding)
}

fn validate_update(request: &UpdateDeploymentProfileRequest) -> Result<(), DeploymentError> {
    if let Some(value) = &request.name {
        validate_text(value, 1, 255, "name")?;
    }
    if let Some(value) = &request.description {
        validate_text(value, 0, 2_000, "description")?;
    }
    if request
        .offline_cache_ttl_hours
        .is_some_and(|value| !(1..=8_760).contains(&value))
    {
        return Err(DeploymentError::BadRequest(
            "offline_cache_ttl_hours is invalid".into(),
        ));
    }
    validate_configuration(&request.callbacks, &request.rate_limits, &request.branding)
}

fn validate_configuration(
    callbacks: &Option<CallbackConfiguration>,
    rate_limits: &Option<RateLimitConfiguration>,
    branding: &Option<BrandingConfiguration>,
) -> Result<(), DeploymentError> {
    if callbacks
        .as_ref()
        .is_some_and(|value| value.max_retries < 0 || value.retry_delay_seconds < 0)
    {
        return Err(DeploymentError::BadRequest(
            "callback retry configuration is invalid".into(),
        ));
    }
    if rate_limits.as_ref().is_some_and(|value| {
        value.requests_per_minute < 0
            || value.requests_per_hour < 0
            || value.requests_per_day < 0
            || value.burst_size < 0
    }) {
        return Err(DeploymentError::BadRequest(
            "rate limit configuration is invalid".into(),
        ));
    }
    if branding.as_ref().is_some_and(|value| {
        !(64..=2_048).contains(&value.qr_size)
            || !(0..=30).contains(&value.qr_logo_size_percent)
            || !(0..=32).contains(&value.qr_border_width)
            || !matches!(value.qr_error_correction.as_str(), "L" | "M" | "Q" | "H")
    }) {
        return Err(DeploymentError::BadRequest(
            "branding QR configuration is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_policy_binding(
    trust: Option<&str>,
    policies: &[String],
    default: Option<&str>,
) -> Result<(), DeploymentError> {
    if trust.is_none_or(str::is_empty) {
        return Err(DeploymentError::BadRequest(
            "trust_profile_id is required".into(),
        ));
    }
    if policies.is_empty() {
        return Err(DeploymentError::BadRequest(
            "presentation_policy_ids must contain at least one policy".into(),
        ));
    }
    if default.is_some_and(|value| !policies.iter().any(|policy| policy == value)) {
        return Err(DeploymentError::BadRequest(
            "default_policy_id must be included in presentation_policy_ids".into(),
        ));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &str,
) -> Result<(), DeploymentError> {
    (minimum..=maximum)
        .contains(&value.len())
        .then_some(())
        .ok_or_else(|| DeploymentError::BadRequest(format!("{field} is invalid")))
}

fn validate_lane_name(value: &str) -> Result<(), DeploymentError> {
    validate_text(value, 1, 255, "name")
}

fn normalize_network_mode(value: &str) -> Result<String, DeploymentError> {
    match value.to_ascii_uppercase().as_str() {
        "ONLINE" | "OFFLINE" | "HYBRID" => Ok(value.to_ascii_uppercase()),
        _ => Err(DeploymentError::BadRequest(
            "network_mode is invalid".into(),
        )),
    }
}

fn normalize_key_access_mode(value: &str) -> Result<String, DeploymentError> {
    match value.to_ascii_uppercase().as_str() {
        "KEY_VAULT" | "HSM" | "DEVICE_KEYSTORE" => Ok(value.to_ascii_uppercase()),
        _ => Err(DeploymentError::BadRequest(
            "key_access_mode is invalid".into(),
        )),
    }
}

fn stable_dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn environment_config(
    value: Option<Map<String, Value>>,
    cache_hours: Option<i32>,
) -> Map<String, Value> {
    let mut merged = Map::from_iter([
        ("language".into(), json!("en-US")),
        ("signage_text".into(), json!({})),
        ("operator_mode".into(), json!(false)),
        ("accessibility_mode".into(), json!(false)),
    ]);
    if let Some(value) = value {
        merged.extend(value.into_iter().filter(|(_, value)| !value.is_null()));
    }
    if !merged.contains_key("offline_cache_ttl_seconds") {
        if let Some(hours) = cache_hours {
            merged.insert("offline_cache_ttl_seconds".into(), json!(hours * 3_600));
        }
    }
    merged
}

fn update_policy(channel: &str, value: Option<Map<String, Value>>) -> Map<String, Value> {
    let mut value = value.unwrap_or_default();
    value.entry("auto_update").or_insert(json!(true));
    value.insert("channel".into(), json!(channel));
    value
}

const fn yes() -> bool {
    true
}
const fn default_cache_hours() -> i32 {
    24
}
fn online() -> String {
    "ONLINE".into()
}
fn key_vault() -> String {
    "KEY_VAULT".into()
}
fn stable() -> String {
    "stable".into()
}
fn kiosk() -> String {
    "kiosk".into()
}
