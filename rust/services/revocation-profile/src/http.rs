use crate::{
    CascadeOperationType, CascadeRevocationOperation, CascadeStatus, CredentialFormat,
    CredentialStatus, InMemoryRevocationOperationRepository, IssuerRevocationConfig, NewProfile,
    OperationError, ProcessRevocation, RevocationAutomationConfig, RevocationBatch,
    RevocationBatchStatus, RevocationMechanism, RevocationOperationRepository, RevocationProfile,
    RevocationProfileService, RevocationTimingMode, ServiceError, StatusListFormat,
    TriggerEntityType, VerifierRevocationConfig,
};
use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};
use subtle::ConstantTimeEq;
use thiserror::Error;

const RESOURCE: &str = "revocation-profile";
const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("membership or required permission was denied")]
    Denied,
    #[error("authorization backend is unavailable: {0}")]
    Unavailable(String),
}

#[async_trait]
pub trait Authorization: Send + Sync {
    async fn require_permission(
        &self,
        user_id: &str,
        organization_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthorizationError>;
}

#[derive(Debug, Clone, Default)]
pub struct InternalServiceAuth {
    expected_token: Option<Arc<str>>,
}

impl InternalServiceAuth {
    pub fn new(expected_token: Option<String>) -> Result<Self, AuthorizationError> {
        let expected_token = match expected_token {
            Some(value) if value.trim().is_empty() => {
                return Err(AuthorizationError::Unavailable(
                    "configured service token is empty".into(),
                ));
            }
            Some(value) => Some(Arc::<str>::from(value.trim())),
            None => None,
        };
        Ok(Self { expected_token })
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let Some(expected) = &self.expected_token else {
            return Ok(());
        };
        let supplied = headers
            .get(SERVICE_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let valid = supplied.len() == expected.len()
            && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()));
        if valid {
            Ok(())
        } else {
            Err(ApiError::Unauthorized(
                "Missing or invalid service token".into(),
            ))
        }
    }
}

#[derive(Clone)]
pub struct RevocationProfileHttp {
    service: RevocationProfileService,
    authorization: Arc<dyn Authorization>,
    internal_auth: InternalServiceAuth,
    operations: Arc<dyn RevocationOperationRepository>,
}

impl RevocationProfileHttp {
    pub fn new(service: RevocationProfileService, authorization: Arc<dyn Authorization>) -> Self {
        Self {
            service,
            authorization,
            internal_auth: InternalServiceAuth::default(),
            operations: Arc::new(InMemoryRevocationOperationRepository::default()),
        }
    }

    pub fn with_internal_service_token(
        mut self,
        expected_token: Option<String>,
    ) -> Result<Self, AuthorizationError> {
        self.internal_auth = InternalServiceAuth::new(expected_token)?;
        Ok(self)
    }

    pub fn with_operation_repository(
        mut self,
        operations: Arc<dyn RevocationOperationRepository>,
    ) -> Self {
        self.operations = operations;
        self
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/v1/revocation-profiles",
                post(create_profile).get(list_profiles),
            )
            .route(
                "/v1/revocation-profiles/{profile_id}",
                get(get_profile).delete(delete_profile),
            )
            .route(
                "/v1/revocation-profiles/{profile_id}/activate",
                post(activate_profile),
            )
            .route(
                "/internal/revocation-profiles/{profile_id}/allocate-index",
                post(allocate_index),
            )
            .route(
                "/internal/revocation-profiles/{profile_id}/reserve-index",
                post(reserve_index),
            )
            .route(
                "/internal/revocation-profiles/{profile_id}/process-revocation",
                post(process_revocation),
            )
            .route(
                "/v1/organizations/{organization_id}/revocation-profiles/{profile_id}/status-lists/{mechanism}/{purpose}",
                get(status_list_document),
            )
            .route(
                "/v1/cascade-revocations",
                post(create_cascade).get(list_cascades),
            )
            .route(
                "/v1/cascade-revocations/{operation_id}",
                get(get_cascade).delete(delete_cascade),
            )
            .route(
                "/v1/cascade-revocations/{operation_id}/confirm",
                post(confirm_cascade),
            )
            .route(
                "/v1/cascade-revocations/{operation_id}/rollback",
                post(rollback_cascade),
            )
            .route(
                "/v1/revocation-batches",
                post(create_batch).get(list_batches),
            )
            .route(
                "/v1/revocation-batches/{batch_id}",
                get(get_batch).delete(delete_batch),
            )
            .route(
                "/v1/revocation-batches/{batch_id}/publish",
                post(publish_batch),
            )
            .with_state(self)
    }

    async fn authorize(
        &self,
        headers: &HeaderMap,
        organization_id: &str,
        action: &str,
    ) -> Result<(), ApiError> {
        let user_id = current_user_id(headers)?;
        self.authorization
            .require_permission(user_id, organization_id, RESOURCE, action)
            .await
            .map_err(ApiError::Authorization)
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IssuerConfigRequest {
    status_list_strategy: crate::StatusListStrategy,
    status_list_base_url: Option<String>,
    status_list_size: usize,
    update_mode: crate::UpdateMode,
    batch_interval_seconds: u32,
    enable_rotation: bool,
    rotation_threshold_percent: u8,
    enable_bitstring_status_list: bool,
    enable_token_status_list: bool,
    enable_legacy_revocation_list: bool,
    auto_allocate_index: Option<bool>,
    batch_update_interval_seconds: Option<u32>,
    list_size: Option<usize>,
    uri_template: Option<String>,
}

impl Default for IssuerConfigRequest {
    fn default() -> Self {
        let defaults = IssuerRevocationConfig::default();
        Self {
            status_list_strategy: defaults.status_list_strategy,
            status_list_base_url: defaults.status_list_base_url,
            status_list_size: defaults.status_list_size,
            update_mode: defaults.update_mode,
            batch_interval_seconds: defaults.batch_interval_seconds,
            enable_rotation: defaults.enable_rotation,
            rotation_threshold_percent: defaults.rotation_threshold_percent,
            enable_bitstring_status_list: defaults.enable_bitstring_status_list,
            enable_token_status_list: defaults.enable_token_status_list,
            enable_legacy_revocation_list: defaults.enable_legacy_revocation_list,
            auto_allocate_index: None,
            batch_update_interval_seconds: None,
            list_size: None,
            uri_template: None,
        }
    }
}

impl IssuerConfigRequest {
    fn into_domain(self) -> (IssuerRevocationConfig, Option<bool>) {
        let auto_allocate_index = self.auto_allocate_index;
        let mut config = IssuerRevocationConfig {
            status_list_strategy: self.status_list_strategy,
            status_list_base_url: self.status_list_base_url,
            status_list_size: self.status_list_size,
            update_mode: self.update_mode,
            batch_interval_seconds: self.batch_interval_seconds,
            enable_rotation: self.enable_rotation,
            rotation_threshold_percent: self.rotation_threshold_percent,
            enable_bitstring_status_list: self.enable_bitstring_status_list,
            enable_token_status_list: self.enable_token_status_list,
            enable_legacy_revocation_list: self.enable_legacy_revocation_list,
        };
        if let Some(value) = self.batch_update_interval_seconds {
            config.batch_interval_seconds = value;
        }
        if let Some(value) = self.list_size {
            config.status_list_size = value;
        }
        if self.uri_template.is_some() {
            config.status_list_base_url = self.uri_template;
        }
        (config, auto_allocate_index)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProfileRequest {
    organization_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    revocation_mechanism: Option<Vec<RevocationMechanism>>,
    #[serde(default)]
    mechanism_priority: Option<Vec<RevocationMechanism>>,
    #[serde(default)]
    check_mode: Option<String>,
    #[serde(default)]
    cache_ttl_seconds: Option<u32>,
    #[serde(default)]
    offline_grace_seconds: Option<u32>,
    #[serde(default)]
    issuer_config: Option<IssuerConfigRequest>,
    #[serde(default)]
    verifier_config: Option<VerifierRevocationConfig>,
    #[serde(default)]
    automation_config: Option<RevocationAutomationConfig>,
    #[serde(default)]
    status_list_url: Option<String>,
    // The legacy public request model accepted this orchestration-only field
    // without persisting it on the profile. Keep that wire compatibility while
    // continuing to reject every other unknown field.
    #[serde(default, rename = "metadata")]
    _metadata: Option<Value>,
    #[serde(default = "default_supported_formats")]
    supported_formats: Vec<CredentialFormat>,
}

fn default_supported_formats() -> Vec<CredentialFormat> {
    vec![
        CredentialFormat::SdJwtVc,
        CredentialFormat::Mdoc,
        CredentialFormat::VcJwt,
    ]
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocateIndexRequest {
    organization_id: String,
    credential_format: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveIndexRequest {
    organization_id: String,
    credential_format: String,
    credential_id: String,
}

#[derive(Debug, Serialize)]
struct AllocateIndexResponse {
    organization_id: String,
    index: usize,
    status_list_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRevocationRequest {
    organization_id: String,
    credential_id: String,
    index: usize,
    status: String,
    #[serde(default)]
    reason: Option<String>,
    credential_format: String,
}

#[derive(Debug, Serialize)]
struct ProcessRevocationResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_list_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCascadeRequest {
    organization_id: String,
    operation_type: CascadeOperationType,
    trigger_entity_type: TriggerEntityType,
    trigger_entity_id: String,
    #[serde(default)]
    affected_credential_count: Option<usize>,
    #[serde(default)]
    affected_credential_ids: Vec<String>,
    #[serde(default)]
    requires_confirmation: Option<bool>,
    #[serde(default = "default_max_cascade_depth")]
    max_cascade_depth: u8,
    #[serde(default)]
    current_depth: u8,
    #[serde(default = "default_circuit_breaker_threshold")]
    circuit_breaker_threshold: usize,
    #[serde(default)]
    can_rollback: bool,
    #[serde(default)]
    rollback_snapshot: Option<Value>,
    #[serde(default)]
    metadata: Option<Value>,
}

fn default_max_cascade_depth() -> u8 {
    3
}

fn default_circuit_breaker_threshold() -> usize {
    1_000
}

#[derive(Debug, Deserialize)]
struct CascadeListQuery {
    organization_id: String,
    #[serde(default)]
    status: Option<CascadeStatus>,
}

#[derive(Debug, Serialize)]
struct CascadeResponse {
    id: String,
    organization_id: String,
    operation_type: CascadeOperationType,
    trigger_entity_type: TriggerEntityType,
    trigger_entity_id: String,
    status: CascadeStatus,
    affected_credential_count: usize,
    affected_credential_ids: Vec<String>,
    requires_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_by: Option<String>,
    max_cascade_depth: u8,
    current_depth: u8,
    circuit_breaker_threshold: usize,
    circuit_breaker_triggered: bool,
    can_rollback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_snapshot: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rolled_back_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rolled_back_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
    created_at: String,
    updated_at: String,
}

impl From<CascadeRevocationOperation> for CascadeResponse {
    fn from(value: CascadeRevocationOperation) -> Self {
        Self {
            id: value.id,
            organization_id: value.organization_id,
            operation_type: value.operation_type,
            trigger_entity_type: value.trigger_entity_type,
            trigger_entity_id: value.trigger_entity_id,
            status: value.status,
            affected_credential_count: value.affected_credential_count,
            affected_credential_ids: value.affected_credential_ids,
            requires_confirmation: value.requires_confirmation,
            confirmed_at: value
                .confirmed_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
            confirmed_by: value.confirmed_by,
            max_cascade_depth: value.max_cascade_depth,
            current_depth: value.current_depth,
            circuit_breaker_threshold: value.circuit_breaker_threshold,
            circuit_breaker_triggered: value.circuit_breaker_triggered,
            can_rollback: value.can_rollback,
            rollback_snapshot: value.rollback_snapshot,
            rolled_back_at: value
                .rolled_back_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
            rolled_back_by: value.rolled_back_by,
            error_message: value.error_message,
            metadata: value.metadata,
            created_at: value
                .created_at
                .to_rfc3339_opts(SecondsFormat::AutoSi, false),
            updated_at: value
                .updated_at
                .to_rfc3339_opts(SecondsFormat::AutoSi, false),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBatchRequest {
    organization_id: String,
    revocation_profile_id: String,
    #[serde(default = "default_batch_interval")]
    batch_interval: String,
    #[serde(default = "default_credential_format")]
    credential_format: String,
    #[serde(default)]
    credential_ids: Vec<String>,
}

fn default_batch_interval() -> String {
    "1h".into()
}

fn default_credential_format() -> String {
    "SD_JWT_VC".into()
}

#[derive(Debug, Deserialize)]
struct BatchListQuery {
    organization_id: String,
    #[serde(default)]
    status: Option<RevocationBatchStatus>,
}

#[derive(Debug, Serialize)]
struct BatchResponse {
    id: String,
    organization_id: String,
    revocation_profile_id: String,
    batch_interval: String,
    credential_format: String,
    credential_count: usize,
    status: RevocationBatchStatus,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_at: Option<String>,
}

impl From<RevocationBatch> for BatchResponse {
    fn from(value: RevocationBatch) -> Self {
        Self {
            id: value.id,
            organization_id: value.organization_id,
            revocation_profile_id: value.revocation_profile_id,
            batch_interval: value.batch_interval,
            credential_format: value.credential_format,
            credential_count: value.credential_ids.len(),
            status: value.status,
            created_at: value
                .created_at
                .to_rfc3339_opts(SecondsFormat::AutoSi, false),
            published_at: value
                .published_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
        }
    }
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
struct IssuerConfigResponse {
    auto_allocate_index: bool,
    batch_update_interval_seconds: u32,
    list_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_template: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfileResponse {
    id: String,
    organization_id: String,
    name: String,
    status: String,
    revocation_mechanism: Vec<String>,
    mechanism_priority: Vec<String>,
    check_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_ttl_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offline_grace_seconds: Option<u32>,
    issuer_config: IssuerConfigResponse,
    status_list_url: String,
    created_at: String,
    updated_at: String,
}

impl ProfileResponse {
    fn from_profile(service: &RevocationProfileService, profile: RevocationProfile) -> Self {
        let mut mechanisms = Vec::new();
        if profile.issuer_config.enable_legacy_revocation_list {
            mechanisms.push(RevocationMechanism::LegacyRevocationList);
        }
        if profile.issuer_config.enable_bitstring_status_list {
            mechanisms.push(RevocationMechanism::BitstringStatusList);
        }
        if profile.issuer_config.enable_token_status_list {
            mechanisms.push(RevocationMechanism::TokenStatusList);
        }
        mechanisms.extend(profile.verifier_config.mechanism_priority.iter().copied());
        let mut seen = HashSet::new();
        mechanisms.retain(|mechanism| seen.insert(*mechanism));
        if mechanisms.is_empty() {
            mechanisms.push(RevocationMechanism::BitstringStatusList);
        }

        let timing_mode = profile.verifier_config.timing_mode;
        Self {
            id: profile.id.clone(),
            organization_id: profile.organization_id.clone(),
            name: profile.name.clone(),
            status: profile.status.as_str().to_ascii_uppercase(),
            revocation_mechanism: mechanisms
                .into_iter()
                .map(|mechanism| mechanism.as_str().to_string())
                .collect(),
            mechanism_priority: profile
                .verifier_config
                .mechanism_priority
                .iter()
                .map(|mechanism| mechanism.as_str().to_string())
                .collect(),
            check_mode: timing_mode.as_str().to_string(),
            cache_ttl_seconds: (timing_mode == RevocationTimingMode::Cached)
                .then_some(profile.verifier_config.cache_ttl_seconds),
            offline_grace_seconds: (timing_mode == RevocationTimingMode::OfflineGrace)
                .then_some(profile.verifier_config.offline_grace_seconds),
            issuer_config: IssuerConfigResponse {
                auto_allocate_index: profile.automation_config.auto_allocate_indices,
                batch_update_interval_seconds: profile.issuer_config.batch_interval_seconds,
                list_size: profile.issuer_config.status_list_size,
                uri_template: profile.issuer_config.status_list_base_url.clone(),
            },
            status_list_url: service.status_list_url_template(&profile),
            created_at: profile
                .created_at
                .to_rfc3339_opts(SecondsFormat::AutoSi, false),
            updated_at: profile
                .updated_at
                .to_rfc3339_opts(SecondsFormat::AutoSi, false),
        }
    }
}

async fn create_profile(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Json(request): Json<CreateProfileRequest>,
) -> Result<Json<ProfileResponse>, ApiError> {
    state
        .authorize(&headers, &request.organization_id, "create")
        .await?;
    validate_create_request(&request)?;

    let mut verifier_config = request.verifier_config.unwrap_or_default();
    let mut automation_config = request.automation_config.unwrap_or_default();
    let (mut issuer_config, auto_allocate_index) = request
        .issuer_config
        .map(IssuerConfigRequest::into_domain)
        .unwrap_or_else(|| (IssuerRevocationConfig::default(), None));

    if let Some(value) = auto_allocate_index {
        automation_config.auto_allocate_indices = value;
    }
    if let Some(value) = request.status_list_url {
        issuer_config.status_list_base_url = Some(value);
    }
    if let Some(mechanisms) = request.revocation_mechanism {
        issuer_config.enable_legacy_revocation_list =
            mechanisms.contains(&RevocationMechanism::LegacyRevocationList);
        issuer_config.enable_bitstring_status_list =
            mechanisms.contains(&RevocationMechanism::BitstringStatusList);
        issuer_config.enable_token_status_list =
            mechanisms.contains(&RevocationMechanism::TokenStatusList);
        if request.mechanism_priority.is_none() {
            verifier_config.mechanism_priority = mechanisms;
        }
    }
    if let Some(priority) = request.mechanism_priority {
        verifier_config.mechanism_priority = priority;
    }
    if let Some(mode) = request.check_mode {
        verifier_config.timing_mode = parse_timing_mode(&mode)?;
    }
    if let Some(value) = request.cache_ttl_seconds {
        verifier_config.cache_ttl_seconds = value;
    }
    if let Some(value) = request.offline_grace_seconds {
        verifier_config.offline_grace_seconds = value;
    }

    let profile = state
        .service
        .create(NewProfile {
            organization_id: request.organization_id,
            name: request.name,
            description: request.description,
            issuer_config: Some(issuer_config),
            verifier_config: Some(verifier_config),
            automation_config: Some(automation_config),
            supported_formats: Some(request.supported_formats),
        })
        .await?;
    Ok(Json(ProfileResponse::from_profile(&state.service, profile)))
}

async fn list_profiles(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ProfileResponse>>, ApiError> {
    if query.limit > 500 {
        return Err(ApiError::Unprocessable("limit must not exceed 500".into()));
    }
    state
        .authorize(&headers, &query.organization_id, "view")
        .await?;
    let profiles = state.service.list(&query.organization_id).await?;
    Ok(Json(
        profiles
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .map(|profile| ProfileResponse::from_profile(&state.service, profile))
            .collect(),
    ))
}

async fn get_profile(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ProfileResponse>, ApiError> {
    let profile = state.service.get(&profile_id).await?;
    state
        .authorize(&headers, &profile.organization_id, "view")
        .await?;
    Ok(Json(ProfileResponse::from_profile(&state.service, profile)))
}

async fn activate_profile(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ProfileResponse>, ApiError> {
    let profile = state.service.get(&profile_id).await?;
    state
        .authorize(&headers, &profile.organization_id, "activate")
        .await?;
    let profile = state.service.activate(&profile_id).await?;
    Ok(Json(ProfileResponse::from_profile(&state.service, profile)))
}

async fn delete_profile(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let profile = state.service.get(&profile_id).await?;
    state
        .authorize(&headers, &profile.organization_id, "delete")
        .await?;
    state.service.delete(&profile_id).await?;
    Ok(Json(json!({"success": true})))
}

async fn allocate_index(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AllocateIndexRequest>,
) -> Result<Json<AllocateIndexResponse>, ApiError> {
    state.internal_auth.authorize(&headers)?;
    let result = state
        .service
        .allocate_index(
            &profile_id,
            &request.organization_id,
            &request.credential_format,
        )
        .await?;
    Ok(Json(AllocateIndexResponse {
        organization_id: result.organization_id,
        index: result.index,
        status_list_url: result.status_list_url,
    }))
}

async fn reserve_index(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ReserveIndexRequest>,
) -> Result<Json<AllocateIndexResponse>, ApiError> {
    state.internal_auth.authorize(&headers)?;
    let result = state
        .service
        .reserve_index(
            &profile_id,
            &request.organization_id,
            &request.credential_format,
            &request.credential_id,
        )
        .await?;
    Ok(Json(AllocateIndexResponse {
        organization_id: result.organization_id,
        index: result.index,
        status_list_url: result.status_list_url,
    }))
}

async fn process_revocation(
    State(state): State<RevocationProfileHttp>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProcessRevocationRequest>,
) -> Result<Json<ProcessRevocationResponse>, ApiError> {
    state.internal_auth.authorize(&headers)?;
    let _reason = request.reason;
    let status = match request.status.as_str() {
        "revoked" => CredentialStatus::Revoked,
        "suspended" => CredentialStatus::Suspended,
        "reinstated" => CredentialStatus::Reinstated,
        other => {
            return Ok(Json(ProcessRevocationResponse {
                success: false,
                organization_id: None,
                status_list_url: None,
                index: None,
                error: Some(format!("Unknown status: {other}")),
            }));
        }
    };
    let operation = ProcessRevocation {
        profile_id: profile_id.clone(),
        organization_id: request.organization_id,
        credential_id: request.credential_id,
        index: request.index,
        status,
        credential_format: request.credential_format,
    };
    match state.service.process_revocation(operation).await {
        Ok(result) => Ok(Json(ProcessRevocationResponse {
            success: true,
            organization_id: Some(result.organization_id),
            status_list_url: Some(result.status_list_url),
            index: Some(result.index),
            error: None,
        })),
        Err(ServiceError::PermissionDenied) => {
            Err(ApiError::Service(ServiceError::PermissionDenied))
        }
        Err(ServiceError::NotFound(_)) => Ok(Json(ProcessRevocationResponse {
            success: false,
            organization_id: None,
            status_list_url: None,
            index: None,
            error: Some(format!("RevocationProfile {profile_id} not found")),
        })),
        Err(ServiceError::FailedPrecondition(detail)) => {
            let detail = detail
                .strip_prefix("revocation profile is not active")
                .map(|suffix| format!("RevocationProfile {profile_id} is not active{suffix}"))
                .unwrap_or(detail);
            Ok(Json(ProcessRevocationResponse {
                success: false,
                organization_id: None,
                status_list_url: None,
                index: None,
                error: Some(detail),
            }))
        }
        Err(_) => Ok(Json(ProcessRevocationResponse {
            success: false,
            organization_id: None,
            status_list_url: None,
            index: None,
            error: Some("Revocation processing failed".into()),
        })),
    }
}

async fn status_list_document(
    State(state): State<RevocationProfileHttp>,
    Path((organization_id, profile_id, mechanism, purpose)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    if !matches!(purpose.as_str(), "revocation" | "suspension") {
        return Err(ApiError::BadRequest(
            "purpose must be revocation or suspension".into(),
        ));
    }
    let format = match mechanism.trim().to_ascii_lowercase().as_str() {
        "bitstring" | "bitstring-status-list" | "bitstring_status_list" => {
            StatusListFormat::Bitstring
        }
        "token" | "token-status-list" | "token_status_list" => StatusListFormat::TokenStatusList,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported status list mechanism: {mechanism}"
            )));
        }
    };
    let profile = state.service.get(&profile_id).await?;
    if profile.organization_id != organization_id {
        return Err(ApiError::NotFound("RevocationProfile not found".into()));
    }
    let record = state
        .service
        .status_list(&profile_id, &organization_id, format)
        .await?;
    let canonical_url = state
        .service
        .status_list_url_for(&profile, format, &purpose);
    let issuer = format!("did:example:org:{organization_id}");
    let payload = match format {
        StatusListFormat::Bitstring => {
            let subject = record
                .bitstring_credential_subject(format!("{canonical_url}#list"), &purpose)
                .map_err(ServiceError::from)?;
            json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": canonical_url,
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": issuer,
                "validFrom": record.created_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
                "credentialSubject": subject,
            })
        }
        StatusListFormat::TokenStatusList => {
            let claim = record.token_claim().map_err(ServiceError::from)?;
            json!({
                "iss": issuer,
                "sub": canonical_url,
                "iat": chrono::Utc::now().timestamp(),
                "status_list": claim,
            })
        }
    };
    let content_type = if format == StatusListFormat::Bitstring {
        "application/vc+ld+json"
    } else {
        "application/json"
    };
    let mut response = Json(payload).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(response)
}

async fn create_cascade(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Json(request): Json<CreateCascadeRequest>,
) -> Result<Json<CascadeResponse>, ApiError> {
    state
        .authorize(&headers, &request.organization_id, "activate")
        .await?;
    if !(1..=10).contains(&request.max_cascade_depth) {
        return Err(ApiError::Unprocessable(
            "max_cascade_depth must be between 1 and 10".into(),
        ));
    }
    if request.current_depth > request.max_cascade_depth {
        return Err(ApiError::Unprocessable(
            "current_depth must be between 0 and max_cascade_depth".into(),
        ));
    }
    if request.circuit_breaker_threshold == 0 {
        return Err(ApiError::Unprocessable(
            "circuit_breaker_threshold must be at least 1".into(),
        ));
    }
    let affected_credential_count = request
        .affected_credential_count
        .unwrap_or(request.affected_credential_ids.len());
    let circuit_breaker_triggered = affected_credential_count >= request.circuit_breaker_threshold;
    let requires_confirmation =
        request.requires_confirmation.unwrap_or(false) || circuit_breaker_triggered;
    let rollback_snapshot = if request.can_rollback && request.rollback_snapshot.is_none() {
        Some(json!({
            "affected_credential_ids": request.affected_credential_ids,
            "affected_credential_count": affected_credential_count,
            "trigger_entity_id": request.trigger_entity_id,
        }))
    } else {
        request.rollback_snapshot
    };
    let now = crate::domain::utc_now();
    let mut operation = CascadeRevocationOperation {
        id: uuid::Uuid::new_v4().to_string(),
        organization_id: request.organization_id,
        operation_type: request.operation_type,
        trigger_entity_type: request.trigger_entity_type,
        trigger_entity_id: request.trigger_entity_id,
        status: if requires_confirmation {
            CascadeStatus::PendingConfirmation
        } else {
            CascadeStatus::InProgress
        },
        affected_credential_count,
        affected_credential_ids: request.affected_credential_ids,
        requires_confirmation,
        confirmed_at: None,
        confirmed_by: None,
        max_cascade_depth: request.max_cascade_depth,
        current_depth: request.current_depth,
        circuit_breaker_threshold: request.circuit_breaker_threshold,
        circuit_breaker_triggered,
        can_rollback: request.can_rollback,
        rollback_snapshot,
        rolled_back_at: None,
        rolled_back_by: None,
        error_message: None,
        metadata: request.metadata,
        created_at: now,
        updated_at: now,
        completed_at: None,
    };
    if !requires_confirmation {
        operation.status = CascadeStatus::Completed;
        operation.completed_at = Some(now);
    }
    state
        .operations
        .save_cascade(operation.clone())
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(operation.into()))
}

async fn list_cascades(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Query(query): Query<CascadeListQuery>,
) -> Result<Json<Vec<CascadeResponse>>, ApiError> {
    state
        .authorize(&headers, &query.organization_id, "view")
        .await?;
    let values = state
        .operations
        .list_cascades(&query.organization_id, query.status)
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(values.into_iter().map(Into::into).collect()))
}

async fn get_cascade(
    State(state): State<RevocationProfileHttp>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CascadeResponse>, ApiError> {
    let operation = get_cascade_operation(&state, &operation_id).await?;
    state
        .authorize(&headers, &operation.organization_id, "view")
        .await?;
    Ok(Json(operation.into()))
}

async fn confirm_cascade(
    State(state): State<RevocationProfileHttp>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CascadeResponse>, ApiError> {
    let mut operation = get_cascade_operation(&state, &operation_id).await?;
    let user_id = current_user_id(&headers)?.to_string();
    state
        .authorize(&headers, &operation.organization_id, "activate")
        .await?;
    operation.confirm(&user_id).map_err(ApiError::Operation)?;
    state
        .operations
        .save_cascade(operation.clone())
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(operation.into()))
}

async fn rollback_cascade(
    State(state): State<RevocationProfileHttp>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CascadeResponse>, ApiError> {
    let mut operation = get_cascade_operation(&state, &operation_id).await?;
    let user_id = current_user_id(&headers)?.to_string();
    state
        .authorize(&headers, &operation.organization_id, "activate")
        .await?;
    operation.rollback(&user_id).map_err(ApiError::Operation)?;
    state
        .operations
        .save_cascade(operation.clone())
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(operation.into()))
}

async fn delete_cascade(
    State(state): State<RevocationProfileHttp>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let operation = get_cascade_operation(&state, &operation_id).await?;
    state
        .authorize(&headers, &operation.organization_id, "activate")
        .await?;
    if operation.status != CascadeStatus::PendingConfirmation {
        return Err(ApiError::BadRequest(
            "Only pending cascade operations can be cancelled".into(),
        ));
    }
    state
        .operations
        .delete_cascade(&operation_id)
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(json!({"success": true})))
}

async fn get_cascade_operation(
    state: &RevocationProfileHttp,
    operation_id: &str,
) -> Result<CascadeRevocationOperation, ApiError> {
    state
        .operations
        .get_cascade(operation_id)
        .await
        .map_err(ApiError::Operation)?
        .ok_or_else(|| ApiError::NotFound("CascadeRevocationOperation not found".into()))
}

async fn create_batch(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Json(request): Json<CreateBatchRequest>,
) -> Result<(StatusCode, Json<BatchResponse>), ApiError> {
    let profile = state.service.get(&request.revocation_profile_id).await?;
    if profile.organization_id != request.organization_id {
        return Err(ApiError::Service(ServiceError::PermissionDenied));
    }
    state
        .authorize(&headers, &request.organization_id, "activate")
        .await?;
    let batch = RevocationBatch::new(
        request.organization_id,
        request.revocation_profile_id,
        request.batch_interval,
        request.credential_format,
        request.credential_ids,
    )
    .map_err(ApiError::Operation)?;
    state
        .operations
        .save_batch(batch.clone())
        .await
        .map_err(ApiError::Operation)?;
    Ok((StatusCode::CREATED, Json(batch.into())))
}

async fn list_batches(
    State(state): State<RevocationProfileHttp>,
    headers: HeaderMap,
    Query(query): Query<BatchListQuery>,
) -> Result<Json<Vec<BatchResponse>>, ApiError> {
    state
        .authorize(&headers, &query.organization_id, "view")
        .await?;
    let values = state
        .operations
        .list_batches(Some(&query.organization_id), query.status)
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(values.into_iter().map(Into::into).collect()))
}

async fn get_batch(
    State(state): State<RevocationProfileHttp>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<BatchResponse>, ApiError> {
    let batch = get_batch_operation(&state, &batch_id).await?;
    state
        .authorize(&headers, &batch.organization_id, "view")
        .await?;
    Ok(Json(batch.into()))
}

async fn publish_batch(
    State(state): State<RevocationProfileHttp>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<BatchResponse>, ApiError> {
    let mut batch = get_batch_operation(&state, &batch_id).await?;
    state
        .authorize(&headers, &batch.organization_id, "activate")
        .await?;
    batch.publish().map_err(ApiError::Operation)?;
    state
        .operations
        .save_batch(batch.clone())
        .await
        .map_err(ApiError::Operation)?;
    Ok(Json(batch.into()))
}

async fn delete_batch(
    State(state): State<RevocationProfileHttp>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let batch = get_batch_operation(&state, &batch_id).await?;
    state
        .authorize(&headers, &batch.organization_id, "activate")
        .await?;
    if batch.status != RevocationBatchStatus::Pending {
        return Err(ApiError::BadRequest(
            "Can only delete PENDING batches".into(),
        ));
    }
    state
        .operations
        .delete_batch(&batch_id)
        .await
        .map_err(ApiError::Operation)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_batch_operation(
    state: &RevocationProfileHttp,
    batch_id: &str,
) -> Result<RevocationBatch, ApiError> {
    state
        .operations
        .get_batch(batch_id)
        .await
        .map_err(ApiError::Operation)?
        .ok_or_else(|| ApiError::NotFound("Revocation batch not found".into()))
}

fn validate_create_request(request: &CreateProfileRequest) -> Result<(), ApiError> {
    if request.organization_id.is_empty() || request.organization_id.len() > 255 {
        return Err(ApiError::Unprocessable(
            "organization_id must contain between 1 and 255 characters".into(),
        ));
    }
    if request.name.is_empty() || request.name.len() > 255 {
        return Err(ApiError::Unprocessable(
            "name must contain between 1 and 255 characters".into(),
        ));
    }
    if request
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 2_000)
    {
        return Err(ApiError::Unprocessable(
            "description must not exceed 2000 characters".into(),
        ));
    }
    if request
        .revocation_mechanism
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        return Err(ApiError::Unprocessable(
            "revocation_mechanism must contain at least one mechanism".into(),
        ));
    }
    let protocol_timing = request.check_mode.as_deref().map(str::to_ascii_uppercase);
    if protocol_timing.as_deref() == Some("CACHED") && request.cache_ttl_seconds.is_none() {
        return Err(ApiError::Unprocessable(
            "cache_ttl_seconds is required when timing_mode is CACHED".into(),
        ));
    }
    if protocol_timing.as_deref() == Some("OFFLINE_GRACE")
        && request.offline_grace_seconds.is_none()
    {
        return Err(ApiError::Unprocessable(
            "offline_grace_seconds is required when timing_mode is OFFLINE_GRACE".into(),
        ));
    }
    let status_url = request.status_list_url.as_deref().or_else(|| {
        request
            .issuer_config
            .as_ref()
            .and_then(|config| config.uri_template.as_deref())
    });
    if let Some(url) = status_url {
        if !url.trim().starts_with("https://") {
            return Err(ApiError::Unprocessable(format!(
                "status_list_url must be an absolute HTTPS URI, got: {url}"
            )));
        }
    }
    Ok(())
}

fn parse_timing_mode(value: &str) -> Result<RevocationTimingMode, ApiError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "ALWAYS" => Ok(RevocationTimingMode::Always),
        "CACHED" => Ok(RevocationTimingMode::Cached),
        "OFFLINE_GRACE" => Ok(RevocationTimingMode::OfflineGrace),
        "DISABLED" => Ok(RevocationTimingMode::Disabled),
        _ => Err(ApiError::Unprocessable(format!(
            "unsupported revocation timing mode: {value}"
        ))),
    }
}

fn current_user_id(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::Unauthorized("Authentication required - missing user context".into())
        })
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Unprocessable(String),
    #[error(transparent)]
    Authorization(AuthorizationError),
    #[error(transparent)]
    Operation(#[from] OperationError),
    #[error(transparent)]
    Service(#[from] ServiceError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Unauthorized(detail) => (StatusCode::UNAUTHORIZED, detail),
            Self::BadRequest(detail) => (StatusCode::BAD_REQUEST, detail),
            Self::NotFound(detail) => (StatusCode::NOT_FOUND, detail),
            Self::Unprocessable(detail) => (StatusCode::UNPROCESSABLE_ENTITY, detail),
            Self::Authorization(AuthorizationError::Denied) => (
                StatusCode::FORBIDDEN,
                "Missing required organization permission".into(),
            ),
            Self::Authorization(AuthorizationError::Unavailable(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authorization backend is unavailable".into(),
            ),
            Self::Operation(OperationError::InvalidArgument(detail))
            | Self::Operation(OperationError::InvalidTransition(detail)) => {
                (StatusCode::BAD_REQUEST, detail)
            }
            Self::Operation(OperationError::NotFound) => (
                StatusCode::NOT_FOUND,
                "Revocation operation not found".into(),
            ),
            Self::Operation(OperationError::PermissionDenied) => (
                StatusCode::FORBIDDEN,
                "Revocation operation belongs to another organization".into(),
            ),
            Self::Operation(OperationError::CircuitBreaker) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Batch contains 1000+ credentials. Use confirm endpoint after review.".into(),
            ),
            Self::Operation(OperationError::Storage(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Revocation operation storage is unavailable".into(),
            ),
            Self::Service(ServiceError::InvalidArgument(detail)) => {
                (StatusCode::UNPROCESSABLE_ENTITY, detail)
            }
            Self::Service(ServiceError::NotFound(_)) => {
                (StatusCode::NOT_FOUND, "RevocationProfile not found".into())
            }
            Self::Service(ServiceError::PermissionDenied) => (
                StatusCode::FORBIDDEN,
                "Revocation Profile belongs to another organization".into(),
            ),
            Self::Service(ServiceError::FailedPrecondition(detail)) => {
                (StatusCode::BAD_REQUEST, detail)
            }
            Self::Service(ServiceError::Storage(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Revocation profile storage is unavailable".into(),
            ),
            Self::Service(ServiceError::Native(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Native status backend is unavailable".into(),
            ),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryProfileRepository, InMemoryStatusRepository};
    use axum::{body::Body, http::Request};
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct RecordingAuthorization {
        calls: Mutex<Vec<(String, String, String)>>,
        denied: bool,
    }

    #[async_trait]
    impl Authorization for RecordingAuthorization {
        async fn require_permission(
            &self,
            user_id: &str,
            organization_id: &str,
            _resource: &str,
            action: &str,
        ) -> Result<(), AuthorizationError> {
            self.calls.lock().unwrap().push((
                user_id.to_string(),
                organization_id.to_string(),
                action.to_string(),
            ));
            if self.denied {
                Err(AuthorizationError::Denied)
            } else {
                Ok(())
            }
        }
    }

    fn app(authorization: Arc<RecordingAuthorization>) -> Router {
        let service = RevocationProfileService::new(
            Arc::new(InMemoryProfileRepository::default()),
            Arc::new(InMemoryStatusRepository::default()),
            "https://status.example.com",
        )
        .unwrap();
        RevocationProfileHttp::new(service, authorization).router()
    }

    async fn json_response(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn profile_crud_preserves_protocol_shape_and_permissions() {
        let authorization = Arc::new(RecordingAuthorization::default());
        let app = app(authorization.clone());
        let create = Request::builder()
            .method("POST")
            .uri("/v1/revocation-profiles")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({
                    "organization_id": "org-1",
                    "name": "Canonical revocation profile",
                    "revocation_mechanism": ["OCSP", "BITSTRING_STATUS_LIST"],
                    "mechanism_priority": ["OCSP", "BITSTRING_STATUS_LIST"],
                    "check_mode": "OFFLINE_GRACE",
                    "offline_grace_seconds": 7200,
                    "metadata": {"source": "public-client-contract"},
                    "issuer_config": {
                        "auto_allocate_index": true,
                        "batch_update_interval_seconds": 600,
                        "list_size": 131072,
                        "uri_template": "https://status.example.com/tenant-a"
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_response(response).await;
        let profile_id = body["id"].as_str().unwrap();
        assert_eq!(body["status"], "DRAFT");
        assert_eq!(body["check_mode"], "OFFLINE_GRACE");
        assert_eq!(body["offline_grace_seconds"], 7200);
        assert_eq!(
            body["issuer_config"],
            json!({
                "auto_allocate_index": true,
                "batch_update_interval_seconds": 600,
                "list_size": 131072,
                "uri_template": "https://status.example.com/tenant-a"
            })
        );
        assert_eq!(
            body["status_list_url"],
            format!(
                "https://status.example.com/tenant-a/v1/organizations/org-1/revocation-profiles/{profile_id}/status-lists/{{mechanism}}/{{purpose}}"
            )
        );
        assert!(body.get("description").is_none());
        assert!(body.get("verifier_config").is_none());

        let activate = Request::builder()
            .method("POST")
            .uri(format!("/v1/revocation-profiles/{profile_id}/activate"))
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(activate).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await["status"], "ACTIVE");

        let delete = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/revocation-profiles/{profile_id}"))
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(delete).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await, json!({"success": true}));

        assert_eq!(
            *authorization.calls.lock().unwrap(),
            vec![
                ("user-1".into(), "org-1".into(), "create".into()),
                ("user-1".into(), "org-1".into(), "activate".into()),
                ("user-1".into(), "org-1".into(), "delete".into()),
            ]
        );
    }

    #[tokio::test]
    async fn missing_identity_and_denied_membership_fail_closed() {
        let authorization = Arc::new(RecordingAuthorization::default());
        let request = Request::builder()
            .method("GET")
            .uri("/v1/revocation-profiles?organization_id=org-1")
            .body(Body::empty())
            .unwrap();
        let response = app(authorization).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_response(response).await,
            json!({"detail": "Authentication required - missing user context"})
        );

        let authorization = Arc::new(RecordingAuthorization {
            denied: true,
            ..Default::default()
        });
        let request = Request::builder()
            .method("GET")
            .uri("/v1/revocation-profiles?organization_id=org-1")
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        let response = app(authorization).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn malformed_protocol_inputs_are_rejected() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/revocation-profiles")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({
                    "organization_id": "org-1",
                    "name": "invalid",
                    "revocation_mechanism": [],
                    "status_list_url": "http://status.example.com"
                })
                .to_string(),
            ))
            .unwrap();
        let response = app(Arc::new(RecordingAuthorization::default()))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            json_response(response).await,
            json!({"detail": "revocation_mechanism must contain at least one mechanism"})
        );
    }

    #[tokio::test]
    async fn internal_lifecycle_requires_service_token_and_public_document_is_canonical() {
        let authorization = Arc::new(RecordingAuthorization::default());
        let service = RevocationProfileService::new(
            Arc::new(InMemoryProfileRepository::default()),
            Arc::new(InMemoryStatusRepository::default()),
            "https://status.example.com",
        )
        .unwrap();
        let token = "s".repeat(48);
        let app = RevocationProfileHttp::new(service, authorization)
            .with_internal_service_token(Some(token.clone()))
            .unwrap()
            .router();

        let create = Request::builder()
            .method("POST")
            .uri("/v1/revocation-profiles")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({"organization_id": "org-1", "name": "status profile"}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(create).await.unwrap();
        let body = json_response(response).await;
        let profile_id = body["id"].as_str().unwrap().to_string();

        let allocate_uri = format!("/internal/revocation-profiles/{profile_id}/allocate-index");
        let allocation_body = json!({
            "organization_id": "org-1",
            "credential_format": "sd_jwt_vc"
        })
        .to_string();
        let unauthorized = Request::builder()
            .method("POST")
            .uri(&allocate_uri)
            .header("content-type", "application/json")
            .body(Body::from(allocation_body.clone()))
            .unwrap();
        let response = app.clone().oneshot(unauthorized).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_response(response).await,
            json!({"detail": "Missing or invalid service token"})
        );

        let allocate = Request::builder()
            .method("POST")
            .uri(&allocate_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(allocation_body.clone()))
            .unwrap();
        let response = app.clone().oneshot(allocate).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let allocation = json_response(response).await;
        assert_eq!(allocation["index"], 0);

        let reserve_uri = format!("/internal/revocation-profiles/{profile_id}/reserve-index");
        let reservation_body = json!({
            "organization_id": "org-1",
            "credential_format": "sd_jwt_vc",
            "credential_id": "credential-1"
        })
        .to_string();
        let reserve = Request::builder()
            .method("POST")
            .uri(&reserve_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(reservation_body.clone()))
            .unwrap();
        let response = app.clone().oneshot(reserve).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await["index"], 1);

        let retry = Request::builder()
            .method("POST")
            .uri(&reserve_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(reservation_body))
            .unwrap();
        let response = app.clone().oneshot(retry).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await["index"], 1);

        let missing_credential_id = Request::builder()
            .method("POST")
            .uri(&reserve_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(
                json!({
                    "organization_id": "org-1",
                    "credential_format": "sd_jwt_vc"
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(missing_credential_id)
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let process_uri = format!("/internal/revocation-profiles/{profile_id}/process-revocation");
        let process_body = json!({
            "organization_id": "org-1",
            "credential_id": "credential-1",
            "index": 0,
            "status": "revoked",
            "credential_format": "sd_jwt_vc"
        })
        .to_string();
        let inactive = Request::builder()
            .method("POST")
            .uri(&process_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(process_body.clone()))
            .unwrap();
        let response = app.clone().oneshot(inactive).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_response(response).await["error"],
            format!("RevocationProfile {profile_id} is not active (status: draft)")
        );

        let activate = Request::builder()
            .method("POST")
            .uri(format!("/v1/revocation-profiles/{profile_id}/activate"))
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(activate).await.unwrap().status(),
            StatusCode::OK
        );

        let process = Request::builder()
            .method("POST")
            .uri(process_uri)
            .header("content-type", "application/json")
            .header(SERVICE_TOKEN_HEADER, &token)
            .body(Body::from(process_body))
            .unwrap();
        let response = app.clone().oneshot(process).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_response(response).await["success"], true);

        let document_uri = format!(
            "/v1/organizations/org-1/revocation-profiles/{profile_id}/status-lists/bitstring-status-list/revocation"
        );
        let document = Request::builder()
            .uri(document_uri)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(document).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/vc+ld+json"
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=300"
        );
        let body = json_response(response).await;
        assert_eq!(body["credentialSubject"]["statusPurpose"], "revocation");
        assert!(body["credentialSubject"]["encodedList"]
            .as_str()
            .unwrap()
            .starts_with('u'));

        let cross_tenant = Request::builder()
            .uri(format!(
                "/v1/organizations/org-2/revocation-profiles/{profile_id}/status-lists/bitstring-status-list/revocation"
            ))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(cross_tenant).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cascade_and_batch_routes_preserve_state_and_tenant_rules() {
        let authorization = Arc::new(RecordingAuthorization::default());
        let app = app(authorization.clone());
        let cascade = Request::builder()
            .method("POST")
            .uri("/v1/cascade-revocations")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({
                    "organization_id": "org-1", "operation_type": "ISSUER_REVOCATION",
                    "trigger_entity_type": "ISSUER", "trigger_entity_id": "issuer-1",
                    "affected_credential_count": 1500, "affected_credential_ids": ["cred-1"],
                    "circuit_breaker_threshold": 1000, "can_rollback": true
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(cascade).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_response(response).await;
        let operation_id = body["id"].as_str().unwrap();
        assert_eq!(body["status"], "PENDING_CONFIRMATION");
        assert_eq!(body["circuit_breaker_triggered"], true);
        assert_eq!(body["rollback_snapshot"]["affected_credential_count"], 1500);

        let confirm = Request::builder()
            .method("POST")
            .uri(format!("/v1/cascade-revocations/{operation_id}/confirm"))
            .header("x-user-id", "admin-1")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(confirm).await.unwrap();
        assert_eq!(json_response(response).await["status"], "COMPLETED");

        let create_profile = Request::builder()
            .method("POST")
            .uri("/v1/revocation-profiles")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({"organization_id": "org-1", "name": "batch profile"}).to_string(),
            ))
            .unwrap();
        let profile = json_response(app.clone().oneshot(create_profile).await.unwrap()).await;
        let profile_id = profile["id"].as_str().unwrap();
        let create_batch = Request::builder()
            .method("POST")
            .uri("/v1/revocation-batches")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1")
            .body(Body::from(
                json!({
                    "organization_id": "org-1", "revocation_profile_id": profile_id,
                    "batch_interval": "1h", "credential_ids": ["cred-1"]
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(create_batch).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let batch = json_response(response).await;
        let batch_id = batch["id"].as_str().unwrap();
        assert_eq!(batch["credential_count"], 1);
        assert_eq!(batch["status"], "PENDING");
        let publish = Request::builder()
            .method("POST")
            .uri(format!("/v1/revocation-batches/{batch_id}/publish"))
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(publish).await.unwrap();
        assert_eq!(json_response(response).await["status"], "PUBLISHED");
        let delete = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/revocation-batches/{batch_id}"))
            .header("x-user-id", "user-1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(delete).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
