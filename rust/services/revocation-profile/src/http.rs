use crate::{
    CredentialFormat, IssuerRevocationConfig, NewProfile, RevocationAutomationConfig,
    RevocationMechanism, RevocationProfile, RevocationProfileService, RevocationTimingMode,
    ServiceError, VerifierRevocationConfig,
};
use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

const RESOURCE: &str = "revocation-profile";

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

#[derive(Clone)]
pub struct RevocationProfileHttp {
    service: RevocationProfileService,
    authorization: Arc<dyn Authorization>,
}

impl RevocationProfileHttp {
    pub fn new(service: RevocationProfileService, authorization: Arc<dyn Authorization>) -> Self {
        Self {
            service,
            authorization,
        }
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
    Unprocessable(String),
    #[error(transparent)]
    Authorization(AuthorizationError),
    #[error(transparent)]
    Service(#[from] ServiceError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Unauthorized(detail) => (StatusCode::UNAUTHORIZED, detail),
            Self::Unprocessable(detail) => (StatusCode::UNPROCESSABLE_ENTITY, detail),
            Self::Authorization(AuthorizationError::Denied) => (
                StatusCode::FORBIDDEN,
                "Missing required organization permission".into(),
            ),
            Self::Authorization(AuthorizationError::Unavailable(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authorization backend is unavailable".into(),
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
}
