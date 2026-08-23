use crate::{
    service::{ApplicantService, Identity, ServiceError},
    Applicant, ApplicantError, Application, Biometric, Evidence, EvidenceStatus, EvidenceUpload,
    ReviewerLock, VettingCheck, LOCK_TTL_SECONDS, MAX_EVIDENCE_BYTES,
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path as FilePath, sync::Arc};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<ApplicantService>,
    pub issuance_url: String,
    pub issuance_api_key: Option<String>,
    pub client: Client,
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/me/applicant-profile", get(get_profile).patch(upsert_profile))
        .route("/v1/me/applicant-profile/biometrics", post(enroll_biometric))
        .route("/v1/me/applications", get(my_applications).post(create_application))
        .route("/v1/issued-credentials/mine", get(issued_credentials))
        .route("/v1/me/applications/{application_id}", get(my_application))
        .route(
            "/v1/me/applications/{application_id}/evidence",
            get(my_evidence_list).post(upload_evidence),
        )
        .route(
            "/v1/me/applications/{application_id}/evidence/{evidence_id}",
            get(my_evidence).delete(delete_my_evidence),
        )
        .route(
            "/v1/me/applications/{application_id}/evidence/{evidence_id}/content",
            get(my_evidence_content),
        )
        .route("/v1/me/applications/{application_id}/submit", post(submit))
        .route("/v1/me/applications/{application_id}/withdraw", post(withdraw_self))
        .route("/v1/me/applications/{application_id}/claim", post(claim))
        .route(
            "/v1/organizations/{organization_id}/applicants",
            get(organization_queue),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}",
            get(organization_application),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence",
            get(organization_evidence_list),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence/{evidence_id}",
            get(organization_evidence),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence/{evidence_id}/content",
            get(organization_evidence_content),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence/{evidence_id}/revoke",
            post(revoke_evidence),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/lock",
            get(lock_status).post(acquire_lock).delete(release_lock),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/approve",
            post(approve),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/reject",
            post(reject),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/request-information",
            post(request_information),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/checks",
            get(checks),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/start",
            post(start_check),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/complete",
            post(complete_check),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/issue",
            post(issue),
        )
        .route(
            "/v1/organizations/{organization_id}/applicants/{application_id}/withdraw",
            post(withdraw_organization),
        )
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    detail: Value,
}

impl ApiError {
    fn new(status: StatusCode, detail: impl Into<Value>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"detail": self.detail}))).into_response()
    }
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        let status = match &error {
            ServiceError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            ServiceError::NotAuthorized | ServiceError::TenantMismatch => StatusCode::FORBIDDEN,
            ServiceError::ApplicantNotFound
            | ServiceError::ApplicationNotFound
            | ServiceError::CheckNotFound
            | ServiceError::EvidenceNotFound => StatusCode::NOT_FOUND,
            ServiceError::DuplicateApplication(_)
            | ServiceError::ApplicantIdentityConflict
            | ServiceError::ReviewerLockRequired
            | ServiceError::ConcurrentModification
            | ServiceError::InvalidApplicationState(_)
            | ServiceError::InactiveEvidence
            | ServiceError::NoActiveFlow => StatusCode::CONFLICT,
            ServiceError::Provider(_) => StatusCode::SERVICE_UNAVAILABLE,
            ServiceError::Domain(ApplicantError::EvidenceSize { .. }) => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };
        let detail = match error {
            ServiceError::Domain(ApplicantError::FieldValidation(errors)) => json!({
                "error": "FIELD_VALIDATION_FAILED",
                "message": "Application data failed validation.",
                "field_errors": errors,
            }),
            ServiceError::RequiredEvidence(id) => json!({
                "error": "EVIDENCE_VALIDATION_FAILED",
                "message": "Application evidence failed validation.",
                "evidence_errors": [{
                    "evidence_requirement_id": id,
                    "code": "REQUIRED_EVIDENCE_MISSING_OR_INVALID",
                    "message": "Required evidence is missing, stale, revoked, or invalid."
                }]
            }),
            ServiceError::DuplicateApplication(reference) => json!({
                "error": "ACTIVE_APPLICATION_EXISTS",
                "message": "An active application already exists.",
                "reference_number": reference,
            }),
            other => Value::String(other.to_string()),
        };
        Self { status, detail }
    }
}

#[derive(Debug, Default, Deserialize)]
struct Page {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    status: Option<String>,
}

const fn default_limit() -> usize {
    100
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRequest {
    email: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    phone: Option<String>,
    vetting_data: Option<Value>,
    vetting_data_patch: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApplicationRequest {
    organization_id: String,
    application_template_id: String,
    #[serde(default)]
    form_data: Map<String, Value>,
    #[serde(default)]
    integration_context: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BiometricRequest {
    #[serde(default = "default_biometric_type")]
    biometric_type: String,
    template_data_base64: String,
    image_data_base64: Option<String>,
    #[serde(default = "default_true")]
    is_live_capture: bool,
    capture_device_id: Option<String>,
}

fn default_biometric_type() -> String {
    "FACIAL".into()
}
const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRequest {
    evidence_requirement_id: String,
    media_type: String,
    filename: String,
    content_base64: String,
    captured_at: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawRequest {
    reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRequest {
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectRequest {
    reason: String,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestInformationRequest {
    #[serde(default)]
    missing_items: Vec<String>,
    #[serde(default)]
    message: String,
    deadline: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteCheckRequest {
    passed: bool,
    notes: Option<String>,
    #[serde(default)]
    result: Map<String, Value>,
    #[serde(default)]
    evidence_submission_ids: Vec<String>,
}

fn header(headers: &HeaderMap, name: &'static str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn user(headers: &HeaderMap) -> Result<String, ApiError> {
    let user = header(headers, "x-user-id");
    if user.is_empty() {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Authentication required",
        ))
    } else {
        Ok(user)
    }
}

fn identity(headers: &HeaderMap) -> Result<Identity, ApiError> {
    let identity = Identity {
        user_id: user(headers)?,
        organization_id: header(headers, "x-organization-id"),
    };
    if identity.organization_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Authenticated organization context is required",
        ));
    }
    Ok(identity)
}

fn organization_identity(
    headers: &HeaderMap,
    organization_id: &str,
    permission: &str,
) -> Result<String, ApiError> {
    let user = user(headers)?;
    let header_org = header(headers, "x-organization-id");
    let permissions = header(headers, "x-org-permissions")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if header_org != organization_id || !permissions.contains(permission) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Action not authorized",
        ));
    }
    Ok(user)
}

async fn get_profile(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(applicant_json(
        &state.service.profile(&identity(&headers)?).await?,
    )))
}

async fn upsert_profile(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ProfileRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = identity(&headers)?;
    let current = state.service.profile(&identity).await.ok();
    let email = body
        .email
        .or_else(|| current.as_ref().map(|value| value.email.clone()))
        .or_else(|| {
            let value = header(&headers, "x-user-email");
            (!value.is_empty()).then_some(value)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "email is required when creating a profile",
            )
        })?;
    let mut applicant = state
        .service
        .upsert_profile(
            &identity,
            &email,
            body.given_name,
            body.family_name,
            body.phone,
            Utc::now(),
        )
        .await?;
    if let Some(vetting_data) = body.vetting_data {
        applicant = state
            .service
            .set_profile_vetting_data(&applicant.id, vetting_data, Utc::now())
            .await?;
    }
    if let Some(vetting_data_patch) = body.vetting_data_patch {
        applicant = state
            .service
            .patch_profile_vetting_data(&applicant.id, &vetting_data_patch, Utc::now())
            .await?;
    }
    Ok(Json(applicant_json(&applicant)))
}

async fn enroll_biometric(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BiometricRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = identity(&headers)?;
    let profile = state.service.profile(&identity).await?;
    if !matches!(
        body.biometric_type.as_str(),
        "FACIAL" | "FINGERPRINT" | "IRIS" | "VOICE" | "SIGNATURE"
    ) || STANDARD.decode(&body.template_data_base64).is_err()
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Biometric payload is invalid",
        ));
    }
    let biometric = state
        .service
        .enroll_biometric(
            &identity,
            Biometric {
                id: String::new(),
                applicant_id: profile.id,
                biometric_type: body.biometric_type,
                template_data_base64: body.template_data_base64,
                image_data_base64: body.image_data_base64,
                is_live_capture: body.is_live_capture,
                capture_device_id: body.capture_device_id,
                created_at: Utc::now(),
            },
        )
        .await?;
    Ok(Json(biometric_json(&biometric)))
}

async fn my_applications(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    let mut applications = state
        .service
        .applications_for_user(&user(&headers)?)
        .await?;
    for application in &mut applications {
        *application = sync_issuance(&state, application).await?;
    }
    Ok(Json(page_values(
        applications.iter().map(application_json).collect(),
        &page,
    )))
}

async fn create_application(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateApplicationRequest>,
) -> Result<Json<Value>, ApiError> {
    let application = state
        .service
        .create_application(
            &identity(&headers)?,
            &body.organization_id,
            &body.application_template_id,
            body.form_data,
            body.integration_context,
            Utc::now(),
        )
        .await?;
    Ok(Json(application_json(&application)))
}

async fn my_application(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (application, applicant) = state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    let application = sync_issuance(&state, &application).await?;
    Ok(Json(enriched_application_json(&application, &applicant)))
}

async fn upload_evidence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
    Json(body): Json<EvidenceRequest>,
) -> Result<Json<Value>, ApiError> {
    let user = user(&headers)?;
    let (application, applicant) = state
        .service
        .self_application(&user, &application_id)
        .await?;
    let requirement = application
        .evidence_requirements
        .iter()
        .find(|value| {
            value.get("evidence_id").and_then(Value::as_str)
                == Some(body.evidence_requirement_id.as_str())
        })
        .ok_or(ServiceError::EvidenceRequirementNotFound)?;
    let evidence_type = requirement
        .get("evidence_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !matches!(
        evidence_type.as_str(),
        "DOCUMENT_SCAN" | "BIOMETRIC" | "SELFIE" | "THIRD_PARTY_VERIFICATION"
    ) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "This requirement must be satisfied by its verified external evidence source",
        ));
    }
    let media_type = body.media_type.trim().to_ascii_lowercase();
    let media_pattern = Regex::new(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
        .expect("static media type expression");
    if !media_pattern.is_match(&media_type) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Evidence media type is invalid",
        ));
    }
    let accepted = requirement
        .get("accepted_formats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !accepted.is_empty() {
        let suffix = FilePath::new(&body.filename)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{value}").to_ascii_lowercase())
            .unwrap_or_default();
        let accepted = accepted.iter().filter_map(Value::as_str).any(|value| {
            let value = value.trim().to_ascii_lowercase();
            value == media_type
                || (!value.contains('/')
                    && suffix
                        == if value.starts_with('.') {
                            value
                        } else {
                            format!(".{value}")
                        })
        });
        if !accepted {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Evidence format is not accepted",
            ));
        }
    }
    let maximum = requirement
        .get("max_file_size_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(MAX_EVIDENCE_BYTES)
        .min(MAX_EVIDENCE_BYTES);
    let captured_at = body
        .captured_at
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Evidence captured_at must be an ISO 8601 date-time",
            )
        })?
        .map(|value| value.with_timezone(&Utc));
    let expires_at = evidence_expiry(requirement, captured_at)?;
    let evidence = state
        .service
        .upload_evidence(
            EvidenceUpload {
                application_id: application.id,
                applicant_id: applicant.id,
                organization_id: application.organization_id,
                evidence_requirement_id: body.evidence_requirement_id,
                evidence_type,
                media_type,
                filename: body.filename,
                content_base64: body.content_base64,
                submitted_by: user,
                captured_at,
                expires_at,
            },
            maximum,
            Utc::now(),
        )
        .await?;
    Ok(Json(evidence_json(&evidence, false)))
}

async fn my_evidence_list(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    Ok(Json(Value::Array(
        state
            .service
            .evidence_for_application(&application_id)
            .await
            .iter()
            .map(|value| evidence_json(value, false))
            .collect(),
    )))
}

async fn my_evidence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((application_id, evidence_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    Ok(Json(evidence_json(
        &state
            .service
            .evidence(&application_id, &evidence_id, Utc::now())
            .await?,
        false,
    )))
}

async fn my_evidence_content(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((application_id, evidence_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    evidence_content(
        state
            .service
            .evidence(&application_id, &evidence_id, Utc::now())
            .await?,
    )
}

async fn delete_my_evidence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((application_id, evidence_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    state
        .service
        .delete_evidence(&application_id, &evidence_id, Utc::now())
        .await?;
    Ok(Json(json!({"deleted": true})))
}

async fn submit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    Ok(Json(application_json(
        &state.service.submit(&application_id, Utc::now()).await?,
    )))
}

async fn withdraw_self(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
    body: Option<Json<WithdrawRequest>>,
) -> Result<Json<Value>, ApiError> {
    state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    Ok(Json(application_json(
        &state
            .service
            .withdraw(
                &application_id,
                body.and_then(|Json(value)| value.reason),
                Utc::now(),
            )
            .await?,
    )))
}

async fn claim(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(application_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (application, _) = state
        .service
        .self_application(&user(&headers)?, &application_id)
        .await?;
    let application = sync_issuance(&state, &application).await?;
    let has_offer = application
        .system_data
        .get("credential_offer_uri")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        || application
            .system_data
            .get("credential_offer_uris")
            .and_then(Value::as_object)
            .is_some_and(|value| !value.is_empty());
    let valid_expiry = application
        .system_data
        .get("offer_expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expiry| expiry > Utc::now());
    if application.claim_state == crate::ClaimState::OfferReady && has_offer && valid_expiry {
        return Ok(Json(application_json(&application)));
    }
    Ok(Json(application_json(
        &state.service.issue(&application_id, Utc::now()).await?,
    )))
}

async fn organization_queue(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    let mut values = state
        .service
        .applications_for_organization(&organization_id)
        .await;
    if let Some(expected) = &page.status {
        values.retain(|application| {
            serde_json::to_value(application.status)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .is_some_and(|status| status.eq_ignore_ascii_case(expected))
        });
    }
    Ok(Json(page_values(
        values.iter().map(application_json).collect(),
        &page,
    )))
}

async fn organization_application(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    let (application, applicant) = state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(enriched_application_json(&application, &applicant)))
}

async fn organization_evidence_list(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(Value::Array(
        state
            .service
            .evidence_for_application(&application_id)
            .await
            .iter()
            .map(|value| evidence_json(value, true))
            .collect(),
    )))
}

async fn organization_evidence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id, evidence_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(evidence_json(
        &state
            .service
            .evidence(&application_id, &evidence_id, Utc::now())
            .await?,
        true,
    )))
}

async fn organization_evidence_content(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id, evidence_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    evidence_content(
        state
            .service
            .evidence(&application_id, &evidence_id, Utc::now())
            .await?,
    )
}

async fn revoke_evidence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id, evidence_id)): Path<(String, String, String)>,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(evidence_json(
        &state
            .service
            .revoke_evidence(&application_id, &evidence_id, body.reason, Utc::now())
            .await?,
        true,
    )))
}

async fn acquire_lock(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let user = organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    let name = {
        let value = header(&headers, "x-user-email");
        if value.is_empty() {
            user.clone()
        } else {
            value
        }
    };
    let lock = state
        .service
        .acquire_lock(&application_id, &user, &name, Utc::now())
        .await?;
    Ok(Json(lock_json(
        Some(&lock),
        &organization_id,
        &application_id,
    )))
}

async fn lock_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    let lock = state.service.lock_status(&application_id, Utc::now()).await;
    Ok(Json(lock_json(
        lock.as_ref(),
        &organization_id,
        &application_id,
    )))
}

async fn release_lock(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let user = organization_identity(&headers, &organization_id, "application:review")?;
    if !state
        .service
        .release_lock(&application_id, &user, Utc::now())
        .await
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Only the lock holder may release this lock",
        ));
    }
    Ok(Json(json!({"released": true})))
}

async fn approve(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<Value>, ApiError> {
    let reviewer = organization_identity(&headers, &organization_id, "application:approve")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(application_json(
        &state
            .service
            .review(
                &application_id,
                &reviewer,
                true,
                body.notes,
                None,
                Utc::now(),
            )
            .await?,
    )))
}

async fn reject(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
    Json(body): Json<RejectRequest>,
) -> Result<Json<Value>, ApiError> {
    let reviewer = organization_identity(&headers, &organization_id, "application:reject")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(application_json(
        &state
            .service
            .review(
                &application_id,
                &reviewer,
                false,
                body.notes,
                Some(body.reason),
                Utc::now(),
            )
            .await?,
    )))
}

async fn request_information(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
    Json(body): Json<RequestInformationRequest>,
) -> Result<Json<Value>, ApiError> {
    let reviewer = organization_identity(&headers, &organization_id, "application:review")?;
    require_lock(&state, &application_id, &reviewer).await?;
    Ok(Json(application_json(
        &state
            .service
            .request_information(
                &application_id,
                body.missing_items,
                body.message,
                body.deadline,
                Utc::now(),
            )
            .await?,
    )))
}

async fn checks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(Value::Array(
        state
            .service
            .checks(&application_id)
            .await
            .iter()
            .map(check_json)
            .collect(),
    )))
}

async fn start_check(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id, check_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let reviewer = organization_identity(&headers, &organization_id, "application:review")?;
    require_lock(&state, &application_id, &reviewer).await?;
    Ok(Json(check_json(
        &state
            .service
            .start_check(&application_id, &check_id, Utc::now())
            .await?,
    )))
}

async fn complete_check(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id, check_id)): Path<(String, String, String)>,
    Json(body): Json<CompleteCheckRequest>,
) -> Result<Json<Value>, ApiError> {
    let reviewer = organization_identity(&headers, &organization_id, "application:review")?;
    require_lock(&state, &application_id, &reviewer).await?;
    let mut result = body.result;
    if let Some(notes) = body.notes {
        result.insert("notes".into(), Value::String(notes));
    }
    Ok(Json(check_json(
        &state
            .service
            .complete_check(
                &check_id,
                body.passed,
                Some(reviewer),
                result,
                body.evidence_submission_ids,
                Utc::now(),
            )
            .await?,
    )))
}

async fn issue(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "issuance:initiate")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(application_json(
        &state.service.issue(&application_id, Utc::now()).await?,
    )))
}

async fn withdraw_organization(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((organization_id, application_id)): Path<(String, String)>,
    body: Option<Json<WithdrawRequest>>,
) -> Result<Json<Value>, ApiError> {
    organization_identity(&headers, &organization_id, "application:review")?;
    state
        .service
        .organization_application(&organization_id, &application_id)
        .await?;
    Ok(Json(application_json(
        &state
            .service
            .withdraw_by_organization(
                &application_id,
                body.and_then(|Json(value)| value.reason),
                Utc::now(),
            )
            .await?,
    )))
}

async fn issued_credentials(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    let profiles = state.service.profiles_for_user(&user(&headers)?).await?;
    let mut records = Vec::new();
    for profile in profiles {
        let mut url = reqwest::Url::parse(&format!(
            "{}/v1/issued-credentials",
            state.issuance_url.trim_end_matches('/')
        ))
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Credential inventory endpoint is invalid",
            )
        })?;
        url.query_pairs_mut()
            .append_pair("organization_id", &profile.organization_id)
            .append_pair("subject_id", &profile.id)
            .append_pair("limit", "500");
        let mut request = state.client.get(url);
        request = request.header("x-organization-id", &profile.organization_id);
        if let Some(api_key) = &state.issuance_api_key {
            request = request.header("x-api-key", api_key);
        }
        let response = request.send().await.map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Credential inventory is temporarily unavailable",
            )
        })?;
        if !response.status().is_success() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Credential inventory is temporarily unavailable",
            ));
        }
        let body = response.json::<Value>().await.map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Credential inventory response is malformed",
            )
        })?;
        let values = body
            .as_array()
            .or_else(|| body.get("items").and_then(Value::as_array))
            .or_else(|| body.get("credentials").and_then(Value::as_array));
        records.extend(
            values
                .into_iter()
                .flatten()
                .filter(|value| {
                    value.get("subject_id").and_then(Value::as_str) == Some(profile.id.as_str())
                })
                .cloned(),
        );
    }
    if let Some(expected) = &page.status {
        records.retain(|value| {
            value
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status.eq_ignore_ascii_case(expected))
        });
    }
    records.sort_by_key(|value| {
        std::cmp::Reverse(
            value
                .get("issued_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )
    });
    Ok(Json(page_values(records, &page)))
}

async fn sync_issuance(
    state: &HttpState,
    application: &Application,
) -> Result<Application, ApiError> {
    let transaction_id = application
        .system_data
        .get("issuance_transaction_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.starts_with("local-"));
    let Some(transaction_id) = transaction_id else {
        return state
            .service
            .reconcile_issuance(&application.id, None, None, Utc::now())
            .await
            .map_err(Into::into);
    };
    let mut request = state.client.get(format!(
        "{}/v1/issuance/transactions/{transaction_id}",
        state.issuance_url.trim_end_matches('/')
    ));
    request = request.header("x-organization-id", &application.organization_id);
    if let Some(api_key) = &state.issuance_api_key {
        request = request.header("x-api-key", api_key);
    }
    let response = request.send().await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuance transaction reconciliation is temporarily unavailable",
        )
    })?;
    if response.status() == StatusCode::NOT_FOUND {
        return state
            .service
            .reconcile_issuance(&application.id, None, None, Utc::now())
            .await
            .map_err(Into::into);
    }
    if !response.status().is_success() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuance transaction reconciliation is temporarily unavailable",
        ));
    }
    let transaction = response.json::<Value>().await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuance transaction response is malformed",
        )
    })?;
    let status = transaction.get("status").and_then(Value::as_str);
    let issued_at = transaction
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    state
        .service
        .reconcile_issuance(&application.id, status, issued_at, Utc::now())
        .await
        .map_err(Into::into)
}

async fn require_lock(
    state: &HttpState,
    application_id: &str,
    reviewer: &str,
) -> Result<(), ApiError> {
    if state
        .service
        .lock_status(application_id, Utc::now())
        .await
        .is_some_and(|lock| lock.reviewer_id == reviewer)
    {
        Ok(())
    } else {
        Err(ServiceError::ReviewerLockRequired.into())
    }
}

fn evidence_expiry(
    requirement: &Value,
    captured_at: Option<DateTime<Utc>>,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let freshness = requirement.get("freshness").and_then(Value::as_object);
    let seconds = freshness
        .and_then(|value| value.get("max_age_seconds"))
        .and_then(Value::as_f64)
        .or_else(|| {
            freshness
                .and_then(|value| value.get("max_age_days"))
                .and_then(Value::as_f64)
                .map(|days| days * 86_400.0)
        });
    let Some(seconds) = seconds else {
        return Ok(None);
    };
    if seconds <= 0.0 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Evidence freshness policy is invalid",
        ));
    }
    let captured_at = captured_at.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Fresh evidence requires captured_at",
        )
    })?;
    if captured_at > Utc::now() + chrono::Duration::minutes(5) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Evidence captured_at cannot be in the future",
        ));
    }
    let expiry = captured_at + chrono::Duration::milliseconds((seconds * 1000.0) as i64);
    if expiry <= Utc::now() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Evidence is stale",
        ));
    }
    Ok(Some(expiry))
}

fn page_values(values: Vec<Value>, page: &Page) -> Value {
    let limit = page.limit.clamp(1, 500);
    let total = values.len();
    let items = values
        .into_iter()
        .skip(page.offset)
        .take(limit)
        .collect::<Vec<_>>();
    json!({"items": items, "total": total, "limit": limit, "offset": page.offset})
}

fn applicant_json(value: &Applicant) -> Value {
    json!({
        "id": value.id,
        "organization_id": value.organization_id,
        "flow_id": value.flow_id,
        "credential_template_id": value.credential_template_id,
        "user_id": value.user_id,
        "external_id": value.external_id,
        "given_name": value.given_name,
        "family_name": value.family_name,
        "email": value.email,
        "phone": value.phone,
        "status": value.status,
        "rejection_reason": value.rejection_reason,
        "application_data": value.vetting_data,
        "vetting_checks": value.verification_results,
        "created_at": value.created_at.to_rfc3339(),
        "updated_at": value.updated_at.to_rfc3339(),
    })
}

fn application_json(value: &Application) -> Value {
    json!({
        "id": value.id,
        "applicant_id": value.applicant_id,
        "organization_id": value.organization_id,
        "reference_number": value.reference_number,
        "application_template_id": value.application_template_id,
        "credential_template_id": value.credential_template_id,
        "form_data": value.form_data,
        "integration_context": value.integration_context,
        "status": value.status,
        "claim_state": value.claim_state,
        "claim_blocker": value.claim_blocker,
        "created_at": value.created_at.to_rfc3339(),
        "submitted_at": value.submitted_at.map(|date| date.to_rfc3339()),
        "reviewed_at": value.reviewed_at.map(|date| date.to_rfc3339()),
        "issued_at": value.issued_at.map(|date| date.to_rfc3339()),
        "updated_at": value.updated_at.to_rfc3339(),
        "credential_display_name": value.system_data.get("credential_display_name"),
        "credential_offer_uri": value.system_data.get("credential_offer_uri"),
        "offer_expires_at": value.system_data.get("offer_expires_at"),
        "credential_offer_uris": value.system_data.get("credential_offer_uris").cloned().unwrap_or_else(|| json!({})),
        "credential_offer_labels": value.system_data.get("credential_offer_labels").cloned().unwrap_or_else(|| json!({})),
    })
}

fn enriched_application_json(application: &Application, applicant: &Applicant) -> Value {
    let mut value = application_json(application);
    if let Some(object) = value.as_object_mut() {
        object.insert("applicant_email".into(), json!(applicant.email));
        object.insert("applicant_given_name".into(), json!(applicant.given_name));
        object.insert("applicant_family_name".into(), json!(applicant.family_name));
        object.insert("applicant_phone".into(), json!(applicant.phone));
        object.insert("applicant_status".into(), json!(applicant.status));
        object.insert(
            "applicant_vetting_level".into(),
            applicant
                .vetting_data
                .get("vetting_level")
                .cloned()
                .unwrap_or_else(|| json!("basic")),
        );
        object.insert(
            "verification_results".into(),
            json!(applicant.verification_results),
        );
    }
    value
}

fn evidence_json(value: &Evidence, reviewer: bool) -> Value {
    let base = if reviewer {
        format!(
            "/v1/organizations/{}/applicants/{}/evidence/{}",
            value.organization_id, value.application_id, value.id
        )
    } else {
        format!(
            "/v1/me/applications/{}/evidence/{}",
            value.application_id, value.id
        )
    };
    json!({
        "id": value.id,
        "organization_id": value.organization_id,
        "application_id": value.application_id,
        "evidence_requirement_id": value.evidence_requirement_id,
        "evidence_type": value.evidence_type,
        "source": value.source,
        "media_type": value.media_type,
        "filename": value.filename,
        "size_bytes": value.size_bytes,
        "sha256": value.sha256,
        "status": value.status,
        "submitted_by": value.submitted_by,
        "captured_at": value.captured_at.map(|date| date.to_rfc3339()),
        "expires_at": value.expires_at.map(|date| date.to_rfc3339()),
        "revoked_at": value.revoked_at.map(|date| date.to_rfc3339()),
        "revocation_reason": value.revocation_reason,
        "content_url": format!("{base}/content"),
        "created_at": value.created_at.to_rfc3339(),
        "updated_at": value.updated_at.to_rfc3339(),
    })
}

fn biometric_json(value: &Biometric) -> Value {
    json!({
        "id": value.id,
        "applicant_id": value.applicant_id,
        "modality": value.biometric_type,
        "template_hash": format!("{:x}", Sha256::digest(value.template_data_base64.as_bytes())),
        "hash_algorithm": "sha-256",
        "capture_device": value.capture_device_id,
        "liveness_verified": value.is_live_capture,
        "status": "ACTIVE",
        "created_at": value.created_at.to_rfc3339(),
    })
}

fn check_json(value: &VettingCheck) -> Value {
    json!({
        "id": value.id,
        "check_type": value.check_type,
        "provider": value.external_provider,
        "status": value.status,
        "performed_by": value.performed_by,
        "started_at": value.started_at.map(|date| date.to_rfc3339()),
        "completed_at": value.completed_at.map(|date| date.to_rfc3339()),
        "raw_result": value.result,
        "evidence_refs": value.result.get("evidence_submission_ids"),
        "created_at": value.created_at.to_rfc3339(),
        "updated_at": value.updated_at.to_rfc3339(),
    })
}

fn lock_json(lock: Option<&ReviewerLock>, organization_id: &str, application_id: &str) -> Value {
    json!({
        "id": lock.map(|value| &value.id),
        "applicant_id": application_id,
        "organization_id": organization_id,
        "holder_user_id": lock.map(|value| &value.reviewer_id),
        "ttl_seconds": LOCK_TTL_SECONDS,
        "expires_at": lock.map(|value| value.expires_at.to_rfc3339()),
        "status": if lock.is_some() { "ACTIVE" } else { "AVAILABLE" },
        "created_at": lock.map(|value| value.acquired_at.to_rfc3339()),
    })
}

fn evidence_content(evidence: Evidence) -> Result<Response, ApiError> {
    if evidence.status != EvidenceStatus::Active {
        return Err(ApiError::new(
            StatusCode::GONE,
            "Application evidence is no longer available",
        ));
    }
    let digest = STANDARD.encode(Sha256::digest(&evidence.content));
    let disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", evidence.filename)).map_err(
            |_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid evidence metadata",
                )
            },
        )?;
    let content_type = HeaderValue::from_str(&evidence.media_type).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid evidence metadata",
        )
    })?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, disposition),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (
                HeaderNameCompat::DIGEST,
                HeaderValue::from_str(&format!("sha-256={digest}")).map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Invalid evidence digest")
                })?,
            ),
        ],
        Body::from(evidence.content),
    )
        .into_response())
}

struct HeaderNameCompat;
impl HeaderNameCompat {
    const DIGEST: header::HeaderName = header::HeaderName::from_static("digest");
}

async fn health() -> Json<Value> {
    Json(json!({"status": "healthy", "service": "applicant-service", "backend": "rust"}))
}
async fn ready() -> Json<Value> {
    Json(json!({"status": "ready", "service": "applicant-service", "backend": "rust"}))
}
async fn startup() -> Json<Value> {
    Json(json!({"status": "started", "service": "applicant-service", "backend": "rust"}))
}
async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        "# TYPE marty_applicant_backend_info gauge\nmarty_applicant_backend_info{backend=\"rust\"} 1\n",
    )
}
