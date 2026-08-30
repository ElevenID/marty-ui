//! HTTP boundary for Canvas platform management.

use axum::{
    body::to_bytes,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::{
    canvas_management::CanvasPlatformRequest,
    canvas_management_domain::{CanvasManagementDomainError, CanvasPlatformRecord},
    canvas_management_service::{CanvasPlatformManagementError, CanvasPlatformManagementService},
    transaction_reads::TransactionReadError,
};

const MAX_MANAGEMENT_BODY_BYTES: usize = 64 * 1024;
const SAFE_CONNECTION_CONFIG_KEYS: &[&str] = &[
    "enabled_intent",
    "oauth_client_id",
    "oauth_status",
    "oauth_capabilities",
    "granted_scopes",
    "lti_config_token_status",
];

#[derive(Clone, Debug)]
pub struct CanvasPlatformManagementHttpService {
    management: CanvasPlatformManagementService,
}

impl CanvasPlatformManagementHttpService {
    #[must_use]
    pub fn new(management: CanvasPlatformManagementService) -> Self {
        Self { management }
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), CanvasManagementHttpError> {
        self.management
            .authorize_request(
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn create(
        &self,
        headers: &HeaderMap,
        request: CanvasPlatformRequest,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .create(
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }

    pub async fn list(
        &self,
        headers: &HeaderMap,
        claimed_organization_id: Option<&str>,
    ) -> Result<Vec<CanvasPlatformResponse>, CanvasManagementHttpError> {
        self.management
            .list(
                claimed_organization_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(|platforms| {
                platforms
                    .into_iter()
                    .map(CanvasPlatformResponse::from)
                    .collect()
            })
            .map_err(Into::into)
    }

    pub async fn get(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .get(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }

    pub async fn update(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
        request: CanvasPlatformRequest,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .update(
                platform_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasPlatformResponse {
    pub id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub display_name: Option<String>,
    pub canvas_base_url: Option<String>,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    pub lti_trust_profile: String,
    pub lti_issuer: Option<String>,
    pub lti_jwks_url: Option<String>,
    pub lti_jwks_fetched_at: Option<String>,
    pub lti_jwks_expires_at: Option<String>,
    pub registration_status: String,
    pub connection_config: Map<String, Value>,
    pub capability_snapshot: Map<String, Value>,
    pub last_validated_at: Option<String>,
    pub last_connection_error: Option<String>,
    pub config_version: i64,
    pub archived_at: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CanvasPlatformRecord> for CanvasPlatformResponse {
    fn from(platform: CanvasPlatformRecord) -> Self {
        let connection_config = SAFE_CONNECTION_CONFIG_KEYS
            .iter()
            .filter_map(|key| {
                platform
                    .connection_config
                    .get(*key)
                    .cloned()
                    .map(|value| ((*key).to_owned(), value))
            })
            .collect();
        Self {
            id: platform.id,
            organization_id: platform.organization_id,
            canvas_account_id: platform.canvas_account_id,
            display_name: platform.display_name,
            canvas_base_url: platform.canvas_base_url,
            lti_client_id: platform.lti_client_id,
            lti_deployment_id: platform.lti_deployment_id,
            lti_trust_profile: platform.lti_trust_profile,
            lti_issuer: platform.lti_issuer,
            lti_jwks_url: platform.lti_jwks_url,
            lti_jwks_fetched_at: optional_timestamp(platform.lti_jwks_fetched_at),
            lti_jwks_expires_at: optional_timestamp(platform.lti_jwks_expires_at),
            registration_status: platform.registration_status,
            connection_config,
            capability_snapshot: platform.capability_snapshot,
            last_validated_at: optional_timestamp(platform.last_validated_at),
            last_connection_error: platform.last_connection_error,
            config_version: platform.config_version,
            archived_at: optional_timestamp(platform.archived_at),
            enabled: platform.enabled,
            created_at: timestamp(platform.created_at),
            updated_at: timestamp(platform.updated_at),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CanvasManagementHttpError {
    Service(CanvasPlatformManagementError),
    Validation(Vec<Value>),
    BodyTooLarge,
}

impl From<CanvasPlatformManagementError> for CanvasManagementHttpError {
    fn from(error: CanvasPlatformManagementError) -> Self {
        Self::Service(error)
    }
}

impl IntoResponse for CanvasManagementHttpError {
    fn into_response(self) -> Response {
        match self {
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas management request body exceeds the size limit"})),
            )
                .into_response(),
            Self::Service(error) => service_failure(error),
        }
    }
}

pub async fn parse_platform_request(
    request: axum::extract::Request,
) -> Result<CanvasPlatformRequest, CanvasManagementHttpError> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    if content_type.as_deref() != Some("application/json") {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": null,
        })]));
    }
    let bytes = to_bytes(request.into_body(), MAX_MANAGEMENT_BODY_BYTES)
        .await
        .map_err(|_| CanvasManagementHttpError::BodyTooLarge)?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "json_invalid",
            "loc": ["body"],
            "msg": "JSON decode error",
            "input": null,
        })])
    })?;
    validate_platform_request_value(&mut value)?;
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid Canvas platform request",
            "input": null,
        })])
    })
}

pub fn organization_id_from_query(query: Option<&str>) -> Option<String> {
    query.and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .filter(|(name, _)| name == "organization_id")
            .map(|(_, value)| value.into_owned())
            .last()
    })
}

fn validate_platform_request_value(value: &mut Value) -> Result<(), CanvasManagementHttpError> {
    let invalid_input = value.clone();
    let Some(object) = value.as_object_mut() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": invalid_input,
        })]));
    };
    let mut errors = Vec::new();
    validate_optional_string(object, "display_name", 200, &mut errors);
    validate_required_string(object, "canvas_base_url", 2_048, &mut errors);
    validate_optional_string(object, "lti_client_id", 512, &mut errors);
    validate_optional_string(object, "lti_deployment_id", 512, &mut errors);
    if let Some(enabled) = object.get("enabled").cloned() {
        if let Some(normalized) = pydantic_bool(&enabled) {
            object.insert("enabled".to_owned(), Value::Bool(normalized));
        } else {
            let structured = enabled.is_array() || enabled.is_object() || enabled.is_null();
            errors.push(json!({
                "type": if structured { "bool_type" } else { "bool_parsing" },
                "loc": ["body", "enabled"],
                "msg": if structured {
                    "Input should be a valid boolean"
                } else {
                    "Input should be a valid boolean, unable to interpret input"
                },
                "input": enabled,
            }));
        }
    }
    for (name, input) in object.iter().filter(|(name, _)| {
        !matches!(
            name.as_str(),
            "display_name" | "canvas_base_url" | "lti_client_id" | "lti_deployment_id" | "enabled"
        )
    }) {
        errors.push(json!({
            "type": "extra_forbidden",
            "loc": ["body", name],
            "msg": "Extra inputs are not permitted",
            "input": input,
        }));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CanvasManagementHttpError::Validation(errors))
    }
}

fn pydantic_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) if value.as_f64() == Some(1.0) => Some(true),
        Value::Number(value) if value.as_f64() == Some(0.0) => Some(false),
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn validate_required_string(
    object: &Map<String, Value>,
    name: &'static str,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(input) = object.get(name) else {
        errors.push(json!({
            "type": "missing",
            "loc": ["body", name],
            "msg": "Field required",
            "input": object,
        }));
        return;
    };
    validate_string(input, name, true, max, errors);
}

fn validate_optional_string(
    object: &Map<String, Value>,
    name: &'static str,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(input) = object.get(name) else {
        return;
    };
    if input.is_null() {
        return;
    }
    validate_string(input, name, false, max, errors);
}

fn validate_string(
    input: &Value,
    name: &'static str,
    required: bool,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(value) = input.as_str() else {
        errors.push(json!({
            "type": "string_type",
            "loc": ["body", name],
            "msg": "Input should be a valid string",
            "input": input,
        }));
        return;
    };
    let length = value.chars().count();
    if required && length == 0 {
        errors.push(json!({
            "type": "string_too_short",
            "loc": ["body", name],
            "msg": "String should have at least 1 character",
            "input": input,
            "ctx": {"min_length": 1},
        }));
    } else if length > max {
        errors.push(json!({
            "type": "string_too_long",
            "loc": ["body", name],
            "msg": format!("String should have at most {max} characters"),
            "input": input,
            "ctx": {"max_length": max},
        }));
    }
}

fn service_failure(error: CanvasPlatformManagementError) -> Response {
    let (status, detail) = match error {
        CanvasPlatformManagementError::Security(error) => match error {
            TransactionReadError::ApiKeyNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server".to_owned(),
            ),
            TransactionReadError::ApiKeyMissing => (
                StatusCode::UNAUTHORIZED,
                "X-API-Key header is missing".to_owned(),
            ),
            TransactionReadError::InvalidApiKey => {
                (StatusCode::UNAUTHORIZED, "Invalid API Key".to_owned())
            }
            TransactionReadError::TrustedOrganizationRequired => (
                StatusCode::BAD_REQUEST,
                "X-Organization-ID is required for Canvas management".to_owned(),
            ),
            TransactionReadError::OrganizationIdRequired => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "detail": [{
                            "type": "missing",
                            "loc": ["query", "organization_id"],
                            "msg": "Field required",
                            "input": null,
                        }]
                    })),
                )
                    .into_response();
            }
            TransactionReadError::ResourceNotFound | TransactionReadError::OrganizationMismatch => {
                (
                    StatusCode::NOT_FOUND,
                    "Canvas resource not found".to_owned(),
                )
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Canvas management authentication is unavailable".to_owned(),
            ),
        },
        CanvasPlatformManagementError::Domain(error) => match error {
            CanvasManagementDomainError::InvalidRequest(error) => {
                (StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
            }
            CanvasManagementDomainError::OriginUntrusted => (
                StatusCode::BAD_REQUEST,
                "Invalid Canvas base URL: Canvas base URL is not permitted by operator policy"
                    .to_owned(),
            ),
            CanvasManagementDomainError::VersionExhausted => (
                StatusCode::CONFLICT,
                "Canvas platform configuration version is exhausted".to_owned(),
            ),
        },
        CanvasPlatformManagementError::PlatformNotFound => (
            StatusCode::NOT_FOUND,
            "Canvas platform not found".to_owned(),
        ),
        CanvasPlatformManagementError::ConfigurationChanged => (
            StatusCode::CONFLICT,
            "Canvas platform configuration changed; retry the request".to_owned(),
        ),
        CanvasPlatformManagementError::Conflict => (
            StatusCode::CONFLICT,
            "Canvas platform conflicts with an existing resource".to_owned(),
        ),
        CanvasPlatformManagementError::RepositoryUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas platform repository is unavailable".to_owned(),
        ),
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn header<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn optional_timestamp(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(timestamp)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, false)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn response_projects_only_the_legacy_public_connection_keys() {
        let now = Utc.with_ymd_and_hms(2026, 8, 30, 22, 0, 0).unwrap();
        let mut connection_config = Map::new();
        connection_config.insert("enabled_intent".to_owned(), json!(true));
        connection_config.insert("oauth_status".to_owned(), json!("connected"));
        connection_config.insert("access_token_secret_ref".to_owned(), json!("secret"));
        connection_config.insert("lti_config_token_hash".to_owned(), json!("digest"));
        let response = CanvasPlatformResponse::from(CanvasPlatformRecord {
            id: "platform-1".to_owned(),
            organization_id: "org-1".to_owned(),
            canvas_account_id: "unverified:platform-1".to_owned(),
            display_name: None,
            canvas_base_url: Some("https://canvas.example.edu".to_owned()),
            lti_client_id: None,
            lti_deployment_id: None,
            lti_trust_profile: "hosted_global".to_owned(),
            lti_issuer: None,
            lti_jwks_url: None,
            lti_jwks_json: Some(json!({"private": "not-public"})),
            lti_jwks_fetched_at: None,
            lti_jwks_expires_at: None,
            lti_openid_configuration: Some(json!({"private": "not-public"})),
            registration_status: "draft".to_owned(),
            connection_config,
            capability_snapshot: Map::new(),
            last_validated_at: None,
            last_connection_error: None,
            config_version: 1,
            archived_at: None,
            enabled: false,
            created_at: now,
            updated_at: now,
        });
        assert_eq!(response.connection_config.len(), 2);
        assert_eq!(response.connection_config["enabled_intent"], true);
        assert!(!response
            .connection_config
            .contains_key("access_token_secret_ref"));
        assert!(!response
            .connection_config
            .contains_key("lti_config_token_hash"));
        assert_eq!(response.created_at, "2026-08-30T22:00:00+00:00");
    }

    #[test]
    fn request_validation_is_strict_and_fastapi_shaped() {
        let mut input = json!({
            "canvas_base_url": "",
            "enabled": "maybe",
            "organization_id": "attacker"
        });
        let error = validate_platform_request_value(&mut input).unwrap_err();
        let CanvasManagementHttpError::Validation(errors) = error else {
            panic!("expected validation errors")
        };
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0]["type"], "string_too_short");
        assert_eq!(errors[1]["type"], "bool_parsing");
        assert_eq!(errors[2]["type"], "extra_forbidden");
    }

    #[test]
    fn request_validation_preserves_pydantic_boolean_coercion() {
        for (input, expected) in [
            (json!("yes"), true),
            (json!("OFF"), false),
            (json!(1), true),
            (json!(0.0), false),
        ] {
            let mut request = json!({
                "canvas_base_url": "https://canvas.example.edu",
                "enabled": input,
            });
            validate_platform_request_value(&mut request).unwrap();
            assert_eq!(request["enabled"], expected);
        }
    }

    #[test]
    fn organization_query_uses_the_last_scalar_value() {
        assert_eq!(
            organization_id_from_query(Some("organization_id=forged&x=1&organization_id=org-1")),
            Some("org-1".to_owned())
        );
        assert_eq!(organization_id_from_query(Some("x=1")), None);
    }
}
