use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use mmf_security::ServiceTokenAuthenticator;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    application::{
        ControlPlaneError, CreateTemplateCommand, CredentialTemplateApplication,
        CredentialTemplateApplicationError, UpdateTemplateCommand, UpdateTemplatePatch,
    },
    normalize_payload_format, resolve_validity_rules, ClaimDefinition, ClaimType, CredentialFormat,
    CredentialTemplate, CredentialTemplateError, DerivedAttribute, DisplayStyle, PrivacyPosture,
    TemplateStatus, ValidityRulesInput,
};

#[derive(Clone)]
pub struct CredentialTemplateHttpState {
    pub application: Arc<CredentialTemplateApplication>,
    pub service_authenticator: Arc<ServiceTokenAuthenticator>,
}

pub fn credential_template_router(state: CredentialTemplateHttpState) -> Router {
    Router::new()
        .route(
            "/v1/credential-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/v1/credential-templates/{template_id}",
            get(get_template)
                .patch(update_template)
                .delete(delete_template),
        )
        .route(
            "/v1/credential-templates/{template_id}/activate",
            post(activate_template),
        )
        .route(
            "/v1/credential-templates/{template_id}/deprecate",
            post(deprecate_template),
        )
        .route(
            "/v1/credential-templates/{template_id}/new-version",
            post(new_version),
        )
        .route(
            "/v1/credential-templates/{template_id}/claims",
            post(add_claim),
        )
        .with_state(state)
}

#[derive(Debug)]
pub struct CredentialTemplateHttpError {
    status: StatusCode,
    detail: String,
}

impl IntoResponse for CredentialTemplateHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"detail":self.detail}))).into_response()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    name: String,
    display_name: String,
    description: Option<String>,
    #[serde(default = "default_claim_type")]
    claim_type: String,
    #[serde(default = "default_true")]
    required: bool,
    #[serde(default = "default_true")]
    selectively_disclosable: bool,
    #[serde(default)]
    derivable: bool,
    derived_from: Option<String>,
    pattern: Option<String>,
    enum_values: Option<Vec<String>>,
    min_value: Option<f64>,
    max_value: Option<f64>,
    mdoc_namespace: Option<String>,
    mdoc_element_identifier: Option<String>,
    display_icon: Option<String>,
}

impl ClaimRequest {
    fn into_domain(self) -> Result<ClaimDefinition, CredentialTemplateHttpError> {
        Ok(ClaimDefinition {
            id: Uuid::new_v4().to_string(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            claim_type: ClaimType::parse(&self.claim_type).map_err(domain_error)?,
            required: self.required,
            selectively_disclosable: self.selectively_disclosable,
            derivable: self.derivable || self.derived_from.is_some(),
            derived_from: self.derived_from,
            pattern: self.pattern,
            enum_values: self.enum_values,
            min_value: self.min_value,
            max_value: self.max_value,
            mdoc_namespace: self.mdoc_namespace,
            mdoc_element_identifier: self.mdoc_element_identifier,
            display_icon: self.display_icon,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedAttributeRequest {
    name: String,
    description: Option<String>,
    source_claim: String,
    derivation_type: String,
    #[serde(default = "empty_object")]
    parameters: Value,
}

impl From<DerivedAttributeRequest> for DerivedAttribute {
    fn from(value: DerivedAttributeRequest) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: value.name,
            description: value.description,
            source_claim: value.source_claim,
            derivation_type: value.derivation_type,
            parameters: value.parameters,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTemplateRequest {
    organization_id: String,
    name: String,
    description: Option<String>,
    credential_type: String,
    vct: Option<String>,
    doctype: Option<String>,
    #[serde(default)]
    claims: Vec<ClaimRequest>,
    #[serde(default = "default_privacy_posture")]
    privacy_posture: String,
    #[serde(default)]
    selective_disclosure_fields: Vec<String>,
    #[serde(default)]
    zk_predicate_claims: Vec<String>,
    #[serde(default)]
    derived_attributes: Vec<DerivedAttributeRequest>,
    display_style: Option<DisplayStyle>,
    validity_rules: Option<ValidityRulesInput>,
    #[serde(default = "default_supported_formats")]
    supported_formats: Vec<String>,
    application_template_id: Option<String>,
    trust_profile_id: Option<String>,
    revocation_profile_id: Option<String>,
    compliance_profile_id: String,
    issuer_did: Option<String>,
    credential_payload_format: Option<String>,
    #[serde(default, rename = "schema_uri")]
    _schema_uri: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UpdateTemplateRequest {
    name: Option<String>,
    description: Option<String>,
    claims: Option<Vec<ClaimRequest>>,
    privacy_posture: Option<String>,
    selective_disclosure_fields: Option<Vec<String>>,
    zk_predicate_claims: Option<Vec<String>>,
    derived_attributes: Option<Vec<DerivedAttributeRequest>>,
    display_style: Option<DisplayStyle>,
    validity_rules: Option<ValidityRulesInput>,
    supported_formats: Option<Vec<String>>,
    application_template_id: Option<String>,
    trust_profile_id: Option<String>,
    revocation_profile_id: Option<String>,
    issuer_did: Option<String>,
    credential_payload_format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: String,
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn create_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateTemplateRequest>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let claims = input
        .claims
        .into_iter()
        .map(ClaimRequest::into_domain)
        .collect::<Result<Vec<_>, _>>()?;
    let supported_formats = parse_formats(&input.supported_formats)?;
    let validity_rules = input
        .validity_rules
        .map(|rules| resolve_validity_rules(&rules, None).map_err(domain_error))
        .transpose()?;
    let template = state
        .application
        .create_template(CreateTemplateCommand {
            user_id,
            organization_id: input.organization_id,
            name: input.name,
            description: input.description,
            credential_type: input.credential_type,
            vct: input.vct,
            doctype: input.doctype,
            claims,
            privacy_posture: parse_privacy(&input.privacy_posture)?,
            selective_disclosure_fields: input.selective_disclosure_fields,
            zk_predicate_claims: input.zk_predicate_claims,
            derived_attributes: input
                .derived_attributes
                .into_iter()
                .map(DerivedAttribute::from)
                .collect(),
            display_style: input.display_style,
            validity_rules,
            supported_formats,
            application_template_id: input.application_template_id,
            trust_profile_id: input.trust_profile_id,
            revocation_profile_id: input.revocation_profile_id,
            compliance_profile: None,
            compliance_profile_id: input.compliance_profile_id,
            issuer_did: input.issuer_did,
            credential_payload_format: input.credential_payload_format,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(template_response(&template)?))
}

async fn list_templates(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let status = query
        .status
        .as_deref()
        .map(TemplateStatus::parse)
        .transpose()
        .map_err(domain_error)?;
    let templates = state
        .application
        .list_templates(
            &user_id,
            &query.organization_id,
            status,
            query.limit.unwrap_or(100),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        templates
            .iter()
            .map(template_response)
            .collect::<Result<Vec<_>, _>>()?,
    )))
}

async fn get_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let template = state
        .application
        .get_template(&user_id, &template_id)
        .await
        .map_err(application_error)?;
    Ok(Json(template_response(&template)?))
}

async fn update_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    Json(input): Json<UpdateTemplateRequest>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let patch = UpdateTemplatePatch {
        name: input.name,
        description: input.description,
        claims: input
            .claims
            .map(|claims| {
                claims
                    .into_iter()
                    .map(ClaimRequest::into_domain)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
        privacy_posture: input
            .privacy_posture
            .as_deref()
            .map(parse_privacy)
            .transpose()?,
        selective_disclosure_fields: input.selective_disclosure_fields,
        zk_predicate_claims: input.zk_predicate_claims,
        derived_attributes: input
            .derived_attributes
            .map(|items| items.into_iter().map(DerivedAttribute::from).collect()),
        display_style: input.display_style,
        validity_rules: input.validity_rules,
        supported_formats: input
            .supported_formats
            .as_deref()
            .map(parse_formats)
            .transpose()?,
        application_template_id: input.application_template_id,
        trust_profile_id: input.trust_profile_id,
        revocation_profile_id: input.revocation_profile_id,
        issuer_did: input.issuer_did,
        credential_payload_format: input.credential_payload_format,
    };
    let template = state
        .application
        .update_template(UpdateTemplateCommand {
            user_id,
            template_id,
            patch,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(template_response(&template)?))
}

async fn activate_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    mutation_response(
        state
            .application
            .activate_template(&user_id, &template_id, Utc::now())
            .await,
    )
}

async fn deprecate_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    mutation_response(
        state
            .application
            .deprecate_template(&user_id, &template_id, Utc::now())
            .await,
    )
}

async fn new_version(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    mutation_response(
        state
            .application
            .new_version(&user_id, &template_id, Utc::now())
            .await,
    )
}

async fn delete_template(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<StatusCode, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    state
        .application
        .delete_template(&user_id, &template_id)
        .await
        .map_err(application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_claim(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    Json(input): Json<ClaimRequest>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let template = state
        .application
        .add_claim(&user_id, &template_id, input.into_domain()?, Utc::now())
        .await
        .map_err(application_error)?;
    Ok(Json(template_response(&template)?))
}

fn mutation_response(
    result: Result<CredentialTemplate, CredentialTemplateApplicationError>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let template = result.map_err(application_error)?;
    Ok(Json(template_response(&template)?))
}

fn template_response(template: &CredentialTemplate) -> Result<Value, CredentialTemplateHttpError> {
    let issuer_did = template
        .issuer_did
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("did:"))
        .ok_or_else(|| service_unavailable("CREDENTIAL_TEMPLATE.INVALID_STORED_ISSUER"))?;
    let compliance_profile_id = template
        .compliance_profile_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| service_unavailable("CREDENTIAL_TEMPLATE.INVALID_STORED_COMPLIANCE"))?;
    let claims = template.claims.iter().map(public_claim).collect::<Vec<_>>();
    let mut validity = Map::new();
    validity.insert(
        "ttl_seconds".to_owned(),
        json!(i64::from(template.validity_rules.default_validity_days) * 86_400),
    );
    validity.insert(
        "renewable".to_owned(),
        json!(template.validity_rules.renewable),
    );
    if template.validity_rules.renewal_window_days != 0 {
        validity.insert(
            "reissue_within_seconds".to_owned(),
            json!(i64::from(template.validity_rules.renewal_window_days) * 86_400),
        );
    }
    if template.validity_rules.not_before_offset_seconds != 0 {
        validity.insert(
            "not_before_offset_seconds".to_owned(),
            json!(template.validity_rules.not_before_offset_seconds),
        );
    }
    let payload_format = normalize_payload_format(
        Some(&template.credential_payload_format),
        &template.supported_formats,
    )
    .map_err(domain_error)?;
    let mut response = json!({
        "id":template.id,
        "organization_id":template.organization_id,
        "name":template.name,
        "description":template.description,
        "status":template.status.as_str().to_ascii_uppercase(),
        "credential_type":template.credential_type,
        "compliance_profile_id":compliance_profile_id,
        "vct":non_empty(&template.vct),
        "doctype":template.doctype.as_deref().and_then(non_empty),
        "credential_payload_format":payload_format.canonical(),
        "application_template_id":template.application_template_id,
        "trust_profile_id":template.trust_profile_id,
        "revocation_profile_id":template.revocation_profile_id,
        "issuer_did":issuer_did,
        "claims":claims,
        "validity_rules":validity,
        "privacy_posture":{
            "default_disclose_all":template.privacy_posture == PrivacyPosture::Standard,
            "prefer_predicates":!template.zk_predicate_claims.is_empty() || template.privacy_posture == PrivacyPosture::ZeroKnowledge,
            "sd_alg":"sha-256"
        },
        "created_at":template.created_at.to_rfc3339(),
        "updated_at":template.updated_at.to_rfc3339()
    });
    response
        .as_object_mut()
        .expect("template response is an object")
        .retain(|_, value| !value.is_null());
    Ok(response)
}

fn public_claim(claim: &ClaimDefinition) -> Value {
    let mut value = Map::new();
    value.insert("name".to_owned(), json!(claim.name));
    value.insert(
        "type".to_owned(),
        json!(public_claim_type(claim.claim_type)),
    );
    value.insert("required".to_owned(), json!(claim.required));
    if let Some(description) = claim.description.as_deref().and_then(non_empty) {
        value.insert("description".to_owned(), json!(description));
    }
    if claim.selectively_disclosable {
        value.insert("selectively_disclosable".to_owned(), json!(true));
    }
    if let Some(namespace) = claim.mdoc_namespace.as_deref().and_then(non_empty) {
        value.insert("namespace".to_owned(), json!(namespace));
    }
    if claim.derivable || claim.derived_from.is_some() {
        value.insert(
            "derived_from".to_owned(),
            json!(claim.derived_from.as_deref().unwrap_or(&claim.name)),
        );
    }
    if !claim.display_name.is_empty() || claim.display_icon.is_some() {
        let mut display = Map::new();
        if !claim.display_name.is_empty() {
            display.insert("label".to_owned(), json!(claim.display_name));
        }
        if let Some(icon) = claim.display_icon.as_deref().and_then(non_empty) {
            display.insert("icon".to_owned(), json!(icon));
        }
        value.insert("display".to_owned(), Value::Object(display));
    }
    Value::Object(value)
}

fn public_claim_type(value: ClaimType) -> &'static str {
    match value {
        ClaimType::String | ClaimType::Image | ClaimType::Binary => "STRING",
        ClaimType::Integer => "INTEGER",
        ClaimType::Boolean => "BOOLEAN",
        ClaimType::Date | ClaimType::Datetime => "DATE",
        ClaimType::Object => "OBJECT",
        ClaimType::Array => "ARRAY",
    }
}

fn trusted_user_id(
    state: &CredentialTemplateHttpState,
    headers: &HeaderMap,
) -> Result<String, CredentialTemplateHttpError> {
    let token = header(headers, "x-service-token");
    state
        .service_authenticator
        .authenticate(token)
        .map_err(|_| unauthorized("CREDENTIAL_TEMPLATE.SERVICE_AUTHENTICATION_REQUIRED"))?;
    header(headers, "x-user-id")
        .map(str::to_owned)
        .ok_or_else(|| unauthorized("CREDENTIAL_TEMPLATE.AUTHENTICATION_REQUIRED"))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_formats(values: &[String]) -> Result<Vec<CredentialFormat>, CredentialTemplateHttpError> {
    values
        .iter()
        .map(|value| CredentialFormat::parse(value).map_err(domain_error))
        .collect()
}

fn parse_privacy(value: &str) -> Result<PrivacyPosture, CredentialTemplateHttpError> {
    PrivacyPosture::parse(value).map_err(domain_error)
}

fn application_error(error: CredentialTemplateApplicationError) -> CredentialTemplateHttpError {
    match error {
        CredentialTemplateApplicationError::NotFound(_) => {
            not_found("Credential Template not found")
        }
        CredentialTemplateApplicationError::ControlPlane(ControlPlaneError::MembershipRequired) => {
            forbidden("CREDENTIAL_TEMPLATE.MEMBERSHIP_REQUIRED")
        }
        CredentialTemplateApplicationError::ControlPlane(ControlPlaneError::Unavailable(_))
        | CredentialTemplateApplicationError::Repository(_) => {
            service_unavailable("CREDENTIAL_TEMPLATE.DEPENDENCY_UNAVAILABLE")
        }
        CredentialTemplateApplicationError::Domain(CredentialTemplateError::TemplateNotDraft) => {
            bad_request("Only draft templates can be modified. Create a new version instead.")
        }
        CredentialTemplateApplicationError::Domain(
            CredentialTemplateError::TemplateNotDeletable,
        ) => conflict("Only draft templates can be deleted. Deprecate active templates instead."),
        error => unprocessable(&error.to_string()),
    }
}

fn domain_error(error: CredentialTemplateError) -> CredentialTemplateHttpError {
    unprocessable(&error.to_string())
}

fn unauthorized(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::UNAUTHORIZED, detail)
}

fn forbidden(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::FORBIDDEN, detail)
}

fn not_found(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::NOT_FOUND, detail)
}

fn bad_request(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::BAD_REQUEST, detail)
}

fn conflict(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::CONFLICT, detail)
}

fn unprocessable(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::UNPROCESSABLE_ENTITY, detail)
}

fn service_unavailable(detail: &str) -> CredentialTemplateHttpError {
    http_error(StatusCode::SERVICE_UNAVAILABLE, detail)
}

fn http_error(status: StatusCode, detail: &str) -> CredentialTemplateHttpError {
    CredentialTemplateHttpError {
        status,
        detail: detail.to_owned(),
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn default_true() -> bool {
    true
}

fn default_claim_type() -> String {
    "string".to_owned()
}

fn default_privacy_posture() -> String {
    "selective_disclosure".to_owned()
}

fn default_supported_formats() -> Vec<String> {
    vec!["SD_JWT_VC".to_owned()]
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}
