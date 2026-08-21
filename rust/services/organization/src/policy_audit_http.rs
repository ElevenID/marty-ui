use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    application_error, authorize_action, authorize_membership, deserialize_policy_documents,
    AuditEvent, AuditQueryInput, CedarPolicyDocument, CreatePolicySetCommand,
    OrganizationApplicationError, OrganizationHttpError, OrganizationHttpState, PolicySet,
    PolicySetStatus, PolicySetType, UpdatePolicySetCommand, UpdatePolicySetPatch,
};

pub const POLICY_HTTP_ROUTES: &[&str] = &[
    "GET /v1/organizations/{organization_id}/policy-sets",
    "POST /v1/organizations/{organization_id}/policy-sets",
    "GET /v1/organizations/{organization_id}/policy-sets/templates",
    "POST /v1/organizations/{organization_id}/policy-sets/validate",
    "GET /v1/organizations/{organization_id}/policy-sets/{policy_set_id}",
    "PATCH /v1/organizations/{organization_id}/policy-sets/{policy_set_id}",
    "DELETE /v1/organizations/{organization_id}/policy-sets/{policy_set_id}",
    "POST /v1/organizations/{organization_id}/policy-sets/{policy_set_id}/activate",
    "POST /v1/organizations/{organization_id}/policy-sets/{policy_set_id}/archive",
];

pub const AUDIT_HTTP_ROUTES: &[&str] = &[
    "GET /v1/organizations/audit/events",
    "GET /v1/organizations/audit/events/export",
    "GET /v1/organizations/audit/events/{event_id}",
];

pub(crate) fn organization_policy_router() -> Router<OrganizationHttpState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/policy-sets",
            get(list_policy_sets).post(create_policy_set),
        )
        .route(
            "/v1/organizations/{organization_id}/policy-sets/templates",
            get(list_policy_templates),
        )
        .route(
            "/v1/organizations/{organization_id}/policy-sets/validate",
            axum::routing::post(validate_policies),
        )
        .route(
            "/v1/organizations/{organization_id}/policy-sets/{policy_set_id}",
            get(get_policy_set)
                .patch(update_policy_set)
                .delete(delete_policy_set),
        )
        .route(
            "/v1/organizations/{organization_id}/policy-sets/{policy_set_id}/activate",
            axum::routing::post(activate_policy_set),
        )
        .route(
            "/v1/organizations/{organization_id}/policy-sets/{policy_set_id}/archive",
            axum::routing::post(archive_policy_set),
        )
        .route("/v1/organizations/audit/events", get(list_audit_events))
        .route(
            "/v1/organizations/audit/events/export",
            get(export_audit_events),
        )
        .route(
            "/v1/organizations/audit/events/{event_id}",
            get(get_audit_event),
        )
}

#[derive(Deserialize)]
struct PolicyListQuery {
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicySetRequest {
    name: String,
    cedar_policies: Vec<CedarPolicyDocument>,
    #[serde(default = "default_policy_type")]
    policy_type: String,
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatePolicyRequest {
    cedar_policies: Vec<CedarPolicyDocument>,
}

#[derive(Deserialize)]
struct AuditQuery {
    organization_id: Uuid,
    #[serde(default = "default_audit_page")]
    page: i64,
    #[serde(default = "default_audit_per_page")]
    per_page: i64,
    limit: Option<i64>,
    #[serde(default)]
    offset: i64,
    time_range: Option<String>,
    category: Option<String>,
    event_type: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    action: Option<String>,
    actor: Option<String>,
    severity: Option<String>,
    search: Option<String>,
    ip_address: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
}

#[derive(Deserialize)]
struct AuditExportQuery {
    #[serde(flatten)]
    query: AuditQuery,
    #[serde(default = "default_export_format")]
    format: String,
}

async fn list_policy_sets(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PolicyListQuery>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let status = query
        .status
        .as_deref()
        .map(parse_policy_status)
        .transpose()?;
    let policy_sets = state
        .application
        .list_policy_sets(organization_id, status)
        .await
        .map_err(application_error)?;
    Ok(Json(
        policy_sets
            .iter()
            .map(policy_set_response)
            .collect::<Vec<_>>(),
    )
    .into_response())
}

async fn create_policy_set(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreatePolicySetRequest>,
) -> Result<Response, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    validate_policy_input(
        &input.name,
        input.description.as_deref(),
        &input.cedar_policies,
    )?;
    let result = state
        .application
        .create_policy_set(CreatePolicySetCommand {
            organization_id,
            name: input.name,
            policies: input.cedar_policies,
            policy_type: parse_policy_type(&input.policy_type)?,
            description: input.description,
            created_by: Some(context.principal_id),
            now: Utc::now(),
        })
        .await;
    match result {
        Ok(policy_set) => {
            Ok((StatusCode::CREATED, Json(policy_set_response(&policy_set))).into_response())
        }
        Err(error) => policy_application_error(error),
    }
}

async fn get_policy_set(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, policy_set_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let policy_set = state
        .application
        .get_policy_set(organization_id, policy_set_id)
        .await
        .map_err(application_error)?;
    match policy_set {
        Some(policy_set) => Ok(Json(policy_set_response(&policy_set)).into_response()),
        None => Ok(policy_not_found()),
    }
}

async fn update_policy_set(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, policy_set_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let patch = parse_policy_patch(input)?;
    let result = state
        .application
        .update_policy_set(UpdatePolicySetCommand {
            organization_id,
            policy_set_id,
            patch,
            now: Utc::now(),
        })
        .await;
    match result {
        Ok(policy_set) => Ok(Json(policy_set_response(&policy_set)).into_response()),
        Err(error) => policy_application_error(error),
    }
}

async fn archive_policy_set(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, policy_set_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    transition_policy(&state, organization_id, policy_set_id, false).await
}

async fn activate_policy_set(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, policy_set_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    transition_policy(&state, organization_id, policy_set_id, true).await
}

async fn transition_policy(
    state: &OrganizationHttpState,
    organization_id: Uuid,
    policy_set_id: Uuid,
    activate: bool,
) -> Result<Response, OrganizationHttpError> {
    let result = if activate {
        state
            .application
            .activate_policy_set(organization_id, policy_set_id, Utc::now())
            .await
    } else {
        state
            .application
            .archive_policy_set(organization_id, policy_set_id, Utc::now())
            .await
    };
    match result {
        Ok(policy_set) => Ok(Json(policy_set_response(&policy_set)).into_response()),
        Err(error) => policy_application_error(error),
    }
}

async fn delete_policy_set(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, policy_set_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    match state
        .application
        .delete_policy_set(organization_id, policy_set_id)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT.into_response()),
        Err(error) => policy_application_error(error),
    }
}

async fn validate_policies(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ValidatePolicyRequest>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    if input.cedar_policies.is_empty() {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":"cedar_policies must not be empty"})),
        )
            .into_response());
    }
    let mut errors = policy_shape_errors(&input.cedar_policies);
    if errors.is_empty() {
        errors = state
            .application
            .policy_validation_errors(&input.cedar_policies)
            .map_err(application_error)?;
    }
    Ok(Json(json!({"valid":errors.is_empty(),"errors":errors})).into_response())
}

async fn list_policy_templates(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    Ok(Json(policy_templates()))
}

async fn list_audit_events(
    State(state): State<OrganizationHttpState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_action(&state, &headers, query.organization_id, "audit:view").await?;
    let page = state
        .application
        .query_audit_events(audit_input(query), Utc::now())
        .await
        .map_err(application_error)?;
    Ok(Json(json!({
        "events":page.events.iter().map(audit_event_response).collect::<Vec<_>>(),
        "total":page.total,"page":page.page,"per_page":page.per_page
    }))
    .into_response())
}

async fn export_audit_events(
    State(state): State<OrganizationHttpState>,
    Query(mut input): Query<AuditExportQuery>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_action(
        &state,
        &headers,
        input.query.organization_id,
        "audit:export",
    )
    .await?;
    input.query.page = 1;
    input.query.per_page = 1_000;
    input.query.limit = None;
    input.query.offset = 0;
    let organization_id = input.query.organization_id;
    let page = state
        .application
        .query_audit_events(audit_input(input.query), Utc::now())
        .await
        .map_err(application_error)?;
    let rows = page
        .events
        .iter()
        .map(audit_event_response)
        .collect::<Vec<_>>();
    match input.format.trim().to_ascii_lowercase().as_str() {
        "json" => Ok(Json(json!({
            "format":"json","filename":format!("audit-events-{organization_id}.json"),
            "events":rows,"total":page.total
        }))
        .into_response()),
        "csv" => Ok(Json(json!({
            "format":"csv","filename":format!("audit-events-{organization_id}.csv"),
            "content_type":"text/csv","content":audit_csv(&page.events),"total":page.total
        }))
        .into_response()),
        _ => Ok((StatusCode::BAD_REQUEST, Json(json!({"detail":{
            "error":"unsupported_export_format","message":"Audit export format must be csv or json."
        }})))
        .into_response()),
    }
}

async fn get_audit_event(
    State(state): State<OrganizationHttpState>,
    Path(event_id): Path<Uuid>,
    Query(query): Query<AuditIdentityQuery>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_action(&state, &headers, query.organization_id, "audit:view").await?;
    let event = state
        .application
        .get_audit_event(query.organization_id, event_id)
        .await
        .map_err(application_error)?;
    match event {
        Some(event) => Ok(Json(audit_event_response(&event)).into_response()),
        None => Ok((StatusCode::NOT_FOUND, Json(json!({"detail":{
            "error":"audit_event_not_found","message":"Audit event was not found for this organization."
        }})))
        .into_response()),
    }
}

#[derive(Deserialize)]
struct AuditIdentityQuery {
    organization_id: Uuid,
}

fn audit_input(query: AuditQuery) -> AuditQueryInput {
    AuditQueryInput {
        organization_id: query.organization_id,
        page: query.page,
        per_page: query.per_page,
        legacy_limit: query.limit,
        legacy_offset: query.offset,
        category: query.category,
        event_type: query.event_type,
        resource_type: query.resource_type,
        resource_id: query.resource_id,
        action: query.action,
        actor: query.actor,
        severity: query.severity,
        search: query.search,
        ip_address: query.ip_address,
        time_range: query.time_range,
        start_date: query.start_date,
        end_date: query.end_date,
    }
}

fn audit_event_response(event: &AuditEvent) -> Value {
    json!({
        "id":event.id.to_string(),"organization_id":event.organization_id.to_string(),
        "event_type":event.event_type,"action":event.action,"category":event.category,
        "resource_type":event.resource_type,"resource_id":event.resource_id,
        "resource_name":event.resource_name,"actor_id":event.actor_id,"actor_type":event.actor_type,
        "severity":event.severity,"message":event.message,"changes":event.changes,
        "metadata":event.metadata,"timestamp":event.timestamp.to_rfc3339()
    })
}

fn audit_csv(events: &[AuditEvent]) -> String {
    let mut output = String::from("id,timestamp,actor_id,actor_type,action,category,resource_type,resource_id,resource_name,severity,message\r\n");
    for event in events {
        let fields = [
            event.id.to_string(),
            event.timestamp.to_rfc3339(),
            event.actor_id.clone().unwrap_or_default(),
            event.actor_type.clone(),
            event.action.clone(),
            event.category.clone(),
            event.resource_type.clone(),
            event.resource_id.clone().unwrap_or_default(),
            event.resource_name.clone().unwrap_or_default(),
            event.severity.clone(),
            event.message.clone(),
        ];
        output.push_str(
            &fields
                .iter()
                .map(|field| csv_field(field))
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push_str("\r\n");
    }
    output
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn policy_set_response(policy_set: &PolicySet) -> Value {
    json!({
        "id":policy_set.id.to_string(),"organization_id":policy_set.organization_id.to_string(),
        "name":policy_set.name,"description":policy_set.description,
        "policy_type":policy_set.policy_type.as_str(),
        "cedar_policies":deserialize_policy_documents(&policy_set.cedar_policies),
        "cedar_schema_version":policy_set.cedar_schema_version,"status":policy_set.status.as_str(),
        "created_at":policy_set.created_at.to_rfc3339(),"updated_at":policy_set.updated_at.to_rfc3339()
    })
}

fn parse_policy_patch(value: Value) -> Result<UpdatePolicySetPatch, OrganizationHttpError> {
    let object = value.as_object().ok_or_else(crate::invalid_request)?;
    if object
        .keys()
        .any(|key| !["name", "description", "cedar_policies"].contains(&key.as_str()))
    {
        return Err(crate::invalid_request());
    }
    let name = object
        .get("name")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(crate::invalid_request)
        })
        .transpose()?;
    let description = object
        .get("description")
        .map(|value| {
            if value.is_null() {
                Ok(None)
            } else {
                value
                    .as_str()
                    .map(str::to_owned)
                    .map(Some)
                    .ok_or_else(crate::invalid_request)
            }
        })
        .transpose()?;
    let policies = object
        .get("cedar_policies")
        .map(|value| {
            serde_json::from_value::<Vec<CedarPolicyDocument>>(value.clone())
                .map_err(|_| crate::invalid_request())
        })
        .transpose()?;
    if name
        .as_ref()
        .is_some_and(|name| name.is_empty() || name.len() > 128)
        || description
            .as_ref()
            .and_then(Option::as_ref)
            .is_some_and(|description| description.len() > 1024)
        || policies.as_ref().is_some_and(Vec::is_empty)
    {
        return Err(crate::invalid_request());
    }
    if let Some(policies) = policies.as_ref() {
        if !policy_shape_errors(policies).is_empty() {
            return Err(crate::invalid_request());
        }
    }
    Ok(UpdatePolicySetPatch {
        name,
        description,
        policies,
    })
}

fn validate_policy_input(
    name: &str,
    description: Option<&str>,
    policies: &[CedarPolicyDocument],
) -> Result<(), OrganizationHttpError> {
    if name.is_empty()
        || name.len() > 128
        || description.is_some_and(|value| value.len() > 1024)
        || policies.is_empty()
        || !policy_shape_errors(policies).is_empty()
    {
        return Err(crate::invalid_request());
    }
    Ok(())
}

fn policy_shape_errors(policies: &[CedarPolicyDocument]) -> Vec<String> {
    let id = Regex::new(r"^[a-z][a-z0-9_-]*$").expect("static policy id regex");
    policies
        .iter()
        .filter_map(|policy| {
            if policy.policy_id.len() > 128 || !id.is_match(&policy.policy_id) {
                Some(format!("Invalid policy_id: {}", policy.policy_id))
            } else if !matches!(policy.effect.as_str(), "permit" | "forbid") {
                Some(format!("Invalid effect: {}", policy.effect))
            } else if policy.cedar_text.len() < 10 {
                Some(format!(
                    "Policy {} Cedar text is too short",
                    policy.policy_id
                ))
            } else if policy
                .description
                .as_ref()
                .is_some_and(|value| value.len() > 512)
            {
                Some(format!(
                    "Policy {} description is too long",
                    policy.policy_id
                ))
            } else {
                None
            }
        })
        .collect()
}

fn parse_policy_type(value: &str) -> Result<PolicySetType, OrganizationHttpError> {
    match value {
        "ACCESS_CONTROL" => Ok(PolicySetType::AccessControl),
        "CREDENTIAL_VERIFICATION" => Ok(PolicySetType::CredentialVerification),
        "APPROVAL_RULES" => Ok(PolicySetType::ApprovalRules),
        "CUSTOM" => Ok(PolicySetType::Custom),
        _ => Err(crate::invalid_request()),
    }
}

fn parse_policy_status(value: &str) -> Result<PolicySetStatus, OrganizationHttpError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "DRAFT" => Ok(PolicySetStatus::Draft),
        "ACTIVE" => Ok(PolicySetStatus::Active),
        "ARCHIVED" => Ok(PolicySetStatus::Archived),
        _ => Err(crate::invalid_request()),
    }
}

fn policy_application_error(
    error: OrganizationApplicationError,
) -> Result<Response, OrganizationHttpError> {
    match error {
        OrganizationApplicationError::PolicySetNotFound(_) => Ok(policy_not_found()),
        OrganizationApplicationError::InvalidPolicy(message) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":{"message":"Invalid Cedar policies","errors":[message]}})),
        )
            .into_response()),
        error => Err(application_error(error)),
    }
}

fn policy_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"detail":"Policy set not found"})),
    )
        .into_response()
}

fn default_policy_type() -> String {
    "CUSTOM".into()
}

const fn default_audit_page() -> i64 {
    1
}

const fn default_audit_per_page() -> i64 {
    50
}

fn default_export_format() -> String {
    "csv".into()
}

fn policy_templates() -> Value {
    json!([
        {"template_id":"approval_verified_evidence","name":"Verified evidence approval","description":"Approve when every required evidence check is satisfied.","policy_type":"APPROVAL_RULES","cedar_policies":[{"policy_id":"approve_verified_evidence","effect":"permit","description":"Permit approval after all evidence requirements pass.","enabled":true,"cedar_text":"@id(\"approve_verified_evidence\")\npermit (principal, action == MIP::Action::\"applications:approve\", resource)\nwhen { context.all_required_evidence_satisfied };"}]},
        {"template_id":"verification_valid_credential","name":"Valid credential verification","description":"Accept current, non-revoked credentials from trusted issuers.","policy_type":"CREDENTIAL_VERIFICATION","cedar_policies":[{"policy_id":"permit_valid_credential","effect":"permit","description":"Permit a valid credential with baseline issuer trust.","enabled":true,"cedar_text":"@id(\"permit_valid_credential\")\npermit (principal, action == MIP::Action::\"credentials:verify\", resource)\nwhen { context.revocation_checked && !context.is_revoked && !context.is_expired && context.issuer_trust_level >= 50 };"}]},
        {"template_id":"access_read_only","name":"Read-only access","description":"Permit read actions for organization viewers.","policy_type":"ACCESS_CONTROL","cedar_policies":[{"policy_id":"viewer_read_access","effect":"permit","description":"Permit read access for viewers.","enabled":true,"cedar_text":"@id(\"viewer_read_access\")\npermit (principal is MIP::User, action in [MIP::Action::\"credentials:read\", MIP::Action::\"flows:read\", MIP::Action::\"applications:read\"], resource)\nwhen { principal in MIP::Role::\"viewer\" };"}]}
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_policy_shapes_preserve_the_public_contract() {
        assert_eq!(policy_templates().as_array().unwrap().len(), 3);
        let valid = CedarPolicyDocument {
            policy_id: "read_access".into(),
            effect: "permit".into(),
            cedar_text: "permit (principal, action, resource);".into(),
            description: None,
            enabled: true,
        };
        assert!(policy_shape_errors(&[valid]).is_empty());
    }

    #[test]
    fn patch_parser_preserves_omit_clear_and_replace() {
        let patch = parse_policy_patch(json!({"description":null,"name":"Updated"})).unwrap();
        assert_eq!(patch.name.as_deref(), Some("Updated"));
        assert_eq!(patch.description, Some(None));
        assert!(patch.policies.is_none());
        assert!(parse_policy_patch(json!({"private":true})).is_err());
    }

    #[test]
    fn csv_fields_quote_delimiters_quotes_and_newlines() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
    }
}
