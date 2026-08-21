use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use mmf_security::ServiceTokenAuthenticator;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use url::Url;
use uuid::Uuid;

use crate::{
    authenticate_forwarded_http_request, authenticate_http_service, ApiKey, ApiKeyScopeType,
    CreateApiKeyCommand, CreateOrganizationCommand, ForwardedPrincipal, HttpTrustError,
    InviteMemberCommand, JoinByCodeCommand, JoinMechanism, JoinOrganizationCommand, Member,
    MemberStatus, Organization, OrganizationApplication, OrganizationApplicationError,
    OrganizationAuthorizationContext, OrganizationType, RemoveMemberCommand, RevokeApiKeyCommand,
    SetMemberRolesCommand, UpdateConsolePreferenceCommand, UpdateConsolePreferencePatch,
    UpdateOrganizationCommand, UpdateOrganizationPatch, ViewMode,
};

pub const CORE_ORGANIZATION_HTTP_ROUTES: &[&str] = &[
    "GET /api/onboarding/status",
    "GET /internal/v1/organizations/{org_id}/lifecycle",
    "PATCH /internal/v1/organizations/{org_id}/settings",
    "GET /v1/me/preferences",
    "PUT /v1/me/preferences",
    "GET /v1/organizations",
    "POST /v1/organizations",
    "GET /v1/organizations/discover",
    "GET /v1/organizations/mine",
    "GET /v1/organizations/{org_id}",
    "PATCH /v1/organizations/{org_id}",
    "GET /v1/organizations/{org_id}/environment",
    "PATCH /v1/organizations/{org_id}/environment",
    "GET /v1/organizations/{org_id}/lifecycle",
];

pub const MEMBERSHIP_API_HTTP_ROUTES: &[&str] = &[
    "POST /v1/organizations/join/code",
    "GET /v1/organizations/join/code/validate",
    "POST /v1/organizations/{org_id}/join",
    "GET /v1/organizations/{org_id}/team/snapshot",
    "GET /v1/organizations/{org_id}/members",
    "POST /v1/organizations/{org_id}/members",
    "PATCH /v1/organizations/{org_id}/members/{member_id}",
    "DELETE /v1/organizations/{org_id}/members/{member_id}",
    "GET /v1/organizations/{org_id}/api-keys",
    "POST /v1/organizations/{org_id}/api-keys",
    "DELETE /v1/organizations/{org_id}/api-keys/{key_id}",
];

#[derive(Clone)]
pub struct OrganizationHttpState {
    pub application: Arc<OrganizationApplication>,
    pub service_authenticator: Arc<ServiceTokenAuthenticator>,
    pub organization_creation_enabled: bool,
    pub marty_organization_id: Option<Uuid>,
}

pub fn organization_core_router(state: OrganizationHttpState) -> Router {
    Router::new()
        .route(
            "/v1/organizations",
            get(list_organizations).post(create_organization),
        )
        .route("/v1/organizations/discover", get(discover_organizations))
        .route("/v1/organizations/mine", get(my_organizations))
        .route(
            "/v1/organizations/{organization_id}",
            get(get_organization).patch(update_organization),
        )
        .route(
            "/v1/organizations/{organization_id}/lifecycle",
            get(get_organization_lifecycle),
        )
        .route(
            "/v1/organizations/{organization_id}/environment",
            get(get_organization_environment).patch(update_organization_environment),
        )
        .route(
            "/internal/v1/organizations/{organization_id}/lifecycle",
            get(get_internal_organization_lifecycle),
        )
        .route(
            "/internal/v1/organizations/{organization_id}/settings",
            patch(update_internal_organization_settings),
        )
        .route(
            "/v1/me/preferences",
            get(get_preferences).put(update_preferences),
        )
        .route("/api/onboarding/status", get(onboarding_status))
        .route("/v1/organizations/join/code", post(join_by_code))
        .route(
            "/v1/organizations/join/code/validate",
            get(validate_join_code),
        )
        .route(
            "/v1/organizations/{organization_id}/join",
            post(join_organization),
        )
        .route(
            "/v1/organizations/{organization_id}/team/snapshot",
            get(get_team_snapshot),
        )
        .route(
            "/v1/organizations/{organization_id}/members",
            get(list_members).post(invite_member),
        )
        .route(
            "/v1/organizations/{organization_id}/members/{member_id}",
            patch(update_member).delete(remove_member),
        )
        .route(
            "/v1/organizations/{organization_id}/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/v1/organizations/{organization_id}/api-keys/{key_id}",
            axum::routing::delete(revoke_api_key),
        )
        .with_state(state)
}

#[derive(Debug)]
pub struct OrganizationHttpError {
    status: StatusCode,
    detail: &'static str,
}

impl IntoResponse for OrganizationHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"detail": self.detail}))).into_response()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOrganizationRequest {
    name: String,
    display_name: String,
    #[serde(default = "default_organization_type")]
    org_type: String,
    description: Option<String>,
    contact_email: Option<String>,
    #[serde(default = "default_visibility")]
    visibility: String,
    #[serde(default = "default_join_mechanism")]
    join_mechanism: String,
    #[serde(default)]
    requires_approval: bool,
}

#[derive(Deserialize)]
struct PaginationQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    search: Option<String>,
    org_type: Option<String>,
    join_mechanism: Option<String>,
}

#[derive(Serialize)]
struct RoleSummaryResponse {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct MembershipSummaryResponse {
    roles: Vec<RoleSummaryResponse>,
    status: String,
    permissions: Vec<String>,
    has_org_console_access: bool,
    is_owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    joined_at: Option<String>,
}

#[derive(Serialize)]
struct OrganizationResponse {
    id: String,
    name: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    join_code: Option<String>,
    visibility: String,
    owner_id: String,
    status: String,
    org_type: String,
    join_mechanism: String,
    requires_approval: bool,
    is_discoverable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    website: Option<String>,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership: Option<MembershipSummaryResponse>,
}

#[derive(Serialize)]
struct PilotRetentionResponse {
    enabled: bool,
    window_days: u64,
    scope_summary: String,
    scope_items: [&'static str; 4],
    access_behavior: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_purged_at: Option<String>,
}

#[derive(Serialize)]
struct OrganizationLifecycleResponse {
    created_at: String,
    compliance_profiles: Vec<String>,
    data_retention_mode: String,
    audit_retention_days: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pilot_retention: Option<PilotRetentionResponse>,
}

#[derive(Serialize)]
struct OrganizationEnvironmentResponse {
    organization_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateEnvironmentRequest {
    environment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalSettingsRequest {
    settings_patch: Map<String, Value>,
}

#[derive(Serialize)]
struct PreferencesResponse {
    last_view_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active_org_id: Option<String>,
}

#[derive(Serialize)]
struct OnboardingStatusResponse {
    needs_onboarding: bool,
    user_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinByCodeRequest {
    code: String,
}

#[derive(Deserialize)]
struct ValidateJoinCodeQuery {
    code: String,
}

#[derive(Serialize)]
struct JoinResponse {
    organization: OrganizationResponse,
    membership: MemberResponse,
}

#[derive(Serialize)]
struct ValidateJoinCodeResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_name: Option<String>,
    expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteMemberRequest {
    email: String,
    role_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateMemberRequest {
    role_ids: Vec<Uuid>,
}

#[derive(Serialize)]
struct MemberResponse {
    id: String,
    organization_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    roles: Vec<RoleSummaryResponse>,
    status: String,
    permissions: Vec<String>,
    has_org_console_access: bool,
    is_owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    invited_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    joined_at: Option<String>,
}

#[derive(Serialize)]
struct TeamMemberResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    roles: Vec<RoleSummaryResponse>,
    status: String,
    is_owner: bool,
    has_org_console_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    joined_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invited_at: Option<String>,
}

#[derive(Serialize)]
struct TeamSnapshotResponse {
    members: Vec<TeamMemberResponse>,
    pending_invites: Vec<TeamMemberResponse>,
    role_distribution: BTreeMap<String, usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyRequest {
    name: String,
    description: Option<String>,
    scopes: Option<Vec<String>>,
    #[serde(default)]
    is_test: bool,
}

#[derive(Serialize)]
struct ApiKeyResponse {
    id: String,
    organization_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    key_prefix: String,
    scope_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_profile_id: Option<String>,
    scopes: Vec<String>,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

async fn create_organization(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), OrganizationHttpError> {
    if !state.organization_creation_enabled {
        return Err(forbidden("ORGANIZATION.CREATION_DISABLED"));
    }
    let user_id = authenticated_user_id(&state, &headers)?;
    validate_create_request(&input)?;
    let result = state
        .application
        .create_organization(CreateOrganizationCommand {
            name: input.name,
            owner_id: user_id.clone(),
            org_type: input.org_type.parse().map_err(|_| invalid_request())?,
            display_name: Some(input.display_name),
            description: input.description,
            contact_email: input.contact_email,
            visibility: input.visibility,
            join_mechanism: input
                .join_mechanism
                .parse()
                .map_err(|_| invalid_request())?,
            requires_approval: input.requires_approval,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    let membership = state
        .application
        .get_membership(&user_id, result.value.id)
        .await
        .map_err(application_error)?;
    Ok((
        StatusCode::OK,
        Json(organization_response(&result.value, membership.as_ref())),
    ))
}

async fn list_organizations(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Vec<OrganizationResponse>>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let organizations = state
        .application
        .list_organizations(limit(&query, 1_000), query.offset.unwrap_or_default())
        .await
        .map_err(application_error)?;
    Ok(Json(
        organizations
            .iter()
            .map(|organization| organization_response(organization, None))
            .collect(),
    ))
}

async fn discover_organizations(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Vec<OrganizationResponse>>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let org_type = query
        .org_type
        .as_deref()
        .map(str::parse::<OrganizationType>)
        .transpose()
        .map_err(|_| invalid_request())?;
    let join_mechanism = query
        .join_mechanism
        .as_deref()
        .map(str::parse::<JoinMechanism>)
        .transpose()
        .map_err(|_| invalid_request())?;
    let organizations = state
        .application
        .discover_organizations(
            query.search.as_deref(),
            org_type,
            join_mechanism,
            limit(&query, 1_000),
            query.offset.unwrap_or_default(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(
        organizations
            .iter()
            .map(|organization| organization_response(organization, None))
            .collect(),
    ))
}

async fn my_organizations(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrganizationResponse>>, OrganizationHttpError> {
    let user_id = authenticated_user_id(&state, &headers)?;
    let organizations = state
        .application
        .get_user_organizations_with_memberships(&user_id)
        .await
        .map_err(application_error)?;
    Ok(Json(
        organizations
            .iter()
            .map(|(organization, membership)| organization_response(organization, Some(membership)))
            .collect(),
    ))
}

async fn get_organization(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationResponse>, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let organization = load_organization(&state, organization_id).await?;
    Ok(Json(organization_response(&organization, None)))
}

async fn update_organization(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<Value>,
) -> Result<Json<OrganizationResponse>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "organization:edit").await?;
    let patch = parse_update_patch(input)?;
    let result = state
        .application
        .update_organization(UpdateOrganizationCommand {
            organization_id,
            patch,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(organization_response(&result.value, None)))
}

async fn get_organization_lifecycle(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationLifecycleResponse>, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    Ok(Json(lifecycle_response(
        &load_organization(&state, organization_id).await?,
    )))
}

async fn get_internal_organization_lifecycle(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationLifecycleResponse>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    Ok(Json(lifecycle_response(
        &load_organization(&state, organization_id).await?,
    )))
}

async fn get_organization_environment(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationEnvironmentResponse>, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let organization = load_organization(&state, organization_id).await?;
    Ok(Json(environment_response(&organization)))
}

async fn update_organization_environment(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<UpdateEnvironmentRequest>,
) -> Result<Json<OrganizationEnvironmentResponse>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "organization:edit").await?;
    let environment = normalize_environment(&input.environment).ok_or_else(invalid_request)?;
    let result = state
        .application
        .update_organization(UpdateOrganizationCommand {
            organization_id,
            patch: UpdateOrganizationPatch {
                settings: Some(Map::from_iter([(
                    "environment".into(),
                    Value::String(environment.into()),
                )])),
                ..UpdateOrganizationPatch::default()
            },
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(environment_response(&result.value)))
}

async fn update_internal_organization_settings(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<InternalSettingsRequest>,
) -> Result<Json<Value>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let result = state
        .application
        .update_organization(UpdateOrganizationCommand {
            organization_id,
            patch: UpdateOrganizationPatch {
                settings: Some(input.settings_patch),
                ..UpdateOrganizationPatch::default()
            },
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(json!({
        "organization_id": result.value.id,
        "updated": true
    })))
}

async fn get_preferences(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    let user_id = authenticated_user_id(&state, &headers)?;
    let preference = state
        .application
        .get_console_preferences(&user_id, Utc::now())
        .await
        .map_err(application_error)?;
    let mut response = Json(preferences_response(&preference)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store, max-age=0".parse().expect("static header"),
    );
    Ok(response)
}

async fn update_preferences(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Json<PreferencesResponse>, OrganizationHttpError> {
    let user_id = authenticated_user_id(&state, &headers)?;
    let object = strict_object(input, &["last_view_mode", "last_active_org_id"])?;
    let last_view_mode = object
        .get("last_view_mode")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(invalid_request)?
                .parse::<ViewMode>()
                .map_err(|_| invalid_request())
        })
        .transpose()?;
    let last_active_organization_id = object
        .get("last_active_org_id")
        .map(|value| {
            if value.is_null() {
                Ok(None)
            } else {
                value
                    .as_str()
                    .and_then(|value| value.parse::<Uuid>().ok())
                    .map(Some)
                    .ok_or_else(invalid_request)
            }
        })
        .transpose()?;
    if last_view_mode.is_none() && last_active_organization_id.is_none() {
        return Err(invalid_request());
    }
    let preference = state
        .application
        .update_console_preferences(UpdateConsolePreferenceCommand {
            user_id,
            patch: UpdateConsolePreferencePatch {
                last_view_mode,
                last_active_organization_id,
            },
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(preferences_response(&preference)))
}

async fn onboarding_status(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
) -> Result<Json<OnboardingStatusResponse>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let context = headers
        .get("x-user-context")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    let roles = context
        .as_ref()
        .and_then(|value| value.get("roles"))
        .and_then(Value::as_array);
    let has_role = |name: &str| {
        roles.is_some_and(|roles| roles.iter().any(|role| role.as_str() == Some(name)))
    };
    let user_type = if has_role("administrator") || has_role("admin") {
        "administrator"
    } else if has_role("applicant") {
        "applicant"
    } else {
        "vendor"
    };
    Ok(Json(OnboardingStatusResponse {
        needs_onboarding: false,
        user_type: user_type.into(),
        organization_id: context
            .as_ref()
            .and_then(|value| value.get("organization_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        organization_name: context
            .as_ref()
            .and_then(|value| value.get("organization_name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }))
}

async fn join_by_code(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Json(input): Json<JoinByCodeRequest>,
) -> Result<(StatusCode, Json<JoinResponse>), OrganizationHttpError> {
    let user_id = authenticated_user_id(&state, &headers)?;
    let email = authenticated_user_email(&headers)?;
    let result = state
        .application
        .join_by_code(JoinByCodeCommand {
            user_id,
            code: input.code.to_ascii_uppercase(),
            email,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok((
        StatusCode::CREATED,
        Json(JoinResponse {
            organization: organization_response(&result.value.0, None),
            membership: member_response(&result.value.1),
        }),
    ))
}

async fn validate_join_code(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Query(query): Query<ValidateJoinCodeQuery>,
) -> Result<Json<ValidateJoinCodeResponse>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let validation = state
        .application
        .validate_join_code(&query.code, Utc::now())
        .await
        .map_err(application_error)?;
    Ok(Json(ValidateJoinCodeResponse {
        valid: validation.is_valid,
        organization_id: validation
            .organization
            .as_ref()
            .map(|organization| organization.id.to_string()),
        organization_name: validation
            .organization
            .as_ref()
            .map(|organization| organization.name.clone()),
        expired: validation.expired,
        message: Some(validation.message),
    }))
}

async fn join_organization(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<JoinResponse>), OrganizationHttpError> {
    let user_id = authenticated_user_id(&state, &headers)?;
    let email = authenticated_user_email(&headers)?;
    let result = state
        .application
        .join_organization(JoinOrganizationCommand {
            user_id,
            organization_id,
            email,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok((
        StatusCode::CREATED,
        Json(JoinResponse {
            organization: organization_response(&result.value.0, None),
            membership: member_response(&result.value.1),
        }),
    ))
}

async fn get_team_snapshot(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TeamSnapshotResponse>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "team:view").await?;
    let members = state
        .application
        .list_members(organization_id)
        .await
        .map_err(application_error)?;
    let active = members
        .iter()
        .filter(|member| member.status == MemberStatus::Active)
        .collect::<Vec<_>>();
    let pending = members
        .iter()
        .filter(|member| matches!(member.status, MemberStatus::Invited | MemberStatus::Pending))
        .collect::<Vec<_>>();
    Ok(Json(TeamSnapshotResponse {
        role_distribution: role_distribution(&active),
        members: active.into_iter().map(team_member_response).collect(),
        pending_invites: pending.into_iter().map(team_member_response).collect(),
    }))
}

async fn list_members(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Vec<MemberResponse>>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "team:view").await?;
    let (offset, limit) = bounded_page(&query, 500)?;
    let members = state
        .application
        .list_members(organization_id)
        .await
        .map_err(application_error)?;
    Ok(Json(
        members
            .iter()
            .skip(offset)
            .take(limit)
            .map(member_response)
            .collect(),
    ))
}

async fn invite_member(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<InviteMemberRequest>,
) -> Result<Json<MemberResponse>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "team:invite").await?;
    if !valid_email(&input.email) || input.role_ids.is_empty() {
        return Err(invalid_request());
    }
    let result = state
        .application
        .invite_member(InviteMemberCommand {
            organization_id,
            email: input.email,
            role_ids: input.role_ids,
            invited_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(member_response(&result.value)))
}

async fn update_member(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "team:manage").await?;
    if input.role_ids.is_empty() {
        return Err(invalid_request());
    }
    let result = state
        .application
        .set_member_roles(SetMemberRolesCommand {
            member_id,
            organization_id,
            role_ids: input.role_ids,
            updated_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(member_response(&result.value)))
}

async fn remove_member(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "team:manage").await?;
    if state.marty_organization_id == Some(organization_id) {
        return Err(forbidden("ORGANIZATION.DEFAULT_MEMBERSHIP_IMMUTABLE"));
    }
    state
        .application
        .remove_member(RemoveMemberCommand {
            organization_id,
            member_id,
            removed_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

async fn list_api_keys(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Vec<ApiKeyResponse>>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "api-key:view").await?;
    let (offset, limit) = bounded_page(&query, 500)?;
    let api_keys = state
        .application
        .list_api_keys(organization_id)
        .await
        .map_err(application_error)?;
    Ok(Json(
        api_keys
            .iter()
            .skip(offset)
            .take(limit)
            .map(|api_key| api_key_response(api_key, None))
            .collect(),
    ))
}

async fn create_api_key(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "api-key:create").await?;
    let result = state
        .application
        .create_api_key(CreateApiKeyCommand {
            organization_id,
            name: input.name,
            created_by: context.principal_id,
            scopes: input.scopes,
            description: input.description,
            is_test: input.is_test,
            scope_type: ApiKeyScopeType::Organization,
            deployment_profile_id: None,
            rate_limit: None,
            expires_at: None,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(api_key_response(
        &result.value.api_key,
        Some(result.value.raw_key),
    )))
}

async fn revoke_api_key(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, key_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "api-key:revoke").await?;
    state
        .application
        .revoke_api_key(RevokeApiKeyCommand {
            organization_id,
            api_key_id: key_id,
            revoked_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

fn authenticate_service(
    state: &OrganizationHttpState,
    headers: &HeaderMap,
) -> Result<(), OrganizationHttpError> {
    authenticate_http_service(headers, &state.service_authenticator).map_err(trust_error)
}

fn authenticated_user_id(
    state: &OrganizationHttpState,
    headers: &HeaderMap,
) -> Result<String, OrganizationHttpError> {
    match authenticate_forwarded_http_request(headers, &state.service_authenticator)
        .map_err(trust_error)?
    {
        ForwardedPrincipal::User { user_id } => Ok(user_id),
        ForwardedPrincipal::ApiKey { .. } => Err(forbidden("ORGANIZATION.USER_REQUIRED")),
    }
}

fn authenticated_user_email(headers: &HeaderMap) -> Result<String, OrganizationHttpError> {
    headers
        .get("x-user-email")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| valid_email(value))
        .map(str::to_owned)
        .ok_or_else(invalid_request)
}

async fn authorize_membership(
    state: &OrganizationHttpState,
    headers: &HeaderMap,
    organization_id: Uuid,
) -> Result<OrganizationAuthorizationContext, OrganizationHttpError> {
    let principal = authenticate_forwarded_http_request(headers, &state.service_authenticator)
        .map_err(trust_error)?;
    state
        .application
        .authorize_organization_membership(organization_id, principal)
        .await
        .map_err(application_error)
}

async fn authorize_action(
    state: &OrganizationHttpState,
    headers: &HeaderMap,
    organization_id: Uuid,
    permission: &str,
) -> Result<OrganizationAuthorizationContext, OrganizationHttpError> {
    let principal = authenticate_forwarded_http_request(headers, &state.service_authenticator)
        .map_err(trust_error)?;
    state
        .application
        .authorize_organization_action(organization_id, principal, permission, false)
        .await
        .map_err(application_error)
}

async fn load_organization(
    state: &OrganizationHttpState,
    organization_id: Uuid,
) -> Result<Organization, OrganizationHttpError> {
    state
        .application
        .get_organization(organization_id)
        .await
        .map_err(application_error)?
        .ok_or_else(|| not_found("ORGANIZATION.NOT_FOUND"))
}

fn validate_create_request(input: &CreateOrganizationRequest) -> Result<(), OrganizationHttpError> {
    let name = Regex::new(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$").expect("static regex");
    if !(2..=64).contains(&input.name.len())
        || !name.is_match(&input.name)
        || input.display_name.trim().is_empty()
        || input.display_name.len() > 128
        || input
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 1_024)
        || input
            .contact_email
            .as_deref()
            .is_some_and(|value| !valid_email(value))
        || !matches!(input.visibility.as_str(), "PUBLIC" | "PRIVATE")
    {
        return Err(invalid_request());
    }
    let join_mechanism = input
        .join_mechanism
        .parse::<JoinMechanism>()
        .map_err(|_| invalid_request())?;
    input
        .org_type
        .parse::<OrganizationType>()
        .map_err(|_| invalid_request())?;
    if join_mechanism == JoinMechanism::Open && input.visibility != "PUBLIC" {
        return Err(invalid_request());
    }
    Ok(())
}

fn parse_update_patch(input: Value) -> Result<UpdateOrganizationPatch, OrganizationHttpError> {
    let object = strict_object(
        input,
        &[
            "name",
            "display_name",
            "org_type",
            "description",
            "contact_email",
            "contact_phone",
            "website",
            "visibility",
            "join_mechanism",
            "requires_approval",
        ],
    )?;
    if object.is_empty() {
        return Err(invalid_request());
    }
    let text = |name: &str| -> Result<Option<String>, OrganizationHttpError> {
        object
            .get(name)
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(invalid_request)
            })
            .transpose()
    };
    let nullable = |name: &str| -> Result<Option<Option<String>>, OrganizationHttpError> {
        object
            .get(name)
            .map(|value| {
                if value.is_null() {
                    Ok(None)
                } else {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .map(Some)
                        .ok_or_else(invalid_request)
                }
            })
            .transpose()
    };
    let name = text("name")?;
    if name
        .as_ref()
        .is_some_and(|value| value.len() > 64 || value.len() < 2)
    {
        return Err(invalid_request());
    }
    let display_name = text("display_name")?;
    if display_name.as_ref().is_some_and(|value| value.len() > 128) {
        return Err(invalid_request());
    }
    let org_type = text("org_type")?
        .as_deref()
        .map(str::parse::<OrganizationType>)
        .transpose()
        .map_err(|_| invalid_request())?;
    let description = nullable("description")?;
    if description
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|value| value.len() > 1_024)
    {
        return Err(invalid_request());
    }
    let contact_email = nullable("contact_email")?;
    if contact_email
        .as_ref()
        .and_then(Option::as_deref)
        .is_some_and(|value| !valid_email(value))
    {
        return Err(invalid_request());
    }
    let contact_phone = nullable("contact_phone")?;
    if contact_phone
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|value| value.len() > 50)
    {
        return Err(invalid_request());
    }
    let website = nullable("website")?;
    if website
        .as_ref()
        .and_then(Option::as_deref)
        .is_some_and(|value| !valid_http_url(value))
    {
        return Err(invalid_request());
    }
    let visibility = text("visibility")?;
    if visibility
        .as_deref()
        .is_some_and(|value| !matches!(value, "PUBLIC" | "PRIVATE"))
    {
        return Err(invalid_request());
    }
    let join_mechanism = text("join_mechanism")?
        .as_deref()
        .map(str::parse::<JoinMechanism>)
        .transpose()
        .map_err(|_| invalid_request())?;
    let requires_approval = object
        .get("requires_approval")
        .map(|value| value.as_bool().ok_or_else(invalid_request))
        .transpose()?;
    Ok(UpdateOrganizationPatch {
        name,
        display_name,
        org_type,
        description,
        contact_email,
        contact_phone,
        website,
        visibility,
        join_mechanism,
        requires_approval,
        settings: None,
    })
}

fn strict_object(
    value: Value,
    allowed: &[&str],
) -> Result<Map<String, Value>, OrganizationHttpError> {
    let object = value.as_object().ok_or_else(invalid_request)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_request());
    }
    Ok(object.clone())
}

fn organization_response(
    organization: &Organization,
    membership: Option<&Member>,
) -> OrganizationResponse {
    OrganizationResponse {
        id: organization.id.to_string(),
        name: organization.name.clone(),
        display_name: organization
            .display_name
            .clone()
            .unwrap_or_else(|| organization.name.clone()),
        description: organization.description.clone(),
        join_code: organization.join_code.clone(),
        visibility: if organization.is_discoverable {
            "PUBLIC".into()
        } else {
            "PRIVATE".into()
        },
        owner_id: organization.owner_id.clone(),
        status: organization.status.as_str().into(),
        org_type: organization.org_type.as_str().into(),
        join_mechanism: organization.join_mechanism.as_str().into(),
        requires_approval: organization.requires_approval,
        is_discoverable: organization.is_discoverable,
        contact_email: organization.contact_email.clone(),
        contact_phone: organization.contact_phone.clone(),
        website: organization.website.clone(),
        created_at: organization.created_at.to_rfc3339(),
        updated_at: organization.updated_at.to_rfc3339(),
        membership: membership.map(membership_summary),
    }
}

fn membership_summary(member: &Member) -> MembershipSummaryResponse {
    MembershipSummaryResponse {
        roles: member
            .roles
            .iter()
            .map(|role| RoleSummaryResponse {
                id: role.id.to_string(),
                name: role.name.clone(),
                display_name: role.display_name.clone(),
            })
            .collect(),
        status: member.status.as_str().into(),
        permissions: member.effective_permissions().into_iter().collect(),
        has_org_console_access: member.has_org_console_access(),
        is_owner: member.is_owner(),
        joined_at: member.joined_at.map(|value| value.to_rfc3339()),
    }
}

fn member_response(member: &Member) -> MemberResponse {
    MemberResponse {
        id: member.id.to_string(),
        organization_id: member.organization_id.to_string(),
        user_id: (!member.user_id.is_empty()).then(|| member.user_id.clone()),
        email: member.email.clone(),
        roles: role_summaries(member),
        status: member.status.as_str().into(),
        permissions: member.effective_permissions().into_iter().collect(),
        has_org_console_access: member.has_org_console_access(),
        is_owner: member.is_owner(),
        invited_at: member.invited_at.map(|value| value.to_rfc3339()),
        joined_at: member.joined_at.map(|value| value.to_rfc3339()),
    }
}

fn team_member_response(member: &Member) -> TeamMemberResponse {
    TeamMemberResponse {
        id: member.id.to_string(),
        user_id: (!member.user_id.is_empty()).then(|| member.user_id.clone()),
        email: member.email.clone(),
        roles: role_summaries(member),
        status: member.status.as_str().into(),
        is_owner: member.is_owner(),
        has_org_console_access: member.has_org_console_access(),
        joined_at: member.joined_at.map(|value| value.to_rfc3339()),
        invited_at: member.invited_at.map(|value| value.to_rfc3339()),
    }
}

fn role_summaries(member: &Member) -> Vec<RoleSummaryResponse> {
    member
        .roles
        .iter()
        .map(|role| RoleSummaryResponse {
            id: role.id.to_string(),
            name: role.name.clone(),
            display_name: role.display_name.clone(),
        })
        .collect()
}

fn role_distribution(members: &[&Member]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::from([
        ("admin".to_owned(), 0),
        ("developer".to_owned(), 0),
        ("operator".to_owned(), 0),
    ]);
    for member in members {
        let mut seen = std::collections::BTreeSet::new();
        for role in &member.roles {
            let role_name = role.name.trim().to_ascii_lowercase();
            let bucket = match role_name.as_str() {
                "owner" | "admin" | "access_admin" => "admin",
                "developer" | "access_developer" => "developer",
                "operator" | "access_operator" => "operator",
                value => value,
            };
            if !bucket.is_empty() && seen.insert(bucket.to_owned()) {
                *counts.entry(bucket.to_owned()).or_default() += 1;
            }
        }
    }
    counts
}

fn api_key_response(api_key: &ApiKey, key: Option<String>) -> ApiKeyResponse {
    ApiKeyResponse {
        id: api_key.id.to_string(),
        organization_id: api_key.organization_id.to_string(),
        name: api_key.name.clone(),
        description: api_key.description.clone(),
        key_prefix: api_key.key_prefix.clone(),
        scope_type: api_key.scope_type.clone(),
        deployment_profile_id: api_key.deployment_profile_id.map(|value| value.to_string()),
        scopes: api_key.scopes.clone(),
        enabled: api_key.enabled,
        expires_at: api_key.expires_at.map(|value| value.to_rfc3339()),
        last_used_at: api_key.last_used_at.map(|value| value.to_rfc3339()),
        created_at: api_key.created_at.to_rfc3339(),
        updated_at: Some(api_key.updated_at.to_rfc3339()),
        key,
    }
}

fn lifecycle_response(organization: &Organization) -> OrganizationLifecycleResponse {
    let hosted_pilot = setting_bool(&organization.settings, "pilot_retention_enabled");
    let retention_days = setting_positive(&organization.settings, "pilot_retention_days", 30);
    let data_retention_mode = if hosted_pilot {
        "hosted_pilot_rolling_purge".into()
    } else {
        setting_string(&organization.settings, "data_retention_mode")
            .unwrap_or_else(|| "standard".into())
    };
    let audit_retention_days = if hosted_pilot || data_retention_mode != "standard" {
        setting_positive(
            &organization.settings,
            "audit_retention_days",
            if hosted_pilot { retention_days } else { 90 },
        )
    } else {
        90
    };
    OrganizationLifecycleResponse {
        created_at: organization.created_at.to_rfc3339(),
        compliance_profiles: organization
            .settings
            .get("compliance_profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        data_retention_mode,
        audit_retention_days,
        pilot_retention: hosted_pilot.then(|| PilotRetentionResponse {
            enabled: true,
            window_days: retention_days,
            scope_summary: format!(
                "Hosted Pilot data older than {retention_days} days is purge-eligible while admin access and deployment settings stay available."
            ),
            scope_items: [
                "Applications and uploaded evidence",
                "Issuance transactions and linked issued credentials",
                "Authorization sessions",
                "Issuance lifecycle events",
            ],
            access_behavior: "Purge affects retained pilot data only. Organization access, configuration, and API setup remain available.",
            last_purged_at: setting_string(
                &organization.settings,
                "pilot_retention_last_purged_at",
            ),
        }),
    }
}

fn environment_response(organization: &Organization) -> OrganizationEnvironmentResponse {
    OrganizationEnvironmentResponse {
        organization_id: organization.id.to_string(),
        environment: organization
            .settings
            .get("environment")
            .and_then(Value::as_str)
            .and_then(normalize_environment)
            .map(str::to_owned),
    }
}

fn preferences_response(preference: &crate::ConsoleContextPreference) -> PreferencesResponse {
    PreferencesResponse {
        last_view_mode: preference.last_view_mode.as_str().into(),
        last_active_org_id: preference.last_active_org_id.map(|value| value.to_string()),
    }
}

fn setting_bool(settings: &Map<String, Value>, name: &str) -> bool {
    settings.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn setting_positive(settings: &Map<String, Value>, name: &str, default: u64) -> u64 {
    settings
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn setting_string(settings: &Map<String, Value>, name: &str) -> Option<String> {
    settings
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn normalize_environment(value: &str) -> Option<&str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "development" => Some("development"),
        "staging" => Some("staging"),
        "production" => Some("production"),
        _ => None,
    }
}

fn valid_email(value: &str) -> bool {
    let value = value.trim();
    value.len() <= 254
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

fn valid_http_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn limit(query: &PaginationQuery, maximum: u32) -> u32 {
    query.limit.unwrap_or(100).min(maximum)
}

fn bounded_page(
    query: &PaginationQuery,
    maximum: u32,
) -> Result<(usize, usize), OrganizationHttpError> {
    if query.limit.is_some_and(|limit| limit > maximum) {
        return Err(invalid_request());
    }
    Ok((
        query.offset.unwrap_or(0) as usize,
        query.limit.unwrap_or(100) as usize,
    ))
}

fn default_organization_type() -> String {
    "startup".into()
}

fn default_visibility() -> String {
    "PRIVATE".into()
}

fn default_join_mechanism() -> String {
    "invite".into()
}

fn trust_error(error: HttpTrustError) -> OrganizationHttpError {
    match error {
        HttpTrustError::ServiceAuthenticationRequired
        | HttpTrustError::UserAuthenticationRequired => OrganizationHttpError {
            status: StatusCode::UNAUTHORIZED,
            detail: "ORGANIZATION.AUTHENTICATION_REQUIRED",
        },
        HttpTrustError::InvalidApiKeyContext => forbidden("ORGANIZATION.ACTION_NOT_AUTHORIZED"),
    }
}

fn application_error(error: OrganizationApplicationError) -> OrganizationHttpError {
    match error {
        OrganizationApplicationError::NotFound(_)
        | OrganizationApplicationError::MemberNotFound(_)
        | OrganizationApplicationError::RoleNotFound(_)
        | OrganizationApplicationError::PermissionNotFound(_)
        | OrganizationApplicationError::ApiKeyNotFound(_)
        | OrganizationApplicationError::PolicySetNotFound(_) => not_found("ORGANIZATION.NOT_FOUND"),
        OrganizationApplicationError::AuthenticationRequired => OrganizationHttpError {
            status: StatusCode::UNAUTHORIZED,
            detail: "ORGANIZATION.AUTHENTICATION_REQUIRED",
        },
        OrganizationApplicationError::MembershipRequired
        | OrganizationApplicationError::MembershipInactive
        | OrganizationApplicationError::ActionNotAuthorized
        | OrganizationApplicationError::OwnerCannotBeRemoved
        | OrganizationApplicationError::OwnerRoleRequired
        | OrganizationApplicationError::SystemRoleDeleteForbidden => {
            forbidden("ORGANIZATION.ACTION_NOT_AUTHORIZED")
        }
        OrganizationApplicationError::Repository(_)
        | OrganizationApplicationError::Messaging(_)
        | OrganizationApplicationError::Event(_)
        | OrganizationApplicationError::Migration(_) => OrganizationHttpError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            detail: "ORGANIZATION.BACKEND_UNAVAILABLE",
        },
        _ => invalid_request(),
    }
}

const fn invalid_request() -> OrganizationHttpError {
    OrganizationHttpError {
        status: StatusCode::BAD_REQUEST,
        detail: "ORGANIZATION.INVALID_REQUEST",
    }
}

const fn forbidden(detail: &'static str) -> OrganizationHttpError {
    OrganizationHttpError {
        status: StatusCode::FORBIDDEN,
        detail,
    }
}

const fn not_found(detail: &'static str) -> OrganizationHttpError {
    OrganizationHttpError {
        status: StatusCode::NOT_FOUND,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_update_parsing_preserves_omit_clear_and_replace() {
        let patch = parse_update_patch(json!({
            "display_name": "Updated",
            "description": null,
            "website": "https://example.com",
            "requires_approval": true
        }))
        .unwrap();
        assert_eq!(patch.display_name.as_deref(), Some("Updated"));
        assert_eq!(patch.description, Some(None));
        assert_eq!(patch.contact_email, None);
        assert_eq!(patch.website, Some(Some("https://example.com".into())));
        assert_eq!(patch.requires_approval, Some(true));
        assert!(parse_update_patch(json!({})).is_err());
        assert!(parse_update_patch(json!({"private": true})).is_err());
    }

    #[test]
    fn lifecycle_defaults_and_hosted_pilot_policy_match_legacy_behavior() {
        let now = Utc::now();
        let (mut organization, _) = Organization::create(crate::OrganizationCreate {
            name: "test-org".into(),
            owner_id: "owner".into(),
            org_type: OrganizationType::Startup,
            display_name: None,
            description: None,
            join_mechanism: JoinMechanism::Invite,
            requires_approval: false,
            is_discoverable: false,
            now,
        })
        .unwrap();
        let standard = lifecycle_response(&organization);
        assert_eq!(standard.data_retention_mode, "standard");
        assert_eq!(standard.audit_retention_days, 90);
        assert!(standard.pilot_retention.is_none());

        organization
            .settings
            .insert("pilot_retention_enabled".into(), Value::Bool(true));
        organization
            .settings
            .insert("pilot_retention_days".into(), json!(45));
        let pilot = lifecycle_response(&organization);
        assert_eq!(pilot.data_retention_mode, "hosted_pilot_rolling_purge");
        assert_eq!(pilot.audit_retention_days, 45);
        assert_eq!(pilot.pilot_retention.unwrap().window_days, 45);
    }

    #[test]
    fn team_snapshot_projection_preserves_buckets_aliases_and_pending_members() {
        let now = Utc::now();
        let organization_id = Uuid::new_v4();
        let role = |name: &str| crate::Role {
            id: Uuid::new_v4(),
            organization_id,
            name: name.into(),
            display_name: None,
            description: None,
            is_system: false,
            is_default_for_new_members: false,
            permissions: vec![crate::Permission::new("team", "view")],
            created_at: now,
            updated_at: now,
        };
        let mut owner = Member::create(
            organization_id,
            "owner",
            Some("owner@example.com".into()),
            MemberStatus::Active,
            now,
        );
        owner.roles = vec![role("owner"), role("access_admin")];
        let mut developer = Member::create(
            organization_id,
            "developer",
            Some("developer@example.com".into()),
            MemberStatus::Active,
            now,
        );
        developer.roles = vec![role("developer")];
        let mut invited =
            Member::create_invitation(organization_id, "invited@example.com", "owner", now);
        invited.roles = vec![role("operator")];

        let active = vec![&owner, &developer];
        let counts = role_distribution(&active);
        assert_eq!(counts["admin"], 1);
        assert_eq!(counts["developer"], 1);
        assert_eq!(counts["operator"], 0);
        assert_eq!(team_member_response(&invited).status, "invited");
        assert!(team_member_response(&invited).user_id.is_none());
    }

    #[test]
    fn raw_api_key_is_disclosed_only_by_the_creation_projection() {
        let now = Utc::now();
        let (api_key, raw_key) = ApiKey::create(
            crate::ApiKeySpec {
                organization_id: Uuid::new_v4(),
                name: "Automation".into(),
                created_by: "owner".into(),
                scopes: None,
                description: None,
                expires_at: None,
                now,
            },
            true,
        );
        let created = serde_json::to_value(api_key_response(&api_key, Some(raw_key))).unwrap();
        let listed = serde_json::to_value(api_key_response(&api_key, None)).unwrap();
        assert!(created["key"].as_str().unwrap().starts_with("mk_test_"));
        assert!(listed.get("key").is_none());
        assert!(listed.get("key_hash").is_none());
    }
}
