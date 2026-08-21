use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use mmf_security::ServiceTokenAuthenticator;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    application::validate_registry_sources_for_decision, Change, CreateProfileInput, IssuerEntity,
    IssuerEntityPatch, OrganizationProfilePatch, OrganizationTrustProfile, ProfilePatch,
    RelationshipPatch, RevocationPolicy, TimePolicy, TrustAnchorType, TrustProfile,
    TrustProfileApplication, TrustProfileApplicationError, TrustProfileIssuer,
    TrustProfileRepository, TrustProfileStatus, TrustRegistryEntry, TrustSource, TrustSourceType,
    ValidationRules,
};

#[derive(Clone, Debug, thiserror::Error)]
pub enum TrustRegistrySyncError {
    #[error("TRUST_PROFILE.REGISTRY_SYNC_UNAVAILABLE")]
    Unavailable,
    #[error("TRUST_PROFILE.REGISTRY_SYNC_FAILED: {0}")]
    Failed(String),
}

#[async_trait]
pub trait TrustRegistrySynchronizer: Send + Sync {
    async fn synchronize(&self, profile: TrustProfile) -> Result<Value, TrustRegistrySyncError>;
}

#[derive(Clone)]
pub struct TrustProfileHttpState {
    pub application: Arc<TrustProfileApplication>,
    pub repository: Arc<dyn TrustProfileRepository>,
    pub service_authenticator: Arc<ServiceTokenAuthenticator>,
    pub internal_api_key: Option<Arc<str>>,
    pub registry_synchronizer: Arc<dyn TrustRegistrySynchronizer>,
}

pub fn trust_profile_router(state: TrustProfileHttpState) -> Router {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/trust-profiles",
            get(list_organization_profiles).post(create_organization_profile),
        )
        .route(
            "/v1/organizations/{organization_id}/trust-profiles/{profile_id}",
            get(get_organization_profile).put(update_organization_profile),
        )
        .route(
            "/v1/trust-profiles",
            get(list_profiles).post(create_profile),
        )
        .route(
            "/v1/trust-profiles/{profile_id}",
            get(get_profile)
                .patch(update_profile)
                .delete(delete_profile),
        )
        .route(
            "/v1/trust-profiles/{profile_id}/activate",
            post(activate_profile),
        )
        .route(
            "/v1/trust-profiles/{profile_id}/suspend",
            post(suspend_profile),
        )
        .route(
            "/v1/trust-profiles/{profile_id}/registry-sync",
            post(synchronize_profile),
        )
        .route(
            "/v1/trust-profiles/{profile_id}/issuers",
            get(list_relationships).post(add_relationship),
        )
        .route(
            "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}",
            get(get_relationship)
                .patch(update_relationship)
                .delete(delete_relationship),
        )
        .route(
            "/internal/v1/trust-profiles/{profile_id}",
            get(internal_profile),
        )
        .route(
            "/internal/v1/resource-owners/trust-profiles/{profile_id}",
            get(profile_owner),
        )
        .route(
            "/internal/v1/resource-owners/issuer-entities/{issuer_entity_id}",
            get(issuer_owner),
        )
        .route("/v1/trust-frameworks", get(list_frameworks))
        .route("/v1/trust-frameworks/{framework_id}", get(get_framework))
        .route("/v1/trust-registry/sync", get(public_registry_sync))
        .route("/v1/trust-registry/csca", get(list_csca))
        .route("/v1/trust-registry/dsc", get(list_dsc))
        .route(
            "/v1/trust-registry/csca/{country_code}",
            get(list_country_csca),
        )
        .route("/v1/trust-registry/status", get(registry_status))
        .route(
            "/v1/issuer-entities",
            get(list_issuer_entities).post(create_issuer_entity),
        )
        .route(
            "/v1/issuer-entities/{issuer_entity_id}",
            get(get_issuer_entity)
                .patch(update_issuer_entity)
                .delete(delete_issuer_entity),
        )
        .with_state(state)
}

#[derive(Debug)]
pub struct TrustProfileHttpError {
    status: StatusCode,
    detail: String,
}

impl IntoResponse for TrustProfileHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"detail": self.detail}))).into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySyncConfigInput {
    protocol: String,
    refresh_interval_hours: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustSourceInput {
    source_type: String,
    url: Option<String>,
    certificate_pem: Option<String>,
    issuer_did: Option<String>,
    description: Option<String>,
    registry_sync: Option<RegistrySyncConfigInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimePolicyInput {
    #[serde(default = "default_clock_skew")]
    clock_skew_seconds: u32,
    #[serde(default)]
    require_freshness: bool,
    freshness_window_seconds: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProfileRequest {
    organization_id: String,
    name: String,
    description: Option<String>,
    #[serde(default = "default_profile_type")]
    profile_type: String,
    #[serde(default = "default_compliance")]
    compliance_status: String,
    #[serde(default)]
    trust_sources: Vec<TrustSourceInput>,
    validation_rules: Option<ValidationRules>,
    allowed_algorithms: Option<Vec<String>>,
    min_key_size_rsa: Option<u16>,
    min_key_size_ec: Option<u16>,
    require_key_usage: Option<bool>,
    max_chain_depth: Option<u8>,
    allow_self_signed: Option<bool>,
    revocation_policy: Option<RevocationPolicy>,
    revocation_profile_id: Option<String>,
    time_policy: Option<TimePolicyInput>,
    #[serde(default = "default_formats")]
    supported_formats: Vec<String>,
    allowed_issuers: Option<Vec<String>>,
    denied_issuers: Option<Vec<String>>,
    #[serde(default)]
    system_issuer_overrides: Map<String, Value>,
    #[serde(default)]
    compatible_compliance_codes: Vec<String>,
    verification_policy_set_id: Option<String>,
    #[serde(default)]
    auto_generated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOrganizationProfileRequest {
    framework_id: Uuid,
    name: String,
    display_name: Option<String>,
    description: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    use_case_tags: Vec<String>,
    #[serde(default = "default_compliance")]
    compliance_status: String,
    #[serde(default)]
    auto_generated: bool,
    revocation_policy: Option<Value>,
    time_policy: Option<Value>,
    allowed_algorithms: Option<Vec<String>>,
    allowed_formats: Option<Vec<String>>,
    allowed_issuers: Option<Vec<String>>,
    denied_issuers: Option<Vec<String>>,
    jurisdiction_filter: Option<Vec<String>>,
    #[serde(default = "empty_object")]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRelationshipRequest {
    issuer_id: Uuid,
    #[serde(default = "default_trust_level")]
    trust_level: u8,
    #[serde(default = "default_relationship_status")]
    relationship_status: String,
    #[serde(default = "default_cascade_policy")]
    cascade_revocation_policy: String,
    #[serde(default = "empty_object")]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateIssuerRequest {
    organization_id: String,
    issuer_id: String,
    #[serde(default = "default_issuer_type")]
    issuer_type: String,
    display_name: String,
    description: Option<String>,
    #[serde(default = "default_issuer_compliance")]
    compliance_status: String,
    accreditation_body: Option<String>,
    #[serde(default)]
    accreditations: Vec<String>,
    accreditation_date: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    trust_anchor_id: Option<String>,
    #[serde(default = "empty_object")]
    metadata: Value,
}

#[derive(Debug, Default, Deserialize)]
struct ListProfilesQuery {
    organization_id: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct RegistryQuery {
    since: Option<String>,
}

async fn create_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let user_id = trusted_user(&state, &headers)?;
    let allowed_was_provided = raw.get("allowed_issuers").is_some();
    let input: CreateProfileRequest = decode(raw)?;
    let now = Utc::now();
    let profile = TrustProfile {
        id: Uuid::new_v4(),
        organization_id: input.organization_id,
        name: input.name,
        description: input.description,
        status: TrustProfileStatus::Draft,
        profile_type: parse_enum(&input.profile_type, "profile_type")?,
        compliance_status: parse_enum(&input.compliance_status, "compliance_status")?,
        trust_sources: input
            .trust_sources
            .into_iter()
            .map(trust_source)
            .collect::<Result<_, _>>()?,
        validation_rules: validation_rules(
            input.validation_rules,
            input.allowed_algorithms,
            input.min_key_size_rsa,
            input.min_key_size_ec,
            input.require_key_usage,
            input.max_chain_depth,
            input.allow_self_signed,
        ),
        allowed_issuers: input.allowed_issuers,
        denied_issuers: input.denied_issuers,
        system_issuer_overrides: input.system_issuer_overrides,
        compatible_compliance_codes: input.compatible_compliance_codes,
        verification_policy_set_id: input.verification_policy_set_id,
        auto_generated: input.auto_generated,
        revocation_policy: input.revocation_policy.unwrap_or_default(),
        revocation_profile_id: input.revocation_profile_id,
        time_policy: input
            .time_policy
            .map(time_policy)
            .transpose()?
            .unwrap_or_default(),
        supported_formats: input
            .supported_formats
            .into_iter()
            .map(|value| value.to_ascii_uppercase())
            .collect(),
        created_at: now,
        updated_at: now,
    };
    let profile = state
        .application
        .create_profile(
            &user_id,
            CreateProfileInput {
                profile,
                allowed_issuers_was_provided: allowed_was_provided,
            },
        )
        .await
        .map_err(application_error)?;
    Ok(Json(profile_response(&profile)))
}

async fn list_profiles(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListProfilesQuery>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let user_id = trusted_user(&state, &headers)?;
    let organization_id = query
        .organization_id
        .as_deref()
        .ok_or_else(|| unprocessable("organization_id is required"))?;
    let profiles = state
        .application
        .profiles(
            &user_id,
            organization_id,
            query.offset.unwrap_or(0),
            query.limit.unwrap_or(100),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        profiles.iter().map(profile_response).collect(),
    )))
}

async fn get_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let user_id = trusted_user(&state, &headers)?;
    let profile = state
        .application
        .profile(&user_id, uuid(&profile_id, "profile_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(profile_response(&profile)))
}

async fn update_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let user_id = trusted_user(&state, &headers)?;
    let profile_id = uuid(&profile_id, "profile_id")?;
    let current = state
        .application
        .profile(&user_id, profile_id)
        .await
        .map_err(application_error)?;
    let object = object(raw)?;
    reject_unknown(
        &object,
        &[
            "name",
            "description",
            "profile_type",
            "compliance_status",
            "trust_sources",
            "validation_rules",
            "allowed_algorithms",
            "min_key_size_rsa",
            "min_key_size_ec",
            "require_key_usage",
            "max_chain_depth",
            "allow_self_signed",
            "revocation_policy",
            "revocation_profile_id",
            "time_policy",
            "supported_formats",
            "allowed_issuers",
            "denied_issuers",
            "system_issuer_overrides",
            "compatible_compliance_codes",
            "verification_policy_set_id",
            "auto_generated",
        ],
    )?;
    if object.is_empty() {
        return Err(unprocessable(
            "at least one Trust Profile field is required",
        ));
    }
    let validation_changed = [
        "validation_rules",
        "allowed_algorithms",
        "min_key_size_rsa",
        "min_key_size_ec",
        "require_key_usage",
        "max_chain_depth",
        "allow_self_signed",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    let validation_rules = if validation_changed {
        let nested = optional_field::<ValidationRules>(&object, "validation_rules")?;
        Change::Set(validation_rules(
            nested.or_else(|| Some(current.validation_rules.clone())),
            optional_field(&object, "allowed_algorithms")?,
            optional_field(&object, "min_key_size_rsa")?,
            optional_field(&object, "min_key_size_ec")?,
            optional_field(&object, "require_key_usage")?,
            optional_field(&object, "max_chain_depth")?,
            optional_field(&object, "allow_self_signed")?,
        ))
    } else {
        Change::Unchanged
    };
    let patch = ProfilePatch {
        name: required_change(&object, "name")?,
        description: nullable_change(&object, "description")?,
        profile_type: enum_change(&object, "profile_type")?,
        compliance_status: enum_change(&object, "compliance_status")?,
        trust_sources: trust_sources_change(&object)?,
        validation_rules,
        revocation_profile_id: nullable_change(&object, "revocation_profile_id")?,
        time_policy: time_policy_change(&object)?,
        supported_formats: uppercase_change(&object, "supported_formats")?,
        allowed_issuers: nullable_change(&object, "allowed_issuers")?,
        denied_issuers: nullable_change(&object, "denied_issuers")?,
        system_issuer_overrides: required_change(&object, "system_issuer_overrides")?,
        compatible_compliance_codes: required_change(&object, "compatible_compliance_codes")?,
        verification_policy_set_id: nullable_change(&object, "verification_policy_set_id")?,
        auto_generated: required_change(&object, "auto_generated")?,
        revocation_policy: required_change(&object, "revocation_policy")?,
    };
    let profile = state
        .application
        .update_profile(&user_id, profile_id, patch, Utc::now())
        .await
        .map_err(application_error)?;
    Ok(Json(profile_response(&profile)))
}

async fn activate_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let profile = state
        .application
        .activate_profile(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(profile_response(&profile)))
}

async fn suspend_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let profile = state
        .application
        .suspend_profile(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(profile_response(&profile)))
}

async fn delete_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    state
        .application
        .delete_profile(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

async fn synchronize_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let profile = state
        .application
        .profile(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
        )
        .await
        .map_err(application_error)?;
    let result = state
        .registry_synchronizer
        .synchronize(profile)
        .await
        .map_err(|error| unavailable(error.to_string()))?;
    Ok(Json(result))
}

async fn create_organization_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let user_id = trusted_user(&state, &headers)?;
    let input: CreateOrganizationProfileRequest = decode(raw)?;
    let now = Utc::now();
    let profile = OrganizationTrustProfile {
        id: Uuid::new_v4(),
        organization_id,
        framework_id: input.framework_id,
        name: input.name,
        display_name: input.display_name,
        description: input.description,
        enabled: input.enabled,
        use_case_tags: input.use_case_tags,
        compliance_status: parse_enum(&input.compliance_status, "compliance_status")?,
        auto_generated: input.auto_generated,
        revocation_policy: input.revocation_policy,
        time_policy: input.time_policy,
        allowed_algorithms: input.allowed_algorithms,
        allowed_formats: uppercase(input.allowed_formats),
        allowed_issuers: input.allowed_issuers,
        denied_issuers: input.denied_issuers,
        jurisdiction_filter: input.jurisdiction_filter,
        metadata: input.metadata,
        created_at: now,
        updated_at: now,
    };
    let profile = state
        .application
        .create_organization_profile(&user_id, profile)
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&profile)))
}

async fn list_organization_profiles(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let profiles = state
        .application
        .organization_profiles(&trusted_user(&state, &headers)?, &organization_id)
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        profiles.iter().map(serialize_without_nulls).collect(),
    )))
}

async fn get_organization_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path((organization_id, profile_id)): Path<(String, String)>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let profile = state
        .application
        .organization_profile(
            &trusted_user(&state, &headers)?,
            &organization_id,
            uuid(&profile_id, "profile_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&profile)))
}

async fn update_organization_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path((organization_id, profile_id)): Path<(String, String)>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let object = object(raw)?;
    reject_unknown(
        &object,
        &[
            "name",
            "display_name",
            "description",
            "enabled",
            "use_case_tags",
            "compliance_status",
            "auto_generated",
            "revocation_policy",
            "time_policy",
            "allowed_algorithms",
            "allowed_formats",
            "allowed_issuers",
            "denied_issuers",
            "jurisdiction_filter",
            "metadata",
        ],
    )?;
    if object.is_empty() {
        return Err(unprocessable(
            "at least one organization Trust Profile field is required",
        ));
    }
    let patch = OrganizationProfilePatch {
        name: required_change(&object, "name")?,
        display_name: nullable_change(&object, "display_name")?,
        description: nullable_change(&object, "description")?,
        enabled: required_change(&object, "enabled")?,
        use_case_tags: required_change(&object, "use_case_tags")?,
        compliance_status: enum_change(&object, "compliance_status")?,
        auto_generated: required_change(&object, "auto_generated")?,
        revocation_policy: nullable_change(&object, "revocation_policy")?,
        time_policy: nullable_change(&object, "time_policy")?,
        allowed_algorithms: nullable_change(&object, "allowed_algorithms")?,
        allowed_formats: nullable_uppercase_change(&object, "allowed_formats")?,
        allowed_issuers: nullable_change(&object, "allowed_issuers")?,
        denied_issuers: nullable_change(&object, "denied_issuers")?,
        jurisdiction_filter: nullable_change(&object, "jurisdiction_filter")?,
        metadata: required_change(&object, "metadata")?,
    };
    let profile = state
        .application
        .update_organization_profile(
            &trusted_user(&state, &headers)?,
            &organization_id,
            uuid(&profile_id, "profile_id")?,
            patch,
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&profile)))
}

async fn add_relationship(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let input: CreateRelationshipRequest = decode(raw)?;
    let now = Utc::now();
    let relationship = TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: uuid(&profile_id, "profile_id")?,
        issuer_id: input.issuer_id,
        trust_level: input.trust_level,
        relationship_status: parse_enum(&input.relationship_status, "relationship_status")?,
        cascade_revocation_policy: parse_enum(
            &input.cascade_revocation_policy,
            "cascade_revocation_policy",
        )?,
        metadata: input.metadata,
        created_at: now,
        updated_at: now,
    };
    let relationship = state
        .application
        .add_relationship(&trusted_user(&state, &headers)?, relationship)
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&relationship)))
}

async fn list_relationships(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Query(query): Query<ListProfilesQuery>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let relationships = state
        .application
        .relationships(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            query.offset.unwrap_or(0),
            query.limit.unwrap_or(100),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        relationships.iter().map(serialize_without_nulls).collect(),
    )))
}

async fn get_relationship(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path((profile_id, issuer_id)): Path<(String, String)>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let relationship = state
        .application
        .relationship(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            uuid(&issuer_id, "issuer_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&relationship)))
}

async fn update_relationship(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path((profile_id, issuer_id)): Path<(String, String)>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let object = object(raw)?;
    reject_unknown(
        &object,
        &[
            "trust_level",
            "relationship_status",
            "cascade_revocation_policy",
            "metadata",
        ],
    )?;
    if object.is_empty() {
        return Err(unprocessable(
            "at least one trust relationship field is required",
        ));
    }
    let patch = RelationshipPatch {
        trust_level: required_change(&object, "trust_level")?,
        relationship_status: enum_change(&object, "relationship_status")?,
        cascade_revocation_policy: enum_change(&object, "cascade_revocation_policy")?,
        metadata: required_change(&object, "metadata")?,
    };
    let relationship = state
        .application
        .update_relationship(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            uuid(&issuer_id, "issuer_id")?,
            patch,
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&relationship)))
}

async fn delete_relationship(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path((profile_id, issuer_id)): Path<(String, String)>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    state
        .application
        .delete_relationship(
            &trusted_user(&state, &headers)?,
            uuid(&profile_id, "profile_id")?,
            uuid(&issuer_id, "issuer_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

async fn create_issuer_entity(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let input: CreateIssuerRequest = decode(raw)?;
    let now = Utc::now();
    let issuer = IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: Some(input.organization_id),
        issuer_id: input.issuer_id,
        issuer_type: parse_enum(&input.issuer_type, "issuer_type")?,
        display_name: input.display_name,
        description: input.description,
        is_system_issuer: false,
        compliance_status: parse_enum(&input.compliance_status, "compliance_status")?,
        accreditation_body: input.accreditation_body,
        accreditations: input.accreditations,
        accreditation_date: optional_datetime(input.accreditation_date.as_deref())?,
        valid_from: optional_datetime(input.valid_from.as_deref())?.unwrap_or(now),
        valid_until: optional_datetime(input.valid_until.as_deref())?,
        trust_anchor_id: input.trust_anchor_id,
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        metadata: input.metadata,
        created_at: now,
        updated_at: now,
    };
    let issuer = state
        .application
        .create_issuer_entity(&trusted_user(&state, &headers)?, issuer)
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&issuer)))
}

async fn list_issuer_entities(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListProfilesQuery>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let issuers = state
        .application
        .issuer_entities(
            &trusted_user(&state, &headers)?,
            query.organization_id.as_deref(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        issuers.iter().map(serialize_without_nulls).collect(),
    )))
}

async fn get_issuer_entity(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let issuer = state
        .application
        .issuer_entity(
            &trusted_user(&state, &headers)?,
            uuid(&issuer_id, "issuer_entity_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&issuer)))
}

async fn update_issuer_entity(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let object = object(raw)?;
    reject_unknown(
        &object,
        &[
            "organization_id",
            "display_name",
            "description",
            "issuer_type",
            "compliance_status",
            "accreditation_body",
            "accreditations",
            "accreditation_date",
            "valid_from",
            "valid_until",
            "trust_anchor_id",
            "metadata",
            "revocation_reason",
        ],
    )?;
    let organization_id = required_field::<String>(&object, "organization_id")?;
    if object.len() == 1 {
        return Err(unprocessable(
            "at least one issuer entity field is required",
        ));
    }
    let patch = IssuerEntityPatch {
        display_name: required_change(&object, "display_name")?,
        description: nullable_change(&object, "description")?,
        issuer_type: enum_change(&object, "issuer_type")?,
        compliance_status: enum_change(&object, "compliance_status")?,
        accreditation_body: nullable_change(&object, "accreditation_body")?,
        accreditations: required_change(&object, "accreditations")?,
        accreditation_date: nullable_datetime_change(&object, "accreditation_date")?,
        valid_from: datetime_change(&object, "valid_from")?,
        valid_until: nullable_datetime_change(&object, "valid_until")?,
        trust_anchor_id: nullable_change(&object, "trust_anchor_id")?,
        metadata: required_change(&object, "metadata")?,
        revocation_reason: optional_field(&object, "revocation_reason")?,
    };
    let issuer = state
        .application
        .update_issuer_entity(
            &trusted_user(&state, &headers)?,
            &organization_id,
            uuid(&issuer_id, "issuer_entity_id")?,
            patch,
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&issuer)))
}

async fn delete_issuer_entity(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    state
        .application
        .delete_issuer_entity(
            &trusted_user(&state, &headers)?,
            uuid(&issuer_id, "issuer_entity_id")?,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

async fn list_frameworks(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, TrustProfileHttpError> {
    trusted_user(&state, &headers)?;
    let frameworks = state
        .application
        .frameworks()
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        frameworks.iter().map(serialize_without_nulls).collect(),
    )))
}

async fn get_framework(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(framework_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    trusted_user(&state, &headers)?;
    let framework = state
        .application
        .framework(uuid(&framework_id, "framework_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(serialize_without_nulls(&framework)))
}

async fn public_registry_sync(
    State(state): State<TrustProfileHttpState>,
    Query(query): Query<RegistryQuery>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let since = query
        .since
        .as_deref()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| bad_request("Invalid sync token"))
        })
        .transpose()?;
    let entries = state
        .application
        .registry_entries(None, None, true, since)
        .await
        .map_err(application_error)?;
    let status = state
        .application
        .registry_status()
        .await
        .map_err(application_error)?;
    Ok(Json(json!({
        "sync_token": status.current_sequence.to_string(),
        "sequence": status.current_sequence,
        "entries": entries.iter().map(registry_entry_response).collect::<Vec<_>>(),
        "has_more": false,
        "generated_at": Utc::now(),
    })))
}

async fn list_csca(
    State(state): State<TrustProfileHttpState>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    registry_entries_response(&state, Some(TrustAnchorType::Csca), None).await
}

async fn list_dsc(
    State(state): State<TrustProfileHttpState>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    registry_entries_response(&state, Some(TrustAnchorType::Dsc), None).await
}

async fn list_country_csca(
    State(state): State<TrustProfileHttpState>,
    Path(country): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    registry_entries_response(
        &state,
        Some(TrustAnchorType::Csca),
        Some(country.to_ascii_uppercase()),
    )
    .await
}

async fn registry_entries_response(
    state: &TrustProfileHttpState,
    anchor_type: Option<TrustAnchorType>,
    country: Option<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let entries = state
        .application
        .registry_entries(anchor_type, country.as_deref(), true, None)
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        entries.iter().map(registry_entry_response).collect(),
    )))
}

async fn registry_status(
    State(state): State<TrustProfileHttpState>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    let status = state
        .application
        .registry_status()
        .await
        .map_err(application_error)?;
    Ok(Json(json!({
        "status": "healthy",
        "current_sequence": status.current_sequence,
        "total_entries": status.total_entries,
        "current_entries": status.current_entries,
        "csca_entries": status.csca_entries,
        "dsc_entries": status.dsc_entries,
        "generated_at": Utc::now(),
    })))
}

async fn internal_profile(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    internal_service(&state, &headers)?;
    let profile = state
        .repository
        .profile_by_id(uuid(&profile_id, "profile_id")?)
        .await
        .map_err(repository_error)?
        .ok_or_else(|| not_found("Trust Profile not found"))?;
    validate_registry_sources_for_decision(&profile, Utc::now()).map_err(decision_error)?;
    let relationships = state
        .repository
        .profile_issuers(profile.id)
        .await
        .map_err(repository_error)?;
    let mut decisions = Vec::with_capacity(relationships.len());
    for relationship in relationships {
        let issuer = state
            .repository
            .issuer_entity_by_id(relationship.issuer_id)
            .await
            .map_err(repository_error)?
            .ok_or_else(|| {
                unavailable("Trust Profile contains an unresolved issuer relationship")
            })?;
        if issuer.organization_id.as_deref() != Some(&profile.organization_id)
            && !(issuer.organization_id.is_none() && issuer.is_system_issuer)
        {
            return Err(unavailable(
                "Trust Profile contains a cross-organization issuer relationship",
            ));
        }
        let keys = issuer
            .metadata
            .get("verification_keys")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        valid_verification_keys(&keys)?;
        decisions.push(json!({
            "issuer_id": issuer.issuer_id,
            "trust_level": relationship.trust_level,
            "relationship_status": relationship.relationship_status,
            "compliance_status": issuer.compliance_status,
            "accreditation_body": issuer.accreditation_body,
            "accreditations": issuer.accreditations,
            "valid_from": issuer.valid_from,
            "valid_until": issuer.valid_until,
            "revoked_at": issuer.revoked_at,
            "verification_keys": keys,
        }));
    }
    let mut response = profile_response(&profile);
    response
        .as_object_mut()
        .expect("profile response is an object")
        .insert("issuer_relationships".into(), Value::Array(decisions));
    append_imported_sources(&profile, &mut response)?;
    Ok(Json(strip_nulls(response)))
}

async fn profile_owner(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    internal_api_key(&state, &headers)?;
    let organization_id = state
        .application
        .profile_owner(uuid(&profile_id, "profile_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"organization_id": organization_id})))
}

async fn issuer_owner(
    State(state): State<TrustProfileHttpState>,
    headers: HeaderMap,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, TrustProfileHttpError> {
    internal_api_key(&state, &headers)?;
    let organization_id = state
        .application
        .issuer_owner(uuid(&issuer_id, "issuer_entity_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"organization_id": organization_id})))
}

fn profile_response(profile: &TrustProfile) -> Value {
    let mut methods = Vec::new();
    if profile.revocation_policy.check_crl {
        methods.push("CRL");
    }
    if profile.revocation_policy.check_ocsp {
        methods.push("OCSP");
    }
    if profile.revocation_policy.check_status_list {
        methods.push("STATUS_LIST");
    }
    let freshness = profile
        .time_policy
        .credential_freshness_hours
        .map(|hours| hours * 3600);
    strip_nulls(json!({
        "id": profile.id,
        "organization_id": profile.organization_id,
        "name": profile.name,
        "description": profile.description,
        "status": profile.status,
        "profile_type": profile.profile_type,
        "compliance_status": profile.compliance_status,
        "trust_sources": profile.trust_sources.iter().map(public_trust_source).collect::<Vec<_>>(),
        "allowed_algorithms": profile.validation_rules.allowed_algorithms,
        "revocation_policy": {
            "check_mode": profile.revocation_policy.check_mode,
            "cache_ttl_seconds": u32::from(profile.revocation_policy.cache_duration_hours) * 3600,
        },
        "revocation_services": {
            "enabled_methods": methods,
            "auto_discover": false,
            "merge_discovered": false,
        },
        "revocation_profile_id": profile.revocation_profile_id,
        "time_policy": {
            "clock_skew_seconds": profile.time_policy.max_clock_skew_seconds,
            "max_credential_age_seconds": freshness,
            "require_freshness": freshness.is_some(),
            "freshness_window_seconds": freshness,
        },
        "supported_formats": profile.supported_formats,
        "allowed_issuers": profile.allowed_issuers,
        "denied_issuers": profile.denied_issuers,
        "system_issuer_overrides": profile.system_issuer_overrides,
        "compatible_compliance_codes": profile.compatible_compliance_codes,
        "verification_policy_set_id": profile.verification_policy_set_id,
        "auto_generated": profile.auto_generated,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }))
}

fn public_trust_source(source: &TrustSource) -> Value {
    strip_nulls(json!({
        "source_type": source.source_type,
        "url": source.url,
        "certificate_pem": source.certificate_pem,
        "issuer_did": source.issuer_did,
        "description": source.description,
        "pinned_certificates": source.pinned_certificates,
        "registry_sync": source.registry_sync,
    }))
}

fn registry_entry_response(entry: &TrustRegistryEntry) -> Value {
    strip_nulls(json!({
        "entry_id": entry.id,
        "anchor_type": entry.anchor_type,
        "operation": entry.operation,
        "country_code": entry.country_code,
        "certificate_pem": entry.certificate_pem,
        "subject_key_id": entry.subject_key_id,
        "not_before": entry.not_before,
        "not_after": entry.not_after,
        "source": entry.source,
    }))
}

fn append_imported_sources(
    profile: &TrustProfile,
    response: &mut Value,
) -> Result<(), TrustProfileHttpError> {
    let sources = response
        .get_mut("trust_sources")
        .and_then(Value::as_array_mut)
        .expect("profile trust_sources is an array");
    for source in profile
        .trust_sources
        .iter()
        .filter(|source| source.enabled && source.registry_sync.is_some())
    {
        let state = marty_verification::trust_sync::RegistryImportState {
            sync_token: source.registry_sync_token.clone(),
            sequence: source.registry_sequence,
            entries: source
                .registry_entries
                .iter()
                .map(|(id, value)| {
                    serde_json::from_value(value.clone())
                        .map(|entry| (id.clone(), entry))
                        .map_err(|_| unavailable("Trust Profile registry state is invalid"))
                })
                .collect::<Result<_, _>>()?,
            synchronized_at: source.registry_last_synced_at,
        };
        for entry in state.entries.values() {
            sources.push(json!({
                "source_type": if entry.anchor_type == marty_verification::trust_sync::AnchorType::Csca {
                    "ROOT_CA"
                } else {
                    "PINNED_ISSUER"
                },
                "certificate_pem": entry.certificate_pem,
                "description": format!("Imported {:?} from {}", entry.anchor_type, source.url.as_deref().unwrap_or("registry")),
                "pinned_certificates": [],
            }));
        }
    }
    Ok(())
}

fn valid_verification_keys(value: &Value) -> Result<(), TrustProfileHttpError> {
    let keys = value
        .as_array()
        .filter(|keys| keys.len() <= 32)
        .ok_or_else(|| unavailable("Trust Profile contains invalid issuer verification keys"))?;
    if keys.iter().any(|key| {
        key.as_object()
            .and_then(|key| key.get("kty"))
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return Err(unavailable(
            "Trust Profile contains invalid issuer verification keys",
        ));
    }
    crate::reject_private_custody_metadata(value)
        .map_err(|_| unavailable("Trust Profile contains invalid issuer verification keys"))
}

fn trust_source(input: TrustSourceInput) -> Result<TrustSource, TrustProfileHttpError> {
    let source_type = source_type(&input.source_type)?;
    let registry_sync = input.registry_sync.map(|config| {
        json!({
            "protocol": config.protocol,
            "refresh_interval_hours": config.refresh_interval_hours,
        })
    });
    let refresh_interval_hours = registry_sync
        .as_ref()
        .and_then(|value| value.get("refresh_interval_hours"))
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(24);
    Ok(TrustSource {
        id: Uuid::new_v4(),
        name: input
            .description
            .clone()
            .or_else(|| input.url.clone())
            .or_else(|| input.issuer_did.clone())
            .unwrap_or_else(|| "Trust Source".into()),
        source_type,
        url: input.url,
        certificate_pem: input.certificate_pem,
        issuer_did: input.issuer_did,
        description: input.description,
        pinned_certificates: vec![],
        refresh_interval_hours,
        enabled: true,
        registry_sync,
        registry_sync_token: None,
        registry_sequence: 0,
        registry_entries: Map::new(),
        registry_last_synced_at: None,
        extensions: Map::new(),
    })
}

fn source_type(value: &str) -> Result<TrustSourceType, TrustProfileHttpError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "registry" | "trust_list" => Ok(TrustSourceType::TrustList),
        "allowlist" | "pinned_issuer" => Ok(TrustSourceType::PinnedIssuer),
        "pinned_root" | "root_ca" => Ok(TrustSourceType::RootCa),
        "pkd" | "pkd_url" => Ok(TrustSourceType::PkdUrl),
        _ => Err(unprocessable("source_type is invalid")),
    }
}

#[allow(clippy::too_many_arguments)]
fn validation_rules(
    nested: Option<ValidationRules>,
    algorithms: Option<Vec<String>>,
    rsa: Option<u16>,
    ec: Option<u16>,
    key_usage: Option<bool>,
    depth: Option<u8>,
    self_signed: Option<bool>,
) -> ValidationRules {
    let mut rules = nested.unwrap_or_default();
    if let Some(value) = algorithms {
        rules.allowed_algorithms = value;
    }
    if let Some(value) = rsa {
        rules.min_key_size_rsa = value;
    }
    if let Some(value) = ec {
        rules.min_key_size_ec = value;
    }
    if let Some(value) = key_usage {
        rules.require_key_usage = value;
    }
    if let Some(value) = depth {
        rules.max_chain_depth = value;
    }
    if let Some(value) = self_signed {
        rules.allow_self_signed = value;
    }
    rules
}

fn time_policy(input: TimePolicyInput) -> Result<TimePolicy, TrustProfileHttpError> {
    if input.require_freshness && input.freshness_window_seconds.is_none() {
        return Err(unprocessable(
            "freshness_window_seconds is required when freshness is enabled",
        ));
    }
    if input
        .freshness_window_seconds
        .is_some_and(|value| value == 0 || value % 3600 != 0)
    {
        return Err(unprocessable(
            "freshness_window_seconds must use whole-hour precision",
        ));
    }
    Ok(TimePolicy {
        max_clock_skew_seconds: input.clock_skew_seconds,
        credential_freshness_hours: input.freshness_window_seconds.map(|value| value / 3600),
        require_not_before: true,
        require_expiration: true,
    })
}

fn trusted_user(
    state: &TrustProfileHttpState,
    headers: &HeaderMap,
) -> Result<String, TrustProfileHttpError> {
    internal_service(state, headers)?;
    header(headers, "x-user-id")
        .map(str::to_owned)
        .ok_or_else(|| unauthorized("TRUST_PROFILE.AUTHENTICATION_REQUIRED"))
}

fn internal_service(
    state: &TrustProfileHttpState,
    headers: &HeaderMap,
) -> Result<(), TrustProfileHttpError> {
    state
        .service_authenticator
        .authenticate(header(headers, "x-service-token"))
        .map_err(|_| unauthorized("TRUST_PROFILE.SERVICE_AUTHENTICATION_REQUIRED"))
}

fn internal_api_key(
    state: &TrustProfileHttpState,
    headers: &HeaderMap,
) -> Result<(), TrustProfileHttpError> {
    let expected = state
        .internal_api_key
        .as_deref()
        .ok_or_else(|| unavailable("Internal API key is not configured"))?;
    let supplied = header(headers, "x-api-key").unwrap_or_default();
    if supplied.len() == expected.len()
        && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
    {
        Ok(())
    } else {
        Err(unauthorized("Invalid internal API key"))
    }
}

fn application_error(error: TrustProfileApplicationError) -> TrustProfileHttpError {
    use crate::TrustAuthorizationError;
    match error {
        TrustProfileApplicationError::NotFound(_) => not_found("Resource not found"),
        TrustProfileApplicationError::Forbidden(message) => forbidden(message),
        TrustProfileApplicationError::Conflict(message) => conflict(message),
        TrustProfileApplicationError::Invalid(message) => unprocessable(message),
        TrustProfileApplicationError::Authorization(
            TrustAuthorizationError::MembershipRequired,
        ) => forbidden("TRUST_PROFILE.MEMBERSHIP_REQUIRED"),
        TrustProfileApplicationError::Authorization(
            TrustAuthorizationError::PermissionRequired { resource, action },
        ) => forbidden(format!("Missing required permission: {resource}:{action}")),
        TrustProfileApplicationError::Authorization(TrustAuthorizationError::Unavailable) => {
            unavailable("TRUST_PROFILE.CONTROL_PLANE_UNAVAILABLE")
        }
        TrustProfileApplicationError::Domain(crate::TrustDomainError::RevokedIssuerTerminal) => {
            bad_request("Revoked issuer cannot be reinstated; create a new IssuerEntity instead")
        }
        TrustProfileApplicationError::Domain(error) => unprocessable(error.to_string()),
        TrustProfileApplicationError::Repository(error) => repository_error(error),
    }
}

fn decision_error(error: TrustProfileApplicationError) -> TrustProfileHttpError {
    match error {
        TrustProfileApplicationError::Conflict("registry_sync_protocol_missing")
        | TrustProfileApplicationError::Invalid("registry_sync_config")
        | TrustProfileApplicationError::Invalid("registry_sync_protocol")
        | TrustProfileApplicationError::Invalid("registry_sync_interval") => {
            unavailable("Trust Profile registry source has no supported sync protocol")
        }
        TrustProfileApplicationError::Conflict("registry_never_synchronized") => {
            unavailable("Trust Profile registry source has never synchronized")
        }
        TrustProfileApplicationError::Conflict("registry_stale") => {
            unavailable("Trust Profile registry source is stale")
        }
        TrustProfileApplicationError::Conflict("registry_state_invalid") => {
            unavailable("Trust Profile registry state is invalid")
        }
        other => application_error(other),
    }
}

fn repository_error(error: crate::TrustProfileRepositoryError) -> TrustProfileHttpError {
    unavailable(format!("TRUST_PROFILE.REPOSITORY_UNAVAILABLE: {error}"))
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, TrustProfileHttpError> {
    serde_json::from_value(value).map_err(|error| unprocessable(error.to_string()))
}

fn object(value: Value) -> Result<Map<String, Value>, TrustProfileHttpError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| unprocessable("request body must be an object"))
}

fn reject_unknown(
    object: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), TrustProfileHttpError> {
    if let Some(field) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(unprocessable(format!("unknown field: {field}")));
    }
    Ok(())
}

fn required_field<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<T, TrustProfileHttpError> {
    object
        .get(key)
        .cloned()
        .ok_or_else(|| unprocessable(format!("{key} is required")))
        .and_then(decode)
}

fn optional_field<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, TrustProfileHttpError> {
    object.get(key).cloned().map(decode).transpose()
}

fn required_change<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<T>, TrustProfileHttpError> {
    object
        .get(key)
        .cloned()
        .map(decode)
        .transpose()
        .map(|value| value.map_or(Change::Unchanged, Change::Set))
}

fn nullable_change<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<Option<T>>, TrustProfileHttpError> {
    match object.get(key) {
        None => Ok(Change::Unchanged),
        Some(Value::Null) => Ok(Change::Set(None)),
        Some(value) => decode(value.clone()).map(|value| Change::Set(Some(value))),
    }
}

fn enum_change<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<T>, TrustProfileHttpError> {
    match object.get(key) {
        None => Ok(Change::Unchanged),
        Some(Value::String(value)) => parse_enum(value, key).map(Change::Set),
        Some(_) => Err(unprocessable(format!("{key} must be a string"))),
    }
}

fn trust_sources_change(
    object: &Map<String, Value>,
) -> Result<Change<Vec<TrustSource>>, TrustProfileHttpError> {
    let Some(value) = object.get("trust_sources") else {
        return Ok(Change::Unchanged);
    };
    decode::<Vec<TrustSourceInput>>(value.clone())?
        .into_iter()
        .map(trust_source)
        .collect::<Result<Vec<_>, _>>()
        .map(Change::Set)
}

fn uppercase_change(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<Vec<String>>, TrustProfileHttpError> {
    required_change::<Vec<String>>(object, key).map(|change| match change {
        Change::Unchanged => Change::Unchanged,
        Change::Set(values) => Change::Set(
            values
                .into_iter()
                .map(|value| value.to_ascii_uppercase())
                .collect(),
        ),
    })
}

fn nullable_uppercase_change(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<Option<Vec<String>>>, TrustProfileHttpError> {
    nullable_change::<Vec<String>>(object, key).map(|change| match change {
        Change::Unchanged => Change::Unchanged,
        Change::Set(value) => Change::Set(uppercase(value)),
    })
}

fn time_policy_change(
    object: &Map<String, Value>,
) -> Result<Change<TimePolicy>, TrustProfileHttpError> {
    object
        .get("time_policy")
        .cloned()
        .map(decode::<TimePolicyInput>)
        .transpose()?
        .map(time_policy)
        .transpose()
        .map(|value| value.map_or(Change::Unchanged, Change::Set))
}

fn datetime_change(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<DateTime<Utc>>, TrustProfileHttpError> {
    match optional_field::<String>(object, key)? {
        None => Ok(Change::Unchanged),
        Some(value) => parse_datetime(&value).map(Change::Set),
    }
}

fn nullable_datetime_change(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Change<Option<DateTime<Utc>>>, TrustProfileHttpError> {
    match object.get(key) {
        None => Ok(Change::Unchanged),
        Some(Value::Null) => Ok(Change::Set(None)),
        Some(value) => decode::<String>(value.clone())
            .and_then(|value| parse_datetime(&value))
            .map(|value| Change::Set(Some(value))),
    }
}

fn parse_enum<T: DeserializeOwned>(value: &str, field: &str) -> Result<T, TrustProfileHttpError> {
    serde_json::from_value(Value::String(value.trim().to_ascii_uppercase()))
        .map_err(|_| unprocessable(format!("{field} is invalid")))
}

fn optional_datetime(value: Option<&str>) -> Result<Option<DateTime<Utc>>, TrustProfileHttpError> {
    value.map(parse_datetime).transpose()
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, TrustProfileHttpError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| unprocessable("datetime must be RFC 3339"))
}

fn uuid(value: &str, field: &str) -> Result<Uuid, TrustProfileHttpError> {
    Uuid::parse_str(value).map_err(|_| unprocessable(format!("{field} must be a UUID")))
}

fn serialize_without_nulls<T: serde::Serialize>(value: &T) -> Value {
    strip_nulls(serde_json::to_value(value).expect("domain serialization cannot fail"))
}

fn strip_nulls(mut value: Value) -> Value {
    match &mut value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() {
                *value = strip_nulls(value.take());
            }
        }
        Value::Array(array) => {
            for value in array {
                *value = strip_nulls(value.take());
            }
        }
        _ => {}
    }
    value
}

fn uppercase(values: Option<Vec<String>>) -> Option<Vec<String>> {
    values.map(|values| {
        values
            .into_iter()
            .map(|value| value.to_ascii_uppercase())
            .collect()
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn default_clock_skew() -> u32 {
    300
}
fn default_profile_type() -> String {
    "CUSTOM".into()
}
fn default_compliance() -> String {
    "SETUP_REQUIRED".into()
}
fn default_formats() -> Vec<String> {
    vec!["SD_JWT_VC".into(), "MDOC".into()]
}
fn default_true() -> bool {
    true
}
fn empty_object() -> Value {
    json!({})
}
fn default_trust_level() -> u8 {
    100
}
fn default_relationship_status() -> String {
    "TRUSTED".into()
}
fn default_cascade_policy() -> String {
    "NOTIFY_ONLY".into()
}
fn default_issuer_type() -> String {
    "ORGANIZATION".into()
}
fn default_issuer_compliance() -> String {
    "COMPLIANT".into()
}

fn bad_request(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::BAD_REQUEST,
        detail: detail.into(),
    }
}
fn unauthorized(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::UNAUTHORIZED,
        detail: detail.into(),
    }
}
fn forbidden(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::FORBIDDEN,
        detail: detail.into(),
    }
}
fn not_found(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::NOT_FOUND,
        detail: detail.into(),
    }
}
fn conflict(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::CONFLICT,
        detail: detail.into(),
    }
}
fn unprocessable(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        detail: detail.into(),
    }
}
fn unavailable(detail: impl Into<String>) -> TrustProfileHttpError {
    TrustProfileHttpError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        detail: detail.into(),
    }
}
