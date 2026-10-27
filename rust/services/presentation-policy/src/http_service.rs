use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{TimeZone, Utc};
use mmf_security::ServiceTokenAuthenticator;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    evaluate_verified_facts_json, AlternativeRequirement, ClaimConstraint, ConstraintType,
    CredentialRequirement, DisplayMetadata, FreshnessPolicy, HolderBinding, IssuerConstraints,
    PolicyApplication, PolicyApplicationError, PolicyStatus, PresentationPolicy, RequestPurpose,
    RequestedClaim,
};

const MAX_PRESENTATION_BYTES: usize = 1_000_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatePresentationRequest {
    pub vp_token: Value,
    pub trust_profile_id: Option<String>,
    pub nonce: Option<String>,
    pub audience: Option<String>,
    #[serde(default)]
    pub context: Map<String, Value>,
    /// Parsed only from workload-authenticated gRPC; still unverified metadata.
    #[serde(skip)]
    pub oid4vp_transport: Option<marty_oid4vp_contract::Oid4vpEvaluationTransportV1>,
    /// Set by the internal gRPC adapter (which is workload-authenticated in
    /// deployed configuration). HTTP JSON cannot assert this marker.
    #[serde(skip)]
    pub trusted_internal_context: bool,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum PresentationVerificationError {
    #[error("PRESENTATION_POLICY.NATIVE_BACKEND_UNAVAILABLE")]
    Unavailable,
    #[error("PRESENTATION_POLICY.VERIFICATION_FAILED: {0}")]
    Failed(String),
}

/// Resolves raw presentation input into cryptographically verified facts.
/// Implementations must perform signature, trust, status, and binding checks;
/// the HTTP service never interprets an unverified token as policy facts.
#[async_trait]
pub trait PresentationVerificationOrchestrator: Send + Sync {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError>;

    async fn verify_material(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<VerifiedPolicyMaterial, PresentationVerificationError> {
        Ok(VerifiedPolicyMaterial::facts_only(
            self.verify(policy, request).await?,
        ))
    }
}

/// Policy facts have Core's strict schema; authenticated identity provenance
/// stays outside those facts until the result is bound to unique evidence.
pub struct VerifiedPolicyMaterial {
    pub(crate) policy_facts: Value,
    pub(crate) authenticated_outer_jti: Option<String>,
}

impl VerifiedPolicyMaterial {
    pub fn facts_only(policy_facts: Value) -> Self {
        Self {
            policy_facts,
            authenticated_outer_jti: None,
        }
    }

    pub fn policy_facts(&self) -> &Value {
        &self.policy_facts
    }

    pub fn authenticated_outer_jti(&self) -> Option<&str> {
        self.authenticated_outer_jti.as_deref()
    }
}

#[derive(Clone)]
pub struct PresentationPolicyHttpState {
    pub application: Arc<PolicyApplication>,
    pub verification: Arc<dyn PresentationVerificationOrchestrator>,
    pub service_authenticator: Arc<ServiceTokenAuthenticator>,
}

pub fn presentation_policy_router(state: PresentationPolicyHttpState) -> Router {
    Router::new()
        .route(
            "/internal/v1/resource-owners/presentation-policies/{policy_id}",
            get(policy_owner),
        )
        .route(
            "/v1/presentation-policies",
            get(list_policies).post(create_policy),
        )
        .route("/v1/presentation-policies/evaluate", post(evaluate_inline))
        .route(
            "/v1/presentation-policies/{policy_id}",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .route(
            "/v1/presentation-policies/{policy_id}/activate",
            post(activate_policy),
        )
        .route(
            "/v1/presentation-policies/{policy_id}/suspend",
            post(suspend_policy),
        )
        .route(
            "/v1/presentation-policies/{policy_id}/new-version",
            post(new_version),
        )
        .route(
            "/v1/presentation-policies/{policy_id}/evaluate",
            post(evaluate_saved),
        )
        .with_state(state)
}

#[derive(Debug)]
pub struct PresentationPolicyHttpError {
    pub(crate) status: StatusCode,
    pub(crate) detail: String,
}

impl IntoResponse for PresentationPolicyHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"detail": self.detail}))).into_response()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimConstraintRequest {
    claim_name: String,
    #[serde(default = "default_constraint")]
    constraint_type: ConstraintType,
    value: Option<Value>,
    description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedClaimRequest {
    claim_name: String,
    #[serde(default)]
    display_name: String,
    description: Option<String>,
    #[serde(default = "default_true")]
    required: bool,
    #[serde(default = "default_true")]
    selective_disclosure: bool,
    #[serde(default = "default_true")]
    accept_derived: bool,
    predicate_spec: Option<Value>,
    #[serde(default)]
    constraints: Vec<ClaimConstraintRequest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolRequiredClaimRequest {
    claim_name: String,
    credential_type: Option<String>,
    value_constraint: Option<Value>,
    predicate_spec: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequirementRequest {
    credential_template_id: String,
    #[serde(default)]
    display_name: String,
    description: Option<String>,
    #[serde(default = "default_true")]
    required: bool,
    #[serde(default = "default_credential_format")]
    credential_payload_format: String,
    requested_claims: Vec<RequestedClaimRequest>,
    trust_profile_id: Option<String>,
    max_age_seconds: Option<u64>,
    #[serde(default)]
    require_fresh_issuance: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlternativeRequirementRequest {
    name: String,
    description: Option<String>,
    credential_requirements: Vec<CredentialRequirementRequest>,
    #[serde(default = "default_min_satisfied")]
    min_satisfied: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayMetadataRequest {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_purpose")]
    purpose: RequestPurpose,
    purpose_description: Option<String>,
    #[serde(default)]
    verifier_name: String,
    verifier_logo_url: Option<String>,
    privacy_policy_url: Option<String>,
    terms_of_service_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicyRequest {
    organization_id: String,
    name: String,
    description: Option<String>,
    purpose: Option<String>,
    display_metadata: Option<DisplayMetadataRequest>,
    #[serde(default)]
    required_claims: Vec<ProtocolRequiredClaimRequest>,
    #[serde(default)]
    accepted_credential_types: Vec<String>,
    trust_profile_id: Option<String>,
    holder_binding: Option<HolderBinding>,
    freshness: Option<FreshnessPolicy>,
    issuer_constraints: Option<IssuerConstraints>,
    #[serde(default = "default_ranking_strategy")]
    credential_ranking_strategy: String,
    credential_ranking_weights: Option<BTreeMap<String, f64>>,
    #[serde(default)]
    credential_requirements: Vec<CredentialRequirementRequest>,
    #[serde(default)]
    alternative_requirements: Vec<AlternativeRequirementRequest>,
    compliance_profile_id: Option<String>,
    #[serde(default)]
    prefer_predicates: bool,
    fallback_policy: Option<String>,
    #[serde(default)]
    supported_circuits: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UpdatePolicyRequest {
    name: Option<String>,
    description: Option<String>,
    purpose: Option<String>,
    display_metadata: Option<DisplayMetadataRequest>,
    required_claims: Option<Vec<ProtocolRequiredClaimRequest>>,
    accepted_credential_types: Option<Vec<String>>,
    trust_profile_id: Option<String>,
    holder_binding: Option<HolderBinding>,
    freshness: Option<FreshnessPolicy>,
    issuer_constraints: Option<IssuerConstraints>,
    credential_ranking_strategy: Option<String>,
    credential_ranking_weights: Option<BTreeMap<String, f64>>,
    credential_requirements: Option<Vec<CredentialRequirementRequest>>,
    alternative_requirements: Option<Vec<AlternativeRequirementRequest>>,
    compliance_profile_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineEvaluationRequest {
    organization_id: String,
    vp_token: Value,
    credential_requirements: Vec<CredentialRequirementRequest>,
    trust_profile_id: Option<String>,
    compliance_profile_id: Option<String>,
    nonce: Option<String>,
    audience: Option<String>,
    #[serde(default)]
    context: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: String,
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn create_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreatePolicyRequest>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let policy = build_policy(input, Utc::now())?;
    let policy = application
        .create(&principal, policy)
        .await
        .map_err(application_error)?;
    Ok(Json(policy_response(&policy)))
}

async fn list_policies(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let organization_id = parse_uuid(&query.organization_id, "organization_id")?;
    let limit = query.limit.unwrap_or(100);
    if limit > 500 {
        return Err(unprocessable("limit must be less than or equal to 500"));
    }
    let policies = application
        .list(&principal, organization_id)
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        policies
            .iter()
            .skip(query.offset.unwrap_or(0))
            .take(limit)
            .map(policy_response)
            .collect(),
    )))
}

async fn get_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let policy = application
        .get(&principal, parse_uuid(&policy_id, "policy_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(policy_response(&policy)))
}

async fn update_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
    Json(input): Json<UpdatePolicyRequest>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let mut policy = application
        .get_for_update(&principal, parse_uuid(&policy_id, "policy_id")?)
        .await
        .map_err(application_error)?;
    apply_update(&mut policy, input, Utc::now())?;
    let policy = application
        .update(&principal, policy)
        .await
        .map_err(application_error)?;
    Ok(Json(policy_response(&policy)))
}

async fn activate_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    lifecycle(&state, &headers, &policy_id, true).await
}

async fn suspend_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    lifecycle(&state, &headers, &policy_id, false).await
}

async fn lifecycle(
    state: &PresentationPolicyHttpState,
    headers: &HeaderMap,
    policy_id: &str,
    activate: bool,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(state, headers)?;
    let id = parse_uuid(policy_id, "policy_id")?;
    let result = if activate {
        application.activate(&principal, id, Utc::now()).await
    } else {
        application.suspend(&principal, id, Utc::now()).await
    };
    Ok(Json(policy_response(&result.map_err(application_error)?)))
}

async fn new_version(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let policy = application
        .new_version(
            &principal,
            parse_uuid(&policy_id, "policy_id")?,
            Uuid::new_v4(),
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(policy_response(&policy)))
}

async fn delete_policy(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    application
        .delete(&principal, parse_uuid(&policy_id, "policy_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success": true})))
}

async fn evaluate_saved(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
    Json(request): Json<EvaluatePresentationRequest>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let policy = application
        .get_for_evaluation(&principal, parse_uuid(&policy_id, "policy_id")?)
        .await
        .map_err(application_error)?;
    evaluate(&state, &policy, &request).await.map(Json)
}

async fn evaluate_inline(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Json(input): Json<InlineEvaluationRequest>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    let (application, principal) = trusted_application(&state, &headers)?;
    let organization_id = parse_uuid(&input.organization_id, "organization_id")?;
    application
        .authorize_inline_evaluation(&principal, organization_id)
        .await
        .map_err(application_error)?;
    if input.credential_requirements.is_empty() {
        return Err(unprocessable("credential_requirements must not be empty"));
    }
    let now = Utc::now();
    let policy = PresentationPolicy {
        id: Uuid::new_v4(),
        organization_id,
        name: "Inline Policy".into(),
        description: None,
        status: PolicyStatus::Active,
        display_metadata: default_display(None),
        required_claims: vec![],
        accepted_credential_types: vec![],
        credential_requirements: convert_requirements(input.credential_requirements)?,
        alternative_requirements: vec![],
        presentation_proof_required: false,
        trust_profile_id: optional_uuid(input.trust_profile_id.as_deref(), "trust_profile_id")?,
        holder_binding: HolderBinding::default(),
        freshness: None,
        issuer_constraints: None,
        credential_ranking_strategy: default_ranking_strategy(),
        credential_ranking_weights: None,
        purpose: None,
        compliance_profile_id: optional_uuid(
            input.compliance_profile_id.as_deref(),
            "compliance_profile_id",
        )?,
        prefer_predicates: false,
        fallback_policy: None,
        supported_circuits: vec![],
        version: 1,
        created_at: now,
        updated_at: now,
    };
    policy.validate().map_err(domain_error)?;
    let request = EvaluatePresentationRequest {
        vp_token: input.vp_token,
        trust_profile_id: input.trust_profile_id,
        nonce: input.nonce,
        audience: input.audience,
        context: input.context,
        oid4vp_transport: None,
        trusted_internal_context: false,
    };
    evaluate(&state, &policy, &request).await.map(Json)
}

async fn evaluate(
    state: &PresentationPolicyHttpState,
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Value, PresentationPolicyHttpError> {
    evaluate_policy(state.verification.as_ref(), policy, request).await
}

pub(crate) async fn evaluate_policy(
    verification: &dyn PresentationVerificationOrchestrator,
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Value, PresentationPolicyHttpError> {
    if policy.status != PolicyStatus::Active {
        return Err(bad_request(&format!(
            "Policy is not active (status: {})",
            status_name(policy.status)
        )));
    }
    validate_evaluation_request(request)?;
    let material = verification
        .verify_material(policy, request)
        .await
        .map_err(verification_error)?;
    evaluate_verified_material_for_policy(material, policy, request)
}

pub fn evaluate_verified_facts_for_policy(
    verified: Value,
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Value, PresentationPolicyHttpError> {
    evaluate_verified_material_for_policy(
        VerifiedPolicyMaterial::facts_only(verified),
        policy,
        request,
    )
}

fn evaluate_verified_material_for_policy(
    material: VerifiedPolicyMaterial,
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Value, PresentationPolicyHttpError> {
    let VerifiedPolicyMaterial {
        mut policy_facts,
        authenticated_outer_jti,
    } = material;
    let object = policy_facts
        .as_object_mut()
        .ok_or_else(|| service_unavailable("PRESENTATION_POLICY.INVALID_VERIFICATION_EVIDENCE"))?;
    // Diagnostic evidence is NOT a native policy fact or authorization input.
    // Core's strict facts schema remains unchanged and rejects unknown fields.
    let authentication_diagnostic =
        object.remove(crate::verification::MDOC_AUTHENTICATION_DIAGNOSTIC);
    object.insert("policy".into(), service_policy(policy));
    let output = evaluate_verified_facts_json(&policy_facts.to_string()).map_err(domain_error)?;
    let native: Value = serde_json::from_str(&output)
        .map_err(|_| service_unavailable("PRESENTATION_POLICY.INVALID_NATIVE_RESULT"))?;
    Ok(project_evaluation(
        native,
        request,
        &policy_facts,
        authentication_diagnostic.as_ref(),
        authenticated_outer_jti.as_deref(),
    ))
}

fn build_policy(
    input: CreatePolicyRequest,
    now: chrono::DateTime<Utc>,
) -> Result<PresentationPolicy, PresentationPolicyHttpError> {
    validate_name(&input.name, "name", 255)?;
    validate_optional_len(input.description.as_deref(), "description", 2000)?;
    validate_optional_len(input.purpose.as_deref(), "purpose", 2000)?;
    let organization_id = parse_uuid(&input.organization_id, "organization_id")?;
    let holder_binding = input.holder_binding.unwrap_or_default().normalize();
    let required_claims = convert_protocol_claims(input.required_claims)?;
    let mut requirements = convert_requirements(input.credential_requirements)?;
    if !required_claims.is_empty() && requirements.is_empty() {
        requirements.push(synthetic_requirement(
            &input.name,
            input.description.clone(),
            &input.accepted_credential_types,
            input.trust_profile_id.as_deref(),
            input.freshness.as_ref(),
            &required_claims,
        )?);
    }
    let alternatives = convert_alternatives(input.alternative_requirements)?;
    let presentation_proof_required = holder_binding.required
        && requirements.is_empty()
        && required_claims.is_empty()
        && alternatives.is_empty();
    let display_metadata = input
        .display_metadata
        .map(|display| display.into_domain(input.purpose.as_deref()))
        .unwrap_or_else(|| default_display(input.purpose.as_deref()));
    let policy = PresentationPolicy {
        id: Uuid::new_v4(),
        organization_id,
        name: input.name,
        description: input.description,
        status: PolicyStatus::Draft,
        display_metadata,
        required_claims,
        accepted_credential_types: input.accepted_credential_types,
        credential_requirements: requirements,
        alternative_requirements: alternatives,
        presentation_proof_required,
        trust_profile_id: optional_uuid(input.trust_profile_id.as_deref(), "trust_profile_id")?,
        holder_binding,
        freshness: input.freshness,
        issuer_constraints: input.issuer_constraints,
        credential_ranking_strategy: input.credential_ranking_strategy.to_uppercase(),
        credential_ranking_weights: input.credential_ranking_weights,
        purpose: input.purpose,
        compliance_profile_id: optional_uuid(
            input.compliance_profile_id.as_deref(),
            "compliance_profile_id",
        )?,
        prefer_predicates: input.prefer_predicates,
        fallback_policy: input.fallback_policy.map(|value| value.to_uppercase()),
        supported_circuits: input.supported_circuits,
        version: 1,
        created_at: now,
        updated_at: now,
    };
    policy.validate().map_err(domain_error)?;
    Ok(policy)
}

pub(crate) fn build_policy_from_transport(
    value: Value,
    now: chrono::DateTime<Utc>,
) -> Result<PresentationPolicy, PresentationPolicyHttpError> {
    let input = serde_json::from_value(value)
        .map_err(|error| unprocessable(&format!("invalid policy request: {error}")))?;
    build_policy(input, now)
}

fn apply_update(
    policy: &mut PresentationPolicy,
    input: UpdatePolicyRequest,
    now: chrono::DateTime<Utc>,
) -> Result<(), PresentationPolicyHttpError> {
    if let Some(name) = input.name {
        validate_name(&name, "name", 255)?;
        policy.name = name;
    }
    if let Some(description) = input.description {
        validate_optional_len(Some(&description), "description", 2000)?;
        policy.description = Some(description);
    }
    if let Some(purpose) = input.purpose {
        validate_optional_len(Some(&purpose), "purpose", 2000)?;
        policy.display_metadata.purpose_description = Some(purpose.clone());
        policy.purpose = Some(purpose);
    }
    if let Some(display) = input.display_metadata {
        policy.display_metadata = display.into_domain(policy.purpose.as_deref());
    }
    if let Some(claims) = input.required_claims {
        policy.required_claims = convert_protocol_claims(claims)?;
    }
    if let Some(types) = input.accepted_credential_types {
        policy.accepted_credential_types = types;
    }
    if let Some(value) = input.trust_profile_id {
        policy.trust_profile_id = Some(parse_uuid(&value, "trust_profile_id")?);
    }
    if let Some(binding) = input.holder_binding {
        policy.holder_binding = binding.normalize();
    }
    if let Some(freshness) = input.freshness {
        policy.freshness = Some(freshness);
    }
    if let Some(constraints) = input.issuer_constraints {
        policy.issuer_constraints = Some(constraints);
    }
    if let Some(strategy) = input.credential_ranking_strategy {
        policy.credential_ranking_strategy = strategy.to_uppercase();
    }
    if let Some(weights) = input.credential_ranking_weights {
        policy.credential_ranking_weights = Some(weights);
    }
    if let Some(requirements) = input.credential_requirements {
        policy.credential_requirements = convert_requirements(requirements)?;
    }
    if let Some(alternatives) = input.alternative_requirements {
        policy.alternative_requirements = convert_alternatives(alternatives)?;
    }
    if let Some(value) = input.compliance_profile_id {
        policy.compliance_profile_id = Some(parse_uuid(&value, "compliance_profile_id")?);
    }
    if !policy.required_claims.is_empty() && policy.credential_requirements.is_empty() {
        policy.credential_requirements.push(synthetic_requirement(
            &policy.name,
            policy.description.clone(),
            &policy.accepted_credential_types,
            policy.trust_profile_id.map(|id| id.to_string()).as_deref(),
            policy.freshness.as_ref(),
            &policy.required_claims,
        )?);
    }
    policy.presentation_proof_required = policy.holder_binding.required
        && policy.credential_requirements.is_empty()
        && policy.required_claims.is_empty()
        && policy.alternative_requirements.is_empty();
    policy.updated_at = now;
    policy.validate().map_err(domain_error)
}

pub(crate) fn apply_update_from_transport(
    policy: &mut PresentationPolicy,
    value: Value,
    now: chrono::DateTime<Utc>,
) -> Result<(), PresentationPolicyHttpError> {
    let input = serde_json::from_value(value)
        .map_err(|error| unprocessable(&format!("invalid policy update: {error}")))?;
    apply_update(policy, input, now)
}

impl DisplayMetadataRequest {
    fn into_domain(self, policy_purpose: Option<&str>) -> DisplayMetadata {
        DisplayMetadata {
            title: self.title,
            description: self.description,
            purpose: self.purpose,
            purpose_description: self
                .purpose_description
                .or_else(|| policy_purpose.map(str::to_owned)),
            verifier_name: self.verifier_name,
            verifier_logo_url: self.verifier_logo_url,
            privacy_policy_url: self.privacy_policy_url,
            terms_of_service_url: self.terms_of_service_url,
        }
    }
}

fn convert_requirements(
    values: Vec<CredentialRequirementRequest>,
) -> Result<Vec<CredentialRequirement>, PresentationPolicyHttpError> {
    values.into_iter().map(convert_requirement).collect()
}

fn convert_requirement(
    value: CredentialRequirementRequest,
) -> Result<CredentialRequirement, PresentationPolicyHttpError> {
    if value.requested_claims.is_empty() {
        return Err(unprocessable("requested_claims must not be empty"));
    }
    Ok(CredentialRequirement {
        id: Uuid::new_v4(),
        credential_template_id: value.credential_template_id,
        display_name: value.display_name,
        description: value.description,
        required: value.required,
        credential_payload_format: value.credential_payload_format,
        requested_claims: value
            .requested_claims
            .into_iter()
            .map(convert_requested_claim)
            .collect(),
        trust_profile_id: optional_uuid(value.trust_profile_id.as_deref(), "trust_profile_id")?,
        max_age_seconds: value.max_age_seconds,
        require_fresh_issuance: value.require_fresh_issuance,
    })
}

fn convert_requested_claim(value: RequestedClaimRequest) -> RequestedClaim {
    RequestedClaim {
        id: Uuid::new_v4(),
        claim_name: value.claim_name,
        display_name: value.display_name,
        description: value.description,
        required: value.required,
        selective_disclosure: value.selective_disclosure,
        accept_derived: value.accept_derived,
        predicate_spec: value.predicate_spec,
        constraints: value
            .constraints
            .into_iter()
            .map(|constraint| ClaimConstraint {
                id: Uuid::new_v4(),
                claim_name: constraint.claim_name,
                constraint_type: constraint.constraint_type,
                value: constraint.value,
                description: constraint.description,
            })
            .collect(),
    }
}

fn convert_protocol_claims(
    values: Vec<ProtocolRequiredClaimRequest>,
) -> Result<Vec<RequestedClaim>, PresentationPolicyHttpError> {
    values
        .into_iter()
        .map(|value| {
            validate_name(&value.claim_name, "claim_name", 255)?;
            let constraints = value
                .value_constraint
                .map(|constraint| ClaimConstraint {
                    id: Uuid::new_v4(),
                    claim_name: value.claim_name.clone(),
                    constraint_type: ConstraintType::Equals,
                    value: Some(constraint),
                    description: None,
                })
                .into_iter()
                .collect();
            Ok(RequestedClaim {
                id: Uuid::new_v4(),
                display_name: value.claim_name.replace('_', " "),
                claim_name: value.claim_name,
                description: value
                    .credential_type
                    .map(|kind| format!("credential_type:{kind}")),
                required: true,
                selective_disclosure: true,
                accept_derived: true,
                predicate_spec: value.predicate_spec,
                constraints,
            })
        })
        .collect()
}

fn convert_alternatives(
    values: Vec<AlternativeRequirementRequest>,
) -> Result<Vec<AlternativeRequirement>, PresentationPolicyHttpError> {
    values
        .into_iter()
        .map(|value| {
            Ok(AlternativeRequirement {
                id: Uuid::new_v4(),
                name: value.name,
                description: value.description,
                credential_requirements: convert_requirements(value.credential_requirements)?,
                min_satisfied: value.min_satisfied,
            })
        })
        .collect()
}

fn synthetic_requirement(
    name: &str,
    description: Option<String>,
    accepted_types: &[String],
    trust_profile_id: Option<&str>,
    freshness: Option<&FreshnessPolicy>,
    claims: &[RequestedClaim],
) -> Result<CredentialRequirement, PresentationPolicyHttpError> {
    Ok(CredentialRequirement {
        id: Uuid::new_v4(),
        credential_template_id: accepted_types
            .first()
            .cloned()
            .unwrap_or_else(|| "protocol-inline".into()),
        display_name: name.to_owned(),
        description,
        required: true,
        credential_payload_format: default_credential_format(),
        requested_claims: claims.to_vec(),
        trust_profile_id: optional_uuid(trust_profile_id, "trust_profile_id")?,
        max_age_seconds: freshness.and_then(|value| value.max_age_seconds),
        require_fresh_issuance: false,
    })
}

pub(crate) fn policy_response(policy: &PresentationPolicy) -> Value {
    without_nulls(json!({
        "id": policy.id,
        "organization_id": policy.organization_id,
        "name": policy.name,
        "status": status_name(policy.status),
        "description": policy.description,
        "purpose": policy.purpose.as_ref().or(policy.display_metadata.purpose_description.as_ref()),
        "required_claims": policy.required_claims.iter().map(protocol_claim_response).collect::<Vec<_>>(),
        "accepted_credential_types": effective_accepted_types(policy),
        "display_metadata": policy.display_metadata,
        "credential_requirements": policy.credential_requirements.iter().map(requirement_response).collect::<Vec<_>>(),
        "alternative_requirements": policy.alternative_requirements.iter().map(alternative_response).collect::<Vec<_>>(),
        "compliance_profile_id": policy.compliance_profile_id,
        "trust_profile_id": policy.trust_profile_id,
        "holder_binding": holder_response(&policy.holder_binding),
        "freshness": policy.freshness,
        "prefer_predicates": policy.prefer_predicates,
        "supported_circuits": policy.supported_circuits,
        "fallback_policy": policy.fallback_policy,
        "issuer_constraints": policy.issuer_constraints,
        "credential_ranking_strategy": policy.credential_ranking_strategy.to_uppercase(),
        "credential_ranking_weights": policy.credential_ranking_weights,
        "version": policy.version,
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.to_rfc3339()
    }))
}

fn protocol_claim_response(claim: &RequestedClaim) -> Value {
    let equality = claim
        .constraints
        .iter()
        .find(|constraint| constraint.constraint_type == ConstraintType::Equals)
        .and_then(|constraint| constraint.value.clone());
    let credential_type = claim
        .description
        .as_deref()
        .and_then(|value| value.strip_prefix("credential_type:"));
    json!({
        "claim_name": claim.claim_name,
        "credential_type": credential_type,
        "value_constraint": equality,
        "predicate_spec": claim.predicate_spec
    })
}

fn requirement_response(requirement: &CredentialRequirement) -> Value {
    json!({
        "credential_template_id": requirement.credential_template_id,
        "display_name": requirement.display_name,
        "description": requirement.description,
        "required": requirement.required,
        "credential_payload_format": requirement.credential_payload_format,
        "requested_claims": requirement.requested_claims.iter().map(requested_claim_response).collect::<Vec<_>>(),
        "trust_profile_id": requirement.trust_profile_id,
        "max_age_seconds": requirement.max_age_seconds,
        "require_fresh_issuance": requirement.require_fresh_issuance
    })
}

fn requested_claim_response(claim: &RequestedClaim) -> Value {
    json!({
        "claim_name": claim.claim_name,
        "display_name": claim.display_name,
        "description": claim.description,
        "required": claim.required,
        "selective_disclosure": claim.selective_disclosure,
        "accept_derived": claim.accept_derived,
        "predicate_spec": claim.predicate_spec,
        "constraints": claim.constraints.iter().map(|constraint| json!({
            "claim_name": constraint.claim_name,
            "constraint_type": constraint.constraint_type,
            "value": constraint.value,
            "description": constraint.description
        })).collect::<Vec<_>>()
    })
}

fn alternative_response(alternative: &AlternativeRequirement) -> Value {
    json!({
        "name": alternative.name,
        "description": alternative.description,
        "credential_requirements": alternative.credential_requirements.iter().map(requirement_response).collect::<Vec<_>>(),
        "min_satisfied": alternative.min_satisfied
    })
}

fn holder_response(binding: &HolderBinding) -> Value {
    if binding.required {
        serde_json::to_value(binding).unwrap_or_else(|_| json!({"required": true}))
    } else {
        json!({"required": false})
    }
}

fn service_policy(policy: &PresentationPolicy) -> Value {
    let freshness = policy.holder_binding.proof_freshness.clone();
    json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "organization_id": policy.organization_id.to_string(),
        "credential_requirements": policy.credential_requirements.iter().map(service_requirement).collect::<Vec<_>>(),
        "alternative_requirements": policy.alternative_requirements.iter().map(|alternative| json!({
            "id": alternative.id.to_string(),
            "name": alternative.name,
            "credential_requirements": alternative.credential_requirements.iter().map(service_requirement).collect::<Vec<_>>(),
            "min_satisfied": alternative.min_satisfied
        })).collect::<Vec<_>>(),
        "trust_profile_id": policy.trust_profile_id.map(|id| id.to_string()),
        "presentation_proof_required": policy.presentation_proof_required,
        "holder_binding": {
            "required": policy.holder_binding.required,
            "binding_methods": policy.holder_binding.binding_methods,
            "proof_profiles": policy.holder_binding.proof_profiles,
            "challenge_required": freshness.get("challenge_required").copied().unwrap_or(false),
            "audience_binding_required": freshness.get("audience_binding_required").copied().unwrap_or(false),
            "replay_detection_required": freshness.get("replay_detection_required").copied().unwrap_or(false),
            "max_proof_age_seconds": Value::Null
        },
        "freshness": policy.freshness,
        "issuer_constraints": policy.issuer_constraints,
        "allowed_issuers": [],
        "single_presentation": true
    })
}

fn service_requirement(requirement: &CredentialRequirement) -> Value {
    json!({
        "id": requirement.id.to_string(),
        "credential_template_id": requirement.credential_template_id,
        "required": requirement.required,
        "credential_payload_format": requirement.credential_payload_format,
        "requested_claims": requirement.requested_claims.iter().map(|claim| json!({
            "claim_name": claim.claim_name,
            "required": claim.required,
            "selective_disclosure": claim.selective_disclosure,
            "accept_derived": claim.accept_derived,
            "predicate_spec": claim.predicate_spec,
            "constraints": claim.constraints.iter().map(|constraint| json!({
                "claim_name": constraint.claim_name,
                "constraint_type": constraint.constraint_type,
                "value": constraint.value
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "trust_profile_id": requirement.trust_profile_id.map(|id| id.to_string()),
        "max_age_seconds": requirement.max_age_seconds,
        "require_fresh_issuance": requirement.require_fresh_issuance
    })
}

/// Match evaluated requirements to exactly one trusted internal evidence row.
/// An absent or ambiguous match cannot establish any verification check.
fn credential_evidence<'a>(verified: &'a Value, result: &Value) -> Option<&'a Value> {
    let template_id = result["credential_template_id"].as_str()?;
    let issuer_id = result["issuer_id"].as_str()?;
    let mut matches = verified["credentials"]
        .as_array()?
        .iter()
        .filter(|credential| {
            credential["issuer_id"].as_str() == Some(issuer_id)
                && credential["credential_template_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(template_id)))
        });
    let credential = matches.next()?;
    matches.next().is_none().then_some(credential)
}

/// Project names, never values, from the native kernel's authenticated mdoc
/// documents. Policy-filtered `verified_claims` cannot prove minimal disclosure.
/// The raw wallet request and requested claim list are deliberately not inputs.
fn authenticated_mdoc_disclosures(verified: &Value, result: &Value) -> Option<Value> {
    if verified["presentation_verified"] != true
        || verified["holder_binding_verified"] != true
        || verified["holder_binding_method"] != "DEVICE_KEY"
    {
        return None;
    }
    let credential = credential_evidence(verified, result)?;
    if credential["signature_verified"] != true || credential["credential_format"] != "mdoc" {
        return None;
    }
    let documents = credential["claims"]["_mdoc"]["documents"].as_array()?;
    if documents.len() != 1 {
        // This is also the native mdoc kernel's authentication boundary.
        return None;
    }
    let mut projected = Vec::new();
    for document in documents {
        let doc_type = document["doc_type"].as_str()?;
        let namespaces = document["namespaces"].as_object()?;
        let mut namespace_names = namespaces.keys().collect::<Vec<_>>();
        namespace_names.sort();
        let mut names = Map::new();
        for namespace in namespace_names {
            let mut claim_names = namespaces[namespace]
                .as_object()?
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            claim_names.sort();
            names.insert(namespace.clone(), json!(claim_names));
        }
        projected.push(json!({"doc_type": doc_type, "namespaces": names}));
    }
    Some(json!({"format": "mso_mdoc", "documents": projected}))
}

fn bound_authentication_diagnostic(
    native: &Value,
    request: &EvaluatePresentationRequest,
    verified: &Value,
    diagnostic: Option<&Value>,
) -> Option<marty_oid4vp_contract::BoundAuthenticationDiagnosticV1> {
    use marty_oid4vp_contract::{BoundAuthenticationDiagnosticV1, MdocAuthenticationDiagnosticV1};
    let credentials = verified["credentials"].as_array()?;
    if credentials.len() != 1
        || credentials
            .iter()
            .any(|credential| credential["signature_verified"] != false)
    {
        return None;
    }
    let authentication: MdocAuthenticationDiagnosticV1 =
        serde_json::from_value(diagnostic?.clone()).ok()?;
    BoundAuthenticationDiagnosticV1::bind(
        native["policy_id"].as_str()?,
        request.nonce.as_deref()?,
        request.vp_token.as_str()?,
        u32::try_from(credentials.len()).ok()?,
        authentication,
    )
    .ok()
}

fn project_evaluation(
    native: Value,
    request: &EvaluatePresentationRequest,
    verified: &Value,
    diagnostic: Option<&Value>,
    authenticated_outer_jti: Option<&str>,
) -> Value {
    let errors = native["errors"].as_array().cloned().unwrap_or_default();
    let error_codes = errors
        .iter()
        .filter_map(|error| error.get("code").cloned())
        .collect::<Vec<_>>();
    let credential_results = native["credential_results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|result| {
            let result_errors = result["errors"].as_array().cloned().unwrap_or_default();
            let codes = result_errors
                .iter()
                .filter_map(|error| error.get("code").cloned())
                .collect::<Vec<_>>();
            let messages = result_errors
                .iter()
                .filter_map(|error| error.get("message").cloned())
                .collect::<Vec<_>>();
            let evidence = credential_evidence(verified, result);
            let signature_valid = evidence
                .and_then(|credential| credential["signature_verified"].as_bool())
                .map(|verified| verified && !has_any_code(&codes, &["SignatureInvalid"]));
            // The identifier comes only from the verified JWT envelope. The exact
            // issuer/template match must identify one credential, never a fallback
            // label or a caller-supplied policy fact.
            let authenticated_credential_id = authenticated_outer_jti
                .filter(|id| !id.is_empty() && id.len() <= 2048 && !id.chars().any(char::is_control))
                .filter(|id| signature_valid == Some(true)
                    && evidence.and_then(|credential| credential["credential_id"].as_str()) == Some(*id));
            let status_checked = evidence.map(|credential| {
                credential["revocation_checked_at_epoch_seconds"].as_u64().is_some()
            });
            let status_evidence = evidence.filter(|_| status_checked == Some(true));
            json!({
                "credential_template_id": result["credential_template_id"],
                "satisfied": result["satisfied"],
                "issuer_did": result["issuer_id"],
                "issuer_name": Value::Null,
                "claim_results": result["claim_results"],
                "authenticated_disclosures": authenticated_mdoc_disclosures(verified, result),
                "trust_check_passed": evidence.and_then(|credential| credential["trust_profile_verified"].as_bool()).map(|verified| verified && !has_any_code(&codes, &["TrustProfileNotVerified", "IssuerNotAllowed", "IssuerTrustLevelInsufficient", "IssuerComplianceStatusMissing", "IssuerAccreditationMissing"])),
                "freshness_check_passed": !has_any_code(&codes, &["CredentialTimestampMissing", "CredentialTimestampFuture", "CredentialStale", "RevocationEvidenceStale"]),
                "signature_valid": signature_valid,
                "credential_id": authenticated_credential_id,
                "revocation_checked": status_checked,
                "not_revoked": status_evidence.and_then(|credential| credential["not_revoked"].as_bool()),
                "revocation_status": status_evidence.and_then(|credential| credential["credential_status"].as_str()),
                "error_codes": codes,
                "errors": messages,
                "warnings": result["warnings"]
            })
        })
        .collect::<Vec<_>>();
    let timestamp = native["evaluation_time_epoch_seconds"]
        .as_i64()
        .and_then(|seconds| Utc.timestamp_opt(seconds, 0).single())
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    without_nulls(json!({
        "result": native["result"],
        "policy_id": native["policy_id"],
        "policy_name": native["policy_name"],
        "credential_results": credential_results,
        (marty_oid4vp_contract::AUTHENTICATION_DIAGNOSTIC): bound_authentication_diagnostic(&native, request, verified, diagnostic),
        "total_requirements": native["total_requirements"],
        "satisfied_requirements": native["satisfied_requirements"],
        "required_satisfied": native["required_satisfied"],
        "required_total": native["required_total"],
        "decision": native["decision"],
        "decision_reason": native["decision_reason"],
        "error_codes": error_codes,
        "warnings": native["warnings"],
        "verified_claims": native["verified_claims"],
        "evaluation_timestamp": timestamp,
        "nonce": request.nonce
    }))
}

fn without_nulls(mut value: Value) -> Value {
    match &mut value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() {
                *value = without_nulls(value.take());
            }
        }
        Value::Array(items) => {
            for value in items {
                *value = without_nulls(value.take());
            }
        }
        _ => {}
    }
    value
}

fn has_any_code(codes: &[Value], expected: &[&str]) -> bool {
    codes.iter().filter_map(Value::as_str).any(|code| {
        expected
            .iter()
            .any(|candidate| equivalent_error_code(code, candidate))
    })
}

fn equivalent_error_code(left: &str, right: &str) -> bool {
    left.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .eq(right
            .bytes()
            .filter(u8::is_ascii_alphanumeric)
            .map(|byte| byte.to_ascii_lowercase()))
}

fn validate_evaluation_request(
    request: &EvaluatePresentationRequest,
) -> Result<(), PresentationPolicyHttpError> {
    if !request.vp_token.is_string() && !request.vp_token.is_object() {
        return Err(unprocessable("vp_token must be a string or object"));
    }
    if request.vp_token.to_string().len() > MAX_PRESENTATION_BYTES {
        return Err(unprocessable("vp_token exceeds 1000000 bytes"));
    }
    validate_optional_len(request.nonce.as_deref(), "nonce", 512)?;
    validate_optional_len(request.audience.as_deref(), "audience", 512)?;
    validate_optional_len(request.trust_profile_id.as_deref(), "trust_profile_id", 255)
}

fn effective_accepted_types(policy: &PresentationPolicy) -> Vec<String> {
    if policy.accepted_credential_types.is_empty() {
        policy
            .credential_requirements
            .iter()
            .map(|requirement| requirement.credential_template_id.clone())
            .collect()
    } else {
        policy.accepted_credential_types.clone()
    }
}

fn default_display(purpose: Option<&str>) -> DisplayMetadata {
    DisplayMetadata {
        title: String::new(),
        description: String::new(),
        purpose: RequestPurpose::IdentityVerification,
        purpose_description: purpose.map(str::to_owned),
        verifier_name: String::new(),
        verifier_logo_url: None,
        privacy_policy_url: None,
        terms_of_service_url: None,
    }
}

async fn policy_owner(
    State(state): State<PresentationPolicyHttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<Value>, PresentationPolicyHttpError> {
    authenticate_service(&state, &headers)?;
    let policy = state
        .application
        .get_for_internal_service(parse_uuid(&policy_id, "policy_id")?)
        .await
        .map_err(application_error)?;
    Ok(Json(
        json!({"id": policy.id, "organization_id": policy.organization_id}),
    ))
}

fn authenticate_service(
    state: &PresentationPolicyHttpState,
    headers: &HeaderMap,
) -> Result<(), PresentationPolicyHttpError> {
    state
        .service_authenticator
        .authenticate(header(headers, "x-service-token"))
        .map_err(|_| unauthorized("PRESENTATION_POLICY.SERVICE_AUTHENTICATION_REQUIRED"))
}

fn trusted_application(
    state: &PresentationPolicyHttpState,
    headers: &HeaderMap,
) -> Result<(PolicyApplication, String), PresentationPolicyHttpError> {
    authenticate_service(state, headers)?;
    if headers.contains_key("x-api-key-id") {
        let key_id = header(headers, "x-api-key-id")
            .ok_or_else(|| unauthorized("PRESENTATION_POLICY.AUTHENTICATION_REQUIRED"))?;
        let key_id = Uuid::parse_str(key_id)
            .map_err(|_| unauthorized("PRESENTATION_POLICY.AUTHENTICATION_REQUIRED"))?;
        let organization_id = header(headers, "x-organization-id")
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| unauthorized("PRESENTATION_POLICY.AUTHENTICATION_REQUIRED"))?;
        let scopes = header(headers, "x-api-key-scopes")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        return Ok((
            state
                .application
                .for_gateway_api_key(key_id, organization_id, scopes),
            key_id.to_string(),
        ));
    }
    if headers.contains_key("x-api-key-scopes") {
        return Err(unauthorized("PRESENTATION_POLICY.AUTHENTICATION_REQUIRED"));
    }
    let principal = header(headers, "x-user-id")
        .map(str::to_owned)
        .ok_or_else(|| unauthorized("PRESENTATION_POLICY.AUTHENTICATION_REQUIRED"))?;
    Ok((state.application.as_ref().clone(), principal))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, PresentationPolicyHttpError> {
    Uuid::parse_str(value).map_err(|_| unprocessable(&format!("{field} must be a UUID")))
}

fn optional_uuid(
    value: Option<&str>,
    field: &str,
) -> Result<Option<Uuid>, PresentationPolicyHttpError> {
    value.map(|value| parse_uuid(value, field)).transpose()
}

fn validate_name(value: &str, field: &str, max: usize) -> Result<(), PresentationPolicyHttpError> {
    if value.is_empty() || value.len() > max {
        return Err(unprocessable(&format!(
            "{field} must contain between 1 and {max} characters"
        )));
    }
    Ok(())
}

fn validate_optional_len(
    value: Option<&str>,
    field: &str,
    max: usize,
) -> Result<(), PresentationPolicyHttpError> {
    if value.is_some_and(|value| value.len() > max) {
        return Err(unprocessable(&format!(
            "{field} must contain at most {max} characters"
        )));
    }
    Ok(())
}

fn application_error(error: PolicyApplicationError) -> PresentationPolicyHttpError {
    match error {
        PolicyApplicationError::NotFound => not_found("Presentation Policy not found"),
        PolicyApplicationError::Forbidden => forbidden("PRESENTATION_POLICY.FORBIDDEN"),
        PolicyApplicationError::Conflict(detail) => bad_request(detail),
        PolicyApplicationError::Domain(error) => domain_error(error),
        PolicyApplicationError::Dependency => {
            service_unavailable("PRESENTATION_POLICY.DEPENDENCY_UNAVAILABLE")
        }
    }
}

fn domain_error(error: crate::PolicyDomainError) -> PresentationPolicyHttpError {
    unprocessable(&error.to_string())
}

fn verification_error(error: PresentationVerificationError) -> PresentationPolicyHttpError {
    match error {
        PresentationVerificationError::Unavailable => {
            service_unavailable("PRESENTATION_POLICY.NATIVE_BACKEND_UNAVAILABLE")
        }
        PresentationVerificationError::Failed(detail) => unprocessable(&detail),
    }
}

fn status_name(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Draft => "draft",
        PolicyStatus::Active => "active",
        PolicyStatus::Suspended => "suspended",
        PolicyStatus::Archived => "archived",
    }
}

fn default_true() -> bool {
    true
}

fn default_constraint() -> ConstraintType {
    ConstraintType::Presence
}

fn default_credential_format() -> String {
    "w3c_vcdm_v2_sd_jwt".into()
}

fn default_min_satisfied() -> usize {
    1
}

fn default_purpose() -> RequestPurpose {
    RequestPurpose::IdentityVerification
}

fn default_ranking_strategy() -> String {
    "FRESHEST_FIRST".into()
}

fn error(status: StatusCode, detail: &str) -> PresentationPolicyHttpError {
    PresentationPolicyHttpError {
        status,
        detail: detail.to_owned(),
    }
}

fn unauthorized(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::UNAUTHORIZED, detail)
}

fn forbidden(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::FORBIDDEN, detail)
}

fn not_found(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::NOT_FOUND, detail)
}

fn bad_request(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::BAD_REQUEST, detail)
}

fn unprocessable(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::UNPROCESSABLE_ENTITY, detail)
}

fn service_unavailable(detail: &str) -> PresentationPolicyHttpError {
    error(StatusCode::SERVICE_UNAVAILABLE, detail)
}

#[cfg(test)]
mod error_code_projection_tests {
    use super::*;

    #[test]
    fn presentation_only_policy_keeps_its_proof_obligation_in_the_canonical_kernel() {
        let policy = build_policy(serde_json::from_value(json!({
            "organization_id": Uuid::from_u128(1).to_string(),
            "name": "Holder presentation proof",
            "holder_binding": {
                "required": true,
                "binding_methods": ["DEVICE_KEY"],
                "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
                "proof_freshness": {"challenge_required": false, "audience_binding_required": false, "replay_detection_required": false}
            }
        })).unwrap(), Utc::now()).unwrap();
        let request: EvaluatePresentationRequest =
            serde_json::from_value(json!({"vp_token": {}})).unwrap();
        for verified in [true, false] {
            let result = evaluate_verified_facts_for_policy(json!({
                "credentials": [], "evaluation_time_epoch_seconds": 1_787_240_300_u64,
                "presentation_verified": verified, "holder_binding_verified": verified,
                "holder_binding_method": "DEVICE_KEY", "proof_profile": "OID4VP_VERIFIABLE_PRESENTATION",
                "challenge_verified": false, "audience_verified": false, "replay_check_verified": false,
                "proof_epoch_seconds": null, "external_authorization": null, "presentation_count": 1
            }), &policy, &request).unwrap();
            assert_eq!(result["decision"], if verified { "allow" } else { "deny" });
        }
    }

    #[test]
    fn projection_requires_actual_status_evidence_even_when_policy_allows() {
        let request: EvaluatePresentationRequest =
            serde_json::from_value(json!({"vp_token": {}})).unwrap();
        let native = json!({"decision": "allow", "credential_results": [{
            "credential_template_id": "template-1", "issuer_id": "issuer-1",
            "satisfied": true, "errors": []
        }]});
        let credential = json!({
            "credential_template_ids": ["template-1"], "issuer_id": "issuer-1",
            "signature_verified": true, "trust_profile_verified": true,
            "revocation_checked_at_epoch_seconds": null, "not_revoked": null
        });
        for (timestamp, not_revoked, status) in [
            (Value::Null, Value::Null, Value::Null),
            (json!(1000), json!(true), json!("active")),
            (json!(1000), json!(false), json!("revoked")),
            (json!(1000), Value::Null, json!("unknown")),
        ] {
            let mut evidence = credential.clone();
            evidence["revocation_checked_at_epoch_seconds"] = timestamp.clone();
            evidence["not_revoked"] = not_revoked.clone();
            evidence["credential_status"] = status.clone();
            let projected = project_evaluation(
                native.clone(),
                &request,
                &json!({"credentials": [evidence]}),
                None,
                None,
            );
            let result = &projected["credential_results"][0];
            assert_eq!(result["revocation_checked"], !timestamp.is_null());
            assert_eq!(result["not_revoked"], not_revoked);
            assert_eq!(result["revocation_status"], status);
            assert_eq!(result["signature_valid"], true);
            assert_eq!(result["trust_check_passed"], true);
        }
        let mut foreign = credential.clone();
        foreign["issuer_id"] = json!("another-issuer");
        for credentials in [
            json!([]),
            json!([foreign]),
            json!([credential.clone(), credential]),
        ] {
            let projected = project_evaluation(
                native.clone(),
                &request,
                &json!({"credentials": credentials}),
                None,
                None,
            );
            let result = &projected["credential_results"][0];
            for key in [
                "signature_valid",
                "trust_check_passed",
                "revocation_checked",
                "not_revoked",
            ] {
                assert!(
                    result.get(key).is_none(),
                    "{key} was guessed from missing/ambiguous evidence"
                );
            }
        }
    }

    #[test]
    fn credential_id_requires_authenticated_outer_jti_and_unique_matching_evidence() {
        let request: EvaluatePresentationRequest =
            serde_json::from_value(json!({"vp_token": {}, "context": {"credential_id": "forged"}}))
                .unwrap();
        let native = json!({"decision": "allow", "credential_results": [{
            "credential_template_id": "template-1", "issuer_id": "issuer-1",
            "satisfied": true, "errors": []
        }]});
        let evidence = json!({
            "credential_id": "urn:uuid:signed-1", "credential_template_ids": ["template-1"],
            "issuer_id": "issuer-1", "signature_verified": true
        });
        let projection = |credentials: Value, authenticated: Option<&str>| {
            project_evaluation(
                native.clone(),
                &request,
                &json!({"credentials": credentials}),
                None,
                authenticated,
            )
        };
        assert_eq!(
            projection(json!([evidence]), Some("urn:uuid:signed-1"))["credential_results"][0]
                ["credential_id"],
            "urn:uuid:signed-1"
        );
        assert!(projection(json!([evidence]), None)["credential_results"][0]
            .get("credential_id")
            .is_none());
        assert!(
            projection(json!([evidence]), Some("urn:uuid:foreign"))["credential_results"][0]
                .get("credential_id")
                .is_none()
        );
        assert!(
            projection(json!([evidence, evidence]), Some("urn:uuid:signed-1"))
                ["credential_results"][0]
                .get("credential_id")
                .is_none()
        );
        let mut denied = evidence.clone();
        denied["signature_verified"] = json!(false);
        assert!(
            projection(json!([denied]), Some("urn:uuid:signed-1"))["credential_results"][0]
                .get("credential_id")
                .is_none()
        );
        let mut foreign = evidence.clone();
        foreign["issuer_id"] = json!("issuer-2");
        assert!(
            projection(json!([foreign]), Some("urn:uuid:signed-1"))["credential_results"][0]
                .get("credential_id")
                .is_none()
        );
    }

    #[test]
    fn language_neutral_error_code_forms_drive_the_same_projection_flags() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/presentation-policy-service-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            contract["evaluation_projection"]["equivalent_error_code_forms"],
            serde_json::json!(["snake_case", "PascalCase"])
        );
        for (native, legacy) in [
            ("revocation_check_required", "RevocationCheckRequired"),
            ("credential_revoked", "CredentialRevoked"),
            ("signature_invalid", "SignatureInvalid"),
            ("trust_profile_not_verified", "TrustProfileNotVerified"),
        ] {
            assert!(has_any_code(&[Value::String(native.into())], &[legacy]));
            assert!(has_any_code(&[Value::String(legacy.into())], &[native]));
        }
    }
    #[test]
    fn rejection_diagnostic_is_separate_from_policy_facts_and_issuer_template_matching() {
        use marty_oid4vp_contract::{
            CertificateTrustFailure, MdocAuthenticationDiagnosticV1, MdocDiagnosticFormat,
        };
        let policy=build_policy(serde_json::from_value(json!({"organization_id":Uuid::from_u128(1).to_string(),"name":"Certificate trust",
            "credential_requirements":[{"credential_template_id":Uuid::from_u128(2).to_string(),"credential_payload_format":"mdoc","requested_claims":[{"claim_name":"age_over_21"}]}]})).unwrap(),Utc::now()).unwrap();
        let nonce = Uuid::new_v4().to_string();
        let request: EvaluatePresentationRequest =
            serde_json::from_value(json!({"vp_token":"raw-mdoc","nonce":nonce.as_str()})).unwrap();
        let diagnostic = MdocAuthenticationDiagnosticV1 {
            format: MdocDiagnosticFormat::MsoMdoc,
            document_count: 1,
            document_type: "org.iso.18013.5.1.mDL".into(),
            issuer_signature_valid: true,
            certificate_trust_passed: false,
            device_authentication_valid: true,
            certificate_trust_failures: vec![CertificateTrustFailure::CertificateChainRejected],
            issuer_certificate_sha256: "1".repeat(64),
        };
        let mut facts = json!({"credentials":[{"credential_id":"rejected","credential_template_ids":[],"credential_format":"mdoc","claims":{},"issuer_id":"unknown","signature_verified":false,"signature_failure_reason":"Authentication rejected","trust_profile_verified":false,"trust_failure_reason":null,"trust_level":null,"compliance_statuses":[],"accreditations":[],"issued_at_epoch_seconds":null,"revocation_checked_at_epoch_seconds":null,"not_revoked":null,"credential_status":null,"warnings":[]}],
            "evaluation_time_epoch_seconds":1787240300_u64,"presentation_verified":false,"holder_binding_verified":false,"holder_binding_method":"DEVICE_KEY","proof_profile":"OID4VP_VERIFIABLE_PRESENTATION","challenge_verified":false,"audience_verified":false,"replay_check_verified":false,"proof_epoch_seconds":null,"external_authorization":null,"presentation_count":1});
        facts[crate::verification::MDOC_AUTHENTICATION_DIAGNOSTIC] =
            serde_json::to_value(diagnostic).unwrap();
        let result = evaluate_verified_facts_for_policy(facts.clone(), &policy, &request).unwrap();
        assert_eq!(result["decision"], "deny");
        assert_eq!(result["verified_claims"], json!({}));
        let bound: marty_oid4vp_contract::BoundAuthenticationDiagnosticV1 = serde_json::from_value(
            result[marty_oid4vp_contract::AUTHENTICATION_DIAGNOSTIC].clone(),
        )
        .unwrap();
        bound
            .validate_request(&policy.id.to_string(), &nonce, "raw-mdoc")
            .unwrap();
        assert!(bound.authentication.issuer_signature_valid);
        assert!(!bound.authentication.certificate_trust_passed);
        facts[crate::verification::MDOC_AUTHENTICATION_DIAGNOSTIC] =
            json!({"claims":{"forged":true}});
        let result = evaluate_verified_facts_for_policy(facts, &policy, &request).unwrap();
        assert_eq!(result["decision"], "deny");
        assert!(result
            .get(marty_oid4vp_contract::AUTHENTICATION_DIAGNOSTIC)
            .is_none());
    }
}
