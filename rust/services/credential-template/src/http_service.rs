use std::{collections::BTreeMap, sync::Arc};

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
    normalize_payload_format,
    registry_application::{
        CreateDestinationCommand, CreateWalletCommand, CredentialTemplateRegistryApplication,
        UpdateDestinationPatch, UpdateWalletPatch,
    },
    resolve_validity_rules,
    wallet::{
        derive_ios_same_device_mode, normalize_issuance_protocol, wallet_capabilities,
        wallet_routing_templates, IosSameDeviceMode, WalletCompatibility,
    },
    ClaimDefinition, ClaimType, CredentialFormat, CredentialTemplate, CredentialTemplateError,
    DeliveryDestinationEntry, DerivedAttribute, DisplayStyle, PrivacyPosture, RuntimeEnvironment,
    TemplateStatus, ValidityRulesInput, WalletRegistryEntry,
};

#[derive(Clone)]
pub struct CredentialTemplateHttpState {
    pub application: Arc<CredentialTemplateApplication>,
    pub registry_application: Arc<CredentialTemplateRegistryApplication>,
    pub service_authenticator: Arc<ServiceTokenAuthenticator>,
    pub environment: RuntimeEnvironment,
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
        .route(
            "/v1/credential-templates/{template_id}/wallet-compatibility",
            get(get_wallet_compatibility),
        )
        .route("/v1/wallet-registry", get(list_wallets).post(create_wallet))
        .route(
            "/v1/wallet-registry/resolve/profile",
            get(resolve_wallet_profile),
        )
        .route(
            "/v1/wallet-registry/{wallet_id}/open-link",
            get(build_wallet_open_link),
        )
        .route(
            "/v1/wallet-registry/{wallet_id}",
            get(get_wallet).patch(update_wallet).delete(delete_wallet),
        )
        .route(
            "/v1/delivery-destinations",
            get(list_delivery_destinations).post(create_delivery_destination),
        )
        .route(
            "/v1/delivery-destinations/{destination_id}",
            get(get_delivery_destination)
                .patch(update_delivery_destination)
                .delete(delete_delivery_destination),
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

#[derive(Debug, Deserialize)]
struct WalletListQuery {
    #[serde(default = "default_true")]
    active_only: bool,
    organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WalletOpenLinkQuery {
    inner_uri: String,
    platform: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResolveWalletProfileQuery {
    organization_id: String,
    credential_format: String,
    issuance_protocol: String,
    compliance_profile_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWalletRequest {
    organization_id: Option<String>,
    credential_format: Option<String>,
    issuance_protocol: Option<String>,
    compliance_profile_code: Option<String>,
    name: String,
    description: Option<String>,
    #[serde(default)]
    wallet_apps: Vec<String>,
    #[serde(default)]
    specifications: Vec<String>,
    logo_url: Option<String>,
    #[serde(default = "default_wallet_deep_link")]
    deep_link_template: String,
    deep_link_pattern: Option<String>,
    #[serde(default)]
    routing_templates: BTreeMap<String, String>,
    #[serde(default)]
    install_urls: BTreeMap<String, String>,
    ios_scheme: Option<String>,
    universal_link_template: Option<String>,
    android_package: Option<String>,
    #[serde(default)]
    supported_formats: Vec<String>,
    #[serde(default = "default_wallet_protocols")]
    supported_protocols: Vec<String>,
    #[serde(default)]
    platforms: Vec<String>,
    supported_platforms: Option<Vec<String>>,
    #[serde(default = "default_true")]
    supports_qr: bool,
    #[serde(default = "default_true")]
    supports_deeplink: bool,
    #[serde(default)]
    supports_digital_credentials: bool,
    #[serde(default)]
    supports_haip: bool,
    docs_url: Option<String>,
    #[serde(default = "default_override_precedence")]
    override_precedence: i32,
    #[serde(default = "default_merge_strategy")]
    merge_strategy: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UpdateWalletRequest {
    organization_id: Option<String>,
    credential_format: Option<String>,
    issuance_protocol: Option<String>,
    compliance_profile_code: Option<String>,
    name: Option<String>,
    description: Option<String>,
    wallet_apps: Option<Vec<String>>,
    specifications: Option<Vec<String>>,
    logo_url: Option<String>,
    deep_link_template: Option<String>,
    deep_link_pattern: Option<String>,
    routing_templates: Option<BTreeMap<String, String>>,
    install_urls: Option<BTreeMap<String, String>>,
    ios_scheme: Option<String>,
    universal_link_template: Option<String>,
    android_package: Option<String>,
    supported_formats: Option<Vec<String>>,
    supported_protocols: Option<Vec<String>>,
    platforms: Option<Vec<String>>,
    supported_platforms: Option<Vec<String>>,
    supports_qr: Option<bool>,
    supports_deeplink: Option<bool>,
    supports_digital_credentials: Option<bool>,
    supports_haip: Option<bool>,
    docs_url: Option<String>,
    is_active: Option<bool>,
    override_precedence: Option<i32>,
    merge_strategy: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DestinationListQuery {
    #[serde(default = "default_true")]
    active_only: bool,
    organization_id: Option<String>,
    provider: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDestinationRequest {
    organization_id: String,
    id: Option<String>,
    name: String,
    description: Option<String>,
    #[serde(default = "default_destination_provider")]
    provider: String,
    #[serde(default = "default_destination_mode")]
    mode: String,
    #[serde(default = "default_destination_actor")]
    setup_actor: String,
    #[serde(default = "default_destination_target")]
    delivery_target: String,
    wallet_profile_id: Option<String>,
    credential_format: Option<String>,
    issuance_protocol: Option<String>,
    compliance_profile_code: Option<String>,
    connector_type: Option<String>,
    connector_id: Option<String>,
    #[serde(default)]
    requires_consent: bool,
    #[serde(default = "empty_object")]
    claim_projection_policy: Value,
    #[serde(default)]
    setup_requirements: Vec<String>,
    #[serde(default)]
    capabilities: BTreeMap<String, bool>,
    docs_url: Option<String>,
    #[serde(default = "default_true")]
    is_enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UpdateDestinationRequest {
    name: Option<String>,
    description: Option<String>,
    provider: Option<String>,
    mode: Option<String>,
    setup_actor: Option<String>,
    delivery_target: Option<String>,
    wallet_profile_id: Option<String>,
    credential_format: Option<String>,
    issuance_protocol: Option<String>,
    compliance_profile_code: Option<String>,
    connector_type: Option<String>,
    connector_id: Option<String>,
    requires_consent: Option<bool>,
    claim_projection_policy: Option<Value>,
    setup_requirements: Option<Vec<String>>,
    capabilities: Option<BTreeMap<String, bool>>,
    docs_url: Option<String>,
    is_enabled: Option<bool>,
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

async fn list_wallets(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Query(query): Query<WalletListQuery>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let wallets = state
        .registry_application
        .list_wallets(
            &user_id,
            query.organization_id.as_deref(),
            query.active_only,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        wallets.iter().map(wallet_response).collect(),
    )))
}

async fn get_wallet(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(wallet_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let wallet = state
        .registry_application
        .get_wallet(&user_id, &wallet_id)
        .await
        .map_err(application_error)?;
    Ok(Json(wallet_response(&wallet)))
}

async fn build_wallet_open_link(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(wallet_id): Path<String>,
    Query(query): Query<WalletOpenLinkQuery>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let link = state
        .registry_application
        .build_wallet_open_link(
            &user_id,
            &wallet_id,
            &query.inner_uri,
            query.platform.as_deref(),
            state.environment,
        )
        .await
        .map_err(application_error)?;
    Ok(Json(json!({
        "wallet_id":link.wallet_id,
        "inner_uri":link.inner_uri,
        "open_uri":link.open_uri,
        "platform":link.platform,
        "transport":"wallet_deeplink"
    })))
}

async fn resolve_wallet_profile(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Query(query): Query<ResolveWalletProfileQuery>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let compatibility = state
        .registry_application
        .resolve_wallet_profile(
            &user_id,
            &query.organization_id,
            &query.credential_format,
            &query.issuance_protocol,
            query.compliance_profile_code.as_deref(),
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(wallet_compatibility_response(&compatibility)))
}

async fn get_wallet_compatibility(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let compatibility = state
        .registry_application
        .template_wallet_compatibility(&user_id, &template_id)
        .await
        .map_err(application_error)?;
    Ok(Json(wallet_compatibility_response(&compatibility)))
}

async fn create_wallet(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<Value>), CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let organization_id = input
        .organization_id
        .ok_or_else(|| unprocessable("organization_id is required for wallet overrides"))?;
    let platforms = input.supported_platforms.unwrap_or(input.platforms);
    let deep_link_template = input
        .deep_link_pattern
        .filter(|value| !value.is_empty())
        .unwrap_or(input.deep_link_template);
    let wallet = state
        .registry_application
        .create_wallet(CreateWalletCommand {
            user_id,
            organization_id,
            credential_format: input.credential_format,
            issuance_protocol: input.issuance_protocol,
            compliance_profile_code: input.compliance_profile_code,
            name: input.name,
            description: input.description,
            wallet_apps: input.wallet_apps,
            specifications: input.specifications,
            logo_url: input.logo_url,
            deep_link_template,
            routing_templates: input.routing_templates,
            install_urls: input.install_urls,
            ios_scheme: input.ios_scheme,
            universal_link_template: input.universal_link_template,
            android_package: input.android_package,
            supported_formats: input.supported_formats,
            supported_protocols: input.supported_protocols,
            platforms,
            supports_qr: input.supports_qr,
            supports_deeplink: input.supports_deeplink,
            supports_digital_credentials: input.supports_digital_credentials,
            supports_haip: input.supports_haip,
            docs_url: input.docs_url,
            override_precedence: input.override_precedence,
            merge_strategy: input.merge_strategy,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok((StatusCode::CREATED, Json(wallet_response(&wallet))))
}

async fn update_wallet(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(wallet_id): Path<String>,
    Json(input): Json<UpdateWalletRequest>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let platforms = input.supported_platforms.or(input.platforms);
    let deep_link_template = input
        .deep_link_pattern
        .filter(|value| !value.is_empty())
        .or(input.deep_link_template.filter(|value| !value.is_empty()));
    let wallet = state
        .registry_application
        .update_wallet(
            &user_id,
            &wallet_id,
            UpdateWalletPatch {
                organization_id: input.organization_id,
                credential_format: input.credential_format,
                issuance_protocol: input.issuance_protocol,
                compliance_profile_code: input.compliance_profile_code,
                name: input.name,
                description: input.description,
                wallet_apps: input.wallet_apps,
                specifications: input.specifications,
                logo_url: input.logo_url,
                deep_link_template,
                routing_templates: input.routing_templates,
                install_urls: input.install_urls,
                ios_scheme: input.ios_scheme,
                universal_link_template: input.universal_link_template,
                android_package: input.android_package,
                supported_formats: input.supported_formats,
                supported_protocols: input.supported_protocols,
                platforms,
                supports_qr: input.supports_qr,
                supports_deeplink: input.supports_deeplink,
                supports_digital_credentials: input.supports_digital_credentials,
                supports_haip: input.supports_haip,
                docs_url: input.docs_url,
                is_active: input.is_active,
                override_precedence: input.override_precedence,
                merge_strategy: input.merge_strategy,
            },
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(wallet_response(&wallet)))
}

async fn delete_wallet(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(wallet_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    state
        .registry_application
        .delete_wallet(&user_id, &wallet_id)
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success":true})))
}

async fn list_delivery_destinations(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Query(query): Query<DestinationListQuery>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let entries = state
        .registry_application
        .list_destinations(
            &user_id,
            query.organization_id.as_deref(),
            query.active_only,
            query.provider.as_deref(),
            query.mode.as_deref(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(Value::Array(
        entries.iter().map(destination_response).collect(),
    )))
}

async fn get_delivery_destination(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(destination_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let entry = state
        .registry_application
        .get_destination(&user_id, &destination_id)
        .await
        .map_err(application_error)?;
    Ok(Json(destination_response(&entry)))
}

async fn create_delivery_destination(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateDestinationRequest>,
) -> Result<(StatusCode, Json<Value>), CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let entry = state
        .registry_application
        .create_destination(CreateDestinationCommand {
            user_id,
            organization_id: input.organization_id,
            id: input.id,
            name: input.name,
            description: input.description,
            provider: input.provider,
            mode: input.mode,
            setup_actor: input.setup_actor,
            delivery_target: input.delivery_target,
            wallet_profile_id: input.wallet_profile_id,
            credential_format: input.credential_format,
            issuance_protocol: input.issuance_protocol,
            compliance_profile_code: input.compliance_profile_code,
            connector_type: input.connector_type,
            connector_id: input.connector_id,
            requires_consent: input.requires_consent,
            claim_projection_policy: input.claim_projection_policy,
            setup_requirements: input.setup_requirements,
            capabilities: input.capabilities,
            docs_url: input.docs_url,
            is_enabled: input.is_enabled,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok((StatusCode::CREATED, Json(destination_response(&entry))))
}

async fn update_delivery_destination(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(destination_id): Path<String>,
    Json(input): Json<UpdateDestinationRequest>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    let entry = state
        .registry_application
        .update_destination(
            &user_id,
            &destination_id,
            UpdateDestinationPatch {
                name: input.name,
                description: input.description,
                provider: input.provider,
                mode: input.mode,
                setup_actor: input.setup_actor,
                delivery_target: input.delivery_target,
                wallet_profile_id: input.wallet_profile_id,
                credential_format: input.credential_format,
                issuance_protocol: input.issuance_protocol,
                compliance_profile_code: input.compliance_profile_code,
                connector_type: input.connector_type,
                connector_id: input.connector_id,
                requires_consent: input.requires_consent,
                claim_projection_policy: input.claim_projection_policy,
                setup_requirements: input.setup_requirements,
                capabilities: input.capabilities,
                docs_url: input.docs_url,
                is_enabled: input.is_enabled,
            },
            Utc::now(),
        )
        .await
        .map_err(application_error)?;
    Ok(Json(destination_response(&entry)))
}

async fn delete_delivery_destination(
    State(state): State<CredentialTemplateHttpState>,
    headers: HeaderMap,
    Path(destination_id): Path<String>,
) -> Result<Json<Value>, CredentialTemplateHttpError> {
    let user_id = trusted_user_id(&state, &headers)?;
    state
        .registry_application
        .delete_destination(&user_id, &destination_id)
        .await
        .map_err(application_error)?;
    Ok(Json(json!({"success":true})))
}

fn wallet_response(wallet: &WalletRegistryEntry) -> Value {
    let ios_mode = derive_ios_same_device_mode(wallet);
    let wallet_apps = if wallet.wallet_apps.is_empty() {
        vec![wallet.name.clone()]
    } else {
        wallet.wallet_apps.clone()
    };
    without_nulls(json!({
        "id":wallet.id,
        "organization_id":wallet.organization_id,
        "is_override":wallet.is_override,
        "override_precedence":wallet.override_precedence,
        "merge_strategy":wallet.merge_strategy.as_str(),
        "credential_format":wallet.credential_format,
        "issuance_protocol":wallet.issuance_protocol.as_deref().map(|value| normalize_issuance_protocol(Some(value))),
        "compliance_profile_code":wallet.compliance_profile_code,
        "name":wallet.name,
        "description":wallet.description,
        "wallet_apps":wallet_apps,
        "specifications":wallet.specifications,
        "logo_url":wallet.logo_url,
        "deep_link_pattern":wallet.deep_link_template,
        "routing_templates":wallet_routing_templates(wallet),
        "install_urls":wallet.install_urls,
        "ios_scheme":wallet.ios_scheme,
        "universal_link_template":wallet.universal_link_template,
        "android_package":wallet.android_package,
        "supported_formats":wallet.supported_formats,
        "supported_protocols":wallet.supported_protocols,
        "supported_platforms":wallet.platforms,
        "supports_qr":wallet.supports_qr,
        "supports_deeplink":wallet.supports_deeplink,
        "supports_digital_credentials":wallet.supports_digital_credentials,
        "supports_haip":wallet.supports_haip,
        "ios_same_device_mode":ios_mode.as_str(),
        "ios_same_device_single_wallet_only":ios_mode == IosSameDeviceMode::ProtocolOnly,
        "docs_url":wallet.docs_url,
        "capabilities":wallet_capabilities(wallet),
        "created_at":wallet.created_at.to_rfc3339(),
        "updated_at":wallet.updated_at.to_rfc3339()
    }))
}

fn wallet_compatibility_response(compatibility: &WalletCompatibility) -> Value {
    let configs = compatibility
        .template_wallet_configs
        .iter()
        .map(|config| {
            without_nulls(json!({
                "wallet_id":config.wallet_id,
                "deep_link_scheme":config.deep_link_scheme,
                "format_variant":config.format_variant
            }))
        })
        .collect::<Vec<_>>();
    let derived_from = without_nulls(json!({
        "credential_format":compatibility.derived_from.credential_format,
        "issuance_protocol":compatibility.derived_from.issuance_protocol,
        "compliance_profile_code":compatibility.derived_from.compliance_profile_code
    }));
    without_nulls(json!({
        "id":compatibility.id,
        "organization_id":compatibility.organization_id,
        "derived_from":derived_from,
        "is_override":compatibility.is_override,
        "override_precedence":compatibility.override_precedence,
        "merge_strategy":compatibility.merge_strategy,
        "name":compatibility.name,
        "description":compatibility.description,
        "credential_format":compatibility.credential_format,
        "issuance_protocol":compatibility.issuance_protocol,
        "compliance_profile_code":compatibility.compliance_profile_code,
        "wallet_apps":compatibility.wallet_apps,
        "specifications":compatibility.specifications,
        "supported_platforms":compatibility.supported_platforms,
        "deep_link_pattern":compatibility.deep_link_pattern,
        "applied_override_ids":compatibility.applied_override_ids,
        "template_wallet_configs":configs,
        "created_at":compatibility.created_at.to_rfc3339(),
        "updated_at":compatibility.updated_at.to_rfc3339()
    }))
}

fn destination_response(entry: &DeliveryDestinationEntry) -> Value {
    without_nulls(json!({
        "id":entry.id,
        "organization_id":entry.organization_id,
        "is_system":entry.is_system,
        "name":entry.name,
        "description":entry.description,
        "provider":entry.provider,
        "mode":entry.mode,
        "setup_actor":entry.setup_actor,
        "delivery_target":entry.delivery_target,
        "wallet_profile_id":entry.wallet_profile_id,
        "credential_format":entry.credential_format,
        "issuance_protocol":entry.issuance_protocol,
        "compliance_profile_code":entry.compliance_profile_code,
        "connector_type":entry.connector_type,
        "connector_id":entry.connector_id,
        "requires_consent":entry.requires_consent,
        "claim_projection_policy":entry.claim_projection_policy,
        "setup_requirements":entry.setup_requirements,
        "capabilities":entry.capabilities,
        "docs_url":entry.docs_url,
        "is_enabled":entry.is_enabled,
        "created_at":entry.created_at.to_rfc3339(),
        "updated_at":entry.updated_at.to_rfc3339()
    }))
}

fn without_nulls(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, value| !value.is_null());
    }
    value
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
        CredentialTemplateApplicationError::WalletNotFound(_) => not_found("Wallet not found"),
        CredentialTemplateApplicationError::DestinationNotFound(_) => {
            not_found("Delivery destination not found")
        }
        CredentialTemplateApplicationError::ControlPlane(ControlPlaneError::MembershipRequired) => {
            forbidden("CREDENTIAL_TEMPLATE.MEMBERSHIP_REQUIRED")
        }
        CredentialTemplateApplicationError::ControlPlane(
            ControlPlaneError::WalletAdminRequired,
        ) => forbidden("Wallet management requires organization console access"),
        CredentialTemplateApplicationError::ControlPlane(
            ControlPlaneError::DestinationAdminRequired,
        ) => forbidden("Organization destination management requires org console access"),
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
        CredentialTemplateApplicationError::SystemWalletReadOnly => {
            forbidden("System wallet entries are read-only")
        }
        CredentialTemplateApplicationError::SystemDestinationReadOnly => {
            forbidden("System delivery destinations are read-only")
        }
        CredentialTemplateApplicationError::OwnershipTransferForbidden => {
            conflict("Wallet ownership cannot be transferred")
        }
        CredentialTemplateApplicationError::DeepLinksUnsupported => {
            bad_request("Wallet does not support deep links")
        }
        CredentialTemplateApplicationError::AlreadyExists(_) => {
            conflict("Delivery destination already exists")
        }
        CredentialTemplateApplicationError::Domain(CredentialTemplateError::MissingInnerUri) => {
            bad_request("inner_uri is required")
        }
        CredentialTemplateApplicationError::Domain(
            CredentialTemplateError::DisallowedInnerUriScheme,
        ) => bad_request("inner_uri scheme is not allowed"),
        CredentialTemplateApplicationError::Domain(
            CredentialTemplateError::InnerUriMissingHost,
        ) => bad_request("inner_uri must include a host"),
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

fn default_wallet_deep_link() -> String {
    "openid-credential-offer://?credential_offer_uri={offer_uri}".to_owned()
}

fn default_wallet_protocols() -> Vec<String> {
    vec!["OID4VCI_PRE_AUTH".to_owned()]
}

fn default_override_precedence() -> i32 {
    50
}

fn default_merge_strategy() -> String {
    "APPEND".to_owned()
}

fn default_destination_provider() -> String {
    "custom".to_owned()
}

fn default_destination_mode() -> String {
    "holder_wallet".to_owned()
}

fn default_destination_actor() -> String {
    "learner".to_owned()
}

fn default_destination_target() -> String {
    "wallet".to_owned()
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}
