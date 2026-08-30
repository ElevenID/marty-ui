use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::credential::{
    remote_credential_format, CredentialTransaction, CredentialTransactionStatus,
    IssuerContextResolver,
};

const IDEMPOTENCY_KEY_PREFIX: &str = "marty:issuance-idempotency-key:v1:";
const IDEMPOTENCY_REQUEST_PREFIX: &str = "marty:issuance-initiate-request:v1:";
const RESERVED_CLAIMS: &[&str] = &[
    "_application_id",
    "_credential_subject",
    "_credential_document",
];
const VCDM_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitiationRequest {
    pub organization_id: String,
    pub issuer_did: String,
    #[serde(default)]
    pub credential_template_id: Option<String>,
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub applicant_id: Option<String>,
    #[serde(default)]
    pub subject_did: Option<String>,
    #[serde(default)]
    pub holder_did: Option<String>,
    #[serde(default)]
    pub authorized_client_id: Option<String>,
    #[serde(default = "default_delivery_mode")]
    pub delivery_mode: String,
    /// `None` distinguishes omission from an explicitly supplied empty object,
    /// matching the Python model's exclusivity checks.
    #[serde(default)]
    pub claims: Option<Map<String, Value>>,
    #[serde(default)]
    pub credential_subject: Option<Value>,
    #[serde(default)]
    pub credential_document: Option<Value>,
}

impl InitiationRequest {
    pub fn validate(&self) -> Result<(), InitiationError> {
        if self.issuer_did.is_empty() {
            return Err(InitiationError::IssuerDidRequired);
        }
        normalize_delivery_mode(&self.delivery_mode)?;
        if let Some(claims) = &self.claims {
            if let Some(field) = RESERVED_CLAIMS
                .iter()
                .find(|field| claims.contains_key(**field))
            {
                return Err(InitiationError::ReservedClaim((*field).to_owned()));
            }
        }
        if self.credential_subject.is_some() && self.claims.is_some() {
            return Err(InitiationError::CredentialSubjectWithClaims);
        }
        if self.credential_document.is_some()
            && (self.claims.is_some() || self.credential_subject.is_some())
        {
            return Err(InitiationError::CredentialDocumentWithClaims);
        }
        if let Some(subject) = &self.credential_subject {
            validate_subject(subject)?;
        }
        if let Some(document) = &self.credential_document {
            validate_credential_document(document, &self.issuer_did)?;
        }
        Ok(())
    }

    pub fn normalized_delivery_mode(&self) -> Result<String, InitiationError> {
        normalize_delivery_mode(&self.delivery_mode)
    }

    pub fn semantic_payload(&self) -> Result<Value, InitiationError> {
        self.validate()?;
        Ok(serde_json::json!({
            "organization_id": self.organization_id,
            "credential_template_id": optional_string(&self.credential_template_id),
            "application_id": optional_string(&self.application_id),
            "applicant_id": optional_string(&self.applicant_id),
            "subject_did": optional_string(&self.subject_did),
            "holder_did": optional_string(&self.holder_did),
            "issuer_did": self.issuer_did,
            "authorized_client_id": optional_string(&self.authorized_client_id),
            "delivery_mode": self.normalized_delivery_mode()?,
            "claims": self.claims.clone().unwrap_or_default(),
            "credential_subject": self.credential_subject.clone(),
            "credential_document": self.credential_document.clone(),
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyBinding {
    pub key_hash: String,
    pub request_hash: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InitiationReservation {
    pub transaction: CredentialTransaction,
    pub created: bool,
}

#[async_trait]
pub trait InitiationRepository: Send + Sync {
    async fn recover_idempotently(
        &self,
        organization_id: &str,
        binding: &IdempotencyBinding,
    ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError>;

    async fn reserve_idempotently(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<InitiationReservation, InitiationRepositoryError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationRepositoryError {
    #[error("idempotency key was already used for a different issuance request")]
    IdempotencyConflict,
    #[error("issuance transaction contains an incomplete idempotency binding")]
    IncompleteIdempotencyBinding,
    #[error("issuance initiation repository is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationValidation {
    Found,
    NotFound,
    Unavailable,
}

#[async_trait]
pub trait InitiationOrganizationValidator: Send + Sync {
    async fn validate(&self, organization_id: &str) -> OrganizationValidation;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiationRegisteredClient {
    pub client_id: String,
    pub active: bool,
    pub token_endpoint_auth_method: String,
}

#[async_trait]
pub trait InitiationClientRepository: Send + Sync {
    async fn get(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct InitiationTemplate {
    pub credential_type: String,
    pub vct: Option<String>,
    pub zk_predicate_claims: Vec<String>,
    pub selective_disclosure_claims: Vec<String>,
    pub credential_payload_format: String,
    pub revocation_profile_id: Option<String>,
    pub issuer_did: Option<String>,
    pub issuer_algorithm: Option<String>,
    pub wallet_configs: Vec<Value>,
    pub validity_days: i64,
    pub renewable: bool,
    pub renewal_window_days: i64,
}

impl Default for InitiationTemplate {
    fn default() -> Self {
        Self {
            credential_type: "org.iso.18013.5.1.mDL".to_owned(),
            vct: None,
            zk_predicate_claims: Vec::new(),
            selective_disclosure_claims: Vec::new(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            revocation_profile_id: None,
            issuer_did: None,
            issuer_algorithm: None,
            wallet_configs: Vec::new(),
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
        }
    }
}

#[async_trait]
pub trait InitiationTemplateResolver: Send + Sync {
    async fn resolve(
        &self,
        template_id: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError>;
}

#[async_trait]
pub trait InitiationRevocationProfileValidator: Send + Sync {
    async fn validate_active(
        &self,
        organization_id: &str,
        profile_id: Option<&str>,
    ) -> Result<(), InitiationDependencyError>;
}

#[async_trait]
pub trait InitiationApplicationClaimsResolver: Send + Sync {
    async fn resolve(&self, application_id: &str) -> Result<Option<Map<String, Value>>, ()>;
}

#[async_trait]
pub trait InitiationRelatedResourceValidator: Send + Sync {
    async fn validate(&self, credential_document: &Value) -> Result<(), InitiationDependencyError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationDependencyError {
    #[error("dependency resource was not found")]
    NotFound,
    #[error("dependency resource is invalid: {0}")]
    Invalid(String),
    #[error("dependency is unavailable")]
    Unavailable,
    #[error("dependency timed out")]
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiationSeed {
    pub transaction_id: String,
    pub pre_authorized_code: String,
}

pub trait InitiationSeedGenerator: Send + Sync {
    fn generate(&self) -> InitiationSeed;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureInitiationSeedGenerator;

impl InitiationSeedGenerator for SecureInitiationSeedGenerator {
    fn generate(&self) -> InitiationSeed {
        let mut capability = [0_u8; 32];
        rand::rng().fill_bytes(&mut capability);
        InitiationSeed {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            pre_authorized_code: URL_SAFE_NO_PAD.encode(capability),
        }
    }
}

pub trait InitiationClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemInitiationClock;

impl InitiationClock for SystemInitiationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct InitiationPorts {
    pub repository: Arc<dyn InitiationRepository>,
    pub organizations: Arc<dyn InitiationOrganizationValidator>,
    pub clients: Arc<dyn InitiationClientRepository>,
    pub templates: Arc<dyn InitiationTemplateResolver>,
    pub revocation_profiles: Arc<dyn InitiationRevocationProfileValidator>,
    pub applications: Arc<dyn InitiationApplicationClaimsResolver>,
    pub related_resources: Arc<dyn InitiationRelatedResourceValidator>,
    pub issuer_resolver: Arc<dyn IssuerContextResolver>,
    pub seeds: Arc<dyn InitiationSeedGenerator>,
    pub clock: Arc<dyn InitiationClock>,
}

#[derive(Clone)]
pub struct InitiationService {
    ports: InitiationPorts,
    issuer_base_url: String,
}

impl std::fmt::Debug for InitiationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitiationService")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl InitiationService {
    pub fn new(
        ports: InitiationPorts,
        issuer_base_url: impl Into<String>,
    ) -> Result<Self, InitiationServiceError> {
        let issuer_base_url = issuer_base_url.into().trim_end_matches('/').to_owned();
        if issuer_base_url.is_empty() {
            return Err(InitiationServiceError::InvalidIssuerBaseUrl);
        }
        Ok(Self {
            ports,
            issuer_base_url,
        })
    }

    pub async fn initiate(
        &self,
        request: &InitiationRequest,
        raw_idempotency_key: Option<&str>,
    ) -> Result<InitiationReservation, InitiationServiceError> {
        request.validate()?;
        let binding = idempotency_binding(raw_idempotency_key, request)?;
        match self
            .ports
            .organizations
            .validate(&request.organization_id)
            .await
        {
            OrganizationValidation::Found | OrganizationValidation::Unavailable => {}
            OrganizationValidation::NotFound => {
                return Err(InitiationServiceError::OrganizationNotFound)
            }
        }
        let authorized_client = self.validate_client(request).await?;
        if let Some(binding) = &binding {
            if let Some(transaction) = self
                .ports
                .repository
                .recover_idempotently(&request.organization_id, binding)
                .await?
            {
                return Ok(InitiationReservation {
                    transaction,
                    created: false,
                });
            }
        }
        let template = self.resolve_template(request).await?;
        validate_explicit_inputs(request, &template.credential_payload_format)?;
        if let Some(document) = &request.credential_document {
            self.ports
                .related_resources
                .validate(document)
                .await
                .map_err(InitiationServiceError::RelatedResourceValidation)?;
        }
        self.ports
            .revocation_profiles
            .validate_active(
                &request.organization_id,
                template.revocation_profile_id.as_deref(),
            )
            .await
            .map_err(InitiationServiceError::RevocationProfile)?;
        let claims = self.resolve_claims(request, &template).await;
        if binding.is_some() && has_didcomm_wallet(&template.wallet_configs) {
            return Err(InitiationServiceError::IdempotentDidcommUnsupported);
        }
        let now = self.ports.clock.now();
        let seed = self.ports.seeds.generate();
        let mut transaction = CredentialTransaction {
            id: seed.transaction_id,
            organization_id: request.organization_id.clone(),
            credential_template_id: request
                .credential_template_id
                .clone()
                .unwrap_or_else(|| "default".to_owned()),
            revocation_profile_id: template.revocation_profile_id,
            renewal_of_credential_id: None,
            applicant_id: request.applicant_id.clone(),
            application_id: request.application_id.clone(),
            subject_did: request.subject_did.clone(),
            idempotency_key_hash: binding.as_ref().map(|value| value.key_hash.clone()),
            idempotency_request_hash: binding.as_ref().map(|value| value.request_hash.clone()),
            status: CredentialTransactionStatus::Pending,
            pre_authorized_code: seed.pre_authorized_code,
            nonce: None,
            claims,
            credential_type: Some(template.credential_type),
            selective_disclosure_claims: template.selective_disclosure_claims,
            zk_predicate_claims: template.zk_predicate_claims,
            credential_payload_format: template.credential_payload_format,
            wallet_configs: template.wallet_configs,
            validity_days: template.validity_days,
            renewable: template.renewable,
            renewal_window_days: template.renewal_window_days,
            delivery_mode: request.normalized_delivery_mode()?,
            issuer_profile_id: None,
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some(request.issuer_did.clone()),
            issuer_algorithm: template.issuer_algorithm,
            signing_service_id: None,
            reserved_credential_id: None,
            oid4vci_client_id: authorized_client.map(|client| client.client_id),
            created_at: now,
            expires_at: now + Duration::minutes(10_080),
        };
        let remote_format = remote_credential_format(&transaction.credential_payload_format)
            .map_err(|_| InitiationServiceError::UnsupportedPayloadFormat)?;
        let issuer = self
            .ports
            .issuer_resolver
            .resolve(&transaction, &remote_format, false)
            .await
            .map_err(|_| InitiationServiceError::IssuerUnavailable)?;
        if issuer.issuer_did != request.issuer_did
            || transaction
                .issuer_algorithm
                .as_deref()
                .is_some_and(|algorithm| algorithm != issuer.algorithm)
        {
            return Err(InitiationServiceError::IssuerContextMismatch);
        }
        transaction.issuer_profile_id = Some(issuer.issuer_profile_id);
        transaction.issuer_did = Some(issuer.issuer_did);
        transaction.issuer_algorithm = Some(issuer.algorithm);
        transaction.signing_service_id = Some(issuer.signing_service_id);
        self.ports
            .repository
            .reserve_idempotently(&transaction)
            .await
            .map_err(Into::into)
    }

    async fn validate_client(
        &self,
        request: &InitiationRequest,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationServiceError> {
        let Some(client_id) = request.authorized_client_id.as_deref() else {
            return Ok(None);
        };
        let client = self
            .ports
            .clients
            .get(&request.organization_id, client_id)
            .await
            .map_err(InitiationServiceError::AuthorizedClientDependency)?
            .ok_or(InitiationServiceError::AuthorizedClientNotRegistered)?;
        if !client.active {
            return Err(InitiationServiceError::AuthorizedClientInactive);
        }
        if client.token_endpoint_auth_method != "private_key_jwt" {
            return Err(InitiationServiceError::AuthorizedClientAuthMethod);
        }
        Ok(Some(client))
    }

    async fn resolve_template(
        &self,
        request: &InitiationRequest,
    ) -> Result<InitiationTemplate, InitiationServiceError> {
        let Some(template_id) = request.credential_template_id.as_deref() else {
            return Ok(InitiationTemplate::default());
        };
        let template = self
            .ports
            .templates
            .resolve(template_id)
            .await
            .map_err(InitiationServiceError::Template)?;
        let template_issuer_did = template
            .issuer_did
            .as_deref()
            .ok_or(InitiationServiceError::TemplateIssuerMissing)?;
        if template_issuer_did != request.issuer_did {
            return Err(InitiationServiceError::TemplateIssuerMismatch);
        }
        if !matches!(
            template.issuer_algorithm.as_deref(),
            Some("ES256" | "ES384" | "RS256" | "EdDSA")
        ) {
            return Err(InitiationServiceError::TemplateAlgorithmUnsupported);
        }
        Ok(template)
    }

    async fn resolve_claims(
        &self,
        request: &InitiationRequest,
        template: &InitiationTemplate,
    ) -> Map<String, Value> {
        let mut claims = request.claims.clone().unwrap_or_default();
        if claims.is_empty()
            && request.credential_subject.is_none()
            && request.credential_document.is_none()
        {
            if let Some(application_id) = request.application_id.as_deref() {
                if let Ok(Some(application_claims)) =
                    self.ports.applications.resolve(application_id).await
                {
                    if !application_claims.is_empty() {
                        claims = application_claims;
                    }
                }
            }
        }
        let vct = template.vct.clone().unwrap_or_else(|| {
            format!(
                "{}/credentials/{}",
                self.issuer_base_url, template.credential_type
            )
        });
        claims.insert("_vct".to_owned(), Value::String(vct));
        if let Some(subject) = &request.credential_subject {
            claims.insert("_credential_subject".to_owned(), subject.clone());
        }
        if let Some(document) = &request.credential_document {
            claims.insert("_credential_document".to_owned(), document.clone());
        }
        claims
    }
}

fn validate_explicit_inputs(
    request: &InitiationRequest,
    payload_format: &str,
) -> Result<(), InitiationServiceError> {
    let normalized = payload_format.trim().to_ascii_lowercase().replace('-', "_");
    let jwt_vc = matches!(
        normalized.as_str(),
        "jwt_vc" | "jwt_vc_json" | "w3c_vcdm_v2_jwt" | "w3c_vcdm_v2_jwt_vc"
    );
    let data_integrity = matches!(normalized.as_str(), "json_ld" | "ldp_vc" | "w3c_vcdm_v2_di");
    if request.credential_subject.is_some() && !(jwt_vc || data_integrity) {
        return Err(InitiationServiceError::CredentialSubjectFormat);
    }
    if request.credential_document.is_some() && !data_integrity {
        return Err(InitiationServiceError::CredentialDocumentFormat);
    }
    Ok(())
}

fn has_didcomm_wallet(wallet_configs: &[Value]) -> bool {
    wallet_configs
        .iter()
        .any(|wallet| wallet.get("format_variant").and_then(Value::as_str) == Some("didcomm_v2"))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationServiceError {
    #[error(transparent)]
    Request(#[from] InitiationError),
    #[error(transparent)]
    Repository(#[from] InitiationRepositoryError),
    #[error("issuer base URL is required")]
    InvalidIssuerBaseUrl,
    #[error("organization was not found")]
    OrganizationNotFound,
    #[error("authorized_client_id is not registered for this organization")]
    AuthorizedClientNotRegistered,
    #[error("authorized_client_id is inactive")]
    AuthorizedClientInactive,
    #[error("authorized_client_id has an unsupported authentication method")]
    AuthorizedClientAuthMethod,
    #[error("authorized client validation failed: {0}")]
    AuthorizedClientDependency(InitiationDependencyError),
    #[error("credential template resolution failed: {0}")]
    Template(InitiationDependencyError),
    #[error("credential template must define an issuer DID")]
    TemplateIssuerMissing,
    #[error("issuer_did cannot override the credential template issuer DID")]
    TemplateIssuerMismatch,
    #[error("credential template must define a supported issuer algorithm")]
    TemplateAlgorithmUnsupported,
    #[error("credential_subject is unsupported for the selected payload format")]
    CredentialSubjectFormat,
    #[error("credential_document is unsupported for the selected payload format")]
    CredentialDocumentFormat,
    #[error("related-resource validation failed: {0}")]
    RelatedResourceValidation(InitiationDependencyError),
    #[error("revocation profile validation failed: {0}")]
    RevocationProfile(InitiationDependencyError),
    #[error("idempotent initiation does not support DIDComm push delivery")]
    IdempotentDidcommUnsupported,
    #[error("credential payload format is unsupported")]
    UnsupportedPayloadFormat,
    #[error("issuer context is unavailable")]
    IssuerUnavailable,
    #[error("issuer context does not match the selected template")]
    IssuerContextMismatch,
}

pub fn idempotency_binding(
    raw_key: Option<&str>,
    request: &InitiationRequest,
) -> Result<Option<IdempotencyBinding>, InitiationError> {
    let Some(key) = normalize_idempotency_key(raw_key)? else {
        return Ok(None);
    };
    let semantic_payload = request.semantic_payload()?;
    Ok(Some(IdempotencyBinding {
        key_hash: sha256(format!("{IDEMPOTENCY_KEY_PREFIX}{key}")),
        request_hash: sha256(format!(
            "{IDEMPOTENCY_REQUEST_PREFIX}{}",
            canonical_json(&semantic_payload)?
        )),
    }))
}

pub fn normalize_idempotency_key(value: Option<&str>) -> Result<Option<String>, InitiationError> {
    let raw = value.unwrap_or_default();
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Ok(None);
    }
    if raw != normalized {
        return Err(InitiationError::IdempotencyWhitespace);
    }
    let allowed = normalized
        .bytes()
        .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b':' | b'-'));
    if !allowed || normalized.len() > 128 {
        return Err(InitiationError::InvalidIdempotencyKey);
    }
    Ok(Some(normalized.to_owned()))
}

pub fn normalize_delivery_mode(value: &str) -> Result<String, InitiationError> {
    let normalized = value.trim();
    let normalized = if normalized.is_empty() {
        "wallet_only"
    } else {
        normalized
    };
    if !matches!(normalized, "wallet_only" | "wallet_plus_canvas_mirror") {
        return Err(InitiationError::InvalidDeliveryMode(normalized.to_owned()));
    }
    Ok(normalized.to_owned())
}

fn default_delivery_mode() -> String {
    "wallet_only".to_owned()
}

fn optional_string(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or_default()
}

fn validate_credential_document(document: &Value, issuer_did: &str) -> Result<(), InitiationError> {
    let document = document
        .as_object()
        .filter(|document| !document.is_empty())
        .ok_or(InitiationError::InvalidCredentialDocument)?;
    if document.contains_key("proof") {
        return Err(InitiationError::CredentialDocumentSigned);
    }
    let valid_context = document
        .get("@context")
        .and_then(Value::as_array)
        .and_then(|context| context.first())
        .and_then(Value::as_str)
        == Some(VCDM_V2_CONTEXT);
    if !valid_context {
        return Err(InitiationError::InvalidCredentialDocument);
    }
    let has_vc_type = match document.get("type") {
        Some(Value::String(value)) => value == "VerifiableCredential",
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some("VerifiableCredential")),
        _ => false,
    };
    if !has_vc_type {
        return Err(InitiationError::InvalidCredentialDocument);
    }
    validate_subject(
        document
            .get("credentialSubject")
            .ok_or(InitiationError::InvalidCredentialDocument)?,
    )
    .map_err(|_| InitiationError::InvalidCredentialDocument)?;
    if document.get("issuer").and_then(identifier) != Some(issuer_did) {
        return Err(InitiationError::CredentialDocumentIssuerMismatch);
    }
    Ok(())
}

fn validate_subject(subject: &Value) -> Result<(), InitiationError> {
    match subject {
        Value::Object(value) if !value.is_empty() => Ok(()),
        Value::Array(values)
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_object().is_some_and(|subject| !subject.is_empty())) =>
        {
            Ok(())
        }
        _ => Err(InitiationError::InvalidCredentialSubject),
    }
}

fn identifier(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("id")?.as_str())
}

fn canonical_json(value: &Value) -> Result<String, InitiationError> {
    serde_json::to_string(&canonicalize(value)).map_err(|_| InitiationError::Canonicalization)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut fields = object.iter().collect::<Vec<_>>();
            fields.sort_unstable_by_key(|(name, _)| *name);
            Value::Object(
                fields
                    .into_iter()
                    .map(|(name, value)| (name.clone(), canonicalize(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn sha256(value: String) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationError {
    #[error("issuer_did is required")]
    IssuerDidRequired,
    #[error("{0} is reserved for internal use")]
    ReservedClaim(String),
    #[error("credential_subject cannot be combined with claims")]
    CredentialSubjectWithClaims,
    #[error("credential_document cannot be combined with claims or credential_subject")]
    CredentialDocumentWithClaims,
    #[error("credential_subject must be a non-empty object or list of non-empty objects")]
    InvalidCredentialSubject,
    #[error("credential_document failed VCDM validation")]
    InvalidCredentialDocument,
    #[error("credential_document must be unsigned")]
    CredentialDocumentSigned,
    #[error("credential_document issuer must match the resolved issuer_did")]
    CredentialDocumentIssuerMismatch,
    #[error("idempotency key must not contain surrounding whitespace")]
    IdempotencyWhitespace,
    #[error("idempotency key must contain 1-128 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidIdempotencyKey,
    #[error(
        "Invalid delivery_mode '{0}'. Must be one of ['wallet_only', 'wallet_plus_canvas_mirror']"
    )]
    InvalidDeliveryMode(String),
    #[error("issuance request could not be canonicalized")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::TimeZone;

    use crate::credential::{CredentialIssuanceError, IssuerContext};

    use super::*;

    #[derive(Clone, Default)]
    struct CallLog(Arc<Mutex<Vec<&'static str>>>);

    impl CallLog {
        fn push(&self, name: &'static str) {
            self.0.lock().unwrap().push(name);
        }

        fn take(&self) -> Vec<&'static str> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    struct TestRepository {
        calls: CallLog,
        transaction: Mutex<Option<CredentialTransaction>>,
    }

    #[async_trait]
    impl InitiationRepository for TestRepository {
        async fn recover_idempotently(
            &self,
            _organization_id: &str,
            binding: &IdempotencyBinding,
        ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
            self.calls.push("recover-idempotent-transaction");
            let transaction = self.transaction.lock().unwrap().clone();
            if transaction.as_ref().is_some_and(|transaction| {
                transaction.idempotency_key_hash.as_ref() == Some(&binding.key_hash)
                    && transaction.idempotency_request_hash.as_ref() == Some(&binding.request_hash)
            }) {
                Ok(transaction)
            } else {
                Ok(None)
            }
        }

        async fn reserve_idempotently(
            &self,
            transaction: &CredentialTransaction,
        ) -> Result<InitiationReservation, InitiationRepositoryError> {
            self.calls.push("reserve-transaction-atomically");
            *self.transaction.lock().unwrap() = Some(transaction.clone());
            Ok(InitiationReservation {
                transaction: transaction.clone(),
                created: true,
            })
        }
    }

    struct TestOrganizations(CallLog);

    #[async_trait]
    impl InitiationOrganizationValidator for TestOrganizations {
        async fn validate(&self, _organization_id: &str) -> OrganizationValidation {
            self.0.push("validate-organization");
            OrganizationValidation::Found
        }
    }

    struct TestClients(CallLog);

    #[async_trait]
    impl InitiationClientRepository for TestClients {
        async fn get(
            &self,
            _organization_id: &str,
            client_id: &str,
        ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
            self.0.push("validate-authorized-client");
            Ok(Some(InitiationRegisteredClient {
                client_id: client_id.to_owned(),
                active: true,
                token_endpoint_auth_method: "private_key_jwt".to_owned(),
            }))
        }
    }

    struct TestTemplates(CallLog);

    #[async_trait]
    impl InitiationTemplateResolver for TestTemplates {
        async fn resolve(
            &self,
            _template_id: &str,
        ) -> Result<InitiationTemplate, InitiationDependencyError> {
            self.0.push("resolve-template");
            Ok(InitiationTemplate {
                credential_type: "UniversityDegreeCredential".to_owned(),
                vct: None,
                selective_disclosure_claims: vec!["degree".to_owned()],
                credential_payload_format: "w3c_vcdm_v2_jwt_vc".to_owned(),
                revocation_profile_id: Some("profile-1".to_owned()),
                issuer_did: Some("did:web:issuer.example".to_owned()),
                issuer_algorithm: Some("ES256".to_owned()),
                validity_days: 730,
                renewable: true,
                ..InitiationTemplate::default()
            })
        }
    }

    struct TestRevocationProfiles(CallLog);

    #[async_trait]
    impl InitiationRevocationProfileValidator for TestRevocationProfiles {
        async fn validate_active(
            &self,
            _organization_id: &str,
            profile_id: Option<&str>,
        ) -> Result<(), InitiationDependencyError> {
            self.0.push("validate-revocation-profile");
            assert_eq!(profile_id, Some("profile-1"));
            Ok(())
        }
    }

    struct TestApplications(CallLog);

    #[async_trait]
    impl InitiationApplicationClaimsResolver for TestApplications {
        async fn resolve(&self, _application_id: &str) -> Result<Option<Map<String, Value>>, ()> {
            self.0.push("resolve-application-claims");
            Ok(Some(
                serde_json::from_value(serde_json::json!({"degree": "BSc"})).unwrap(),
            ))
        }
    }

    struct TestRelatedResources;

    #[async_trait]
    impl InitiationRelatedResourceValidator for TestRelatedResources {
        async fn validate(
            &self,
            _credential_document: &Value,
        ) -> Result<(), InitiationDependencyError> {
            Ok(())
        }
    }

    struct TestIssuerResolver(CallLog);

    #[async_trait]
    impl IssuerContextResolver for TestIssuerResolver {
        async fn resolve(
            &self,
            _transaction: &CredentialTransaction,
            credential_format: &str,
            _force: bool,
        ) -> Result<IssuerContext, CredentialIssuanceError> {
            self.0.push("resolve-required-remote-kms-issuer-context");
            assert_eq!(credential_format, "jwt_vc_json");
            Ok(IssuerContext {
                issuer_profile_id: "issuer-profile-1".to_owned(),
                issuer_did: "did:web:issuer.example".to_owned(),
                signing_service_id: "kms-service-1".to_owned(),
                algorithm: "ES256".to_owned(),
                verification_method_id: Some("did:web:issuer.example#key-1".to_owned()),
                public_jwk: None,
                certificate_chain: Vec::new(),
                raw_context: serde_json::json!({}),
            })
        }
    }

    struct TestSeeds;

    impl InitiationSeedGenerator for TestSeeds {
        fn generate(&self) -> InitiationSeed {
            InitiationSeed {
                transaction_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                pre_authorized_code: "a".repeat(43),
            }
        }
    }

    struct TestClock;

    impl InitiationClock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap()
        }
    }

    fn request() -> InitiationRequest {
        serde_json::from_value(serde_json::json!({
            "organization_id": "org-1",
            "credential_template_id": "template-1",
            "application_id": "application-1",
            "applicant_id": "applicant-1",
            "subject_did": "did:key:z6MkHolder",
            "issuer_did": "did:web:issuer.example",
            "authorized_client_id": "client-1",
            "delivery_mode": "wallet_plus_canvas_mirror",
            "claims": {"profile": {"level": 2}, "roles": ["student", "member"]}
        }))
        .expect("valid initiation request")
    }

    #[tokio::test]
    async fn shared_service_preserves_dependency_order_and_short_circuits_recovery() {
        let calls = CallLog::default();
        let repository = Arc::new(TestRepository {
            calls: calls.clone(),
            transaction: Mutex::new(None),
        });
        let service = InitiationService::new(
            InitiationPorts {
                repository: repository.clone(),
                organizations: Arc::new(TestOrganizations(calls.clone())),
                clients: Arc::new(TestClients(calls.clone())),
                templates: Arc::new(TestTemplates(calls.clone())),
                revocation_profiles: Arc::new(TestRevocationProfiles(calls.clone())),
                applications: Arc::new(TestApplications(calls.clone())),
                related_resources: Arc::new(TestRelatedResources),
                issuer_resolver: Arc::new(TestIssuerResolver(calls.clone())),
                seeds: Arc::new(TestSeeds),
                clock: Arc::new(TestClock),
            },
            "https://issuer.example/",
        )
        .unwrap();
        let mut request = request();
        request.claims = None;
        let created = service
            .initiate(&request, Some("stable-retry"))
            .await
            .unwrap();
        assert!(created.created);
        assert_eq!(
            calls.take(),
            [
                "validate-organization",
                "validate-authorized-client",
                "recover-idempotent-transaction",
                "resolve-template",
                "validate-revocation-profile",
                "resolve-application-claims",
                "resolve-required-remote-kms-issuer-context",
                "reserve-transaction-atomically",
            ]
        );
        assert_eq!(created.transaction.claims["degree"], "BSc");
        assert_eq!(
            created.transaction.claims["_vct"],
            "https://issuer.example/credentials/UniversityDegreeCredential"
        );
        assert_eq!(
            created.transaction.expires_at - created.transaction.created_at,
            Duration::days(7)
        );
        assert_eq!(created.transaction.pre_authorized_code.len(), 43);
        assert_eq!(
            created.transaction.issuer_profile_id.as_deref(),
            Some("issuer-profile-1")
        );

        let recovered = service
            .initiate(&request, Some("stable-retry"))
            .await
            .unwrap();
        assert!(!recovered.created);
        assert_eq!(recovered.transaction.id, created.transaction.id);
        assert_eq!(
            calls.take(),
            [
                "validate-organization",
                "validate-authorized-client",
                "recover-idempotent-transaction",
            ]
        );
    }

    #[test]
    fn idempotency_vector_matches_the_language_neutral_contract() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-initiation.json"
        ))
        .expect("valid initiation contract");
        let vector = &contract["idempotency"]["vector"];
        let request: InitiationRequest =
            serde_json::from_value(vector["request"].clone()).expect("valid vector request");
        let binding = idempotency_binding(vector["key"].as_str(), &request)
            .expect("valid idempotency binding")
            .expect("binding is present");

        assert_eq!(binding.key_hash, vector["key_hash"]);
        assert_eq!(binding.request_hash, vector["request_hash"]);
        assert_eq!(request.semantic_payload().unwrap(), vector["request"]);
    }

    #[test]
    fn nested_claim_order_does_not_change_the_request_hash() {
        let first = request();
        let mut second = request();
        second.claims = Some(
            serde_json::from_value(serde_json::json!({
                "roles": ["student", "member"],
                "profile": {"level": 2}
            }))
            .unwrap(),
        );
        assert_eq!(
            idempotency_binding(Some("same"), &first).unwrap(),
            idempotency_binding(Some("same"), &second).unwrap()
        );
    }

    #[test]
    fn strict_request_and_explicit_subject_rules_match_the_contract() {
        let unknown = serde_json::from_value::<InitiationRequest>(serde_json::json!({
            "organization_id": "org-1",
            "issuer_did": "did:web:issuer.example",
            "unknown": true
        }));
        assert!(unknown.is_err());

        let mut explicit_subject = request();
        explicit_subject.credential_subject = Some(serde_json::json!({"name": "Ada"}));
        assert_eq!(
            explicit_subject.validate(),
            Err(InitiationError::CredentialSubjectWithClaims)
        );
        explicit_subject.claims = None;
        assert_eq!(explicit_subject.validate(), Ok(()));

        explicit_subject.credential_subject = Some(serde_json::json!([]));
        assert_eq!(
            explicit_subject.validate(),
            Err(InitiationError::InvalidCredentialSubject)
        );
    }

    #[test]
    fn unsigned_matching_vcdm_document_is_accepted_and_signed_or_foreign_is_rejected() {
        let document = serde_json::json!({
            "@context": [VCDM_V2_CONTEXT],
            "type": ["VerifiableCredential", "EmployeeCredential"],
            "issuer": {"id": "did:web:issuer.example"},
            "credentialSubject": [{"id": "did:example:subject", "employeeNumber": "E-1"}]
        });
        let mut request = request();
        request.claims = None;
        request.credential_document = Some(document.clone());
        assert_eq!(request.validate(), Ok(()));

        let mut signed = document.clone();
        signed
            .as_object_mut()
            .unwrap()
            .insert("proof".to_owned(), serde_json::json!({}));
        request.credential_document = Some(signed);
        assert_eq!(
            request.validate(),
            Err(InitiationError::CredentialDocumentSigned)
        );

        let mut foreign = document;
        foreign.as_object_mut().unwrap().insert(
            "issuer".to_owned(),
            Value::String("did:web:other.example".to_owned()),
        );
        request.credential_document = Some(foreign);
        assert_eq!(
            request.validate(),
            Err(InitiationError::CredentialDocumentIssuerMismatch)
        );
    }

    #[test]
    fn key_and_delivery_normalization_are_exact() {
        assert_eq!(normalize_idempotency_key(None), Ok(None));
        assert_eq!(normalize_idempotency_key(Some("")), Ok(None));
        assert_eq!(
            normalize_idempotency_key(Some(" padded")),
            Err(InitiationError::IdempotencyWhitespace)
        );
        assert_eq!(
            normalize_idempotency_key(Some("contains a space")),
            Err(InitiationError::InvalidIdempotencyKey)
        );
        assert_eq!(normalize_delivery_mode("  ").unwrap(), "wallet_only");
        assert_eq!(
            normalize_delivery_mode("direct-kms"),
            Err(InitiationError::InvalidDeliveryMode(
                "direct-kms".to_owned()
            ))
        );
    }

    #[test]
    fn secure_seed_and_format_boundaries_match_the_contract() {
        let seed = SecureInitiationSeedGenerator.generate();
        assert_eq!(
            uuid::Uuid::parse_str(&seed.transaction_id)
                .unwrap()
                .get_version_num(),
            4
        );
        assert_eq!(seed.pre_authorized_code.len(), 43);

        let mut request = request();
        request.claims = None;
        request.credential_subject = Some(serde_json::json!({"name": "Ada"}));
        assert_eq!(
            validate_explicit_inputs(&request, "w3c_vcdm_v2_jwt_vc"),
            Ok(())
        );
        assert_eq!(
            validate_explicit_inputs(&request, "w3c_vcdm_v2_sd_jwt"),
            Err(InitiationServiceError::CredentialSubjectFormat)
        );
        assert!(has_didcomm_wallet(&[serde_json::json!({
            "format_variant": "didcomm_v2"
        })]));
    }
}
