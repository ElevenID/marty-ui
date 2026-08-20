use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use mmf_security::{
    authorize_tenant_membership, SecurityError, TenantAuthorizationFailure,
    TenantMembershipProvider,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const REQUIRED_FLOW_PROVIDERS: &[&str] = &[
    "tenant_membership",
    "credential_template",
    "presentation_policy",
    "issuance",
    "signing_identity",
    "flow_key_envelope",
    "physical_document",
];

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowProviderError {
    #[error("FLOW.PROVIDER_NOT_FOUND: {provider}: {resource}")]
    NotFound {
        provider: &'static str,
        resource: String,
    },
    #[error("FLOW.PROVIDER_CONFLICT: {provider}: {message}")]
    Conflict {
        provider: &'static str,
        message: String,
    },
    #[error("FLOW.PROVIDER_REJECTED: {provider}: {message}")]
    Rejected {
        provider: &'static str,
        message: String,
    },
    #[error("FLOW.PROVIDER_INVALID_RESPONSE: {provider}: {message}")]
    InvalidResponse {
        provider: &'static str,
        message: String,
    },
    #[error("FLOW.PROVIDER_UNAVAILABLE: {provider}")]
    Unavailable { provider: &'static str },
    #[error("FLOW.PROVIDERS_MISSING: {0}")]
    Missing(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialTemplateReference {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub issuer_did: String,
    pub credential_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_algorithm: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PresentationPolicyReference {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    #[serde(default)]
    pub credential_requirements: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PresentationEvaluationRequest {
    pub policy_id: String,
    pub organization_id: String,
    pub presentation: String,
    pub nonce: String,
    pub audience: String,
    #[serde(default)]
    pub context: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PresentationEvaluationResult {
    pub result: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default)]
    pub verified_claims: BTreeMap<String, Value>,
    #[serde(default)]
    pub credential_results: Vec<Value>,
    #[serde(default)]
    pub error_codes: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IssuanceInitiationRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub credential_template_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    pub issuer_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IssuanceInitiationResult {
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_offer_uri: Option<String>,
    #[serde(default)]
    pub credential_offer_uris: BTreeMap<String, String>,
    #[serde(default)]
    pub credential_offer_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_authorized_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SigningIdentity {
    pub organization_id: String,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub public_jwk: BTreeMap<String, Value>,
    pub key_purpose: String,
    #[serde(default)]
    pub credential_format: String,
    pub algorithm: String,
}

impl SigningIdentity {
    pub fn validate_binding(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        algorithm: Option<&str>,
    ) -> Result<(), FlowProviderError> {
        let secret = ["d", "p", "q", "k"]
            .iter()
            .any(|name| self.public_jwk.contains_key(*name));
        let valid = self.organization_id == organization_id
            && self.issuer_did == issuer_did
            && self
                .verification_method_id
                .starts_with(&format!("{issuer_did}#"))
            && self.key_purpose == key_purpose
            && self.credential_format == credential_format
            && algorithm.is_none_or(|algorithm| self.algorithm == algorithm)
            && !self.algorithm.trim().is_empty()
            && public_key_matches_algorithm(&self.public_jwk, &self.algorithm)
            && !secret;
        if valid {
            Ok(())
        } else {
            Err(FlowProviderError::InvalidResponse {
                provider: "signing_identity",
                message: "identity is not bound to the requested tenant, DID, purpose, format, and algorithm".into(),
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SigningRequest {
    pub organization_id: String,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub key_purpose: String,
    pub credential_format: String,
    pub algorithm: String,
    pub payload_b64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SigningResult {
    pub issuer_did: String,
    pub verification_method_id: String,
    pub algorithm: String,
    pub signature_raw_b64url: String,
}

impl SigningResult {
    pub fn validate_binding(&self, request: &SigningRequest) -> Result<(), FlowProviderError> {
        if self.issuer_did == request.issuer_did
            && self.verification_method_id == request.verification_method_id
            && self.algorithm == request.algorithm
            && !self.signature_raw_b64url.trim().is_empty()
        {
            Ok(())
        } else {
            Err(FlowProviderError::InvalidResponse {
                provider: "signing_identity",
                message: "signature response identity does not match the request".into(),
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FlowKeyEnvelopeRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub purpose: String,
    pub key_json: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FlowKeyEnvelope {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub purpose: String,
    pub envelope: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalDocumentOperation {
    Initialize,
    GenerateDataGroups,
    SignSod,
    SubmitToPersonalization,
    TrackProduction,
    QualityVerify,
    ActivateCredential,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PhysicalDocumentRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub operation: PhysicalDocumentOperation,
    #[serde(default)]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PhysicalDocumentResult {
    pub operation: PhysicalDocumentOperation,
    pub status: String,
    #[serde(default)]
    pub data: BTreeMap<String, Value>,
}

#[async_trait]
pub trait CredentialTemplateProvider: Send + Sync {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError>;
}

#[async_trait]
pub trait PresentationPolicyProvider: Send + Sync {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError>;

    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError>;
}

#[async_trait]
pub trait IssuanceProvider: Send + Sync {
    async fn initiate(
        &self,
        request: &IssuanceInitiationRequest,
    ) -> Result<IssuanceInitiationResult, FlowProviderError>;
}

#[async_trait]
pub trait SigningIdentityProvider: Send + Sync {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError>;

    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError>;
}

#[async_trait]
pub trait FlowKeyEnvelopeProvider: Send + Sync {
    async fn wrap(
        &self,
        request: &FlowKeyEnvelopeRequest,
    ) -> Result<FlowKeyEnvelope, FlowProviderError>;

    async fn unwrap(&self, envelope: &FlowKeyEnvelope) -> Result<String, FlowProviderError>;
}

#[async_trait]
pub trait PhysicalDocumentProvider: Send + Sync {
    async fn execute(
        &self,
        request: &PhysicalDocumentRequest,
    ) -> Result<PhysicalDocumentResult, FlowProviderError>;
}

#[derive(Clone, Default)]
pub struct FlowProviderRegistry {
    pub tenant_membership: Option<Arc<dyn TenantMembershipProvider>>,
    pub credential_template: Option<Arc<dyn CredentialTemplateProvider>>,
    pub presentation_policy: Option<Arc<dyn PresentationPolicyProvider>>,
    pub issuance: Option<Arc<dyn IssuanceProvider>>,
    pub signing_identity: Option<Arc<dyn SigningIdentityProvider>>,
    pub flow_key_envelope: Option<Arc<dyn FlowKeyEnvelopeProvider>>,
    pub physical_document: Option<Arc<dyn PhysicalDocumentProvider>>,
}

impl FlowProviderRegistry {
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        [
            ("tenant_membership", self.tenant_membership.is_none()),
            ("credential_template", self.credential_template.is_none()),
            ("presentation_policy", self.presentation_policy.is_none()),
            ("issuance", self.issuance.is_none()),
            ("signing_identity", self.signing_identity.is_none()),
            ("flow_key_envelope", self.flow_key_envelope.is_none()),
            ("physical_document", self.physical_document.is_none()),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(name))
        .collect()
    }

    pub fn require_complete(&self) -> Result<(), FlowProviderError> {
        let missing = self.missing();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(FlowProviderError::Missing(missing.join(",")))
        }
    }

    pub async fn authorize(
        &self,
        principal_id: &str,
        organization_id: &str,
        permission: &str,
        owner_only: bool,
    ) -> Result<(), FlowProviderError> {
        let provider = self
            .tenant_membership
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "tenant_membership",
            })?;
        let membership = provider
            .membership(principal_id, organization_id)
            .await
            .map_err(|_| FlowProviderError::Unavailable {
                provider: "tenant_membership",
            })?;
        authorize_tenant_membership(
            permission,
            principal_id,
            organization_id,
            membership.as_ref(),
            owner_only,
        )
        .map_err(authorization_error)
    }
}

fn authorization_error(error: TenantAuthorizationFailure) -> FlowProviderError {
    let message = match error {
        TenantAuthorizationFailure::AuthenticationRequired => "authentication required",
        TenantAuthorizationFailure::MembershipMissing => "membership missing",
        TenantAuthorizationFailure::MembershipInactive => "membership inactive",
        TenantAuthorizationFailure::ActionNotAuthorized => "action not authorized",
    };
    FlowProviderError::Rejected {
        provider: "tenant_membership",
        message: message.into(),
    }
}

fn public_key_matches_algorithm(jwk: &BTreeMap<String, Value>, algorithm: &str) -> bool {
    let value = |name: &str| jwk.get(name).and_then(Value::as_str);
    match algorithm {
        "ES256" => {
            value("kty") == Some("EC")
                && value("crv") == Some("P-256")
                && value("x").is_some()
                && value("y").is_some()
        }
        "ES384" => {
            value("kty") == Some("EC")
                && value("crv") == Some("P-384")
                && value("x").is_some()
                && value("y").is_some()
        }
        "EdDSA" => {
            value("kty") == Some("OKP") && value("crv") == Some("Ed25519") && value("x").is_some()
        }
        "RS256" | "PS256" => {
            value("kty") == Some("RSA") && value("n").is_some() && value("e").is_some()
        }
        _ => false,
    }
}

impl From<SecurityError> for FlowProviderError {
    fn from(_: SecurityError) -> Self {
        Self::Unavailable {
            provider: "tenant_membership",
        }
    }
}
