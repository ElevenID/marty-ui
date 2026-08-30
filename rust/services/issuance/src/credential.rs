use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use mmf_security::constant_time_secret_eq;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    proof_nonce::{ProofNonceError, ProofNonceRepository},
    token_exchange::DpopProofVerifier,
};

const INTERNAL_CLAIM_FIELDS: &[&str] = &[
    "credential_offer_uri",
    "credential_offer_uris",
    "offer_expires_at",
    "issuance_transaction_id",
    "issuance_fallback",
    "credential_type",
    "credential_display_name",
    "rejection_reason",
    "review_notes",
    "info_requests",
    "applicant_id",
    "_vct",
    "_credential_subject",
    "_credential_document",
];

const SD_JWT_PAYLOAD_FORMATS: &[&str] = &[
    "w3c_vcdm_v2_sd_jwt",
    "ietf_sd_jwt",
    "sd_jwt_vc",
    "vc+sd_jwt",
    "dc+sd_jwt",
];
const JWT_VC_PAYLOAD_FORMATS: &[&str] = &[
    "jwt_vc",
    "jwt_vc_json",
    "w3c_vcdm_v2_jwt",
    "w3c_vcdm_v2_jwt_vc",
];
const MDOC_PAYLOAD_FORMATS: &[&str] = &["mso_mdoc", "mdoc"];
const DATA_INTEGRITY_PAYLOAD_FORMATS: &[&str] = &["json_ld", "ldp_vc", "w3c_vcdm_v2_di"];
const REDACTED_CREDENTIAL_DIAGNOSTIC: &str = "[REDACTED]";

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CredentialRequest {
    pub proofs: Option<Map<String, Value>>,
    pub credential_configuration_id: Option<String>,
    pub credential_identifier: Option<String>,
    pub(crate) legacy_format: Option<String>,
}

impl std::fmt::Debug for CredentialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("proof_count", &self.proofs.as_ref().map_or(0, Map::len))
            .field(
                "credential_configuration_id",
                &self.credential_configuration_id,
            )
            .field(
                "has_credential_identifier",
                &self.credential_identifier.is_some(),
            )
            .field("legacy_format", &self.legacy_format)
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct CanonicalCredentialRequest {
    proofs: Option<Map<String, Value>>,
    credential_configuration_id: Option<String>,
    credential_identifier: Option<String>,
}

impl<'de> Deserialize<'de> for CredentialRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("proof"))
        {
            return Err(serde::de::Error::custom(
                "use the OID4VCI 'proofs' object instead of removed 'proof'",
            ));
        }
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("format"))
        {
            return Err(serde::de::Error::custom(
                "select credential_configuration_id or credential_identifier; the removed 'format' member is not supported",
            ));
        }
        let canonical =
            CanonicalCredentialRequest::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            proofs: canonical.proofs,
            credential_configuration_id: canonical.credential_configuration_id,
            credential_identifier: canonical.credential_identifier,
            legacy_format: None,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CredentialResponse {
    pub credentials: Vec<Value>,
    pub notification_id: String,
}

impl std::fmt::Debug for CredentialResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialResponse")
            .field("credential_count", &self.credentials.len())
            .field("has_notification_id", &!self.notification_id.is_empty())
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

/// Transport-neutral result metadata for callers that must project a newly
/// committed issuance into another boundary, such as the legacy gRPC event
/// stream. Replayed or concurrently recovered credentials intentionally have
/// no `issued_credential`, matching the legacy adapter's one-event-per-commit
/// behavior.
#[derive(Clone, PartialEq)]
pub struct CredentialIssuanceOutcome {
    pub response: CredentialResponse,
    pub issued_credential: Option<IssuedCredential>,
    pub disposition: CredentialIssuanceDisposition,
}

impl std::fmt::Debug for CredentialIssuanceOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialIssuanceOutcome")
            .field("response", &self.response)
            .field("has_issued_credential", &self.issued_credential.is_some())
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialIssuanceDisposition {
    Committed,
    Replay,
    ConcurrentRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialTransactionStatus {
    Pending,
    Authorized,
    Signing,
    Issued,
    Failed,
    Expired,
    Revoked,
}

impl TryFrom<&str> for CredentialTransactionStatus {
    type Error = CredentialIssuanceError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "authorized" => Ok(Self::Authorized),
            "signing" => Ok(Self::Signing),
            "issued" => Ok(Self::Issued),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(CredentialIssuanceError::RepositoryUnavailable),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct CredentialTransaction {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub revocation_profile_id: Option<String>,
    pub renewal_of_credential_id: Option<String>,
    pub applicant_id: Option<String>,
    pub application_id: Option<String>,
    pub subject_did: Option<String>,
    pub idempotency_key_hash: Option<String>,
    pub idempotency_request_hash: Option<String>,
    pub status: CredentialTransactionStatus,
    pub pre_authorized_code: String,
    pub nonce: Option<String>,
    pub claims: Map<String, Value>,
    pub credential_type: Option<String>,
    pub selective_disclosure_claims: Vec<String>,
    pub zk_predicate_claims: Vec<String>,
    pub credential_payload_format: String,
    pub wallet_configs: Vec<Value>,
    pub validity_days: i64,
    pub renewable: bool,
    pub renewal_window_days: i64,
    pub delivery_mode: String,
    pub issuer_profile_id: Option<String>,
    pub issuer_mode: String,
    pub issuer_did: Option<String>,
    pub issuer_algorithm: Option<String>,
    pub signing_service_id: Option<String>,
    pub reserved_credential_id: Option<String>,
    pub oid4vci_client_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for CredentialTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialTransaction")
            .field("status", &self.status)
            .field(
                "has_revocation_profile",
                &self.revocation_profile_id.is_some(),
            )
            .field(
                "has_renewal_source",
                &self.renewal_of_credential_id.is_some(),
            )
            .field("has_applicant", &self.applicant_id.is_some())
            .field("has_application", &self.application_id.is_some())
            .field("has_subject_did", &self.subject_did.is_some())
            .field("has_idempotency_key", &self.idempotency_key_hash.is_some())
            .field(
                "has_idempotency_request_hash",
                &self.idempotency_request_hash.is_some(),
            )
            .field("has_nonce", &self.nonce.is_some())
            .field("claim_count", &self.claims.len())
            .field("credential_type", &self.credential_type)
            .field(
                "selective_disclosure_claim_count",
                &self.selective_disclosure_claims.len(),
            )
            .field("zk_predicate_claim_count", &self.zk_predicate_claims.len())
            .field("credential_payload_format", &self.credential_payload_format)
            .field("wallet_config_count", &self.wallet_configs.len())
            .field("validity_days", &self.validity_days)
            .field("renewable", &self.renewable)
            .field("renewal_window_days", &self.renewal_window_days)
            .field("delivery_mode", &self.delivery_mode)
            .field("has_issuer_profile", &self.issuer_profile_id.is_some())
            .field("issuer_mode", &self.issuer_mode)
            .field("has_issuer_did", &self.issuer_did.is_some())
            .field("issuer_algorithm", &self.issuer_algorithm)
            .field("has_signing_service", &self.signing_service_id.is_some())
            .field(
                "has_reserved_credential_id",
                &self.reserved_credential_id.is_some(),
            )
            .field("has_oid4vci_client", &self.oid4vci_client_id.is_some())
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialAuthorizationSession {
    pub id: String,
    pub organization_id: String,
    pub issuer_state: Option<String>,
    pub credential_configuration_ids: Vec<String>,
    pub dpop_jkt: Option<String>,
}

impl std::fmt::Debug for CredentialAuthorizationSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialAuthorizationSession")
            .field("has_issuer_state", &self.issuer_state.is_some())
            .field(
                "credential_configuration_count",
                &self.credential_configuration_ids.len(),
            )
            .field("has_dpop_binding", &self.dpop_jkt.is_some())
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub struct ExistingCredential {
    pub id: String,
    pub credential: String,
}

impl std::fmt::Debug for ExistingCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExistingCredential")
            .field("contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct IssuedCredential {
    pub id: String,
    pub transaction_id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub subject_did: Option<String>,
    pub issuer_did: String,
    pub revocation_profile_id: Option<String>,
    pub renewed_from_credential_id: Option<String>,
    pub status_list_entries: Vec<Value>,
    pub credential: String,
    pub credential_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("has_applicant", &self.applicant_id.is_some())
            .field("has_subject_did", &self.subject_did.is_some())
            .field(
                "has_revocation_profile",
                &self.revocation_profile_id.is_some(),
            )
            .field(
                "has_renewal_source",
                &self.renewed_from_credential_id.is_some(),
            )
            .field("status_list_entry_count", &self.status_list_entries.len())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub struct IssuerContext {
    pub issuer_profile_id: String,
    pub issuer_did: String,
    pub signing_service_id: String,
    pub algorithm: String,
    pub verification_method_id: Option<String>,
    pub public_jwk: Option<Value>,
    pub certificate_chain: Vec<String>,
    pub raw_context: Value,
}

impl std::fmt::Debug for IssuerContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuerContext")
            .field("issuer_profile_id", &self.issuer_profile_id)
            .field("issuer_did", &self.issuer_did)
            .field("signing_service_id", &self.signing_service_id)
            .field("algorithm", &self.algorithm)
            .field("verification_method_id", &self.verification_method_id)
            .field("has_public_jwk", &self.public_jwk.is_some())
            .field("certificate_chain_len", &self.certificate_chain.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub struct VerifiedCredentialProof {
    pub holder_did: String,
    pub holder_jwk: Option<Value>,
}

impl std::fmt::Debug for VerifiedCredentialProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedCredentialProof")
            .field("contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialBuilderKind {
    SdJwt,
    JwtVcJson,
    DataIntegrity,
    Mdoc,
}

#[derive(Clone, PartialEq)]
pub struct CredentialBuildRequest {
    pub organization_id: String,
    pub kind: CredentialBuilderKind,
    pub response_format: String,
    pub remote_credential_format: String,
    pub credential_id: String,
    pub credential_type: String,
    pub achievement_id: Option<String>,
    pub subject_did: Option<String>,
    pub holder_jwk: Option<Value>,
    pub claims: Map<String, Value>,
    pub credential_subject: Option<Value>,
    pub credential_document: Option<Value>,
    pub selective_disclosure_claims: Vec<String>,
    pub validity_seconds: i64,
    pub issuer: IssuerContext,
    pub status_list_entries: Vec<Value>,
}

impl std::fmt::Debug for CredentialBuildRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialBuildRequest")
            .field("kind", &self.kind)
            .field("response_format", &self.response_format)
            .field("remote_credential_format", &self.remote_credential_format)
            .field("has_achievement_id", &self.achievement_id.is_some())
            .field("has_subject_did", &self.subject_did.is_some())
            .field("has_holder_jwk", &self.holder_jwk.is_some())
            .field("claim_count", &self.claims.len())
            .field("has_credential_subject", &self.credential_subject.is_some())
            .field(
                "has_credential_document",
                &self.credential_document.is_some(),
            )
            .field(
                "selective_disclosure_claim_count",
                &self.selective_disclosure_claims.len(),
            )
            .field("validity_seconds", &self.validity_seconds)
            .field("issuer_algorithm", &self.issuer.algorithm)
            .field(
                "issuer_certificate_chain_len",
                &self.issuer.certificate_chain.len(),
            )
            .field("status_list_entry_count", &self.status_list_entries.len())
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BuiltCredential {
    pub credential_id: String,
    pub credential: String,
}

impl std::fmt::Debug for BuiltCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BuiltCredential")
            .field("contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish()
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct AllocatedCredentialStatus {
    pub revocation_profile_id: Option<String>,
    pub entries: Vec<Value>,
}

impl std::fmt::Debug for AllocatedCredentialStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AllocatedCredentialStatus")
            .field(
                "has_revocation_profile",
                &self.revocation_profile_id.is_some(),
            )
            .field("entry_count", &self.entries.len())
            .field("sensitive_contents", &REDACTED_CREDENTIAL_DIAGNOSTIC)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn transaction_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>;

    async fn authorization_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialAuthorizationSession>, CredentialIssuanceError>;

    async fn ensure_authorization_transaction(
        &self,
        session: &CredentialAuthorizationSession,
        access_token: &str,
    ) -> Result<CredentialTransaction, CredentialIssuanceError>;

    async fn credential_by_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ExistingCredential>, CredentialIssuanceError>;

    async fn transaction_by_id(
        &self,
        transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>;

    async fn claim_for_signing(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>;

    async fn finalize(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError>;

    async fn mark_failed_if_signing(
        &self,
        transaction_id: &str,
        reason: &str,
    ) -> Result<(), CredentialIssuanceError>;
}

#[async_trait]
pub trait CredentialProofVerifier: Send + Sync {
    async fn verify(
        &self,
        proof_jwt: &str,
        expected_nonce: &str,
        organization_id: &str,
        issuer: &IssuerContext,
    ) -> Result<VerifiedCredentialProof, CredentialIssuanceError>;
}

#[async_trait]
pub trait IssuerContextResolver: Send + Sync {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError>;
}

#[async_trait]
pub trait CredentialBuilder: Send + Sync {
    async fn build(
        &self,
        request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError>;
}

#[async_trait]
pub trait CredentialLifecycle: Send + Sync {
    async fn ensure_ready(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError>;

    async fn allocate_status(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
        credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError>;

    async fn after_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        response_format: &str,
    ) -> Result<(), CredentialIssuanceError>;

    async fn after_didcomm_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        service_endpoint: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        let _ = (service_endpoint, message_id);
        self.after_issued(transaction, credential, "vc+sd-jwt")
            .await
    }
}

pub trait NotificationIdGenerator: Send + Sync {
    fn generate(&self) -> String;
}

#[derive(Clone, Debug, Default)]
pub struct UuidNotificationIdGenerator;

impl NotificationIdGenerator for UuidNotificationIdGenerator {
    fn generate(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

#[derive(Clone)]
pub struct CredentialPorts {
    pub repository: Arc<dyn CredentialRepository>,
    pub nonce_repository: Arc<dyn ProofNonceRepository>,
    pub dpop_verifier: Arc<dyn DpopProofVerifier>,
    pub proof_verifier: Arc<dyn CredentialProofVerifier>,
    pub issuer_resolver: Arc<dyn IssuerContextResolver>,
    pub builder: Arc<dyn CredentialBuilder>,
    pub lifecycle: Arc<dyn CredentialLifecycle>,
    pub notification_ids: Arc<dyn NotificationIdGenerator>,
}

impl std::fmt::Debug for CredentialPorts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialPorts")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct CredentialIssuanceService {
    ports: CredentialPorts,
    issuer_base_url: Arc<str>,
}

impl CredentialIssuanceService {
    #[must_use]
    pub fn new(ports: CredentialPorts, issuer_base_url: &str) -> Self {
        Self {
            ports,
            issuer_base_url: Arc::from(issuer_base_url.trim_end_matches('/')),
        }
    }

    pub async fn issue(
        &self,
        request: &CredentialRequest,
        authorization: Option<&str>,
        dpop_proof: Option<&str>,
        endpoint_url: &str,
    ) -> Result<CredentialResponse, CredentialIssuanceError> {
        self.issue_with_outcome(request, authorization, dpop_proof, endpoint_url)
            .await
            .map(|outcome| outcome.response)
    }

    pub async fn issue_with_outcome(
        &self,
        request: &CredentialRequest,
        authorization: Option<&str>,
        dpop_proof: Option<&str>,
        endpoint_url: &str,
    ) -> Result<CredentialIssuanceOutcome, CredentialIssuanceError> {
        let access_token = bearer_token(authorization)?;
        let (mut transaction, authorization_session) = self.transaction(access_token).await?;
        self.verify_dpop(&transaction, dpop_proof, endpoint_url)?;
        validate_selector(request)?;
        if transaction.status == CredentialTransactionStatus::Issued {
            return self.existing_response(request, &transaction).await;
        }
        if transaction.status == CredentialTransactionStatus::Signing {
            return Err(CredentialIssuanceError::IssuanceInProgress);
        }
        if transaction.status != CredentialTransactionStatus::Authorized {
            return Err(CredentialIssuanceError::InvalidTransactionState);
        }
        validate_selection(request, &mut transaction, authorization_session.as_ref())?;
        let policy = format_policy(request, &transaction)?;
        let issuer = self
            .ports
            .issuer_resolver
            .resolve(&transaction, &policy.remote_format, false)
            .await?;
        apply_issuer_context(&mut transaction, &issuer);
        let proof_jwt = proof_jwt(request).ok_or(CredentialIssuanceError::ProofRequired)?;
        let proof_claims = unverified_proof_claims(proof_jwt)?;
        validate_audience(&proof_claims, &transaction.organization_id)?;
        let nonce = proof_claims
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(CredentialIssuanceError::InvalidNonce)?;
        let verified = self
            .ports
            .proof_verifier
            .verify(proof_jwt, nonce, &transaction.organization_id, &issuer)
            .await?;
        match self.ports.nonce_repository.consume_proof_nonce(nonce).await {
            Ok(true) => {}
            Ok(false) => return Err(CredentialIssuanceError::InvalidNonce),
            Err(ProofNonceError::RepositoryUnavailable) => {
                return Err(CredentialIssuanceError::NonceRepositoryUnavailable)
            }
        }
        let issuer = self
            .ports
            .issuer_resolver
            .resolve(&transaction, &policy.remote_format, true)
            .await?;
        apply_issuer_context(&mut transaction, &issuer);
        self.ports
            .lifecycle
            .ensure_ready(&transaction, &issuer)
            .await?;
        self.sign_and_finalize(transaction, policy, issuer, verified)
            .await
    }

    async fn transaction(
        &self,
        access_token: &str,
    ) -> Result<
        (
            CredentialTransaction,
            Option<CredentialAuthorizationSession>,
        ),
        CredentialIssuanceError,
    > {
        if let Some(transaction) = self
            .ports
            .repository
            .transaction_by_access_token(access_token)
            .await?
        {
            return Ok((transaction, None));
        }
        let session = self
            .ports
            .repository
            .authorization_by_access_token(access_token)
            .await?
            .ok_or(CredentialIssuanceError::InvalidAccessToken)?;
        let transaction = self
            .ports
            .repository
            .ensure_authorization_transaction(&session, access_token)
            .await?;
        Ok((transaction, Some(session)))
    }

    fn verify_dpop(
        &self,
        transaction: &CredentialTransaction,
        dpop_proof: Option<&str>,
        endpoint_url: &str,
    ) -> Result<(), CredentialIssuanceError> {
        let Some(expected) = transaction
            .claims
            .get("_dpop_jkt")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let proof = dpop_proof.ok_or(CredentialIssuanceError::DpopRequired)?;
        let actual = self
            .ports
            .dpop_verifier
            .verify(proof, "POST", endpoint_url)
            .map_err(|_| CredentialIssuanceError::InvalidDpopProof)?;
        if !constant_time_secret_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(CredentialIssuanceError::DpopMismatch);
        }
        Ok(())
    }

    async fn existing_response(
        &self,
        request: &CredentialRequest,
        transaction: &CredentialTransaction,
    ) -> Result<CredentialIssuanceOutcome, CredentialIssuanceError> {
        let existing = self
            .ports
            .repository
            .credential_by_transaction(&transaction.id)
            .await?
            .ok_or(CredentialIssuanceError::CredentialAlreadyIssued)?;
        let policy = format_policy(request, transaction)?;
        let response = response(
            &existing.credential,
            policy.kind,
            &policy.response_format,
            self.ports.notification_ids.generate(),
        )?;
        Ok(CredentialIssuanceOutcome {
            response,
            issued_credential: None,
            disposition: CredentialIssuanceDisposition::Replay,
        })
    }

    async fn sign_and_finalize(
        &self,
        transaction: CredentialTransaction,
        policy: FormatPolicy,
        issuer: IssuerContext,
        proof: VerifiedCredentialProof,
    ) -> Result<CredentialIssuanceOutcome, CredentialIssuanceError> {
        if policy.kind == CredentialBuilderKind::Mdoc && proof.holder_jwk.is_none() {
            return Err(CredentialIssuanceError::MdocHolderKeyRequired);
        }
        let credential_id = reserved_credential_id(&transaction);
        let Some(transaction) = self
            .ports
            .repository
            .claim_for_signing(&transaction, &credential_id)
            .await?
        else {
            return self.concurrent_response(&transaction.id, &policy).await;
        };
        let result = self
            .build_finalize_and_notify(&transaction, &credential_id, policy, issuer, proof)
            .await;
        if let Err(error) = &result {
            let _ = self
                .ports
                .repository
                .mark_failed_if_signing(&transaction.id, &error.to_string())
                .await;
        }
        result
    }

    async fn concurrent_response(
        &self,
        transaction_id: &str,
        policy: &FormatPolicy,
    ) -> Result<CredentialIssuanceOutcome, CredentialIssuanceError> {
        let current = self
            .ports
            .repository
            .transaction_by_id(transaction_id)
            .await?;
        let existing = self
            .ports
            .repository
            .credential_by_transaction(transaction_id)
            .await?;
        if current
            .as_ref()
            .is_some_and(|transaction| transaction.status == CredentialTransactionStatus::Issued)
        {
            if let Some(existing) = existing {
                let response = response(
                    &existing.credential,
                    policy.kind,
                    &policy.response_format,
                    self.ports.notification_ids.generate(),
                )?;
                return Ok(CredentialIssuanceOutcome {
                    response,
                    issued_credential: None,
                    disposition: CredentialIssuanceDisposition::ConcurrentRecovery,
                });
            }
        }
        Err(CredentialIssuanceError::IssuanceInProgress)
    }

    async fn build_finalize_and_notify(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
        policy: FormatPolicy,
        issuer: IssuerContext,
        proof: VerifiedCredentialProof,
    ) -> Result<CredentialIssuanceOutcome, CredentialIssuanceError> {
        let issued = materialize_credential(
            CredentialMaterializationContext {
                builder: self.ports.builder.as_ref(),
                lifecycle: self.ports.lifecycle.as_ref(),
                issuer_base_url: &self.issuer_base_url,
            },
            transaction,
            credential_id,
            &policy,
            issuer,
            proof,
        )
        .await?;
        self.ports.repository.finalize(transaction, &issued).await?;
        self.ports
            .lifecycle
            .after_issued(transaction, &issued, &policy.response_format)
            .await?;
        let response = response(
            &issued.credential,
            policy.kind,
            &policy.response_format,
            self.ports.notification_ids.generate(),
        )?;
        Ok(CredentialIssuanceOutcome {
            response,
            issued_credential: Some(issued),
            disposition: CredentialIssuanceDisposition::Committed,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CredentialMaterializationContext<'a> {
    pub(crate) builder: &'a dyn CredentialBuilder,
    pub(crate) lifecycle: &'a dyn CredentialLifecycle,
    pub(crate) issuer_base_url: &'a str,
}

pub(crate) async fn materialize_credential(
    context: CredentialMaterializationContext<'_>,
    transaction: &CredentialTransaction,
    credential_id: &str,
    policy: &FormatPolicy,
    issuer: IssuerContext,
    proof: VerifiedCredentialProof,
) -> Result<IssuedCredential, CredentialIssuanceError> {
    let status = context
        .lifecycle
        .allocate_status(transaction, credential_id, &policy.remote_format)
        .await?;
    let clean_claims = clean_claims(&transaction.claims);
    let disclosures = if policy.kind == CredentialBuilderKind::SdJwt
        && transaction.selective_disclosure_claims.is_empty()
    {
        clean_claims
            .keys()
            .filter(|name| !name.starts_with('_'))
            .cloned()
            .collect()
    } else {
        transaction.selective_disclosure_claims.clone()
    };
    let build_request = CredentialBuildRequest {
        organization_id: transaction.organization_id.clone(),
        kind: policy.kind,
        response_format: policy.response_format.clone(),
        remote_credential_format: policy.remote_format.clone(),
        credential_id: credential_id.to_owned(),
        credential_type: signing_credential_type(transaction, policy.kind, context.issuer_base_url),
        achievement_id: is_open_badge_type(transaction.credential_type.as_deref())
            .then(|| signing_vct(transaction, context.issuer_base_url)),
        subject_did: if policy.kind == CredentialBuilderKind::Mdoc {
            None
        } else {
            (!proof.holder_did.is_empty())
                .then_some(proof.holder_did.clone())
                .or_else(|| transaction.subject_did.clone())
        },
        holder_jwk: proof.holder_jwk,
        claims: clean_claims,
        credential_subject: transaction.claims.get("_credential_subject").cloned(),
        credential_document: transaction.claims.get("_credential_document").cloned(),
        selective_disclosure_claims: disclosures,
        validity_seconds: transaction.validity_days.saturating_mul(86_400),
        issuer: issuer.clone(),
        status_list_entries: status.entries.clone(),
    };
    let built = context.builder.build(&build_request).await?;
    if built.credential_id != credential_id {
        return Err(CredentialIssuanceError::BuilderChangedCredentialId);
    }
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::days(transaction.validity_days);
    Ok(IssuedCredential {
        id: credential_id.to_owned(),
        transaction_id: transaction.id.clone(),
        organization_id: transaction.organization_id.clone(),
        credential_template_id: transaction.credential_template_id.clone(),
        applicant_id: transaction.applicant_id.clone(),
        subject_did: build_request.subject_did,
        issuer_did: issuer.issuer_did,
        revocation_profile_id: status.revocation_profile_id,
        renewed_from_credential_id: transaction.renewal_of_credential_id.clone(),
        status_list_entries: status.entries,
        credential_hash: format!("{:x}", Sha256::digest(built.credential.as_bytes())),
        credential: built.credential,
        issued_at,
        expires_at,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FormatPolicy {
    pub(crate) kind: CredentialBuilderKind,
    pub(crate) response_format: String,
    pub(crate) remote_format: String,
}

fn bearer_token(authorization: Option<&str>) -> Result<&str, CredentialIssuanceError> {
    authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(CredentialIssuanceError::MissingAuthorization)
}

fn validate_selector(request: &CredentialRequest) -> Result<(), CredentialIssuanceError> {
    if request.credential_configuration_id.is_some() && request.credential_identifier.is_some() {
        return Err(CredentialIssuanceError::SelectorRequired);
    }
    if request.credential_configuration_id.is_none()
        && request.credential_identifier.is_none()
        && request.legacy_format.is_none()
    {
        return Err(CredentialIssuanceError::SelectorRequired);
    }
    Ok(())
}

fn validate_selection(
    request: &CredentialRequest,
    transaction: &mut CredentialTransaction,
    session: Option<&CredentialAuthorizationSession>,
) -> Result<(), CredentialIssuanceError> {
    if let Some(configuration_id) = &request.credential_configuration_id {
        let valid = if let Some(session) = session {
            session
                .credential_configuration_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            let credential_type = transaction.credential_type.as_deref().unwrap_or("default");
            let mut valid = BTreeSet::from([credential_configuration_id_for_format(
                credential_type,
                &transaction.credential_payload_format,
            )]);
            for variant in transaction
                .wallet_configs
                .iter()
                .filter_map(|config| config.get("format_variant").and_then(Value::as_str))
            {
                valid.insert(credential_configuration_id_for_format(
                    credential_type,
                    variant,
                ));
            }
            valid
        };
        if !valid.contains(configuration_id) {
            return Err(CredentialIssuanceError::UnknownConfiguration(
                configuration_id.clone(),
            ));
        }
        if session.is_some() {
            transaction.credential_type = Some(
                configuration_id
                    .split_once('#')
                    .map_or(configuration_id.as_str(), |(base, _)| base)
                    .to_owned(),
            );
        }
    }
    if let Some(identifier) = &request.credential_identifier {
        let valid = session.is_some_and(|session| {
            session
                .credential_configuration_ids
                .iter()
                .any(|value| value == identifier)
        });
        if !valid {
            return Err(CredentialIssuanceError::UnknownIdentifier(
                identifier.clone(),
            ));
        }
    }
    Ok(())
}

fn format_policy(
    request: &CredentialRequest,
    transaction: &CredentialTransaction,
) -> Result<FormatPolicy, CredentialIssuanceError> {
    let response_format = request.legacy_format.clone().unwrap_or_else(|| {
        request
            .credential_configuration_id
            .as_deref()
            .or(request.credential_identifier.as_deref())
            .and_then(format_from_configuration_id)
            .map(str::to_owned)
            .unwrap_or_else(|| default_request_format(&transaction.credential_payload_format))
    });
    let normalized = normalize_format(&transaction.credential_payload_format);
    let kind = if MDOC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        CredentialBuilderKind::Mdoc
    } else if DATA_INTEGRITY_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        CredentialBuilderKind::DataIntegrity
    } else if SD_JWT_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        CredentialBuilderKind::SdJwt
    } else if JWT_VC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        CredentialBuilderKind::JwtVcJson
    } else {
        return Err(CredentialIssuanceError::UnsupportedFormat(normalized));
    };
    let remote_format = remote_credential_format(&transaction.credential_payload_format)?;
    Ok(FormatPolicy {
        kind,
        response_format,
        remote_format,
    })
}

pub(crate) fn didcomm_format_policy(
    transaction: &CredentialTransaction,
) -> Result<FormatPolicy, CredentialIssuanceError> {
    let normalized = normalize_format(&transaction.credential_payload_format);
    if !SD_JWT_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        return Err(CredentialIssuanceError::UnsupportedFormat(normalized));
    }
    Ok(FormatPolicy {
        kind: CredentialBuilderKind::SdJwt,
        response_format: "vc+sd-jwt".to_owned(),
        remote_format: remote_credential_format(&transaction.credential_payload_format)?,
    })
}

pub(crate) fn remote_credential_format(
    payload_format: &str,
) -> Result<String, CredentialIssuanceError> {
    let normalized = normalize_format(payload_format);
    if MDOC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("mso_mdoc".to_owned())
    } else if DATA_INTEGRITY_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("ldp_vc".to_owned())
    } else if SD_JWT_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("dc+sd-jwt".to_owned())
    } else if JWT_VC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("jwt_vc_json".to_owned())
    } else {
        Err(CredentialIssuanceError::UnsupportedFormat(normalized))
    }
}

fn normalize_format(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn format_from_configuration_id(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.ends_with("#credential-manager") || normalized.ends_with("#sd-jwt") {
        Some("dc+sd-jwt")
    } else if normalized.ends_with("#mdoc") || normalized.ends_with("#apple-wallet") {
        Some("mso_mdoc")
    } else if normalized.ends_with("#ldp-vc") {
        Some("ldp_vc")
    } else {
        None
    }
}

fn default_request_format(payload_format: &str) -> String {
    let normalized = normalize_format(payload_format);
    if MDOC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        "mso_mdoc"
    } else if DATA_INTEGRITY_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        "ldp_vc"
    } else if SD_JWT_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        "vc+sd-jwt"
    } else {
        "jwt_vc_json"
    }
    .to_owned()
}

pub(crate) fn credential_configuration_id_for_format(base: &str, variant: &str) -> String {
    let normalized = normalize_format(variant);
    if MDOC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        format!("{base}#mdoc")
    } else if DATA_INTEGRITY_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        format!("{base}#ldp-vc")
    } else if JWT_VC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        base.to_owned()
    } else if normalized == "credential_manager" {
        format!("{base}#credential-manager")
    } else if normalized == "apple_wallet" {
        format!("{base}#apple-wallet")
    } else {
        format!("{base}#sd-jwt")
    }
}

fn proof_jwt(request: &CredentialRequest) -> Option<&str> {
    request
        .proofs
        .as_ref()?
        .get("jwt")?
        .as_array()?
        .first()?
        .as_str()
}

fn unverified_proof_claims(proof: &str) -> Result<Map<String, Value>, CredentialIssuanceError> {
    let mut parts = proof.split('.');
    let _header = parts.next();
    let payload = parts
        .next()
        .ok_or(CredentialIssuanceError::MalformedProof)?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(CredentialIssuanceError::MalformedProof);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CredentialIssuanceError::MalformedProof)?;
    serde_json::from_slice::<Value>(&decoded)
        .map_err(|_| CredentialIssuanceError::MalformedProof)?
        .as_object()
        .cloned()
        .ok_or(CredentialIssuanceError::MalformedProof)
}

fn allowed_audience_paths(organization_id: &str) -> [String; 4] {
    [
        format!("/org/{organization_id}"),
        format!("/org/{organization_id}/credential-manager"),
        format!("/org/{organization_id}/apple-wallet"),
        format!("/org/{organization_id}/waltid"),
    ]
}

fn validate_audience(
    claims: &Map<String, Value>,
    organization_id: &str,
) -> Result<(), CredentialIssuanceError> {
    let audience = claims.get("aud").and_then(Value::as_str).unwrap_or("");
    let path = if audience.contains("://") {
        url::Url::parse(audience)
            .map_err(|_| CredentialIssuanceError::MalformedProof)?
            .path()
            .trim_end_matches('/')
            .to_owned()
    } else {
        audience.trim_end_matches('/').to_owned()
    };
    let allowed = allowed_audience_paths(organization_id);
    if !allowed.iter().any(|candidate| candidate == &path) {
        return Err(CredentialIssuanceError::AudienceMismatch {
            allowed,
            actual: audience.to_owned(),
        });
    }
    Ok(())
}

fn clean_claims(claims: &Map<String, Value>) -> Map<String, Value> {
    claims
        .iter()
        .filter(|(name, _)| !INTERNAL_CLAIM_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub(crate) fn reserved_credential_id(transaction: &CredentialTransaction) -> String {
    transaction
        .reserved_credential_id
        .clone()
        .or_else(|| {
            transaction
                .claims
                .get("_credential_document")
                .and_then(Value::as_object)
                .and_then(|document| document.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            format!(
                "urn:uuid:{}",
                Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("marty:issuance:{}", transaction.id).as_bytes()
                )
            )
        })
}

fn signing_credential_type(
    transaction: &CredentialTransaction,
    kind: CredentialBuilderKind,
    issuer_base_url: &str,
) -> String {
    let credential_type = transaction
        .credential_type
        .as_deref()
        .unwrap_or("org.iso.18013.5.1.mDL");
    if matches!(
        kind,
        CredentialBuilderKind::Mdoc | CredentialBuilderKind::JwtVcJson
    ) {
        return credential_type.to_owned();
    }
    transaction
        .claims
        .get("_vct")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if credential_type.starts_with("http") {
                credential_type.to_owned()
            } else {
                format!("{issuer_base_url}/credentials/{credential_type}")
            }
        })
}

fn signing_vct(transaction: &CredentialTransaction, issuer_base_url: &str) -> String {
    let credential_type = transaction
        .credential_type
        .as_deref()
        .unwrap_or("VerifiableCredential");
    transaction
        .claims
        .get("_vct")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if credential_type.starts_with("http") {
                credential_type.to_owned()
            } else {
                format!("{issuer_base_url}/credentials/{credential_type}")
            }
        })
}

fn is_open_badge_type(value: Option<&str>) -> bool {
    matches!(
        value
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "open_badge" | "open_badge_v3" | "openbadgecredential"
    )
}

pub(crate) fn apply_issuer_context(
    transaction: &mut CredentialTransaction,
    issuer: &IssuerContext,
) {
    transaction.issuer_profile_id = Some(issuer.issuer_profile_id.clone());
    transaction.issuer_did = Some(issuer.issuer_did.clone());
    transaction.issuer_algorithm = Some(issuer.algorithm.clone());
    transaction.signing_service_id = Some(issuer.signing_service_id.clone());
}

fn response(
    credential: &str,
    kind: CredentialBuilderKind,
    response_format: &str,
    notification_id: String,
) -> Result<CredentialResponse, CredentialIssuanceError> {
    let credential = if kind == CredentialBuilderKind::DataIntegrity {
        let document: Value = serde_json::from_str(credential)
            .map_err(|_| CredentialIssuanceError::InvalidStoredDataIntegrityCredential)?;
        if !document.is_object() || !document["proof"].is_object() {
            return Err(CredentialIssuanceError::InvalidStoredDataIntegrityCredential);
        }
        document
    } else {
        Value::String(credential.to_owned())
    };
    Ok(CredentialResponse {
        credentials: vec![serde_json::json!({
            "format": response_format,
            "credential": credential,
        })],
        notification_id,
    })
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialIssuanceError {
    #[error("missing or invalid authorization")]
    MissingAuthorization,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("DPoP proof is required")]
    DpopRequired,
    #[error("invalid DPoP proof")]
    InvalidDpopProof,
    #[error("DPoP proof does not match access token")]
    DpopMismatch,
    #[error("exactly one credential selector is required")]
    SelectorRequired,
    #[error("credential already issued")]
    CredentialAlreadyIssued,
    #[error("invalid transaction state")]
    InvalidTransactionState,
    #[error("unknown credential configuration: {0}")]
    UnknownConfiguration(String),
    #[error("unknown credential identifier: {0}")]
    UnknownIdentifier(String),
    #[error("proof is required")]
    ProofRequired,
    #[error("proof JWT could not be decoded")]
    MalformedProof,
    #[error("proof audience mismatch")]
    AudienceMismatch {
        allowed: [String; 4],
        actual: String,
    },
    #[error("invalid proof nonce")]
    InvalidNonce,
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    #[error("proof nonce repository is unavailable")]
    NonceRepositoryUnavailable,
    #[error("mso_mdoc requires a verified holder public JWK")]
    MdocHolderKeyRequired,
    #[error("unsupported credential format: {0}")]
    UnsupportedFormat(String),
    #[error("credential issuance is in progress")]
    IssuanceInProgress,
    #[error("credential builder changed the reserved credential ID")]
    BuilderChangedCredentialId,
    #[error("stored ldp_vc credential is invalid")]
    InvalidStoredDataIntegrityCredential,
    #[error("issuer identity is unavailable: {0}")]
    IssuerUnavailable(String),
    #[error("credential signing is unavailable: {0}")]
    SigningUnavailable(String),
    #[error("credential lifecycle dependency is unavailable: {0}")]
    LifecycleUnavailable(String),
    #[error("the credential template has no revocation profile")]
    RevocationProfileRequired,
    #[error("credential eligibility requirements are not satisfied")]
    CanvasEligibilityDenied,
    #[error("credential repository is unavailable")]
    RepositoryUnavailable,
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map, Value};

    use super::{
        clean_claims, credential_configuration_id_for_format, format_policy,
        reserved_credential_id, validate_audience, validate_selector, AllocatedCredentialStatus,
        BuiltCredential, CredentialAuthorizationSession, CredentialBuildRequest,
        CredentialBuilderKind, CredentialIssuanceDisposition, CredentialIssuanceOutcome,
        CredentialRequest, CredentialResponse, CredentialTransaction, CredentialTransactionStatus,
        ExistingCredential, IssuedCredential, IssuerContext, VerifiedCredentialProof,
    };

    fn transaction() -> CredentialTransaction {
        CredentialTransaction {
            id: "tx-signing-contract".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            revocation_profile_id: None,
            renewal_of_credential_id: None,
            applicant_id: None,
            application_id: None,
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Authorized,
            pre_authorized_code: "pre-auth".to_owned(),
            nonce: Some("proof-nonce".to_owned()),
            claims: serde_json::from_value(json!({
                "achievement": "Portable Canvas",
                "applicant_id": "internal",
            }))
            .expect("claims"),
            credential_type: Some("OpenBadgeCredential".to_owned()),
            selective_disclosure_claims: vec![],
            zk_predicate_claims: vec![],
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            wallet_configs: vec![],
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
            delivery_mode: "wallet_only".to_owned(),
            issuer_profile_id: None,
            issuer_mode: "org_managed".to_owned(),
            issuer_did: None,
            issuer_algorithm: None,
            signing_service_id: None,
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        }
    }

    #[test]
    fn credential_pipeline_debug_output_is_stable_and_fully_redacted() {
        fn canary_object(key: &str, value: &str) -> Value {
            Value::Object(Map::from_iter([(
                key.to_owned(),
                Value::String(value.to_owned()),
            )]))
        }

        fn assert_redacted<T: std::fmt::Debug>(value: &T, canaries: &[&str]) -> String {
            let compact = format!("{value:?}");
            let pretty = format!("{value:#?}");
            assert!(pretty.contains("[REDACTED]"));
            for canary in canaries {
                assert!(
                    !compact.contains(canary),
                    "compact credential diagnostic exposed canary: {canary}"
                );
                assert!(
                    !pretty.contains(canary),
                    "pretty credential diagnostic exposed canary: {canary}"
                );
            }
            compact
        }

        const PROOF_CANARIES: &[&str] = &[
            "proof-holder-did-canary",
            "proof-jwk-kty-canary",
            "proof-jwk-crv-canary",
            "proof-jwk-x-canary",
            "proof-jwk-y-canary",
            "proof-jwk-d-canary",
            "proof-jwk-p-canary",
            "proof-jwk-q-canary",
            "proof-jwk-dp-canary",
            "proof-jwk-dq-canary",
            "proof-jwk-qi-canary",
            "proof-jwk-oth-canary",
            "proof-jwk-k-canary",
        ];
        let proof = VerifiedCredentialProof {
            holder_did: PROOF_CANARIES[0].to_owned(),
            holder_jwk: Some(json!({
                "kty": PROOF_CANARIES[1],
                "crv": PROOF_CANARIES[2],
                "x": PROOF_CANARIES[3],
                "y": PROOF_CANARIES[4],
                "d": PROOF_CANARIES[5],
                "p": PROOF_CANARIES[6],
                "q": PROOF_CANARIES[7],
                "dp": PROOF_CANARIES[8],
                "dq": PROOF_CANARIES[9],
                "qi": PROOF_CANARIES[10],
                "oth": [{"r": PROOF_CANARIES[11]}],
                "k": PROOF_CANARIES[12],
            })),
        };

        const REQUEST_CANARIES: &[&str] = &[
            "request-organization-canary",
            "request-response-format-canary",
            "request-remote-format-canary",
            "request-credential-id-canary",
            "request-credential-type-canary",
            "request-achievement-id-canary",
            "request-subject-did-canary",
            "request-holder-jwk-kty-canary",
            "request-holder-jwk-crv-canary",
            "request-holder-jwk-x-canary",
            "request-holder-jwk-y-canary",
            "request-holder-jwk-d-canary",
            "request-holder-jwk-p-canary",
            "request-holder-jwk-q-canary",
            "request-holder-jwk-dp-canary",
            "request-holder-jwk-dq-canary",
            "request-holder-jwk-qi-canary",
            "request-holder-jwk-oth-canary",
            "request-holder-jwk-k-canary",
            "request-claim-name-canary",
            "request-claim-value-canary",
            "request-subject-name-canary",
            "request-subject-value-canary",
            "request-document-name-canary",
            "request-document-value-canary",
            "request-disclosure-name-canary",
            "request-validity-control-canary",
            "request-issuer-profile-canary",
            "request-issuer-did-canary",
            "request-signing-service-canary",
            "request-algorithm-canary",
            "request-verification-method-canary",
            "request-issuer-jwk-kty-canary",
            "request-issuer-jwk-d-canary",
            "request-certificate-leaf-canary",
            "request-certificate-intermediate-canary",
            "request-raw-context-name-canary",
            "request-raw-context-value-canary",
            "request-status-name-canary",
            "request-status-value-canary",
        ];
        let request = CredentialBuildRequest {
            organization_id: REQUEST_CANARIES[0].to_owned(),
            kind: CredentialBuilderKind::SdJwt,
            response_format: "dc+sd-jwt".to_owned(),
            remote_credential_format: "dc+sd-jwt".to_owned(),
            credential_id: REQUEST_CANARIES[3].to_owned(),
            credential_type: REQUEST_CANARIES[4].to_owned(),
            achievement_id: Some(REQUEST_CANARIES[5].to_owned()),
            subject_did: Some(REQUEST_CANARIES[6].to_owned()),
            holder_jwk: Some(json!({
                "kty": REQUEST_CANARIES[7],
                "crv": REQUEST_CANARIES[8],
                "x": REQUEST_CANARIES[9],
                "y": REQUEST_CANARIES[10],
                "d": REQUEST_CANARIES[11],
                "p": REQUEST_CANARIES[12],
                "q": REQUEST_CANARIES[13],
                "dp": REQUEST_CANARIES[14],
                "dq": REQUEST_CANARIES[15],
                "qi": REQUEST_CANARIES[16],
                "oth": [{"r": REQUEST_CANARIES[17]}],
                "k": REQUEST_CANARIES[18],
            })),
            claims: Map::from_iter([(
                REQUEST_CANARIES[19].to_owned(),
                Value::String(REQUEST_CANARIES[20].to_owned()),
            )]),
            credential_subject: Some(canary_object(REQUEST_CANARIES[21], REQUEST_CANARIES[22])),
            credential_document: Some(canary_object(REQUEST_CANARIES[23], REQUEST_CANARIES[24])),
            selective_disclosure_claims: vec![REQUEST_CANARIES[25].to_owned()],
            validity_seconds: 9_876_543_210,
            issuer: IssuerContext {
                issuer_profile_id: REQUEST_CANARIES[27].to_owned(),
                issuer_did: REQUEST_CANARIES[28].to_owned(),
                signing_service_id: REQUEST_CANARIES[29].to_owned(),
                algorithm: "ES256".to_owned(),
                verification_method_id: Some(REQUEST_CANARIES[31].to_owned()),
                public_jwk: Some(json!({
                    "kty": REQUEST_CANARIES[32],
                    "d": REQUEST_CANARIES[33],
                })),
                certificate_chain: vec![
                    REQUEST_CANARIES[34].to_owned(),
                    REQUEST_CANARIES[35].to_owned(),
                ],
                raw_context: canary_object(REQUEST_CANARIES[36], REQUEST_CANARIES[37]),
            },
            status_list_entries: vec![canary_object(REQUEST_CANARIES[38], REQUEST_CANARIES[39])],
        };

        const BUILT_CANARIES: &[&str] = &[
            "built-credential-id-canary",
            "built-signed-header-canary",
            "built-signed-payload-canary",
            "built-signature-canary",
            "built-disclosure-one-canary",
            "built-disclosure-two-canary",
        ];
        let built = BuiltCredential {
            credential_id: BUILT_CANARIES[0].to_owned(),
            credential: format!(
                "{}.{}.{}~{}~{}~",
                BUILT_CANARIES[1],
                BUILT_CANARIES[2],
                BUILT_CANARIES[3],
                BUILT_CANARIES[4],
                BUILT_CANARIES[5]
            ),
        };

        const TRANSPORT_CANARIES: &[&str] = &[
            "request-proof-jwt-canary",
            "request-credential-identifier-canary",
            "response-signed-credential-canary",
            "response-notification-id-canary",
        ];
        let credential_request = CredentialRequest {
            proofs: Some(Map::from_iter([(
                "jwt".to_owned(),
                json!([TRANSPORT_CANARIES[0]]),
            )])),
            credential_configuration_id: Some("OpenBadgeCredential#sd-jwt".to_owned()),
            credential_identifier: Some(TRANSPORT_CANARIES[1].to_owned()),
            legacy_format: Some("dc+sd-jwt".to_owned()),
        };
        let response = CredentialResponse {
            credentials: vec![json!({"credential": TRANSPORT_CANARIES[2]})],
            notification_id: TRANSPORT_CANARIES[3].to_owned(),
        };

        const TRANSACTION_CANARIES: &[&str] = &[
            "transaction-id-canary",
            "transaction-organization-canary",
            "transaction-template-canary",
            "transaction-revocation-profile-canary",
            "transaction-renewal-source-canary",
            "transaction-applicant-canary",
            "transaction-application-canary",
            "transaction-subject-did-canary",
            "transaction-idempotency-key-canary",
            "transaction-idempotency-request-canary",
            "transaction-pre-authorized-code-canary",
            "transaction-nonce-canary",
            "transaction-claim-name-canary",
            "transaction-claim-value-canary",
            "transaction-disclosure-canary",
            "transaction-predicate-canary",
            "transaction-wallet-config-canary",
            "transaction-issuer-profile-canary",
            "transaction-issuer-did-canary",
            "transaction-signing-service-canary",
            "transaction-reserved-credential-canary",
            "transaction-client-canary",
        ];
        let mut diagnostic_transaction = transaction();
        diagnostic_transaction.id = TRANSACTION_CANARIES[0].to_owned();
        diagnostic_transaction.organization_id = TRANSACTION_CANARIES[1].to_owned();
        diagnostic_transaction.credential_template_id = TRANSACTION_CANARIES[2].to_owned();
        diagnostic_transaction.revocation_profile_id = Some(TRANSACTION_CANARIES[3].to_owned());
        diagnostic_transaction.renewal_of_credential_id = Some(TRANSACTION_CANARIES[4].to_owned());
        diagnostic_transaction.applicant_id = Some(TRANSACTION_CANARIES[5].to_owned());
        diagnostic_transaction.application_id = Some(TRANSACTION_CANARIES[6].to_owned());
        diagnostic_transaction.subject_did = Some(TRANSACTION_CANARIES[7].to_owned());
        diagnostic_transaction.idempotency_key_hash = Some(TRANSACTION_CANARIES[8].to_owned());
        diagnostic_transaction.idempotency_request_hash = Some(TRANSACTION_CANARIES[9].to_owned());
        diagnostic_transaction.pre_authorized_code = TRANSACTION_CANARIES[10].to_owned();
        diagnostic_transaction.nonce = Some(TRANSACTION_CANARIES[11].to_owned());
        diagnostic_transaction.claims = Map::from_iter([(
            TRANSACTION_CANARIES[12].to_owned(),
            Value::String(TRANSACTION_CANARIES[13].to_owned()),
        )]);
        diagnostic_transaction.selective_disclosure_claims =
            vec![TRANSACTION_CANARIES[14].to_owned()];
        diagnostic_transaction.zk_predicate_claims = vec![TRANSACTION_CANARIES[15].to_owned()];
        diagnostic_transaction.wallet_configs = vec![json!(TRANSACTION_CANARIES[16])];
        diagnostic_transaction.issuer_profile_id = Some(TRANSACTION_CANARIES[17].to_owned());
        diagnostic_transaction.issuer_did = Some(TRANSACTION_CANARIES[18].to_owned());
        diagnostic_transaction.issuer_algorithm = Some("ES256".to_owned());
        diagnostic_transaction.signing_service_id = Some(TRANSACTION_CANARIES[19].to_owned());
        diagnostic_transaction.reserved_credential_id = Some(TRANSACTION_CANARIES[20].to_owned());
        diagnostic_transaction.oid4vci_client_id = Some(TRANSACTION_CANARIES[21].to_owned());

        const PERSISTENCE_CANARIES: &[&str] = &[
            "authorization-id-canary",
            "authorization-organization-canary",
            "authorization-issuer-state-canary",
            "authorization-configuration-canary",
            "authorization-dpop-canary",
            "existing-credential-id-canary",
            "existing-signed-credential-canary",
            "issued-credential-id-canary",
            "issued-transaction-id-canary",
            "issued-organization-canary",
            "issued-template-canary",
            "issued-applicant-canary",
            "issued-subject-did-canary",
            "issued-issuer-did-canary",
            "issued-revocation-profile-canary",
            "issued-renewal-source-canary",
            "issued-status-entry-canary",
            "issued-signed-credential-canary",
            "issued-credential-hash-canary",
            "allocated-revocation-profile-canary",
            "allocated-entry-canary",
        ];
        let authorization = CredentialAuthorizationSession {
            id: PERSISTENCE_CANARIES[0].to_owned(),
            organization_id: PERSISTENCE_CANARIES[1].to_owned(),
            issuer_state: Some(PERSISTENCE_CANARIES[2].to_owned()),
            credential_configuration_ids: vec![PERSISTENCE_CANARIES[3].to_owned()],
            dpop_jkt: Some(PERSISTENCE_CANARIES[4].to_owned()),
        };
        let existing = ExistingCredential {
            id: PERSISTENCE_CANARIES[5].to_owned(),
            credential: PERSISTENCE_CANARIES[6].to_owned(),
        };
        let now = chrono::Utc::now();
        let issued = IssuedCredential {
            id: PERSISTENCE_CANARIES[7].to_owned(),
            transaction_id: PERSISTENCE_CANARIES[8].to_owned(),
            organization_id: PERSISTENCE_CANARIES[9].to_owned(),
            credential_template_id: PERSISTENCE_CANARIES[10].to_owned(),
            applicant_id: Some(PERSISTENCE_CANARIES[11].to_owned()),
            subject_did: Some(PERSISTENCE_CANARIES[12].to_owned()),
            issuer_did: PERSISTENCE_CANARIES[13].to_owned(),
            revocation_profile_id: Some(PERSISTENCE_CANARIES[14].to_owned()),
            renewed_from_credential_id: Some(PERSISTENCE_CANARIES[15].to_owned()),
            status_list_entries: vec![json!(PERSISTENCE_CANARIES[16])],
            credential: PERSISTENCE_CANARIES[17].to_owned(),
            credential_hash: PERSISTENCE_CANARIES[18].to_owned(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(1),
        };
        let allocated = AllocatedCredentialStatus {
            revocation_profile_id: Some(PERSISTENCE_CANARIES[19].to_owned()),
            entries: vec![json!(PERSISTENCE_CANARIES[20])],
        };
        let outcome = CredentialIssuanceOutcome {
            response: response.clone(),
            issued_credential: Some(issued.clone()),
            disposition: CredentialIssuanceDisposition::Committed,
        };

        assert_eq!(
            assert_redacted(&proof, PROOF_CANARIES),
            "VerifiedCredentialProof { contents: \"[REDACTED]\" }"
        );
        assert_eq!(
            assert_redacted(&request, REQUEST_CANARIES),
            "CredentialBuildRequest { kind: SdJwt, response_format: \"dc+sd-jwt\", remote_credential_format: \"dc+sd-jwt\", has_achievement_id: true, has_subject_did: true, has_holder_jwk: true, claim_count: 1, has_credential_subject: true, has_credential_document: true, selective_disclosure_claim_count: 1, validity_seconds: 9876543210, issuer_algorithm: \"ES256\", issuer_certificate_chain_len: 2, status_list_entry_count: 1, sensitive_contents: \"[REDACTED]\", .. }"
        );
        assert_eq!(
            assert_redacted(&built, BUILT_CANARIES),
            "BuiltCredential { contents: \"[REDACTED]\" }"
        );
        assert_redacted(&credential_request, TRANSPORT_CANARIES);
        assert_redacted(&response, TRANSPORT_CANARIES);
        assert_redacted(&diagnostic_transaction, TRANSACTION_CANARIES);
        assert_redacted(&authorization, PERSISTENCE_CANARIES);
        assert_redacted(&existing, PERSISTENCE_CANARIES);
        assert_redacted(&issued, PERSISTENCE_CANARIES);
        assert_redacted(&allocated, PERSISTENCE_CANARIES);
        assert_redacted(
            &outcome,
            &[TRANSPORT_CANARIES, PERSISTENCE_CANARIES].concat(),
        );
    }

    #[test]
    fn credential_policy_preserves_stable_identity_and_filters_internal_claims() {
        let transaction = transaction();
        assert_eq!(
            reserved_credential_id(&transaction),
            "urn:uuid:bfdc1781-37a5-5f2d-929d-76487fbe2241"
        );
        assert_eq!(
            clean_claims(&transaction.claims),
            json!({"achievement": "Portable Canvas"})
                .as_object()
                .expect("object")
                .clone()
        );
        assert_eq!(
            credential_configuration_id_for_format("OpenBadgeCredential", "w3c_vcdm_v2_sd_jwt"),
            "OpenBadgeCredential#sd-jwt"
        );
    }

    #[test]
    fn grpc_legacy_format_remains_transport_scoped_and_preserves_response_shape() {
        let request = CredentialRequest {
            legacy_format: Some("dc+sd-jwt".to_owned()),
            ..CredentialRequest::default()
        };
        assert!(validate_selector(&request).is_ok());
        let policy = format_policy(&request, &transaction()).expect("format policy");
        assert_eq!(policy.response_format, "dc+sd-jwt");
        assert_eq!(policy.remote_format, "dc+sd-jwt");

        let http_request = CredentialRequest::default();
        assert!(validate_selector(&http_request).is_err());
    }

    #[test]
    fn tenant_audience_requires_the_exact_normalized_path() {
        let valid = json!({"aud": "https://issuer.example/org/org-a"});
        assert!(validate_audience(valid.as_object().expect("object"), "org-a").is_ok());
        let prefixed = json!({"aud": "https://issuer.example/evil/org/org-a"});
        assert!(validate_audience(prefixed.as_object().expect("object"), "org-a").is_err());
    }

    #[test]
    fn final_request_shape_rejects_removed_members_but_ignores_extensions() {
        let request: CredentialRequest = serde_json::from_value(json!({
            "credential_configuration_id": "OpenBadgeCredential#sd-jwt",
            "proofs": {"jwt": ["header.payload.signature"]},
            "official_conformance_extension": "ignored"
        }))
        .expect("canonical request with an extension");
        assert_eq!(
            request.credential_configuration_id.as_deref(),
            Some("OpenBadgeCredential#sd-jwt")
        );

        let proof_error = serde_json::from_value::<CredentialRequest>(json!({
            "credential_configuration_id": "OpenBadgeCredential#sd-jwt",
            "proof": {"proof_type": "jwt", "jwt": "header.payload.signature"}
        }))
        .unwrap_err();
        assert!(proof_error.to_string().contains("removed 'proof'"));

        let format_error = serde_json::from_value::<CredentialRequest>(json!({
            "format": "vc+sd-jwt"
        }))
        .unwrap_err();
        assert!(format_error.to_string().contains("removed 'format'"));
    }
}
