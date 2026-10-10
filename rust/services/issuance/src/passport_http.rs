//! Tenant-authenticated native physical-document routes. This router is opt-in:
//! production traffic must not reach it until all provider and parity gates pass.

#[cfg(test)]
#[path = "passport_http_reconciliation_tests.rs"]
mod reconciliation_tests;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use marty_crypto::certificate::load_certificate_pem;
use marty_passport_auth::{
    PassportTenantAuthError, PassportTenantCredentialSource, PassportTenantKeyring,
    PassportTenantPrincipal,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tracing::error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::IssuanceServiceConfig,
    passport_artifact_kms::{KmsArtifactError, KmsPassportArtifactCipher},
    passport_beta_material::{material_digests, PassportBetaMaterialDigests},
    passport_bureau::{
        beta_batch_wire_commitment, parse_beta_batch_mapping, BetaBatchWireCommitments,
        BetaBatchWireEvidence, BureauClient, BureauError, DocumentType, KmsWebhookVerifier,
        PersonalizationBatch, PersonalizationJob, ProductionStatus,
    },
    passport_contract::{
        application_nested_field_orders, decode_python_validated_base64, json_field_order,
        python_datetime, PassportApplicationRequest, PassportRequestError, PassportSafeResponse,
        QualityResultRequest,
    },
    passport_repository::{
        fill_missing_bureau_metadata, should_apply_bureau_status, PassportBatchIdentity,
        PassportBetaBatchBinding, PassportBetaBatchDestination, PassportBetaMaterialReceipt,
        PassportJob, PassportJobInsert, PassportJobPatch, PassportJobStatus,
        PassportSubmissionReservation, PassportWebhookRepositoryError, PostgresPassportRepository,
    },
    passport_signer::{
        ManagedProfileSigner, PassportSigner, RemoteSigner, SignedMaterial, SignerError,
    },
};

#[derive(Clone)]
pub struct PassportHttpService {
    keyring: PassportTenantCredentialSource,
    internal_service_token: Option<String>,
    repository: PostgresPassportRepository,
    cipher: ArtifactAvailability,
    signer: Option<PassportSigner>,
    bureau: Option<BureauClient>,
    bureau_provider_profile_id: Option<String>,
    beta_reconciliation_enabled: bool,
    beta_reconciliation_operator_token: Option<String>,
    webhook_kms: Option<KmsWebhookVerifier>,
}

#[derive(Clone)]
enum ArtifactAvailability {
    Missing,
    Ready(ArtifactCryptor),
}

#[derive(Clone)]
struct ArtifactCryptor(KmsPassportArtifactCipher);

#[derive(serde::Deserialize, serde::Serialize)]
struct SubmissionSigningProvenance {
    signing_mode: String,
    artifact_custody: String,
    issuer_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_profile_id: Option<String>,
    dsc_der_sha256: String,
    csca_der_sha256: String,
    validated_at: DateTime<Utc>,
}

impl SubmissionSigningProvenance {
    fn managed_kms(
        job: &PassportJob,
        signed: &SignedMaterial,
        validated_at: DateTime<Utc>,
    ) -> Result<Self, PassportHttpError> {
        let issuer_did = job
            .issuer_did
            .clone()
            .ok_or(PassportHttpError::Signer(SignerError::MissingIssuerDid))?;
        let dsc = load_certificate_pem(&signed.dsc_cert_pem)
            .map_err(|_| PassportHttpError::Signer(SignerError::InvalidManagedMaterial))?;
        let csca = signed
            .csca_cert_pem
            .as_deref()
            .ok_or(PassportHttpError::Signer(
                SignerError::InvalidManagedMaterial,
            ))
            .and_then(|pem| {
                load_certificate_pem(pem)
                    .map_err(|_| PassportHttpError::Signer(SignerError::InvalidManagedMaterial))
            })?;
        Ok(Self {
            signing_mode: "managed-issuer-profile".into(),
            artifact_custody: "kms".into(),
            issuer_did,
            issuer_profile_id: signed.issuer_profile_id.clone(),
            dsc_der_sha256: hex::encode(Sha256::digest(dsc)),
            csca_der_sha256: hex::encode(Sha256::digest(csca)),
            validated_at,
        })
    }

    fn matches(&self, job: &PassportJob, signed: &SignedMaterial) -> bool {
        self.signing_mode == "managed-issuer-profile"
            && self.artifact_custody == "kms"
            && job.issuer_did.as_deref() == Some(self.issuer_did.as_str())
            && self.validated_at >= job.created_at
            && job
                .submission_intent_started_at
                .or_else(|| {
                    (job.submission_batch_id.is_some() && job.bureau_job_id.is_some())
                        .then_some(job.submitted_at)
                        .flatten()
                })
                .is_some_and(|deadline| self.validated_at <= deadline)
            && Self::managed_kms(job, signed, self.validated_at).is_ok_and(|actual| {
                actual.dsc_der_sha256 == self.dsc_der_sha256
                    && actual.csca_der_sha256 == self.csca_der_sha256
                    && actual.issuer_profile_id == self.issuer_profile_id
            })
    }
}

impl ArtifactCryptor {
    async fn encrypt(
        &self,
        organization_id: &str,
        artifact_id: &str,
        artifact: &crate::passport_artifact::PassportSensitiveArtifact,
    ) -> Result<String, PassportHttpError> {
        self.0
            .encrypt(organization_id, artifact_id, artifact)
            .await
            .map_err(kms_artifact_error)
    }

    async fn decrypt(
        &self,
        job: &PassportJob,
    ) -> Result<crate::passport_artifact::PassportSensitiveArtifact, PassportHttpError> {
        self.0
            .decrypt(
                &job.organization_id,
                &job.id,
                &job.secure_artifact_ciphertext,
            )
            .await
            .map_err(kms_artifact_error)
    }

    async fn encrypted_scrubbed_artifact(
        &self,
        job: &PassportJob,
    ) -> Result<String, PassportHttpError> {
        self.0
            .encrypted_scrubbed_artifact(&job.organization_id, &job.id)
            .await
            .map_err(kms_artifact_error)
    }
}

fn kms_artifact_error(error: KmsArtifactError) -> PassportHttpError {
    match error {
        KmsArtifactError::InvalidArtifact => PassportHttpError::InvalidArtifact,
        KmsArtifactError::InvalidConfig | KmsArtifactError::Unavailable => {
            PassportHttpError::ArtifactKmsUnavailable
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PassportStartupError {
    #[error("{0} is required for native passport HTTP")]
    Missing(&'static str),
    #[error("beta reconciliation operator token must differ from the shared service token")]
    SharedOperatorToken,
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error(transparent)]
    Bureau(#[from] BureauError),
    #[error(transparent)]
    Artifact(#[from] KmsArtifactError),
}

impl PassportHttpService {
    fn beta_batch_ready(&self) -> bool {
        self.beta_reconciliation_enabled
            && self.bureau_provider_profile_id.as_deref() == Some("passport-beta-bureau")
            && self.bureau.is_some()
            && matches!(
                (&self.signer, &self.cipher),
                (
                    Some(PassportSigner::Managed(_)),
                    ArtifactAvailability::Ready(_)
                )
            )
    }

    pub fn from_config(
        config: &IssuanceServiceConfig,
        pool: sqlx::PgPool,
    ) -> Result<Option<Self>, PassportStartupError> {
        let native = &config.passport_native;
        if !native.enabled {
            return Ok(None);
        }
        if native.beta_reconciliation_enabled
            && native.beta_reconciliation_operator_token.as_deref()
                == config.internal_service_token.as_deref()
        {
            return Err(PassportStartupError::SharedOperatorToken);
        }
        let keyring = if native.internal_service_auth_enabled {
            PassportTenantCredentialSource::internal_service_token(
                config
                    .internal_service_token
                    .as_deref()
                    .ok_or(PassportStartupError::Missing("GRPC_SERVICE_TOKEN"))?,
            )
            .map_err(|_| PassportStartupError::Missing("GRPC_SERVICE_TOKEN"))?
        } else {
            config
                .passport_tenant_keys
                .clone()
                .ok_or(PassportStartupError::Missing("PASSPORT_TENANT_API_KEYS"))?
                .into()
        };
        let cipher = if native.kms_artifacts_enabled {
            let api_key = config.signing_keys_internal_api_key.as_deref().ok_or(
                PassportStartupError::Missing("SIGNING_KEYS_INTERNAL_API_KEY"),
            )?;
            ArtifactAvailability::Ready(ArtifactCryptor(KmsPassportArtifactCipher::new(
                config.signing_keys_internal_url.clone(),
                api_key,
            )?))
        } else {
            ArtifactAvailability::Missing
        };
        let signer = if native.managed_issuer_signing_enabled {
            Some(PassportSigner::Managed(Box::new(
                ManagedProfileSigner::new(
                    config.signing_keys_internal_url.clone(),
                    config.signing_keys_internal_api_key.as_deref(),
                    config.issuer_sign_key.as_deref(),
                )?,
            )))
        } else if let Some(url) = native.signer_url.as_deref() {
            Some(PassportSigner::Remote(RemoteSigner::new(
                url,
                native.signer_api_key.as_deref().unwrap_or_default(),
            )?))
        } else {
            None
        };
        let bureau = native
            .bureau_url
            .as_deref()
            .map(|url| BureauClient::new(url, native.bureau_api_key.as_deref().unwrap_or_default()))
            .transpose()?;
        let mut service = Self::with_artifact_availability(
            keyring,
            PostgresPassportRepository::new(pool),
            cipher,
            signer,
            bureau,
        );
        service.internal_service_token = config.internal_service_token.clone();
        service.bureau_provider_profile_id = native.bureau_provider_profile_id.clone();
        service.beta_reconciliation_enabled = native.beta_reconciliation_enabled;
        service.beta_reconciliation_operator_token =
            native.beta_reconciliation_operator_token.clone();
        // Inbound callbacks from already-submitted jobs remain verifiable even
        // when outbound bureau submission is not configured.
        if native.kms_callbacks_enabled {
            let api_key = config.signing_keys_internal_api_key.as_deref().ok_or(
                PassportStartupError::Missing("SIGNING_KEYS_INTERNAL_API_KEY"),
            )?;
            service.webhook_kms = Some(KmsWebhookVerifier::new(
                config.signing_keys_internal_url.clone(),
                api_key,
            )?);
        }
        Ok(Some(service))
    }

    #[must_use]
    pub fn new(
        keyring: PassportTenantKeyring,
        repository: PostgresPassportRepository,
        cipher: Option<KmsPassportArtifactCipher>,
        signer: Option<PassportSigner>,
        bureau: Option<BureauClient>,
    ) -> Self {
        Self::with_artifact_availability(
            keyring.into(),
            repository,
            cipher.map_or(ArtifactAvailability::Missing, |cipher| {
                ArtifactAvailability::Ready(ArtifactCryptor(cipher))
            }),
            signer,
            bureau,
        )
    }

    #[must_use]
    pub fn with_webhook_verifier(mut self, verifier: KmsWebhookVerifier) -> Self {
        self.webhook_kms = Some(verifier);
        self
    }

    fn with_artifact_availability(
        keyring: PassportTenantCredentialSource,
        repository: PostgresPassportRepository,
        cipher: ArtifactAvailability,
        signer: Option<PassportSigner>,
        bureau: Option<BureauClient>,
    ) -> Self {
        Self {
            keyring,
            internal_service_token: None,
            repository,
            cipher,
            signer,
            bureau,
            bureau_provider_profile_id: None,
            beta_reconciliation_enabled: false,
            beta_reconciliation_operator_token: None,
            webhook_kms: None,
        }
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<PassportTenantPrincipal, PassportHttpError> {
        self.keyring
            .authenticate(
                header(headers, "x-organization-id"),
                header(headers, "x-api-key"),
            )
            .map_err(PassportHttpError::Auth)
    }

    fn authenticate_internal_flow(
        &self,
        headers: &HeaderMap,
    ) -> Result<PassportTenantPrincipal, PassportHttpError> {
        let principal = self.authenticate(headers)?;
        let expected = self
            .internal_service_token
            .as_deref()
            .ok_or(PassportHttpError::OperatorUnauthorized)?;
        let supplied =
            header(headers, "x-service-token").ok_or(PassportHttpError::OperatorUnauthorized)?;
        if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
            return Err(PassportHttpError::OperatorUnauthorized);
        }
        Ok(principal)
    }

    fn authenticate_beta_reconciliation_operator(
        &self,
        headers: &HeaderMap,
    ) -> Result<PassportTenantPrincipal, PassportHttpError> {
        let principal = self.authenticate(headers)?;
        let expected = self
            .beta_reconciliation_operator_token
            .as_deref()
            .ok_or(PassportHttpError::OperatorUnauthorized)?;
        let supplied = header(headers, "x-passport-reconciliation-token")
            .ok_or(PassportHttpError::OperatorUnauthorized)?;
        if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
            return Err(PassportHttpError::OperatorUnauthorized);
        }
        Ok(principal)
    }

    fn cipher(&self) -> Result<&ArtifactCryptor, PassportHttpError> {
        match &self.cipher {
            ArtifactAvailability::Ready(cipher) => Ok(cipher),
            ArtifactAvailability::Missing => Err(PassportHttpError::ArtifactKmsUnavailable),
        }
    }

    fn signer(&self) -> Result<&PassportSigner, PassportHttpError> {
        self.signer
            .as_ref()
            .ok_or(PassportHttpError::Signer(SignerError::NotConfigured))
    }

    fn bureau(&self) -> Result<&BureauClient, PassportHttpError> {
        self.bureau.as_ref().ok_or(PassportHttpError::MissingBureau)
    }

    async fn job(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
    ) -> Result<PassportJob, PassportHttpError> {
        self.repository
            .get(principal, application_id)
            .await
            .map_err(PassportHttpError::Storage)?
            .ok_or(PassportHttpError::ApplicationNotFound)
    }

    async fn update(
        &self,
        principal: &PassportTenantPrincipal,
        job: &PassportJob,
        patch: &PassportJobPatch,
    ) -> Result<PassportJob, PassportHttpError> {
        self.repository
            .update(
                principal,
                &job.application_id,
                &job.status,
                patch,
                Utc::now(),
            )
            .await
            .map_err(PassportHttpError::Storage)?
            .ok_or(PassportHttpError::ConcurrentChange)
    }

    async fn decrypt(
        &self,
        job: &PassportJob,
    ) -> Result<crate::passport_artifact::PassportSensitiveArtifact, PassportHttpError> {
        self.cipher()?.decrypt(job).await
    }

    async fn sign(
        &self,
        job: &PassportJob,
    ) -> Result<
        (
            crate::passport_artifact::PassportSensitiveArtifact,
            SignedMaterial,
            bool,
        ),
        PassportHttpError,
    > {
        let artifact = self.decrypt(job).await?;
        let data_groups = artifact
            .numbered_data_groups()
            .map_err(|_| PassportHttpError::InvalidArtifact)?;
        let signed = self
            .signer()?
            .sign_for_identity(
                &job.country_code,
                &job.organization_id,
                job.issuer_did.as_deref(),
                &data_groups,
            )
            .await
            .map_err(PassportHttpError::Signer)?;
        let sod_verified = signed.verify_data_groups(&data_groups).is_ok();
        if matches!(self.signer.as_ref(), Some(PassportSigner::Managed(_))) && !sod_verified {
            return Err(PassportHttpError::Signer(
                SignerError::InvalidManagedMaterial,
            ));
        }
        Ok((artifact, signed, sod_verified))
    }

    async fn validate_cached_signed_material(
        &self,
        job: &PassportJob,
        artifact: &crate::passport_artifact::PassportSensitiveArtifact,
        signed: &SignedMaterial,
    ) -> Result<bool, PassportHttpError> {
        let groups = artifact
            .numbered_data_groups()
            .map_err(|_| PassportHttpError::InvalidArtifact)?;
        if let Some(PassportSigner::Managed(managed)) = self.signer.as_ref() {
            managed
                .validate_existing(
                    &job.country_code,
                    &job.organization_id,
                    job.issuer_did
                        .as_deref()
                        .ok_or(PassportHttpError::Signer(SignerError::MissingIssuerDid))?,
                    &groups,
                    signed,
                )
                .await
                .map_err(PassportHttpError::Signer)?;
            Ok(true)
        } else {
            Ok(signed.verify_data_groups(&groups).is_ok())
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn python_model_body(body: &[u8], headers: &HeaderMap) -> Result<Value, PassportHttpError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    let media_type = header(headers, "content-type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let is_json = media_type == "application/json"
        || media_type
            .split_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+json"));
    if !is_json {
        return Ok(Value::String(String::from_utf8_lossy(body).into_owned()));
    }
    serde_json::from_slice(body).map_err(|error| {
        PassportHttpError::Validation(json!({"detail": [
            crate::python_json_diagnostic::diagnostic(body, &error)
        ]}))
    })
}

#[derive(Debug, thiserror::Error)]
enum PassportHttpError {
    #[error("{0}")]
    Auth(PassportTenantAuthError),
    #[error("Passport beta reconciliation operator credential is invalid")]
    OperatorUnauthorized,
    #[error("Organization context does not match requested organization")]
    OrganizationMismatch,
    #[error("{0}")]
    InvalidRequest(PassportRequestError),
    #[error("Physical document application not found")]
    ApplicationNotFound,
    #[error("Physical document job not found")]
    WebhookJobNotFound,
    #[error("Secure physical document artifact cannot be decrypted")]
    InvalidArtifact,
    #[error("KMS passport artifact provider is unavailable")]
    ArtifactKmsUnavailable,
    #[error("{0}")]
    Signer(SignerError),
    #[error("Personalization bureau not configured. Set PERSONALIZATION_BUREAU_URL environment variable.")]
    MissingBureau,
    #[error("Personalization bureau provider is unavailable for this job")]
    ProviderUnavailable,
    #[error("{0}")]
    Bureau(BureauError),
    #[error("Document is not ready for quality verification")]
    QualityNotReady,
    #[error("A passing quality result is required before activation")]
    ActivationNotReady,
    #[error("DG1 and DG2 are required for physical document issuance")]
    MissingDataGroups,
    #[error("Invalid stored document type")]
    InvalidDocumentType,
    #[error("X-Personalization-Signature header is missing")]
    MissingWebhookSignature,
    #[error("Physical document request validation failed")]
    Validation(Value),
    #[error("Physical document changed concurrently; retry the operation")]
    ConcurrentChange,
    #[error("Physical document has already been submitted to the bureau")]
    AlreadySubmitted,
    #[error("Previously signed SOD material is unavailable; regenerate SOD before submission")]
    SignedMaterialUnavailable,
    #[error("Physical document repository failed")]
    Storage(sqlx::Error),
    #[error("Physical document webhook repository failed")]
    WebhookStorage(PassportWebhookRepositoryError),
}

impl IntoResponse for PassportHttpError {
    fn into_response(self) -> Response {
        if matches!(&self, Self::MissingWebhookSignature) {
            return crate::management_http::missing_header("x-personalization-signature");
        }
        if let Self::Validation(body) = &self {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(body.clone())).into_response();
        }
        let status = match &self {
            Self::Auth(
                PassportTenantAuthError::MissingOrganization
                | PassportTenantAuthError::MissingKey
                | PassportTenantAuthError::InvalidKey,
            )
            | Self::OperatorUnauthorized => StatusCode::UNAUTHORIZED,
            Self::OrganizationMismatch => StatusCode::FORBIDDEN,
            Self::InvalidRequest(_)
            | Self::MissingDataGroups
            | Self::Signer(SignerError::MissingIssuerDid) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ApplicationNotFound | Self::WebhookJobNotFound => StatusCode::NOT_FOUND,
            Self::ArtifactKmsUnavailable
            | Self::Signer(SignerError::NotConfigured)
            | Self::Signer(SignerError::ManagedUnavailable)
            | Self::MissingBureau
            | Self::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Signer(SignerError::InvalidManagedMaterial) => StatusCode::BAD_GATEWAY,
            Self::Signer(SignerError::UntrustedDsc)
            | Self::QualityNotReady
            | Self::ActivationNotReady
            | Self::ConcurrentChange
            | Self::AlreadySubmitted
            | Self::SignedMaterialUnavailable => StatusCode::CONFLICT,
            Self::Bureau(BureauError::InvalidWebhookSignature) => StatusCode::UNAUTHORIZED,
            Self::Bureau(BureauError::InvalidWebhookEvent) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Bureau(
                BureauError::CallbackKmsConfiguration | BureauError::CallbackKmsUnavailable,
            ) => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidArtifact
            | Self::InvalidDocumentType
            | Self::Signer(_)
            | Self::Bureau(_)
            | Self::Storage(_)
            | Self::WebhookStorage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MissingWebhookSignature => unreachable!("handled before status selection"),
            Self::Validation(_) => unreachable!("handled before status selection"),
        };
        match &self {
            Self::Storage(error) => error!(%error, "physical document repository failed"),
            Self::WebhookStorage(error) => {
                error!(%error, "physical document webhook repository failed")
            }
            Self::Signer(error) if status == StatusCode::INTERNAL_SERVER_ERROR => {
                error!(%error, "physical document signer failed")
            }
            Self::Bureau(error) if status == StatusCode::INTERNAL_SERVER_ERROR => {
                error!(%error, "physical document bureau failed")
            }
            _ => {}
        }
        let detail = match &self {
            Self::Storage(_) | Self::WebhookStorage(_) | Self::InvalidDocumentType => {
                "Internal Server Error".to_owned()
            }
            Self::Signer(error) if status == StatusCode::INTERNAL_SERVER_ERROR => match error {
                SignerError::IncompleteMaterial => error.to_string(),
                _ => "ICAO document signer failed".to_owned(),
            },
            Self::Bureau(error) if status == StatusCode::INTERNAL_SERVER_ERROR => match error {
                BureauError::InvalidResponse(_) => {
                    "Personalization bureau returned invalid response".to_owned()
                }
                _ => "Personalization bureau failed".to_owned(),
            },
            _ => self.to_string(),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

fn safe(job: &PassportJob) -> Value {
    // Serialization of this closed projection cannot include sensitive fields.
    serde_json::to_value(PassportSafeResponse::from(job)).expect("safe response serializes")
}

pub fn router(service: PassportHttpService) -> Router {
    Router::new()
        .route("/v1/passport/capabilities", get(capabilities))
        .route("/v1/passport/applications", post(create_application))
        .route(
            "/v1/passport/applications/{application_id}/generate-data-groups",
            post(generate_data_groups),
        )
        .route(
            "/v1/passport/applications/{application_id}/generate-sod",
            post(generate_sod),
        )
        .route(
            "/internal/passport/applications/{application_id}/generate-sod",
            post(generate_sod_for_flow),
        )
        .route(
            "/v1/passport/applications/{application_id}/submit-personalization",
            post(submit_personalization),
        )
        .route(
            "/internal/passport/applications/{application_id}/reconcile-submission",
            post(reconcile_beta_submission),
        )
        .route(
            "/internal/passport/beta-batches/{batch_id}/submit",
            post(submit_beta_batch),
        )
        .route(
            "/internal/passport/beta-batches/preflight",
            get(beta_batch_preflight),
        )
        .route(
            "/v1/passport/applications/{application_id}/production-status",
            get(production_status),
        )
        .route(
            "/v1/passport/applications/{application_id}/quality-verify",
            post(quality_verify),
        )
        .route(
            "/v1/passport/applications/{application_id}/activate",
            post(activate),
        )
        .route(
            "/v1/passport/webhooks/personalization",
            post(personalization_webhook),
        )
        .with_state(service)
}

async fn capabilities(State(service): State<PassportHttpService>) -> Json<Value> {
    let mut blockers = Vec::new();
    if service.signer.is_none() {
        blockers.push("Configure ICAO_DOCUMENT_SIGNER_URL. Self-signed document certificates are permitted only in explicit test mode.");
    }
    let signer_blockers = blockers.clone();
    match &service.cipher {
        ArtifactAvailability::Missing => blockers.push(
            "Configure managed KMS passport artifact custody for encrypted sensitive artifacts.",
        ),
        ArtifactAvailability::Ready(_) => {}
    }
    if service.bureau.is_none() {
        blockers.push("Configure PERSONALIZATION_BUREAU_URL for production handoff.");
    }
    Json(json!({
        "supported": blockers.is_empty(),
        "signer": {"configured": service.signer.is_some(), "mode": service.signer.as_ref().map_or("UNAVAILABLE", PassportSigner::mode), "blockers": signer_blockers},
        "bureau_configured": service.bureau.is_some(),
        "encrypted_artifact_store": matches!(&service.cipher, ArtifactAvailability::Ready(_)),
        "blockers": blockers,
    }))
}

async fn create_application(
    State(service): State<PassportHttpService>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), PassportHttpError> {
    let payload = python_model_body(&body, &headers)?;
    let order = json_field_order(&body);
    let (mrz_order, data_group_order) = application_nested_field_orders(&body);
    let request = PassportApplicationRequest::from_python_value(
        &payload,
        Some(&order),
        Some(&mrz_order),
        Some(&data_group_order),
    )
    .map_err(PassportHttpError::Validation)?;
    let principal = service.authenticate(&headers)?;
    if principal.organization_id() != request.organization_id {
        return Err(PassportHttpError::OrganizationMismatch);
    }
    request
        .validate()
        .map_err(PassportHttpError::InvalidRequest)?;
    if matches!(service.signer.as_ref(), Some(PassportSigner::Managed(_)))
        && request
            .issuer_did
            .as_deref()
            .is_none_or(|did| !did.starts_with("did:"))
    {
        return Err(PassportHttpError::Signer(SignerError::MissingIssuerDid));
    }
    let id = Uuid::new_v4().to_string();
    let ciphertext = service
        .cipher()?
        .encrypt(&request.organization_id, &id, &request.sensitive_artifact())
        .await?;
    let inserted = service
        .repository
        .insert(
            &principal,
            &PassportJobInsert {
                id: id.clone(),
                application_id: Uuid::new_v4().to_string(),
                flow_execution_id: request.flow_execution_id,
                application_template_id: request.application_template_id,
                credential_template_id: request.credential_template_id,
                revocation_profile_id: None,
                delivery_destination_profile_id: request.delivery_destination_profile_id,
                document_type: serde_json::to_value(request.document_type)
                    .expect("document type serializes")
                    .as_str()
                    .expect("document type string")
                    .to_owned(),
                country_code: request.country_code,
                issuer_did: request.issuer_did,
                secure_artifact_ciphertext: ciphertext,
                secure_artifact_reference: format!("physical-artifact://{id}"),
            },
            Utc::now(),
        )
        .await
        .map_err(PassportHttpError::Storage)?;
    Ok((StatusCode::CREATED, Json(safe(&inserted))))
}

async fn generate_data_groups(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    if job.bureau_job_id.is_some() || job.submission_intent_id.is_some() {
        return Err(PassportHttpError::AlreadySubmitted);
    }
    let groups = service
        .decrypt(&job)
        .await?
        .numbered_data_groups()
        .map_err(|_| PassportHttpError::InvalidArtifact)?;
    if !groups.contains_key(&num_bigint::BigUint::from(1u8))
        || !groups.contains_key(&num_bigint::BigUint::from(2u8))
    {
        return Err(PassportHttpError::MissingDataGroups);
    }
    let updated = service
        .update(
            &principal,
            &job,
            &PassportJobPatch::new(PassportJobStatus::DataGenerated),
        )
        .await?;
    Ok(Json(safe(&updated)))
}

async fn generate_sod(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    generate_sod_authenticated(service, application_id, principal, false).await
}

async fn generate_sod_for_flow(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate_internal_flow(&headers)?;
    generate_sod_authenticated(service, application_id, principal, true).await
}

async fn generate_sod_authenticated(
    service: PassportHttpService,
    application_id: String,
    principal: PassportTenantPrincipal,
    include_profile_id: bool,
) -> Result<Json<Value>, PassportHttpError> {
    let job = service.job(&principal, &application_id).await?;
    if job.bureau_job_id.is_some() || job.submission_intent_id.is_some() {
        return Err(PassportHttpError::AlreadySubmitted);
    }
    if job.status == PassportJobStatus::SodSigned.as_str() {
        let artifact = service.decrypt(&job).await?;
        if let Some(signed) = artifact.signed_material.as_ref() {
            let hash = signed_sod_sha256(signed)?;
            if job.sod_sha256.as_deref() == Some(hash.as_str()) {
                if let Ok(verified) = service
                    .validate_cached_signed_material(&job, &artifact, signed)
                    .await
                {
                    let mut response = safe(&job);
                    response["sod_sha256"] = Value::String(hash);
                    response["sod_signature_verified"] = Value::Bool(verified);
                    if include_profile_id {
                        if let Some(profile_id) = &signed.issuer_profile_id {
                            response["issuer_profile_id"] = Value::String(profile_id.clone());
                        }
                    }
                    return Ok(Json(response));
                }
            }
        }
    }
    let (mut artifact, signed, sod_verified) = service.sign(&job).await?;
    let hash = signed_sod_sha256(&signed)?;
    let issuer_profile_id = signed.issuer_profile_id.clone();
    artifact.signed_material = Some(signed);
    let mut patch = PassportJobPatch::new(PassportJobStatus::SodSigned);
    patch.expected_sod_sha256 = Some(job.sod_sha256.clone());
    patch.expected_secure_artifact_ciphertext = Some(job.secure_artifact_ciphertext.clone());
    patch.sod_sha256 = Some(Some(hash.clone()));
    patch.secure_artifact_ciphertext = Some(
        service
            .cipher()?
            .encrypt(&job.organization_id, &job.id, &artifact)
            .await?,
    );
    let updated = service.update(&principal, &job, &patch).await?;
    let mut response = safe(&updated);
    response["sod_sha256"] = Value::String(hash);
    response["sod_signature_verified"] = Value::Bool(sod_verified);
    if include_profile_id {
        if let Some(profile_id) = issuer_profile_id {
            response["issuer_profile_id"] = Value::String(profile_id);
        }
    }
    Ok(Json(response))
}

async fn prepared_personalization_job(
    service: &PassportHttpService,
    job: &PassportJob,
    require_cached: bool,
    historical_provenance: Option<&SubmissionSigningProvenance>,
) -> Result<(PersonalizationJob, String, Option<String>, SignedMaterial), PassportHttpError> {
    let mut artifact = service.decrypt(job).await?;
    let mut newly_signed = false;
    let signed = if let Some(signed) = artifact.signed_material.clone() {
        if job.sod_sha256.as_deref() != Some(signed_sod_sha256(&signed)?.as_str()) {
            return Err(PassportHttpError::SignedMaterialUnavailable);
        }
        if let Some(provenance) = historical_provenance {
            if !provenance.matches(job, &signed) {
                return Err(PassportHttpError::SignedMaterialUnavailable);
            }
            signed
                .verify_data_groups(
                    &artifact
                        .numbered_data_groups()
                        .map_err(|_| PassportHttpError::InvalidArtifact)?,
                )
                .map_err(PassportHttpError::Signer)?;
        } else {
            service
                .validate_cached_signed_material(job, &artifact, &signed)
                .await?;
        }
        signed
    } else {
        if require_cached || job.sod_sha256.is_some() {
            return Err(PassportHttpError::SignedMaterialUnavailable);
        }
        newly_signed = true;
        service.sign(job).await?.1
    };
    let submitted_sod_sha256 = signed_sod_sha256(&signed)?;
    let signed_artifact_ciphertext = if newly_signed {
        artifact.signed_material = Some(signed.clone());
        Some(
            service
                .cipher()?
                .encrypt(&job.organization_id, &job.id, &artifact)
                .await?,
        )
    } else {
        None
    };
    let document_type: DocumentType =
        serde_json::from_value(Value::String(job.document_type.clone()))
            .map_err(|_| PassportHttpError::InvalidDocumentType)?;
    Ok((
        PersonalizationJob {
            id: job.id.clone(),
            application_id: job.application_id.clone(),
            organization_id: job.organization_id.clone(),
            country_code: job.country_code.clone(),
            document_type,
            data_groups: artifact
                .numbered_data_groups()
                .map_err(|_| PassportHttpError::InvalidArtifact)?,
            sod_der_base64: signed.sod_der_base64.clone(),
            dsc_cert_pem: signed.dsc_cert_pem.clone(),
            mrz_line_1: artifact.mrz.get("line_1").cloned().unwrap_or_default(),
            mrz_line_2: artifact.mrz.get("line_2").cloned().unwrap_or_default(),
            bureau_job_id: None,
            status: ProductionStatus::Queued,
            tracking_number: None,
            error_message: None,
            submitted_at: Utc::now(),
            updated_at: Utc::now(),
            completed_at: None,
        },
        submitted_sod_sha256,
        signed_artifact_ciphertext,
        signed,
    ))
}

async fn submit_personalization(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    if job.bureau_job_id.is_some() {
        return Ok(Json(safe(&job)));
    }
    if job.submission_batch_id.is_some() {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if job.submission_intent_id.is_some() {
        return wait_for_submission(&service, &principal, &application_id).await;
    }
    let (prepared, submitted_sod_sha256, signed_artifact_ciphertext, signed) =
        prepared_personalization_job(&service, &job, false, None).await?;
    let bureau = service.bureau()?;
    let intent_id = Uuid::new_v4();
    let endpoint_sha256 = bureau.endpoint_sha256();
    let reserved_at = database_precision_now();
    let signing_provenance = if matches!(
        (&service.signer, &service.cipher),
        (
            Some(PassportSigner::Managed(_)),
            ArtifactAvailability::Ready(_)
        )
    ) {
        Some(
            serde_json::to_value(SubmissionSigningProvenance::managed_kms(
                &job,
                &signed,
                reserved_at,
            )?)
            .map_err(|_| PassportHttpError::InvalidArtifact)?,
        )
    } else {
        None
    };
    let reserved = service
        .repository
        .reserve_submission(
            &principal,
            &job,
            &PassportSubmissionReservation {
                intent_id,
                sod_sha256: &submitted_sod_sha256,
                signed_artifact_ciphertext: signed_artifact_ciphertext.as_deref(),
                provider_profile_id: service.bureau_provider_profile_id.as_deref(),
                bureau_endpoint_sha256: &endpoint_sha256,
                signing_provenance: signing_provenance.as_ref(),
                now: reserved_at,
            },
        )
        .await
        .map_err(PassportHttpError::Storage)?;
    let Some(reserved) = reserved else {
        return wait_for_submission(&service, &principal, &application_id).await;
    };
    if reserved.submission_intent_provider_profile_id != service.bureau_provider_profile_id
        || reserved.submission_intent_bureau_endpoint_sha256.as_deref()
            != Some(endpoint_sha256.as_str())
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let outcome = bureau
        .submit(&prepared)
        .await
        .map_err(PassportHttpError::Bureau)?;
    let mut patch = PassportJobPatch::new(status_from_bureau(outcome.status));
    patch.expected_sod_sha256 = Some(reserved.sod_sha256.clone());
    patch.expected_secure_artifact_ciphertext = Some(reserved.secure_artifact_ciphertext.clone());
    patch.expected_submission_intent_id = Some(intent_id);
    patch.clear_submission_intent = true;
    // Generic bureau endpoints do not prove that any HTTP error happened
    // before the provider accepted the source job. Keep the reservation and
    // exact signed bytes for private reconciliation on every no-ID outcome.
    if outcome.bureau_job_id.is_none() {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let beta_receipt = if service.beta_reconciliation_enabled {
        let digests = material_digests(
            &prepared.payload(),
            &job.organization_id,
            &job.id,
            &job.country_code,
            Some(&job.document_type),
        )
        .map_err(|_| PassportHttpError::InvalidArtifact)?;
        let receipt = service
            .repository
            .beta_material_receipt(&principal, &job.id)
            .await
            .map_err(PassportHttpError::Storage)?
            .ok_or(PassportHttpError::ConcurrentChange)?;
        if outcome.bureau_job_id.as_deref() != Some(receipt.bureau_job_id.to_string().as_str())
            || !beta_receipt_matches(&receipt, &digests, &job.document_type)
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
        Some(receipt)
    } else {
        None
    };
    patch.bureau_job_id = Some(outcome.bureau_job_id.clone());
    patch.bureau_provider_profile_id = outcome
        .bureau_job_id
        .as_ref()
        .and(service.bureau_provider_profile_id.clone());
    patch.tracking_number = Some(outcome.tracking_number);
    patch.error_code = Some(
        (outcome.status == ProductionStatus::Failed).then(|| "BUREAU_SUBMISSION_FAILED".to_owned()),
    );
    patch.error_message = Some(outcome.error_message);
    patch.submitted_at =
        Some(beta_receipt.map_or_else(Utc::now, |receipt| receipt.first_accepted_at));
    let updated = match service.update(&principal, &reserved, &patch).await {
        Ok(updated) => updated,
        Err(PassportHttpError::ConcurrentChange) => {
            let current = service.job(&principal, &application_id).await?;
            if outcome.bureau_job_id.is_none()
                || current.bureau_job_id.as_deref() != outcome.bureau_job_id.as_deref()
                || current.bureau_provider_profile_id != patch.bureau_provider_profile_id
                || current.sod_sha256.as_deref() != Some(submitted_sod_sha256.as_str())
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
            current
        }
        Err(error) => return Err(error),
    };
    let mut response = safe(&updated);
    if let Some(hash) = &updated.sod_sha256 {
        response["sod_sha256"] = Value::String(hash.clone());
    }
    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BetaBatchSubmitRequest {
    selected_flow_instance_id: String,
    selected_application_id: String,
    companion_application_id: String,
}

async fn submit_beta_batch(
    State(service): State<PassportHttpService>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BetaBatchSubmitRequest>,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate_beta_reconciliation_operator(&headers)?;
    if !service.beta_batch_ready() {
        return Err(PassportHttpError::ProviderUnavailable);
    }
    let wire_key = header(&headers, "x-passport-batch-wire-key")
        .ok_or(PassportHttpError::ConcurrentChange)
        .and_then(|encoded| {
            let decoded = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .map_err(|_| PassportHttpError::ConcurrentChange)?,
            );
            if decoded.len() != 32 {
                return Err(PassportHttpError::ConcurrentChange);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&decoded);
            Ok(key)
        })?;
    let wire_key_sha256 = hex::encode(Sha256::digest(wire_key.as_slice()));
    let batch_id = Uuid::parse_str(&batch_id)
        .ok()
        .filter(|parsed| parsed.to_string() == batch_id)
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if request.selected_flow_instance_id.trim().is_empty()
        || request.selected_application_id.trim().is_empty()
        || request.companion_application_id.trim().is_empty()
        || request.selected_application_id == request.companion_application_id
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let bureau = service.bureau()?;
    let endpoint_sha256 = bureau.endpoint_sha256();
    let existing = service
        .repository
        .beta_batch_jobs(&principal, batch_id)
        .await
        .map_err(PassportHttpError::Storage)?;
    let had_existing = existing.is_some();
    let jobs = if let Some(jobs) = existing {
        jobs
    } else {
        [
            service
                .job(&principal, &request.selected_application_id)
                .await?,
            service
                .job(&principal, &request.companion_application_id)
                .await?,
        ]
    };
    if jobs[0].id == jobs[1].id
        || jobs[0].application_id != request.selected_application_id
        || jobs[1].application_id != request.companion_application_id
        || jobs[0].flow_execution_id != request.selected_flow_instance_id
        || jobs
            .iter()
            .any(|job| job.organization_id != principal.organization_id())
        || !had_existing
            && jobs.iter().any(|job| {
                job.status != PassportJobStatus::SodSigned.as_str()
                    || job.bureau_job_id.is_some()
                    || job.submission_intent_id.is_some()
                    || job.submission_batch_id.is_some()
            })
        || had_existing
            && jobs.iter().any(|job| {
                job.submission_batch_id != Some(batch_id)
                    || job.submission_batch_selected_flow_instance_id.as_deref()
                        != Some(request.selected_flow_instance_id.as_str())
                    || if job.bureau_job_id.is_some() {
                        job.bureau_provider_profile_id.as_deref() != Some("passport-beta-bureau")
                            || job.submission_intent_id.is_some()
                            || job.submission_intent_provider_profile_id.is_some()
                            || job.submission_intent_bureau_endpoint_sha256.is_some()
                            || job.submission_batch_bureau_endpoint_sha256.as_deref()
                                != Some(endpoint_sha256.as_str())
                    } else {
                        job.bureau_provider_profile_id.is_some()
                            || job.submission_intent_id.is_none()
                            || job.submission_intent_provider_profile_id.as_deref()
                                != Some("passport-beta-bureau")
                            || job.submission_intent_bureau_endpoint_sha256.as_deref()
                                != Some(endpoint_sha256.as_str())
                    }
            })
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if had_existing && jobs.iter().all(|job| job.bureau_job_id.is_some()) {
        let mut selected_profile_id: Option<String> = None;
        for job in &jobs {
            let profile_id = verified_bound_batch_job(&service, &principal, job).await?;
            if selected_profile_id
                .as_deref()
                .is_some_and(|selected| selected != profile_id)
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
            selected_profile_id = Some(profile_id);
        }
        return beta_batch_safe_wire_response(&service, &principal, batch_id, &jobs, &wire_key)
            .await;
    }
    if had_existing
        && jobs
            .iter()
            .filter(|job| job.bureau_job_id.is_some())
            .count()
            == 1
    {
        return recover_partial_beta_batch(
            &service, &principal, batch_id, &request, &jobs, bureau, &wire_key,
        )
        .await;
    }
    let historical = if had_existing {
        Some([
            serde_json::from_value::<SubmissionSigningProvenance>(
                jobs[0]
                    .submission_intent_signing_provenance
                    .as_ref()
                    .or(jobs[0].submission_batch_signing_provenance.as_ref())
                    .cloned()
                    .ok_or(PassportHttpError::ConcurrentChange)?,
            )
            .map_err(|_| PassportHttpError::ConcurrentChange)?,
            serde_json::from_value::<SubmissionSigningProvenance>(
                jobs[1]
                    .submission_intent_signing_provenance
                    .as_ref()
                    .or(jobs[1].submission_batch_signing_provenance.as_ref())
                    .cloned()
                    .ok_or(PassportHttpError::ConcurrentChange)?,
            )
            .map_err(|_| PassportHttpError::ConcurrentChange)?,
        ])
    } else {
        None
    };
    let prepared_selected = prepared_personalization_job(
        &service,
        &jobs[0],
        true,
        historical.as_ref().map(|values| &values[0]),
    )
    .await?;
    let prepared_companion = prepared_personalization_job(
        &service,
        &jobs[1],
        true,
        historical.as_ref().map(|values| &values[1]),
    )
    .await?;
    let prepared = [prepared_selected.0, prepared_companion.0];
    let sod_hashes = [prepared_selected.1, prepared_companion.1];
    let signed = [prepared_selected.3, prepared_companion.3];
    if prepared_selected.2.is_some()
        || prepared_companion.2.is_some()
        || jobs
            .iter()
            .zip(&sod_hashes)
            .any(|(job, hash)| job.sod_sha256.as_deref() != Some(hash.as_str()))
        || signed[0].issuer_profile_id.is_none()
        || signed[0].issuer_profile_id != signed[1].issuer_profile_id
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if had_existing
        && !service
            .repository
            .selected_flow_ready(
                &principal,
                &jobs[0],
                &PassportBatchIdentity {
                    batch_id,
                    selected_flow_instance_id: &request.selected_flow_instance_id,
                    selected_job_id: &jobs[0].id,
                    companion_job_id: &jobs[1].id,
                },
                &sod_hashes[0],
                jobs[0].submission_intent_signing_provenance.as_ref(),
            )
            .await
            .map_err(PassportHttpError::Storage)?
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let digests = [
        material_digests(
            &prepared[0].payload(),
            &jobs[0].organization_id,
            &jobs[0].id,
            &jobs[0].country_code,
            Some(&jobs[0].document_type),
        )
        .map_err(|_| PassportHttpError::InvalidArtifact)?,
        material_digests(
            &prepared[1].payload(),
            &jobs[1].organization_id,
            &jobs[1].id,
            &jobs[1].country_code,
            Some(&jobs[1].document_type),
        )
        .map_err(|_| PassportHttpError::InvalidArtifact)?,
    ];
    let existing_receipts = if had_existing {
        [
            service
                .repository
                .beta_material_receipt(&principal, &jobs[0].id)
                .await
                .map_err(PassportHttpError::Storage)?,
            service
                .repository
                .beta_material_receipt(&principal, &jobs[1].id)
                .await
                .map_err(PassportHttpError::Storage)?,
        ]
    } else {
        [None, None]
    };
    for index in 0..2 {
        if existing_receipts[index].as_ref().is_some_and(|receipt| {
            !beta_receipt_material_matches(receipt, &digests[index])
                || receipt
                    .document_type
                    .as_deref()
                    .is_some_and(|document_type| document_type != jobs[index].document_type)
        }) {
            return Err(PassportHttpError::ConcurrentChange);
        }
    }
    if !had_existing {
        for job in &jobs {
            if service
                .repository
                .beta_material_receipt(&principal, &job.id)
                .await
                .map_err(PassportHttpError::Storage)?
                .is_some()
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
        }
        let now = database_precision_now();
        let provenance = [
            serde_json::to_value(SubmissionSigningProvenance::managed_kms(
                &jobs[0], &signed[0], now,
            )?)
            .map_err(|_| PassportHttpError::InvalidArtifact)?,
            serde_json::to_value(SubmissionSigningProvenance::managed_kms(
                &jobs[1], &signed[1], now,
            )?)
            .map_err(|_| PassportHttpError::InvalidArtifact)?,
        ];
        let reservations = [
            PassportSubmissionReservation {
                intent_id: Uuid::new_v4(),
                sod_sha256: &sod_hashes[0],
                signed_artifact_ciphertext: None,
                provider_profile_id: Some("passport-beta-bureau"),
                bureau_endpoint_sha256: &endpoint_sha256,
                signing_provenance: Some(&provenance[0]),
                now,
            },
            PassportSubmissionReservation {
                intent_id: Uuid::new_v4(),
                sod_sha256: &sod_hashes[1],
                signed_artifact_ciphertext: None,
                provider_profile_id: Some("passport-beta-bureau"),
                bureau_endpoint_sha256: &endpoint_sha256,
                signing_provenance: Some(&provenance[1]),
                now,
            },
        ];
        service
            .repository
            .reserve_batch_submissions(
                &principal,
                [&jobs[0], &jobs[1]],
                [&reservations[0], &reservations[1]],
                &PassportBatchIdentity {
                    batch_id,
                    selected_flow_instance_id: &request.selected_flow_instance_id,
                    selected_job_id: &jobs[0].id,
                    companion_job_id: &jobs[1].id,
                },
            )
            .await
            .map_err(PassportHttpError::Storage)?
            .ok_or(PassportHttpError::ConcurrentChange)?;
    }
    if had_existing && jobs.iter().any(|job| job.bureau_job_id.is_some()) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let mapped_ids = if let [Some(first), Some(second)] = &existing_receipts {
        if first.bureau_job_id == second.bureau_job_id {
            return Err(PassportHttpError::ConcurrentChange);
        }
        [first.bureau_job_id, second.bureau_job_id]
    } else {
        if had_existing
            && !service
                .repository
                .claim_beta_batch_replay(&principal, batch_id, database_precision_now())
                .await
                .map_err(PassportHttpError::Storage)?
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
        let batch = PersonalizationBatch {
            id: batch_id.to_string(),
            organization_id: principal.organization_id().to_owned(),
            jobs: prepared.to_vec(),
            status: ProductionStatus::Queued,
            submitted_at: Utc::now(),
        };
        let (outcome, evidence) = bureau
            .submit_beta_batch_with_wire_evidence(&batch, Some(&wire_key))
            .await
            .map_err(|_| PassportHttpError::ConcurrentChange)?;
        if !had_existing {
            let identity = PassportBatchIdentity {
                batch_id,
                selected_flow_instance_id: &request.selected_flow_instance_id,
                selected_job_id: &jobs[0].id,
                companion_job_id: &jobs[1].id,
            };
            if !service
                .repository
                .mark_beta_batch_first_response(&principal, &identity, database_precision_now())
                .await
                .map_err(PassportHttpError::Storage)?
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
            if retain_beta_batch_first_wire(
                &service,
                &principal,
                &identity,
                &wire_key_sha256,
                evidence.ok_or(PassportHttpError::ConcurrentChange)?,
            )
            .await
            .is_err()
            {
                // Issuance can continue from immutable simulator receipts. The
                // acceptance response explicitly withholds unverified proof.
                error!("first beta batch wire evidence could not be retained");
            }
        }
        [
            outcome.jobs[0]
                .bureau_job_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(PassportHttpError::ConcurrentChange)?,
            outcome.jobs[1]
                .bureau_job_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(PassportHttpError::ConcurrentChange)?,
        ]
    };
    // A single-job submit is an upsert. Prove that both batch rows already
    // exist before allowing it to fill a missing document_type on either row.
    let mut receipts =
        beta_batch_receipts(&service, &principal, &jobs, &digests, &mapped_ids).await?;
    beta_batch_first_wire_commitments(
        &service,
        &principal,
        batch_id,
        &jobs,
        &mapped_ids,
        &wire_key,
    )
    .await?;
    if receipts
        .iter()
        .any(|receipt| receipt.document_type.is_none())
        && !service
            .repository
            .claim_beta_batch_receipt_completion(&principal, batch_id, database_precision_now())
            .await
            .map_err(PassportHttpError::Storage)?
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    for index in 0..2 {
        if receipts[index].document_type.is_none() {
            receipts =
                beta_batch_receipts(&service, &principal, &jobs, &digests, &mapped_ids).await?;
            let reserved = service
                .repository
                .beta_batch_jobs(&principal, batch_id)
                .await
                .map_err(PassportHttpError::Storage)?
                .ok_or(PassportHttpError::ConcurrentChange)?;
            if reserved.iter().enumerate().any(|(i, job)| {
                job.id != jobs[i].id
                    || job.submission_batch_id != Some(batch_id)
                    || job.submission_intent_id.is_none()
                    || had_existing && job.submission_intent_id != jobs[i].submission_intent_id
                    || job.submission_intent_provider_profile_id.as_deref()
                        != Some("passport-beta-bureau")
                    || job.submission_intent_bureau_endpoint_sha256.as_deref()
                        != Some(endpoint_sha256.as_str())
                    || job.bureau_job_id.is_some()
            }) {
                return Err(PassportHttpError::ConcurrentChange);
            }
            if receipts[index].document_type.is_some() {
                continue;
            }
            let confirmed = bureau.submit(&prepared[index]).await;
            if let Ok(confirmed) = confirmed {
                if confirmed
                    .bureau_job_id
                    .as_deref()
                    .is_some_and(|reported| reported != mapped_ids[index].to_string().as_str())
                {
                    return Err(PassportHttpError::ConcurrentChange);
                }
            }
        }
    }
    receipts = beta_batch_receipts(&service, &principal, &jobs, &digests, &mapped_ids).await?;
    for index in 0..2 {
        if !beta_receipt_matches(
            &receipts[index],
            &digests[index],
            &jobs[index].document_type,
        ) {
            return Err(PassportHttpError::ConcurrentChange);
        }
    }
    let reserved = service
        .repository
        .beta_batch_jobs(&principal, batch_id)
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let digest_snapshots = [
        serde_json::to_value(&digests[0]).map_err(|_| PassportHttpError::InvalidArtifact)?,
        serde_json::to_value(&digests[1]).map_err(|_| PassportHttpError::InvalidArtifact)?,
    ];
    let patches: [PassportJobPatch; 2] = std::array::from_fn(|index| {
        let mut patch = PassportJobPatch::new(PassportJobStatus::Submitted);
        patch.expected_sod_sha256 = Some(reserved[index].sod_sha256.clone());
        patch.expected_secure_artifact_ciphertext =
            Some(reserved[index].secure_artifact_ciphertext.clone());
        patch.expected_submission_intent_id = reserved[index].submission_intent_id;
        patch.clear_submission_intent = true;
        patch.bureau_job_id = Some(Some(mapped_ids[index].to_string()));
        patch.bureau_provider_profile_id = Some("passport-beta-bureau".to_owned());
        patch.submission_batch_material_digests = Some(digest_snapshots[index].clone());
        patch.submitted_at = Some(receipts[index].first_accepted_at);
        patch
    });
    let bindings = [
        PassportBetaBatchBinding {
            bureau_job_id: mapped_ids[0],
            material_digests: &digests[0],
        },
        PassportBetaBatchBinding {
            bureau_job_id: mapped_ids[1],
            material_digests: &digests[1],
        },
    ];
    let bound = service
        .repository
        .bind_batch_submissions(
            &principal,
            [&reserved[0], &reserved[1]],
            [&patches[0], &patches[1]],
            [&bindings[0], &bindings[1]],
            &PassportBetaBatchDestination {
                provider_profile_id: "passport-beta-bureau",
                endpoint_sha256: &endpoint_sha256,
            },
            Utc::now(),
        )
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    beta_batch_safe_wire_response(&service, &principal, batch_id, &bound, &wire_key).await
}

async fn beta_batch_preflight(
    State(service): State<PassportHttpService>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    service.authenticate_beta_reconciliation_operator(&headers)?;
    if !service.beta_batch_ready() {
        return Err(PassportHttpError::ProviderUnavailable);
    }
    Ok(Json(json!({
        "ready": true,
        "provider_profile_id": "passport-beta-bureau",
        "issuer_mode": "managed-issuer-profile",
        "artifact_custody": "kms",
    })))
}

async fn verified_bound_batch_job(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    job: &PassportJob,
) -> Result<String, PassportHttpError> {
    let provenance: SubmissionSigningProvenance = serde_json::from_value(
        job.submission_batch_signing_provenance
            .clone()
            .ok_or(PassportHttpError::ConcurrentChange)?,
    )
    .map_err(|_| PassportHttpError::ConcurrentChange)?;
    let digests: PassportBetaMaterialDigests = serde_json::from_value(
        job.submission_batch_material_digests
            .clone()
            .ok_or(PassportHttpError::ConcurrentChange)?,
    )
    .map_err(|_| PassportHttpError::ConcurrentChange)?;
    let profile_id = provenance
        .issuer_profile_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if provenance.signing_mode != "managed-issuer-profile"
        || provenance.artifact_custody != "kms"
        || job.issuer_did.as_deref() != Some(provenance.issuer_did.as_str())
        || provenance.validated_at < job.created_at
        // The receipt timestamp comes from PostgreSQL while validation uses
        // the service clock. Keep the ordering check with bounded clock skew.
        || job.submitted_at.is_none_or(|at| {
            provenance.validated_at > at + chrono::Duration::seconds(30)
        })
        || digests
            .sod_der_sha256
            .as_ref()
            .is_none_or(|digest| job.sod_sha256.as_deref() != Some(hex::encode(digest).as_str()))
        || digests
            .dsc_der_sha256
            .as_ref()
            .is_none_or(|digest| provenance.dsc_der_sha256 != hex::encode(digest))
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let receipt = service
        .repository
        .beta_material_receipt(principal, &job.id)
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if job.bureau_job_id.as_deref() != Some(receipt.bureau_job_id.to_string().as_str())
        || !beta_receipt_matches(&receipt, &digests, &job.document_type)
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    Ok(profile_id.to_owned())
}

async fn recover_partial_beta_batch(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    batch_id: Uuid,
    request: &BetaBatchSubmitRequest,
    jobs: &[PassportJob; 2],
    bureau: &BureauClient,
    wire_key: &[u8; 32],
) -> Result<Json<Value>, PassportHttpError> {
    let endpoint_sha256 = bureau.endpoint_sha256();
    let bound_index = usize::from(jobs[0].bureau_job_id.is_none());
    let pending_index = 1 - bound_index;
    let bound = &jobs[bound_index];
    let pending = &jobs[pending_index];
    let bound_profile = verified_bound_batch_job(service, principal, bound).await?;
    if pending.status != PassportJobStatus::SodSigned.as_str() {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let provenance: SubmissionSigningProvenance = serde_json::from_value(
        pending
            .submission_intent_signing_provenance
            .clone()
            .ok_or(PassportHttpError::ConcurrentChange)?,
    )
    .map_err(|_| PassportHttpError::ConcurrentChange)?;
    if provenance.issuer_profile_id.as_deref() != Some(bound_profile.as_str()) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let (prepared, sod_sha256, newly_signed, signed) =
        prepared_personalization_job(service, pending, true, Some(&provenance)).await?;
    if newly_signed.is_some()
        || pending.sod_sha256.as_deref() != Some(sod_sha256.as_str())
        || signed.issuer_profile_id.as_deref() != Some(bound_profile.as_str())
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if pending_index == 0
        && !service
            .repository
            .selected_flow_ready(
                principal,
                pending,
                &PassportBatchIdentity {
                    batch_id,
                    selected_flow_instance_id: &request.selected_flow_instance_id,
                    selected_job_id: &jobs[0].id,
                    companion_job_id: &jobs[1].id,
                },
                &sod_sha256,
                pending.submission_intent_signing_provenance.as_ref(),
            )
            .await
            .map_err(PassportHttpError::Storage)?
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let digests = material_digests(
        &prepared.payload(),
        &pending.organization_id,
        &pending.id,
        &pending.country_code,
        Some(&pending.document_type),
    )
    .map_err(|_| PassportHttpError::InvalidArtifact)?;
    // A missing row cannot prove this source was accepted by the two-job
    // batch. Do not create it through the single-job endpoint.
    let mut receipt = service
        .repository
        .beta_material_receipt(principal, &pending.id)
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if !beta_receipt_material_matches(&receipt, &digests)
        || receipt
            .document_type
            .as_deref()
            .is_some_and(|value| value != pending.document_type)
        || bound.bureau_job_id.as_deref() == Some(receipt.bureau_job_id.to_string().as_str())
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if receipt.document_type.is_none() {
        if !service
            .repository
            .claim_beta_batch_receipt_completion(principal, batch_id, database_precision_now())
            .await
            .map_err(PassportHttpError::Storage)?
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
        let result = bureau.submit(&prepared).await;
        receipt = service
            .repository
            .beta_material_receipt(principal, &pending.id)
            .await
            .map_err(PassportHttpError::Storage)?
            .ok_or(PassportHttpError::ConcurrentChange)?;
        if let Ok(outcome) = result {
            if outcome
                .bureau_job_id
                .as_deref()
                .is_some_and(|reported| reported != receipt.bureau_job_id.to_string())
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
        }
    }
    if !beta_receipt_matches(&receipt, &digests, &pending.document_type) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let mut patch = PassportJobPatch::new(PassportJobStatus::Submitted);
    patch.expected_sod_sha256 = Some(pending.sod_sha256.clone());
    patch.expected_secure_artifact_ciphertext = Some(pending.secure_artifact_ciphertext.clone());
    patch.expected_submission_intent_id = pending.submission_intent_id;
    patch.clear_submission_intent = true;
    patch.bureau_job_id = Some(Some(receipt.bureau_job_id.to_string()));
    patch.bureau_provider_profile_id = Some("passport-beta-bureau".to_owned());
    patch.submission_batch_material_digests =
        Some(serde_json::to_value(&digests).map_err(|_| PassportHttpError::InvalidArtifact)?);
    patch.submitted_at = Some(receipt.first_accepted_at);
    service
        .repository
        .bind_partial_batch_submission(
            principal,
            [bound, pending],
            &patch,
            &PassportBetaBatchBinding {
                bureau_job_id: receipt.bureau_job_id,
                material_digests: &digests,
            },
            &PassportBetaBatchDestination {
                provider_profile_id: "passport-beta-bureau",
                endpoint_sha256: &endpoint_sha256,
            },
            Utc::now(),
        )
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let pair = service
        .repository
        .beta_batch_jobs(principal, batch_id)
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if pair.iter().any(|job| job.bureau_job_id.is_none()) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    beta_batch_safe_wire_response(service, principal, batch_id, &pair, wire_key).await
}

fn beta_batch_safe_response(batch_id: Uuid, jobs: &[PassportJob; 2]) -> Value {
    json!({
        "batch_id": batch_id,
        "jobs": [safe(&jobs[0]), safe(&jobs[1])]
    })
}

async fn retain_beta_batch_first_wire(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    identity: &PassportBatchIdentity<'_>,
    wire_key_sha256: &str,
    evidence: BetaBatchWireEvidence,
) -> Result<(), PassportHttpError> {
    let ArtifactCryptor(cipher) = service.cipher()?;
    let request_len = u32::try_from(evidence.request_bytes.len())
        .map_err(|_| PassportHttpError::ConcurrentChange)?;
    // PBW1 || u32 request length || exact request || exact response. The
    // tenant-bound KMS envelope retains private bytes without base64 copies.
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext.extend_from_slice(b"PBW1");
    plaintext.extend_from_slice(&request_len.to_be_bytes());
    plaintext.extend_from_slice(&evidence.request_bytes);
    plaintext.extend_from_slice(&evidence.response_bytes);
    let ciphertext = cipher
        .encrypt_bytes(
            principal.organization_id(),
            &format!("passport-beta-batch-{}-wire", identity.batch_id),
            &plaintext,
        )
        .await
        .map_err(kms_artifact_error)?;
    if !service
        .repository
        .retain_beta_batch_first_wire(
            principal,
            identity,
            &ciphertext,
            wire_key_sha256,
            &evidence.commitments,
        )
        .await
        .map_err(PassportHttpError::Storage)?
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    Ok(())
}

async fn beta_batch_safe_wire_response(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    batch_id: Uuid,
    jobs: &[PassportJob; 2],
    wire_key: &[u8; 32],
) -> Result<Json<Value>, PassportHttpError> {
    let mapped_ids = std::array::from_fn(|index| {
        jobs[index]
            .bureau_job_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
    });
    let [Some(first), Some(second)] = mapped_ids else {
        return Err(PassportHttpError::ConcurrentChange);
    };
    let commitments = beta_batch_first_wire_commitments(
        service,
        principal,
        batch_id,
        jobs,
        &[first, second],
        wire_key,
    )
    .await?;
    let mut response = beta_batch_safe_response(batch_id, jobs);
    if let Some(commitments) = commitments {
        response["wire_evidence_status"] = json!("verified");
        response["http_status"] = json!(202);
        response["batch_status"] = json!("QUEUED");
        response["wire_commitments"] =
            serde_json::to_value(commitments).map_err(|_| PassportHttpError::ConcurrentChange)?;
        return Ok(Json(response));
    }
    response["wire_evidence_status"] = json!("unavailable");
    Ok(Json(response))
}

async fn beta_batch_first_wire_commitments(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    batch_id: Uuid,
    jobs: &[PassportJob; 2],
    mapped_ids: &[Uuid; 2],
    wire_key: &[u8; 32],
) -> Result<Option<BetaBatchWireCommitments>, PassportHttpError> {
    let wire_key_sha256 = hex::encode(Sha256::digest(wire_key));
    let commitments = service
        .repository
        .beta_batch_first_wire_commitments(principal, batch_id, &wire_key_sha256)
        .await
        .map_err(PassportHttpError::Storage)?;
    let Some(commitments) = commitments else {
        if service
            .repository
            .beta_batch_has_first_wire(principal, batch_id)
            .await
            .map_err(PassportHttpError::Storage)?
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
        return Ok(None);
    };
    let ciphertext = service
        .repository
        .beta_batch_first_wire_ciphertext(principal, batch_id, &wire_key_sha256)
        .await
        .map_err(PassportHttpError::Storage)?
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let ArtifactCryptor(cipher) = service.cipher()?;
    let plaintext = cipher
        .decrypt_bytes(
            principal.organization_id(),
            &format!("passport-beta-batch-{batch_id}-wire"),
            &ciphertext,
        )
        .await
        .map_err(kms_artifact_error)?;
    if plaintext.len() < 9 || &plaintext[..4] != b"PBW1" {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let request_len = u32::from_be_bytes(
        plaintext[4..8]
            .try_into()
            .map_err(|_| PassportHttpError::ConcurrentChange)?,
    ) as usize;
    let split = 8usize
        .checked_add(request_len)
        .filter(|split| *split < plaintext.len())
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let request_bytes = &plaintext[8..split];
    let response_bytes = &plaintext[split..];
    if beta_batch_wire_commitment(wire_key, b"request", request_bytes)
        != commitments.request_commitment
        || beta_batch_wire_commitment(wire_key, b"response", response_bytes)
            != commitments.response_commitment
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let request: Value =
        serde_json::from_slice(request_bytes).map_err(|_| PassportHttpError::ConcurrentChange)?;
    if request["batch_id"] != batch_id.to_string()
        || request["organization_id"] != principal.organization_id()
        || request["jobs"].as_array().is_none_or(|items| {
            items.len() != 2 || items[0]["job_id"] != jobs[0].id || items[1]["job_id"] != jobs[1].id
        })
        || !beta_batch_wire_response_matches(response_bytes, [&jobs[0].id, &jobs[1].id], mapped_ids)
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    Ok(Some(commitments))
}

fn beta_batch_wire_response_matches(
    response_bytes: &[u8],
    source_ids: [&str; 2],
    mapped_ids: &[Uuid; 2],
) -> bool {
    parse_beta_batch_mapping(response_bytes, source_ids)
        .is_ok_and(|first_response_ids| first_response_ids == *mapped_ids)
}

async fn wait_for_submission(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    application_id: &str,
) -> Result<Json<Value>, PassportHttpError> {
    // Preserve the released route's concurrent retry result when the first
    // submit binds successfully. A durable ambiguous intent is never retried
    // or silently cleared; it becomes a conflict after the send window.
    let max_age = chrono::Duration::seconds(35);
    let local_deadline = tokio::time::Instant::now() + Duration::from_secs(35);
    loop {
        let current = service.job(principal, application_id).await?;
        if current.bureau_job_id.is_some() {
            return Ok(Json(safe(&current)));
        }
        let Some(started_at) = current.submission_intent_started_at else {
            return Err(PassportHttpError::ConcurrentChange);
        };
        if Utc::now().signed_duration_since(started_at) >= max_age
            || tokio::time::Instant::now() >= local_deadline
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn beta_batch_receipts(
    service: &PassportHttpService,
    principal: &PassportTenantPrincipal,
    jobs: &[PassportJob; 2],
    digests: &[PassportBetaMaterialDigests; 2],
    mapped_ids: &[Uuid; 2],
) -> Result<[PassportBetaMaterialReceipt; 2], PassportHttpError> {
    let receipts = [
        service
            .repository
            .beta_material_receipt(principal, &jobs[0].id)
            .await
            .map_err(PassportHttpError::Storage)?,
        service
            .repository
            .beta_material_receipt(principal, &jobs[1].id)
            .await
            .map_err(PassportHttpError::Storage)?,
    ];
    verified_beta_batch_receipts(
        receipts,
        [&jobs[0].document_type, &jobs[1].document_type],
        digests,
        mapped_ids,
    )
}

fn verified_beta_batch_receipts(
    receipts: [Option<PassportBetaMaterialReceipt>; 2],
    document_types: [&str; 2],
    digests: &[PassportBetaMaterialDigests; 2],
    mapped_ids: &[Uuid; 2],
) -> Result<[PassportBetaMaterialReceipt; 2], PassportHttpError> {
    let [Some(first), Some(second)] = receipts else {
        return Err(PassportHttpError::ConcurrentChange);
    };
    if first.bureau_job_id == second.bureau_job_id {
        return Err(PassportHttpError::ConcurrentChange);
    }
    for (index, receipt) in [&first, &second].iter().enumerate() {
        if receipt.bureau_job_id != mapped_ids[index]
            || !beta_receipt_material_matches(receipt, &digests[index])
            || receipt
                .document_type
                .as_deref()
                .is_some_and(|document_type| document_type != document_types[index])
        {
            return Err(PassportHttpError::ConcurrentChange);
        }
    }
    Ok([first, second])
}

fn beta_receipt_material_matches(
    receipt: &PassportBetaMaterialReceipt,
    digests: &PassportBetaMaterialDigests,
) -> bool {
    let Some(sod_der_sha256) = digests.sod_der_sha256.as_deref() else {
        return false;
    };
    let Some(dsc_der_sha256) = digests.dsc_der_sha256.as_deref() else {
        return false;
    };
    receipt.content_sha256.as_deref() == Some(digests.content_sha256.as_slice())
        && receipt.sod_der_sha256.as_deref() == Some(sod_der_sha256)
        && receipt.dsc_der_sha256.as_deref() == Some(dsc_der_sha256)
        && receipt.dsc_pem_wire_sha256.as_deref() == Some(digests.dsc_pem_wire_sha256.as_slice())
}

fn beta_receipt_matches(
    receipt: &PassportBetaMaterialReceipt,
    digests: &PassportBetaMaterialDigests,
    document_type: &str,
) -> bool {
    beta_receipt_material_matches(receipt, digests)
        && receipt.document_type.as_deref() == Some(document_type)
}

async fn reconcile_beta_submission(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    if !service.beta_reconciliation_enabled {
        return Err(PassportHttpError::ProviderUnavailable);
    }
    let principal = service.authenticate_beta_reconciliation_operator(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    if job.submission_batch_id.is_some() {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if job.bureau_job_id.is_some() {
        return Ok(Json(safe(&job)));
    }
    let intent_id = job
        .submission_intent_id
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let started_at = job
        .submission_intent_started_at
        .ok_or(PassportHttpError::ConcurrentChange)?;
    if Utc::now().signed_duration_since(started_at) < chrono::Duration::seconds(35) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let bureau = service.bureau()?;
    if job.submission_intent_provider_profile_id.as_deref() != Some("passport-beta-bureau")
        || job.submission_intent_bureau_endpoint_sha256.as_deref()
            != Some(bureau.endpoint_sha256().as_str())
    {
        return Err(PassportHttpError::ConcurrentChange);
    }
    if !matches!(
        (&service.signer, &service.cipher),
        (
            Some(PassportSigner::Managed(_)),
            ArtifactAvailability::Ready(_)
        )
    ) {
        return Err(PassportHttpError::ProviderUnavailable);
    }
    let provenance: SubmissionSigningProvenance = job
        .submission_intent_signing_provenance
        .clone()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or(PassportHttpError::ConcurrentChange)?;
    let (prepared, sod_sha256, newly_signed, _) =
        prepared_personalization_job(&service, &job, true, Some(&provenance)).await?;
    if newly_signed.is_some() || job.sod_sha256.as_deref() != Some(sod_sha256.as_str()) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let digests = material_digests(
        &prepared.payload(),
        &job.organization_id,
        &job.id,
        &job.country_code,
        Some(&job.document_type),
    )
    .map_err(|_| PassportHttpError::InvalidArtifact)?;
    let mut receipt = service
        .repository
        .beta_material_receipt(&principal, &job.id)
        .await
        .map_err(PassportHttpError::Storage)?;
    let needs_replay = match receipt.as_ref() {
        None => true,
        Some(existing) if existing.document_type.is_none() => {
            if !beta_receipt_material_matches(existing, &digests) {
                return Err(PassportHttpError::ConcurrentChange);
            }
            true
        }
        Some(_) => false,
    };
    if needs_replay {
        // The simulator is idempotent by tenant and source ID. One exact replay
        // can fill a missing row or return its first accepted UUID. Its HTTP
        // outcome alone is never proof: read the immutable receipt afterward.
        let replay = bureau.submit(&prepared).await;
        receipt = service
            .repository
            .beta_material_receipt(&principal, &job.id)
            .await
            .map_err(PassportHttpError::Storage)?;
        if let (Ok(outcome), Some(receipt)) = (&replay, &receipt) {
            if outcome
                .bureau_job_id
                .as_deref()
                .is_some_and(|reported| reported != receipt.bureau_job_id.to_string())
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
        }
    }
    let receipt = receipt.ok_or(PassportHttpError::ConcurrentChange)?;
    if !beta_receipt_matches(&receipt, &digests, &job.document_type) {
        return Err(PassportHttpError::ConcurrentChange);
    }
    let mut patch = PassportJobPatch::new(PassportJobStatus::Submitted);
    patch.expected_sod_sha256 = Some(job.sod_sha256.clone());
    patch.expected_secure_artifact_ciphertext = Some(job.secure_artifact_ciphertext.clone());
    patch.expected_submission_intent_id = Some(intent_id);
    patch.clear_submission_intent = true;
    patch.bureau_job_id = Some(Some(receipt.bureau_job_id.to_string()));
    patch.bureau_provider_profile_id = Some("passport-beta-bureau".to_owned());
    patch.submitted_at = Some(receipt.first_accepted_at);
    let updated = match service.update(&principal, &job, &patch).await {
        Ok(updated) => updated,
        Err(PassportHttpError::ConcurrentChange) => {
            let current = service.job(&principal, &application_id).await?;
            if current.bureau_job_id.as_deref() != Some(receipt.bureau_job_id.to_string().as_str())
                || current.bureau_provider_profile_id.as_deref() != Some("passport-beta-bureau")
                || current.sod_sha256 != job.sod_sha256
                || current.submission_intent_id.is_some()
            {
                return Err(PassportHttpError::ConcurrentChange);
            }
            current
        }
        Err(error) => return Err(error),
    };
    Ok(Json(safe(&updated)))
}

fn signed_sod_sha256(signed: &SignedMaterial) -> Result<String, PassportHttpError> {
    let sod = decode_python_validated_base64(&signed.sod_der_base64)
        .map_err(|_| PassportHttpError::Signer(SignerError::IncompleteMaterial))?;
    Ok(hex::encode(Sha256::digest(sod)))
}

fn database_precision_now() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current UTC timestamp fits PostgreSQL timestamp range")
}

fn status_from_bureau(status: ProductionStatus) -> PassportJobStatus {
    match status {
        ProductionStatus::Queued => PassportJobStatus::Submitted,
        ProductionStatus::Printing | ProductionStatus::Encoding => PassportJobStatus::InProduction,
        ProductionStatus::QualityCheck => PassportJobStatus::QualityCheck,
        ProductionStatus::Shipped | ProductionStatus::Delivered => {
            PassportJobStatus::ReadyForActivation
        }
        ProductionStatus::Failed => PassportJobStatus::Failed,
        ProductionStatus::Cancelled => PassportJobStatus::Cancelled,
    }
}

async fn production_status(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    let Some(bureau_job_id) = &job.bureau_job_id else {
        return Ok(Json(safe(&job)));
    };
    if matches!(job.status.as_str(), "ACTIVE" | "FAILED" | "CANCELLED") {
        return Ok(Json(safe(&job)));
    }
    if job.bureau_provider_profile_id.as_deref() != service.bureau_provider_profile_id.as_deref() {
        return Err(PassportHttpError::ProviderUnavailable);
    }
    let outcome = service
        .bureau()?
        .poll(bureau_job_id)
        .await
        .map_err(PassportHttpError::Bureau)?;
    let incoming_status = status_from_bureau(outcome.status);
    if job.status == incoming_status.as_str() {
        if fill_missing_bureau_metadata(
            job.tracking_number.as_deref(),
            job.error_message.as_deref(),
            outcome.tracking_number.as_deref(),
            outcome.error_message.as_deref(),
        )
        .is_none()
        {
            let current = service.job(&principal, &application_id).await?;
            return Ok(Json(safe(&current)));
        }
        let updated = service
            .repository
            .fill_missing_bureau_metadata(
                &principal,
                &job.application_id,
                &job.status,
                outcome.tracking_number.as_deref(),
                outcome.error_message.as_deref(),
                Utc::now(),
            )
            .await
            .map_err(PassportHttpError::Storage)?;
        let updated = match updated {
            Some(updated) => updated,
            None => service.job(&principal, &application_id).await?,
        };
        return Ok(Json(safe(&updated)));
    }
    if !should_apply_bureau_status(&job.status, incoming_status.as_str()) {
        let current = service.job(&principal, &application_id).await?;
        return Ok(Json(safe(&current)));
    }
    let mut patch = PassportJobPatch::new(incoming_status);
    patch.tracking_number = Some(
        outcome
            .tracking_number
            .filter(|number| !number.trim().is_empty())
            .or(job.tracking_number.clone()),
    );
    patch.error_message = Some(outcome.error_message);
    let updated = service.update(&principal, &job, &patch).await?;
    Ok(Json(safe(&updated)))
}

async fn quality_verify(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, PassportHttpError> {
    let payload = python_model_body(&body, &headers)?;
    let order = json_field_order(&body);
    let request = QualityResultRequest::from_python_value(&payload, Some(&order))
        .map_err(PassportHttpError::Validation)?;
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    if !matches!(
        job.status.as_str(),
        "QUALITY_CHECK" | "READY_FOR_ACTIVATION"
    ) {
        return Err(PassportHttpError::QualityNotReady);
    }
    let mut patch = PassportJobPatch::new(if request.passed {
        PassportJobStatus::ReadyForActivation
    } else {
        PassportJobStatus::Failed
    });
    patch.quality_result = Some(Some(json!({
        "passed": request.passed, "checked_at": python_datetime(Utc::now()),
        "checked_by": header(&headers, "x-user-id"), "failure_codes": request.failure_codes,
    })));
    patch.error_code = Some((!request.passed).then(|| "QUALITY_CHECK_FAILED".to_owned()));
    let updated = service.update(&principal, &job, &patch).await?;
    Ok(Json(safe(&updated)))
}

async fn activate(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    if job.status != "READY_FOR_ACTIVATION"
        || job
            .quality_result
            .as_ref()
            .and_then(|value| value.get("passed"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(PassportHttpError::ActivationNotReady);
    }
    let mut patch = PassportJobPatch::new(PassportJobStatus::Active);
    patch.completed_at = Some(Utc::now());
    patch.secure_artifact_ciphertext =
        Some(service.cipher()?.encrypted_scrubbed_artifact(&job).await?);
    let updated = service.update(&principal, &job, &patch).await?;
    Ok(Json(safe(&updated)))
}

async fn personalization_webhook(
    State(service): State<PassportHttpService>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, PassportHttpError> {
    let signature = header(&headers, "x-personalization-signature")
        .ok_or(PassportHttpError::MissingWebhookSignature)?;
    let verifier = service
        .webhook_kms
        .as_ref()
        .ok_or(PassportHttpError::Bureau(
            BureauError::CallbackKmsUnavailable,
        ))?;
    let event = verifier
        .verify(&body, signature)
        .await
        .map_err(PassportHttpError::Bureau)?;
    let updated = service
        .repository
        .apply_verified_webhook(&event, Utc::now())
        .await
        .map_err(PassportHttpError::WebhookStorage)?;
    if updated.is_none() {
        return Err(PassportHttpError::WebhookJobNotFound);
    }
    Ok(Json(json!({"accepted": true})))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn beta_receipt_requires_every_first_accepted_digest() {
        let digests = PassportBetaMaterialDigests {
            content_sha256: vec![1; 32],
            legacy_request_sha256: vec![9; 32],
            sod_der_sha256: Some(vec![2; 32]),
            dsc_der_sha256: Some(vec![3; 32]),
            dsc_pem_wire_sha256: vec![4; 32],
        };
        let mut receipt = PassportBetaMaterialReceipt {
            bureau_job_id: Uuid::new_v4(),
            content_sha256: Some(vec![1; 32]),
            sod_der_sha256: Some(vec![2; 32]),
            dsc_der_sha256: Some(vec![3; 32]),
            dsc_pem_wire_sha256: Some(vec![4; 32]),
            document_type: Some("TD1".into()),
            first_accepted_at: Utc::now(),
        };
        assert!(beta_receipt_matches(&receipt, &digests, "TD1"));
        receipt.dsc_der_sha256 = None;
        assert!(!beta_receipt_matches(&receipt, &digests, "TD1"));
        receipt.dsc_der_sha256 = Some(vec![3; 32]);
        receipt.content_sha256 = None;
        assert!(!beta_receipt_matches(&receipt, &digests, "TD1"));
        receipt.content_sha256 = Some(vec![1; 32]);
        assert!(!beta_receipt_matches(&receipt, &digests, "TD2"));
        receipt.document_type = None;
        assert!(beta_receipt_material_matches(&receipt, &digests));
        assert!(!beta_receipt_matches(&receipt, &digests, "TD1"));
    }

    #[test]
    fn beta_batch_type_completion_requires_both_first_accepted_rows() {
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let digests = std::array::from_fn(|index| PassportBetaMaterialDigests {
            content_sha256: vec![index as u8 + 1; 32],
            legacy_request_sha256: vec![9; 32],
            sod_der_sha256: Some(vec![2; 32]),
            dsc_der_sha256: Some(vec![3; 32]),
            dsc_pem_wire_sha256: vec![4; 32],
        });
        let receipt = |index: usize| PassportBetaMaterialReceipt {
            bureau_job_id: ids[index],
            content_sha256: Some(digests[index].content_sha256.clone()),
            sod_der_sha256: digests[index].sod_der_sha256.clone(),
            dsc_der_sha256: digests[index].dsc_der_sha256.clone(),
            dsc_pem_wire_sha256: Some(digests[index].dsc_pem_wire_sha256.clone()),
            document_type: None,
            first_accepted_at: Utc::now(),
        };
        assert!(matches!(
            verified_beta_batch_receipts([Some(receipt(0)), None], ["TD1", "TD1"], &digests, &ids),
            Err(PassportHttpError::ConcurrentChange)
        ));
        assert!(matches!(
            verified_beta_batch_receipts(
                [Some(receipt(0)), Some(receipt(0))],
                ["TD1", "TD1"],
                &digests,
                &ids,
            ),
            Err(PassportHttpError::ConcurrentChange)
        ));
        assert!(verified_beta_batch_receipts(
            [Some(receipt(0)), Some(receipt(1))],
            ["TD1", "TD1"],
            &digests,
            &ids,
        )
        .is_ok());
    }

    #[test]
    fn beta_batch_retained_response_must_match_receipt_mapping() {
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let reversed = serde_json::to_vec(&json!({
            "status": "QUEUED",
            "jobs": [
                {"job_id": "companion", "bureau_job_id": ids[1], "status": "QUEUED"},
                {"job_id": "selected", "bureau_job_id": ids[0], "status": "QUEUED"},
            ]
        }))
        .unwrap();
        assert!(beta_batch_wire_response_matches(
            &reversed,
            ["selected", "companion"],
            &ids,
        ));
        assert!(!beta_batch_wire_response_matches(
            &reversed,
            ["selected", "companion"],
            &[ids[1], ids[0]],
        ));
        assert!(!beta_batch_wire_response_matches(
            &reversed,
            ["selected", "other"],
            &ids,
        ));
    }

    fn test_router() -> Router {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let keyring = PassportTenantKeyring::from_json(
            r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#,
        )
        .unwrap();
        router(PassportHttpService::new(
            keyring,
            PostgresPassportRepository::new(pool),
            None,
            None,
            None,
        ))
    }

    #[tokio::test]
    async fn internal_service_token_authenticates_only_the_presented_organization_context() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let token = "synthetic-internal-passport-token-00000001";
        let service = PassportHttpService::with_artifact_availability(
            PassportTenantCredentialSource::internal_service_token(token).unwrap(),
            PostgresPassportRepository::new(pool),
            ArtifactAvailability::Missing,
            None,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-organization-id", "org-a".parse().unwrap());
        headers.insert("x-api-key", token.parse().unwrap());
        assert_eq!(
            service.authenticate(&headers).unwrap().organization_id(),
            "org-a"
        );
        headers.insert("x-api-key", "wrong-token".parse().unwrap());
        assert!(service.authenticate(&headers).is_err());
        headers.remove("x-api-key");
        assert!(service.authenticate(&headers).is_err());
        headers.insert("x-api-key", token.parse().unwrap());
        headers.remove("x-organization-id");
        assert!(service.authenticate(&headers).is_err());
    }

    #[tokio::test]
    async fn private_flow_signing_requires_tenant_and_service_credentials() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let keyring = PassportTenantKeyring::from_json(
            r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#,
        )
        .unwrap();
        let mut service = PassportHttpService::new(
            keyring,
            PostgresPassportRepository::new(pool),
            None,
            None,
            None,
        );
        service.internal_service_token = Some("flow-service-test-token-00000000000001".into());
        let mut headers = HeaderMap::new();
        headers.insert("x-organization-id", "org-1".parse().unwrap());
        headers.insert(
            "x-api-key",
            "passport-tenant-test-key-00000000000001".parse().unwrap(),
        );
        assert!(service.authenticate_internal_flow(&headers).is_err());
        headers.insert("x-service-token", "wrong-flow-token".parse().unwrap());
        assert!(service.authenticate_internal_flow(&headers).is_err());
        headers.insert(
            "x-service-token",
            "flow-service-test-token-00000000000001".parse().unwrap(),
        );
        assert_eq!(
            service
                .authenticate_internal_flow(&headers)
                .unwrap()
                .organization_id(),
            "org-1"
        );
        headers.insert("x-api-key", "wrong-tenant-key".parse().unwrap());
        assert!(service.authenticate_internal_flow(&headers).is_err());
    }

    #[tokio::test]
    async fn beta_reconciliation_requires_a_second_operator_credential() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let service_token = "synthetic-internal-passport-token-00000001";
        let mut service = PassportHttpService::with_artifact_availability(
            PassportTenantCredentialSource::internal_service_token(service_token).unwrap(),
            PostgresPassportRepository::new(pool),
            ArtifactAvailability::Missing,
            None,
            None,
        );
        service.beta_reconciliation_operator_token =
            Some("synthetic-reconciliation-operator-token-00000001".into());
        let mut headers = HeaderMap::new();
        headers.insert("x-organization-id", "org-a".parse().unwrap());
        headers.insert("x-api-key", service_token.parse().unwrap());
        assert!(matches!(
            service.authenticate_beta_reconciliation_operator(&headers),
            Err(PassportHttpError::OperatorUnauthorized)
        ));
        headers.insert(
            "x-passport-reconciliation-token",
            service_token.parse().unwrap(),
        );
        assert!(matches!(
            service.authenticate_beta_reconciliation_operator(&headers),
            Err(PassportHttpError::OperatorUnauthorized)
        ));
        headers.insert(
            "x-passport-reconciliation-token",
            "synthetic-reconciliation-operator-token-00000001"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            service
                .authenticate_beta_reconciliation_operator(&headers)
                .unwrap()
                .organization_id(),
            "org-a"
        );
    }

    fn authenticated_application_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/passport/applications")
            .header("content-type", "application/json")
            .header("x-organization-id", "org-1")
            .header("x-api-key", "passport-tenant-test-key-00000000000001")
            .body(Body::from(
                json!({
                    "organization_id": "org-1", "flow_execution_id": "flow-1",
                    "application_template_id": "template-1", "credential_template_id": "credential-1",
                    "delivery_destination_profile_id": "destination-1", "country_code": "USA",
                    "applicant": {}, "mrz": {}, "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}
                })
                .to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn missing_webhook_signature_matches_frozen_python_validation() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"bureau_job_id":"synthetic","status":"SHIPPED"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            frozen["webhook_missing_signature_observation"]["status"]
                .as_u64()
                .unwrap() as u16
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            frozen["webhook_missing_signature_observation"]["body"]
        );
    }

    #[tokio::test]
    async fn managed_webhook_verification_does_not_require_outbound_bureau_url() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let config = IssuanceServiceConfig::from_values(vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
            (
                "PASSPORT_TENANT_API_KEYS".to_owned(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
            ),
            (
                "PASSPORT_KMS_CALLBACKS_ENABLED".to_owned(),
                "true".to_owned(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".to_owned(),
                "internal-test-key".to_owned(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_URL".to_owned(),
                "http://127.0.0.1:1/internal/signing-keys".to_owned(),
            ),
        ])
        .unwrap();
        let service = PassportHttpService::from_config(&config, pool)
            .unwrap()
            .unwrap();
        assert!(service.bureau.is_none());
        assert!(service.webhook_kms.is_some());
        let payload =
            br#"{"organization_id":"org-1","bureau_job_id":"synthetic","status":"SHIPPED"}"#;
        let router = router(service);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header("x-personalization-signature", "invalid")
                    .body(Body::from(payload.as_slice().to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let expected = &frozen["webhook_without_bureau_url_observation"]["invalid_signature"];
        assert_eq!(
            response.status().as_u16(),
            expected["status"].as_u64().unwrap() as u16
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, expected["body"]);
        let unavailable = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header(
                        "x-personalization-signature",
                        "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    )
                    .body(Body::from(payload.as_slice().to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn kms_callback_mode_requires_internal_credential_and_never_falls_back_to_a_secret() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let values = vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
            ("PASSPORT_KMS_CALLBACKS_ENABLED".into(), "true".into()),
            (
                "PASSPORT_TENANT_API_KEYS".into(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.into(),
            ),
        ];
        let missing = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&missing, pool.clone()),
            Err(PassportStartupError::Missing(
                "SIGNING_KEYS_INTERNAL_API_KEY"
            ))
        ));
        let mut values = values;
        values.push((
            "SIGNING_KEYS_INTERNAL_API_KEY".into(),
            "internal-test-key".into(),
        ));
        values.push((
            "SIGNING_KEYS_INTERNAL_URL".into(),
            "http://127.0.0.1:1/internal/signing-keys".into(),
        ));
        let configured = IssuanceServiceConfig::from_values(values).unwrap();
        let service = PassportHttpService::from_config(&configured, pool)
            .unwrap()
            .unwrap();
        assert!(service.webhook_kms.is_some());
        let router = router(service);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header("x-personalization-signature", "legacy-hex-signature")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","bureau_job_id":"job-1","status":"SHIPPED"}"#
                            .as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let unavailable = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header(
                        "x-personalization-signature",
                        "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    )
                    .body(Body::from(
                        br#"{"organization_id":"org-1","bureau_job_id":"job-1","status":"SHIPPED"}"#
                            .as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn application_validation_matches_frozen_python_responses() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let base = frozen["application_validation_base_input"]
            .as_object()
            .unwrap();
        for case in frozen["application_validation_observations"]
            .as_array()
            .unwrap()
        {
            let payload = case.get("input").cloned().unwrap_or_else(|| {
                let mut payload = base.clone();
                if let Some(overrides) = case.get("override").and_then(Value::as_object) {
                    payload.extend(overrides.clone());
                }
                Value::Object(payload)
            });
            let raw_body = case["raw_body"]
                .as_str()
                .map_or_else(|| payload.to_string(), str::to_owned);
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/passport/applications");
            if case["omit_content_type"] != true {
                request = request.header(
                    "content-type",
                    case["content_type"].as_str().unwrap_or("application/json"),
                );
            }
            let response = test_router()
                .oneshot(request.body(Body::from(raw_body)).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                case["status"].as_u64().unwrap() as u16,
                "payload: {payload}"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body, case["body"], "payload: {payload}");
        }
    }

    #[tokio::test]
    async fn quality_validation_matches_frozen_python_responses() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        for case in frozen["quality_validation_observations"]
            .as_array()
            .unwrap()
        {
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/passport/applications/example/quality-verify");
            if case["omit_content_type"] != true {
                request = request.header(
                    "content-type",
                    case["content_type"].as_str().unwrap_or("application/json"),
                );
            }
            let response = test_router()
                .oneshot(
                    request
                        .body(Body::from(
                            case["raw_body"]
                                .as_str()
                                .map_or_else(|| case["input"].to_string(), str::to_owned),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                case["status"].as_u64().unwrap() as u16
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body, case["body"], "input: {}", case["input"]);
        }
    }

    #[tokio::test]
    async fn startup_is_default_off_and_rejects_local_key_or_unsafe_urls() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let disabled = IssuanceServiceConfig::from_values(Vec::new()).unwrap();
        assert!(PassportHttpService::from_config(&disabled, pool.clone())
            .unwrap()
            .is_none());

        let values = |signer_url: &str, bureau_url: &str| {
            vec![
                ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
                (
                    "PASSPORT_KMS_ARTIFACTS_ENABLED".to_owned(),
                    "true".to_owned(),
                ),
                (
                    "SIGNING_KEYS_INTERNAL_API_KEY".to_owned(),
                    "internal-test-key".to_owned(),
                ),
                (
                    "PASSPORT_TENANT_API_KEYS".to_owned(),
                    r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
                ),
                ("ICAO_DOCUMENT_SIGNER_URL".to_owned(), signer_url.to_owned()),
                (
                    "ICAO_DOCUMENT_SIGNER_API_KEY".to_owned(),
                    "signer-key".to_owned(),
                ),
                (
                    "PERSONALIZATION_BUREAU_URL".to_owned(),
                    bureau_url.to_owned(),
                ),
                (
                    "PERSONALIZATION_BUREAU_API_KEY".to_owned(),
                    "bureau-key".to_owned(),
                ),
            ]
        };
        let valid = IssuanceServiceConfig::from_values(values(
            "https://signer.example.test",
            "https://bureau.example.test",
        ))
        .unwrap();
        assert!(PassportHttpService::from_config(&valid, pool.clone())
            .unwrap()
            .is_some());
        let degraded = IssuanceServiceConfig::from_values(vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
            (
                "PASSPORT_TENANT_API_KEYS".to_owned(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
            ),
        ])
        .unwrap();
        let degraded = PassportHttpService::from_config(&degraded, pool.clone())
            .unwrap()
            .unwrap();
        let kms_values = vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
            ("PASSPORT_KMS_ARTIFACTS_ENABLED".into(), "true".into()),
            (
                "PASSPORT_TENANT_API_KEYS".into(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.into(),
            ),
        ];
        let kms_without_credential =
            IssuanceServiceConfig::from_values(kms_values.clone()).unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&kms_without_credential, pool.clone()),
            Err(PassportStartupError::Missing(
                "SIGNING_KEYS_INTERNAL_API_KEY"
            ))
        ));
        let mut kms_values = kms_values;
        kms_values.push((
            "SIGNING_KEYS_INTERNAL_API_KEY".into(),
            "internal-test-key".into(),
        ));
        let kms_config = IssuanceServiceConfig::from_values(kms_values).unwrap();
        let kms_service = PassportHttpService::from_config(&kms_config, pool.clone())
            .unwrap()
            .unwrap();
        assert!(matches!(kms_service.cipher, ArtifactAvailability::Ready(_)));
        let managed = IssuanceServiceConfig::from_values(vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
            (
                "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED".into(),
                "true".into(),
            ),
            (
                "PASSPORT_TENANT_API_KEYS".into(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.into(),
            ),
        ])
        .unwrap();
        let managed = PassportHttpService::from_config(&managed, pool.clone())
            .unwrap()
            .unwrap();
        assert_eq!(
            managed.signer.as_ref().unwrap().mode(),
            "MANAGED_ISSUER_PROFILE"
        );
        let missing_selector = router(managed)
            .oneshot(authenticated_application_request())
            .await
            .unwrap();
        assert_eq!(missing_selector.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let expected = &contract["degraded_capabilities"];
        let degraded_router = router(degraded);
        let response = degraded_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/passport/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            expected["http_status"].as_u64().unwrap()
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        for field in ["supported", "encrypted_artifact_store", "bureau_configured"] {
            assert_eq!(body[field], expected[field]);
        }
        assert_eq!(body["signer"]["mode"], expected["signer_mode"]);
        assert_eq!(
            body["blockers"].as_array().unwrap().len(),
            expected["blocker_count"].as_u64().unwrap() as usize
        );
        let response = degraded_router
            .oneshot(authenticated_application_request())
            .await
            .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            expected["authenticated_application_create"]["status"]
                .as_u64()
                .unwrap()
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["detail"],
            expected["authenticated_application_create"]["detail"]
        );
        let mut local_key = values("https://signer.example.test", "https://bureau.example.test");
        local_key.push((
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY".to_owned(),
            "invalid-secret-artifact-key".to_owned(),
        ));
        assert!(IssuanceServiceConfig::from_values(local_key).is_err());
        let bad_signer = IssuanceServiceConfig::from_values(values(
            "https://user:password@signer.example.test",
            "https://bureau.example.test",
        ))
        .unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&bad_signer, pool.clone()).err(),
            Some(PassportStartupError::Signer(SignerError::InvalidUrl))
        ));
        let bad_bureau = IssuanceServiceConfig::from_values(values(
            "https://signer.example.test",
            "https://bureau.example.test?token=secret",
        ))
        .unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&bad_bureau, pool).err(),
            Some(PassportStartupError::Bureau(BureauError::InvalidUrl))
        ));
    }

    #[tokio::test]
    async fn remote_signer_is_selected_and_local_signing_is_rejected() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let values = vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
            (
                "ICAO_DOCUMENT_SIGNER_URL".to_owned(),
                "https://signer.example.test".to_owned(),
            ),
            (
                "PASSPORT_TENANT_API_KEYS".to_owned(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
            ),
            (
                "PASSPORT_KMS_ARTIFACTS_ENABLED".to_owned(),
                "true".to_owned(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".to_owned(),
                "synthetic-internal-key".to_owned(),
            ),
            (
                "PERSONALIZATION_BUREAU_URL".to_owned(),
                "https://bureau.example.test".to_owned(),
            ),
        ];
        let remote_config = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        let remote = PassportHttpService::from_config(&remote_config, pool)
            .unwrap()
            .unwrap();
        assert_eq!(remote.signer.as_ref().unwrap().mode(), "REMOTE");
        let response = router(remote)
            .oneshot(
                Request::builder()
                    .uri("/v1/passport/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["signer"]["mode"], "REMOTE");
        assert_eq!(body["supported"], true);

        let mut forbidden = values;
        forbidden.push((
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED".to_owned(),
            "true".to_owned(),
        ));
        assert!(IssuanceServiceConfig::from_values(forbidden).is_err());
    }

    #[tokio::test]
    async fn frozen_nine_routes_are_registered_without_enabling_database_or_providers() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let routes = [
            ("GET", "/v1/passport/capabilities", StatusCode::OK),
            (
                "POST",
                "/v1/passport/applications",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/applications/example/generate-data-groups",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/applications/example/generate-sod",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/applications/example/submit-personalization",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "GET",
                "/v1/passport/applications/example/production-status",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/applications/example/quality-verify",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/applications/example/activate",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "POST",
                "/v1/passport/webhooks/personalization",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ];
        assert_eq!(routes.len(), 9);
        let observed: Vec<_> = routes
            .iter()
            .map(|(method, path, _)| {
                json!({
                    "method": method,
                    "path": path.replace("/example/", "/{application_id}/"),
                })
            })
            .collect();
        assert_eq!(json!(observed), frozen["routes"]);
        for (method, path, expected) in routes {
            let body = if path == "/v1/passport/applications" {
                json!({
                    "organization_id": "org-1", "flow_execution_id": "flow-1",
                    "application_template_id": "template-1", "credential_template_id": "credential-1",
                    "delivery_destination_profile_id": "destination-1", "country_code": "USA",
                    "applicant": {}, "mrz": {}, "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}
                }).to_string()
            } else if path.ends_with("quality-verify") {
                json!({"passed": true}).to_string()
            } else {
                String::new()
            };
            let response = test_router()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{method} {path}");
            if path == "/v1/passport/capabilities" {
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["supported"], false);
                assert_eq!(body["signer"]["mode"], "UNAVAILABLE");
            }
        }
    }
}
