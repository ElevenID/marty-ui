//! Tenant-authenticated native physical-document routes. This router is opt-in:
//! production traffic must not reach it until all provider and parity gates pass.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use marty_passport_auth::{
    PassportTenantAuthError, PassportTenantKeyring, PassportTenantPrincipal,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::error;
use uuid::Uuid;

use crate::{
    config::IssuanceServiceConfig,
    passport_artifact::{PassportArtifactCipher, PassportArtifactError},
    passport_bureau::{
        parse_verified_webhook, BureauClient, BureauError, DocumentType, PersonalizationJob,
        ProductionStatus,
    },
    passport_contract::{
        application_nested_field_orders, decode_python_validated_base64, json_field_order,
        python_datetime, PassportApplicationRequest, PassportRequestError, PassportSafeResponse,
        QualityResultRequest,
    },
    passport_repository::{
        PassportJob, PassportJobInsert, PassportJobPatch, PassportJobStatus,
        PassportWebhookRepositoryError, PostgresPassportRepository,
    },
    passport_signer::{
        ManagedProfileSigner, PassportSigner, RemoteSigner, SignedMaterial, SignerError,
    },
};

#[derive(Clone)]
pub struct PassportHttpService {
    keyring: PassportTenantKeyring,
    repository: PostgresPassportRepository,
    cipher: ArtifactAvailability,
    signer: Option<PassportSigner>,
    bureau: Option<BureauClient>,
    webhook_secret: Option<Vec<u8>>,
}

#[derive(Clone)]
enum ArtifactAvailability {
    Missing,
    Invalid,
    Ready(PassportArtifactCipher),
}

#[derive(Debug, thiserror::Error)]
pub enum PassportStartupError {
    #[error("{0} is required for native passport HTTP")]
    Missing(&'static str),
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error(transparent)]
    Bureau(#[from] BureauError),
}

impl PassportHttpService {
    pub fn from_config(
        config: &IssuanceServiceConfig,
        pool: sqlx::PgPool,
    ) -> Result<Option<Self>, PassportStartupError> {
        let native = &config.passport_native;
        if !native.enabled {
            return Ok(None);
        }
        let keyring = config
            .passport_tenant_keys
            .clone()
            .ok_or(PassportStartupError::Missing("PASSPORT_TENANT_API_KEYS"))?;
        let cipher = match native.artifact_key.as_deref() {
            None => ArtifactAvailability::Missing,
            Some(key) => match PassportArtifactCipher::from_key(key) {
                Ok(cipher) => ArtifactAvailability::Ready(cipher),
                Err(PassportArtifactError::InvalidKey) => ArtifactAvailability::Invalid,
                Err(PassportArtifactError::InvalidArtifact) => {
                    unreachable!("key parsing cannot decrypt")
                }
            },
        };
        let signer = if native.managed_issuer_signing_enabled {
            Some(PassportSigner::Managed(Box::new(
                ManagedProfileSigner::new(
                    config.signing_keys_internal_url.clone(),
                    config.signing_keys_internal_api_key.as_deref(),
                )?,
            )))
        } else if let Some(url) = native.signer_url.as_deref() {
            Some(PassportSigner::Remote(RemoteSigner::new(
                url,
                native.signer_api_key.as_deref().unwrap_or_default(),
            )?))
        } else if native.self_signed_test_enabled {
            #[cfg(feature = "passport-self-signed-test")]
            {
                Some(PassportSigner::SelfSignedTest)
            }
            #[cfg(not(feature = "passport-self-signed-test"))]
            {
                return Err(PassportStartupError::Signer(
                    SignerError::TestModeUnavailable,
                ));
            }
        } else {
            None
        };
        let bureau = native
            .bureau_url
            .as_deref()
            .map(|url| {
                BureauClient::new(
                    url,
                    native.bureau_api_key.as_deref().unwrap_or_default(),
                    native.bureau_webhook_secret.as_deref(),
                )
            })
            .transpose()?;
        let mut service = Self::with_artifact_availability(
            keyring,
            PostgresPassportRepository::new(pool),
            cipher,
            signer,
            bureau,
        );
        // Inbound callbacks from already-submitted jobs remain verifiable even
        // when outbound bureau submission is not configured.
        service.webhook_secret = native
            .bureau_webhook_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .map(|secret| secret.as_bytes().to_vec());
        Ok(Some(service))
    }

    #[must_use]
    pub fn new(
        keyring: PassportTenantKeyring,
        repository: PostgresPassportRepository,
        cipher: Option<PassportArtifactCipher>,
        signer: Option<PassportSigner>,
        bureau: Option<BureauClient>,
    ) -> Self {
        Self::with_artifact_availability(
            keyring,
            repository,
            cipher.map_or(ArtifactAvailability::Missing, ArtifactAvailability::Ready),
            signer,
            bureau,
        )
    }

    fn with_artifact_availability(
        keyring: PassportTenantKeyring,
        repository: PostgresPassportRepository,
        cipher: ArtifactAvailability,
        signer: Option<PassportSigner>,
        bureau: Option<BureauClient>,
    ) -> Self {
        let webhook_secret = bureau
            .as_ref()
            .and_then(BureauClient::webhook_secret)
            .map(<[u8]>::to_vec);
        Self {
            keyring,
            repository,
            cipher,
            signer,
            bureau,
            webhook_secret,
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

    fn cipher(&self) -> Result<&PassportArtifactCipher, PassportHttpError> {
        match &self.cipher {
            ArtifactAvailability::Ready(cipher) => Ok(cipher),
            ArtifactAvailability::Missing => Err(PassportHttpError::MissingArtifactKey),
            ArtifactAvailability::Invalid => Err(PassportHttpError::InvalidArtifactKey),
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

    fn decrypt(
        &self,
        job: &PassportJob,
    ) -> Result<crate::passport_artifact::PassportSensitiveArtifact, PassportHttpError> {
        self.cipher()?
            .decrypt(&job.secure_artifact_ciphertext)
            .map_err(|_| PassportHttpError::InvalidArtifact)
    }

    async fn sign(
        &self,
        job: &PassportJob,
    ) -> Result<
        (
            crate::passport_artifact::PassportSensitiveArtifact,
            SignedMaterial,
        ),
        PassportHttpError,
    > {
        let artifact = self.decrypt(job)?;
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
        Ok((artifact, signed))
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
    #[error("Organization context does not match requested organization")]
    OrganizationMismatch,
    #[error("{0}")]
    InvalidRequest(PassportRequestError),
    #[error("Physical document application not found")]
    ApplicationNotFound,
    #[error("Physical document job not found")]
    WebhookJobNotFound,
    #[error("PHYSICAL_DOCUMENT_ARTIFACT_KEY is required for encrypted document artifacts")]
    MissingArtifactKey,
    #[error("PHYSICAL_DOCUMENT_ARTIFACT_KEY is invalid")]
    InvalidArtifactKey,
    #[error("Secure physical document artifact cannot be decrypted")]
    InvalidArtifact,
    #[error("{0}")]
    Signer(SignerError),
    #[error("Personalization bureau not configured. Set PERSONALIZATION_BUREAU_URL environment variable.")]
    MissingBureau,
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
            ) => StatusCode::UNAUTHORIZED,
            Self::OrganizationMismatch => StatusCode::FORBIDDEN,
            Self::InvalidRequest(_)
            | Self::MissingDataGroups
            | Self::Signer(SignerError::MissingIssuerDid) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ApplicationNotFound | Self::WebhookJobNotFound => StatusCode::NOT_FOUND,
            Self::MissingArtifactKey
            | Self::InvalidArtifactKey
            | Self::Signer(SignerError::NotConfigured)
            | Self::Signer(SignerError::ManagedUnavailable)
            | Self::MissingBureau => StatusCode::SERVICE_UNAVAILABLE,
            Self::Signer(SignerError::InvalidManagedMaterial) => StatusCode::BAD_GATEWAY,
            Self::Signer(SignerError::UntrustedDsc)
            | Self::QualityNotReady
            | Self::ActivationNotReady
            | Self::ConcurrentChange => StatusCode::CONFLICT,
            Self::Bureau(BureauError::InvalidWebhookSignature) => StatusCode::UNAUTHORIZED,
            Self::Bureau(BureauError::InvalidWebhookEvent) => StatusCode::UNPROCESSABLE_ENTITY,
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
            "/v1/passport/applications/{application_id}/submit-personalization",
            post(submit_personalization),
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
        ArtifactAvailability::Missing => blockers
            .push("Configure PHYSICAL_DOCUMENT_ARTIFACT_KEY for encrypted sensitive artifacts."),
        ArtifactAvailability::Invalid => blockers
            .push("PHYSICAL_DOCUMENT_ARTIFACT_KEY is invalid for encrypted sensitive artifacts."),
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
        .encrypt(&request.sensitive_artifact())
        .map_err(|_| PassportHttpError::InvalidArtifact)?;
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
    let groups = service
        .decrypt(&job)?
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
    let job = service.job(&principal, &application_id).await?;
    let (_, signed) = service.sign(&job).await?;
    let sod = decode_python_validated_base64(&signed.sod_der_base64)
        .map_err(|_| PassportHttpError::Signer(SignerError::IncompleteMaterial))?;
    let hash = hex::encode(Sha256::digest(sod));
    let mut patch = PassportJobPatch::new(PassportJobStatus::SodSigned);
    patch.sod_sha256 = Some(Some(hash.clone()));
    let updated = service.update(&principal, &job, &patch).await?;
    let mut response = safe(&updated);
    response["sod_sha256"] = Value::String(hash);
    Ok(Json(response))
}

async fn submit_personalization(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    let job = service.job(&principal, &application_id).await?;
    let (artifact, signed) = service.sign(&job).await?;
    let document_type: DocumentType =
        serde_json::from_value(Value::String(job.document_type.clone()))
            .map_err(|_| PassportHttpError::InvalidDocumentType)?;
    let outcome = service
        .bureau()?
        .submit(&PersonalizationJob {
            id: job.id.clone(),
            application_id: job.application_id.clone(),
            organization_id: job.organization_id.clone(),
            country_code: job.country_code.clone(),
            document_type,
            data_groups: artifact
                .numbered_data_groups()
                .map_err(|_| PassportHttpError::InvalidArtifact)?,
            sod_der_base64: signed.sod_der_base64,
            dsc_cert_pem: signed.dsc_cert_pem,
            mrz_line_1: artifact.mrz.get("line_1").cloned().unwrap_or_default(),
            mrz_line_2: artifact.mrz.get("line_2").cloned().unwrap_or_default(),
            bureau_job_id: None,
            status: ProductionStatus::Queued,
            tracking_number: None,
            error_message: None,
            submitted_at: Utc::now(),
            updated_at: Utc::now(),
            completed_at: None,
        })
        .await
        .map_err(PassportHttpError::Bureau)?;
    let mut patch = PassportJobPatch::new(status_from_bureau(outcome.status));
    patch.bureau_job_id = Some(outcome.bureau_job_id);
    patch.tracking_number = Some(outcome.tracking_number);
    patch.error_code = Some(
        (outcome.status == ProductionStatus::Failed).then(|| "BUREAU_SUBMISSION_FAILED".to_owned()),
    );
    patch.error_message = Some(outcome.error_message);
    patch.submitted_at = Some(Utc::now());
    let updated = service.update(&principal, &job, &patch).await?;
    Ok(Json(safe(&updated)))
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
    let outcome = service
        .bureau()?
        .poll(bureau_job_id)
        .await
        .map_err(PassportHttpError::Bureau)?;
    let mut patch = PassportJobPatch::new(status_from_bureau(outcome.status));
    patch.tracking_number = Some(
        outcome
            .tracking_number
            .filter(|number| !number.is_empty())
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
    patch.secure_artifact_ciphertext = Some(service.cipher()?.encrypted_scrubbed_artifact());
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
    let event = parse_verified_webhook(service.webhook_secret.as_deref(), &body, signature)
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
    async fn signed_webhook_verification_does_not_require_outbound_bureau_url() {
        use hmac::Mac;

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
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET".to_owned(),
                "webhook-secret".to_owned(),
            ),
        ])
        .unwrap();
        let service = PassportHttpService::from_config(&config, pool)
            .unwrap()
            .unwrap();
        assert!(service.bureau.is_none());
        assert!(service.webhook_secret.is_some());
        let payload = br#"{"bureau_job_id":"synthetic","status":"SHIPPED"}"#;
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(b"webhook-secret").unwrap();
        mac.update(payload);
        let signature = hex::encode(mac.finalize().into_bytes());
        let verified =
            parse_verified_webhook(service.webhook_secret.as_deref(), payload, &signature).unwrap();
        assert_eq!(verified.bureau_job_id(), "synthetic");
        let response = router(service)
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
    async fn startup_is_default_off_and_reports_invalid_key_or_rejects_unsafe_urls() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let disabled = IssuanceServiceConfig::from_values(Vec::new()).unwrap();
        assert!(PassportHttpService::from_config(&disabled, pool.clone())
            .unwrap()
            .is_none());

        let fernet_key = fernet::Fernet::generate_key();
        let values = |key: &str, signer_url: &str, bureau_url: &str| {
            vec![
                ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
                (
                    "PASSPORT_TENANT_API_KEYS".to_owned(),
                    r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
                ),
                ("PHYSICAL_DOCUMENT_ARTIFACT_KEY".to_owned(), key.to_owned()),
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
                (
                    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET".to_owned(),
                    "webhook-secret".to_owned(),
                ),
            ]
        };
        let valid = IssuanceServiceConfig::from_values(values(
            &fernet_key,
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
        let bad_key = IssuanceServiceConfig::from_values(values(
            "invalid-secret-artifact-key",
            "https://signer.example.test",
            "https://bureau.example.test",
        ))
        .unwrap();
        let bad_key = PassportHttpService::from_config(&bad_key, pool.clone())
            .unwrap()
            .unwrap();
        let bad_key_router = router(bad_key);
        let response = bad_key_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/passport/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["encrypted_artifact_store"], false);
        assert!(body["blockers"]
            .as_array()
            .unwrap()
            .contains(&expected["invalid_artifact_key"]["capability_blocker"]));
        let response = bad_key_router
            .oneshot(authenticated_application_request())
            .await
            .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            expected["invalid_artifact_key"]["authenticated_application_create"]["status"]
                .as_u64()
                .unwrap()
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["detail"],
            expected["invalid_artifact_key"]["authenticated_application_create"]["detail"]
        );
        let bad_signer = IssuanceServiceConfig::from_values(values(
            &fernet_key,
            "https://user:password@signer.example.test",
            "https://bureau.example.test",
        ))
        .unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&bad_signer, pool.clone()).err(),
            Some(PassportStartupError::Signer(SignerError::InvalidUrl))
        ));
        let bad_bureau = IssuanceServiceConfig::from_values(values(
            &fernet_key,
            "https://signer.example.test",
            "https://bureau.example.test?token=secret",
        ))
        .unwrap();
        assert!(matches!(
            PassportHttpService::from_config(&bad_bureau, pool).err(),
            Some(PassportStartupError::Bureau(BureauError::InvalidUrl))
        ));
    }

    #[cfg(feature = "passport-self-signed-test")]
    #[tokio::test]
    async fn explicit_test_signer_is_capable_and_remote_url_takes_precedence() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:5432/unused")
            .unwrap();
        let mut values = vec![
            ("PASSPORT_NATIVE_HTTP_ENABLED".to_owned(), "true".to_owned()),
            (
                "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED".to_owned(),
                "true".to_owned(),
            ),
            (
                "PASSPORT_TENANT_API_KEYS".to_owned(),
                r#"{"org-1":"passport-tenant-test-key-00000000000001"}"#.to_owned(),
            ),
            (
                "PHYSICAL_DOCUMENT_ARTIFACT_KEY".to_owned(),
                fernet::Fernet::generate_key(),
            ),
            (
                "PERSONALIZATION_BUREAU_URL".to_owned(),
                "https://bureau.example.test".to_owned(),
            ),
        ];
        let local_config = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        let local = PassportHttpService::from_config(&local_config, pool.clone())
            .unwrap()
            .unwrap();
        assert_eq!(local.signer.as_ref().unwrap().mode(), "SELF_SIGNED_TEST");
        let response = router(local)
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
        assert_eq!(body["signer"]["mode"], "SELF_SIGNED_TEST");
        assert_eq!(body["supported"], true);

        values.push((
            "ICAO_DOCUMENT_SIGNER_URL".to_owned(),
            "https://signer.example.test".to_owned(),
        ));
        let remote_config = IssuanceServiceConfig::from_values(values).unwrap();
        let remote = PassportHttpService::from_config(&remote_config, pool)
            .unwrap()
            .unwrap();
        assert_eq!(remote.signer.as_ref().unwrap().mode(), "REMOTE");
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
