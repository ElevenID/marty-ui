//! Renewal admission reuses the shared initiation and delivery graph.
//!
//! The frozen Python oracle is retained. RENEWAL-001 deliberately binds trusted
//! links before delivery; RENEWAL-002 uses the existing native pending projection.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Datelike, Duration, SecondsFormat, Timelike, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    credential::CredentialTransaction,
    initiation::{InitiationClock, InitiationRenewalContext, InitiationRequest},
    initiation_http::{InitiationHttpError, InitiationHttpService},
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalSource {
    pub id: String,
    pub organization_id: String,
    pub transaction_id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub subject_did: Option<String>,
    pub status: String,
    pub renewed_to_credential_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RenewalRepositoryError {
    #[error("Renewal repository is unavailable.")]
    Unavailable,
    #[error("Renewal transaction was not persisted.")]
    ReservationMissing,
    #[error("idempotency key was already used for a different issuance request")]
    BindingConflict,
}

#[async_trait]
pub trait RenewalRepository: Send + Sync {
    async fn source(&self, id: &str) -> Result<Option<RenewalSource>, RenewalRepositoryError>;

    async fn source_transaction(
        &self,
        source: &RenewalSource,
    ) -> Result<Option<CredentialTransaction>, RenewalRepositoryError>;

    /// Atomically attach a historical unlinked reservation or verify the exact
    /// existing binding. Never overwrite a different source/application link.
    async fn bind_reservation(
        &self,
        transaction: &CredentialTransaction,
        source: &RenewalSource,
        application_id: Option<&str>,
    ) -> Result<CredentialTransaction, RenewalRepositoryError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialRenewalOfferResponse {
    pub source_credential_id: String,
    pub transaction_id: String,
    pub credential_offer_uri: String,
    pub credential_offer_uris: BTreeMap<String, String>,
    pub credential_offer_labels: BTreeMap<String, String>,
    pub expires_at: String,
}

#[derive(Clone)]
pub struct CredentialRenewalService {
    repository: Arc<dyn RenewalRepository>,
    initiation: InitiationHttpService,
    security: ManagementSecurity,
    clock: Arc<dyn InitiationClock>,
}

impl std::fmt::Debug for CredentialRenewalService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRenewalService")
            .finish_non_exhaustive()
    }
}

impl CredentialRenewalService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn RenewalRepository>,
        initiation: InitiationHttpService,
        management_api_key: Option<&str>,
        clock: Arc<dyn InitiationClock>,
    ) -> Self {
        Self {
            repository,
            initiation,
            security: ManagementSecurity::new(management_api_key),
            clock,
        }
    }

    pub async fn renew(
        &self,
        headers: &HeaderMap,
        credential_id: &str,
    ) -> Result<CredentialRenewalOfferResponse, RenewalError> {
        self.security.authorize(header(headers, "X-API-Key"))?;
        let source = self
            .repository
            .source(credential_id)
            .await?
            .ok_or(RenewalError::SourceNotFound)?;
        self.security.require_organization(
            header(headers, "X-Organization-ID"),
            &source.organization_id,
            true,
        )?;
        if source.status != "active" {
            return Err(RenewalError::Inactive);
        }
        if source
            .renewed_to_credential_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(RenewalError::AlreadyRenewed);
        }
        let source_tx = self
            .repository
            .source_transaction(&source)
            .await?
            .ok_or(RenewalError::SourceTransactionMissing)?;
        let request = renewal_request(&source, &source_tx, self.clock.now())?;
        let context = InitiationRenewalContext {
            source_credential_id: source.id.clone(),
            application_id: source_tx.application_id.clone(),
        };
        let mut reservation = self
            .initiation
            .reserve_authorized(headers, &request, Some(&context))
            .await?;
        reservation.transaction = self
            .repository
            .bind_reservation(
                &reservation.transaction,
                &source,
                context.application_id.as_deref(),
            )
            .await?;
        let offer = self
            .initiation
            .project_reserved(reservation, &request)
            .await?;
        Ok(CredentialRenewalOfferResponse {
            source_credential_id: source.id,
            transaction_id: offer.id,
            credential_offer_uri: offer.credential_offer_uri,
            credential_offer_uris: offer.credential_offer_uris,
            credential_offer_labels: offer.credential_offer_labels,
            expires_at: offer.expires_at,
        })
    }
}

fn renewal_request(
    source: &RenewalSource,
    transaction: &CredentialTransaction,
    now: DateTime<Utc>,
) -> Result<InitiationRequest, RenewalError> {
    if transaction.organization_id != source.organization_id
        || transaction.id != source.transaction_id
    {
        return Err(RenewalError::SourceTransactionMissing);
    }
    if !transaction.renewable {
        return Err(RenewalError::NotRenewable);
    }
    let issuer_did = transaction
        .issuer_did
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(RenewalError::IssuerMissing)?;
    let expires = source.expires_at.ok_or(RenewalError::ExpiryMissing)?;
    let eligible = Duration::try_days(transaction.renewal_window_days)
        .and_then(|window| expires.checked_sub_signed(window))
        .filter(|value| (1..=9999).contains(&value.year()))
        .ok_or(RenewalError::EligibilityOutOfRange)?;
    if now < eligible {
        return Err(RenewalError::NotYetAvailable(eligible));
    }
    Ok(InitiationRequest {
        organization_id: source.organization_id.clone(),
        issuer_did: issuer_did.to_owned(),
        credential_template_id: Some(source.credential_template_id.clone()),
        applicant_id: source.applicant_id.clone(),
        subject_did: source.subject_did.clone(),
        delivery_mode: transaction.delivery_mode.clone(),
        claims: Some(transaction.claims.clone()),
        // Preserve the legacy semantic request/hash and claim-resolution path.
        // The trusted application/source links travel through a separate context.
        application_id: None,
        ..InitiationRequest::default()
    })
}

#[derive(Debug, Error)]
pub enum RenewalError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error(transparent)]
    Repository(#[from] RenewalRepositoryError),
    #[error("Issuance initiation failed")]
    Initiation(InitiationHttpError),
    #[error("Issued credential not found")]
    SourceNotFound,
    #[error("Only active credentials can be renewed.")]
    Inactive,
    #[error("Credential has already been renewed.")]
    AlreadyRenewed,
    #[error("Source issuance transaction is unavailable.")]
    SourceTransactionMissing,
    #[error("Credential Template does not allow renewal.")]
    NotRenewable,
    #[error("Source issuance lacks an issuer_did and cannot be renewed safely.")]
    IssuerMissing,
    #[error("Credential has no renewal eligibility date.")]
    ExpiryMissing,
    #[error("Credential is outside its renewal window.")]
    NotYetAvailable(DateTime<Utc>),
    #[error("date value out of range")]
    EligibilityOutOfRange,
}

impl From<InitiationHttpError> for RenewalError {
    fn from(value: InitiationHttpError) -> Self {
        Self::Initiation(value)
    }
}

impl IntoResponse for RenewalError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Security(error) => {
                return crate::http::TransactionReadHttpError::from(error).into_response()
            }
            Self::Initiation(error) => return error.into_response(),
            Self::SourceNotFound => (StatusCode::NOT_FOUND, Value::String(self.to_string())),
            Self::Repository(
                RenewalRepositoryError::Unavailable | RenewalRepositoryError::ReservationMissing,
            ) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Value::String(self.to_string()),
            ),
            Self::EligibilityOutOfRange => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Value::String(self.to_string()),
            ),
            Self::NotYetAvailable(eligible) => (
                StatusCode::CONFLICT,
                json!({
                    "code": "RENEWAL_NOT_YET_AVAILABLE",
                    "message": "Credential is outside its renewal window.",
                    "eligible_at": eligible.to_rfc3339_opts(
                        if eligible.nanosecond() == 0 { SecondsFormat::Secs } else { SecondsFormat::Micros }, false,
                    ),
                }),
            ),
            _ => (StatusCode::CONFLICT, Value::String(self.to_string())),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Candidate owner only: the gateway coverage/selector is deliberately unchanged.
pub fn router(service: CredentialRenewalService) -> Router {
    Router::new()
        .route("/v1/issued-credentials/{credential_id}/renew", post(renew))
        .with_state(service)
}

async fn renew(
    State(service): State<CredentialRenewalService>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CredentialRenewalOfferResponse>, RenewalError> {
    service.renew(&headers, &credential_id).await.map(Json)
}
