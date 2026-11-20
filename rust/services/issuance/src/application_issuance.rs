//! Provider-neutral application issuance primitives and required issuer validation.
use crate::credential::{
    remote_credential_format, CredentialIssuanceError, CredentialTransaction, IssuerContext,
    IssuerContextResolver,
};
use crate::internal_application_diagnostics::InternalApplicationDiagnosticCategory;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde_json::Value;
use std::fmt;
use thiserror::Error;
const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationApprovalError {
    #[error("Application approval readiness changed")]
    ReadinessDrift,
    #[error("Application approval is temporarily unavailable")]
    Unavailable,
}

pub trait ApplicationClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemApplicationClock;

impl ApplicationClock for SystemApplicationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalSeed {
    pub transaction_id: String,
    pub pre_authorized_code: String,
}

impl fmt::Debug for ApprovalSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalSeed")
            .field("transaction_id", &self.transaction_id)
            .field("pre_authorized_code", &REDACTED)
            .finish()
    }
}

pub trait ApprovalSeedGenerator: Send + Sync {
    fn generate(&self) -> ApprovalSeed;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureApprovalSeedGenerator;

impl ApprovalSeedGenerator for SecureApprovalSeedGenerator {
    fn generate(&self) -> ApprovalSeed {
        let mut capability = [0_u8; 32];
        rand::rng().fill_bytes(&mut capability);
        ApprovalSeed {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            pre_authorized_code: URL_SAFE_NO_PAD.encode(capability),
        }
    }
}

pub(crate) async fn resolve_and_attach_required_issuer(
    issuer_resolver: &dyn IssuerContextResolver,
    transaction: &mut CredentialTransaction,
) -> Result<(), ApplicationApprovalError> {
    let remote_format = remote_credential_format(&transaction.credential_payload_format)
        .map_err(|_| ApplicationApprovalError::ReadinessDrift)?;
    let issuer = issuer_resolver
        .resolve(transaction, &remote_format, true)
        .await
        .map_err(approval_issuer_error)?;
    if !required_kms_issuer_context(&issuer) {
        return Err(ApplicationApprovalError::ReadinessDrift);
    }
    attach_issuer_context(transaction, &issuer);
    if transaction.issuer_profile_id.as_deref() != Some(issuer.issuer_profile_id.as_str())
        || transaction.issuer_did.as_deref() != Some(issuer.issuer_did.as_str())
        || transaction.issuer_algorithm.as_deref() != Some(issuer.algorithm.as_str())
        || transaction.signing_service_id.as_deref() != Some(issuer.signing_service_id.as_str())
    {
        return Err(ApplicationApprovalError::ReadinessDrift);
    }
    Ok(())
}

pub(crate) const fn issuer_diagnostic_category(
    error: &ApplicationApprovalError,
) -> InternalApplicationDiagnosticCategory {
    match error {
        ApplicationApprovalError::Unavailable => {
            InternalApplicationDiagnosticCategory::DependencyUnavailable
        }
        ApplicationApprovalError::ReadinessDrift => {
            InternalApplicationDiagnosticCategory::IssuerContextInvalid
        }
    }
}

pub(crate) fn required_kms_issuer_context(issuer: &IssuerContext) -> bool {
    let raw = issuer.raw_context.as_object();
    let profile = raw
        .and_then(|value| value.get("issuer_profile"))
        .and_then(Value::as_object);
    let signing_key_reference = raw
        .and_then(|value| value.get("signing_key_reference"))
        .or_else(|| profile.and_then(|value| value.get("signing_key_reference")));
    let profile_id = first_text(&[
        raw.and_then(|value| value.get("issuer_profile_id")),
        profile.and_then(|value| value.get("id")),
    ]);
    let issuer_did = first_text(&[
        raw.and_then(|value| value.get("issuer_did")),
        profile.and_then(|value| value.get("issuer_did")),
    ]);
    let algorithm = first_text(&[
        raw.and_then(|value| value.get("algorithm")),
        profile.and_then(|value| value.get("algorithm")),
    ]);
    let signing_service_id = first_text(&[
        raw.and_then(|value| value.get("signing_service_id")),
        profile.and_then(|value| value.get("signing_service_id")),
    ]);
    let verification_method = first_text(&[
        raw.and_then(|value| value.get("verification_method_id")),
        profile.and_then(|value| value.get("verification_method_id")),
    ]);
    profile.is_none_or(|profile| {
        trimmed_json_text(profile.get("status")).eq_ignore_ascii_case("active")
    }) && profile_id == issuer.issuer_profile_id
        && issuer_did == issuer.issuer_did
        && algorithm == issuer.algorithm
        && signing_service_id == issuer.signing_service_id
        && issuer.verification_method_id.as_deref() == Some(verification_method.as_str())
        && !trimmed_json_text(signing_key_reference).is_empty()
}

pub(crate) fn first_text(values: &[Option<&Value>]) -> String {
    values
        .iter()
        .map(|value| trimmed_json_text(*value))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

pub(crate) fn attach_issuer_context(
    transaction: &mut CredentialTransaction,
    issuer: &IssuerContext,
) {
    transaction.issuer_profile_id = Some(issuer.issuer_profile_id.clone());
    transaction.issuer_mode = "org_managed".to_owned();
    transaction.issuer_did = Some(issuer.issuer_did.clone());
    transaction.issuer_algorithm = Some(issuer.algorithm.clone());
    transaction.signing_service_id = Some(issuer.signing_service_id.clone());
}

pub(crate) fn approval_issuer_error(error: CredentialIssuanceError) -> ApplicationApprovalError {
    match error {
        CredentialIssuanceError::SigningResponse(cause) if cause.is_signing() => {
            ApplicationApprovalError::Unavailable
        }
        CredentialIssuanceError::RepositoryUnavailable
        | CredentialIssuanceError::SigningUnavailable(_)
        | CredentialIssuanceError::LifecycleUnavailable(_) => ApplicationApprovalError::Unavailable,
        _ => ApplicationApprovalError::ReadinessDrift,
    }
}

pub(crate) fn trimmed_json_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').trim().to_owned(),
    }
}
