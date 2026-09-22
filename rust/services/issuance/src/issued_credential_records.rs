use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mmf_config::numeric_config::PythonConfigInteger;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canvas_award_candidate::python_canonical_json,
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleAuditContext, CredentialManagementError,
        CredentialManagementService,
    },
    management_security::ManagementSecurity,
    python_datetime::isoformat,
    python_value::{python_string, python_truthy},
    transaction_reads::TransactionReadError,
};

const SUBJECT_HASH_EXCLUDED_KEYS: [&str; 12] = [
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
];

#[derive(Clone, Debug, PartialEq)]
pub struct IssuedCredentialProjectionSource {
    pub id: String,
    pub transaction_id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub subject_did: Option<String>,
    pub issuer_did: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub renewed_from_credential_id: Option<String>,
    pub renewed_to_credential_id: Option<String>,
    pub status_list_entries: Vec<Value>,
    pub credential_hash: Option<String>,
    pub status: String,
    pub status_updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transaction: Option<IssuedCredentialTransactionProjection>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IssuedCredentialTransactionProjection {
    pub applicant_id: Option<String>,
    pub application_id: Option<String>,
    pub subject_did: Option<String>,
    pub issuer_did_override: Option<String>,
    pub claims: Value,
    pub credential_type: Option<String>,
    pub credential_payload_format: Option<String>,
    pub renewable: bool,
    pub renewal_window_days: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuedCredentialStatusListEntry {
    pub status_list_id: String,
    pub index: Value,
    pub status_list_uri: Option<String>,
    #[serde(rename = "type")]
    pub entry_type: Option<String>,
    pub status_purpose: Option<String>,
    pub status_list_credential: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PublicCredentialFormat {
    #[serde(rename = "MDOC")]
    Mdoc,
    #[serde(rename = "VDS_NC")]
    VdsNc,
    #[serde(rename = "SD_JWT_VC")]
    SdJwtVc,
    #[serde(rename = "VC_JWT")]
    VcJwt,
    #[serde(rename = "JSON_LD")]
    JsonLd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PublicCredentialStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "SUSPENDED")]
    Suspended,
    #[serde(rename = "REVOKED")]
    Revoked,
    #[serde(rename = "EXPIRED")]
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuedCredentialRecord {
    pub id: String,
    pub organization_id: String,
    pub credential_id: String,
    pub credential_type: String,
    pub credential_format: PublicCredentialFormat,
    pub flow_execution_id: String,
    pub credential_template_id: String,
    pub application_id: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub renewed_from_credential_id: Option<String>,
    pub renewed_to_credential_id: Option<String>,
    pub renewable: bool,
    pub renewal_eligible_at: Option<String>,
    pub can_renew: bool,
    pub subject_id: String,
    pub subject_claims_hash: Option<String>,
    pub issued_at: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub status: PublicCredentialStatus,
    pub status_list_entries: Vec<IssuedCredentialStatusListEntry>,
    pub credential_hash: Option<String>,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub issuer_did: Option<String>,
    pub revoked_by: Option<String>,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Issued-credential repository is unavailable")]
pub struct IssuedCredentialRepositoryError;

#[async_trait]
pub trait IssuedCredentialRecordRepository: Send + Sync {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError>;

    async fn list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError>;
}

pub trait IssuedCredentialClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug)]
pub struct SystemIssuedCredentialClock;

impl IssuedCredentialClock for SystemIssuedCredentialClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IssuedCredentialAdapterError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error("Issued credential not found")]
    NotFound,
    #[error("Issued credential data is temporarily unavailable")]
    RepositoryUnavailable,
    #[error(transparent)]
    Lifecycle(#[from] CredentialManagementError),
}

#[derive(Clone)]
pub struct IssuedCredentialAdapterService {
    repository: Arc<dyn IssuedCredentialRecordRepository>,
    lifecycle: CredentialManagementService,
    security: ManagementSecurity,
    clock: Arc<dyn IssuedCredentialClock>,
}

impl std::fmt::Debug for IssuedCredentialAdapterService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedCredentialAdapterService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl IssuedCredentialAdapterService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn IssuedCredentialRecordRepository>,
        lifecycle: CredentialManagementService,
        management_api_key: Option<&str>,
        clock: Arc<dyn IssuedCredentialClock>,
    ) -> Self {
        Self {
            repository,
            lifecycle,
            security: ManagementSecurity::new(management_api_key),
            clock,
        }
    }

    pub fn preflight(&self, api_key: Option<&str>) -> Result<(), IssuedCredentialAdapterError> {
        self.security.authorize(api_key).map_err(Into::into)
    }

    pub async fn list(
        &self,
        organization_id: Option<&str>,
        status: Option<&str>,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<Vec<IssuedCredentialRecord>, IssuedCredentialAdapterError> {
        self.security.authorize(api_key)?;
        let organization_id =
            organization_id.ok_or(TransactionReadError::OrganizationIdRequired)?;
        self.security
            .require_organization(trusted_organization, organization_id, false)?;
        let now = self.clock.now();
        let mut records = self
            .repository
            .list_by_organization(organization_id)
            .await
            .map_err(|_| IssuedCredentialAdapterError::RepositoryUnavailable)?
            .into_iter()
            .map(|source| project_issued_credential(source, now))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(status) = status.filter(|status| !status.is_empty()) {
            let status = status.to_uppercase();
            records.retain(|record| public_status_name(record.status) == status);
        }
        Ok(records)
    }

    pub async fn get(
        &self,
        credential_id: &str,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<IssuedCredentialRecord, IssuedCredentialAdapterError> {
        self.security.authorize(api_key)?;
        let source = self.load_public(credential_id).await?;
        self.security
            .require_organization(trusted_organization, &source.organization_id, true)?;
        project_issued_credential(source, self.clock.now())
    }

    pub async fn transition(
        &self,
        credential_id: &str,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
        audit: &CredentialLifecycleAuditContext,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<IssuedCredentialRecord, IssuedCredentialAdapterError> {
        self.security.authorize(api_key)?;
        let source = self.load_public(credential_id).await?;
        self.security
            .require_organization(trusted_organization, &source.organization_id, true)?;
        self.lifecycle
            .transition_with_context(credential_id, trusted_organization, action, reason, audit)
            .await?;
        let updated = self.load_public(credential_id).await?;
        project_issued_credential(updated, self.clock.now())
    }

    async fn load_public(
        &self,
        credential_id: &str,
    ) -> Result<IssuedCredentialProjectionSource, IssuedCredentialAdapterError> {
        self.repository
            .get(credential_id)
            .await
            .map_err(|_| IssuedCredentialAdapterError::RepositoryUnavailable)?
            .ok_or(IssuedCredentialAdapterError::NotFound)
    }
}

pub fn project_issued_credential(
    source: IssuedCredentialProjectionSource,
    now: DateTime<Utc>,
) -> Result<IssuedCredentialRecord, IssuedCredentialAdapterError> {
    let transaction = source.transaction.as_ref();
    let subject_id = first_nonempty([
        source.subject_did.as_deref(),
        source.applicant_id.as_deref(),
        transaction.and_then(|value| value.subject_did.as_deref()),
        transaction.and_then(|value| value.applicant_id.as_deref()),
    ])
    .unwrap_or(&source.id)
    .to_owned();
    let status = public_status(&source.status, source.expires_at, now)?;
    let credential_format =
        public_format(transaction.and_then(|value| value.credential_payload_format.as_deref()));
    let renewable = transaction.is_some_and(|value| value.renewable);
    let renewal_eligible = match (transaction, source.expires_at) {
        (Some(transaction), Some(expires_at)) if transaction.renewable => {
            let window = Duration::try_days(transaction.renewal_window_days)
                .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?;
            Some(
                expires_at
                    .checked_sub_signed(window)
                    .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?,
            )
        }
        _ => None,
    };
    let can_renew = renewable
        && renewal_eligible.is_some_and(|eligible| now >= eligible)
        && source.status == "active"
        && source
            .renewed_to_credential_id
            .as_deref()
            .is_none_or(str::is_empty);
    let issued_at = timestamp(source.issued_at);
    let updated_at = timestamp(source.status_updated_at);
    let issuer_did = first_nonempty([
        source.issuer_did.as_deref(),
        transaction.and_then(|value| value.issuer_did_override.as_deref()),
    ])
    .map(str::to_owned);
    let credential_type = transaction
        .and_then(|value| value.credential_type.as_deref())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned();

    Ok(IssuedCredentialRecord {
        id: source.id.clone(),
        organization_id: source.organization_id,
        credential_id: source.id,
        credential_type,
        credential_format,
        flow_execution_id: source.transaction_id,
        credential_template_id: source.credential_template_id,
        application_id: transaction.and_then(|value| value.application_id.clone()),
        revocation_profile_id: source.revocation_profile_id,
        renewed_from_credential_id: source.renewed_from_credential_id,
        renewed_to_credential_id: source.renewed_to_credential_id,
        renewable,
        renewal_eligible_at: renewal_eligible.map(timestamp),
        can_renew,
        subject_id,
        subject_claims_hash: transaction.map(subject_claims_hash).transpose()?,
        issued_at: issued_at.clone(),
        valid_from: Some(issued_at.clone()),
        valid_until: source.expires_at.map(timestamp),
        status,
        status_list_entries: status_list_entries(&source.status_list_entries)?,
        credential_hash: source.credential_hash,
        revoked_at: source.revoked_at.map(timestamp),
        revocation_reason: source.revocation_reason,
        issuer_did,
        revoked_by: None,
        created_at: issued_at,
        updated_at: Some(updated_at),
    })
}

fn public_status(
    stored: &str,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<PublicCredentialStatus, IssuedCredentialAdapterError> {
    match stored {
        "active" if expires_at.is_some_and(|expires_at| expires_at < now) => {
            Ok(PublicCredentialStatus::Expired)
        }
        "active" => Ok(PublicCredentialStatus::Active),
        "suspended" => Ok(PublicCredentialStatus::Suspended),
        "revoked" => Ok(PublicCredentialStatus::Revoked),
        _ => Err(IssuedCredentialAdapterError::RepositoryUnavailable),
    }
}

fn public_status_name(status: PublicCredentialStatus) -> &'static str {
    match status {
        PublicCredentialStatus::Active => "ACTIVE",
        PublicCredentialStatus::Suspended => "SUSPENDED",
        PublicCredentialStatus::Revoked => "REVOKED",
        PublicCredentialStatus::Expired => "EXPIRED",
    }
}

fn public_format(value: Option<&str>) -> PublicCredentialFormat {
    let normalized = value
        .unwrap_or_default()
        .trim()
        .to_lowercase()
        .replace('-', "_");
    match normalized.as_str() {
        "mso_mdoc" | "mdoc" => PublicCredentialFormat::Mdoc,
        "vds_nc" | "vdsnc" => PublicCredentialFormat::VdsNc,
        "json_ld" | "ldp_vc" | "w3c_vcdm_v2_di" => PublicCredentialFormat::JsonLd,
        "jwt_vc" | "jwt_vc_json" | "w3c_vcdm_v2_jwt" | "w3c_vcdm_v2_jwt_vc" => {
            PublicCredentialFormat::VcJwt
        }
        _ => PublicCredentialFormat::SdJwtVc,
    }
}

fn subject_claims_hash(
    transaction: &IssuedCredentialTransactionProjection,
) -> Result<String, IssuedCredentialAdapterError> {
    let claims = transaction
        .claims
        .as_object()
        .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?;
    let clean = claims
        .iter()
        .filter(|(name, _)| !SUBJECT_HASH_EXCLUDED_KEYS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    Ok(hex::encode(Sha256::digest(
        python_canonical_json(&Value::Object(clean)).as_bytes(),
    )))
}

fn status_list_entries(
    entries: &[Value],
) -> Result<Vec<IssuedCredentialStatusListEntry>, IssuedCredentialAdapterError> {
    entries
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|entry| {
            let status_list_id = python_or(
                entry.get("status_list_id"),
                entry.get("revocation_profile_id"),
            )?;
            let index = entry.get("index").filter(|value| !value.is_null())?;
            Some((entry, status_list_id, index))
        })
        .map(|(entry, status_list_id, index)| {
            let status_list_id = python_string(status_list_id)
                .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?;
            Ok(IssuedCredentialStatusListEntry {
                status_list_id,
                index: python_integer(index)?,
                status_list_uri: optional_string(python_or(
                    entry.get("status_list_uri"),
                    entry.get("statusListCredential"),
                ))?,
                entry_type: optional_string(entry.get("type"))?,
                status_purpose: optional_string(python_or(
                    entry.get("status_purpose"),
                    entry.get("statusPurpose"),
                ))?,
                status_list_credential: optional_string(python_or(
                    entry.get("status_list_credential"),
                    entry.get("statusListCredential"),
                ))?,
            })
        })
        .collect()
}

fn python_or<'value>(
    first: Option<&'value Value>,
    second: Option<&'value Value>,
) -> Option<&'value Value> {
    first
        .filter(|value| python_truthy(value))
        .or_else(|| second.filter(|value| python_truthy(value)))
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, IssuedCredentialAdapterError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(IssuedCredentialAdapterError::RepositoryUnavailable),
    }
}

fn python_integer(value: &Value) -> Result<Value, IssuedCredentialAdapterError> {
    let number = match value {
        Value::Bool(value) => Number::from(u8::from(*value)),
        Value::Number(value) => match value.to_string().parse::<PythonConfigInteger>() {
            Ok(value) => python_config_number(&value)?,
            Err(_) => {
                let value = value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?;
                python_float_integer(value)?
            }
        },
        Value::String(value) => python_decimal_integer(value)?,
        _ => return Err(IssuedCredentialAdapterError::RepositoryUnavailable),
    };
    Ok(Value::Number(number))
}

fn python_decimal_integer(value: &str) -> Result<Number, IssuedCredentialAdapterError> {
    value
        .parse::<PythonConfigInteger>()
        .map_err(|_| IssuedCredentialAdapterError::RepositoryUnavailable)
        .and_then(|value| python_config_number(&value))
}

fn python_config_number(
    value: &PythonConfigInteger,
) -> Result<Number, IssuedCredentialAdapterError> {
    value
        .as_decimal()
        .parse::<Number>()
        .map_err(|_| IssuedCredentialAdapterError::RepositoryUnavailable)
}

fn python_float_integer(value: f64) -> Result<Number, IssuedCredentialAdapterError> {
    BigInt::from_f64(value.trunc())
        .ok_or(IssuedCredentialAdapterError::RepositoryUnavailable)?
        .to_string()
        .parse::<Number>()
        .map_err(|_| IssuedCredentialAdapterError::RepositoryUnavailable)
}

fn first_nonempty<const N: usize>(values: [Option<&str>; N]) -> Option<&str> {
    values.into_iter().flatten().find(|value| !value.is_empty())
}

fn timestamp(value: DateTime<Utc>) -> String {
    isoformat(value)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn source(format: &str) -> IssuedCredentialProjectionSource {
        IssuedCredentialProjectionSource {
            id: "credential-1".to_owned(),
            transaction_id: "transaction-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: "template-1".to_owned(),
            applicant_id: Some("credential-applicant".to_owned()),
            subject_did: None,
            issuer_did: None,
            revocation_profile_id: Some("profile-1".to_owned()),
            renewed_from_credential_id: None,
            renewed_to_credential_id: None,
            status_list_entries: vec![json!({
                "revocation_profile_id": "profile-1",
                "index": "42",
                "statusListCredential": "https://issuer.example/status/1",
                "statusPurpose": "revocation",
                "type": "BitstringStatusListEntry"
            })],
            credential_hash: Some("credential-hash".to_owned()),
            status: "active".to_owned(),
            status_updated_at: Utc.with_ymd_and_hms(2026, 9, 20, 8, 0, 0).unwrap(),
            revoked_at: None,
            revocation_reason: None,
            issued_at: Utc.with_ymd_and_hms(2026, 9, 1, 8, 0, 0).unwrap(),
            expires_at: Some(Utc.with_ymd_and_hms(2026, 10, 1, 8, 0, 0).unwrap()),
            transaction: Some(IssuedCredentialTransactionProjection {
                applicant_id: Some("transaction-applicant".to_owned()),
                application_id: Some("application-1".to_owned()),
                subject_did: Some("did:example:transaction".to_owned()),
                issuer_did_override: Some("did:web:issuer.example".to_owned()),
                claims: json!({
                    "name": "José",
                    "nested": {"z": 1, "a": true},
                    "credential_offer_uri": "private",
                    "_vct": "private-type"
                }),
                credential_type: Some("EmployeeCredential".to_owned()),
                credential_payload_format: Some(format.to_owned()),
                renewable: true,
                renewal_window_days: 7,
            }),
        }
    }

    #[test]
    fn projector_preserves_full_public_shape_and_python_hashing() {
        let now = Utc.with_ymd_and_hms(2026, 9, 25, 8, 0, 0).unwrap();
        let record = project_issued_credential(source("vds-nc"), now).expect("record");
        assert_eq!(record.credential_format, PublicCredentialFormat::VdsNc);
        assert_eq!(record.subject_id, "credential-applicant");
        assert_eq!(record.issuer_did.as_deref(), Some("did:web:issuer.example"));
        assert_eq!(record.status, PublicCredentialStatus::Active);
        assert_eq!(
            record.renewal_eligible_at.as_deref(),
            Some("2026-09-24T08:00:00+00:00")
        );
        assert!(record.can_renew);
        assert_eq!(
            record.subject_claims_hash.as_deref(),
            Some("180d30d699a798a7f2a1571daaf513e6b1c76062b36c6b4b4a2b05b253e39e14")
        );
        assert_eq!(record.status_list_entries[0].index, json!(42));
        assert_eq!(
            record.status_list_entries[0].status_list_uri.as_deref(),
            Some("https://issuer.example/status/1")
        );
        assert_eq!(record.revoked_by, None);
        let serialized = serde_json::to_value(record).expect("public JSON");
        assert!(serialized.get("credential_jwt").is_none());
        assert!(serialized.get("claims").is_none());
        assert!(serialized.get("comments").is_none());
        assert!(serialized.get("deliveries").is_none());
    }

    #[test]
    fn expiration_boundary_and_renewal_match_the_python_oracle() {
        let expires = Utc.with_ymd_and_hms(2026, 10, 1, 8, 0, 0).unwrap();
        let at_boundary = project_issued_credential(source("mso_mdoc"), expires).unwrap();
        assert_eq!(at_boundary.status, PublicCredentialStatus::Active);
        let expired =
            project_issued_credential(source("mso_mdoc"), expires + Duration::nanoseconds(1))
                .unwrap();
        assert_eq!(expired.status, PublicCredentialStatus::Expired);
        assert!(expired.can_renew, "stored ACTIVE governs renewal parity");
    }

    #[test]
    fn format_and_subject_fallbacks_are_complete() {
        for (input, expected) in [
            ("mdoc", PublicCredentialFormat::Mdoc),
            ("vdsnc", PublicCredentialFormat::VdsNc),
            ("w3c_vcdm_v2_di", PublicCredentialFormat::JsonLd),
            ("jwt_vc_json", PublicCredentialFormat::VcJwt),
            ("ietf_sd_jwt", PublicCredentialFormat::SdJwtVc),
        ] {
            assert_eq!(
                project_issued_credential(source(input), Utc::now())
                    .unwrap()
                    .credential_format,
                expected
            );
        }

        let mut value = source("ietf_sd_jwt");
        value.applicant_id = None;
        assert_eq!(
            project_issued_credential(value.clone(), Utc::now())
                .unwrap()
                .subject_id,
            "did:example:transaction"
        );
        value.transaction = None;
        assert_eq!(
            project_issued_credential(value, Utc::now())
                .unwrap()
                .subject_id,
            "credential-1"
        );

        let mut value = source("ietf_sd_jwt");
        value.status_list_entries = vec![json!({
            "status_list_id": [true, null, "x"],
            "index": 1
        })];
        assert_eq!(
            project_issued_credential(value, Utc::now())
                .unwrap()
                .status_list_entries[0]
                .status_list_id,
            "[True, None, 'x']",
            "status-list identifiers retain Python str() compatibility"
        );
    }

    #[test]
    fn status_list_entries_preserve_python_null_and_decimal_compatibility() {
        let mut value = source("ietf_sd_jwt");
        value.status_list_entries = vec![
            json!({"status_list_id": "skip-null-index", "index": null}),
            json!({
                "status_list_id": "status-list-10",
                "index": "\u{2003}1_0\u{2003}",
                "type": null
            }),
            json!({"status_list_id": "arabic-indic", "index": "١_٢"}),
            json!({"status_list_id": "fullwidth", "index": "１２"}),
            json!({"status_list_id": "mixed", "index": "1_٢"}),
            json!({
                "status_list_id": "unbounded",
                "index": "184467440737095516160"
            }),
        ];
        let record = project_issued_credential(value, Utc::now()).unwrap();
        assert_eq!(record.status_list_entries.len(), 5);
        assert_eq!(record.status_list_entries[0].index, json!(10));
        assert_eq!(record.status_list_entries[0].entry_type, None);
        assert_eq!(record.status_list_entries[1].index, json!(12));
        assert_eq!(record.status_list_entries[2].index, json!(12));
        assert_eq!(record.status_list_entries[3].index, json!(12));
        assert_eq!(
            record.status_list_entries[4].index.to_string(),
            "184467440737095516160"
        );

        for invalid in ["²", "Ⅻ"] {
            assert_eq!(
                python_integer(&Value::String(invalid.to_owned())),
                Err(IssuedCredentialAdapterError::RepositoryUnavailable),
                "non-decimal Unicode numeric characters must remain invalid"
            );
        }
    }

    #[test]
    fn status_list_float_indices_match_unbounded_python_int_conversion() {
        let positive = python_integer(&json!(1e100)).unwrap();
        let negative = python_integer(&json!(-1e100)).unwrap();
        assert_eq!(
            positive.to_string(),
            "10000000000000000159028911097599180468360808563945281389781327557747838772170381060813469985856815104"
        );
        assert_eq!(
            negative.to_string(),
            "-10000000000000000159028911097599180468360808563945281389781327557747838772170381060813469985856815104"
        );
        assert_eq!(python_integer(&json!(123.875)).unwrap(), json!(123));
        for invalid in ["NaN", "Infinity", "-Infinity"] {
            assert_eq!(
                python_integer(&Value::String(invalid.to_owned())),
                Err(IssuedCredentialAdapterError::RepositoryUnavailable)
            );
        }
    }

    #[test]
    fn every_projected_timestamp_preserves_python_microsecond_precision() {
        let mut value = source("ietf_sd_jwt");
        value.issued_at = DateTime::parse_from_rfc3339("2026-09-01T08:00:00.120000+00:00")
            .unwrap()
            .to_utc();
        value.status_updated_at = DateTime::parse_from_rfc3339("2026-09-20T08:00:00.000001+00:00")
            .unwrap()
            .to_utc();
        value.expires_at = Some(
            DateTime::parse_from_rfc3339("2026-10-01T08:00:00.120000+00:00")
                .unwrap()
                .to_utc(),
        );
        value.revoked_at = Some(
            DateTime::parse_from_rfc3339("2026-09-20T08:00:00.120000+00:00")
                .unwrap()
                .to_utc(),
        );
        let record = project_issued_credential(
            value,
            DateTime::parse_from_rfc3339("2026-09-25T08:00:00+00:00")
                .unwrap()
                .to_utc(),
        )
        .unwrap();

        assert_eq!(record.issued_at, "2026-09-01T08:00:00.120000+00:00");
        assert_eq!(
            record.valid_from.as_deref(),
            Some("2026-09-01T08:00:00.120000+00:00")
        );
        assert_eq!(
            record.valid_until.as_deref(),
            Some("2026-10-01T08:00:00.120000+00:00")
        );
        assert_eq!(
            record.renewal_eligible_at.as_deref(),
            Some("2026-09-24T08:00:00.120000+00:00")
        );
        assert_eq!(
            record.revoked_at.as_deref(),
            Some("2026-09-20T08:00:00.120000+00:00")
        );
        assert_eq!(record.created_at, "2026-09-01T08:00:00.120000+00:00");
        assert_eq!(
            record.updated_at.as_deref(),
            Some("2026-09-20T08:00:00.000001+00:00")
        );
    }
}
