//! CSCA certificate lifecycle state with provider-managed private-key custody.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use marty_crypto::certificate::{
    get_certificate_info, load_certificate_pem, verify_certificate_signature,
};
use marty_crypto::jwk::certificate_pem_to_jwk;
use redis::{aio::ConnectionManager, AsyncCommands};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_SAFE_REDIS_REVISION: u64 = 9_007_199_254_740_991;
const CSCA_LIFECYCLE_SCHEMA_VERSION: u32 = 3;
const MAX_OUTBOX_EVENTS: usize = 10_000;
const MAX_OUTBOX_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CscaLifecycleError {
    #[error("{0}")]
    Invalid(String),
    #[error("CSCA certificate '{0}' already exists")]
    Conflict(String),
    #[error("CSCA certificate '{0}' was not found")]
    NotFound(String),
    #[error("CSCA outbox event '{0}' was not found")]
    OutboxEventNotFound(String),
    #[error("CSCA certificate '{0}' is revoked")]
    Revoked(String),
    #[error("CSCA certificate '{0}' is expired")]
    Expired(String),
    #[error("CSCA certificate '{0}' is not yet valid")]
    NotYetValid(String),
    #[error("CSCA lifecycle state changed concurrently; retry the operation")]
    ConcurrentModification,
    #[error("CSCA lifecycle storage is unavailable: {0}")]
    Storage(String),
    #[error("stored CSCA lifecycle document is malformed: {0}")]
    Corrupt(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CscaCertificateStatus {
    Valid,
    NotYetValid,
    Expired,
    Revoked,
}

impl CscaCertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportCscaCertificateRequest {
    pub cert_pem: String,
    #[serde(default)]
    pub cert_chain_pem: String,
    pub key_reference: String,
    pub expected_public_jwk: Value,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeCscaCertificateRequest {
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RenewCscaCertificateRequest {
    pub replacement_certificate_id: String,
    pub cert_pem: String,
    #[serde(default)]
    pub cert_chain_pem: String,
    pub key_reference: String,
    pub expected_public_jwk: Value,
    #[serde(default)]
    pub metadata: Value,
}

impl RenewCscaCertificateRequest {
    pub fn into_import(self) -> ImportCscaCertificateRequest {
        ImportCscaCertificateRequest {
            cert_pem: self.cert_pem,
            cert_chain_pem: self.cert_chain_pem,
            key_reference: self.key_reference,
            expected_public_jwk: self.expected_public_jwk,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpiringCscaCertificatesRequest {
    #[serde(default)]
    pub days_threshold: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListCscaOutboxQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CscaOutboxEvent {
    pub event_id: String,
    pub topic: String,
    pub key: String,
    pub payload: Value,
    pub created_at: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CscaCertificateDataResponse {
    pub certificate_id: String,
    pub certificate_data: String,
    pub status: CscaCertificateStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CscaCertificateRecord {
    pub certificate_id: String,
    pub subject: String,
    pub issuer: String,
    pub cert_pem: String,
    pub cert_chain_pem: String,
    pub key_reference: String,
    pub public_jwk: Value,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub renewed_from: Option<String>,
    pub renewed_to: Option<String>,
    pub metadata: Value,
}

impl CscaCertificateRecord {
    pub fn status_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<CscaCertificateStatus, CscaLifecycleError> {
        if self.revoked_at.is_some() {
            return Ok(CscaCertificateStatus::Revoked);
        }
        let not_before = parse_time("not_before", &self.not_before)?;
        if not_before > now {
            return Ok(CscaCertificateStatus::NotYetValid);
        }
        let not_after = parse_time("not_after", &self.not_after)?;
        Ok(if not_after <= now {
            CscaCertificateStatus::Expired
        } else {
            CscaCertificateStatus::Valid
        })
    }

    fn view_at(&self, now: DateTime<Utc>) -> Result<CscaCertificateView, CscaLifecycleError> {
        Ok(CscaCertificateView {
            certificate: self.clone(),
            status: self.status_at(now)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CscaCertificateView {
    #[serde(flatten)]
    pub certificate: CscaCertificateRecord,
    pub status: CscaCertificateStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListCscaCertificatesQuery {
    #[serde(default)]
    pub status: Option<CscaCertificateStatus>,
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CscaLifecycleDocument {
    pub schema_version: u32,
    #[serde(default)]
    pub revision: u64,
    pub organization_id: String,
    pub certificates: BTreeMap<String, CscaCertificateRecord>,
    #[serde(default)]
    pub outbox: BTreeMap<String, CscaOutboxEvent>,
    pub updated_at: String,
}

impl CscaLifecycleDocument {
    pub fn empty(organization_id: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            schema_version: CSCA_LIFECYCLE_SCHEMA_VERSION,
            revision: 0,
            organization_id: organization_id.into(),
            certificates: BTreeMap::new(),
            outbox: BTreeMap::new(),
            updated_at: timestamp(now),
        }
    }

    pub fn import(
        &mut self,
        certificate_id: &str,
        request: ImportCscaCertificateRequest,
        now: DateTime<Utc>,
    ) -> Result<CscaCertificateView, CscaLifecycleError> {
        validate_identifier("certificate_id", certificate_id)?;
        if self.certificates.contains_key(certificate_id) {
            return Err(CscaLifecycleError::Conflict(certificate_id.to_string()));
        }
        let record = build_record(certificate_id, request, now, None)?;
        let view = record.view_at(now)?;
        self.prepare_outbox("certificate.issued", certificate_id)?;
        self.certificates.insert(certificate_id.to_string(), record);
        self.enqueue(
            "certificate.issued",
            certificate_id,
            serde_json::json!({
                "organization_id": self.organization_id,
                "certificate_id": certificate_id,
                "subject": view.certificate.subject,
                "not_after": view.certificate.not_after,
            }),
            now,
        )?;
        self.touch(now)?;
        Ok(view)
    }

    pub fn get(
        &self,
        certificate_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CscaCertificateView, CscaLifecycleError> {
        self.record(certificate_id)?.view_at(now)
    }

    pub fn certificate_data(
        &self,
        certificate_id: &str,
        now: DateTime<Utc>,
    ) -> Result<&str, CscaLifecycleError> {
        let record = self.record(certificate_id)?;
        match record.status_at(now)? {
            CscaCertificateStatus::Valid => Ok(&record.cert_pem),
            CscaCertificateStatus::Revoked => {
                Err(CscaLifecycleError::Revoked(certificate_id.to_string()))
            }
            CscaCertificateStatus::Expired => {
                Err(CscaLifecycleError::Expired(certificate_id.to_string()))
            }
            CscaCertificateStatus::NotYetValid => {
                Err(CscaLifecycleError::NotYetValid(certificate_id.to_string()))
            }
        }
    }

    pub fn revoke(
        &mut self,
        certificate_id: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<CscaCertificateView, CscaLifecycleError> {
        if self.record(certificate_id)?.revoked_at.is_some() {
            return self.record(certificate_id)?.view_at(now);
        }
        self.prepare_outbox("certificate.revoked", certificate_id)?;
        let record = self.record_mut(certificate_id)?;
        record.revoked_at = Some(timestamp(now));
        record.revocation_reason = Some(if reason.trim().is_empty() {
            "unspecified".to_string()
        } else {
            reason.trim().to_string()
        });
        let view = record.view_at(now)?;
        self.enqueue(
            "certificate.revoked",
            certificate_id,
            serde_json::json!({
                "organization_id": self.organization_id,
                "certificate_id": certificate_id,
                "reason": view.certificate.revocation_reason,
            }),
            now,
        )?;
        self.touch(now)?;
        Ok(view)
    }

    pub fn renew(
        &mut self,
        certificate_id: &str,
        replacement_id: &str,
        request: ImportCscaCertificateRequest,
        now: DateTime<Utc>,
    ) -> Result<CscaCertificateView, CscaLifecycleError> {
        validate_identifier("replacement_certificate_id", replacement_id)?;
        if certificate_id == replacement_id || self.certificates.contains_key(replacement_id) {
            return Err(CscaLifecycleError::Conflict(replacement_id.to_string()));
        }
        self.record(certificate_id)?;
        let replacement = build_record(
            replacement_id,
            request,
            now,
            Some(certificate_id.to_string()),
        )?;
        let view = replacement.view_at(now)?;
        self.prepare_outbox("certificate.renewed", replacement_id)?;
        let prior = self.record_mut(certificate_id)?;
        prior.revoked_at = Some(timestamp(now));
        prior.revocation_reason = Some("SUPERSEDED".to_string());
        prior.renewed_to = Some(replacement_id.to_string());
        self.certificates
            .insert(replacement_id.to_string(), replacement);
        self.enqueue(
            "certificate.renewed",
            replacement_id,
            serde_json::json!({
                "organization_id": self.organization_id,
                "previous_id": certificate_id,
                "certificate_id": replacement_id,
                "subject": view.certificate.subject,
            }),
            now,
        )?;
        self.touch(now)?;
        Ok(view)
    }

    pub fn pending_outbox(
        &self,
        query: &ListCscaOutboxQuery,
    ) -> Result<Vec<CscaOutboxEvent>, CscaLifecycleError> {
        let limit = query.limit.unwrap_or(100);
        if limit == 0 || limit > MAX_OUTBOX_PAGE_SIZE {
            return Err(CscaLifecycleError::Invalid(format!(
                "limit must be between 1 and {MAX_OUTBOX_PAGE_SIZE}"
            )));
        }
        Ok(self
            .outbox
            .values()
            .filter(|event| event.published_at.is_none())
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn acknowledge_outbox(
        &mut self,
        event_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CscaOutboxEvent, CscaLifecycleError> {
        let event = self
            .outbox
            .get_mut(event_id)
            .ok_or_else(|| CscaLifecycleError::OutboxEventNotFound(event_id.to_string()))?;
        if event.published_at.is_some() {
            return Ok(event.clone());
        }
        event.published_at = Some(timestamp(now));
        let response = event.clone();
        self.touch(now)?;
        Ok(response)
    }

    pub fn list(
        &self,
        query: &ListCscaCertificatesQuery,
        now: DateTime<Utc>,
    ) -> Result<Vec<CscaCertificateView>, CscaLifecycleError> {
        let subject = query.subject.as_deref().map(str::to_lowercase);
        self.certificates
            .values()
            .filter(|record| {
                subject
                    .as_ref()
                    .is_none_or(|value| record.subject.to_lowercase().contains(value))
            })
            .map(|record| record.view_at(now))
            .filter(|result| {
                result.as_ref().map_or(true, |view| {
                    query.status.is_none_or(|status| view.status == status)
                })
            })
            .collect()
    }

    pub fn expiring(
        &self,
        days_threshold: i64,
        now: DateTime<Utc>,
    ) -> Result<Vec<CscaCertificateView>, CscaLifecycleError> {
        if !(0..=36_500).contains(&days_threshold) {
            return Err(CscaLifecycleError::Invalid(
                "days_threshold must be between 0 and 36500".to_string(),
            ));
        }
        let effective_days = if days_threshold == 0 {
            30
        } else {
            days_threshold
        };
        // The retired service compared `timedelta.days`, which includes the
        // entire final calendar-day bucket. Keep that effective behavior.
        let threshold_exclusive = now + Duration::days(effective_days + 1);
        self.certificates
            .values()
            .filter(|record| record.revoked_at.is_none())
            .filter_map(|record| {
                let expiry = match parse_time("not_after", &record.not_after) {
                    Ok(expiry) => expiry,
                    Err(error) => return Some(Err(error)),
                };
                (expiry >= now && expiry < threshold_exclusive).then(|| record.view_at(now))
            })
            .collect()
    }

    fn record(&self, certificate_id: &str) -> Result<&CscaCertificateRecord, CscaLifecycleError> {
        self.certificates
            .get(certificate_id)
            .ok_or_else(|| CscaLifecycleError::NotFound(certificate_id.to_string()))
    }

    fn record_mut(
        &mut self,
        certificate_id: &str,
    ) -> Result<&mut CscaCertificateRecord, CscaLifecycleError> {
        self.certificates
            .get_mut(certificate_id)
            .ok_or_else(|| CscaLifecycleError::NotFound(certificate_id.to_string()))
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), CscaLifecycleError> {
        if self.revision >= MAX_SAFE_REDIS_REVISION {
            return Err(CscaLifecycleError::Corrupt(
                "revision counter overflowed".to_string(),
            ));
        }
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            CscaLifecycleError::Corrupt("revision counter overflowed".to_string())
        })?;
        self.updated_at = timestamp(now);
        Ok(())
    }

    fn enqueue(
        &mut self,
        topic: &str,
        key: &str,
        payload: Value,
        now: DateTime<Utc>,
    ) -> Result<(), CscaLifecycleError> {
        let next_revision = self.revision.checked_add(1).ok_or_else(|| {
            CscaLifecycleError::Corrupt("revision counter overflowed".to_string())
        })?;
        let event_id = format!("{next_revision:016x}-{topic}-{key}");
        let event = CscaOutboxEvent {
            event_id: event_id.clone(),
            topic: topic.to_string(),
            key: key.to_string(),
            payload,
            created_at: timestamp(now),
            published_at: None,
        };
        if self.outbox.insert(event_id.clone(), event).is_some() {
            return Err(CscaLifecycleError::Corrupt(format!(
                "duplicate outbox event '{event_id}'"
            )));
        }
        Ok(())
    }

    fn prepare_outbox(&mut self, topic: &str, key: &str) -> Result<(), CscaLifecycleError> {
        if self.revision >= MAX_SAFE_REDIS_REVISION {
            return Err(CscaLifecycleError::Corrupt(
                "revision counter overflowed".to_string(),
            ));
        }
        if self.outbox.len() >= MAX_OUTBOX_EVENTS {
            self.outbox.retain(|_, event| event.published_at.is_none());
        }
        if self.outbox.len() >= MAX_OUTBOX_EVENTS {
            return Err(CscaLifecycleError::Storage(
                "CSCA lifecycle outbox capacity was reached".to_string(),
            ));
        }
        let event_id = format!("{:016x}-{topic}-{key}", self.revision + 1);
        if self.outbox.contains_key(&event_id) {
            return Err(CscaLifecycleError::Corrupt(format!(
                "duplicate outbox event '{event_id}'"
            )));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct CscaLifecycleStore {
    connection: ConnectionManager,
}

impl CscaLifecycleStore {
    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    pub async fn load(
        &self,
        organization_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CscaLifecycleDocument, CscaLifecycleError> {
        validate_identifier("organization_id", organization_id)?;
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(csca_lifecycle_storage_key(organization_id))
            .await
            .map_err(|error| CscaLifecycleError::Storage(error.to_string()))?;
        let document = payload
            .map(|payload| {
                serde_json::from_str(&payload)
                    .map_err(|error| CscaLifecycleError::Corrupt(error.to_string()))
            })
            .transpose()
            .map(|document| {
                document.unwrap_or_else(|| CscaLifecycleDocument::empty(organization_id, now))
            })?;
        if document.organization_id != organization_id {
            return Err(CscaLifecycleError::Corrupt(
                "organization identifier does not match its storage key".to_string(),
            ));
        }
        validate_stored_document(&document)?;
        Ok(document)
    }

    pub async fn save(&self, document: &CscaLifecycleDocument) -> Result<(), CscaLifecycleError> {
        validate_identifier("organization_id", &document.organization_id)?;
        validate_stored_document(document)?;
        let payload = serde_json::to_string(document)
            .map_err(|error| CscaLifecycleError::Invalid(error.to_string()))?;
        if document.revision == 0 || document.revision > MAX_SAFE_REDIS_REVISION {
            return Err(CscaLifecycleError::Invalid(
                "an unchanged lifecycle document cannot be saved".to_string(),
            ));
        }
        let expected_revision = document.revision - 1;
        let script = redis::Script::new(
            r#"
local existing = redis.call('GET', KEYS[1])
local current_revision = 0
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if not ok then
    return redis.error_reply('stored CSCA lifecycle document is malformed')
  end
  current_revision = tonumber(decoded.revision or 0)
end
if current_revision ~= tonumber(ARGV[1]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
return 1
"#,
        );
        let mut connection = self.connection.clone();
        let saved: i64 = script
            .key(csca_lifecycle_storage_key(&document.organization_id))
            .arg(expected_revision)
            .arg(payload)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| CscaLifecycleError::Storage(error.to_string()))?;
        if saved == 0 {
            return Err(CscaLifecycleError::ConcurrentModification);
        }
        Ok(())
    }
}

pub fn csca_lifecycle_storage_key(organization_id: &str) -> String {
    format!("signing:csca-lifecycle:{organization_id}")
}

fn build_record(
    certificate_id: &str,
    request: ImportCscaCertificateRequest,
    now: DateTime<Utc>,
    renewed_from: Option<String>,
) -> Result<CscaCertificateRecord, CscaLifecycleError> {
    validate_key_reference(&request.key_reference)?;
    if has_private_key_marker(&request.cert_pem) {
        return Err(CscaLifecycleError::Invalid(
            "cert_pem must not contain private key material".to_string(),
        ));
    }
    if contains_private_key(&request.metadata) {
        return Err(CscaLifecycleError::Invalid(
            "metadata must not contain private key material".to_string(),
        ));
    }
    let der = load_certificate_pem(&request.cert_pem)
        .map_err(|error| CscaLifecycleError::Invalid(format!("invalid cert_pem: {error}")))?;
    let info = get_certificate_info(&der)
        .map_err(|error| CscaLifecycleError::Invalid(format!("invalid cert_pem: {error}")))?;
    validate_certificate_path(&der, &info, &request.cert_chain_pem)?;
    if !info.is_ca {
        return Err(CscaLifecycleError::Invalid(
            "CSCA certificate must assert CA basic constraints".to_string(),
        ));
    }
    let public_jwk = serde_json::to_value(
        certificate_pem_to_jwk(&request.cert_pem)
            .map_err(|error| CscaLifecycleError::Invalid(format!("invalid cert_pem: {error}")))?,
    )
    .map_err(|error| CscaLifecycleError::Invalid(error.to_string()))?;
    if !crate::documents::same_public_jwk(&public_jwk, &request.expected_public_jwk) {
        return Err(CscaLifecycleError::Invalid(
            "certificate public key does not match expected_public_jwk".to_string(),
        ));
    }
    let not_before = parse_time("not_before", &info.not_before)?;
    let not_after = parse_time("not_after", &info.not_after)?;
    if not_after <= not_before {
        return Err(CscaLifecycleError::Invalid(
            "CSCA certificate not_after must be later than not_before".to_string(),
        ));
    }
    Ok(CscaCertificateRecord {
        certificate_id: certificate_id.to_string(),
        subject: info.subject,
        issuer: info.issuer,
        cert_pem: request.cert_pem,
        cert_chain_pem: request.cert_chain_pem,
        key_reference: request.key_reference.trim().to_string(),
        public_jwk,
        not_before: info.not_before,
        not_after: info.not_after,
        created_at: timestamp(now),
        revoked_at: None,
        revocation_reason: None,
        renewed_from,
        renewed_to: None,
        metadata: request.metadata,
    })
}

fn validate_stored_document(document: &CscaLifecycleDocument) -> Result<(), CscaLifecycleError> {
    if document.schema_version != CSCA_LIFECYCLE_SCHEMA_VERSION {
        return Err(CscaLifecycleError::Corrupt(format!(
            "unsupported schema version {}",
            document.schema_version
        )));
    }
    parse_time("updated_at", &document.updated_at).map_err(as_corrupt)?;
    if document.revision > MAX_SAFE_REDIS_REVISION {
        return Err(CscaLifecycleError::Corrupt(
            "revision counter exceeds the Redis-safe integer range".to_string(),
        ));
    }
    if document.outbox.len() > MAX_OUTBOX_EVENTS {
        return Err(CscaLifecycleError::Corrupt(
            "CSCA lifecycle outbox exceeds its capacity".to_string(),
        ));
    }
    for (certificate_id, record) in &document.certificates {
        validate_identifier("certificate_id", certificate_id).map_err(as_corrupt)?;
        if record.certificate_id != *certificate_id {
            return Err(CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' does not match its map key"
            )));
        }
        validate_key_reference(&record.key_reference).map_err(as_corrupt)?;
        if contains_private_key(&record.metadata) {
            return Err(CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' metadata contains private key material"
            )));
        }
        if has_private_key_marker(&record.cert_pem) {
            return Err(CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' contains private key material"
            )));
        }
        let der = load_certificate_pem(&record.cert_pem).map_err(|error| {
            CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' is invalid: {error}"
            ))
        })?;
        let info = get_certificate_info(&der).map_err(|error| {
            CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' is invalid: {error}"
            ))
        })?;
        validate_certificate_path(&der, &info, &record.cert_chain_pem).map_err(as_corrupt)?;
        let public_jwk =
            serde_json::to_value(certificate_pem_to_jwk(&record.cert_pem).map_err(|error| {
                CscaLifecycleError::Corrupt(format!(
                    "certificate '{certificate_id}' public key is invalid: {error}"
                ))
            })?)
            .map_err(|error| CscaLifecycleError::Corrupt(error.to_string()))?;
        if !info.is_ca
            || info.subject != record.subject
            || info.issuer != record.issuer
            || info.not_before != record.not_before
            || info.not_after != record.not_after
            || !crate::documents::same_public_jwk(&public_jwk, &record.public_jwk)
        {
            return Err(CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' metadata does not match its X.509 certificate"
            )));
        }
        let not_before = parse_time("not_before", &record.not_before).map_err(as_corrupt)?;
        let not_after = parse_time("not_after", &record.not_after).map_err(as_corrupt)?;
        if not_after <= not_before {
            return Err(CscaLifecycleError::Corrupt(format!(
                "certificate '{certificate_id}' has an invalid validity interval"
            )));
        }
        parse_time("created_at", &record.created_at).map_err(as_corrupt)?;
        if let Some(value) = &record.revoked_at {
            parse_time("revoked_at", value).map_err(as_corrupt)?;
        }
        for value in [record.renewed_from.as_deref(), record.renewed_to.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_identifier("renewal certificate identifier", value).map_err(as_corrupt)?;
        }
    }
    for (event_id, event) in &document.outbox {
        if event.event_id != *event_id
            || event_id.len() > 512
            || event_id.chars().any(char::is_control)
        {
            return Err(CscaLifecycleError::Corrupt(
                "outbox event identifier does not match its map key".to_string(),
            ));
        }
        if !matches!(
            event.topic.as_str(),
            "certificate.issued" | "certificate.renewed" | "certificate.revoked"
        ) {
            return Err(CscaLifecycleError::Corrupt(format!(
                "outbox event '{event_id}' has an unsupported topic"
            )));
        }
        validate_identifier("outbox key", &event.key).map_err(as_corrupt)?;
        if contains_private_key(&event.payload) {
            return Err(CscaLifecycleError::Corrupt(format!(
                "outbox event '{event_id}' contains private key material"
            )));
        }
        parse_time("outbox created_at", &event.created_at).map_err(as_corrupt)?;
        if let Some(value) = &event.published_at {
            parse_time("outbox published_at", value).map_err(as_corrupt)?;
        }
    }
    Ok(())
}

fn validate_key_reference(value: &str) -> Result<(), CscaLifecycleError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CscaLifecycleError::Invalid(
            "key_reference is required; private keys must remain in managed custody".to_string(),
        ));
    }
    if value.len() > 2048 || value.chars().any(char::is_control) || has_private_key_marker(value) {
        return Err(CscaLifecycleError::Invalid(
            "key_reference must be a bounded managed-provider reference, not key material"
                .to_string(),
        ));
    }
    Ok(())
}

fn parse_certificate_chain(value: &str) -> Result<Vec<Vec<u8>>, CscaLifecycleError> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    if has_private_key_marker(value) {
        return Err(CscaLifecycleError::Invalid(
            "cert_chain_pem must not contain private key material".to_string(),
        ));
    }
    let pattern = Regex::new(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----")
        .expect("certificate regex");
    let certificates: Vec<_> = pattern.find_iter(value).collect();
    if certificates.is_empty() || !pattern.replace_all(value, "").trim().is_empty() {
        return Err(CscaLifecycleError::Invalid(
            "cert_chain_pem must contain only PEM certificates".to_string(),
        ));
    }
    certificates
        .into_iter()
        .map(|certificate| {
            load_certificate_pem(certificate.as_str()).map_err(|error| {
                CscaLifecycleError::Invalid(format!("invalid cert_chain_pem: {error}"))
            })
        })
        .collect()
}

fn validate_certificate_path(
    certificate_der: &[u8],
    certificate_info: &marty_crypto::certificate::CertificateInfo,
    chain_pem: &str,
) -> Result<(), CscaLifecycleError> {
    let chain = parse_certificate_chain(chain_pem)?;
    if chain.is_empty() {
        if certificate_info.subject != certificate_info.issuer {
            return Err(CscaLifecycleError::Invalid(
                "a non-self-issued CSCA certificate requires its issuer chain".to_string(),
            ));
        }
        verify_certificate_link(certificate_der, certificate_info, certificate_der)?;
        return Ok(());
    }

    let mut child_der = certificate_der;
    let mut child_info = get_certificate_info(child_der)
        .map_err(|error| CscaLifecycleError::Invalid(format!("invalid cert_pem: {error}")))?;
    for issuer_der in &chain {
        verify_certificate_link(child_der, &child_info, issuer_der)?;
        child_der = issuer_der;
        child_info = get_certificate_info(child_der).map_err(|error| {
            CscaLifecycleError::Invalid(format!("invalid cert_chain_pem: {error}"))
        })?;
    }
    if child_info.subject == child_info.issuer {
        verify_certificate_link(child_der, &child_info, child_der)?;
    }
    Ok(())
}

fn verify_certificate_link(
    child_der: &[u8],
    child_info: &marty_crypto::certificate::CertificateInfo,
    issuer_der: &[u8],
) -> Result<(), CscaLifecycleError> {
    let issuer_info = get_certificate_info(issuer_der).map_err(|error| {
        CscaLifecycleError::Invalid(format!("invalid issuer certificate: {error}"))
    })?;
    if !issuer_info.is_ca {
        return Err(CscaLifecycleError::Invalid(
            "certificate chain issuer must assert CA basic constraints".to_string(),
        ));
    }
    if child_info.issuer != issuer_info.subject {
        return Err(CscaLifecycleError::Invalid(
            "certificate chain issuer and subject names do not match".to_string(),
        ));
    }
    let valid = verify_certificate_signature(child_der, issuer_der).map_err(|error| {
        CscaLifecycleError::Invalid(format!("certificate chain signature is invalid: {error}"))
    })?;
    if !valid {
        return Err(CscaLifecycleError::Invalid(
            "certificate chain signature is invalid".to_string(),
        ));
    }
    Ok(())
}

fn contains_private_key(value: &Value) -> bool {
    match value {
        Value::String(value) => has_private_key_marker(value),
        Value::Array(values) => values.iter().any(contains_private_key),
        Value::Object(values) => {
            let private_named_field = values.iter().any(|(name, value)| {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                !value.is_null()
                    && matches!(
                        normalized.as_str(),
                        "privatekey" | "privatekeypem" | "secretkey" | "secretkeypem" | "pkcs8"
                    )
            });
            let private_jwk = values.contains_key("kty")
                && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                    .iter()
                    .any(|name| values.get(*name).is_some_and(|value| !value.is_null()));
            private_named_field || private_jwk || values.values().any(contains_private_key)
        }
        _ => false,
    }
}

fn has_private_key_marker(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}

fn as_corrupt(error: CscaLifecycleError) -> CscaLifecycleError {
    CscaLifecycleError::Corrupt(error.to_string())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), CscaLifecycleError> {
    if value.trim().is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
    {
        return Err(CscaLifecycleError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn parse_time(field: &str, value: &str) -> Result<DateTime<Utc>, CscaLifecycleError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CscaLifecycleError::Invalid(format!("{field} must be RFC 3339")))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
