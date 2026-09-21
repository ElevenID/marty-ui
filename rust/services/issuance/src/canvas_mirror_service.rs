//! Route-neutral Canvas mirror queries. Authentication remains at HTTP admission.

use chrono::{DateTime, Utc};
use serde_json::Value;
use serde_json::{json, Map};
use std::sync::Arc;
use thiserror::Error;

use crate::{
    canvas_mirror_domain::{
        canvas_mirror_alert_for_record, canvas_mirror_health, canvas_mirror_provenance,
        CanvasMirrorAlert, CanvasMirrorAlertEvent, CanvasMirrorAlertThresholds,
        CanvasMirrorDeliveryRecord,
    },
    canvas_mirror_provider::{
        CanvasMirrorAlertWebhook, CanvasMirrorPublicationProvider, CanvasMirrorStatusProvider,
    },
    canvas_mirror_repository::{
        CanvasMirrorDeliveryQuery, CanvasMirrorDeliveryStatus, CanvasMirrorRepository,
        CanvasMirrorRepositoryError,
    },
    credential_management::CredentialLifecycleAction,
};

const CLAIM_LEASE_MINUTES: i64 = 15;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasMirrorProvenanceSelector {
    pub delivery_record_id: Option<String>,
    pub external_credential_id: Option<String>,
    pub credential_id: Option<String>,
    pub canvas_account_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanvasMirrorServiceError {
    #[error("Provide delivery_record_id, external_credential_id, or credential_id")]
    SelectorRequired,
    #[error("Canvas mirror delivery record not found")]
    NotFound,
    #[error("Canonical issued credential not found for Canvas mirror record")]
    CanonicalCredentialMissing,
    #[error("Canvas mirror canonical ownership is inconsistent")]
    CanonicalOwnershipMismatch,
    #[error("Trusted organization context is required")]
    TrustedOrganizationRequired,
    #[error("Issuance transaction not found for credential")]
    TransactionNotFound,
    #[error("No Canvas mirror delivery record exists for this credential")]
    DeliveryNotFound,
    #[error("Canvas mirror delivery is already being processed")]
    DeliveryInProgress,
    #[error(transparent)]
    Repository(#[from] CanvasMirrorRepositoryError),
}

#[derive(Clone)]
pub struct CanvasMirrorService {
    repository: Arc<dyn CanvasMirrorRepository>,
    issuer_base_url: String,
    thresholds: CanvasMirrorAlertThresholds,
    publication: Option<Arc<dyn CanvasMirrorPublicationProvider>>,
    status: Option<Arc<dyn CanvasMirrorStatusProvider>>,
    alert_webhook: Option<Arc<dyn CanvasMirrorAlertWebhook>>,
}

impl CanvasMirrorService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasMirrorRepository>,
        issuer_base_url: String,
        thresholds: CanvasMirrorAlertThresholds,
    ) -> Self {
        Self {
            repository,
            issuer_base_url,
            thresholds,
            publication: None,
            status: None,
            alert_webhook: None,
        }
    }

    #[must_use]
    pub fn with_status_provider(mut self, status: Arc<dyn CanvasMirrorStatusProvider>) -> Self {
        self.status = Some(status);
        self
    }

    #[must_use]
    pub fn with_publication_provider(
        mut self,
        publication: Arc<dyn CanvasMirrorPublicationProvider>,
    ) -> Self {
        self.publication = Some(publication);
        self
    }

    #[must_use]
    pub fn with_alert_webhook(mut self, webhook: Arc<dyn CanvasMirrorAlertWebhook>) -> Self {
        self.alert_webhook = Some(webhook);
        self
    }

    pub async fn publish(
        &self,
        credential_id: &str,
        organization_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        self.publish_admitted(credential_id, Some(organization_id), now)
            .await
    }

    pub async fn publish_admitted(
        &self,
        credential_id: &str,
        trusted_organization_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        let credential = self
            .repository
            .credential_unscoped(credential_id)
            .await?
            .ok_or(CanvasMirrorServiceError::NotFound)?;
        let organization_id = credential["organization_id"]
            .as_str()
            .ok_or(CanvasMirrorServiceError::CanonicalOwnershipMismatch)?;
        let trusted_organization_id = trusted_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CanvasMirrorServiceError::TrustedOrganizationRequired)?;
        if !mmf_security::constant_time_secret_eq(
            trusted_organization_id.as_bytes(),
            organization_id.as_bytes(),
        ) {
            return Err(CanvasMirrorServiceError::NotFound);
        }
        let transaction_id = credential["transaction_id"]
            .as_str()
            .ok_or(CanvasMirrorServiceError::CanonicalOwnershipMismatch)?;
        let transaction = self
            .repository
            .publication_transaction(transaction_id, organization_id)
            .await?
            .ok_or(CanvasMirrorServiceError::TransactionNotFound)?;
        if credential["id"].as_str() != Some(credential_id)
            || credential["organization_id"].as_str() != Some(organization_id)
            || transaction.id != transaction_id
            || transaction.organization_id != organization_id
        {
            return Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch);
        }
        let claim_id = uuid::Uuid::new_v4().to_string();
        let record = self
            .repository
            .claim_delivery_for_credential(
                credential_id,
                organization_id,
                &claim_id,
                now + chrono::TimeDelta::minutes(CLAIM_LEASE_MINUTES),
            )
            .await?;
        let record = match record {
            Some(record) => record,
            None => {
                let existing = self
                    .repository
                    .deliveries_for_credential(credential_id, organization_id)
                    .await?
                    .into_iter()
                    .find(|record| record.delivery_target == "canvas_credentials");
                match existing {
                    Some(record) if record.status == "delivered" => return Ok(record),
                    Some(_) => return Err(CanvasMirrorServiceError::DeliveryInProgress),
                    None => return Err(CanvasMirrorServiceError::DeliveryNotFound),
                }
            }
        };
        self.process_publication(record, credential, transaction, now, Some(&claim_id))
            .await
    }

    pub async fn process_pending(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        retry_failed: bool,
        now: DateTime<Utc>,
    ) -> Result<Value, CanvasMirrorServiceError> {
        let mut statuses = vec![CanvasMirrorDeliveryStatus::Pending];
        if retry_failed {
            statuses.push(CanvasMirrorDeliveryStatus::Failed);
        }
        let claim_id = uuid::Uuid::new_v4().to_string();
        let records = self
            .repository
            .claim_canvas_deliveries(
                CanvasMirrorDeliveryQuery {
                    organization_id: organization_id.map(str::to_owned),
                    statuses,
                    limit: Some(limit),
                    status_sync_failures_only: false,
                },
                &claim_id,
                now + chrono::TimeDelta::minutes(CLAIM_LEASE_MINUTES),
            )
            .await?;
        let mut processed = Vec::with_capacity(records.len());
        for record in records.into_iter().filter(|record| {
            record.delivery_target == "canvas_credentials"
                && organization_id.is_none_or(|organization| record.organization_id == organization)
                && (record.status == "pending" || retry_failed && record.status == "failed")
        }) {
            let record_organization = record.organization_id.clone();
            let credential = self
                .repository
                .credential(&record.credential_id, &record_organization)
                .await?;
            let transaction = self
                .repository
                .publication_transaction(&record.transaction_id, &record_organization)
                .await?;
            let updated = match (credential, transaction) {
                (Some(credential), Some(transaction)) => {
                    self.process_publication(record, credential, transaction, now, Some(&claim_id))
                        .await?
                }
                (None, _) => {
                    let detail =
                        format!("Issued credential {} was not found", record.credential_id);
                    self.fail_publication(record, detail, now, true, Some(&claim_id))
                        .await?
                }
                (_, None) => {
                    let detail = format!(
                        "Issuance transaction {} was not found",
                        record.transaction_id
                    );
                    self.fail_publication(record, detail, now, true, Some(&claim_id))
                        .await?
                }
            };
            processed.push(updated);
        }
        self.emit_alerts(&processed, organization_id, true, now)
            .await?;
        let delivered = processed
            .iter()
            .filter(|record| record.status == "delivered")
            .count();
        let failed = processed
            .iter()
            .filter(|record| record.status == "failed")
            .count();
        let blocked = processed
            .iter()
            .filter(|record| {
                record.metadata.get("canvas_feature_gate_blocked") == Some(&Value::Bool(true))
            })
            .count();
        let records = processed
            .iter()
            .map(CanvasMirrorDeliveryRecord::public_projection)
            .collect::<Vec<_>>();
        Ok(json!({
            "delivery_target":"canvas_credentials",
            "organization_id":organization_id,
            "retry_failed":retry_failed,
            "processed_count":records.len(),
            "delivered_count":delivered,
            "failed_count":failed,
            "blocked_count":blocked,
            "metrics":{
                "publish.processed":records.len(),
                "publish.delivered":delivered,
                "publish.failed":failed,
                "publish.blocked":blocked,
            },
            "records":records,
        }))
    }

    pub async fn process_status_sync_failures(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<Value, CanvasMirrorServiceError> {
        let claim_id = uuid::Uuid::new_v4().to_string();
        let records = self
            .repository
            .claim_canvas_deliveries(
                CanvasMirrorDeliveryQuery {
                    organization_id: organization_id.map(str::to_owned),
                    statuses: vec![CanvasMirrorDeliveryStatus::Delivered],
                    limit: Some(limit),
                    status_sync_failures_only: true,
                },
                &claim_id,
                now + chrono::TimeDelta::minutes(CLAIM_LEASE_MINUTES),
            )
            .await?;
        let mut processed = Vec::new();
        for mut record in records.into_iter().filter(|record| {
            record.delivery_target == "canvas_credentials"
                && record.status == "delivered"
                && organization_id.is_none_or(|organization| record.organization_id == organization)
                && record
                    .metadata
                    .get("last_status_sync_error")
                    .is_some_and(truthy)
        }) {
            let organization = record.organization_id.clone();
            let Some(credential) = self
                .repository
                .credential(&record.credential_id, &organization)
                .await?
            else {
                let action = metadata_text(&record.metadata, "last_status_sync_action")
                    .unwrap_or_else(|| "reinstate".into());
                increment_attempt(&mut record.metadata, "status_sync_attempts");
                record
                    .metadata
                    .insert("last_status_sync_action".into(), json!(action));
                record.metadata.insert(
                    "last_status_sync_attempted_at".into(),
                    json!(timestamp(now)),
                );
                let detail = format!(
                    "Issued credential {} was not found for Canvas lifecycle resync",
                    record.credential_id
                );
                record.last_error = Some(detail.clone());
                record
                    .metadata
                    .insert("last_status_sync_error".into(), json!(detail));
                record
                    .metadata
                    .insert("last_status_sync_error_at".into(), json!(timestamp(now)));
                record.updated_at = timestamp(now);
                self.save_delivery(&record, Some(&claim_id)).await?;
                processed.push(record);
                continue;
            };
            let transaction = self
                .repository
                .publication_transaction(&record.transaction_id, &organization)
                .await?;
            let updated = self
                .process_status_record(
                    record,
                    credential,
                    transaction.as_ref(),
                    now,
                    Some(&claim_id),
                )
                .await?;
            processed.push(updated);
        }
        self.emit_alerts(&processed, organization_id, false, now)
            .await?;
        let failed = processed
            .iter()
            .filter(|record| {
                record
                    .metadata
                    .get("last_status_sync_error")
                    .is_some_and(truthy)
            })
            .count();
        let blocked = processed
            .iter()
            .filter(|record| {
                record.metadata.get("canvas_feature_gate_blocked") == Some(&Value::Bool(true))
            })
            .count();
        let synced = processed.len() - failed;
        let records = processed
            .iter()
            .map(CanvasMirrorDeliveryRecord::public_projection)
            .collect::<Vec<_>>();
        Ok(json!({
            "delivery_target":"canvas_credentials",
            "organization_id":organization_id,
            "processed_count":records.len(),
            "synced_count":synced,
            "failed_count":failed,
            "blocked_count":blocked,
            "metrics":{
                "status_sync.processed":records.len(),
                "status_sync.synced":synced,
                "status_sync.failed":failed,
                "status_sync.blocked":blocked,
                "status_sync.retry_outcomes":records.len(),
                "status_sync.retry_succeeded":synced,
                "status_sync.retry_failed":failed,
                "status_sync.retry_blocked":blocked,
            },
            "records":records,
        }))
    }

    pub async fn run_automation_cycle(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        retry_failed: bool,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Result<Value, CanvasMirrorServiceError> {
        let publish = self
            .process_pending(organization_id, limit, retry_failed, started_at)
            .await?;
        let status_sync = self
            .process_status_sync_failures(organization_id, limit, started_at)
            .await?;
        let processed = publish["processed_count"].as_u64().unwrap_or_default()
            + status_sync["processed_count"].as_u64().unwrap_or_default();
        let failed = publish["failed_count"].as_u64().unwrap_or_default()
            + status_sync["failed_count"].as_u64().unwrap_or_default();
        let blocked = publish["blocked_count"].as_u64().unwrap_or_default()
            + status_sync["blocked_count"].as_u64().unwrap_or_default();
        let mut metrics = Map::new();
        for (prefix, source) in [("publish", &publish), ("status_sync", &status_sync)] {
            if let Some(values) = source["metrics"].as_object() {
                for (key, value) in values {
                    let suffix = key.strip_prefix(&format!("{prefix}.")).unwrap_or(key);
                    metrics.insert(format!("{prefix}.{suffix}"), value.clone());
                }
            }
        }
        metrics.insert("automation.processed".into(), json!(processed));
        metrics.insert("automation.failed".into(), json!(failed));
        metrics.insert("automation.blocked".into(), json!(blocked));
        Ok(json!({
            "delivery_target":"canvas_credentials",
            "organization_id":organization_id,
            "retry_failed":retry_failed,
            "publish":publish,
            "status_sync":status_sync,
            "processed_count":processed,
            "failed_count":failed,
            "blocked_count":blocked,
            "metrics":metrics,
            "started_at":timestamp(started_at),
            "completed_at":timestamp(completed_at),
        }))
    }

    pub async fn health(&self, organization_id: &str) -> Result<Value, CanvasMirrorServiceError> {
        let records = self
            .repository
            .canvas_deliveries(CanvasMirrorDeliveryQuery {
                organization_id: Some(organization_id.to_owned()),
                status_sync_failures_only: false,
                ..Default::default()
            })
            .await?
            .into_iter()
            .filter(|record| record.is_canvas_record_for(organization_id, None))
            .collect::<Vec<_>>();
        Ok(canvas_mirror_health(
            organization_id,
            &records,
            self.thresholds,
        ))
    }

    pub async fn provenance(
        &self,
        organization_id: &str,
        selector: CanvasMirrorProvenanceSelector,
        now: DateTime<Utc>,
    ) -> Result<Value, CanvasMirrorServiceError> {
        let record = self.resolve(organization_id, &selector).await?;
        let credential = self
            .repository
            .credential(&record.credential_id, organization_id)
            .await?
            .ok_or(CanvasMirrorServiceError::CanonicalCredentialMissing)?;
        if credential["organization_id"].as_str() != Some(organization_id)
            || credential["id"].as_str() != Some(record.credential_id.as_str())
            || credential["transaction_id"].as_str() != Some(record.transaction_id.as_str())
        {
            return Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch);
        }
        let transaction = self
            .repository
            .transaction(&record.transaction_id, organization_id)
            .await?;
        if transaction.as_ref().is_some_and(|transaction| {
            transaction["organization_id"].as_str() != Some(organization_id)
                || transaction["id"].as_str() != Some(record.transaction_id.as_str())
        }) {
            return Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch);
        }
        Ok(canvas_mirror_provenance(
            &record,
            &credential,
            transaction.as_ref(),
            &self.issuer_base_url,
            now,
        ))
    }

    async fn resolve(
        &self,
        organization_id: &str,
        selector: &CanvasMirrorProvenanceSelector,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        let record = if let Some(id) = selector.delivery_record_id.as_deref() {
            self.repository
                .delivery_record(id, organization_id)
                .await?
                .filter(|record| {
                    record.is_canvas_record_for(
                        organization_id,
                        selector.canvas_account_id.as_deref(),
                    )
                })
        } else if let Some(id) = selector.external_credential_id.as_deref() {
            self.repository
                .delivery_by_external_credential(
                    id,
                    selector.canvas_account_id.as_deref(),
                    organization_id,
                )
                .await?
        } else if let Some(id) = selector.credential_id.as_deref() {
            self.repository
                .deliveries_for_credential(id, organization_id)
                .await?
                .into_iter()
                .find(|record| {
                    record.is_canvas_record_for(
                        organization_id,
                        selector.canvas_account_id.as_deref(),
                    )
                })
        } else {
            return Err(CanvasMirrorServiceError::SelectorRequired);
        };
        record.ok_or(CanvasMirrorServiceError::NotFound)
    }

    async fn process_publication(
        &self,
        mut record: CanvasMirrorDeliveryRecord,
        credential: Value,
        transaction: crate::credential::CredentialTransaction,
        now: DateTime<Utc>,
        claim_id: Option<&str>,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        if record.status == "delivered" {
            return Ok(record);
        }
        if record.organization_id != transaction.organization_id
            || record.credential_id != credential["id"].as_str().unwrap_or_default()
            || record.transaction_id != transaction.id
            || credential["organization_id"].as_str() != Some(record.organization_id.as_str())
            || credential["transaction_id"].as_str() != Some(record.transaction_id.as_str())
        {
            return Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch);
        }
        self.hydrate_feature_metadata(&mut record, &transaction)
            .await?;
        for flag in ["enable_canvas_mirror_publish", "enable_canvas_mirror_ops"] {
            if !feature_enabled(&record.metadata, flag) {
                let detail = if flag == "enable_canvas_mirror_ops" {
                    "Canvas mirror operations are disabled by deployment profile"
                } else {
                    "Canvas mirror publish is disabled by deployment profile"
                };
                record.status = "failed".into();
                record.last_error = Some(detail.into());
                record.updated_at = timestamp(now);
                record
                    .metadata
                    .insert("canvas_feature_gate_blocked".into(), json!(true));
                record
                    .metadata
                    .insert("canvas_feature_gate".into(), json!(flag));
                record.metadata.insert(
                    "canvas_feature_gate_blocked_at".into(),
                    json!(timestamp(now)),
                );
                record.metadata.insert("retryable".into(), json!(false));
                self.save_delivery(&record, claim_id).await?;
                return Ok(record);
            }
        }
        let platform = match self.resolve_target(&mut record).await? {
            Ok(platform) => platform,
            Err(detail) => {
                return self
                    .fail_publication(record, detail, now, true, claim_id)
                    .await
            }
        };
        self.mark_claim_effect_started(&record, claim_id, now)
            .await?;
        increment_attempt(&mut record.metadata, "publish_attempts");
        record
            .metadata
            .insert("last_attempted_at".into(), json!(timestamp(now)));
        let delivery = serde_json::to_value(&record)
            .map_err(|_| CanvasMirrorServiceError::CanonicalOwnershipMismatch)?;
        let outcome = match &self.publication {
            Some(provider) => {
                provider
                    .publish(&credential, &transaction, &platform, &delivery)
                    .await
            }
            None => Err(crate::canvas_mirror_provider::CanvasMirrorProviderError(
                "Canvas Credentials provider is unavailable".into(),
            )),
        };
        match outcome {
            Ok(outcome) => {
                record.status = "delivered".into();
                record.external_credential_id = outcome.external_credential_id;
                record.external_issuer_id = outcome.external_issuer_id;
                record.last_error = None;
                record.metadata.extend(outcome.metadata);
                record.updated_at = timestamp(now);
                self.save_delivery(&record, claim_id).await?;
                Ok(record)
            }
            Err(failure) => {
                record.status = "failed".into();
                record.last_error = Some(failure.0);
                record
                    .metadata
                    .insert("last_error_at".into(), json!(timestamp(now)));
                record.updated_at = timestamp(now);
                self.save_delivery(&record, claim_id).await?;
                Ok(record)
            }
        }
    }

    async fn process_status_record(
        &self,
        mut record: CanvasMirrorDeliveryRecord,
        credential: Value,
        transaction: Option<&crate::credential::CredentialTransaction>,
        now: DateTime<Utc>,
        claim_id: Option<&str>,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        if credential["id"].as_str() != Some(record.credential_id.as_str())
            || credential["transaction_id"].as_str() != Some(record.transaction_id.as_str())
            || credential["organization_id"].as_str() != Some(record.organization_id.as_str())
            || transaction.is_some_and(|transaction| {
                transaction.id != record.transaction_id
                    || transaction.organization_id != record.organization_id
            })
        {
            return Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch);
        }
        if let Some(transaction) = transaction {
            self.hydrate_feature_metadata(&mut record, transaction)
                .await?;
        }
        if !feature_enabled(&record.metadata, "enable_canvas_mirror_ops") {
            let detail = "Canvas mirror operations are disabled by deployment profile";
            record.last_error = Some(detail.into());
            record
                .metadata
                .insert("canvas_feature_gate_blocked".into(), json!(true));
            record.metadata.insert(
                "canvas_feature_gate".into(),
                json!("enable_canvas_mirror_ops"),
            );
            record.metadata.insert(
                "canvas_feature_gate_blocked_at".into(),
                json!(timestamp(now)),
            );
            record.metadata.insert("retryable".into(), json!(false));
            record
                .metadata
                .insert("last_status_sync_error".into(), json!(detail));
            record
                .metadata
                .insert("last_status_sync_error_at".into(), json!(timestamp(now)));
            record.updated_at = timestamp(now);
            self.save_delivery(&record, claim_id).await?;
            return Ok(record);
        }
        let action_name = metadata_text(&record.metadata, "last_status_sync_action")
            .unwrap_or_else(|| match credential["status"].as_str() {
                Some("revoked") => "revoke".into(),
                Some("suspended") => "suspend".into(),
                _ => "reinstate".into(),
            });
        let action = match action_name.as_str() {
            "revoke" => CredentialLifecycleAction::Revoke,
            "suspend" => CredentialLifecycleAction::Suspend,
            _ => CredentialLifecycleAction::Reinstate,
        };
        let platform = match self.resolve_target(&mut record).await? {
            Ok(platform) => platform,
            Err(detail) => {
                increment_status_attempt(&mut record, &credential, &action_name, now);
                let detail = format!("Canvas lifecycle sync skipped: {detail}");
                record.last_error = Some(detail.clone());
                record
                    .metadata
                    .insert("last_status_sync_error".into(), json!(detail));
                record
                    .metadata
                    .insert("last_status_sync_error_at".into(), json!(timestamp(now)));
                record.updated_at = timestamp(now);
                self.save_delivery(&record, claim_id).await?;
                return Ok(record);
            }
        };
        self.mark_claim_effect_started(&record, claim_id, now)
            .await?;
        increment_status_attempt(&mut record, &credential, &action_name, now);
        let delivery = serde_json::to_value(&record)
            .map_err(|_| CanvasMirrorServiceError::CanonicalOwnershipMismatch)?;
        let reason = credential["revocation_reason"].as_str();
        let outcome = match &self.status {
            Some(provider) => {
                provider
                    .synchronize(
                        &credential,
                        &record.transaction_id,
                        &platform,
                        &delivery,
                        action,
                        reason,
                    )
                    .await
            }
            None => Err(crate::canvas_mirror_provider::CanvasMirrorProviderError(
                "Canvas Credentials status provider is unavailable".into(),
            )),
        };
        match outcome {
            Ok(metadata) => {
                record.last_error = None;
                record.metadata.extend(metadata);
                record
                    .metadata
                    .insert("last_status_sync_error".into(), Value::Null);
            }
            Err(failure) => {
                record.last_error = Some(failure.0.clone());
                record
                    .metadata
                    .insert("last_status_sync_error".into(), json!(failure.0));
                record
                    .metadata
                    .insert("last_status_sync_error_at".into(), json!(timestamp(now)));
            }
        }
        record.updated_at = timestamp(now);
        self.save_delivery(&record, claim_id).await?;
        Ok(record)
    }

    async fn hydrate_feature_metadata(
        &self,
        record: &mut CanvasMirrorDeliveryRecord,
        transaction: &crate::credential::CredentialTransaction,
    ) -> Result<(), CanvasMirrorServiceError> {
        if record
            .metadata
            .get("deployment_profile_id")
            .is_some_and(truthy)
            && record
                .metadata
                .get("canvas_feature_flags")
                .is_some_and(truthy)
        {
            return Ok(());
        }
        let Some(application_id) = transaction.application_id.as_deref() else {
            return Ok(());
        };
        let Some(application) = self
            .repository
            .application(application_id, &record.organization_id)
            .await?
        else {
            return Ok(());
        };
        let Some(canvas) = application["integration_context"]["canvas"].as_object() else {
            return Ok(());
        };
        for (source, destination) in [
            ("canvas_platform_id", "canvas_platform_id"),
            ("canvas_program_binding_id", "canvas_program_binding_id"),
            ("deployment_profile_id", "deployment_profile_id"),
            ("delivery_mode", "canvas_binding_delivery_mode"),
        ] {
            if canvas.get(source).is_some_and(truthy) {
                record
                    .metadata
                    .insert(destination.into(), canvas[source].clone());
            }
        }
        if canvas.get("feature_flags").is_some_and(truthy) {
            record.metadata.insert(
                "canvas_feature_flags".into(),
                canvas["feature_flags"].clone(),
            );
        }
        Ok(())
    }

    async fn resolve_target(
        &self,
        record: &mut CanvasMirrorDeliveryRecord,
    ) -> Result<Result<Value, String>, CanvasMirrorServiceError> {
        let Some(binding_id) = metadata_text(&record.metadata, "canvas_program_binding_id") else {
            return Ok(Err(
                "Canvas mirror delivery record is missing canvas_program_binding_id".into(),
            ));
        };
        let Some(binding) = self
            .repository
            .canvas_program_binding(&binding_id, &record.organization_id)
            .await?
        else {
            return Ok(Err(format!(
                "Canvas program binding {binding_id} was not found"
            )));
        };
        if binding["enabled"] != true {
            return Ok(Err(format!(
                "Canvas program binding {binding_id} is disabled"
            )));
        }
        if binding["canvas_credentials"]
            .as_object()
            .is_some_and(|value| !value.is_empty())
        {
            record.metadata.insert(
                "canvas_credentials".into(),
                binding["canvas_credentials"].clone(),
            );
        }
        let platform_id = binding["platform_id"].as_str().unwrap_or_default();
        let Some(platform) = self
            .repository
            .canvas_platform(platform_id, &record.organization_id)
            .await?
        else {
            return Ok(Err(format!("Canvas platform {platform_id} was not found")));
        };
        if platform["enabled"] != true {
            return Ok(Err(format!("Canvas platform {platform_id} is disabled")));
        }
        record.canvas_account_id = platform["canvas_account_id"].as_str().map(str::to_owned);
        record
            .metadata
            .insert("canvas_platform_id".into(), json!(platform_id));
        record
            .metadata
            .insert("canvas_program_binding_id".into(), json!(binding_id));
        Ok(Ok(platform))
    }

    async fn fail_publication(
        &self,
        mut record: CanvasMirrorDeliveryRecord,
        detail: String,
        now: DateTime<Utc>,
        increment: bool,
        claim_id: Option<&str>,
    ) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorServiceError> {
        if increment {
            increment_attempt(&mut record.metadata, "publish_attempts");
            record
                .metadata
                .insert("last_attempted_at".into(), json!(timestamp(now)));
        }
        record.status = "failed".into();
        record.last_error = Some(detail);
        record
            .metadata
            .insert("last_error_at".into(), json!(timestamp(now)));
        record.updated_at = timestamp(now);
        self.save_delivery(&record, claim_id).await?;
        Ok(record)
    }

    async fn save_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
        claim_id: Option<&str>,
    ) -> Result<(), CanvasMirrorServiceError> {
        match claim_id {
            Some(claim_id) => {
                self.repository
                    .save_claimed_delivery(record, claim_id)
                    .await?
            }
            None => self.repository.save_delivery(record).await?,
        }
        Ok(())
    }

    async fn mark_claim_effect_started(
        &self,
        record: &CanvasMirrorDeliveryRecord,
        claim_id: Option<&str>,
        started_at: DateTime<Utc>,
    ) -> Result<(), CanvasMirrorServiceError> {
        if let Some(claim_id) = claim_id {
            self.repository
                .mark_claim_effect_started(record, claim_id, started_at)
                .await?;
        }
        Ok(())
    }

    async fn emit_alerts(
        &self,
        records: &[CanvasMirrorDeliveryRecord],
        requested_organization_id: Option<&str>,
        publish: bool,
        now: DateTime<Utc>,
    ) -> Result<(), CanvasMirrorServiceError> {
        let alerts = records
            .iter()
            .filter(|record| {
                if publish {
                    record.status == "failed"
                } else {
                    record
                        .metadata
                        .get("last_status_sync_error")
                        .is_some_and(truthy)
                }
            })
            .filter_map(|record| {
                canvas_mirror_alert_for_record(record, publish, self.thresholds.normalized())
                    .map(|alert| (record.organization_id.clone(), alert))
            })
            .collect::<Vec<_>>();
        let effective_organization_id =
            requested_organization_id.map(str::to_owned).or_else(|| {
                alerts
                    .first()
                    .map(|(organization_id, _)| organization_id.clone())
            });
        for (organization_id, alert) in &alerts {
            let mut metadata = serde_json::to_value(alert)
                .ok()
                .and_then(|value| value.as_object().cloned())
                .ok_or(CanvasMirrorServiceError::CanonicalOwnershipMismatch)?;
            metadata.insert(
                "organization_id".into(),
                json!(effective_organization_id
                    .as_deref()
                    .unwrap_or(organization_id)),
            );
            self.repository
                .save_alert_event(&CanvasMirrorAlertEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    transaction_id: alert.transaction_id.clone(),
                    application_id: None,
                    event_type: "canvas_mirror_alert_emitted".into(),
                    metadata: Value::Object(metadata),
                    created_at: timestamp(now),
                })
                .await?;
        }
        if let (Some(organization_id), Some(webhook)) = (
            effective_organization_id.as_deref(),
            self.alert_webhook.as_ref(),
        ) {
            let critical = alerts
                .iter()
                .filter_map(|(_, alert)| (alert.severity == "critical").then_some(alert))
                .collect::<Vec<&CanvasMirrorAlert>>();
            if !critical.is_empty() {
                // Webhook delivery is advisory in the frozen owner. Durable alert
                // events above remain authoritative if this outbound call fails.
                if webhook
                    .post(json!({
                        "event":"canvas_mirror_critical_alert",
                        "organization_id":organization_id,
                        "alerts":critical,
                        "generated_at":timestamp(now),
                    }))
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        organization_id,
                        "Canvas mirror alert webhook delivery failed"
                    );
                }
            }
        }
        Ok(())
    }
}

fn feature_enabled(metadata: &Map<String, Value>, flag: &str) -> bool {
    let Some(flags) = metadata
        .get("canvas_feature_flags")
        .and_then(Value::as_object)
        .filter(|flags| !flags.is_empty())
    else {
        return true;
    };
    flags.get(flag).is_some_and(truthy)
}

fn metadata_text(metadata: &Map<String, Value>, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn increment_attempt(metadata: &mut Map<String, Value>, key: &str) {
    let previous = metadata
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(0);
    metadata.insert(key.into(), json!(previous.saturating_add(1)));
}

fn increment_status_attempt(
    record: &mut CanvasMirrorDeliveryRecord,
    credential: &Value,
    action: &str,
    now: DateTime<Utc>,
) {
    increment_attempt(&mut record.metadata, "status_sync_attempts");
    record
        .metadata
        .insert("last_status_sync_action".into(), json!(action));
    record.metadata.insert(
        "last_status_sync_attempted_at".into(),
        json!(timestamp(now)),
    );
    if let Some(status) = credential["status"].as_str() {
        record
            .metadata
            .insert("last_synced_credential_status".into(), json!(status));
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) => true,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn timestamp(now: DateTime<Utc>) -> String {
    crate::canvas_legacy_ingest::timestamp_string(now)
}
