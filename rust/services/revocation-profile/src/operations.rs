use crate::domain::utc_now;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CascadeOperationType {
    IssuerRevocation,
    AnchorRevocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TriggerEntityType {
    Issuer,
    TrustAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CascadeStatus {
    PendingConfirmation,
    InProgress,
    Completed,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CascadeRevocationOperation {
    pub id: String,
    pub organization_id: String,
    pub operation_type: CascadeOperationType,
    pub trigger_entity_type: TriggerEntityType,
    pub trigger_entity_id: String,
    pub status: CascadeStatus,
    pub affected_credential_count: usize,
    pub affected_credential_ids: Vec<String>,
    pub requires_confirmation: bool,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub confirmed_by: Option<String>,
    pub max_cascade_depth: u8,
    pub current_depth: u8,
    pub circuit_breaker_threshold: usize,
    pub circuit_breaker_triggered: bool,
    pub can_rollback: bool,
    pub rollback_snapshot: Option<Value>,
    pub rolled_back_at: Option<DateTime<Utc>>,
    pub rolled_back_by: Option<String>,
    pub error_message: Option<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl CascadeRevocationOperation {
    pub fn confirm(&mut self, user_id: &str) -> Result<(), OperationError> {
        if self.status != CascadeStatus::PendingConfirmation {
            return Err(OperationError::InvalidTransition(
                "Only pending cascade operations can be confirmed".into(),
            ));
        }
        let now = utc_now();
        self.confirmed_at = Some(now);
        self.confirmed_by = Some(user_id.to_string());
        self.status = CascadeStatus::Completed;
        self.completed_at = Some(now);
        self.updated_at = now;
        Ok(())
    }

    pub fn rollback(&mut self, user_id: &str) -> Result<(), OperationError> {
        if self.status != CascadeStatus::Completed {
            return Err(OperationError::InvalidTransition(
                "Only completed cascade operations can be rolled back".into(),
            ));
        }
        if !self.can_rollback {
            return Err(OperationError::InvalidTransition(
                "Rollback is not enabled for this cascade operation".into(),
            ));
        }
        let completed_at = self.completed_at.ok_or_else(|| {
            OperationError::InvalidTransition("Cascade completion timestamp is missing".into())
        })?;
        let now = utc_now();
        if now - completed_at > Duration::hours(72) {
            return Err(OperationError::InvalidTransition(
                "Cascade rollback window has expired".into(),
            ));
        }
        self.status = CascadeStatus::RolledBack;
        self.rolled_back_at = Some(now);
        self.rolled_back_by = Some(user_id.to_string());
        self.rollback_snapshot = None;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationBatchStatus {
    Pending,
    Publishing,
    Published,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationBatch {
    pub id: String,
    pub organization_id: String,
    pub revocation_profile_id: String,
    pub batch_interval: String,
    pub credential_format: String,
    pub credential_ids: Vec<String>,
    pub status: RevocationBatchStatus,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

impl RevocationBatch {
    pub fn new(
        organization_id: String,
        revocation_profile_id: String,
        batch_interval: String,
        credential_format: String,
        credential_ids: Vec<String>,
    ) -> Result<Self, OperationError> {
        if !matches!(batch_interval.as_str(), "1h" | "6h" | "24h") {
            return Err(OperationError::InvalidArgument(
                "batch_interval must be 1h, 6h, or 24h".into(),
            ));
        }
        if credential_ids.len() >= 1_000 {
            return Err(OperationError::CircuitBreaker);
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            organization_id,
            revocation_profile_id,
            batch_interval,
            credential_format,
            credential_ids,
            status: RevocationBatchStatus::Pending,
            created_at: utc_now(),
            published_at: None,
        })
    }

    pub fn publish(&mut self) -> Result<(), OperationError> {
        if !matches!(
            self.status,
            RevocationBatchStatus::Pending | RevocationBatchStatus::Failed
        ) {
            return Err(OperationError::InvalidTransition(format!(
                "Cannot publish batch in {} status",
                batch_status_name(self.status)
            )));
        }
        self.status = RevocationBatchStatus::Publishing;
        self.status = RevocationBatchStatus::Published;
        self.published_at = Some(utc_now());
        Ok(())
    }
}

pub fn batch_status_name(status: RevocationBatchStatus) -> &'static str {
    match status {
        RevocationBatchStatus::Pending => "PENDING",
        RevocationBatchStatus::Publishing => "PUBLISHING",
        RevocationBatchStatus::Published => "PUBLISHED",
        RevocationBatchStatus::Failed => "FAILED",
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OperationError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid operation transition: {0}")]
    InvalidTransition(String),
    #[error("operation was not found")]
    NotFound,
    #[error("operation belongs to another organization")]
    PermissionDenied,
    #[error("batch circuit breaker requires manual review")]
    CircuitBreaker,
    #[error("operation storage failed: {0}")]
    Storage(String),
}

#[async_trait]
pub trait RevocationOperationRepository: Send + Sync {
    async fn save_cascade(
        &self,
        operation: CascadeRevocationOperation,
    ) -> Result<(), OperationError>;
    async fn get_cascade(
        &self,
        operation_id: &str,
    ) -> Result<Option<CascadeRevocationOperation>, OperationError>;
    async fn list_cascades(
        &self,
        organization_id: &str,
        status: Option<CascadeStatus>,
    ) -> Result<Vec<CascadeRevocationOperation>, OperationError>;
    async fn delete_cascade(&self, operation_id: &str) -> Result<bool, OperationError>;
    async fn save_batch(&self, batch: RevocationBatch) -> Result<(), OperationError>;
    async fn get_batch(&self, batch_id: &str) -> Result<Option<RevocationBatch>, OperationError>;
    async fn list_batches(
        &self,
        organization_id: Option<&str>,
        status: Option<RevocationBatchStatus>,
    ) -> Result<Vec<RevocationBatch>, OperationError>;
    async fn delete_batch(&self, batch_id: &str) -> Result<bool, OperationError>;
}

#[derive(Debug, Default)]
pub struct InMemoryRevocationOperationRepository {
    cascades: Arc<Mutex<HashMap<String, CascadeRevocationOperation>>>,
    batches: Arc<Mutex<HashMap<String, RevocationBatch>>>,
}

#[async_trait]
impl RevocationOperationRepository for InMemoryRevocationOperationRepository {
    async fn save_cascade(
        &self,
        operation: CascadeRevocationOperation,
    ) -> Result<(), OperationError> {
        self.cascades
            .lock()
            .await
            .insert(operation.id.clone(), operation);
        Ok(())
    }

    async fn get_cascade(
        &self,
        operation_id: &str,
    ) -> Result<Option<CascadeRevocationOperation>, OperationError> {
        Ok(self.cascades.lock().await.get(operation_id).cloned())
    }

    async fn list_cascades(
        &self,
        organization_id: &str,
        status: Option<CascadeStatus>,
    ) -> Result<Vec<CascadeRevocationOperation>, OperationError> {
        let mut values = self
            .cascades
            .lock()
            .await
            .values()
            .filter(|value| value.organization_id == organization_id)
            .filter(|value| status.is_none_or(|status| value.status == status))
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|value| std::cmp::Reverse(value.created_at));
        Ok(values)
    }

    async fn delete_cascade(&self, operation_id: &str) -> Result<bool, OperationError> {
        Ok(self.cascades.lock().await.remove(operation_id).is_some())
    }

    async fn save_batch(&self, batch: RevocationBatch) -> Result<(), OperationError> {
        self.batches.lock().await.insert(batch.id.clone(), batch);
        Ok(())
    }

    async fn get_batch(&self, batch_id: &str) -> Result<Option<RevocationBatch>, OperationError> {
        Ok(self.batches.lock().await.get(batch_id).cloned())
    }

    async fn list_batches(
        &self,
        organization_id: Option<&str>,
        status: Option<RevocationBatchStatus>,
    ) -> Result<Vec<RevocationBatch>, OperationError> {
        let mut values = self
            .batches
            .lock()
            .await
            .values()
            .filter(|value| organization_id.is_none_or(|org| value.organization_id == org))
            .filter(|value| status.is_none_or(|status| value.status == status))
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|value| std::cmp::Reverse(value.created_at));
        Ok(values)
    }

    async fn delete_batch(&self, batch_id: &str) -> Result<bool, OperationError> {
        Ok(self.batches.lock().await.remove(batch_id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_transitions_fail_closed() {
        let now = utc_now();
        let mut operation = CascadeRevocationOperation {
            id: "cascade-1".into(),
            organization_id: "org-1".into(),
            operation_type: CascadeOperationType::IssuerRevocation,
            trigger_entity_type: TriggerEntityType::Issuer,
            trigger_entity_id: "issuer-1".into(),
            status: CascadeStatus::PendingConfirmation,
            affected_credential_count: 1,
            affected_credential_ids: vec!["credential-1".into()],
            requires_confirmation: true,
            confirmed_at: None,
            confirmed_by: None,
            max_cascade_depth: 3,
            current_depth: 0,
            circuit_breaker_threshold: 1_000,
            circuit_breaker_triggered: false,
            can_rollback: true,
            rollback_snapshot: Some(serde_json::json!({"credential": "credential-1"})),
            rolled_back_at: None,
            rolled_back_by: None,
            error_message: None,
            metadata: None,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };
        operation.confirm("admin-1").unwrap();
        assert_eq!(operation.status, CascadeStatus::Completed);
        assert!(operation.confirm("admin-1").is_err());
        operation.rollback("admin-1").unwrap();
        assert_eq!(operation.status, CascadeStatus::RolledBack);
        assert!(operation.rollback_snapshot.is_none());
        assert!(operation.rollback("admin-1").is_err());
    }

    #[test]
    fn batch_limits_and_transitions_match_existing_contract() {
        assert!(matches!(
            RevocationBatch::new(
                "org-1".into(),
                "profile-1".into(),
                "invalid".into(),
                "SD_JWT_VC".into(),
                Vec::new(),
            ),
            Err(OperationError::InvalidArgument(_))
        ));
        assert!(matches!(
            RevocationBatch::new(
                "org-1".into(),
                "profile-1".into(),
                "1h".into(),
                "SD_JWT_VC".into(),
                vec!["credential".into(); 1_000],
            ),
            Err(OperationError::CircuitBreaker)
        ));
        let mut batch = RevocationBatch::new(
            "org-1".into(),
            "profile-1".into(),
            "1h".into(),
            "SD_JWT_VC".into(),
            vec!["credential-1".into()],
        )
        .unwrap();
        batch.publish().unwrap();
        assert_eq!(batch.status, RevocationBatchStatus::Published);
        assert!(batch.publish().is_err());
    }
}
