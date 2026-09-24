//! Persistence port shared by Canvas mirror HTTP and automation consumers.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::canvas_mirror_domain::{CanvasMirrorAlertEvent, CanvasMirrorDeliveryRecord};
use crate::credential::CredentialTransaction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasMirrorDeliveryStatus {
    Pending,
    Failed,
    Delivered,
}

impl CanvasMirrorDeliveryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Delivered => "delivered",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasMirrorDeliveryQuery {
    pub organization_id: Option<String>,
    pub statuses: Vec<CanvasMirrorDeliveryStatus>,
    pub limit: Option<u32>,
    pub status_sync_failures_only: bool,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Canvas mirror repository is unavailable")]
pub struct CanvasMirrorRepositoryError;

#[async_trait]
pub trait CanvasMirrorRepository: Send + Sync {
    async fn delivery_record(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError>;

    async fn delivery_by_external_credential(
        &self,
        external_credential_id: &str,
        canvas_account_id: Option<&str>,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError>;

    async fn deliveries_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError>;

    async fn canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError>;

    async fn claim_canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
        _claim_id: &str,
        _claim_expires_at: DateTime<Utc>,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.canvas_deliveries(query).await
    }

    async fn claim_delivery_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
        _claim_id: &str,
        _claim_expires_at: DateTime<Utc>,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        Ok(self
            .deliveries_for_credential(credential_id, organization_id)
            .await?
            .into_iter()
            .find(|record| record.delivery_target == "canvas_credentials"))
    }

    async fn credential(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    /// Admission-only lookup for the legacy publish route. The caller must
    /// compare the returned row's organization against trusted gateway
    /// context before performing any subsequent read or effect.
    async fn credential_unscoped(
        &self,
        id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    async fn transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    async fn publication_transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, CanvasMirrorRepositoryError>;

    async fn application(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    async fn canvas_program_binding(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    async fn canvas_platform(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError>;

    async fn save_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
    ) -> Result<(), CanvasMirrorRepositoryError>;

    async fn save_claimed_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
        _claim_id: &str,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        self.save_delivery(record).await
    }

    async fn mark_claim_effect_started(
        &self,
        _record: &CanvasMirrorDeliveryRecord,
        _claim_id: &str,
        _started_at: DateTime<Utc>,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        Ok(())
    }

    async fn save_alert_event(
        &self,
        event: &CanvasMirrorAlertEvent,
    ) -> Result<(), CanvasMirrorRepositoryError>;
}
