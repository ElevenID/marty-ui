//! Retryable remote deletion of locally revoked holder keys.

use chrono::Utc;
use reqwest::{Client, Url};
use serde_json::json;
use std::time::Duration;

use crate::{
    holder_key_repository::{PendingHolderKeyDeletion, PostgresHolderKeyRepository},
    DeviceError,
};

#[derive(Clone)]
pub struct HolderKeyCleanup {
    repository: PostgresHolderKeyRepository,
    client: Client,
    endpoint: String,
    service_key: String,
}

impl HolderKeyCleanup {
    pub fn new(
        repository: PostgresHolderKeyRepository,
        endpoint: &str,
        service_key: String,
    ) -> Result<Self, DeviceError> {
        let parsed = Url::parse(endpoint)
            .map_err(|_| DeviceError::BadRequest("Signing Keys holder origin is invalid".into()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || service_key.len() < 32
        {
            return Err(DeviceError::BadRequest(
                "Signing Keys holder cleanup configuration is invalid".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| DeviceError::Persistence("holder cleanup client unavailable".into()))?;
        Ok(Self {
            repository,
            client,
            endpoint: endpoint.trim_end_matches('/').into(),
            service_key,
        })
    }

    async fn revoke_remote(&self, entry: &PendingHolderKeyDeletion) -> Result<(), DeviceError> {
        let response = self
            .client
            .post(format!(
                "{}/internal/device-registration/holder-keys/revoke",
                self.endpoint
            ))
            .header("x-device-registration-key", &self.service_key)
            .json(&json!({
                "organization_id":entry.organization_id,
                "registration_id":entry.registration_id,
                "purpose":entry.purpose,
                "provider_reference":entry.provider_reference,
            }))
            .send()
            .await
            .map_err(|_| DeviceError::Persistence("holder KMS revoke failed".into()))?;
        if !response.status().is_success() {
            return Err(DeviceError::Persistence("holder KMS revoke failed".into()));
        }
        Ok(())
    }

    /// A failed call leaves the durable entry pending for a later pass.
    pub async fn run_once(&self) -> Result<(usize, usize), DeviceError> {
        let pending = self.repository.pending_deletions(100).await?;
        let mut deleted = 0;
        let mut postponed = 0;
        for entry in pending {
            match self.revoke_remote(&entry).await {
                Ok(()) => {
                    self.repository
                        .mark_deleted(&entry.provider_reference, Utc::now())
                        .await?;
                    deleted += 1;
                }
                Err(_) => {
                    self.repository
                        .postpone_deletion(&entry.provider_reference, Utc::now())
                        .await?;
                    postponed += 1;
                }
            }
        }
        Ok((deleted, postponed))
    }

    pub async fn run_forever(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            match self.run_once().await {
                Ok((deleted, postponed)) if deleted > 0 || postponed > 0 => {
                    tracing::info!(deleted, postponed, "holder KMS deletion pass");
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("holder KMS deletion pass could not complete"),
            }
        }
    }
}
