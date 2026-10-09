//! Retryable remote deletion of locally revoked holder keys.

use chrono::Utc;
use std::time::Duration;

use crate::{
    holder_key_client::HolderKeyClient, holder_key_repository::PostgresHolderKeyRepository,
    DeviceError,
};
use marty_holder_key_reference::HolderKeyScope;

#[derive(Clone)]
pub struct HolderKeyCleanup {
    repository: PostgresHolderKeyRepository,
    client: HolderKeyClient,
}

impl HolderKeyCleanup {
    pub fn new(repository: PostgresHolderKeyRepository, client: HolderKeyClient) -> Self {
        Self { repository, client }
    }

    /// A failed call leaves the durable entry pending for a later pass.
    pub async fn run_once(&self) -> Result<(usize, usize), DeviceError> {
        let mut pending: Vec<_> = self
            .repository
            .pending_deletions(100)
            .await?
            .into_iter()
            .map(|entry| (entry, false))
            .collect();
        pending.extend(
            self.repository
                .expired_provisions(100)
                .await?
                .into_iter()
                .map(|entry| (entry, true)),
        );
        let mut deleted = 0;
        let mut postponed = 0;
        for (entry, unbound) in pending {
            let scope = HolderKeyScope {
                organization_id: entry.organization_id,
                registration_id: entry.registration_id,
                purpose: entry.purpose,
                provider_reference: entry.provider_reference,
            };
            match self.client.revoke(&scope).await {
                Ok(()) => {
                    if unbound {
                        self.repository
                            .mark_provision_cleaned(&scope.provider_reference, Utc::now())
                            .await?;
                    } else {
                        self.repository
                            .mark_deleted(&scope.provider_reference, Utc::now())
                            .await?;
                    }
                    deleted += 1;
                }
                Err(_) => {
                    if unbound {
                        self.repository
                            .postpone_provision(&scope.provider_reference, Utc::now())
                            .await?;
                    } else {
                        self.repository
                            .postpone_deletion(&scope.provider_reference, Utc::now())
                            .await?;
                    }
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
