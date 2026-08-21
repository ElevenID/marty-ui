use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{NativeTrustRegistrySynchronizer, TrustProfileRepository, TrustProfileRepositoryError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScheduledRegistrySyncReport {
    pub due_profiles: usize,
    pub synchronized_profiles: usize,
    pub failed_profiles: usize,
    pub synchronized_sources: usize,
}

#[derive(Clone)]
pub struct TrustRegistryScheduler {
    repository: Arc<dyn TrustProfileRepository>,
    synchronizer: Arc<NativeTrustRegistrySynchronizer>,
    poll_interval: Duration,
}

impl std::fmt::Debug for TrustRegistryScheduler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustRegistryScheduler")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl TrustRegistryScheduler {
    #[must_use]
    pub fn new(
        repository: Arc<dyn TrustProfileRepository>,
        synchronizer: Arc<NativeTrustRegistrySynchronizer>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            repository,
            synchronizer,
            poll_interval,
        }
    }

    pub async fn run_once_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<ScheduledRegistrySyncReport, TrustProfileRepositoryError> {
        let profiles = self.repository.profiles().await?;
        let mut report = ScheduledRegistrySyncReport::default();
        for profile in profiles {
            let profile_id = profile.id;
            match self.synchronizer.synchronize_due(profile, now).await {
                Ok(Some(result)) => {
                    report.due_profiles += 1;
                    report.synchronized_profiles += 1;
                    report.synchronized_sources += result["sources"].as_array().map_or(0, Vec::len);
                    info!(%profile_id, "scheduled trust registry synchronization completed");
                }
                Ok(None) => {}
                Err(error) => {
                    report.due_profiles += 1;
                    report.failed_profiles += 1;
                    warn!(%profile_id, %error, "scheduled trust registry synchronization failed");
                }
            }
        }
        Ok(report)
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            if let Err(error) = self.run_once_at(Utc::now()).await {
                warn!(%error, "scheduled trust registry scan failed");
            }
            tokio::select! {
                () = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}
