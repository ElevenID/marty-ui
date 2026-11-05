//! Retention for public verification payloads and minimal admission receipts.
use crate::{PostgresFlowRepository, RepositoryError};
use tokio::sync::watch;

pub const PUBLIC_VERIFICATION_RECEIPT_DAYS: u32 = 30;
pub const PUBLIC_VERIFICATION_SWEEP_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct PublicVerificationRetentionPolicy {
    pub result_access_seconds: i64,
    pub receipt_days: u32,
}
impl Default for PublicVerificationRetentionPolicy {
    fn default() -> Self {
        Self {
            result_access_seconds: crate::public_verification_session::RESULT_ACCESS_SECONDS,
            receipt_days: PUBLIC_VERIFICATION_RECEIPT_DAYS,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicVerificationRetentionSweep {
    pub sessions: u64,
    pub nonces: u64,
    pub receipts: u64,
}

/// Runs even with public admission disabled, so rollback does not disable
/// deletion of sessions admitted by a preceding release/configuration.
pub async fn run_public_verification_retention(
    repository: PostgresFlowRepository,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RepositoryError> {
    loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Ok(());
        }
        for _ in 0..10 {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Ok(());
            }
            match repository.sweep_public_verification_retention(100).await {
                Ok(counts) => {
                    if counts.sessions + counts.nonces + counts.receipts == 0 {
                        break;
                    }
                    tracing::info!(
                        sessions = counts.sessions,
                        nonces = counts.nonces,
                        receipts = counts.receipts,
                        "public verification retention sweep"
                    );
                }
                Err(_) => {
                    // Never include SQL parameters, visitor IDs or payloads.
                    tracing::error!("public verification retention sweep failed; retry scheduled");
                    break;
                }
            }
        }
        tokio::select! {
            changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { return Ok(()); } },
            () = tokio::time::sleep(std::time::Duration::from_secs(PUBLIC_VERIFICATION_SWEEP_SECONDS)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stopped_or_closed_retention_worker_does_not_acquire_a_database_connection() {
        let repository = PostgresFlowRepository::new(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
        );
        let (sender, receiver) = watch::channel(true);
        run_public_verification_retention(repository.clone(), receiver)
            .await
            .unwrap();
        drop(sender);
        let (sender, receiver) = watch::channel(false);
        drop(sender);
        run_public_verification_retention(repository, receiver)
            .await
            .unwrap();
    }
}
