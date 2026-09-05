//! Explicit per-job identity for transactional Canvas processor effects.

use sqlx::{Postgres, Transaction};

use crate::canvas_sync_worker::{
    CanvasSyncJob, CanvasSyncJobStatus, CanvasSyncProcessingError, CanvasSyncRepositoryError,
};

pub(crate) fn lease_lost() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::retryable(
        "canvas_sync_lease_lost",
        "Canvas synchronization no longer owns its job lease",
    )
}

/// An identity to reauthorize against durable state, not a cached grant.
/// Never contains a provider credential or a locally trusted expiry timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasSyncLease {
    pub(crate) job_id: String,
    pub(crate) organization_id: String,
    pub(crate) target_id: String,
    pub(crate) worker_id: String,
    pub(crate) attempt_count: i32,
}

impl CanvasSyncLease {
    pub fn from_job(
        job: &CanvasSyncJob,
        worker_id: &str,
    ) -> Result<Self, CanvasSyncRepositoryError> {
        if job.status != CanvasSyncJobStatus::Leased
            || job.lease_owner.as_deref() != Some(worker_id)
            || worker_id.is_empty()
            || job.id.is_empty()
            || job.organization_id.is_empty()
            || job.target_id.is_empty()
            || job.attempt_count < 1
        {
            return Err(CanvasSyncRepositoryError::InvalidState);
        }
        Ok(Self {
            job_id: job.id.clone(),
            organization_id: job.organization_id.clone(),
            target_id: job.target_id.clone(),
            worker_id: worker_id.to_owned(),
            attempt_count: job.attempt_count,
        })
    }

    /// Lock the job before resource rows, matching completion/recovery ordering.
    /// Check the database clock AFTER acquiring the lock; lock waits must not
    /// authorize a write using a timestamp evaluated before the wait.
    pub(crate) async fn lock_current(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: &str,
        target_id: &str,
    ) -> Result<bool, sqlx::Error> {
        if self.organization_id != organization_id || self.target_id != target_id {
            return Ok(false);
        }
        let locked: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM issuance_service.canvas_evidence_sync_jobs
             WHERE id = $1 AND organization_id = $2 AND target_id = $3 FOR UPDATE",
        )
        .bind(&self.job_id)
        .bind(&self.organization_id)
        .bind(&self.target_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if locked.is_none() {
            return Ok(false);
        }
        sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM issuance_service.canvas_evidence_sync_jobs
                WHERE id = $1 AND organization_id = $2 AND target_id = $3
                  AND status = 'leased' AND lease_owner = $4 AND attempt_count = $5
                  AND lease_expires_at > clock_timestamp())",
        )
        .bind(&self.job_id)
        .bind(&self.organization_id)
        .bind(&self.target_id)
        .bind(&self.worker_id)
        .bind(self.attempt_count)
        .fetch_one(&mut **transaction)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn lease_context_requires_a_complete_owned_job_identity() {
        let now = Utc::now();
        let job = CanvasSyncJob {
            id: "job".into(),
            organization_id: "org".into(),
            target_id: "target".into(),
            target_config_version: 3,
            status: CanvasSyncJobStatus::Leased,
            attempt_count: 1,
            max_attempts: 8,
            available_at: now,
            lease_owner: Some("worker".into()),
            lease_expires_at: None,
            created_at: now,
            started_at: Some(now),
        };
        let lease = CanvasSyncLease::from_job(&job, "worker").unwrap();
        assert_eq!(lease.job_id, job.id);
        assert_eq!(lease.organization_id, job.organization_id);
        assert_eq!(lease.target_id, job.target_id);
        assert_eq!(lease.attempt_count, job.attempt_count);
        // This identity never confers authorization from the local expiry;
        // every real transaction checks the current durable lease and DB clock.
        for field in [
            "job",
            "organization",
            "target",
            "owner",
            "status",
            "attempt",
        ] {
            let mut invalid = job.clone();
            match field {
                "job" => invalid.id.clear(),
                "organization" => invalid.organization_id.clear(),
                "target" => invalid.target_id.clear(),
                "owner" => invalid.lease_owner = None,
                "status" => invalid.status = CanvasSyncJobStatus::Succeeded,
                "attempt" => invalid.attempt_count = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                CanvasSyncLease::from_job(&invalid, "worker"),
                Err(CanvasSyncRepositoryError::InvalidState),
                "{field}"
            );
        }
        assert!(CanvasSyncLease::from_job(&job, "another-worker").is_err());
        assert!(CanvasSyncLease::from_job(&job, "").is_err());
    }
}
