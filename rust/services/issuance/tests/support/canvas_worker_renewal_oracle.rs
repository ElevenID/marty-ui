//! Actual worker renewal with PostgreSQL and controlled active processors.

use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};

use chrono::{DateTime, Utc};
use marty_issuance_service::canvas_sync_worker::CanvasSyncWorkerConfig;
use sqlx::PgPool;

use super::canvas_worker_lifecycle_oracle::{
    await_both_processors, controlled_cycle_with_config, ControlledCycle,
};

pub async fn assert_generation_change_preserves_process_liveness(pool: &PgPool) {
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        (
            "CANVAS_SYNC_WORKER_ID".to_owned(),
            "renewal-oracle".to_owned(),
        ),
        (
            "CANVAS_SYNC_WORKER_LEASE_SECONDS".to_owned(),
            "30".to_owned(),
        ),
    ]))
    .unwrap();
    assert_eq!(config.lease_renewal_interval(), Duration::from_secs(10));
    let ControlledCycle { worker, state, .. } =
        controlled_cycle_with_config(pool, None, config).await;
    let mut cycle = Box::pin(worker.run_cycle());
    await_both_processors(cycle.as_mut(), &state).await;
    // The frozen Python repository serializes heartbeat_at.isoformat().
    // A PostgreSQL display-format string is not the portable wire timestamp.
    let target_heartbeats: Vec<String> = sqlx::query_scalar(
        "SELECT metadata->>'worker_heartbeat_at'
         FROM issuance_service.canvas_evidence_sync_targets ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(target_heartbeats.len(), 2);
    for value in target_heartbeats {
        DateTime::parse_from_rfc3339(&value)
            .expect("actual target heartbeat must retain the legacy ISO timestamp shape");
    }
    let (heartbeat_before,): (DateTime<Utc>,) = sqlx::query_as(
        "SELECT last_heartbeat_at FROM issuance_service.canvas_worker_heartbeats
         WHERE worker_id = 'renewal-oracle'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let (lease_before,): (DateTime<Utc>,) = sqlx::query_as(
        "SELECT max(lease_expires_at) FROM issuance_service.canvas_evidence_sync_jobs",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = config_version + 1, metadata = '{}'::jsonb",
    )
    .execute(pool)
    .await
    .unwrap();

    // No fake clock/renewal/cycle: wait for both real minimum-ten-second renewals.
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                _ = &mut cycle => panic!("processors must remain active during renewal"),
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
            let renewed: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs
                 WHERE lease_expires_at > $1 AND status = 'leased'",
            )
            .bind(lease_before)
            .fetch_one(pool)
            .await
            .unwrap();
            if renewed == 2 {
                break;
            }
        }
    })
    .await
    .expect("both durable leases must renew after the target generation changes");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                _ = &mut cycle => panic!("cycle must remain active after renewal"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            let advanced: bool = sqlx::query_scalar(
                "SELECT last_heartbeat_at > $1
                 FROM issuance_service.canvas_worker_heartbeats WHERE worker_id = 'renewal-oracle'",
            )
            .bind(heartbeat_before)
            .fetch_one(pool)
            .await
            .unwrap();
            if advanced {
                break;
            }
        }
    })
    .await
    .expect("target CAS loss must not suppress renewed process liveness");

    let fenced_targets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_evidence_sync_targets
         WHERE config_version = 4 AND NOT (metadata ? 'worker_heartbeat_at')",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        fenced_targets, 2,
        "new target generation must not receive stale heartbeat writes"
    );
    assert_eq!(state.active.load(Ordering::SeqCst), 2);
    drop(cycle);
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);
    let incomplete: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs
         WHERE status = 'leased' AND completed_at IS NULL",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(incomplete, 2, "renewal/cancellation is not job completion");
    eprintln!("actual PostgreSQL renewal: target-generation fence and process liveness passed");
}
