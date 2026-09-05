//! Actual worker renewal with PostgreSQL and controlled active processors.

use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};

use chrono::{DateTime, Utc};
use marty_issuance_service::canvas_sync_worker::CanvasSyncWorkerConfig;
use sqlx::PgPool;

use super::canvas_worker_lifecycle_oracle::{
    await_both_processors, controlled_cycle_with_config, ControlledCycle,
};

fn renewal_config() -> CanvasSyncWorkerConfig {
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
    config
}

pub async fn assert_generation_change_preserves_process_liveness(pool: &PgPool) {
    let ControlledCycle { worker, state, .. } =
        controlled_cycle_with_config(pool, None, renewal_config()).await;
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

// Installed only after both actual processors enter, so these probes cannot
// confuse initial leasing/heartbeats with renewal. Sequence increments survive
// statement rollback and therefore count ATTEMPTS, not successful persistence.
const WRITE_STAGES: [&str; 3] = ["lease", "target", "process"];

pub(super) async fn install_write_failure(pool: &PgPool, failed_stage: &str) {
    assert!(WRITE_STAGES.contains(&failed_stage));
    sqlx::raw_sql(
        "CREATE TABLE issuance_service.renewal_failed_stage (stage text NOT NULL);
         CREATE SEQUENCE issuance_service.renewal_lease_attempts;
         CREATE SEQUENCE issuance_service.renewal_target_attempts;
         CREATE SEQUENCE issuance_service.renewal_process_attempts;
         CREATE FUNCTION issuance_service.renewal_write_probe() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
           IF TG_ARGV[0] = 'process' THEN
             IF NEW.metadata->>'phase' IS DISTINCT FROM 'processing' THEN
               RETURN NEW;
             END IF;
           END IF;
           PERFORM nextval(TG_ARGV[1]::regclass);
           IF TG_ARGV[0] = (SELECT stage FROM issuance_service.renewal_failed_stage) THEN
             RAISE EXCEPTION 'synthetic renewal write failure';
           END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER renewal_write_probe BEFORE UPDATE OF lease_expires_at
           ON issuance_service.canvas_evidence_sync_jobs FOR EACH ROW EXECUTE FUNCTION
           issuance_service.renewal_write_probe('lease', 'issuance_service.renewal_lease_attempts');
         CREATE TRIGGER renewal_write_probe BEFORE UPDATE OF metadata
           ON issuance_service.canvas_evidence_sync_targets FOR EACH ROW EXECUTE FUNCTION
           issuance_service.renewal_write_probe('target', 'issuance_service.renewal_target_attempts');
         CREATE TRIGGER renewal_write_probe BEFORE INSERT
           ON issuance_service.canvas_worker_heartbeats FOR EACH ROW EXECUTE FUNCTION
           issuance_service.renewal_write_probe('process', 'issuance_service.renewal_process_attempts');",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO issuance_service.renewal_failed_stage (stage) VALUES ($1)")
        .bind(failed_stage)
        .execute(pool)
        .await
        .unwrap();
}

pub(super) async fn remove_write_probes(pool: &PgPool) {
    sqlx::raw_sql(
        "DROP TRIGGER renewal_write_probe ON issuance_service.canvas_evidence_sync_jobs;
         DROP TRIGGER renewal_write_probe ON issuance_service.canvas_evidence_sync_targets;
         DROP TRIGGER renewal_write_probe ON issuance_service.canvas_worker_heartbeats;
         DROP FUNCTION issuance_service.renewal_write_probe();
         DROP SEQUENCE issuance_service.renewal_lease_attempts,
                       issuance_service.renewal_target_attempts,
                       issuance_service.renewal_process_attempts;
         DROP TABLE issuance_service.renewal_failed_stage;",
    )
    .execute(pool)
    .await
    .unwrap();
}

pub async fn assert_renewal_write_failure_boundaries(pool: &PgPool) {
    for (failed_stage, expected_attempts) in [
        ("lease", [2_i64, 0, 0]),
        ("target", [2, 2, 0]),
        ("process", [2, 2, 2]),
    ] {
        let ControlledCycle { worker, state, .. } =
            controlled_cycle_with_config(pool, None, renewal_config()).await;
        let mut cycle = Box::pin(worker.run_cycle());
        await_both_processors(cycle.as_mut(), &state).await;
        let before: Vec<(String, DateTime<Utc>, String)> = sqlx::query_as(
            "SELECT j.target_id, j.lease_expires_at, t.metadata->>'worker_heartbeat_at'
             FROM issuance_service.canvas_evidence_sync_jobs j
             JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
             ORDER BY j.target_id",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(before.len(), 2);
        install_write_failure(pool, failed_stage).await;
        await_write_failure(cycle.as_mut(), pool, expected_attempts).await;
        assert_eq!(state.active.load(Ordering::SeqCst), 2);
        assert_eq!(state.cleaned.load(Ordering::SeqCst), 0);
        // Operational failure leaves processing alive; cancellation, not the
        // renewal error, now acknowledges both owned scopes. Durable partial
        // write and attempt assertions below are unchanged.
        drop(cycle);
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);

        let attempts = write_attempts(pool).await;
        for ((stage, actual), expected) in WRITE_STAGES
            .into_iter()
            .zip(attempts)
            .zip(expected_attempts)
        {
            assert_eq!(actual, expected, "failure={failed_stage}, stage={stage}");
        }
        for (target_id, lease_before, heartbeat_before) in before {
            let (lease_after, heartbeat_after, status, completed): (
                DateTime<Utc>,
                String,
                String,
                bool,
            ) = sqlx::query_as(
                "SELECT j.lease_expires_at, t.metadata->>'worker_heartbeat_at',
                        j.status, j.completed_at IS NOT NULL
                 FROM issuance_service.canvas_evidence_sync_jobs j
                 JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
                 WHERE j.target_id = $1",
            )
            .bind(target_id)
            .fetch_one(pool)
            .await
            .unwrap();
            if failed_stage == "lease" {
                assert_eq!(lease_after, lease_before);
            } else {
                assert!(
                    lease_after > lease_before,
                    "prior lease write remains committed"
                );
            }
            if failed_stage == "process" {
                assert!(
                    DateTime::parse_from_rfc3339(&heartbeat_after).unwrap()
                        > DateTime::parse_from_rfc3339(&heartbeat_before).unwrap(),
                    "target heartbeat remains committed despite process heartbeat failure"
                );
            } else {
                assert_eq!(heartbeat_after, heartbeat_before);
            }
            assert_eq!(status, "leased");
            assert!(
                !completed,
                "renewal failure is not successful job completion"
            );
        }
        remove_write_probes(pool).await;
    }
}

async fn write_attempts(pool: &PgPool) -> [i64; 3] {
    let (lease, target, process): (i64, i64, i64) = sqlx::query_as(
        "SELECT CASE WHEN l.is_called THEN l.last_value ELSE 0 END,
                CASE WHEN t.is_called THEN t.last_value ELSE 0 END,
                CASE WHEN p.is_called THEN p.last_value ELSE 0 END
         FROM issuance_service.renewal_lease_attempts l,
              issuance_service.renewal_target_attempts t,
              issuance_service.renewal_process_attempts p",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    [lease, target, process]
}

pub(super) async fn await_write_failure<F: std::future::Future>(
    mut cycle: std::pin::Pin<&mut F>,
    pool: &PgPool,
    expected: [i64; 3],
) {
    tokio::time::timeout(Duration::from_secs(25), async {
        tokio::select! {
            _ = &mut cycle => panic!("operational renewal failure discarded processing"),
            () = async {
                loop {
                    let actual = write_attempts(pool).await;
                    assert!(actual.iter().zip(expected).all(|(a, e)| *a <= e), "unexpected renewal attempts: {actual:?}");
                    if actual == expected { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } => {}
        }
    }).await.expect("real configured renewal writes must be attempted");
    // Drive the actual cycle after the failing statements, without restarting
    // it or treating an observation timeout as process completion.
    assert!(tokio::time::timeout(Duration::from_millis(20), cycle)
        .await
        .is_err());
}
