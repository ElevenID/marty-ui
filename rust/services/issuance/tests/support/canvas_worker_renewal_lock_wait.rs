//! Ignored real-repository diagnostic, NOT whole-worker or published parity.
//! A lock-only transaction delays the actual renewal statement. No lease, job,
//! target, deadline, clock, trigger, or runtime implementation is rewritten.
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use marty_issuance_service::{
    canvas_sync_worker::CanvasSyncWorkerRepository,
    canvas_sync_worker_lifecycle::worker_pool_options,
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool, Postgres, Transaction};
use std::{panic::AssertUnwindSafe, time::Duration};
use tokio::{task::JoinSet, time::Instant};

const OWNER: &str = "renewal-lock-owner";
const APPLICATION: &str = "canvas-renewal-lock-diagnostic";
const TARGET: &str = "renewal-lock-target";
type Checked<T> = Result<T, &'static str>;

fn require(condition: bool, message: &'static str) -> Checked<()> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}

struct Observation {
    job: Value,
    targets: Value,
    database_now: DateTime<Utc>,
    before: Instant,
    after: Instant,
}

async fn observe(pool: &PgPool, id: &str) -> Checked<Observation> {
    let before = Instant::now();
    let (job, targets, database_now): (Value, Value, DateTime<Utc>) = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_as(
            "SELECT to_jsonb(j),
                 (SELECT jsonb_agg(to_jsonb(t) ORDER BY id)
                  FROM issuance_service.canvas_evidence_sync_targets t),
                 clock_timestamp()
             FROM issuance_service.canvas_evidence_sync_jobs j
             WHERE j.id=$1 AND j.organization_id='org-1'",
        )
        .bind(id)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| "renewal diagnostic observation exceeded its bound")?
    .map_err(|_| "renewal diagnostic observation failed")?;
    let after = Instant::now();
    require(
        after.duration_since(before) <= Duration::from_millis(500),
        "renewal diagnostic observation exceeded its bound",
    )?;
    Ok(Observation {
        job,
        targets,
        database_now,
        before,
        after,
    })
}

fn validate_clock(sample: &Observation, origin: &Observation) -> Checked<()> {
    let elapsed = sample
        .database_now
        .signed_duration_since(origin.database_now)
        .num_microseconds()
        .ok_or("renewal diagnostic clock range exceeded")? as f64
        / 1_000_000.0;
    let lower = sample
        .before
        .checked_duration_since(origin.after)
        .ok_or("renewal diagnostic clock order changed")?
        .as_secs_f64();
    let upper = sample.after.duration_since(origin.before).as_secs_f64();
    require(
        elapsed >= lower - 0.5 && elapsed <= upper + 0.5,
        "renewal diagnostic database and monotonic clocks disagree",
    )
}

fn validate_blocker(row: (i64, i64), blocker: i32, operation: i32) -> Checked<()> {
    require(
        blocker > 1 && operation > 1 && blocker != operation,
        "renewal diagnostic backend identity invalid",
    )?;
    require(
        row == (1, 1),
        "renewal diagnostic exact blocked operation missing",
    )
}

async fn blocked(pool: &PgPool, blocker: i32, operation: i32) -> Checked<bool> {
    let before = Instant::now();
    let counts: (i64, i64) = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_as(
            "SELECT count(*), count(*) FILTER (
             WHERE pid=$2 AND application_name=$3 AND state='active'
               AND wait_event_type='Lock'
               AND query LIKE 'UPDATE issuance_service.canvas_evidence_sync_jobs%'
               AND query LIKE '%SET lease_expires_at = $5%')
         FROM pg_stat_activity
         WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))",
        )
        .bind(blocker)
        .bind(operation)
        .bind(APPLICATION)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| "renewal diagnostic blocker observation timed out")?
    .map_err(|_| "renewal diagnostic blocker observation failed")?;
    require(
        before.elapsed() <= Duration::from_millis(500),
        "renewal diagnostic blocker observation timed out",
    )?;
    if counts == (0, 0) {
        return Ok(false);
    }
    validate_blocker(counts, blocker, operation)?;
    Ok(true)
}

fn without_renewal_fields(job: &Value) -> Checked<Value> {
    let mut fields = job
        .as_object()
        .ok_or("renewal diagnostic job shape invalid")?
        .clone();
    require(
        fields.remove("lease_expires_at").is_some() && fields.remove("updated_at").is_some(),
        "renewal diagnostic job fields missing",
    )?;
    Ok(Value::Object(fields))
}

async fn experiment<'a>(
    pool: &'a PgPool,
    operation_pool: &PgPool,
    blocker: &mut Option<Transaction<'a, Postgres>>,
    tasks: &mut JoinSet<Checked<bool>>,
    crosses_expiry: bool,
) -> Checked<Value> {
    let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    require(
        repository
            .enqueue_due(&1_u64.into())
            .await
            .map_err(|_| "renewal diagnostic scheduling failed")?
            == 1,
        "renewal diagnostic must schedule exactly one job",
    )?;
    let jobs = repository
        .lease_ready(OWNER, &1_u64.into(), &30_u64.into())
        .await
        .map_err(|_| "renewal diagnostic legitimate leasing failed")?;
    require(
        jobs.len() == 1,
        "renewal diagnostic must lease exactly one job",
    )?;
    let job = jobs
        .into_iter()
        .next()
        .ok_or("renewal diagnostic leased job missing")?;
    require(
        job.organization_id == "org-1"
            && job.target_id == TARGET
            && job.attempt_count == 1
            && job.lease_owner.as_deref() == Some(OWNER),
        "renewal diagnostic leased generation differs",
    )?;
    let expires = job
        .lease_expires_at
        .ok_or("renewal diagnostic original expiry missing")?;
    let origin = observe(pool, &job.id).await?;
    require(
        expires > origin.database_now
            && expires.signed_duration_since(origin.database_now) >= chrono::Duration::seconds(29),
        "renewal diagnostic original lease is not fresh",
    )?;
    let anchor = origin.after;

    *blocker = Some(
        pool.begin()
            .await
            .map_err(|_| "renewal diagnostic blocker could not begin")?,
    );
    let transaction = blocker
        .as_mut()
        .ok_or("renewal diagnostic blocker missing")?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| "renewal diagnostic blocker timeout setup failed")?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "renewal diagnostic blocker identity unavailable")?;
    let locked: String = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar(
            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs
         WHERE id=$1 AND organization_id='org-1' AND target_id=$2 FOR UPDATE",
        )
        .bind(&job.id)
        .bind(TARGET)
        .fetch_one(&mut **transaction),
    )
    .await
    .map_err(|_| "renewal diagnostic lock acquisition timed out")?
    .map_err(|_| "renewal diagnostic lock acquisition failed")?;
    require(
        locked == job.id,
        "renewal diagnostic locked a different job",
    )?;
    let operation_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(operation_pool)
        .await
        .map_err(|_| "renewal diagnostic operation identity unavailable")?;
    require(
        blocker_pid > 1 && operation_pid > 1 && blocker_pid != operation_pid,
        "renewal diagnostic backend identity invalid",
    )?;

    tokio::time::sleep_until(anchor + Duration::from_secs(10)).await;
    let renewal_repository = PostgresCanvasSyncWorkerRepository::new(operation_pool.clone());
    let renewed_job = job.clone();
    tasks.spawn(async move {
        require(
            anchor.elapsed() >= Duration::from_secs(10)
                && anchor.elapsed() <= Duration::from_millis(10_500),
            "renewal diagnostic missed the predeclared renewal start",
        )?;
        renewal_repository
            .renew_lease(&renewed_job, OWNER, &30_u64.into())
            .await
            .map_err(|_| "renewal diagnostic repository renewal failed")
    });
    let mut saw_blocked = false;
    loop {
        require(
            anchor.elapsed() < Duration::from_secs(34),
            "renewal diagnostic did not reach lock release",
        )?;
        let sample = observe(pool, &job.id).await?;
        validate_clock(&sample, &origin)?;
        require(
            sample.job == origin.job && sample.targets == origin.targets,
            "renewal diagnostic locked rows changed",
        )?;
        let waiting = blocked(pool, blocker_pid, operation_pid).await?;
        require(
            !saw_blocked || waiting,
            "renewal diagnostic operation left the blocker early",
        )?;
        saw_blocked |= waiting;
        let release_due = if crosses_expiry {
            sample.database_now >= expires + chrono::Duration::seconds(1)
        } else {
            anchor.elapsed() >= Duration::from_secs(12)
        };
        if release_due {
            require(
                waiting && saw_blocked,
                "renewal diagnostic renewal was not actually blocked",
            )?;
            let before = observe(pool, &job.id).await?;
            validate_clock(&before, &origin)?;
            let transaction = blocker.take().ok_or("renewal diagnostic blocker missing")?;
            tokio::time::timeout(Duration::from_secs(2), transaction.rollback())
                .await
                .map_err(|_| "renewal diagnostic release rollback timed out")?
                .map_err(|_| "renewal diagnostic release rollback failed")?;
            let after = observe(pool, &job.id).await?;
            validate_clock(&after, &origin)?;
            require(
                after.after.duration_since(before.before) <= Duration::from_millis(500),
                "renewal diagnostic release bracket too wide",
            )?;
            if crosses_expiry {
                require(
                    before.database_now >= expires + chrono::Duration::seconds(1)
                        && after.database_now <= expires + chrono::Duration::seconds(2),
                    "renewal diagnostic release did not cross original expiry in its fixed band",
                )?;
            } else {
                require(
                    before.before.duration_since(anchor) >= Duration::from_millis(11_500)
                        && after.after.duration_since(anchor) <= Duration::from_millis(12_500)
                        && after.database_now < expires,
                    "renewal diagnostic early release missed its fixed current-lease band",
                )?;
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let renewed = tokio::time::timeout(Duration::from_secs(5), tasks.join_next())
        .await
        .map_err(|_| "renewal diagnostic operation did not finish after release")?
        .ok_or("renewal diagnostic owned task missing")?
        .map_err(|_| "renewal diagnostic owned task failed")??;
    let final_state = observe(pool, &job.id).await?;
    validate_clock(&final_state, &origin)?;
    require(
        without_renewal_fields(&final_state.job)? == without_renewal_fields(&origin.job)?
            && final_state.targets == origin.targets,
        "renewal diagnostic changed non-renewal state",
    )?;
    let final_expiry = final_state.job["lease_expires_at"]
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or("renewal diagnostic final expiry invalid")?;
    if renewed {
        require(
            final_expiry > expires,
            "renewal diagnostic accepted without advancing expiry",
        )?;
    } else {
        require(
            final_state.job == origin.job,
            "renewal diagnostic rejection changed the job",
        )?;
    }
    let current = final_expiry > final_state.database_now;
    if !crosses_expiry {
        require(
            renewed && current,
            "renewal diagnostic early positive control failed",
        )?;
    }
    Ok(json!({
        "schema":"marty.canvas-worker-renewal-lock-wait-diagnostic/v1",
        "case":if crosses_expiry {"renewal_lock_crosses_expiry"} else {"renewal_lock_early_release"},
        "scope":"real-repository-only-not-process-parity",
        "renewed":renewed,
        "lease_current_after_operation":current,
        "original_expired_before_release":crosses_expiry,
        "expiry_advanced":final_expiry > expires,
        "expiry_delta_milliseconds":final_expiry.signed_duration_since(expires).num_milliseconds(),
        "remaining_lease_milliseconds":final_expiry.signed_duration_since(final_state.database_now).num_milliseconds(),
        "exact_blocked_backend_observed":saw_blocked,
        "identity_attempt_start_result_and_target_preserved":true,
    }))
}

pub(super) async fn run(pool: &PgPool, database_url: &str, crosses_expiry: bool) -> Checked<Value> {
    let options: PgConnectOptions = database_url
        .parse()
        .map_err(|_| "renewal diagnostic connection configuration invalid")?;
    let operation_pool = tokio::time::timeout(
        Duration::from_secs(5),
        worker_pool_options()
            .max_connections(1)
            .connect_with(options.application_name(APPLICATION)),
    )
    .await
    .map_err(|_| "renewal diagnostic operation pool connection timed out")?
    .map_err(|_| "renewal diagnostic operation pool connection failed")?;
    let mut blocker = None;
    let mut tasks = JoinSet::new();
    // Convert panics only after unwinding the experiment, then attempt every
    // exact owned cleanup. No task may detach when a timing assertion fails.
    let result = AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(45),
        experiment(
            pool,
            &operation_pool,
            &mut blocker,
            &mut tasks,
            crosses_expiry,
        ),
    ))
    .catch_unwind()
    .await;
    let result = result
        .map_err(|_| "renewal diagnostic experiment panicked")
        .and_then(|value| value.map_err(|_| "renewal diagnostic experiment timed out"))
        .and_then(|value| value);
    let rollback_ok = if let Some(transaction) = blocker.take() {
        matches!(
            tokio::time::timeout(Duration::from_secs(3), transaction.rollback()).await,
            Ok(Ok(()))
        )
    } else {
        true
    };
    tasks.abort_all();
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    let closed = tokio::time::timeout(Duration::from_secs(5), operation_pool.close())
        .await
        .is_ok();
    // Preserve the first fixed failure category; cleanup cannot expose the
    // private SQLx error or overwrite it with a secondary disposal failure.
    let observation = result?;
    require(
        rollback_ok && joined && closed,
        "renewal diagnostic owned cleanup failed",
    )?;
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock_sample(
        anchor: Instant,
        before_milliseconds: u64,
        after_milliseconds: u64,
        database_microseconds: i64,
    ) -> Observation {
        Observation {
            job: json!({}),
            targets: json!([]),
            database_now: DateTime::parse_from_rfc3339("2026-09-08T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
                + chrono::Duration::microseconds(database_microseconds),
            before: anchor + Duration::from_millis(before_milliseconds),
            after: anchor + Duration::from_millis(after_milliseconds),
        }
    }

    #[test]
    fn clock_agreement_uses_both_query_brackets_and_rejects_drift() {
        let anchor = Instant::now();
        let origin = clock_sample(anchor, 0, 100, 0);
        // Monotonic elapsed is [9.9, 10.1], with the existing 0.5s
        // agreement allowance. Test its exact edges, not only its midpoint.
        for micros in [9_400_000, 10_000_000, 10_600_000] {
            assert!(validate_clock(&clock_sample(anchor, 10_000, 10_100, micros), &origin).is_ok());
        }
        for micros in [8_000_000, 9_399_999, 10_600_001, 12_000_000] {
            assert_eq!(
                validate_clock(&clock_sample(anchor, 10_000, 10_100, micros), &origin),
                Err("renewal diagnostic database and monotonic clocks disagree")
            );
        }
    }

    #[test]
    fn clock_sample_cannot_precede_the_completed_origin_observation() {
        let anchor = Instant::now();
        let origin = clock_sample(anchor, 1_000, 1_100, 0);
        for (before, after) in [(0, 100), (1_000, 1_050), (1_099, 1_200)] {
            assert_eq!(
                validate_clock(&clock_sample(anchor, before, after, 0), &origin),
                Err("renewal diagnostic clock order changed")
            );
        }
        // Adjacent non-overlapping reads are a valid boundary, not reversal.
        assert!(validate_clock(&clock_sample(anchor, 1_100, 1_200, 100_000), &origin).is_ok());
    }

    fn diagnostic_job() -> Value {
        json!({
            "id":"job-1", "organization_id":"org-1", "target_id":"target-1",
            "status":"leased", "attempt_count":1, "max_attempts":8,
            "lease_owner":"owner-1", "started_at":"original-start",
            "available_at":"original-available", "created_at":"original-created",
            "completed_at":null, "last_error_code":null, "last_error_summary":null,
            "result":{"target_config_version":3},
            "lease_expires_at":"original-expiry", "updated_at":"original-update"
        })
    }

    #[test]
    fn preservation_projection_ignores_only_the_two_renewal_fields() {
        let original = diagnostic_job();
        let expected = without_renewal_fields(&original).unwrap();
        let mut renewed = original.clone();
        renewed["lease_expires_at"] = json!("later-expiry");
        renewed["updated_at"] = json!("later-update");
        assert_eq!(without_renewal_fields(&renewed).unwrap(), expected);
        assert_eq!(
            original,
            diagnostic_job(),
            "projection must not mutate its input"
        );

        for (key, changed_value) in [
            ("id", json!("different-job")),
            ("organization_id", json!("different-org")),
            ("target_id", json!("different-target")),
            ("status", json!("succeeded")),
            ("attempt_count", json!(2)),
            ("max_attempts", json!(1)),
            ("lease_owner", Value::Null),
            ("started_at", json!("different-start")),
            ("result", json!({"target_config_version":4})),
            ("last_error_code", json!("unexpected-error")),
            ("future_runtime_field", json!({"must_not_disappear":true})),
        ] {
            let mut changed = renewed.clone();
            changed[key] = changed_value;
            assert_ne!(
                without_renewal_fields(&changed).unwrap(),
                expected,
                "non-renewal field changes must remain observable"
            );
        }
        let mut missing_identity = renewed;
        missing_identity.as_object_mut().unwrap().remove("id");
        assert_ne!(without_renewal_fields(&missing_identity).unwrap(), expected);
    }

    #[test]
    fn preservation_projection_rejects_missing_fields_and_private_nonobjects_statically() {
        for absent in ["lease_expires_at", "updated_at"] {
            let mut missing = diagnostic_job();
            missing.as_object_mut().unwrap().remove(absent);
            assert_eq!(
                without_renewal_fields(&missing),
                Err("renewal diagnostic job fields missing")
            );
        }
        for invalid in [
            Value::Null,
            json!([]),
            json!("private-row-payload"),
            json!(true),
        ] {
            assert_eq!(
                without_renewal_fields(&invalid),
                Err("renewal diagnostic job shape invalid")
            );
        }
    }

    #[test]
    fn blocker_requires_exact_single_distinct_owned_backend() {
        assert!(validate_blocker((1, 1), 10, 11).is_ok());
        for (row, blocker, operation) in [
            ((0, 0), 10, 11),
            ((1, 0), 10, 11),
            ((2, 1), 10, 11),
            ((2, 2), 10, 11),
            ((1, 1), 10, 10),
            ((1, 1), 1, 11),
            ((1, 1), 10, 0),
        ] {
            assert!(validate_blocker(row, blocker, operation).is_err());
        }
    }
}
