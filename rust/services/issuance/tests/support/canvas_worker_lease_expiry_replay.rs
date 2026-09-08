//! Real native worker/provider renewal-lock observation. Never changes runtime
//! fences or live job/lease/clock values. A diagnostic mismatch is not parity.
use super::{
    canvas_worker_output::OwnedOutput,
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::snapshot,
    canvas_worker_rest_replay::{prepare, validation_scenarios, worker_environment, WorkerFixture},
};
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use std::{
    fs::File,
    io::Write,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tokio::time::{Duration, Instant};

const JOB: &str = "worker-validation-job";
// The shared launcher also uses this ID as the PostgreSQL application name.
// Keep the observer and frozen lease/target identity on that same owner.
const WORKER_ID: &str = "worker-rest";
const CASES: [&str; 2] = ["renewal_lock_early_release", "renewal_lock_crosses_expiry"];
type Checked<T> = Result<T, &'static str>;

// Only closed, payload-free categories are emitted. The parent never forwards
// Rust panic text, arbitrary error messages, database rows or timing values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Diagnostic {
    AwaitRequest,
    VerifyInitial,
    LockHeld,
    ReleaseDue,
    VerifyHeldState,
    VerifyEffects,
    SampleBeforeRollback,
    Rollback,
    SampleAfterRollback,
    CheckReleaseBand,
    ObserveOutcome,
    PublishOutcome,
    AwaitLateWindow,
    VerifyJoinedState,
    VerifyShutdown,
    Complete,
    FailureClockAgreement,
    FailureClockOrder,
    FailureRenewalBlocker,
    FailureRenewalNotObserved,
    FailureRenewalLeftLock,
    FailureHeldState,
    FailureLockedJob,
    FailurePreReleaseJob,
    FailureEffects,
    FailureReleaseBracket,
    FailureEarlyBand,
    FailureExpiryBand,
    FailureLeasedIdentity,
    FailureJobGeneration,
    FailureTerminalLease,
    FailureJobQuery,
    FailureShutdownWait,
    FailureShutdownStatus,
    FailurePostShutdownState,
    FailureOutput,
    FailureParity,
    FailureUnknown,
}

fn emit_diagnostic(category: Diagnostic) {
    eprintln!("MARTY_EXPIRY_DIAG_V1:{category:?}");
}

fn failure_diagnostic(reason: &str) -> Diagnostic {
    match reason {
        "native expiry database and monotonic clocks disagree" => Diagnostic::FailureClockAgreement,
        "native expiry clock ordering invalid" | "native expiry clock range invalid" => {
            Diagnostic::FailureClockOrder
        }
        "native expiry exact renewal blocker differs" => Diagnostic::FailureRenewalBlocker,
        "native expiry renewal never reached the owned blocker" => {
            Diagnostic::FailureRenewalNotObserved
        }
        "native expiry renewal left owned lock" => Diagnostic::FailureRenewalLeftLock,
        "native expiry held state differs from reference" => Diagnostic::FailureHeldState,
        "native expiry locked job changed" => Diagnostic::FailureLockedJob,
        "native expiry pre-release generation changed" => Diagnostic::FailurePreReleaseJob,
        "native expiry incomplete body changed business effects" => Diagnostic::FailureEffects,
        "native expiry release clock bracket too wide" => Diagnostic::FailureReleaseBracket,
        "native expiry early release missed current-lease band" => Diagnostic::FailureEarlyBand,
        "native expiry release missed original database expiry band" => {
            Diagnostic::FailureExpiryBand
        }
        "native expiry leased identity or original fence changed" => {
            Diagnostic::FailureLeasedIdentity
        }
        "native expiry original job generation changed" => Diagnostic::FailureJobGeneration,
        "native expiry terminal lease was not cleared" => Diagnostic::FailureTerminalLease,
        "native expiry narrow job query timed out"
        | "native expiry narrow job query failed"
        | "native expiry narrow query too wide" => Diagnostic::FailureJobQuery,
        "native expiry worker shutdown wait failed" => Diagnostic::FailureShutdownWait,
        "native expiry worker shutdown status differs" => Diagnostic::FailureShutdownStatus,
        "native expiry post-shutdown state verification failed" => {
            Diagnostic::FailurePostShutdownState
        }
        "native expiry output requires separate closed classification" => Diagnostic::FailureOutput,
        "native expiry full outcome differs from frozen published behavior" => {
            Diagnostic::FailureParity
        }
        _ => Diagnostic::FailureUnknown,
    }
}

fn require(condition: bool, message: &'static str) -> Checked<()> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}

fn matrix() -> &'static Value {
    static INPUT: OnceLock<Value> = OnceLock::new();
    INPUT.get_or_init(|| {
        let mut value: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-lease-expiry-scenarios.json"
        ))
        .unwrap();
        let body: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-body-timeout-scenarios.json"
        ))
        .unwrap();
        let state: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-deadline-scenarios.json"
        ))
        .unwrap();
        for key in ["application_seed", "target_sql"] {
            value[key] = body[key].clone();
        }
        for key in ["effect_rows_sql", "operational_rows_sql"] {
            value[key] = state[key].clone();
        }
        value
    })
}

fn reference(name: &str) -> Checked<&'static Value> {
    static REPORTS: OnceLock<Value> = OnceLock::new();
    let reports = REPORTS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-lease-expiry-oracle.json"
        ))
        .unwrap()
    });
    let reports = reports
        .as_array()
        .ok_or("native expiry reference shape invalid")?;
    require(reports.len() == 2, "native expiry reference cases missing")?;
    for (report, case) in reports.iter().zip(CASES) {
        require(
            report["status"] == "passed"
                && report["worker_lease_expiry"]["case"] == case
                && report["worker_lease_expiry"]["schema"]
                    == "marty.canvas-worker-lease-expiry-observation/v1",
            "native expiry reference identity differs",
        )?;
    }
    reports
        .iter()
        .map(|row| &row["worker_lease_expiry"])
        .find(|row| row["case"] == name)
        .ok_or("native expiry reference selection missing")
}

fn control_directory() -> Checked<PathBuf> {
    let supplied = std::env::var("MARTY_CANVAS_WORKER_LEASE_EXPIRY_CONTROL")
        .map_err(|_| "native expiry control missing")?;
    let control = PathBuf::from(supplied)
        .canonicalize()
        .map_err(|_| "native expiry control invalid")?;
    let certificate = PathBuf::from(
        std::env::var("SSL_CERT_FILE").map_err(|_| "native expiry certificate missing")?,
    )
    .canonicalize()
    .map_err(|_| "native expiry certificate invalid")?;
    require(
        control.is_dir()
            && control
                .file_name()
                .is_some_and(|name| name == "native-control")
            && !control.starts_with(
                certificate
                    .parent()
                    .ok_or("native expiry certificate owner missing")?,
            ),
        "native expiry control must outlive the certificate owner",
    )?;
    Ok(control)
}

fn marker(control: &Path, name: &str) -> Checked<PathBuf> {
    require(
        matches!(
            name,
            "request-received"
                | "before-release-verified"
                | "outcome-observed"
                | "late-window-complete"
                | "late-window-verified"
                | "handlers-joined"
                | "child-done"
        ),
        "native expiry marker invalid",
    )?;
    Ok(control.join(name))
}

fn mark(control: &Path, name: &str) -> Checked<()> {
    File::create_new(marker(control, name)?).map_err(|_| "native expiry marker creation failed")?;
    Ok(())
}

fn alive(worker: &mut OwnedWorker) -> Checked<()> {
    require(
        worker
            .0
            .try_wait()
            .map_err(|_| "native expiry worker liveness failed")?
            .is_none(),
        "native expiry worker exited early",
    )
}

async fn await_marker(
    control: &Path,
    name: &str,
    worker: &mut OwnedWorker,
    seconds: u64,
) -> Checked<()> {
    let path = marker(control, name)?;
    tokio::time::timeout(Duration::from_secs(seconds), async {
        while !path.is_file() {
            alive(worker)?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        require(
            !path.is_symlink(),
            "native expiry marker is not an owned regular file",
        )?;
        alive(worker)
    })
    .await
    .map_err(|_| "native expiry parent handshake timed out")?
}

struct PendingOutcome(Option<PathBuf>);
impl Drop for PendingOutcome {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn publish(control: &Path, value: &Value) -> Checked<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| "native expiry outcome encoding failed")?;
    require(
        bytes.len() <= 512,
        "native expiry outcome exceeded its bound",
    )?;
    let pending = control
        .parent()
        .ok_or("native expiry control owner missing")?
        .join("expiry-outcome.pending");
    let mut file =
        File::create_new(&pending).map_err(|_| "native expiry pending outcome creation failed")?;
    let mut owner = PendingOutcome(Some(pending));
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .map_err(|_| "native expiry outcome write failed")?;
    drop(file);
    std::fs::hard_link(
        owner
            .0
            .as_ref()
            .ok_or("native expiry pending owner missing")?,
        marker(control, "outcome-observed")?,
    )
    .map_err(|_| "native expiry outcome publication failed")?;
    std::fs::remove_file(
        owner
            .0
            .take()
            .ok_or("native expiry pending owner missing")?,
    )
    .map_err(|_| "native expiry pending outcome cleanup failed")?;
    Ok(())
}

struct JobSample {
    row: Value,
    expires: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    before: Instant,
    after: Instant,
}

async fn read_job(pool: &PgPool) -> Checked<JobSample> {
    let before = Instant::now();
    let (row, expires, now): (Value, Option<DateTime<Utc>>, DateTime<Utc>) = tokio::time::timeout(
        Duration::from_millis(500), sqlx::query_as(
            "SELECT to_jsonb(j), lease_expires_at, clock_timestamp()
             FROM issuance_service.canvas_evidence_sync_jobs j WHERE id=$1 AND organization_id='org-review'"
        ).bind(JOB).fetch_one(pool)).await
        .map_err(|_| "native expiry narrow job query timed out")?
        .map_err(|_| "native expiry narrow job query failed")?;
    let after = Instant::now();
    require(
        after.duration_since(before) <= Duration::from_millis(500),
        "native expiry narrow query too wide",
    )?;
    Ok(JobSample {
        row,
        expires,
        now,
        before,
        after,
    })
}

fn validate_clock(sample: &JobSample, origin: &JobSample) -> Checked<()> {
    let elapsed = sample
        .now
        .signed_duration_since(origin.now)
        .num_microseconds()
        .ok_or("native expiry clock range invalid")? as f64
        / 1_000_000.0;
    let lo = sample
        .before
        .checked_duration_since(origin.after)
        .ok_or("native expiry clock ordering invalid")?
        .as_secs_f64();
    let hi = sample.after.duration_since(origin.before).as_secs_f64();
    require(
        elapsed >= lo - 0.5 && elapsed <= hi + 0.5,
        "native expiry database and monotonic clocks disagree",
    )
}

fn status(sample: &JobSample, initial: &JobSample) -> Checked<&'static str> {
    for key in [
        "id",
        "organization_id",
        "target_id",
        "attempt_count",
        "started_at",
        "created_at",
    ] {
        require(
            sample.row.get(key) == initial.row.get(key),
            "native expiry original job generation changed",
        )?;
    }
    let state = match sample.row["status"].as_str() {
        Some("leased") => "leased",
        Some("succeeded") => "succeeded",
        Some("retry") => "retry",
        Some("dead_letter") => "dead_letter",
        _ => return Err("native expiry job status unknown"),
    };
    if state == "leased" {
        let mut current = sample
            .row
            .as_object()
            .ok_or("native expiry job shape invalid")?
            .clone();
        let mut original = initial
            .row
            .as_object()
            .ok_or("native expiry original job shape invalid")?
            .clone();
        for key in ["lease_expires_at", "updated_at"] {
            current.remove(key);
            original.remove(key);
        }
        require(
            current == original && sample.expires.is_some() && sample.expires >= initial.expires,
            "native expiry leased identity or original fence changed",
        )?;
    } else {
        require(
            sample.expires.is_none() && sample.row["lease_owner"].is_null(),
            "native expiry terminal lease was not cleared",
        )?;
    }
    Ok(state)
}

fn initial_age(sample: &JobSample) -> Checked<()> {
    let started = sample.row["started_at"]
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or("native expiry initial start timestamp invalid")?;
    let age = sample.now.signed_duration_since(started);
    require(
        age >= chrono::Duration::zero() && age <= chrono::Duration::seconds(2),
        "native expiry initial held observation missed the reference setup budget",
    )
}

async fn scalar(pool: &PgPool, key: &str) -> Checked<Value> {
    let query = matrix()[key]
        .as_str()
        .ok_or("native expiry frozen query missing")?;
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar(query).fetch_one(pool),
    )
    .await
    .map_err(|_| "native expiry state query timed out")?
    .map_err(|_| "native expiry state query failed")
}

async fn observe(pool: &PgPool, fixture: &WorkerFixture) -> Checked<Value> {
    let mut state = tokio::time::timeout(Duration::from_secs(2), snapshot(pool, fixture))
        .await
        .map_err(|_| "native expiry snapshot timed out")?;
    state["target"] = scalar(pool, "target_sql").await?;
    Ok(state)
}

fn held_state(actual: &Value, published: &Value) -> Checked<()> {
    // Existing explicit native target-generation fence; no arbitrary stripping.
    let mut expected = published.clone();
    require(
        expected["jobs"]
            .as_array()
            .is_some_and(|jobs| jobs.len() == 1)
            && expected["jobs"][0]["status"] == "leased"
            && expected["jobs"][0]["result"] == json!({}),
        "native expiry held reference shape differs",
    )?;
    expected["jobs"][0]["result"] = json!({"target_config_version":1});
    require(
        actual == &expected,
        "native expiry held state differs from reference",
    )
}

async fn blocked(pool: &PgPool, blocker: i32) -> Checked<Option<i32>> {
    let before = Instant::now();
    let (count, matches, pid): (i64, i64, Option<i32>) = tokio::time::timeout(Duration::from_millis(500), sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE application_name=$2 AND state='active'
             AND wait_event_type='Lock' AND query LIKE 'UPDATE issuance_service.canvas_evidence_sync_jobs%'
             AND query LIKE '%SET lease_expires_at = $5%'), min(pid)
         FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))"
    ).bind(blocker).bind(WORKER_ID).fetch_one(pool)).await
        .map_err(|_| "native expiry blocker query timed out")?
        .map_err(|_| "native expiry blocker query failed")?;
    require(
        before.elapsed() <= Duration::from_millis(500),
        "native expiry blocker query too wide",
    )?;
    if count == 0 && matches == 0 && pid.is_none() {
        return Ok(None);
    }
    require(
        count == 1 && matches == 1 && pid.is_some_and(|value| value > 1 && value != blocker),
        "native expiry exact renewal blocker differs",
    )?;
    Ok(pid)
}

async fn stable(
    pool: &PgPool,
    fixture: &WorkerFixture,
    outcome: &Value,
    rows: &(Value, Value),
) -> Checked<()> {
    require(
        scalar(pool, "effect_rows_sql").await? == rows.0
            && scalar(pool, "operational_rows_sql").await? == rows.1
            && observe(pool, fixture).await? == *outcome,
        "native expiry late response changed durable state",
    )
}

struct Replay<'a> {
    pool: &'a PgPool,
    fixture: &'a WorkerFixture,
    control: &'a Path,
    expected: &'a Value,
    crosses_expiry: bool,
}

async fn run<'a>(
    context: &Replay<'a>,
    worker: &mut OwnedWorker,
    output: &mut OwnedOutput,
    database_url: &str,
    blocker: &mut Option<Transaction<'a, Postgres>>,
) -> Checked<()> {
    let Replay {
        pool,
        fixture,
        control,
        expected,
        crosses_expiry,
    } = *context;
    emit_diagnostic(Diagnostic::AwaitRequest);
    await_marker(control, "request-received", worker, 30).await?;
    let r0 = Instant::now(); // Parent S/R0/A bracket: before every database read.
    emit_diagnostic(Diagnostic::VerifyInitial);
    let initial = read_job(pool).await?;
    initial_age(&initial)?;
    let expires = initial
        .expires
        .ok_or("native expiry original lease missing")?;
    require(
        initial.row["id"] == JOB
            && initial.row["target_id"] == "target-review"
            && initial.row["status"] == "leased"
            && initial.row["attempt_count"] == 1
            && initial.row["max_attempts"] == 8
            && initial.row["lease_owner"] == WORKER_ID
            && initial.row["result"] == json!({"target_config_version":1})
            && expires > initial.now,
        "native expiry initial owned job differs",
    )?;
    held_state(&observe(pool, fixture).await?, &expected["initial_held"])?;
    let initial_effects = scalar(pool, "effect_rows_sql").await?;
    *blocker = Some(
        pool.begin()
            .await
            .map_err(|_| "native expiry blocker begin failed")?,
    );
    let transaction = blocker.as_mut().ok_or("native expiry blocker missing")?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| "native expiry blocker bound setup failed")?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "native expiry blocker identity failed")?;
    let locked: String = sqlx::query_scalar(
        "SELECT id FROM issuance_service.canvas_evidence_sync_jobs
        WHERE id=$1 AND organization_id='org-review' AND target_id='target-review' FOR UPDATE",
    )
    .bind(JOB)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "native expiry owned row lock failed")?;
    require(
        locked == JOB && blocker_pid > 1,
        "native expiry blocker locked wrong identity",
    )?;
    require(
        r0.elapsed() < Duration::from_secs(2),
        "native expiry held setup exceeded request budget",
    )?;
    mark(control, "before-release-verified")?;
    emit_diagnostic(Diagnostic::LockHeld);

    let mut waiting_pid = None;
    let (release_start, release_end, locked_sample) = loop {
        alive(worker)?;
        require(
            r0.elapsed() < Duration::from_secs(34),
            "native expiry lock release budget exceeded",
        )?;
        let sample = read_job(pool).await?;
        validate_clock(&sample, &initial)?;
        require(
            sample.row == initial.row,
            "native expiry locked job changed",
        )?;
        let waiting = blocked(pool, blocker_pid).await?;
        if waiting_pid.is_some() {
            require(
                waiting == waiting_pid,
                "native expiry renewal left owned lock",
            )?;
        }
        if waiting.is_some() {
            waiting_pid = waiting;
        }
        let due = if crosses_expiry {
            sample.now >= expires + chrono::Duration::seconds(1)
        } else {
            r0.elapsed() >= Duration::from_secs(12)
        };
        if due {
            emit_diagnostic(Diagnostic::ReleaseDue);
            require(
                waiting_pid.is_some(),
                "native expiry renewal never reached the owned blocker",
            )?;
            emit_diagnostic(Diagnostic::VerifyHeldState);
            held_state(&observe(pool, fixture).await?, &expected["before_release"])?;
            emit_diagnostic(Diagnostic::VerifyEffects);
            require(
                scalar(pool, "effect_rows_sql").await? == initial_effects,
                "native expiry incomplete body changed business effects",
            )?;
            emit_diagnostic(Diagnostic::SampleBeforeRollback);
            let before = read_job(pool).await?;
            validate_clock(&before, &initial)?;
            require(
                before.row == initial.row,
                "native expiry pre-release generation changed",
            )?;
            let transaction = blocker
                .take()
                .ok_or("native expiry release owner missing")?;
            emit_diagnostic(Diagnostic::Rollback);
            tokio::time::timeout(Duration::from_secs(2), transaction.rollback())
                .await
                .map_err(|_| "native expiry rollback timed out")?
                .map_err(|_| "native expiry rollback failed")?;
            emit_diagnostic(Diagnostic::SampleAfterRollback);
            let after = read_job(pool).await?;
            validate_clock(&after, &initial)?;
            require(
                after.after.duration_since(before.before) <= Duration::from_millis(500),
                "native expiry release clock bracket too wide",
            )?;
            emit_diagnostic(Diagnostic::CheckReleaseBand);
            if crosses_expiry {
                require(
                    before.now >= expires + chrono::Duration::seconds(1)
                        && after.now <= expires + chrono::Duration::seconds(2),
                    "native expiry release missed original database expiry band",
                )?;
            } else {
                require(
                    before.before.duration_since(r0) >= Duration::from_millis(11_500)
                        && after.after.duration_since(r0) <= Duration::from_millis(12_500)
                        && after.now < expires,
                    "native expiry early release missed current-lease band",
                )?;
            }
            // Preserve the first post-release narrow sample, including an
            // immediately terminal observation; never substitute a later idle.
            break (
                before.before.duration_since(r0).as_secs_f64(),
                after.after.duration_since(r0).as_secs_f64(),
                (before, after),
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    emit_diagnostic(Diagnostic::ObserveOutcome);
    let mut renewed = false;
    let mut first_terminal: Option<&'static str> = None;
    let mut first_terminal_bracket = None;
    let mut last_leased_start = locked_sample.0.before;
    let mut next_sample = Some(locked_sample.1);
    let (outcome, outcome_status) = loop {
        alive(worker)?;
        let sample = match next_sample.take() {
            Some(sample) => sample,
            None => read_job(pool).await?,
        };
        let current_status = status(&sample, &initial)?;
        if current_status == "leased" {
            require(
                first_terminal.is_none(),
                "native expiry terminal job reverted",
            )?;
            last_leased_start = sample.before;
            renewed |= sample.expires.is_some_and(|value| value > expires);
        } else if let Some(previous) = first_terminal {
            require(
                previous == current_status,
                "native expiry terminal status changed",
            )?;
        } else {
            first_terminal = Some(current_status);
            first_terminal_bracket = Some((last_leased_start, sample.after));
        }
        let state = observe(pool, fixture).await?;
        require(
            r0.elapsed() < Duration::from_secs(40),
            "native expiry idle observation exceeded its bound",
        )?;
        if state["jobs"][0]["status"] != current_status {
            require(
                current_status == "leased"
                    && matches!(
                        state["jobs"][0]["status"].as_str(),
                        Some("succeeded" | "retry" | "dead_letter")
                    ),
                "native expiry full snapshot crossed an invalid transition",
            )?;
            continue;
        }
        if state["heartbeat"]["metadata"]["phase"] == "idle" {
            break (state, current_status);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    require(
        first_terminal.is_some() == first_terminal_bracket.is_some()
            && first_terminal_bracket.is_none_or(|(lo, hi)| lo <= hi),
        "native expiry terminal observation bracket invalid",
    )?;
    let rows = (
        scalar(pool, "effect_rows_sql").await?,
        scalar(pool, "operational_rows_sql").await?,
    );
    // Valid-state mismatches remain observations, not early fixture exits.
    // Preserve their actual rows through late writes/join/shutdown, then fail.
    // An idle leased job with effects is NOT thereby classified as safe.
    let parity = outcome == expected["outcome"]
        && expected["lease_advanced_after_release"].as_bool() == Some(renewed)
        && first_terminal.map(Value::from).unwrap_or(Value::Null)
            == expected["first_terminal_status"]
        && (crosses_expiry || (renewed && outcome_status == "succeeded"))
        && (outcome_status != "leased" || rows.0 == initial_effects);
    emit_diagnostic(Diagnostic::PublishOutcome);
    publish(
        control,
        &json!({
            "schema":"marty.canvas-worker-lease-expiry-native-observation/v1",
            "status":outcome_status, "lease_advanced_after_release":renewed,
            "original_lease_expired_at_release":crosses_expiry, "first_terminal_status":first_terminal,
            "release_start_seconds":release_start, "release_end_seconds":release_end,
        }),
    )?;
    // Keep diagnostic outcomes alive through the same actual late-write window.
    emit_diagnostic(Diagnostic::AwaitLateWindow);
    let late = marker(control, "late-window-complete")?;
    tokio::time::timeout(Duration::from_secs(40), async {
        while !late.is_file() {
            alive(worker)?;
            stable(pool, fixture, &outcome, &rows).await?;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        stable(pool, fixture, &outcome, &rows).await
    })
    .await
    .map_err(|_| "native expiry late window timed out")??;
    mark(control, "late-window-verified")?;
    await_marker(control, "handlers-joined", worker, 10).await?;
    emit_diagnostic(Diagnostic::VerifyJoinedState);
    stable(pool, fixture, &outcome, &rows).await?;
    worker.signal("SIGINT");
    emit_diagnostic(Diagnostic::VerifyShutdown);
    // Keep the existing ten-second wait and status requirement. Classify a
    // wait panic without inspecting or forwarding its potentially private payload.
    let shutdown_status = AssertUnwindSafe(worker.wait())
        .catch_unwind()
        .await
        .map_err(|_| "native expiry worker shutdown wait failed")?;
    require(
        shutdown_status.code() == Some(130),
        "native expiry worker shutdown status differs",
    )?;
    stable(pool, fixture, &outcome, &rows)
        .await
        .map_err(|_| "native expiry post-shutdown state verification failed")?;
    // Unexpected native output remains unqualified, even if the database
    // result is an anticipated diagnostic divergence. Never print its bytes.
    let quiet = std::panic::catch_unwind(AssertUnwindSafe(|| {
        output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url)
    }))
    .is_ok();
    mark(control, "child-done")?;
    require(
        quiet,
        "native expiry output requires separate closed classification",
    )?;
    require(
        parity,
        "native expiry full outcome differs from frozen published behavior",
    )?;
    emit_diagnostic(Diagnostic::Complete);
    Ok(())
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, case_name: &str) {
    assert_eq!(std::env::consts::OS, "linux");
    assert!(CASES.contains(&case_name), "native expiry case invalid");
    let expected = reference(case_name).expect("native expiry reference invalid");
    let fixture = prepare(pool, origin, "retry").await;
    for statement in [
        matrix()["application_seed"].as_str().unwrap(),
        validation_scenarios()["initial_job_seed"].as_str().unwrap(),
    ] {
        assert_eq!(
            sqlx::raw_sql(statement)
                .execute(pool)
                .await
                .expect("native expiry seed failed")
                .rows_affected(),
            1
        );
    }
    let control = control_directory().expect("native expiry control invalid");
    let (mut output, stdout, stderr) = OwnedOutput::new(&control);
    let mut environment = worker_environment(origin);
    for (key, value) in matrix()["environment"].as_object().unwrap() {
        environment.insert(key.clone(), value.as_str().unwrap().to_owned());
    }
    environment.insert("RUST_LOG".into(), "warn".into());
    let mut worker = OwnedWorker::start_with_environment_and_output(
        database_url,
        WORKER_ID,
        &environment,
        stdout,
        stderr,
    );
    let mut blocker = None;
    let context = Replay {
        pool,
        fixture: &fixture,
        control: &control,
        expected,
        crosses_expiry: case_name == CASES[1],
    };
    let result = AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(110),
        run(
            &context,
            &mut worker,
            &mut output,
            database_url,
            &mut blocker,
        ),
    ))
    .catch_unwind()
    .await;
    // Releasing our exact blocker precedes worker teardown on every failure.
    let rollback_ok = if let Some(transaction) = blocker.take() {
        matches!(
            tokio::time::timeout(Duration::from_secs(3), transaction.rollback()).await,
            Ok(Ok(()))
        )
    } else {
        true
    };
    let cleanup_ok = if matches!(worker.0.try_wait(), Ok(Some(_))) {
        true
    } else {
        let killed = worker.0.kill().is_ok();
        let reaped = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match worker.0.try_wait() {
                    Ok(Some(_)) => return true,
                    Err(_) => return false,
                    Ok(None) => {}
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or(false);
        killed && reaped
    };
    let result = result
        .map_err(|_| "native expiry coordinator failed in a fixed phase")
        .and_then(|value| value.map_err(|_| "native expiry coordinator exceeded its total bound"))
        .and_then(|value| value);
    if let Err(reason) = result {
        emit_diagnostic(failure_diagnostic(reason));
    }
    result.expect("native expiry replay failed");
    assert!(
        rollback_ok && cleanup_ok,
        "native expiry owned cleanup failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_observer_identity_matches_launcher_and_both_frozen_targets() {
        use super::super::canvas_worker_process_signals::worker_database_url;
        use sqlx::postgres::PgConnectOptions;
        use std::str::FromStr;

        for database_url in [
            "postgres://synthetic-user@127.0.0.1/owned_test",
            "postgres://synthetic-user@127.0.0.1/owned_test?application_name=canvas-native-expiry-worker",
        ] {
            let launched = worker_database_url(database_url, WORKER_ID);
            let options = PgConnectOptions::from_str(launched.as_str()).unwrap();
            assert_eq!(options.get_application_name(), Some(WORKER_ID));
            for case in CASES {
                let expected = reference(case).unwrap();
                for state in ["initial_held", "before_release", "outcome"] {
                    assert_eq!(expected[state]["target"]["metadata"]["worker_id"], WORKER_ID);
                }
            }
        }
    }

    #[test]
    fn diagnostic_failure_mapping_is_exact_and_payload_free() {
        for (reason, expected) in [
            (
                "native expiry worker shutdown wait failed",
                Diagnostic::FailureShutdownWait,
            ),
            (
                "native expiry worker shutdown status differs",
                Diagnostic::FailureShutdownStatus,
            ),
            (
                "native expiry post-shutdown state verification failed",
                Diagnostic::FailurePostShutdownState,
            ),
            (
                "native expiry output requires separate closed classification",
                Diagnostic::FailureOutput,
            ),
            (
                "native expiry full outcome differs from frozen published behavior",
                Diagnostic::FailureParity,
            ),
            (
                "native expiry clock ordering invalid",
                Diagnostic::FailureClockOrder,
            ),
            (
                "native expiry clock range invalid",
                Diagnostic::FailureClockOrder,
            ),
            (
                "native expiry renewal left owned lock",
                Diagnostic::FailureRenewalLeftLock,
            ),
            (
                "native expiry locked job changed",
                Diagnostic::FailureLockedJob,
            ),
            (
                "native expiry pre-release generation changed",
                Diagnostic::FailurePreReleaseJob,
            ),
            (
                "native expiry incomplete body changed business effects",
                Diagnostic::FailureEffects,
            ),
            (
                "native expiry original job generation changed",
                Diagnostic::FailureJobGeneration,
            ),
            (
                "native expiry terminal lease was not cleared",
                Diagnostic::FailureTerminalLease,
            ),
            (
                "native expiry narrow job query timed out",
                Diagnostic::FailureJobQuery,
            ),
            (
                "native expiry narrow job query failed",
                Diagnostic::FailureJobQuery,
            ),
            (
                "native expiry narrow query too wide",
                Diagnostic::FailureJobQuery,
            ),
            (
                "native expiry database and monotonic clocks disagree",
                Diagnostic::FailureClockAgreement,
            ),
            (
                "native expiry exact renewal blocker differs",
                Diagnostic::FailureRenewalBlocker,
            ),
            (
                "native expiry renewal never reached the owned blocker",
                Diagnostic::FailureRenewalNotObserved,
            ),
            (
                "native expiry held state differs from reference",
                Diagnostic::FailureHeldState,
            ),
            (
                "native expiry release clock bracket too wide",
                Diagnostic::FailureReleaseBracket,
            ),
            (
                "native expiry early release missed current-lease band",
                Diagnostic::FailureEarlyBand,
            ),
            (
                "native expiry release missed original database expiry band",
                Diagnostic::FailureExpiryBand,
            ),
            (
                "native expiry leased identity or original fence changed",
                Diagnostic::FailureLeasedIdentity,
            ),
        ] {
            assert_eq!(failure_diagnostic(reason), expected);
            for altered in [
                format!("private-payload {reason}"),
                format!("{reason}: private-payload"),
            ] {
                assert_eq!(failure_diagnostic(&altered), Diagnostic::FailureUnknown);
            }
        }
        for unknown in ["", "private-payload", "\nMARTY_EXPIRY_DIAG_V1:Complete\n"] {
            assert_eq!(failure_diagnostic(unknown), Diagnostic::FailureUnknown);
            assert_eq!(
                format!("{:?}", failure_diagnostic(unknown)),
                "FailureUnknown"
            );
        }
    }

    fn leased() -> JobSample {
        let now = DateTime::parse_from_rfc3339("2026-09-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        JobSample {
            row: json!({
                "id":JOB, "organization_id":"org-review", "target_id":"target-review",
                "status":"leased", "attempt_count":1, "max_attempts":8,
                "started_at":"2026-09-08T00:00:00Z", "created_at":"original-created",
                "available_at":"original-available", "lease_owner":WORKER_ID,
                "lease_expires_at":"original-expiry", "updated_at":"original-updated",
                "result":{"target_config_version":1}
            }),
            expires: Some(now + chrono::Duration::seconds(30)),
            now,
            before: Instant::now(),
            after: Instant::now(),
        }
    }

    fn terminal(state: &str) -> JobSample {
        let mut sample = leased();
        sample.row["status"] = json!(state);
        sample.row["lease_owner"] = Value::Null;
        sample.row["lease_expires_at"] = Value::Null;
        sample.expires = None;
        sample
    }

    #[test]
    fn diagnostic_status_preserves_legitimate_retry_and_terminal_rewrites() {
        let original = leased();
        let mut retry = terminal("retry");
        retry.row["available_at"] = json!("future-retry");
        retry.row["result"] = json!({"status":"retry"});
        assert_eq!(status(&retry, &original), Ok("retry"));
        let mut dead = terminal("dead_letter");
        dead.row["max_attempts"] = json!(1);
        assert_eq!(status(&dead, &original), Ok("dead_letter"));
        assert_eq!(status(&terminal("succeeded"), &original), Ok("succeeded"));
        for key in ["max_attempts", "available_at", "result"] {
            let mut changed = leased();
            changed.row[key] = json!("changed-while-leased");
            assert!(status(&changed, &original).is_err());
        }
    }

    #[test]
    fn diagnostic_status_rejects_changed_generation_and_uncleared_terminal_lease() {
        let original = leased();
        for state in ["leased", "succeeded", "retry", "dead_letter"] {
            for key in [
                "id",
                "organization_id",
                "target_id",
                "attempt_count",
                "started_at",
                "created_at",
            ] {
                let mut changed = if state == "leased" {
                    leased()
                } else {
                    terminal(state)
                };
                changed.row[key] = json!("private-generation-payload");
                assert_eq!(
                    status(&changed, &original),
                    Err("native expiry original job generation changed")
                );
            }
        }
        let mut uncleared = terminal("retry");
        uncleared.row["lease_owner"] = json!(WORKER_ID);
        assert_eq!(
            status(&uncleared, &original),
            Err("native expiry terminal lease was not cleared")
        );
        let mut unknown = leased();
        unknown.row["status"] = json!("private-status-payload");
        assert_eq!(
            status(&unknown, &original),
            Err("native expiry job status unknown")
        );
    }

    #[test]
    fn initial_held_age_has_exact_reference_budget_without_clock_edits() {
        for milliseconds in [0, 1_000, 2_000] {
            let mut sample = leased();
            sample.now += chrono::Duration::milliseconds(milliseconds);
            assert!(initial_age(&sample).is_ok());
        }
        for milliseconds in [-1, 2_001, 10_000] {
            let mut sample = leased();
            sample.now += chrono::Duration::milliseconds(milliseconds);
            assert_eq!(
                initial_age(&sample),
                Err("native expiry initial held observation missed the reference setup budget")
            );
        }
        let mut malformed = leased();
        malformed.row["started_at"] = json!("private-timestamp-payload");
        assert_eq!(
            initial_age(&malformed),
            Err("native expiry initial start timestamp invalid")
        );
    }
}
