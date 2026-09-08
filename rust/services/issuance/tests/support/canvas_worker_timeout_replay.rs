//! Actual native worker delayed-header replay; no live job, lease or clock edits.
//! Python owns the one-request transport/release clock; this owner proves every
//! durable state and keeps the actual worker alive through the late window.
use super::{
    canvas_worker_output::OwnedOutput,
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{assert_leased_state, snapshot},
    canvas_worker_rest_replay::{prepare, validation_scenarios, worker_environment, WorkerFixture},
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};

fn scenarios() -> &'static Value {
    static MATRIX: OnceLock<Value> = OnceLock::new();
    MATRIX.get_or_init(|| {
        let mut matrix: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-timeout-scenarios.json"
        ))
        .unwrap();
        let state: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-deadline-scenarios.json"
        ))
        .unwrap();
        for key in ["effect_rows_sql", "operational_rows_sql"] {
            matrix[key] = state[key].clone();
        }
        matrix
    })
}

fn reference() -> &'static Value {
    static REFERENCE: OnceLock<Value> = OnceLock::new();
    REFERENCE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-timeout-oracle.json"
        ))
        .unwrap()
    })
}

fn roster_scenarios() -> &'static Value {
    static ROSTER: OnceLock<Value> = OnceLock::new();
    ROSTER.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-roster-failure-scenarios.json"
        ))
        .unwrap()
    })
}

fn select<'a>(rows: &'a Value, key: &str, name: &str) -> &'a Value {
    let matches = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row[key] == name)
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "timeout case must have exactly one frozen entry"
    );
    matches[0]
}

async fn scalar(pool: &PgPool, query: &'static str) -> Value {
    // Only SELECT text from compile-time frozen fixtures reaches this helper.
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

fn control_directory() -> PathBuf {
    let supplied = PathBuf::from(std::env::var("MARTY_CANVAS_WORKER_TIMEOUT_CONTROL").unwrap());
    let directory = supplied.canonicalize().unwrap();
    assert!(directory.is_dir());
    assert_eq!(directory.file_name().unwrap(), "native-control");
    let certificate = PathBuf::from(std::env::var("SSL_CERT_FILE").unwrap())
        .canonicalize()
        .unwrap();
    assert!(!directory.starts_with(certificate.parent().unwrap()));
    directory
}

fn marker(control: &Path, name: &str) -> PathBuf {
    assert!(matches!(
        name,
        "request-received"
            | "before-release-verified"
            | "outcome-observed"
            | "late-window-complete"
            | "late-window-verified"
            | "handlers-joined"
            | "child-done"
    ));
    control.join(name)
}

fn mark(control: &Path, name: &str) {
    File::create_new(marker(control, name)).unwrap();
}

fn transition_bytes(lo: f64, hi: f64) -> Vec<u8> {
    assert!(
        lo.is_finite() && hi.is_finite() && 0.0 <= lo && lo <= hi && hi <= 90.0,
        "invalid native terminal transition interval"
    );
    let bytes = serde_json::to_vec(&json!({
        "schema": "marty.canvas-worker-timeout-transition/v1",
        "last_leased_start_seconds": lo,
        "first_terminal_end_seconds": hi,
    }))
    .unwrap();
    assert!(
        bytes.len() <= 512,
        "native transition exceeds its bounded protocol"
    );
    bytes
}

struct PendingTransition(Option<PathBuf>);

impl Drop for PendingTransition {
    fn drop(&mut self) {
        // This exact file was created exclusively in the parent's owned root.
        // No directory discovery, overwrite or recursive cleanup is involved.
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn publish_transition(control: &Path, lo: f64, hi: f64) -> std::io::Result<()> {
    let bytes = transition_bytes(lo, hi);
    let temporary = control.parent().unwrap().join("timeout-transition.pending");
    let mut file = File::create_new(&temporary)?;
    let mut pending = PendingTransition(Some(temporary));
    let written = file.write_all(&bytes).and_then(|()| file.flush());
    drop(file);
    written?;
    // A completed same-filesystem inode becomes visible atomically. Unlike
    // rename, hard_link never overwrites an existing protocol marker.
    std::fs::hard_link(
        pending.0.as_ref().unwrap(),
        marker(control, "outcome-observed"),
    )?;
    // Disarm before the explicit removal: never retry a pathname which another
    // actor could recreate after this successful unlink.
    std::fs::remove_file(pending.0.take().unwrap())?;
    Ok(())
}

struct JobObservation {
    id: String,
    attempt_count: i32,
    status: String,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    started_at: DateTime<Utc>,
    result: Value,
}

impl JobObservation {
    fn verified_status(
        &self,
        job_id: &str,
        started: DateTime<Utc>,
        expires: DateTime<Utc>,
    ) -> &str {
        assert!(
            self.id == job_id && self.attempt_count == 1 && self.started_at == started,
            "native timeout observation changed job identity or generation"
        );
        match self.status.as_str() {
            "leased" => {
                assert!(
                    self.lease_owner.as_deref() == Some("worker-rest")
                        && self.lease_expires_at == Some(expires)
                        && self.result == json!({"target_config_version": 1}),
                    "native timeout leased observation lost its exact owner or fence"
                );
            }
            "succeeded" | "retry" | "dead_letter" => {}
            _ => panic!("native timeout job left the allowed first-attempt transition"),
        }
        &self.status
    }
}

async fn read_job(pool: &PgPool) -> JobObservation {
    let rows = sqlx::query(
        "SELECT id,attempt_count,status,lease_owner,lease_expires_at,started_at,result
         FROM issuance_service.canvas_evidence_sync_jobs WHERE organization_id='org-review'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "timeout fixture must retain exactly one durable job"
    );
    let row = &rows[0];
    JobObservation {
        id: row.get("id"),
        attempt_count: row.get("attempt_count"),
        status: row.get("status"),
        lease_owner: row.get("lease_owner"),
        lease_expires_at: row.get("lease_expires_at"),
        started_at: row.get("started_at"),
        result: row.get("result"),
    }
}

fn alive(worker: &mut OwnedWorker) {
    assert!(
        worker.0.try_wait().unwrap().is_none(),
        "native timeout worker exited early"
    );
}

async fn await_marker(control: &Path, name: &str, worker: &mut OwnedWorker) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !marker(control, name).is_file() {
            alive(worker);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        alive(worker);
    })
    .await
    .expect("native timeout parent handshake exceeded its fixed bound");
}

async fn observe(pool: &PgPool, fixture: &WorkerFixture) -> Value {
    let mut state = snapshot(pool, fixture).await;
    state["target"] = scalar(pool, scenarios()["target_sql"].as_str().unwrap()).await;
    state
}

async fn effects(pool: &PgPool) -> Value {
    scalar(pool, scenarios()["effect_rows_sql"].as_str().unwrap()).await
}

async fn operational(pool: &PgPool) -> Value {
    scalar(pool, scenarios()["operational_rows_sql"].as_str().unwrap()).await
}

fn assert_unavailable_effects(before: &Value, after: &Value) {
    // Validation state can change after an unavailable authoritative read, but
    // unavailability is not verified negative evidence or a candidate event.
    for key in [
        "facts",
        "heads",
        "reviews",
        "events",
        "candidates",
        "observations",
    ] {
        assert!(before.get(key).is_some() && after.get(key).is_some());
        assert!(
            before[key] == after[key],
            "unavailable read changed business evidence"
        );
    }
}

async fn assert_stable(
    pool: &PgPool,
    fixture: &WorkerFixture,
    outcome: &Value,
    rows: &(Value, Value),
) {
    assert!(
        observe(pool, fixture).await == *outcome,
        "timeout outcome changed after completion"
    );
    assert!(
        effects(pool).await == rows.0,
        "late response changed raw business effects"
    );
    assert!(
        operational(pool).await == rows.1,
        "late response changed raw job or target"
    );
}

fn assert_reference(case: &Value, expected: &Value) {
    let matrix = scenarios();
    assert_eq!(
        reference()["schema"],
        "marty.canvas-worker-timeout-oracle/v1"
    );
    assert_eq!(matrix["schema"], "marty.canvas-worker-timeout-scenarios/v1");
    assert_eq!(
        expected["schema"],
        "marty.canvas-worker-timeout-observation/v1"
    );
    assert_eq!(expected["case"], case["name"]);
    assert_eq!(
        expected["outcome"]["jobs"][0]["status"],
        case["expected_status"]
    );
    assert_eq!(
        matrix["environment"],
        json!({
            "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
            "CANVAS_SYNC_WORKER_LEASE_SECONDS": "90",
            "CANVAS_SYNC_WORKER_POLL_SECONDS": "120", "LOG_LEVEL": "WARNING"
        })
    );
    assert_eq!(
        expected["timing"],
        json!({
            "outcome_within_declared_source_window": true,
            "release_within_declared_band": true,
            "outcome_before_release": case["expected_status"] == "retry",
            "lease_current_while_response_held": true,
            "original_lease_current_after_outcome": true
        })
    );
    assert_eq!(
        expected["stable_after_release_handler_join_and_interrupt"],
        true
    );
    assert_eq!(expected["exit_code_after_interrupt"], -2);
    for key in ["source_sha256", "http_source_sha256", "log_source_sha256"] {
        assert_eq!(expected[key], matrix[key]);
    }
    // A language-specific import warning is reference provenance, never a
    // fabricated native log observation. Native output is independently checked.
    assert_eq!(
        expected["logs_before_interrupt"],
        json!({
            "stdout_empty": true,
            "stderr_warning_categories": {
                "missing_revocation_profile_service_url": 1,
                "missing_credential_template_service_url": 1
            }, "other_output_empty": true
        })
    );
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, case_name: &str) {
    assert_eq!(std::env::consts::OS, "linux");
    assert!(matches!(
        case_name,
        "application_prompt"
            | "application_delayed_headers"
            | "roster_prompt"
            | "roster_delayed_headers"
    ));
    let matrix = scenarios();
    let case = select(&matrix["cases"], "name", case_name);
    let expected = select(&reference()["observations"], "case", case_name);
    assert_reference(case, expected);

    let fixture = prepare(pool, origin, "retry").await;
    // Exact published post-OAuth setup, before the worker process exists.
    let job_id = if case["target_type"] == "background_roster" {
        for statement in roster_scenarios()["seed"].as_array().unwrap() {
            assert_eq!(
                sqlx::raw_sql(statement.as_str().unwrap())
                    .execute(pool)
                    .await
                    .unwrap()
                    .rows_affected(),
                1
            );
        }
        "worker-roster-failure-job"
    } else {
        assert_eq!(case["target_type"], "learner_application");
        for statement in [
            matrix["application_seed"].as_str().unwrap(),
            validation_scenarios()["initial_job_seed"].as_str().unwrap(),
        ] {
            assert_eq!(
                sqlx::raw_sql(statement)
                    .execute(pool)
                    .await
                    .unwrap()
                    .rows_affected(),
                1
            );
        }
        "worker-validation-job"
    };
    let initial_effects = effects(pool).await;
    let control = control_directory();
    let (mut output, stdout, stderr) = OwnedOutput::new(&control);
    let mut environment = worker_environment(origin);
    for (key, value) in matrix["environment"].as_object().unwrap() {
        environment.insert(key.clone(), value.as_str().unwrap().to_owned());
    }
    environment.insert("RUST_LOG".into(), "warn".into());
    let mut worker = OwnedWorker::start_with_environment_and_output(
        database_url,
        "worker-rest",
        &environment,
        stdout,
        stderr,
    );
    await_marker(&control, "request-received", &mut worker).await;
    let request_origin = Instant::now();
    let mut last_leased_start = Instant::now();
    let leased = read_job(pool).await;
    let started = leased.started_at;
    let expires = leased.lease_expires_at.unwrap();
    assert_eq!(leased.verified_status(job_id, started, expires), "leased");
    assert_original_lease_current(pool, expires).await;
    assert_leased_state(
        observe(pool, &fixture).await,
        &expected["before_release"],
        1,
    );
    mark(&control, "before-release-verified");

    // Do not time a full snapshot or wait for idle here. Each verified leased
    // query starts before its snapshot; the first terminal query finishes after
    // its snapshot. Together these bracket the actual durable transition.
    let (first_terminal_end, terminal_status) =
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                alive(&mut worker);
                let query_start = Instant::now();
                let observed = read_job(pool).await;
                let query_end = Instant::now();
                let status = observed.verified_status(job_id, started, expires);
                if status != "leased" {
                    break (query_end, status.to_owned());
                }
                last_leased_start = query_start;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("native timeout worker must reach its first terminal job status");
    let lo = last_leased_start
        .duration_since(request_origin)
        .as_secs_f64();
    let hi = first_terminal_end
        .duration_since(request_origin)
        .as_secs_f64();

    // Idle bookkeeping is a separate requirement, never the terminal timestamp.
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            alive(&mut worker);
            let state = observe(pool, &fixture).await;
            let jobs = state["jobs"].as_array().unwrap();
            assert_eq!(jobs.len(), 1);
            if state["heartbeat"]["metadata"]["phase"] == "idle"
                && matches!(
                    jobs[0]["status"].as_str(),
                    Some("succeeded" | "retry" | "dead_letter")
                )
            {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native timeout worker must become idle after its first terminal outcome");
    assert_eq!(outcome["jobs"][0]["status"], terminal_status);
    assert!(
        outcome == expected["outcome"],
        "native timeout outcome differs from frozen published state"
    );
    publish_transition(&control, lo, hi).expect("native timeout transition publication failed");
    let completed = read_job(pool).await;
    assert_eq!(
        completed.verified_status(job_id, started, expires),
        terminal_status
    );
    assert_original_lease_current(pool, expires).await;
    let stable = (effects(pool).await, operational(pool).await);
    if case["expected_status"] == "retry" {
        assert_unavailable_effects(&initial_effects, &stable.0);
    }
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !marker(&control, "late-window-complete").is_file() {
            alive(&mut worker);
            assert_stable(pool, &fixture, &outcome, &stable).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("parent must complete the fixed timeout late-response window");
    alive(&mut worker);
    assert_stable(pool, &fixture, &outcome, &stable).await;
    // This is the original captured lease, not a later renewal or cleared
    // terminal field; it must still be current after the independent release.
    assert_original_lease_current(pool, expires).await;
    mark(&control, "late-window-verified");
    await_marker(&control, "handlers-joined", &mut worker).await;
    assert_stable(pool, &fixture, &outcome, &stable).await;
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    assert_stable(pool, &fixture, &outcome, &stable).await;
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    mark(&control, "child-done");
    eprintln!("native worker timeout {case_name}: exact held/outcome state, original lease and no late effects passed");
}

async fn assert_original_lease_current(pool: &PgPool, expires: DateTime<Utc>) {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(
        expires > now,
        "lease expiry masked the provider timeout boundary"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_transition_payload_is_closed_finite_and_bounded() {
        for (lo, hi) in [(0.0, 0.0), (0.0, 90.0), (14.5, 16.5), (90.0, 90.0)] {
            let bytes = transition_bytes(lo, hi);
            assert!(bytes.len() <= 512);
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value,
                json!({
                    "schema": "marty.canvas-worker-timeout-transition/v1",
                    "last_leased_start_seconds": lo,
                    "first_terminal_end_seconds": hi,
                })
            );
        }
        for (lo, hi) in [
            (-0.01, 1.0),
            (2.0, 1.0),
            (0.0, 90.001),
            (f64::NAN, 1.0),
            (0.0, f64::NAN),
            (f64::NEG_INFINITY, 1.0),
            (0.0, f64::INFINITY),
        ] {
            assert!(std::panic::catch_unwind(|| transition_bytes(lo, hi)).is_err());
        }
    }

    #[test]
    fn timeout_transition_publishes_complete_json_without_overwrite_or_protocol_tempfile() {
        struct OwnedControl(PathBuf);
        impl Drop for OwnedControl {
            fn drop(&mut self) {
                for path in [
                    self.0.join("native-control/outcome-observed"),
                    self.0.join("timeout-transition.pending"),
                ] {
                    let _ = std::fs::remove_file(path);
                }
                let _ = std::fs::remove_dir(self.0.join("native-control"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let owner = OwnedControl(std::env::temp_dir().join(format!(
            "canvas-timeout-transition-test-{}",
            uuid::Uuid::new_v4()
        )));
        std::fs::create_dir(&owner.0).unwrap();
        let control = owner.0.join("native-control");
        std::fs::create_dir(&control).unwrap();
        publish_transition(&control, 14.9, 15.1).unwrap();
        let initial = std::fs::read(marker(&control, "outcome-observed")).unwrap();
        assert_eq!(initial, transition_bytes(14.9, 15.1));
        assert_eq!(std::fs::read_dir(&control).unwrap().count(), 1);
        assert!(!owner.0.join("timeout-transition.pending").exists());
        assert!(publish_transition(&control, 19.9, 20.1).is_err());
        assert_eq!(
            std::fs::read(marker(&control, "outcome-observed")).unwrap(),
            initial
        );
        assert!(!owner.0.join("timeout-transition.pending").exists());
        let root = owner.0.clone();
        drop(owner);
        assert!(!root.exists());
    }

    #[test]
    fn timeout_narrow_observer_rejects_wrong_job_attempt_start_owner_fence_and_state() {
        let started = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires = started + chrono::Duration::seconds(90);
        let sample = || JobObservation {
            id: "worker-validation-job".into(),
            attempt_count: 1,
            status: "leased".into(),
            lease_owner: Some("worker-rest".into()),
            lease_expires_at: Some(expires),
            started_at: started,
            result: json!({"target_config_version": 1}),
        };
        assert_eq!(
            sample().verified_status("worker-validation-job", started, expires),
            "leased"
        );
        for status in ["succeeded", "retry", "dead_letter"] {
            let mut terminal = sample();
            terminal.status = status.into();
            terminal.lease_owner = None;
            terminal.lease_expires_at = None;
            terminal.result = json!({});
            assert_eq!(
                terminal.verified_status("worker-validation-job", started, expires),
                status
            );
        }
        for index in 0..12 {
            let mut invalid = sample();
            match index {
                0 => invalid.id = "wrong-job".into(),
                1 => invalid.attempt_count = 2,
                2 => invalid.started_at += chrono::Duration::seconds(1),
                3 => invalid.lease_owner = Some("other-worker".into()),
                4 => invalid.lease_owner = None,
                5 => invalid.lease_expires_at = None,
                6 => invalid.result = json!({}),
                7 => invalid.result = json!({"target_config_version": 2}),
                8 => invalid.result = json!({"target_config_version": 1, "extra": true}),
                9 => invalid.status = "queued".into(),
                10 => invalid.lease_expires_at = Some(expires + chrono::Duration::seconds(1)),
                11 => invalid.lease_expires_at = Some(expires - chrono::Duration::seconds(1)),
                _ => unreachable!(),
            }
            assert!(std::panic::catch_unwind(|| invalid.verified_status(
                "worker-validation-job",
                started,
                expires
            ))
            .is_err());
        }
    }

    #[test]
    fn timeout_replay_retains_all_four_frozen_controls_and_exact_provenance() {
        let names = [
            "application_prompt",
            "application_delayed_headers",
            "roster_prompt",
            "roster_delayed_headers",
        ];
        assert_eq!(scenarios()["cases"].as_array().unwrap().len(), names.len());
        assert_eq!(
            reference()["observations"].as_array().unwrap().len(),
            names.len()
        );
        for name in names {
            let case = select(&scenarios()["cases"], "name", name);
            let expected = select(&reference()["observations"], "case", name);
            assert_reference(case, expected);
            let mut wrong = expected.clone();
            wrong["timing"]["outcome_before_release"] =
                json!(name != "application_delayed_headers");
            assert!(std::panic::catch_unwind(|| assert_reference(case, &wrong)).is_err());
        }
    }

    #[test]
    fn unavailable_timeout_never_invents_or_discards_raw_business_evidence() {
        let before = json!({"facts": [], "heads": [], "reviews": [], "events": [],
            "candidates": [], "observations": [], "validation_state": "before"});
        let mut allowed = before.clone();
        allowed["validation_state"] = json!("unavailable");
        assert_unavailable_effects(&before, &allowed);
        for key in [
            "facts",
            "heads",
            "reviews",
            "events",
            "candidates",
            "observations",
        ] {
            let mut altered = allowed.clone();
            altered[key] = json!([{"synthetic": "unexpected"}]);
            assert!(
                std::panic::catch_unwind(|| assert_unavailable_effects(&before, &altered)).is_err()
            );
            altered.as_object_mut().unwrap().remove(key);
            assert!(
                std::panic::catch_unwind(|| assert_unavailable_effects(&before, &altered)).is_err()
            );
        }
    }
}
