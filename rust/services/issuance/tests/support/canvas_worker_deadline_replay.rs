//! Real native worker cancellation during the third HTTPS read, compared with
//! independently frozen published state. No clock, live job or lease is edited.
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
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};

fn scenarios() -> &'static Value {
    static MATRIX: OnceLock<Value> = OnceLock::new();
    MATRIX.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-deadline-scenarios.json"
        ))
        .unwrap()
    })
}

async fn scalar(pool: &PgPool, query: &'static str) -> Value {
    // All callers supply only compile-time frozen fixture SELECT statements.
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

fn control_directory() -> PathBuf {
    let supplied = PathBuf::from(std::env::var("MARTY_CANVAS_WORKER_DEADLINE_CONTROL").unwrap());
    let directory = supplied.canonicalize().unwrap();
    assert!(directory.is_dir());
    assert_eq!(directory.file_name().unwrap(), "native-control");
    // The Python owner must keep markers/logs alive after its HTTPS owner closes.
    let certificate = PathBuf::from(std::env::var("SSL_CERT_FILE").unwrap())
        .canonicalize()
        .unwrap();
    assert!(!directory.starts_with(certificate.parent().unwrap()));
    directory
}

fn marker(control: &Path, name: &str) -> PathBuf {
    assert!(matches!(
        name,
        "request-received-0"
            | "request-received-1"
            | "request-received-2"
            | "renewal-observed-0"
            | "renewal-observed-1"
            | "committed-prefix"
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

fn alive(worker: &mut OwnedWorker) {
    assert!(
        worker.0.try_wait().unwrap().is_none(),
        "native deadline worker exited early"
    );
}

async fn await_marker(control: &Path, name: &str, worker: &mut OwnedWorker) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !marker(control, name).is_file() {
            alive(worker);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        alive(worker);
    })
    .await
    .expect("native deadline parent handshake exceeded its fixed bound");
}

struct Generation {
    id: String,
    attempt: i32,
    owner: Option<String>,
    expires: DateTime<Utc>,
    started: DateTime<Utc>,
}

async fn generation(pool: &PgPool) -> Generation {
    let rows = sqlx::query(
        "SELECT id,attempt_count,lease_owner,lease_expires_at,started_at
         FROM issuance_service.canvas_evidence_sync_jobs
         WHERE organization_id='org-review'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "deadline fixture must retain one durable job"
    );
    let row = &rows[0];
    Generation {
        id: row.get("id"),
        attempt: row.get("attempt_count"),
        owner: row.get("lease_owner"),
        expires: row.get("lease_expires_at"),
        started: row.get("started_at"),
    }
}

async fn renewed(pool: &PgPool, worker: &mut OwnedWorker, previous: &Generation) -> Generation {
    tokio::time::timeout(Duration::from_secs(14), async {
        loop {
            alive(worker);
            let current = generation(pool).await;
            assert_eq!(current.id, previous.id);
            assert_eq!(current.attempt, 1);
            assert_eq!(current.owner.as_deref(), Some("worker-rest"));
            assert_eq!(current.started, previous.started);
            if current.expires > previous.expires {
                break current;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual worker must renew its lease while provider response is pending")
}

struct AgeSample {
    row: Value,
    before: Instant,
    after: Instant,
}

async fn job_age(pool: &PgPool) -> AgeSample {
    let before = Instant::now();
    let row = scalar(pool, scenarios()["job_age_sql"].as_str().unwrap()).await;
    AgeSample {
        row,
        before,
        after: Instant::now(),
    }
}

fn assert_timing(sample: &AgeSample, initial: Option<&AgeSample>, deadline: bool) {
    let bounds = &scenarios()["timing_bounds"];
    assert_eq!(
        bounds,
        &json!({
            "initial_job_age_max_seconds": 2, "query_latency_max_seconds": 1,
            "deadline_job_age_min_seconds": 29.5, "deadline_job_age_max_seconds": 33,
            "clock_agreement_max_seconds": 0.5,
        })
    );
    assert_eq!(sample.row["id"], "worker-validation-job");
    assert_eq!(sample.row["attempt_count"], 1);
    assert!(sample.row["started_at"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    let age = sample.row["age_seconds"].as_f64().unwrap();
    assert!(age.is_finite() && age >= 0.0);
    assert!(
        sample.after.duration_since(sample.before).as_secs_f64()
            <= bounds["query_latency_max_seconds"].as_f64().unwrap()
    );
    if let Some(initial) = initial {
        for key in ["id", "attempt_count", "started_at"] {
            assert_eq!(sample.row[key], initial.row[key]);
        }
        let delta = age - initial.row["age_seconds"].as_f64().unwrap();
        let agreement = bounds["clock_agreement_max_seconds"].as_f64().unwrap();
        let lower = sample.before.duration_since(initial.after).as_secs_f64() - agreement;
        let upper = sample.after.duration_since(initial.before).as_secs_f64() + agreement;
        assert!(
            lower <= delta && delta <= upper,
            "DB and monotonic elapsed time disagree"
        );
        if deadline {
            assert!(
                bounds["deadline_job_age_min_seconds"].as_f64().unwrap() <= age
                    && age <= bounds["deadline_job_age_max_seconds"].as_f64().unwrap(),
                "native deadline outcome is outside fixed published timing bounds"
            );
        }
    } else {
        assert!(
            age <= bounds["initial_job_age_max_seconds"].as_f64().unwrap(),
            "native first-request setup exceeded the fixed fixture budget"
        );
    }
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

async fn assert_stable(
    pool: &PgPool,
    fixture: &WorkerFixture,
    outcome: &Value,
    rows: &(Value, Value),
) {
    assert_eq!(observe(pool, fixture).await, *outcome);
    assert!(
        effects(pool).await == rows.0,
        "business effects changed after outcome"
    );
    assert!(
        operational(pool).await == rows.1,
        "raw job or target changed after outcome"
    );
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, case_name: &str) {
    assert_eq!(std::env::consts::OS, "linux");
    assert!(matches!(case_name, "early_release" | "deadline_cancel"));
    let matrix = scenarios();
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-deadline-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        reference["schema"],
        "marty.canvas-worker-deadline-oracle/v1"
    );
    let matches = reference["observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["case"] == case_name)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    let expected = matches[0];
    assert_eq!(expected["timing_bounds"], matrix["timing_bounds"]);
    assert_eq!(
        expected["logs_before_interrupt"],
        json!({
            "stdout_empty": true,
            "stderr_warning_categories": {
                "missing_revocation_profile_service_url": 1,
                "missing_credential_template_service_url": 1,
            },
            "other_output_empty": true,
        })
    );
    assert_eq!(
        expected["log_source_sha256"],
        "2b6d2eb7cec34bb4596ef9b758d8af02a3172337e89bad3b5d26b558d0dd00b7"
    );
    for key in [
        "first_request_setup_within_age_budget",
        "timing_query_latency_within_budget",
        "database_and_monotonic_elapsed_agree",
        "last_renewed_lease_still_current_at_outcome",
        "stable_after_release_and_handler_join",
        "worker_live_and_idle_after_late_response_window",
        "stable_after_interrupt",
    ] {
        assert_eq!(expected[key], true);
    }
    assert_eq!(
        expected["completed_reads_released_before_published_http_timeout"],
        2
    );
    assert_eq!(expected["renewals_observed_while_reads_pending"], 2);
    if case_name == "deadline_cancel" {
        for key in [
            "deadline_outcome_within_declared_age_bounds",
            "committed_prefix_preserved_on_deadline",
            "third_response_released_after_deadline_outcome",
        ] {
            assert_eq!(expected[key], true);
        }
    }

    let fixture = prepare(pool, origin, "facts").await;
    let requirements = matrix["requirement_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            fixture.spec["requirements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|requirement| requirement["requirement_id"] == *id)
                .unwrap()
                .clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(requirements.len(), 3);
    // Only pre-start fixture writes: restrict existing real requirements and
    // enqueue the same frozen first job before the native process exists.
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=$1 WHERE id='binding-review' AND organization_id='org-review'")
        .bind(json!(requirements)).execute(pool).await.unwrap().rows_affected(), 1);
    assert_eq!(
        sqlx::raw_sql(validation_scenarios()["initial_job_seed"].as_str().unwrap())
            .execute(pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
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
    await_marker(&control, "request-received-0", &mut worker).await;
    let initial_age = job_age(pool).await;
    assert_timing(&initial_age, None, false);
    let mut lease = generation(pool).await;
    assert_eq!(lease.id, "worker-validation-job");
    assert_eq!(lease.attempt, 1);
    assert_eq!(lease.owner.as_deref(), Some("worker-rest"));
    assert_leased_state(
        observe(pool, &fixture).await,
        &expected["before_first_release"],
        1,
    );
    let mut prior_facts = Vec::new();
    for index in 0..2 {
        lease = renewed(pool, &mut worker, &lease).await;
        mark(
            &control,
            ["renewal-observed-0", "renewal-observed-1"][index],
        );
        await_marker(
            &control,
            ["request-received-1", "request-received-2"][index],
            &mut worker,
        )
        .await;
        let state = observe(pool, &fixture).await;
        assert_leased_state(state, &expected["completed_read_states"][index], 1);
        let current = effects(pool).await;
        let facts = current["facts"].as_array().unwrap();
        assert_eq!(facts.len(), index + 1);
        assert!(
            prior_facts.iter().all(|row| facts.contains(row)),
            "earlier committed fact changed"
        );
        prior_facts = facts.clone();
    }
    let committed = effects(pool).await;
    mark(&control, "committed-prefix");
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            alive(&mut worker);
            let state = observe(pool, &fixture).await;
            let jobs = state["jobs"].as_array().unwrap();
            if jobs.len() == 1
                && state["heartbeat"]["metadata"]["phase"] == "idle"
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
    .expect("native deadline worker must reach its actual durable idle outcome");
    assert_timing(
        &job_age(pool).await,
        Some(&initial_age),
        case_name == "deadline_cancel",
    );
    assert_eq!(outcome, expected["outcome"]);
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(
        lease.expires > now,
        "deadline must occur before the renewed lease expires"
    );
    if case_name == "deadline_cancel" {
        assert!(
            effects(pool).await == committed,
            "deadline lost or added committed prefix effects"
        );
    }
    let stable = (effects(pool).await, operational(pool).await);
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    mark(&control, "outcome-observed");
    tokio::time::timeout(Duration::from_secs(25), async {
        while !marker(&control, "late-window-complete").is_file() {
            alive(&mut worker);
            assert_stable(pool, &fixture, &outcome, &stable).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("parent must observe the full fixed late-response window");
    assert_stable(pool, &fixture, &outcome, &stable).await;
    mark(&control, "late-window-verified");
    await_marker(&control, "handlers-joined", &mut worker).await;
    assert_stable(pool, &fixture, &outcome, &stable).await;
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    assert_eq!(expected["exit_code_after_interrupt"], -2);
    assert_stable(pool, &fixture, &outcome, &stable).await;
    output.assert_private_quiet(fixture.spec["token"].as_str().unwrap(), database_url);
    mark(&control, "child-done");
    eprintln!("native worker deadline {case_name}: two real renewals, retained prefix, exact outcome and no late effects passed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };

    const OUTPUT_TOKEN: &str = "synthetic-deadline-output-token";
    const OUTPUT_DATABASE: &str =
        "postgres://synthetic:synthetic-deadline-db-password@127.0.0.1/owned_test";

    struct OutputFixture {
        output: Option<OwnedOutput>,
        writers: Option<[File; 2]>,
        root: PathBuf,
    }

    impl OutputFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "canvas-deadline-output-test-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&root).unwrap();
            let mut fixture = Self {
                output: None,
                writers: None,
                root,
            };
            let control = fixture.root.join("native-control");
            std::fs::create_dir(&control).unwrap();
            let (output, stdout, stderr) = OwnedOutput::new(&control);
            fixture.output = Some(output);
            drop((stdout, stderr));
            // Reopen only the test-owned append writers; never clone a reader
            // descriptor (which would share its seek offset on Unix).
            fixture.writers = Some(["worker-stdout.log", "worker-stderr.log"].map(|name| {
                OpenOptions::new()
                    .append(true)
                    .open(fixture.root.join("native-worker-output").join(name))
                    .unwrap()
            }));
            fixture
        }

        fn append(&mut self, stream: usize, bytes: &[u8]) {
            let writer = &mut self.writers.as_mut().unwrap()[stream];
            writer.write_all(bytes).unwrap();
            writer.flush().unwrap();
        }

        fn check(&mut self) {
            self.output
                .as_mut()
                .unwrap()
                .assert_private_quiet(OUTPUT_TOKEN, OUTPUT_DATABASE);
        }

        fn rejected(&mut self) -> String {
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check()))
                .expect_err("nonempty owned output must fail closed");
            failure
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    failure
                        .downcast_ref::<&str>()
                        .map(|value| (*value).to_owned())
                })
                .expect("output rejection must have a static textual diagnostic")
        }
    }

    impl Drop for OutputFixture {
        fn drop(&mut self) {
            drop(self.writers.take());
            drop(self.output.take());
            // Exact known temporary files only; never recursively delete a
            // derived root or follow a directory discovered from log contents.
            let logs = self.root.join("native-worker-output");
            for name in ["worker-stdout.log", "worker-stderr.log"] {
                let _ = std::fs::remove_file(logs.join(name));
            }
            let _ = std::fs::remove_dir(logs);
            let _ = std::fs::remove_dir(self.root.join("native-control"));
            let _ = std::fs::remove_dir(&self.root);
        }
    }

    #[test]
    fn native_deadline_output_empty_streams_pass_and_owned_files_are_removed() {
        let mut fixture = OutputFixture::new();
        let root = fixture.root.clone();
        fixture.check();
        fixture.check();
        drop(fixture);
        assert!(!root.exists());
    }

    #[test]
    fn native_deadline_output_classified_sqlx_warnings_still_fail_strict_gate() {
        use super::super::canvas_worker_output::OutputDiagnostic;
        let record = serde_json::json!({"level":"WARN","target":"sqlx::query",
            "fields":{"message":"slow statement: execution time exceeded alert threshold",
                "db.statement":"synthetic-private-query"}});
        let bytes = format!("{record}\n").into_bytes();
        for stream in 0..2 {
            let mut fixture = OutputFixture::new();
            fixture.append(stream, &bytes);
            for _ in 0..2 {
                assert_eq!(
                    fixture
                        .output
                        .as_mut()
                        .unwrap()
                        .diagnostic(OUTPUT_TOKEN, OUTPUT_DATABASE),
                    OutputDiagnostic::SqlxSlowQueries
                );
                let message = fixture.rejected();
                assert!(message.contains(&format!("stream={stream} bytes={}", bytes.len())));
                assert!(!message.contains("synthetic-private-query"));
            }
            // A later private append cannot be hidden by a prior classification.
            fixture.append(stream, OUTPUT_TOKEN.as_bytes());
            assert_eq!(
                fixture
                    .output
                    .as_mut()
                    .unwrap()
                    .diagnostic(OUTPUT_TOKEN, OUTPUT_DATABASE),
                OutputDiagnostic::AuthenticationMaterial
            );
            assert_eq!(
                fixture.rejected(),
                "native worker output contained synthetic authentication material"
            );
        }
    }

    #[test]
    fn native_deadline_output_rejects_ordinary_bytes_in_either_stream_without_payload() {
        for stream in 0..2 {
            let mut fixture = OutputFixture::new();
            fixture.append(stream, b"private-ordinary-output");
            for _ in 0..2 {
                let message = fixture.rejected();
                assert!(message.contains(&format!("stream={stream} bytes=23")));
                assert!(!message.contains("private-ordinary-output"));
            }
        }
    }

    #[test]
    fn native_deadline_output_rejects_each_authentication_sentinel_without_echoing_it() {
        for secret in [
            OUTPUT_TOKEN,
            "synthetic-process-signal-key",
            "synthetic-startup-api-key",
            "synthetic-startup-hmac-key",
            "synthetic-local-only",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "synthetic-deadline-db-password",
        ] {
            for stream in 0..2 {
                let mut fixture = OutputFixture::new();
                fixture.append(stream, format!("prefix:{secret}:suffix").as_bytes());
                assert_eq!(
                    fixture.rejected(),
                    "native worker output contained synthetic authentication material"
                );
            }
        }
    }

    #[test]
    fn native_deadline_output_rejects_oversized_capture_at_the_read_cap() {
        for stream in 0..2 {
            let mut fixture = OutputFixture::new();
            fixture.append(stream, &vec![b'x'; 65_537]);
            assert_eq!(
                fixture.rejected(),
                "native worker output exceeded bounded capture"
            );
        }
    }

    #[test]
    fn native_deadline_output_rechecks_appends_after_an_initial_empty_read() {
        for stream in 0..2 {
            let mut fixture = OutputFixture::new();
            fixture.check();
            fixture.append(stream, b"first:");
            assert!(fixture.rejected().contains("bytes=6"));
            fixture.append(stream, OUTPUT_TOKEN.as_bytes());
            assert_eq!(
                fixture.rejected(),
                "native worker output contained synthetic authentication material"
            );
            let mut reader = File::open(
                fixture
                    .root
                    .join("native-worker-output")
                    .join(["worker-stdout.log", "worker-stderr.log"][stream]),
            )
            .unwrap();
            reader.seek(SeekFrom::Start(0)).unwrap();
            let mut actual = String::new();
            reader.read_to_string(&mut actual).unwrap();
            assert_eq!(actual, format!("first:{OUTPUT_TOKEN}"));
        }
    }

    fn sample(age: f64, before: Instant, after: Instant) -> AgeSample {
        AgeSample {
            row: json!({
                "id": "worker-validation-job", "attempt_count": 1,
                "started_at": "synthetic-start", "age_seconds": age,
            }),
            before,
            after,
        }
    }

    #[test]
    fn native_deadline_timing_rejects_wrong_timer_and_accepts_exact_tolerance_boundaries() {
        let start = Instant::now();
        let initial = sample(1.0, start, start);
        assert_timing(&initial, None, false);
        for (age, accepted) in [
            (25.0, false),
            (29.499, false),
            (29.5, true),
            (30.0, true),
            (33.0, true),
            (33.001, false),
            (35.0, false),
        ] {
            let at = start + Duration::from_secs_f64(age - 1.0);
            let observed = sample(age, at, at);
            assert_eq!(
                std::panic::catch_unwind(|| assert_timing(&observed, Some(&initial), true)).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn native_deadline_timing_rejects_setup_latency_clock_and_generation_gaps() {
        let start = Instant::now();
        for (age, accepted) in [(0.0, true), (2.0, true), (2.001, false), (-0.001, false)] {
            let observed = sample(age, start, start);
            assert_eq!(
                std::panic::catch_unwind(|| assert_timing(&observed, None, false)).is_ok(),
                accepted
            );
        }
        for (latency, accepted) in [(1.0, true), (1.001, false)] {
            let observed = sample(1.0, start, start + Duration::from_secs_f64(latency));
            assert_eq!(
                std::panic::catch_unwind(|| assert_timing(&observed, None, false)).is_ok(),
                accepted
            );
        }
        let initial = sample(1.0, start, start);
        for (drift, accepted) in [(-0.5, true), (0.5, true), (-0.501, false), (0.501, false)] {
            let at = start + Duration::from_secs_f64(29.0 + drift);
            let observed = sample(30.0, at, at);
            assert_eq!(
                std::panic::catch_unwind(|| assert_timing(&observed, Some(&initial), true)).is_ok(),
                accepted
            );
        }
        for (key, value) in [
            ("id", json!("wrong-job")),
            ("attempt_count", json!(2)),
            ("started_at", json!("changed-start")),
            ("age_seconds", Value::Null),
        ] {
            let at = start + Duration::from_secs(29);
            let mut observed = sample(30.0, at, at);
            observed.row[key] = value;
            assert!(
                std::panic::catch_unwind(|| assert_timing(&observed, Some(&initial), true))
                    .is_err()
            );
        }
    }
}
