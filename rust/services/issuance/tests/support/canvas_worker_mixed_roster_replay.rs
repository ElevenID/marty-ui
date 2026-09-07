//! Seven naturally scheduled cycles of the actual worker against real HTTPS.
//! The Python owner checks frozen Canvas and synthetic signer wire transcripts;
//! this owner checks complete durable projections, preservation and idle restart.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::snapshot,
    canvas_worker_rest_replay::{prepare, worker_environment, WorkerFixture},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

async fn scalar(pool: &PgPool, query: &str) -> Value {
    // Private test-only SELECTs from the compile-time frozen fixtures. The
    // only transformation replaces two fixed synthetic target literals;
    // caller, provider and environment values never enter this SQL text.
    sqlx::query_scalar(sqlx::AssertSqlSafe(query))
        .fetch_one(pool)
        .await
        .unwrap()
}

fn control_directory() -> PathBuf {
    let directory =
        PathBuf::from(std::env::var("MARTY_CANVAS_WORKER_MIXED_ROSTER_CONTROL").unwrap())
            .canonicalize()
            .unwrap();
    let certificate = PathBuf::from(std::env::var("SSL_CERT_FILE").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(
        directory,
        certificate.parent().unwrap().join("native-control")
    );
    assert!(directory.is_dir());
    directory
}

fn marker(index: usize, kind: &str) -> String {
    assert!(index < 7);
    assert!(matches!(kind, "ready" | "done" | "ack"));
    format!("stage-{kind}-{index}")
}

async fn await_parent(
    directory: &std::path::Path,
    index: usize,
    kind: &str,
    worker: &mut Option<OwnedWorker>,
) {
    assert!(matches!(kind, "ready" | "ack"));
    let path = directory.join(marker(index, kind));
    tokio::time::timeout(Duration::from_secs(20), async {
        while !path.is_file() {
            if let Some(worker) = worker.as_mut() {
                assert!(
                    worker.0.try_wait().unwrap().is_none(),
                    "worker exited at handshake"
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTPS parent must acknowledge the exact stage within its deadline");
}

async fn seed(pool: &PgPool, matrix: &Value, case: &Value, origin: &str) {
    let old: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-mixed-roster-oracle.json"
    ))
    .unwrap();
    let sources = old["observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|stage| stage["name"] == matrix["seed_observation_stage"])
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 1);
    let candidates = sources[0]["snapshot"]["candidates"].as_array().unwrap();
    let source = candidates
        .iter()
        .find(|candidate| candidate["user"] == "7")
        .unwrap();
    let heads = source["observations"].as_array().unwrap();
    assert_eq!(heads.len(), 2);
    assert_eq!(
        heads
            .iter()
            .map(|head| text(&head["requirement"]))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["rest", "ags"])
    );
    assert!(heads
        .iter()
        .all(|head| head["current"] == true && head["superseded"] == false));
    let requirements: Value = serde_json::from_str(
        &serde_json::to_string(&matrix["requirements"])
            .unwrap()
            .replace("{origin}", origin),
    )
    .unwrap();
    let metadata = json!({
        "verified_binding_id": "binding-review",
        "verified_binding_config_version": 1,
        "nrps_context_memberships_url": format!("{origin}/api/lti/courses/42/memberships"),
        "roster_cursor": case["initial_cursor"],
        "synthetic_marker": "preserve",
    });
    // All fixture writes occur in this transaction before any worker starts.
    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_platforms SET lti_issuer=$1,lti_client_id='synthetic-client',lti_trust_profile='self_managed_same_origin',lti_openid_configuration=$2 WHERE id='platform-review' AND organization_id='org-review'")
        .bind(origin).bind(json!({"token_endpoint": format!("{origin}/login/oauth2/token")}))
        .execute(&mut *transaction).await.unwrap().rows_affected(), 1);
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=$1 WHERE id='binding-review' AND organization_id='org-review'")
        .bind(requirements).execute(&mut *transaction).await.unwrap().rows_affected(), 1);
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET target_type='background_roster',application_id=NULL,schedule_seconds=$1,metadata=$2 WHERE id='target-review' AND organization_id='org-review'")
        .bind(i32::try_from(matrix["schedule_seconds"].as_i64().unwrap()).unwrap())
        .bind(metadata).execute(&mut *transaction).await.unwrap().rows_affected(), 1);
    for identity in matrix["identities"].as_array().unwrap() {
        let user = text(&identity["user"]);
        assert_eq!(sqlx::query("INSERT INTO issuance_service.canvas_learner_identities (id,organization_id,platform_id,deployment_id,lti_subject,canvas_user_id,status) VALUES ($1,'org-review','platform-review','deployment',$2,$3,$4)")
            .bind(format!("worker-roster-identity-{user}")).bind(format!("subject-{user}"))
            .bind(user).bind(text(&identity["status"]))
            .execute(&mut *transaction).await.unwrap().rows_affected(), 1);
    }
    for candidate in matrix["terminal_candidates"].as_array().unwrap() {
        let user = text(&candidate["user"]);
        let id = format!("worker-roster-candidate-{user}");
        let identity = if user == "7" {
            "identity-review".to_owned()
        } else {
            format!("worker-roster-identity-{user}")
        };
        let key = hex::encode(Sha256::digest(
            format!("platform-review:binding-review:canvas_user:{user}").as_bytes(),
        ));
        assert_eq!(sqlx::query("INSERT INTO issuance_service.canvas_award_candidates (id,organization_id,platform_id,binding_id,learner_identity_id,candidate_key,canvas_user_id,lti_subject,state,observed_at,created_at,updated_at) VALUES ($1,'org-review','platform-review','binding-review',$2,$3,$4,$5,$6,now(),now(),now())")
            .bind(&id).bind(identity).bind(key).bind(user).bind(format!("subject-{user}"))
            .bind(text(&candidate["state"])).execute(&mut *transaction).await.unwrap().rows_affected(), 1);
        for head in heads {
            let requirement = text(&head["requirement"]);
            assert_eq!(sqlx::query("INSERT INTO issuance_service.canvas_candidate_observations (id,organization_id,candidate_id,requirement_id,logical_key,assertion,verification,payload_hash,is_current,observed_at,created_at) VALUES ($1,'org-review',$2,$3,$3,$4,$5,$6,true,now(),now())")
                .bind(format!("worker-roster-observation-{user}-{requirement}")).bind(&id)
                .bind(requirement).bind(&head["assertion"]).bind(&head["verification"])
                .bind(text(&head["hash"])).execute(&mut *transaction).await.unwrap().rows_affected(), 1);
        }
    }
    transaction.commit().await.unwrap();
}

async fn observe(
    pool: &PgPool,
    fixture: &WorkerFixture,
    matrix: &Value,
    roster_sql: &str,
) -> Value {
    let state = snapshot(pool, fixture).await;
    let roster = scalar(pool, roster_sql).await;
    assert_eq!(roster["applications"], 1);
    assert_eq!(roster["credentials"], 1);
    assert_eq!(roster["facts"], 0);
    let stored = scalar(pool, text(&matrix["stored_roster_sql"]))
        .await
        .to_string();
    assert!(!stored.contains("SYNTHETIC_NAME_MUST_NOT_PERSIST"));
    assert!(!stored.contains("synthetic-no-retention@example.invalid"));
    json!({"state": state, "roster": roster, "target": scalar(pool, text(&matrix["target_sql"])).await})
}

async fn stop_preserving(
    worker: &mut Option<OwnedWorker>,
    pool: &PgPool,
    fixture: &WorkerFixture,
    matrix: &Value,
    roster_sql: &str,
    observed: &Value,
) {
    let jobs = scalar(pool, text(&matrix["job_rows_sql"])).await;
    let mut stopped = worker
        .take()
        .expect("only the owned live worker is stopped");
    stopped.signal("SIGINT");
    assert_eq!(stopped.wait().await.code(), Some(130));
    assert_eq!(
        observe(pool, fixture, matrix, roster_sql).await,
        *observed,
        "durable state changed after idle interrupt"
    );
    assert_eq!(
        scalar(pool, text(&matrix["job_rows_sql"])).await,
        jobs,
        "raw jobs changed after idle interrupt"
    );
}

pub async fn replay(
    pool: &PgPool,
    database_url: &str,
    origin: &str,
    signer_origin: &str,
    case_name: &str,
) {
    assert_eq!(std::env::consts::OS, "linux");
    let matrix: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-mixed-roster-scenarios.json"
    ))
    .unwrap();
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-mixed-roster-oracle.json"
    ))
    .unwrap();
    let roster_matrix: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-mixed-roster-scenarios.json"
    ))
    .unwrap();
    let cases = matrix["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1);
    let case = &cases[0];
    assert_eq!(case["name"], case_name);
    assert_eq!(reference["case"], case_name);
    assert_eq!(
        matrix["reference_scenario"],
        "canvas-worker-rest-scenarios.json"
    );
    assert_eq!(
        matrix["roster_scenario"],
        "canvas-mixed-roster-scenarios.json"
    );
    assert_eq!(
        matrix["roster_reference"],
        "canvas-mixed-roster-oracle.json"
    );
    assert_eq!(matrix["schedule_seconds"], 60);
    let signer = url::Url::parse(signer_origin).unwrap();
    assert_eq!(signer.scheme(), "http");
    assert_eq!(signer.host_str(), Some("127.0.0.1"));
    assert!(signer.port().is_some());
    assert_eq!(signer.path(), "/internal/signing-keys");
    assert!(signer.query().is_none() && signer.fragment().is_none());
    assert!(signer.username().is_empty() && signer.password().is_none());
    let fixture = prepare(pool, origin, "rest").await;
    seed(pool, &matrix, case, origin).await;
    let roster_sql =
        text(&roster_matrix["snapshot_sql"]).replace("'target-roster'", "'target-review'");
    assert_ne!(roster_sql, text(&roster_matrix["snapshot_sql"]));
    assert_eq!(scalar(pool, &roster_sql).await, reference["initial_roster"]);
    assert_eq!(scalar(pool, text(&matrix["job_rows_sql"])).await, json!([]));
    let mut environment = worker_environment(origin);
    environment.extend([
        (
            "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE".into(),
            matrix["batch_size"].to_string(),
        ),
        (
            "CANVAS_BACKGROUND_ROSTER_MAX_SIZE".into(),
            matrix["roster_limit"].to_string(),
        ),
        ("CANVAS_SYNC_WORKER_POLL_SECONDS".into(), "0.1".into()),
        ("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST".into(), origin.into()),
        (
            "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID".into(),
            "org-review".into(),
        ),
        (
            "CANVAS_LTI_TOOL_ISSUER_DID".into(),
            "did:web:synthetic-worker.invalid:canvas".into(),
        ),
        (
            "ISSUANCE_API_KEY".into(),
            "synthetic-startup-api-key".into(),
        ),
        ("SIGNING_KEYS_INTERNAL_URL".into(), signer_origin.into()),
    ]);
    let stages = case["stages"].as_array().unwrap();
    let expected = reference["observations"].as_array().unwrap();
    assert_eq!(stages.len(), 7);
    assert_eq!(expected.len(), stages.len());
    assert_eq!(
        stages
            .iter()
            .map(|stage| text(&stage["name"]))
            .collect::<BTreeSet<_>>()
            .len(),
        7
    );
    let directory = control_directory();
    let mut worker = None;
    let mut restarts = Vec::new();
    let mut completed_jobs: Vec<Value> = Vec::new();
    for (index, (stage, expected)) in stages.iter().zip(expected).enumerate() {
        assert_eq!(stage["name"], expected["name"]);
        await_parent(&directory, index, "ready", &mut worker).await;
        if worker.is_none() {
            worker = Some(OwnedWorker::start_with_environment(
                database_url,
                "worker-rest",
                &environment,
            ));
        }
        let observed = tokio::time::timeout(Duration::from_secs(95), async {
            loop {
                assert!(worker.as_mut().unwrap().0.try_wait().unwrap().is_none(), "worker exited before stage outcome");
                let jobs = scalar(pool, text(&fixture.spec["jobs_sql"])).await;
                let rows = jobs.as_array().unwrap();
                assert!(rows.len() <= index + 1, "worker scheduled unexpected extra work");
                if rows.len() == index + 1 {
                    let latest = &rows[index];
                    assert!(!matches!(latest["status"].as_str(), Some("retry" | "dead_letter")), "mixed-roster job failed: {latest}");
                    let idle: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest' AND metadata->>'phase'='idle')").fetch_one(pool).await.unwrap();
                    if latest["status"] == "succeeded" && idle {
                        break observe(pool, &fixture, &matrix, &roster_sql).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("natural minute-scheduled worker cycle must reach its durable idle outcome");
        for key in ["state", "roster", "target"] {
            assert_eq!(observed[key], expected[key], "{key} in {}", stage["name"]);
        }
        let raw_jobs = scalar(pool, text(&matrix["job_rows_sql"])).await;
        let raw_jobs = raw_jobs.as_array().unwrap();
        assert_eq!(raw_jobs.len(), index + 1);
        assert_eq!(
            &raw_jobs[..index],
            completed_jobs.as_slice(),
            "later cycles or restart replaced an earlier completed job"
        );
        assert_eq!(
            raw_jobs
                .iter()
                .map(|job| text(&job["id"]))
                .collect::<BTreeSet<_>>()
                .len(),
            raw_jobs.len(),
            "every natural cycle must retain a distinct durable job"
        );
        completed_jobs.clone_from(raw_jobs);
        assert_eq!(expected["target"]["worker_id"], Value::Null);
        for job in expected["state"]["jobs"].as_array().unwrap() {
            assert_eq!(job["status"], "succeeded");
            assert_eq!(job["attempt_count"], 1);
            assert_eq!(
                job["result"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "candidates_seen",
                    "pending_claim",
                    "identity_link_required",
                    "observations_written"
                ])
            );
        }
        assert_eq!(
            expected["issued_rows_transactions_ciphertext_preserved"],
            true
        );
        assert_eq!(expected["roster_name_email_not_retained"], true);
        if index == 6 {
            stop_preserving(&mut worker, pool, &fixture, &matrix, &roster_sql, &observed).await;
            assert_eq!(reference["exit_code_after_interrupt"], -2);
            assert_eq!(reference["final_durable_state_unchanged_after_exit"], true);
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(marker(index, "done")))
            .unwrap();
        await_parent(&directory, index, "ack", &mut worker).await;
        assert_eq!(
            stage
                .get("restart_after_idle")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            index == 1
        );
        if index == 1 {
            stop_preserving(&mut worker, pool, &fixture, &matrix, &roster_sql, &observed).await;
            restarts.push(json!({"after_stage": stage["name"], "cursor": observed["roster"]["cursor"], "job_count": index + 1, "exit_code": -2, "durable_state_unchanged": true}));
        }
        eprintln!(
            "Native mixed-roster durable stage passed: {}",
            stage["name"]
        );
    }
    assert!(worker.is_none());
    assert_eq!(Value::Array(restarts), reference["idle_restarts"]);
    fixture.assert_preserved(pool).await;
}
