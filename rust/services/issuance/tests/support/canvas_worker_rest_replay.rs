//! Actual native binary, published schema, real HTTPS and encrypted OAuth.
//! The Python parent checks every request; this child checks durable effects.
use super::canvas_worker_process_signals::OwnedWorker;
use chrono::Utc;
use marty_issuance_service::{
    canvas_oauth::{CanvasOAuthConnection, CanvasOAuthRepository, CanvasOAuthSecretVault},
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    integration_secret::{IntegrationSecretCipher, NewIntegrationSecret},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::OnceLock, time::Duration};

const CIPHERTEXT_SQL: &str = "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'";

pub(super) struct WorkerFixture {
    pub(super) spec: &'static Value,
    pub(super) shared: &'static Value,
    preserved: Value,
    ciphertext: String,
}

impl WorkerFixture {
    pub(super) async fn assert_preserved(&self, pool: &PgPool) {
        let current: Value =
            sqlx::query_scalar(self.shared["preserved_rows_sql"].as_str().unwrap())
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(current, self.preserved, "issued rows changed");
        let current_ciphertext: String = sqlx::query_scalar(CIPHERTEXT_SQL)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(current_ciphertext, self.ciphertext);
    }
}

pub(super) fn worker_environment(origin: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "org-review".into()),
        ("CANVAS_PRIVATE_ORIGIN_ALLOWLIST".into(), origin.into()),
        (
            "SSL_CERT_FILE".into(),
            std::env::var("SSL_CERT_FILE").unwrap(),
        ),
        (
            "SSL_CERT_DIR".into(),
            std::env::var("SSL_CERT_DIR").unwrap(),
        ),
    ])
}

pub(super) fn validation_scenarios() -> &'static Value {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-validation-scenarios.json"
        ))
        .unwrap()
    })
}

pub(super) async fn seed_validation_case(pool: &PgPool, name: &str) -> &'static Value {
    let matrix = validation_scenarios();
    let cases = matrix["cases"].as_array().unwrap();
    let matching = cases
        .iter()
        .filter(|case| case["name"] == name)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "unknown or duplicate validation case");
    let case = matching[0];
    for statement in case["seed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .chain(std::iter::once(
            matrix["initial_job_seed"].as_str().unwrap(),
        ))
    {
        sqlx::raw_sql(statement).execute(pool).await.unwrap();
    }
    case
}

pub(super) async fn prepare(pool: &PgPool, origin: &str, scenario: &str) -> WorkerFixture {
    let origin_url = url::Url::parse(origin).unwrap();
    assert_eq!(origin_url.scheme(), "https");
    assert_eq!(origin_url.host_str(), Some("127.0.0.1"));
    assert!(origin_url.port().is_some());
    static SPEC: OnceLock<Value> = OnceLock::new();
    static FACTS_SPEC: OnceLock<Value> = OnceLock::new();
    static RETRY_SPEC: OnceLock<Value> = OnceLock::new();
    static SHARED: OnceLock<Value> = OnceLock::new();
    let spec = SPEC.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-rest-scenarios.json"
        ))
        .unwrap()
    });
    let extend = |source: &str| {
        let extension: Value = serde_json::from_str(source).unwrap();
        let mut combined = spec.clone();
        combined
            .as_object_mut()
            .unwrap()
            .extend(extension.as_object().unwrap().clone());
        combined
    };
    let spec = match scenario {
        "rest" => spec,
        "facts" => FACTS_SPEC.get_or_init(|| {
            extend(include_str!(
                "../../../../../contracts/canvas-worker-facts-scenarios.json"
            ))
        }),
        "retry" => RETRY_SPEC.get_or_init(|| {
            extend(include_str!(
                "../../../../../contracts/canvas-worker-retry-scenarios.json"
            ))
        }),
        _ => panic!("unknown static worker scenario"),
    };
    let shared = SHARED.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-issued-review-scenarios.json"
        ))
        .unwrap()
    });
    for statement in shared["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    if let Some(requirements) = spec.get("requirements") {
        sqlx::query("UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=$1 WHERE id='binding-review'")
            .bind(requirements).execute(pool).await.unwrap();
    }
    sqlx::query("UPDATE issuance_service.canvas_platforms SET canvas_base_url=$1")
        .bind(origin)
        .execute(pool)
        .await
        .unwrap();
    let vault = PostgresIntegrationSecretVault::new(
        pool.clone(),
        IntegrationSecretCipher::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap(),
    );
    vault
        .save(NewIntegrationSecret {
            id: "worker-rest-token".into(),
            organization_id: "org-review".into(),
            name: "Synthetic REST token".into(),
            provider: "canvas".into(),
            purpose: "api_token".into(),
            value: spec["token"].as_str().unwrap().into(),
            metadata: json!({}),
        })
        .await
        .unwrap();
    let published = PostgresCanvasOAuthRepository::new(pool.clone())
        .publish_connection(&CanvasOAuthConnection {
            id: "worker-rest-connection".into(),
            organization_id: "org-review".into(),
            platform_id: "platform-review".into(),
            canvas_base_url: origin.into(),
            platform_config_version: 1,
            client_id: "synthetic-client".into(),
            client_secret_ref: "org_secret://org-review/unused-client".into(),
            capabilities: vec![],
            scopes: vec![],
            access_token_secret_ref: Some("org_secret://org-review/worker-rest-token".into()),
            refresh_token_secret_ref: None,
            token_expires_at: None,
            status: "connected".into(),
            revoke_retry_count: 0,
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
    assert!(published.is_some());
    let preserved: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let ciphertext: String = sqlx::query_scalar(CIPHERTEXT_SQL)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_ne!(ciphertext, spec["token"].as_str().unwrap());
    WorkerFixture {
        spec,
        shared,
        preserved,
        ciphertext,
    }
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, scenario: &str) {
    let fixture = prepare(
        pool,
        origin,
        if matches!(scenario, "retry-after" | "validation") {
            "rest"
        } else {
            scenario
        },
    )
    .await;
    let (spec, shared) = (fixture.spec, fixture.shared);
    let mut matrix_stages = Value::Null;
    let mut reference: Value = serde_json::from_str(match scenario {
        "rest" => include_str!("../../../../../contracts/canvas-worker-rest-oracle.json"),
        "facts" => include_str!("../../../../../contracts/canvas-worker-facts-oracle.json"),
        "retry" => include_str!("../../../../../contracts/canvas-worker-retry-oracle.json"),
        "retry-after" => {
            include_str!("../../../../../contracts/canvas-worker-retry-after-oracle.json")
        }
        "validation" => {
            include_str!("../../../../../contracts/canvas-worker-validation-oracle.json")
        }
        _ => unreachable!(),
    })
    .unwrap();
    if matches!(scenario, "retry-after" | "validation") {
        let flag = if scenario == "validation" {
            "MARTY_CANVAS_WORKER_VALIDATION_CASE"
        } else {
            "MARTY_CANVAS_WORKER_RETRY_AFTER_CASE"
        };
        let name = std::env::var(flag).unwrap();
        let stage = if scenario == "validation" {
            seed_validation_case(pool, &name).await.clone()
        } else {
            let matrix: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-retry-after-scenarios.json"
            ))
            .unwrap();
            let cases = matrix["cases"].as_array().unwrap();
            let matching = cases
                .iter()
                .filter(|case| case["name"] == name)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1, "unknown or duplicate Retry-After case");
            matching[0].clone()
        };
        matrix_stages = json!([stage]);
        reference = reference[&name].clone();
    }
    let stages = if matches!(scenario, "retry-after" | "validation") {
        &matrix_stages
    } else {
        &spec["stages"]
    }
    .as_array()
    .unwrap();
    let observations = reference["observations"].as_array().unwrap();
    assert_eq!(
        stages.len(),
        match scenario {
            "retry" => 5,
            "retry-after" | "validation" => 1,
            _ => 4,
        }
    );
    assert_eq!(stages.len(), observations.len());
    for (index, (stage, expected)) in stages.iter().zip(observations).enumerate() {
        assert_eq!(stage["name"], expected["name"]);
        let prior_job_ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs ORDER BY created_at,id",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        let retry_existing = stage["retry_existing"].as_bool() == Some(true);
        if retry_existing {
            let job_id = prior_job_ids
                .last()
                .expect("retry must refer to an existing job");
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let due: bool = sqlx::query_scalar("SELECT status='retry' AND available_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1")
                        .bind(job_id).fetch_one(pool).await.unwrap();
                    if due { break; }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }).await.expect("actual persisted retry must become due without timestamp mutation");
        } else {
            sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET next_run_at=clock_timestamp() WHERE id='target-review'")
                .execute(pool).await.unwrap();
        }
        let expected_jobs = stage["expected_jobs"]
            .as_u64()
            .map(|count| usize::try_from(count).unwrap())
            .unwrap_or(index + 1);
        let expected_attempts = stage["expected_attempts"].as_i64().unwrap_or(1);
        assert!(expected_jobs > 0);
        sqlx::query("TRUNCATE issuance_service.canvas_worker_heartbeats")
            .execute(pool)
            .await
            .unwrap();
        let environment = worker_environment(origin);
        let mut worker =
            OwnedWorker::start_with_environment(database_url, "worker-rest", &environment);
        let (jobs, heartbeat) = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                assert!(worker.0.try_wait().unwrap().is_none(), "worker exited in {}", stage["name"]);
                let jobs: Value = sqlx::query_scalar(spec["jobs_sql"].as_str().unwrap())
                    .fetch_one(pool).await.unwrap();
                let heartbeat: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('role',role,'metadata',metadata) FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest' AND metadata->>'phase'='idle'")
                    .fetch_optional(pool).await.unwrap();
                let rows = jobs.as_array().unwrap();
                if rows.len() == expected_jobs && rows[expected_jobs - 1]["attempt_count"].as_i64() == Some(expected_attempts)
                    && matches!(rows[expected_jobs - 1]["status"].as_str(), Some("succeeded" | "retry" | "dead_letter")) {
                    if let Some(heartbeat) = heartbeat {
                        break (jobs, heartbeat);
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("actual nonempty native worker must reach an idle durable outcome");
        worker.signal("SIGINT");
        let status = worker.wait().await;
        assert_eq!(expected["exit_code_after_interrupt"], -2);
        assert_eq!(status.code(), Some(130));
        if retry_existing || scenario == "validation" {
            let current_job_ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM issuance_service.canvas_evidence_sync_jobs ORDER BY created_at,id",
            )
            .fetch_all(pool)
            .await
            .unwrap();
            assert_eq!(
                current_job_ids, prior_job_ids,
                "worker replaced an existing job"
            );
        }
        if retry_existing {
            assert_eq!(expected["same_job_ids"], true);
        } else {
            assert!(expected.get("same_job_ids").is_none());
        }
        assert_eq!(jobs, expected["jobs"], "jobs in {}", stage["name"]);
        assert_eq!(
            heartbeat, expected["heartbeat"],
            "heartbeat in {}",
            stage["name"]
        );
        for (key, query) in [
            ("snapshot", shared["snapshot_sql"].as_str().unwrap()),
            ("facts", spec["facts_sql"].as_str().unwrap()),
            ("oauth", spec["oauth_sql"].as_str().unwrap()),
        ] {
            let observed: Value = sqlx::query_scalar(query).fetch_one(pool).await.unwrap();
            assert_eq!(observed, expected[key], "{key} in {}", stage["name"]);
        }
        fixture.assert_preserved(pool).await;
        if scenario == "validation" {
            assert_eq!(prior_job_ids, ["worker-validation-job"]);
            let target: Value = sqlx::query_scalar("SELECT jsonb_build_object('enabled',enabled,'config_version',config_version) FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'")
                .fetch_one(pool).await.unwrap();
            assert_eq!(target, reference["target"], "validation target state");
        }
        if scenario == "retry-after" {
            let (available_at, updated_at): (chrono::DateTime<Utc>, chrono::DateTime<Utc>) =
                sqlx::query_as("SELECT available_at,updated_at FROM issuance_service.canvas_evidence_sync_jobs")
                    .fetch_one(pool).await.unwrap();
            // Transient synthetic timing evidence only. The HTTPS parent checks
            // this actual deadline against its emitted header, never a mock clock.
            println!(
                "\nCANVAS_WORKER_RETRY_TIMING={}",
                json!({
                    "available_at": available_at.to_rfc3339(),
                    "updated_at": updated_at.to_rfc3339(),
                })
            );
        }
    }
}
