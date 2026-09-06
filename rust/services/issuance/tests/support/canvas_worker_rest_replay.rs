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

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str) {
    let origin_url = url::Url::parse(origin).unwrap();
    assert_eq!(origin_url.scheme(), "https");
    assert_eq!(origin_url.host_str(), Some("127.0.0.1"));
    assert!(origin_url.port().is_some());
    static SPEC: OnceLock<Value> = OnceLock::new();
    static SHARED: OnceLock<Value> = OnceLock::new();
    let spec = SPEC.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-rest-scenarios.json"
        ))
        .unwrap()
    });
    let shared = SHARED.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-issued-review-scenarios.json"
        ))
        .unwrap()
    });
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-rest-oracle.json"
    ))
    .unwrap();
    for statement in shared["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
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
    let stages = spec["stages"].as_array().unwrap();
    let observations = reference["observations"].as_array().unwrap();
    assert_eq!(stages.len(), 4);
    assert_eq!(stages.len(), observations.len());
    for (index, (stage, expected)) in stages.iter().zip(observations).enumerate() {
        assert_eq!(stage["name"], expected["name"]);
        sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET next_run_at=clock_timestamp() WHERE id='target-review'")
            .execute(pool).await.unwrap();
        sqlx::query("TRUNCATE issuance_service.canvas_worker_heartbeats")
            .execute(pool)
            .await
            .unwrap();
        let environment = BTreeMap::from([
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
        ]);
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
                if rows.len() == index + 1 && matches!(rows[index]["status"].as_str(), Some("succeeded" | "retry" | "dead_letter")) {
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
        let current: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            current, preserved,
            "issued rows changed in {}",
            stage["name"]
        );
        let current_ciphertext: String = sqlx::query_scalar(CIPHERTEXT_SQL)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(current_ciphertext, ciphertext);
    }
}
