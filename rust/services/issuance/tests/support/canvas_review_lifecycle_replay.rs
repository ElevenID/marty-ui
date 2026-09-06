//! Real Rust review + credential service + PostgreSQL replay. Only external
//! status publication and mirror ports are controlled, matching published Python.
use super::canvas_operations_read_replay::{
    fixtures, insert_review, request_case, seed, timestamps,
};
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_lifecycle_delivery::CanvasLifecycleProviderError,
    lossless_json::{object, LosslessObject},
};
use marty_issuance_service::{
    canvas_lifecycle_delivery::{CanvasLifecycleCredential, CanvasLifecycleStatusProvider},
    canvas_operations::{candidate_router, CanvasOperationsService},
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleEvent, CredentialLifecycleEventSink,
        CredentialManagementPortError, CredentialManagementService, CredentialStatusPublisher,
        ManagedCredential,
    },
    credential_management_postgres::PostgresCredentialManagementRepository,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

struct Ports {
    pool: PgPool,
    stage: Mutex<Value>,
    calls: Mutex<Vec<Value>>,
    entered: Notify,
    release: Notify,
}
impl Ports {
    async fn observe(
        &self,
        port: &str,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
        delivery: Option<&Value>,
    ) {
        let claim: bool = sqlx::query_scalar("SELECT resolution_claim_token IS NOT NULL AND status='open' AND resolution_claim_action=$1 FROM issuance_service.evidence_policy_reviews")
            .bind(action.as_str()).fetch_one(&self.pool).await.unwrap();
        assert!(claim);
        self.calls.lock().await.push(json!({"port":port,"action":action.as_str(),
            "credential_id":credential.id,"credential_status":credential.status.as_str(),
            "reason":reason,"delivery_id":delivery.map(|record| &record["id"]),"claim_active":claim}));
        let stage = self.stage.lock().await.clone();
        if stage["cancel_at"] == port || (stage["concurrent"] == true && port == "publication") {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
}
#[async_trait]
impl CredentialStatusPublisher for Ports {
    async fn publish(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        self.observe("publication", credential, action, reason, None)
            .await;
        if self.stage.lock().await["publication_failure"] == true {
            Err(CredentialManagementPortError(
                "Synthetic publication unavailable".into(),
            ))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl CanvasLifecycleStatusProvider for Ports {
    async fn synchronize(
        &self,
        context: CanvasLifecycleCredential<'_>,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<LosslessObject, CanvasLifecycleProviderError> {
        let credential = context.credential;
        assert_eq!(context.transaction_id, "transaction-review");
        assert_eq!(platform["id"], "platform-review");
        self.observe("mirror", credential, action, reason, Some(delivery))
            .await;
        if self.stage.lock().await["mirror_failure"] == true {
            Err(CredentialManagementPortError(
                "Synthetic Canvas status provider unavailable".into(),
            )
            .into())
        } else {
            Ok(object(
                json!({"provider_status":credential.status.as_str()})
                    .as_object()
                    .unwrap()
                    .clone(),
            ))
        }
    }
}
#[async_trait]
impl CredentialLifecycleEventSink for Ports {
    async fn emit(&self, _: CredentialLifecycleEvent) {}
}

fn response(value: (u16, String, Value)) -> Value {
    let (status, content_type, mut body) = value;
    timestamps(&mut body);
    json!({"status":status,"content_type":content_type,"body":body})
}

pub async fn replay(pool: &PgPool, expected: &Value, use_candidate: bool) {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    let scenarios = SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-review-lifecycle-scenarios.json"
        ))
        .unwrap()
    });
    seed(pool).await;
    let preserved_sql = scenarios["preserved_rows_sql"].as_str().unwrap();
    let before: Value = sqlx::query_scalar(preserved_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    let ports = Arc::new(Ports {
        pool: pool.clone(),
        stage: Mutex::new(Value::Null),
        calls: Mutex::new(Vec::new()),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let mut repository = PostgresCredentialManagementRepository::new(pool.clone());
    if use_candidate {
        repository = repository.with_canvas_lifecycle(ports.clone());
    }
    let service =
        CredentialManagementService::new(Arc::new(repository), ports.clone(), ports.clone());
    let router = candidate_router(
        CanvasOperationsService::new(pool.clone(), Some("synthetic-operations-key"))
            .with_review_operations(Some(Arc::new(service))),
    );
    let cases = scenarios["cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        expected["observations"].as_array().unwrap().len()
    );
    for (case, expected) in cases
        .iter()
        .zip(expected["observations"].as_array().unwrap())
    {
        *ports.stage.lock().await = case.clone();
        ports.calls.lock().await.clear();
        sqlx::query("DELETE FROM issuance_service.evidence_policy_reviews")
            .execute(pool)
            .await
            .unwrap();
        insert_review(pool, case["prepare_review"].as_str().unwrap()).await;
        for statement in case["sql"].as_array().unwrap() {
            sqlx::query(statement.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        let mut record = if case.get("cancel_at").is_some() || case["concurrent"] == true {
            let app = router.clone();
            let request = case.clone();
            let task = tokio::spawn(async move { request_case(&app, &request).await });
            if tokio::time::timeout(Duration::from_secs(5), ports.entered.notified())
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
                panic!("actual lifecycle port was not reached before deadline");
            }
            let competing = response(request_case(&router, case).await);
            assert_eq!(competing["status"], 409);
            let mut record = if case.get("cancel_at").is_some() {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                json!({"cancelled":true})
            } else {
                ports.release.notify_one();
                response(task.await.unwrap())
            };
            record["competing_response"] = competing;
            record
        } else {
            response(request_case(&router, case).await)
        };
        record["name"] = case["name"].clone();
        let mut snapshot: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        timestamps(&mut snapshot);
        record["snapshot"] = snapshot;
        record["lifecycle_calls"] = json!(*ports.calls.lock().await);
        if !use_candidate {
            assert_eq!(case["name"], "suspend_delivered");
            assert_ne!(
                record, *expected,
                "legacy pending adapter must remain a negative control"
            );
            assert_eq!(record["lifecycle_calls"].as_array().unwrap().len(), 1);
            assert_eq!(
                record["snapshot"]["deliveries"][0]["metadata"]["status_sync_state"],
                "pending"
            );
            assert_eq!(expected["lifecycle_calls"].as_array().unwrap().len(), 2);
            break;
        }
        assert_eq!(record, *expected, "real lifecycle parity: {}", case["name"]);
        let current: Value = sqlx::query_scalar(preserved_sql)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(current, before, "lifecycle must not alter transactions");
    }
    // Ensure the shared seed owner is still linked; no private schema replica.
    assert_eq!(
        fixtures()[0]["schema"],
        "marty.canvas-issued-review-scenarios/v1"
    );
}
