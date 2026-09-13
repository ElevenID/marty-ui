//! All46 actual HTTP/state cases on corrected official schema. External
//! lifecycle effects are controlled exactly as in the published oracle.
use super::canvas_base_gateway_recovery::{GatewayCase, GatewayEndpoint};
use super::canvas_operations_read_replay::{
    fixtures, generated_ids, insert_review, request_case, runtime_router, seed, timestamps,
};
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_operations::{CanvasOperationsService, OperationsError},
    canvas_review_resolution::CanvasReviewLifecycle,
    credential_management::CredentialLifecycleAction,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, Notify};

struct Lifecycle {
    pool: PgPool,
    stage: Mutex<Value>,
    calls: Mutex<Vec<Value>>,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl CanvasReviewLifecycle for Lifecycle {
    async fn transition(
        &self,
        organization: &str,
        credential: &str,
        action: CredentialLifecycleAction,
        reason: &str,
    ) -> Result<(), OperationsError> {
        assert_eq!(organization, "org-review");
        assert_eq!(credential, "credential-review");
        let active: bool = sqlx::query_scalar("SELECT resolution_claim_token IS NOT NULL AND status='open' AND resolution_claim_action=$1 FROM issuance_service.evidence_policy_reviews WHERE organization_id=$2 AND credential_id=$3")
            .bind(action.as_str()).bind(organization).bind(credential).fetch_one(&self.pool).await.unwrap();
        assert!(active, "lifecycle must follow winning durable claim");
        let stage = self.stage.lock().await.clone();
        if stage["recovery_during_handler"] == true {
            sqlx::query("UPDATE issuance_service.evidence_policy_reviews SET resolution_recovery_pending=true,current_decision='{\"allowed\":true}'")
                .execute(&self.pool).await.unwrap();
        }
        self.calls.lock().await.push(json!({"action":action.as_str(),"credential_id":credential,"reason":reason,"claim_active":active}));
        if stage["concurrent"] == true {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if stage["handler_failure"] == true {
            Err(OperationsError::Internal)
        } else {
            Ok(())
        }
    }
}

fn response(value: (u16, String, Value), aliases: &mut BTreeMap<String, String>) -> Value {
    let (status, content_type, mut body) = value;
    timestamps(&mut body);
    generated_ids(&mut body, aliases);
    json!({"status":status,"content_type":content_type,"body":body})
}

pub async fn replay(pool: &PgPool, expected: &Value) {
    let [shared, scenarios, _] = fixtures();
    replay_cases(pool, shared, scenarios, expected, false).await;
}

pub async fn replay_gateway(pool: &PgPool, expected: &Value) {
    let [shared, scenarios, _] = fixtures();
    replay_cases(pool, shared, scenarios, expected, true).await;
}

pub async fn replay_inputs(pool: &PgPool, expected: &Value) {
    static SCENARIOS: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let scenarios = SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-review-input-scenarios.json"
        ))
        .unwrap()
    });
    replay_cases(pool, &fixtures()[0], scenarios, expected, false).await;
}

async fn replay_cases(
    pool: &PgPool,
    shared: &'static Value,
    scenarios: &'static Value,
    expected: &Value,
    gateway: bool,
) {
    seed(pool).await;
    let preserved_sql = shared["preserved_rows_sql"].as_str().unwrap();
    let preserved: Value = sqlx::query_scalar(preserved_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    let lifecycle = Arc::new(Lifecycle {
        pool: pool.clone(),
        stage: Mutex::new(Value::Null),
        calls: Mutex::new(Vec::new()),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let mut aliases = BTreeMap::new();
    let mut gateway_cases = Vec::new();
    let mut manual_actors = std::collections::BTreeSet::new();
    let cases = scenarios["cases"].as_array().unwrap();
    assert_eq!(
        expected["observations"].as_array().unwrap().len(),
        cases.len()
    );
    for (case, expected) in cases
        .iter()
        .zip(expected["observations"].as_array().unwrap())
    {
        *lifecycle.stage.lock().await = case.clone();
        lifecycle.calls.lock().await.clear();
        if let Some(id) = case["prepare_review"].as_str() {
            // Same explicit synthetic preparation as the published corpus.
            sqlx::query("DELETE FROM issuance_service.evidence_policy_reviews")
                .execute(pool)
                .await
                .unwrap();
            insert_review(pool, id).await;
        }
        for statement in case["sql"].as_array().into_iter().flatten() {
            sqlx::query(statement.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        let router = runtime_router(
            CanvasOperationsService::new(pool.clone(), Some("synthetic-operations-key"))
                .with_job_operations(
                    case["rollout"].as_bool().unwrap_or(true),
                    ["org-review".into()].into(),
                )
                .with_review_operations(Some(lifecycle.clone())),
        );
        let selected = gateway.then(|| GatewayCase::from_case(case)).flatten();
        let endpoint = if let Some(selected) = selected {
            gateway_cases.push(selected);
            Some(GatewayEndpoint::start(router.clone(), case).await)
        } else {
            None
        };
        let mut expected = expected.clone();
        if selected.is_some() && expected["status"] == 200 {
            assert!(expected["body"]["resolved_by"].is_null());
            expected["body"]["resolved_by"] = json!("actor-primary");
            manual_actors.insert(case["prepare_review"].as_str().unwrap().to_owned());
        }
        for review in expected["snapshot"]["reviews"].as_array_mut().unwrap() {
            if manual_actors.contains(review["id"].as_str().unwrap()) {
                assert!(matches!(
                    review["action"].as_str(),
                    Some("suspend" | "revoke")
                ));
                assert!(review["actor"].is_null());
                review["actor"] = json!("actor-primary");
            }
        }
        let send = |competing| {
            let endpoint = &endpoint;
            let router = &router;
            let expected = &expected;
            async move {
                if let Some(endpoint) = endpoint {
                    endpoint
                        .request(
                            case,
                            if competing {
                                &expected["competing_response"]
                            } else {
                                expected
                            },
                        )
                        .await
                } else {
                    request_case(router, case).await
                }
            }
        };
        let (primary, competing) = if case["concurrent"] == true {
            let (primary, competing) = tokio::join!(send(false), async {
                lifecycle.entered.notified().await;
                let result = send(true).await;
                lifecycle.release.notify_one();
                result
            });
            (primary, Some(competing))
        } else {
            (send(false).await, None)
        };
        let mut record = response(primary, &mut aliases);
        record["name"] = case["name"].clone();
        let mut snapshot: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        generated_ids(&mut snapshot, &mut aliases);
        record["snapshot"] = snapshot;
        record["lifecycle_calls"] = json!(*lifecycle.calls.lock().await);
        if let Some(competing) = competing {
            record["competing_response"] = response(competing, &mut aliases);
        }
        assert_eq!(record, expected, "full operations parity: {}", case["name"]);
        let current: Value = sqlx::query_scalar(preserved_sql)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            current, preserved,
            "controlled lifecycle must not mutate credential/transaction rows"
        );
        if let Some(endpoint) = endpoint {
            endpoint
                .close(if case["concurrent"] == true { 2 } else { 1 })
                .await;
        }
    }
    if gateway {
        assert_eq!(gateway_cases, GatewayCase::ALL);
        assert_eq!(
            cases.len(),
            46,
            "preserve all original setup/follow-up cases"
        );
    }
}
