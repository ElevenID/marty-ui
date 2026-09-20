//! Normative no-signing guard through real worker cycles and PostgreSQL.
//! Only the typed processor is controlled; this is not published-process parity.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        canvas_sync_result, CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
        CanvasSyncTarget, CanvasSyncWorkerConfig, CanvasSyncWorkerCycleResult,
    },
};
use serde_json::{json, Value};
use sqlx::PgPool;

struct ResultProcessor(BTreeMap<String, CanvasSyncResult>);

#[async_trait]
impl CanvasSyncProcessor for ResultProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        Ok(self.0.get(&target.id).expect("owned result case").clone())
    }
}

pub async fn assert_signing_guard(pool: &PgPool) {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-canvas-sync-worker.json"
    ))
    .unwrap();
    // Keep an explicit cardinality/key assertion: removing a forbidden field
    // from the contract must not silently reduce regression coverage.
    let keys = [
        "credential_id",
        "issued_credential_id",
        "signed_credential",
        "credential_jwt",
    ];
    let dispatch = &contract["processor_dispatch"];
    assert_eq!(dispatch["forbidden_outcome_keys"], json!(keys));
    assert_eq!(dispatch["forbidden_outcome"]["retryable"], false);

    let mut supplied = BTreeMap::new();
    for key in keys {
        for (index, value) in [
            Value::Null,
            json!(false),
            json!(0),
            json!(""),
            json!("synthetic-signed-result-do-not-persist"),
            json!({"detail": "synthetic-signed-result-do-not-persist"}),
            json!(["synthetic-signed-result-do-not-persist"]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut result = json!({"facts_changed": 1}).as_object().unwrap().clone();
            result.insert(key.to_owned(), value);
            supplied.insert(
                format!("signing-guard-{key}-{index}"),
                canvas_sync_result(result).unwrap(),
            );
        }
    }
    supplied.insert("control-empty".to_owned(), CanvasSyncResult::new());
    supplied.insert(
        "control-safe".to_owned(),
        canvas_sync_result(
            json!({"facts_changed": 1, "unlisted_provider_detail": "synthetic-discard"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap(),
    );
    assert_eq!(supplied.len(), 30);
    for target in supplied.keys() {
        super::seed_target(pool, target, 900).await;
    }
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        (
            "CANVAS_SYNC_WORKER_ID".to_owned(),
            "signing-guard-worker".to_owned(),
        ),
        ("CANVAS_SYNC_WORKER_BATCH_SIZE".to_owned(), "100".to_owned()),
    ]))
    .unwrap();
    let (worker, _) = super::canvas_worker_range_oracle::observed_worker(
        pool,
        config,
        Arc::new(ResultProcessor(supplied)),
        None,
    );
    let result = tokio::time::timeout(Duration::from_secs(10), worker.run_cycle())
        .await
        .expect("result guard must not stall sibling jobs")
        .unwrap();
    assert_eq!(result.scheduled, 30);
    assert_eq!(result.leased, 30);
    assert_eq!(result.dead_lettered, 28);
    assert_eq!(result.succeeded, 2);
    assert_eq!(result.retried, 0);

    let rows: Vec<(String, Value, Value)> = sqlx::query_as(
        "SELECT t.id, to_jsonb(j), to_jsonb(t)
         FROM issuance_service.canvas_evidence_sync_jobs j
         JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
         ORDER BY t.id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 30);
    for (target, job, state) in rows {
        let forbidden = target.starts_with("signing-guard-");
        assert_eq!(
            job["status"],
            if forbidden {
                "dead_letter"
            } else {
                "succeeded"
            },
            "{target}"
        );
        assert_eq!(job["attempt_count"], 1, "{target}");
        assert_eq!(
            job["max_attempts"],
            if forbidden { 1 } else { 8 },
            "{target}"
        );
        assert!(!job["completed_at"].is_null(), "{target}");
        assert!(job["lease_owner"].is_null(), "{target}");
        assert!(job["lease_expires_at"].is_null(), "{target}");
        assert_eq!(state["enabled"], !forbidden, "{target}");
        assert_eq!(state["last_succeeded_at"].is_null(), forbidden, "{target}");
        if forbidden {
            assert_eq!(
                job["last_error_code"], dispatch["forbidden_outcome"]["code"],
                "{target}"
            );
            assert_eq!(
                job["last_error_summary"],
                "Canvas synchronization attempted to return a signed credential",
                "{target}"
            );
        } else {
            assert!(job["last_error_code"].is_null(), "{target}");
            assert!(job["last_error_summary"].is_null(), "{target}");
        }
        assert_eq!(
            job["result"],
            if target == "control-safe" {
                json!({"facts_changed": 1})
            } else {
                json!({})
            },
            "{target}"
        );
    }
    assert_eq!(
        worker.run_cycle().await.unwrap(),
        CanvasSyncWorkerCycleResult::default(),
        "terminal results must not be retried or immediately rescheduled"
    );
    eprintln!("native PostgreSQL signing guard PASS: 28 forbidden results, 2 successful controls");
}
