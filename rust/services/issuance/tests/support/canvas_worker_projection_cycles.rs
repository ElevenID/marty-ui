//! Gates 6/7: actual run_cycle and SQL outcomes with controlled processor values.
//!
//! The existing dedicated worker-test schema intentionally has no target FK.
//! Its preseeded orphan proves the repository's target(None) worker boundary,
//! not orphan reachability/deletion races on published migrations or binary
//! parity. No target, queued job, lease or clock is changed after cycle startup.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult, CanvasSyncTarget,
        CanvasSyncWorkerConfig, CanvasSyncWorkerCycleResult,
    },
};
use serde_json::{json, Value};
use sqlx::PgPool;

struct RawResultProcessor {
    supplied: BTreeMap<String, CanvasSyncResult>,
    calls: Mutex<BTreeSet<String>>,
}

#[async_trait]
impl CanvasSyncProcessor for RawResultProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        assert!(
            self.calls.lock().unwrap().insert(target.id.clone()),
            "each owned target must be processed only once"
        );
        // Deliberately no safe_result here: only production run_cycle may
        // sanitize these lossless, unmodified processor-returned JSON values.
        Ok(self
            .supplied
            .get(&target.id)
            .expect("owned result target")
            .clone())
    }
}

type DurableRow = (String, String, Value, Option<Value>);

async fn durable_rows(pool: &PgPool) -> Vec<DurableRow> {
    sqlx::query_as(
        "SELECT j.target_id, j.result::text, to_jsonb(j), to_jsonb(t)
         FROM issuance_service.canvas_evidence_sync_jobs j
         LEFT JOIN issuance_service.canvas_evidence_sync_targets t
           ON t.id=j.target_id AND t.organization_id=j.organization_id
         ORDER BY j.target_id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

pub async fn assert_projection_cycles(pool: &PgPool) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-result-oracle.json"
    ))
    .unwrap();
    assert_eq!(fixture["schema"], "elevenid.canvas-worker-result-oracle/v1");
    assert_eq!(
        fixture["observed_source"],
        "d6b6dd67fd9674eb14388320e65d3ae9642b3b42"
    );
    assert_eq!(
        fixture["worker_blob"],
        "b516ed3d0855f16e9ec899a452a22df49d2cafe5"
    );
    let cases = fixture["value_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 21, "retain every frozen JSON value class");
    let mut names = BTreeSet::new();
    let mut supplied = BTreeMap::new();
    let mut expected = BTreeMap::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        assert!(names.insert(name));
        let target = format!("projection-{name}");
        // One allowlisted field suffices for composing each value class; the
        // retained 483-vector helper gate separately exhausts all field names.
        assert!(fixture["allowed_fields"]
            .as_array()
            .unwrap()
            .contains(&json!("candidate_state")));
        let mut input: CanvasSyncResult = serde_json::from_str(&format!(
            "{{\"candidate_state\":{}}}",
            case["input_json"].as_str().unwrap()
        ))
        .unwrap();
        for unknown in fixture["unknown_fields"].as_array().unwrap() {
            let field = unknown.as_str().unwrap();
            input.insert(
                field.into(),
                serde_json::value::RawValue::from_string(
                    r#"{"private":"synthetic-projection-payload-must-not-persist"}"#.into(),
                )
                .unwrap(),
            );
        }
        let output = if case["omitted"] == true {
            CanvasSyncResult::new()
        } else {
            serde_json::from_str(&format!(
                "{{\"candidate_state\":{}}}",
                case["expected_json"].as_str().unwrap()
            ))
            .unwrap()
        };
        supplied.insert(target.clone(), input);
        expected.insert(target, output);
    }
    supplied.insert("projection-empty-control".into(), CanvasSyncResult::new());
    expected.insert("projection-empty-control".into(), CanvasSyncResult::new());
    assert_eq!(supplied.len(), 22);
    for target in supplied.keys() {
        super::seed_target(pool, target, 900).await;
    }

    // This is the same supported orphan shape used by the existing direct
    // repository regression, now leased and handled by the real worker cycle.
    // It is prepared before starting the worker, never manufactured mid-lease.
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs
         (id,organization_id,target_id,status,attempt_count,max_attempts,
          available_at,result,created_at,updated_at)
         VALUES ('projection-orphan-job','org-1','projection-missing-target',
                 'queued',0,8,clock_timestamp(),'{}'::json,
                 clock_timestamp(),clock_timestamp())",
    )
    .execute(pool)
    .await
    .unwrap();
    let untouched = supplied
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::to_string(value).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let processor = Arc::new(RawResultProcessor {
        supplied,
        calls: Mutex::new(BTreeSet::new()),
    });
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        (
            "CANVAS_SYNC_WORKER_ID".into(),
            "projection-cycle-worker".into(),
        ),
        ("CANVAS_SYNC_WORKER_BATCH_SIZE".into(), "100".into()),
    ]))
    .unwrap();
    let (worker, repository) =
        super::canvas_worker_range_oracle::observed_worker(pool, config, processor.clone(), None);
    let cycle = tokio::time::timeout(Duration::from_secs(10), worker.run_cycle())
        .await
        .expect("projection cycle must complete without losing siblings")
        .unwrap();
    assert_eq!(
        cycle,
        CanvasSyncWorkerCycleResult {
            scheduled: 22,
            leased: 23,
            succeeded: 22,
            dead_lettered: 1,
            ..CanvasSyncWorkerCycleResult::default()
        }
    );
    assert_eq!(
        *processor.calls.lock().unwrap(),
        expected.keys().cloned().collect()
    );
    assert!(!processor
        .calls
        .lock()
        .unwrap()
        .contains("projection-missing-target"));
    assert_eq!(
        processor
            .supplied
            .iter()
            .map(|(key, value)| { (key.clone(), serde_json::to_string(value).unwrap()) })
            .collect::<BTreeMap<_, _>>(),
        untouched
    );

    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-canvas-sync-worker.json"
    ))
    .unwrap();
    let rows = durable_rows(pool).await;
    assert_eq!(rows.len(), 23);
    for (target_id, raw_result, job, target) in &rows {
        assert_eq!(job["attempt_count"], 1);
        assert!(!job["started_at"].is_null());
        assert!(!job["completed_at"].is_null());
        assert!(job["lease_owner"].is_null());
        assert!(job["lease_expires_at"].is_null());
        assert!(!raw_result.contains("synthetic-projection-payload"));
        if target_id == "projection-missing-target" {
            assert!(target.is_none());
            assert_eq!(
                job["status"],
                contract["job_outcomes"]["missing_target"]["state"]
            );
            assert_eq!(
                job["last_error_code"],
                contract["job_outcomes"]["missing_target"]["code"]
            );
            // Static native summary regression, not a new published capture.
            assert_eq!(
                job["last_error_summary"],
                "Canvas synchronization target is unavailable"
            );
            assert_eq!(job["max_attempts"], 1);
            assert_eq!(raw_result, "{}");
        } else {
            assert_eq!(job["status"], "succeeded");
            assert_eq!(job["max_attempts"], 8);
            assert!(job["last_error_code"].is_null());
            assert!(job["last_error_summary"].is_null());
            let target = target.as_ref().unwrap();
            assert_eq!(target["enabled"], true);
            assert_eq!(target["config_version"], 3);
            assert_eq!(target["organization_id"], "org-1");
            assert!(!target["last_succeeded_at"].is_null());
            let actual: CanvasSyncResult = serde_json::from_str(raw_result).unwrap();
            let expected = &expected[target_id];
            assert_eq!(
                actual.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>()
            );
            for (key, value) in expected {
                // Never route the result through Value: its fixed-width
                // numeric model can conceal large-integer/coercion failures.
                assert_eq!(actual[key].get(), value.get(), "{target_id}/{key}");
            }
        }
    }
    assert_eq!(
        repository.phase_events("heartbeat"),
        ["scheduling", "processing", "idle"]
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), worker.run_cycle())
            .await
            .unwrap()
            .unwrap(),
        CanvasSyncWorkerCycleResult::default()
    );
    assert_eq!(
        durable_rows(pool).await,
        rows,
        "second cycle cannot retry terminal orphan or rewrite successful siblings"
    );
    assert_eq!(processor.calls.lock().unwrap().len(), 22);
    eprintln!("native controlled processor/test-schema cycle PASS: missing-target terminal plus sibling, 21 frozen result value classes and empty control; not published-process parity");
}
