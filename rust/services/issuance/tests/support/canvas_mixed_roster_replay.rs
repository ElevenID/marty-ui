//! Replay a frozen published-Python corpus through the real native processor.
//! Controlled normalized provider observations do not qualify HTTP transport.
use super::canvas_published_processor::{run_for_organization, WORKER};
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasAuthoritativeProvider, CanvasProviderReadError,
        CanvasRosterSnapshot, CanvasSyncResources, NativeCanvasSyncProcessor,
    },
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::{CanvasSyncTarget, CanvasSyncWorkerConfig},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

fn scenarios() -> &'static Value {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-mixed-roster-scenarios.json"
        ))
        .unwrap()
    })
}

struct Provider {
    stage: AtomicUsize,
    reads: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasAuthoritativeProvider for Provider {
    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        requirement: &Value,
        user: Option<&str>,
        subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        let rest = requirement["source"] == "canvas_rest";
        self.reads.lock().unwrap().push(json!({
            "source": if rest { "rest" } else { "ags" },
            "identity": if rest { user } else { subject },
        }));
        let stage = &scenarios()["stages"][self.stage.load(Ordering::SeqCst)];
        if stage.get("error").is_some() {
            return Err(CanvasProviderReadError::Unavailable);
        }
        let score = stage["score"].as_f64().unwrap();
        let (assertion, payload, method) = if rest {
            (
                json!({"completed":true,"score":90.0,"score_maximum":100.0,"score_percent":90.0,
                    "provider_state":"graded","requirement_count":null,"requirement_completed_count":null}),
                json!({"id":11,"assignment_id":9,"score":90,"workflow_state":"graded","points_possible":100}),
                "CANVAS_OAUTH_API_READ",
            )
        } else {
            (
                // Match the full shared HTTP provider observation. The roster
                // processor must retain Python's distinct hash projection.
                json!({"completed":true,"score":score,"score_maximum":100.0,"score_percent":score,"result_status":"FullyGraded"}),
                json!({"id":"result-7","resultScore":stage["score"],"resultMaximum":100,"resultStatus":"FullyGraded"}),
                "LTI_AGS_RESULT_READ",
            )
        };
        Ok(CanvasAuthoritativeObservation {
            assertion: assertion.as_object().unwrap().clone(),
            source_payload: payload.as_object().unwrap().clone(),
            verification_method: method,
            effective_at: None,
        })
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        limit: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        assert_eq!(limit, 10);
        let mut subjects = vec!["unlinked-subject".into()];
        if scenarios()["stages"][self.stage.load(Ordering::SeqCst)]["active"] == true {
            subjects.push("subject-7".into());
        }
        Ok(CanvasRosterSnapshot {
            canvas_user_ids: vec!["8".into(), "7".into(), "7".into()],
            lti_subjects: subjects,
            ..Default::default()
        })
    }
}

pub async fn replay(pool: &PgPool, expected: &Value) {
    for statement in scenarios()["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    let provider = Arc::new(Provider {
        stage: AtomicUsize::new(0),
        reads: Mutex::new(Vec::new()),
    });
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), WORKER.into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "org-roster".into()),
    ]))
    .unwrap();
    let processor = NativeCanvasSyncProcessor::new(
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())),
        provider.clone(),
        config,
        2,
        10,
    );
    let stages = scenarios()["stages"].as_array().unwrap();
    assert_eq!(
        stages.len(),
        expected["observations"].as_array().unwrap().len()
    );
    for (index, stage) in stages.iter().enumerate() {
        provider.stage.store(index, Ordering::SeqCst);
        provider.reads.lock().unwrap().clear();
        if let Some(action) = stage.get("action").and_then(Value::as_str) {
            let affected = sqlx::raw_sql(scenarios()["actions"][action].as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
            assert_eq!(affected.rows_affected(), 1);
        }
        let result = run_for_organization(pool, &processor, "target-roster", "org-roster")
            .await
            .unwrap();
        let snapshot: Value = sqlx::query_scalar(scenarios()["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        let observed = json!({
            "name":stage["name"], "result":result,
            "reads":provider.reads.lock().unwrap().clone(), "snapshot":snapshot,
        });
        assert_eq!(
            observed, expected["observations"][index],
            "mixed-roster parity at {}",
            stage["name"]
        );
        eprintln!("Mixed-roster Python/native parity: {}", stage["name"]);
    }
}
