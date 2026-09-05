use super::canvas_operations_read_replay::{fixtures, job_router, request_case, seed, timestamps};
use serde_json::{json, Value};
use sqlx::PgPool;

fn ids(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "id" {
                    *value = json!("$job");
                } else if key == "target_id" {
                    *value = json!("$target");
                } else {
                    ids(value);
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                ids(value);
            }
        }
        _ => {}
    }
}

pub async fn replay(pool: &PgPool, frozen: &Value) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-enqueue-input-scenarios.json"
    ))
    .unwrap();
    seed(pool).await;
    let preserved_sql = fixtures()[0]["preserved_rows_sql"].as_str().unwrap();
    let preserved: Value = sqlx::query_scalar(preserved_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 28);
    assert_eq!(
        cases.len(),
        frozen["observations"].as_array().unwrap().len()
    );
    for (case, expected) in cases.iter().zip(frozen["observations"].as_array().unwrap()) {
        // Exact-owned synthetic schema only, just as in the published capture.
        sqlx::query("DELETE FROM issuance_service.canvas_evidence_sync_jobs")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM issuance_service.canvas_evidence_sync_targets")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE issuance_service.applications SET integration_context=$1,credential_id=$2 WHERE id='application-review'")
            .bind(case.get("context").unwrap_or(&scenarios["default_context"]))
            .bind(case.get("credential_id").map_or(Some("credential-review"), Value::as_str))
            .execute(pool).await.unwrap();
        sqlx::query(
            "UPDATE issuance_service.canvas_platforms SET enabled=$1 WHERE id='platform-review'",
        )
        .bind(case["platform_enabled"].as_bool().unwrap_or(true))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE issuance_service.canvas_program_bindings SET enabled=$1 WHERE id='binding-review'")
            .bind(case["binding_enabled"].as_bool().unwrap_or(true)).execute(pool).await.unwrap();
        if let Some(metadata) = case.get("metadata") {
            sqlx::query("INSERT INTO issuance_service.canvas_evidence_sync_targets
                (id,organization_id,platform_id,binding_id,target_type,logical_key,application_id,metadata)
                VALUES ('target-input','org-review','platform-review','binding-review','issued_drift','application:application-review','application-review',$1)")
                .bind(metadata).execute(pool).await.unwrap();
        }
        let router = job_router(pool, case["rollout"].as_bool().unwrap_or(true));
        let mut request = case.clone();
        request["method"] = json!("POST");
        request["path"] = json!(format!(
            "/v1/integrations/canvas/applications/{}/canvas-sync",
            case["application"].as_str().unwrap_or("application-review")
        ));
        let (status, content_type, mut body) = request_case(&router, &request).await;
        timestamps(&mut body);
        ids(&mut body);
        let targets: Option<Value> = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_object('target_type',target_type,'schedule_seconds',schedule_seconds,'enabled',enabled,'metadata',metadata)) FROM issuance_service.canvas_evidence_sync_targets")
            .fetch_one(pool).await.unwrap();
        let jobs: Option<Value> = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_object('status',status,'attempt_count',attempt_count,'max_attempts',max_attempts)) FROM issuance_service.canvas_evidence_sync_jobs")
            .fetch_one(pool).await.unwrap();
        assert_eq!(
            json!({"name":case["name"],"status":status,"content_type":content_type,"body":body,"targets":targets,"jobs":jobs}),
            *expected,
            "enqueue input: {}",
            case["name"]
        );
        let current: Value = sqlx::query_scalar(preserved_sql)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            current, preserved,
            "enqueue input mutated credential/transaction"
        );
    }
}
