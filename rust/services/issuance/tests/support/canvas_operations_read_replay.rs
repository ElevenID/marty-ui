use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use marty_issuance_service::canvas_operations::{candidate_router, CanvasOperationsService};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

fn timestamps(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key.ends_with("_at") && value.is_string() {
                    chrono::DateTime::parse_from_rfc3339(value.as_str().unwrap()).unwrap();
                    *value = json!("$timestamp");
                } else {
                    timestamps(value);
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                timestamps(value);
            }
        }
        _ => {}
    }
}

async fn request_case(router: &axum::Router, case: &Value) -> (u16, String, Value) {
    let mut headers = std::collections::BTreeMap::from([
        (
            "X-API-Key".to_owned(),
            "synthetic-operations-key".to_owned(),
        ),
        ("X-Organization-ID".to_owned(), "org-review".to_owned()),
    ]);
    if let Some(overrides) = case["headers"].as_object() {
        for (key, value) in overrides {
            headers.insert(key.clone(), value.as_str().unwrap().into());
        }
    }
    for key in case["omit_headers"].as_array().into_iter().flatten() {
        headers.remove(key.as_str().unwrap());
    }
    let mut request = Request::builder().uri(case["path"].as_str().unwrap());
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, content_type, body)
}

async fn filtering_window(pool: &PgPool, router: &axum::Router) {
    sqlx::query("UPDATE issuance_service.evidence_policy_reviews SET created_at='2000-01-01T00:00:00Z' WHERE id='review-dismiss'").execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.evidence_policy_reviews
        (id,organization_id,application_id,credential_id,binding_id,status,prior_decision,current_decision,resolution_recovery_pending,created_at,updated_at)
        SELECT 'window-'||i, 'org-review','application-review','credential-review',NULL,'resolved','{}','{}',false,
        '2026-01-01T00:00:00Z'::timestamptz + i * interval '1 second', now() FROM generate_series(1,500) i")
        .execute(pool).await.unwrap();
    let case = json!({"path":"/v1/integrations/canvas/evidence-policy-reviews?binding_id=binding-review&limit=1"});
    let (status, _, body) = request_case(router, &case).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!([]),
        "matching record 501 must remain outside the published window"
    );
    sqlx::query("UPDATE issuance_service.evidence_policy_reviews SET binding_id='binding-review' WHERE id='window-1'").execute(pool).await.unwrap();
    let (status, _, body) = request_case(router, &case).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(
        body[0]["id"], "window-1",
        "matching record 500 must remain reachable"
    );
    let (_, _, body) = request_case(
        router,
        &json!({"path":"/v1/integrations/canvas/evidence-policy-reviews?binding_id="}),
    )
    .await;
    assert_eq!(
        body.as_array().unwrap().len(),
        100,
        "empty optional review filter is not applied"
    );
    let (_, _, body) = request_case(router, &json!({"path":"/v1/integrations/canvas/evidence-policy-reviews?limit=500","headers":{"X-Organization-ID":"foreign"}})).await;
    assert_eq!(
        body,
        json!([]),
        "foreign organization cannot read seeded reviews"
    );
}

pub async fn replay_inputs(pool: &PgPool) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-operations-input-scenarios.json"
    ))
    .unwrap();
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-operations-input-oracle.json"
    ))
    .unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 75);
    assert_eq!(
        frozen["observations"].as_array().unwrap().len(),
        cases.len()
    );
    let router = candidate_router(CanvasOperationsService::new(
        pool.clone(),
        Some("synthetic-operations-key"),
    ));
    for (case, expected) in cases.iter().zip(frozen["observations"].as_array().unwrap()) {
        let (status, _content_type, body) = request_case(&router, case).await;
        assert_eq!(
            json!({"name":case["name"],"status":status,"body":body}),
            *expected,
            "input: {}",
            case["name"]
        );
    }
}

fn fixtures() -> &'static [Value; 3] {
    static FIXTURES: std::sync::OnceLock<[Value; 3]> = std::sync::OnceLock::new();
    FIXTURES.get_or_init(|| {
        [
            serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-issued-review-scenarios.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-operations-scenarios.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-operations-oracle.json"
            ))
            .unwrap(),
        ]
    })
}

pub async fn replay(pool: &PgPool) {
    let [shared, scenarios, frozen] = fixtures();
    for statement in shared["seed"]
        .as_array()
        .unwrap()
        .iter()
        .chain(scenarios["seed"].as_array().unwrap())
    {
        sqlx::query(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO issuance_service.evidence_policy_reviews \
        (id,organization_id,application_id,credential_id,binding_id,status,prior_decision,current_decision,resolution_recovery_pending,created_at,updated_at) \
        VALUES ('review-dismiss','org-review','application-review','credential-review','binding-review','open','{\"allowed\":true}','{\"allowed\":false}',false,now(),now())")
        .execute(pool).await.unwrap();
    let preserved: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let router = candidate_router(CanvasOperationsService::new(
        pool.clone(),
        Some("synthetic-operations-key"),
    ));
    let mut count = 0;
    for (case, expected) in scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(frozen["observations"].as_array().unwrap())
    {
        if case["method"] != "GET" {
            continue;
        }
        assert_eq!(case["name"], expected["name"]);
        let (status, content_type, mut body) = request_case(&router, case).await;
        timestamps(&mut body);
        assert_eq!(
            json!({"status":status,"content_type":content_type,"body":body}),
            json!({"status":expected["status"],"content_type":expected["content_type"],"body":expected["body"]}),
            "{}",
            case["name"]
        );
        let snapshot: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            snapshot, expected["snapshot"],
            "read mutated state: {}",
            case["name"]
        );
        let current: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            current, preserved,
            "read mutated credential/transaction rows"
        );
        count += 1;
    }
    assert_eq!(count, 25, "all frozen operations read cases must execute");
    filtering_window(pool, &router).await;
    pool.close().await;
    let (status, content_type, body) = request_case(
        &router,
        &json!({"path":"/v1/integrations/canvas/canvas-sync-jobs"}),
    )
    .await;
    assert_eq!(status, 500);
    assert_eq!(content_type, "text/plain; charset=utf-8");
    assert_eq!(body, json!("Internal Server Error"));
}
