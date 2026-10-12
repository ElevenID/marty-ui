use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    routing::any,
    Json, Router,
};
use marty_canvas_demo_seed::{build_run_config, run_seed};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type Calls = Arc<Mutex<Vec<(String, String, String)>>>;

async fn gateway(State(calls): State<Calls>, request: Request) -> (StatusCode, Json<Value>) {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let key = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    calls
        .lock()
        .unwrap()
        .push((method.to_string(), path.clone(), key));
    let value = match (method, path.as_str()) {
        (Method::GET, "/v1/integrations/canvas/platforms") => json!([]),
        (Method::POST, "/v1/integrations/canvas/platforms") => {
            json!({"id": "platform-1", "organization_id": "org-1", "canvas_account_id": "account-1"})
        }
        (Method::POST, "/v1/integrations/canvas/platforms/platform-1/jwks-refresh") => {
            json!({"platform": {"id": "platform-1", "organization_id": "org-1", "canvas_account_id": "account-1"}})
        }
        (Method::GET, "/v1/integrations/canvas/program-bindings") => json!([]),
        (Method::POST, "/v1/integrations/canvas/platforms/platform-1/program-bindings") => {
            json!({"id": "binding-1"})
        }
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unexpected request"})),
            )
        }
    };
    (StatusCode::OK, Json(value))
}

#[tokio::test]
async fn local_gateway_journey_has_no_db_or_canvas_side_effects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/{*path}", any(gateway))
        .with_state(calls.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let env = HashMap::from([
        ("MARTY_API_KEY".into(), "gateway-key".into()),
        ("MARTY_API_BASE_URL".into(), format!("http://{address}")),
        ("CANVAS_ORGANIZATION_ID".into(), "org-1".into()),
        ("CANVAS_ACCOUNT_ID".into(), "account-1".into()),
        ("CANVAS_OPEN_BADGE_SCENARIO_ENABLED".into(), "false".into()),
        (
            "CANVAS_DEMO_APPLICATION_SEED_ENABLED".into(),
            "false".into(),
        ),
        ("CANVAS_PROGRAM_BINDING_SEED_ENABLED".into(), "true".into()),
        ("CANVAS_LMS_SEED_ENABLED".into(), "false".into()),
        ("SIGNING_KEYS_INTERNAL_API_KEY".into(), String::new()),
    ]);
    let config = build_run_config(&env, false, false).unwrap();
    let report = run_seed(&config, &env, "postgresql://unreachable.invalid/unused")
        .await
        .unwrap();
    server.abort();
    assert_eq!(report["platform"]["id"], "platform-1");
    assert_eq!(report["binding"]["id"], "binding-1");
    assert_eq!(report["canvas_lms"], Value::Null);
    assert_eq!(report["warnings"], json!([]));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert!(calls.iter().all(|(_, _, key)| key == "gateway-key"));
}
