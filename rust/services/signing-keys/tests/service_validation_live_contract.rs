use std::sync::{Arc, OnceLock};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    routing::any,
    Router,
};
use marty_signing_keys::validation::{validate, ValidationRequest};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    token: String,
    namespace: String,
}

#[derive(Clone)]
struct StubState(Arc<tokio::sync::Mutex<Vec<CapturedRequest>>>);

static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn transit_stub(State(state): State<StubState>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_string();
    let token = request
        .headers()
        .get("x-vault-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let namespace = request
        .headers()
        .get("x-vault-namespace")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    state.0.lock().await.push(CapturedRequest {
        path: path.clone(),
        token,
        namespace,
    });
    let body = if path.contains("/sign/") {
        json!({"data": {"signature": "vault:v1:test-signature"}})
    } else {
        json!({})
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("stub response")
}

#[tokio::test]
async fn service_token_and_namespace_reach_every_custom_transit_probe() {
    let _env_guard = ENV_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    std::env::set_var("BAO_TOKEN", "service-token-from-environment");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider stub");
    let address = listener.local_addr().expect("stub address");
    let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(transit_stub))
        .with_state(StubState(Arc::clone(&captured)));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("provider stub server");
    });

    let request: ValidationRequest = serde_json::from_value(json!({
        "service_type": "custom-transit-compatible",
        "endpoint": format!("http://{address}"),
        "mount": "transit",
        "namespace": "tenant-a",
        "auth_mode": "service_token",
        "key_reference": "issuer",
        "algorithms": ["ES256"]
    }))
    .expect("validation request");
    let result = validate(request).await;

    std::env::remove_var("BAO_TOKEN");
    let _ = shutdown_tx.send(());
    assert!(result.ok, "custom transit validation should pass");
    let requests = captured.lock().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "/v1/sys/health",
            "/v1/auth/token/lookup-self",
            "/v1/transit/sign/issuer"
        ]
    );
    for request in requests.iter() {
        assert_eq!(request.token, "service-token-from-environment");
        assert_eq!(request.namespace, "tenant-a");
    }
}

#[test]
fn validation_request_rejects_non_object_inputs() {
    assert!(serde_json::from_value::<ValidationRequest>(Value::Null).is_err());
}
