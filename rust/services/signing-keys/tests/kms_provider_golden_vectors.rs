use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use marty_signing_keys::kms::{self, ProviderRequest, SignRequest};
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    sign_cases: Vec<SignCase>,
    public_key_cases: Vec<PublicKeyCase>,
    verify_cases: Vec<VerifyCase>,
}

#[derive(Debug, Deserialize)]
struct SignCase {
    name: String,
    service_config: Value,
    payload_b64: String,
    expected_request: ExpectedRequest,
    provider_response: Value,
    expected_response: Value,
}

#[derive(Debug, Deserialize)]
struct ExpectedRequest {
    method: String,
    path_query: String,
    headers: BTreeMap<String, String>,
    #[serde(default)]
    json: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PublicKeyCase {
    name: String,
    service_config: Value,
    expected_request: ExpectedRequest,
    provider_response: Value,
    expected_response: Value,
}

#[derive(Debug, Deserialize)]
struct VerifyCase {
    name: String,
    service_config: Value,
    expected_request: ExpectedRequest,
    provider_status: u16,
    provider_response: Value,
    expected_response: Value,
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path_query: String,
    headers: BTreeMap<String, String>,
    json: Value,
}

#[derive(Clone)]
struct StubState {
    status: StatusCode,
    response: Value,
    captured: Arc<Mutex<Option<CapturedRequest>>>,
}

#[derive(Clone)]
struct ManagedTransitState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

fn fixture() -> Fixture {
    // Fixed process-local credentials keep the official AWS client offline and
    // make its signed HTTP request observable by the same provider stub.
    std::env::set_var("AWS_ACCESS_KEY_ID", "test-access-key");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test-secret-key");
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    serde_json::from_str(include_str!("fixtures/kms_provider_vectors.json"))
        .expect("valid KMS provider vectors")
}

async fn capture(State(state): State<StubState>, request: Request<Body>) -> Response {
    let method = request.method().to_string();
    let path_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = to_bytes(request.into_body(), 64 * 1024)
        .await
        .expect("bounded request body");
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("JSON provider request")
    };
    *state.captured.lock().await = Some(CapturedRequest {
        method,
        path_query,
        headers,
        json,
    });
    Response::builder()
        .status(state.status)
        .header("content-type", "application/json")
        .body(Body::from(state.response.to_string()))
        .expect("stub response")
}

async fn spawn_stub(
    status: StatusCode,
    response: Value,
) -> (
    String,
    Arc<Mutex<Option<CapturedRequest>>>,
    oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider stub");
    let address = listener.local_addr().expect("stub address");
    let captured = Arc::new(Mutex::new(None));
    let state = StubState {
        status,
        response,
        captured: Arc::clone(&captured),
    };
    let app = Router::new().fallback(any(capture)).with_state(state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("provider stub server");
    });
    (format!("http://{address}"), captured, shutdown_tx)
}

async fn managed_transit_stub(
    State(state): State<ManagedTransitState>,
    request: Request<Body>,
) -> Response {
    let path_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    let prior_path_count = state
        .requests
        .lock()
        .await
        .iter()
        .filter(|captured| captured.path_query == path_query)
        .count();
    let method = request.method().to_string();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = to_bytes(request.into_body(), 64 * 1024)
        .await
        .expect("bounded request body");
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("JSON provider request")
    };
    state.requests.lock().await.push(CapturedRequest {
        method,
        path_query: path_query.clone(),
        headers,
        json,
    });
    let (status, body) = match (path_query.as_str(), prior_path_count) {
        ("/v1/transit/sign/issuer-key", 0) => (
            StatusCode::NOT_FOUND,
            r#"{"errors":["key not found"]}"#.to_string(),
        ),
        ("/v1/transit/keys/issuer-key", 0) => (
            StatusCode::NOT_FOUND,
            r#"{"errors":["no handler for route"]}"#.to_string(),
        ),
        ("/v1/sys/mounts/transit", 0) | ("/v1/transit/keys/issuer-key", 1) => {
            (StatusCode::NO_CONTENT, String::new())
        }
        ("/v1/transit/sign/issuer-key", 1) => (
            StatusCode::OK,
            r#"{"data":{"signature":"vault:v1:c2lnbmF0dXJl"}}"#.to_string(),
        ),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_string()),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("managed transit response")
}

#[tokio::test]
async fn managed_openbao_missing_key_and_mount_are_created_before_one_retry() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind managed transit stub");
    let address = listener.local_addr().expect("stub address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(managed_transit_stub))
        .with_state(ManagedTransitState {
            requests: Arc::clone(&requests),
        });
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("managed transit stub server");
    });

    let response = kms::sign(SignRequest {
        service_config: serde_json::json!({
            "id": "managed-openbao-transit",
            "service_type": "custom-transit-compatible",
            "endpoint": format!("http://{address}"),
            "mount": "transit",
            "auth_mode": "token",
            "auth_reference": "service-token",
            "key_reference": "issuer-key",
            "algorithm": "EdDSA"
        }),
        payload_b64: "cGF5bG9hZA".into(),
    })
    .await
    .expect("managed sign retries");
    let _ = shutdown_tx.send(());
    assert_eq!(response.signature_b64, "c2lnbmF0dXJl");
    assert_eq!(response.signature_encoding, "raw");
    let requests = requests.lock().await;
    assert_eq!(
        requests
            .iter()
            .map(|request| request.path_query.as_str())
            .collect::<Vec<_>>(),
        [
            "/v1/transit/sign/issuer-key",
            "/v1/transit/keys/issuer-key",
            "/v1/sys/mounts/transit",
            "/v1/transit/keys/issuer-key",
            "/v1/transit/sign/issuer-key"
        ]
    );
    assert!(requests.iter().all(|request| {
        request.headers.get("x-vault-token").map(String::as_str) == Some("service-token")
    }));
}

#[tokio::test]
async fn provider_signing_matches_language_neutral_http_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);

    for mut case in fixture.sign_cases {
        let (endpoint, captured, shutdown) =
            spawn_stub(StatusCode::OK, case.provider_response).await;
        case.service_config["endpoint"] = Value::String(endpoint);
        let response = kms::sign(SignRequest {
            service_config: case.service_config,
            payload_b64: case.payload_b64,
        })
        .await
        .unwrap_or_else(|error| panic!("{} signing failed: {error}", case.name));
        assert_eq!(
            serde_json::to_value(response).expect("serializable sign response"),
            case.expected_response,
            "{} response",
            case.name
        );

        let captured = captured
            .lock()
            .await
            .take()
            .unwrap_or_else(|| panic!("{} did not call the provider", case.name));
        assert_eq!(
            captured.method, case.expected_request.method,
            "{} method",
            case.name
        );
        assert_eq!(
            captured.path_query, case.expected_request.path_query,
            "{} path/query",
            case.name
        );
        assert_eq!(
            Some(captured.json),
            case.expected_request.json,
            "{} JSON",
            case.name
        );
        for (name, expected) in case.expected_request.headers {
            assert_eq!(
                captured.headers.get(&name),
                Some(&expected),
                "{} header {name}",
                case.name
            );
        }
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn public_key_discovery_matches_language_neutral_http_vectors() {
    for mut case in fixture().public_key_cases {
        let (endpoint, captured, shutdown) =
            spawn_stub(StatusCode::OK, case.provider_response).await;
        case.service_config["endpoint"] = Value::String(endpoint);
        let response = kms::public_key(ProviderRequest {
            service_config: case.service_config,
        })
        .await
        .unwrap_or_else(|error| panic!("{} public-key discovery failed: {error}", case.name));
        assert_eq!(response, case.expected_response, "{} response", case.name);

        let captured = captured
            .lock()
            .await
            .take()
            .unwrap_or_else(|| panic!("{} did not call the provider", case.name));
        assert_eq!(
            captured.method, case.expected_request.method,
            "{} method",
            case.name
        );
        assert_eq!(
            captured.path_query, case.expected_request.path_query,
            "{} path/query",
            case.name
        );
        if let Some(expected_json) = case.expected_request.json {
            assert_eq!(captured.json, expected_json, "{} body", case.name);
        } else {
            assert_eq!(captured.json, Value::Null, "{} body", case.name);
        }
        for (name, expected) in case.expected_request.headers {
            assert_eq!(
                captured.headers.get(&name),
                Some(&expected),
                "{} header {name}",
                case.name
            );
        }
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn connectivity_probes_match_language_neutral_http_vectors() {
    for mut case in fixture().verify_cases {
        let status = StatusCode::from_u16(case.provider_status).expect("fixture HTTP status");
        let (endpoint, captured, shutdown) = spawn_stub(status, case.provider_response).await;
        case.service_config["endpoint"] = Value::String(endpoint);
        let response = kms::verify(ProviderRequest {
            service_config: case.service_config,
        })
        .await
        .unwrap_or_else(|error| panic!("{} connectivity probe failed: {error}", case.name));
        assert_eq!(
            serde_json::to_value(response).expect("serializable capability result"),
            case.expected_response,
            "{} response",
            case.name
        );

        let captured = captured
            .lock()
            .await
            .take()
            .unwrap_or_else(|| panic!("{} did not call the provider", case.name));
        assert_eq!(
            captured.method, case.expected_request.method,
            "{} method",
            case.name
        );
        assert_eq!(
            captured.path_query, case.expected_request.path_query,
            "{} path/query",
            case.name
        );
        for (name, expected) in case.expected_request.headers {
            assert_eq!(
                captured.headers.get(&name),
                Some(&expected),
                "{} header {name}",
                case.name
            );
        }
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn missing_and_unknown_provider_configuration_fails_closed() {
    for config in [
        serde_json::json!({"service_type": "unknown"}),
        serde_json::json!({"service_type": "openbao-transit", "key_reference": "key"}),
        serde_json::json!({"service_type": "azure-key-vault", "endpoint": "http://localhost"}),
        serde_json::json!({"service_type": "gcp-cloud-kms"}),
        serde_json::json!({"service_type": "aws-kms"}),
    ] {
        assert!(kms::sign(SignRequest {
            service_config: config,
            payload_b64: "cGF5bG9hZA".to_string(),
        })
        .await
        .is_err());
    }
}
