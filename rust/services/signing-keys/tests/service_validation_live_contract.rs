use std::sync::Arc;

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
#[path = "support/https_stub.rs"]
mod https_stub;

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    token: String,
    namespace: String,
}

#[derive(Clone)]
struct StubState(Arc<tokio::sync::Mutex<Vec<CapturedRequest>>>);

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
async fn tenant_token_and_namespace_reach_every_custom_transit_probe() {
    let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(transit_stub))
        .with_state(StubState(Arc::clone(&captured)));
    let peer = https_stub::TestHttpsServer::start(app).await;

    let request: ValidationRequest = serde_json::from_value(json!({
        "service_type": "custom-transit-compatible",
        "endpoint": peer.endpoint.clone(),
        "ca_cert_file": peer.ca_file.path(),
        "mount": "transit",
        "namespace": "tenant-a",
        "auth_mode": "token",
        "auth_reference": "tenant-provided-token",
        "key_reference": "issuer",
        "algorithms": ["ES256"]
    }))
    .expect("validation request");
    let result = validate(request).await;

    assert!(
        result.ok,
        "custom transit validation should pass: {result:?}"
    );
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
        assert_eq!(request.token, "tenant-provided-token");
        assert_eq!(request.namespace, "tenant-a");
    }
}

#[test]
fn validation_request_rejects_non_object_inputs() {
    assert!(serde_json::from_value::<ValidationRequest>(Value::Null).is_err());
}

#[derive(Clone)]
struct AwsStubState {
    targets: Arc<tokio::sync::Mutex<Vec<String>>>,
    enabled: bool,
    usage: &'static str,
    deny_public_key: bool,
}

async fn aws_stub(State(state): State<AwsStubState>, request: Request<Body>) -> Response {
    let target = request
        .headers()
        .get("x-amz-target")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    state.targets.lock().await.push(target.clone());
    let arn = "arn:aws:kms:us-east-1:111122223333:key/registered-key";
    let mut status = StatusCode::OK;
    let body = match target.as_str() {
        "TrentService.DescribeKey" => json!({"KeyMetadata": {
            "Arn": arn, "Enabled": state.enabled,
            "KeyState": if state.enabled { "Enabled" } else { "Disabled" },
            "KeyUsage": state.usage,
        }}),
        "TrentService.GetPublicKey" if state.deny_public_key => {
            status = StatusCode::FORBIDDEN;
            json!({"__type": "AccessDeniedException", "message": "fixture access denied"})
        }
        "TrentService.GetPublicKey" => json!({
            "KeyId": arn,
            "PublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==",
            "SigningAlgorithms": ["ECDSA_SHA_256", "ECDSA_SHA_384"], "KeySpec": "ECC_NIST_P256",
            "KeyUsage": state.usage,
        }),
        other => panic!("registration validation must not call {other}"),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/x-amz-json-1.1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn aws_registration_checks_existing_key_state_and_algorithms_without_mutation() {
    const CHILD: &str = "MARTY_AWS_REGISTRATION_VALIDATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Configure a successful legacy bridge only in the child process. This
        // proves native failures cannot be masked without global env races.
        let bridge_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&bridge_calls);
        let bridge = Router::new().fallback(any(move || {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::Json(json!({"ok": true}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "aws_registration_checks_existing_key_state_and_algorithms_without_mutation",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("AWS_KMS_VALIDATOR_URL", endpoint)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        server.abort();
        assert!(
            output.status.success(),
            "child contract failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(bridge_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        return;
    }
    for (enabled, usage, algorithm, deny_public_key, expected_ok, expected_calls) in [
        (true, "SIGN_VERIFY", "ES256", false, true, 2),
        (false, "SIGN_VERIFY", "ES256", false, false, 1),
        (true, "KEY_AGREEMENT", "ES256", false, false, 1),
        (true, "SIGN_VERIFY", "ES384", false, false, 2),
        (true, "SIGN_VERIFY", "ES256", true, false, 2),
    ] {
        let targets = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(any(aws_stub))
            .with_state(AwsStubState {
                targets: Arc::clone(&targets),
                enabled,
                usage,
                deny_public_key,
            });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let request = serde_json::from_value(json!({
            "service_type": "aws-kms", "endpoint": endpoint, "region": "us-east-1",
            "auth_mode": "access_key",
            "auth_reference": "{\"access_key_id\":\"fixture-key\",\"secret_access_key\":\"fixture-secret\"}",
            "key_reference": "arn:aws:kms:us-east-1:111122223333:key/registered-key",
            "algorithms": [algorithm], "live_probe": true,
        })).unwrap();
        let result = validate(request).await;
        server.abort();
        assert_eq!(
            result.ok, expected_ok,
            "{enabled} {usage} {algorithm}: {result:?}"
        );
        assert_eq!(result.basis, "live");
        let targets = targets.lock().await;
        assert_eq!(targets.len(), expected_calls);
        assert_eq!(targets[0], "TrentService.DescribeKey");
        if expected_calls == 2 {
            assert_eq!(targets[1], "TrentService.GetPublicKey");
        }
    }
}
