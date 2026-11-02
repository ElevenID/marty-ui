use super::*;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    response::IntoResponse,
    routing::post,
    Router,
};
use mmf_aws_kms::AwsAuth;
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

const ARN: &str = "arn:aws:kms:us-east-2:111122223333:key/notification-envelope";
const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct Stub {
    origin: &'static str,
    deny_decrypt: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    // Protocol fixture only: no local encryption or cryptographic substitute.
    plaintext: Arc<Mutex<Vec<u8>>>,
}

async fn handler(State(state): State<Stub>, request: Request<Body>) -> axum::response::Response {
    let operation = request.headers()["x-amz-target"]
        .to_str()
        .unwrap()
        .rsplit('.')
        .next()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&to_bytes(request.into_body(), 20_000).await.unwrap()).unwrap();
    state
        .calls
        .lock()
        .unwrap()
        .push((operation.clone(), body.clone()));
    if operation == "Decrypt" && state.deny_decrypt.load(Ordering::Acquire) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "__type": "AccessDeniedException", "message": "do-not-echo-provider-detail"
            })),
        )
            .into_response();
    }
    let output = match operation.as_str() {
        "DescribeKey" => json!({"KeyMetadata": {
            "KeyId": "notification-envelope", "Arn": ARN, "KeyState": "Enabled", "Enabled": true,
            "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "Origin": state.origin,
            "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]
        }}),
        "Encrypt" => {
            *state.plaintext.lock().unwrap() = STANDARD
                .decode(body["Plaintext"].as_str().unwrap())
                .unwrap();
            json!({"KeyId": ARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextBlob": STANDARD.encode(b"opaque-provider-ciphertext")})
        }
        "Decrypt" => json!({"KeyId": ARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "Plaintext": STANDARD.encode(&*state.plaintext.lock().unwrap())}),
        _ => panic!("unexpected AWS operation"),
    };
    axum::Json(output).into_response()
}

struct Fixture {
    envelope: WebhookSecretEnvelope,
    state: Stub,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(origin: &'static str) -> Fixture {
    let state = Stub {
        origin,
        deny_decrypt: Arc::new(AtomicBool::new(false)),
        calls: Arc::new(Mutex::new(Vec::new())),
        plaintext: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/", post(handler))
        .with_state(state.clone());
    let task = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    let envelope = WebhookSecretEnvelope {
        provider: WebhookSecretProvider::AwsKms(AwsWebhookSecretEnvelope {
            config: AwsKmsConfig {
                region: "us-east-2".into(),
                authentication: AwsAuth::AccessKey {
                    access_key_id: "test-only-explicit-key".into(),
                    secret_access_key: "test-only-secret".into(),
                    session_token: None,
                },
                endpoint: Some(endpoint),
                request_timeout: Duration::from_secs(2),
            },
            key_arn: ARN.into(),
            client: Arc::new(OnceCell::new()),
        }),
    };
    Fixture {
        envelope,
        state,
        task,
    }
}

#[tokio::test]
async fn aws_envelope_keeps_the_existing_binding_and_static_context() {
    let fixture = fixture("AWS_KMS").await;
    fixture.envelope.check_ready().await.unwrap();
    let ciphertext = fixture
        .envelope
        .wrap("org-a", "webhook-a", SECRET)
        .await
        .unwrap();
    assert!(ciphertext.starts_with("aws-kms:v1:"));
    assert_eq!(
        fixture
            .envelope
            .unwrap("org-a", "webhook-a", &ciphertext)
            .await
            .unwrap(),
        SECRET
    );
    for (organization, webhook) in [("org-b", "webhook-a"), ("org-a", "webhook-b")] {
        assert!(matches!(
            fixture
                .envelope
                .unwrap(organization, webhook, &ciphertext)
                .await,
            Err(WebhookError::InvalidEnvelope(_))
        ));
    }
    let bound: Value = serde_json::from_slice(&fixture.state.plaintext.lock().unwrap()).unwrap();
    assert_eq!(
        bound,
        json!({
            "schema": WEBHOOK_SECRET_ENVELOPE_SCHEMA, "purpose": WEBHOOK_SECRET_ENVELOPE_PURPOSE,
            "organization_id": "org-a", "webhook_id": "webhook-a", "secret": SECRET
        })
    );
    for (field, value) in [
        ("schema", json!("wrong-schema")),
        ("purpose", json!("wrong-purpose")),
        ("secret", json!("short")),
        ("unexpected", json!(true)),
    ] {
        let mut modified = bound.clone();
        modified[field] = value;
        *fixture.state.plaintext.lock().unwrap() = serde_json::to_vec(&modified).unwrap();
        assert!(matches!(
            fixture
                .envelope
                .unwrap("org-a", "webhook-a", &ciphertext)
                .await,
            Err(WebhookError::InvalidEnvelope(_))
        ));
    }
    for (operation, body) in fixture.state.calls.lock().unwrap().iter() {
        assert_eq!(body["KeyId"], ARN);
        if operation == "Encrypt" || operation == "Decrypt" {
            assert_eq!(
                body["EncryptionContext"],
                json!({
                    "marty-envelope-schema": WEBHOOK_SECRET_ENVELOPE_SCHEMA
                })
            );
        }
    }
}

#[tokio::test]
async fn wrong_codec_and_oversize_values_fail_before_provider_access() {
    let fixture = fixture("AWS_KMS").await;
    for ciphertext in [
        "vault:v1:opaque",
        "aws-kms:v2:b3BhcXVl",
        "aws-kms:v1:",
        "aws-kms:v1:AQ",
    ] {
        assert!(matches!(
            fixture
                .envelope
                .unwrap("org-a", "webhook-a", ciphertext)
                .await,
            Err(WebhookError::InvalidEnvelope(_))
        ));
    }
    for secret in ["a".repeat(31), "a".repeat(129)] {
        assert!(fixture
            .envelope
            .wrap("org-a", "webhook-a", &secret)
            .await
            .is_err());
    }
    assert!(fixture
        .envelope
        .wrap(&"a".repeat(4096), "webhook-a", SECRET)
        .await
        .is_err());
    assert!(fixture.state.calls.lock().unwrap().is_empty());
    let openbao = WebhookSecretEnvelope {
        provider: WebhookSecretProvider::OpenBao(OpenBaoWebhookSecretEnvelope {
            bao_addr: "https://must-not-connect.invalid".into(),
            bao_token: "redact-this-scoped-token".into(),
            key_id: WEBHOOK_SECRET_ENVELOPE_KEY_ID.into(),
            client: Client::new(),
        }),
    };
    assert!(matches!(
        openbao
            .unwrap("org-a", "webhook-a", "aws-kms:v1:b3BhcXVl")
            .await,
        Err(WebhookError::InvalidEnvelope(_))
    ));
    assert!(!format!("{openbao:?}").contains("redact-this-scoped-token"));
    assert!(storable_webhook_ciphertext("vault:v1:legacy"));
    assert!(storable_webhook_ciphertext(
        &mmf_aws_kms::encode_ciphertext(b"opaque").unwrap()
    ));
    for value in [
        "plaintext",
        "aws-kms:v2:b3BhcXVl",
        "aws-kms:v1:",
        "aws-kms:v1:AQ",
    ] {
        assert!(!storable_webhook_ciphertext(value));
    }
}

#[tokio::test]
async fn readiness_requires_encrypt_and_decrypt_permissions() {
    let fixture = fixture("AWS_KMS").await;
    fixture.state.deny_decrypt.store(true, Ordering::Release);
    let result = fixture.envelope.check_ready().await;
    assert!(matches!(result, Err(WebhookError::EnvelopeUnavailable(_))));
    let calls = fixture.state.calls.lock().unwrap();
    assert!(calls.iter().any(|(operation, _)| operation == "Encrypt"));
    assert!(calls.iter().any(|(operation, _)| operation == "Decrypt"));
}

#[tokio::test]
async fn unsuitable_aws_key_cannot_fall_back_to_another_provider() {
    let fixture = fixture("EXTERNAL").await;
    assert!(matches!(
        fixture.envelope.check_ready().await,
        Err(WebhookError::EnvelopeUnavailable(_))
    ));
    assert!(matches!(
        fixture.envelope.wrap("org-a", "webhook-a", SECRET).await,
        Err(WebhookError::EnvelopeUnavailable(_))
    ));
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .all(|(operation, _)| operation == "DescribeKey"));
}
