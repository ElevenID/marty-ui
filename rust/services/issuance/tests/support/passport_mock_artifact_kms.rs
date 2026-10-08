//! Public-API KMS transport fixture for passport HTTP/Postgres behavior tests.
//! Real custody is qualified separately against the disposable OpenBao service.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_issuance_service::{
    passport_artifact_kms::KmsPassportArtifactCipher,
    passport_bureau::{BureauError, KmsWebhookVerifier, VerifiedWebhookEvent},
};
use serde_json::{json, Value};

const API_KEY: &str = "synthetic-passport-artifact-api-key";

#[derive(Default)]
struct Store {
    chunks: Mutex<BTreeMap<String, BoundChunk>>,
    callbacks: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
    sequence: AtomicU64,
}

#[allow(dead_code)] // Shared by Issuance and Gateway contract targets with different coverage.
pub struct MockPassportKms {
    pub cipher: KmsPassportArtifactCipher,
    pub webhook_verifier: KmsWebhookVerifier,
    store: Arc<Store>,
    pub server: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)]
impl MockPassportKms {
    pub fn callback_signature(&self, body: &[u8]) -> String {
        let event: Value = serde_json::from_slice(body).unwrap();
        let organization_id = event["organization_id"].as_str().unwrap().to_owned();
        let sequence = self.store.sequence.fetch_add(1, Ordering::Relaxed);
        let mut token = [0u8; 32];
        token[..8].copy_from_slice(&sequence.to_be_bytes());
        let signature = format!("vault:v1:{}", STANDARD.encode(token));
        self.store
            .callbacks
            .lock()
            .unwrap()
            .insert(signature.clone(), (organization_id, body.to_vec()));
        signature
    }

    pub async fn verified_callback(&self, body: &[u8]) -> VerifiedWebhookEvent {
        let signature = self.callback_signature(body);
        self.webhook_verifier
            .verify(body, &signature)
            .await
            .unwrap()
    }

    pub async fn rejected_callback(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<VerifiedWebhookEvent, BureauError> {
        self.webhook_verifier.verify(body, signature).await
    }
}

struct BoundChunk {
    organization_id: String,
    artifact_id: String,
    index: u64,
    count: u64,
    plaintext_b64: String,
}

fn binding(
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: &Value,
) -> Option<(String, String, u64, u64)> {
    if headers.get("x-api-key")?.to_str().ok()? != API_KEY {
        return None;
    }
    let organization_id = query.get("organization_id")?.clone();
    let artifact_id = body.get("artifact_id")?.as_str()?.to_owned();
    let index = body.get("chunk_index")?.as_u64()?;
    let count = body.get("chunk_count")?.as_u64()?;
    if organization_id.is_empty() || artifact_id.is_empty() || index >= count {
        return None;
    }
    Some((organization_id, artifact_id, index, count))
}

async fn encrypt(
    State(store): State<Arc<Store>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some((organization_id, artifact_id, index, count)) = binding(&query, &headers, &body)
    else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let Some(plaintext_b64) = body.get("plaintext_b64").and_then(Value::as_str) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let ciphertext = format!(
        "vault:v1:passport-test-{}",
        store.sequence.fetch_add(1, Ordering::Relaxed)
    );
    store.chunks.lock().unwrap().insert(
        ciphertext.clone(),
        BoundChunk {
            organization_id,
            artifact_id,
            index,
            count,
            plaintext_b64: plaintext_b64.to_owned(),
        },
    );
    (StatusCode::OK, Json(json!({"ciphertext": ciphertext})))
}

async fn decrypt(
    State(store): State<Arc<Store>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some((organization_id, artifact_id, index, count)) = binding(&query, &headers, &body)
    else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let Some(ciphertext) = body.get("ciphertext").and_then(Value::as_str) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let chunks = store.chunks.lock().unwrap();
    let Some(chunk) = chunks.get(ciphertext) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    if (
        chunk.organization_id.as_str(),
        chunk.artifact_id.as_str(),
        chunk.index,
        chunk.count,
    ) != (organization_id.as_str(), artifact_id.as_str(), index, count)
    {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({"plaintext_b64": chunk.plaintext_b64})),
    )
}

async fn verify_callback(
    State(store): State<Arc<Store>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        != Some(API_KEY)
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    let Some(organization_id) = query.get("organization_id") else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let Some(signature) = body.get("signature").and_then(Value::as_str) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let Some(encoded_body) = body.get("body_b64").and_then(Value::as_str) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let Ok(callback_body) = STANDARD.decode(encoded_body) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({})));
    };
    let callbacks = store.callbacks.lock().unwrap();
    let valid = callbacks
        .get(signature)
        .is_some_and(|(tenant, expected)| tenant == organization_id && expected == &callback_body);
    (StatusCode::OK, Json(json!({"valid": valid})))
}

pub async fn start() -> MockPassportKms {
    let store = Arc::new(Store::default());
    let router = Router::new()
        .route(
            "/internal/signing-keys/passport-artifacts/encrypt",
            post(encrypt),
        )
        .route(
            "/internal/signing-keys/passport-artifacts/decrypt",
            post(decrypt),
        )
        .route(
            "/internal/signing-keys/passport-callbacks/verify",
            post(verify_callback),
        )
        .with_state(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = url::Url::parse(&format!(
        "http://{}/internal/signing-keys",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    MockPassportKms {
        cipher: KmsPassportArtifactCipher::new(base.clone(), API_KEY).unwrap(),
        webhook_verifier: KmsWebhookVerifier::new(base, API_KEY).unwrap(),
        store,
        server,
    }
}
