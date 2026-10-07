//! Synthetic remote custody boundary for repository tests. It holds opaque
//! tokens and plaintext in the test server, without any local cryptographic key.
//! Real OpenBao behavior is exercised by the opt-in live migration contract.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use marty_issuance_service::integration_secret_kms::KmsIntegrationSecretCipher;
use serde_json::{json, Value};
use url::Url;

type Records = Arc<Mutex<HashMap<String, Value>>>;

fn identity(body: &Value) -> Option<[&str; 4]> {
    Some([
        body.get("organization_id")?.as_str()?,
        body.get("secret_id")?.as_str()?,
        body.get("provider")?.as_str()?,
        body.get("purpose")?.as_str()?,
    ])
}

fn authorized(headers: &HeaderMap, query: &HashMap<String, String>, body: &Value) -> bool {
    headers
        .get("x-api-key")
        .is_some_and(|key| key == "test-remote-secret")
        && identity(body).is_some_and(|parts| {
            query
                .get("organization_id")
                .is_some_and(|org| org == parts[0])
        })
}

async fn encrypt(
    State(records): State<Records>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &query, &body) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let plaintext = body
        .get("plaintext_b64")
        .and_then(Value::as_str)
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let token = uuid::Uuid::new_v4().to_string();
    let mut record = body.clone();
    record["plaintext_b64"] = Value::String(plaintext.to_owned());
    records.lock().unwrap().insert(token.clone(), record);
    Ok(Json(
        json!({"schema":"marty.integration-secret-envelope/v1","ciphertext":format!("vault:v1:{token}")}),
    ))
}

async fn decrypt(
    State(records): State<Records>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &query, &body) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = body
        .pointer("/envelope/ciphertext")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("vault:v1:"))
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let stored = records
        .lock()
        .unwrap()
        .get(token)
        .cloned()
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    if identity(&stored) != identity(&body) {
        return Err(StatusCode::CONFLICT);
    }
    Ok(Json(json!({"plaintext_b64":stored["plaintext_b64"]})))
}

pub const API_KEY: &str = "test-remote-secret";

pub fn base_url() -> Url {
    static BASE: OnceLock<Url> = OnceLock::new();
    let base = BASE.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let records: Records = Arc::new(Mutex::new(HashMap::new()));
                let app = Router::new()
                    .route("/internal/integration-secrets/encrypt", post(encrypt))
                    .route("/internal/integration-secrets/decrypt", post(decrypt))
                    .with_state(records);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                sender.send(listener.local_addr().unwrap().port()).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        Url::parse(&format!(
            "http://127.0.0.1:{}/internal",
            receiver.recv().unwrap()
        ))
        .unwrap()
    });
    base.clone()
}

#[allow(dead_code)] // Process fixtures use the URL and key; repository fixtures use this client.
pub fn cipher() -> KmsIntegrationSecretCipher {
    KmsIntegrationSecretCipher::new(base_url(), API_KEY).unwrap()
}
