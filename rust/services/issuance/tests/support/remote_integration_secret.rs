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

#[derive(Clone)]
struct RemoteState {
    records: Records,
    api_key: &'static str,
}

fn identity(body: &Value) -> Option<[&str; 4]> {
    Some([
        body.get("organization_id")?.as_str()?,
        body.get("secret_id")?.as_str()?,
        body.get("provider")?.as_str()?,
        body.get("purpose")?.as_str()?,
    ])
}

fn authorized(
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    body: &Value,
    api_key: &str,
) -> bool {
    headers.get("x-api-key").is_some_and(|key| key == api_key)
        && identity(body).is_some_and(|parts| {
            query
                .get("organization_id")
                .is_some_and(|org| org == parts[0])
        })
}

async fn encrypt(
    State(state): State<RemoteState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &query, &body, state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let plaintext = body
        .get("plaintext_b64")
        .and_then(Value::as_str)
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let token = uuid::Uuid::new_v4().to_string();
    let mut record = body.clone();
    record["plaintext_b64"] = Value::String(plaintext.to_owned());
    state.records.lock().unwrap().insert(token.clone(), record);
    Ok(Json(
        json!({"schema":"marty.integration-secret-envelope/v1","ciphertext":format!("vault:v1:{token}")}),
    ))
}

async fn decrypt(
    State(state): State<RemoteState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &query, &body, state.api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = body
        .pointer("/envelope/ciphertext")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("vault:v1:"))
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let stored = state
        .records
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

pub(crate) fn router_for(api_key: &'static str) -> Router {
    let state = RemoteState {
        records: Arc::new(Mutex::new(HashMap::new())),
        api_key,
    };
    Router::new()
        .route("/integration-secrets/encrypt", post(encrypt))
        .route("/integration-secrets/decrypt", post(decrypt))
        .route("/internal/integration-secrets/encrypt", post(encrypt))
        .route("/internal/integration-secrets/decrypt", post(decrypt))
        .with_state(state)
}

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
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                sender.send(listener.local_addr().unwrap().port()).unwrap();
                axum::serve(listener, router_for(API_KEY)).await.unwrap();
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
    match (
        std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_URL"),
        std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_API_KEY"),
    ) {
        (Ok(remote_url), Ok(api_key)) => {
            return KmsIntegrationSecretCipher::new(Url::parse(&remote_url).unwrap(), &api_key)
                .expect("live Signing Keys test configuration");
        }
        (Err(_), Err(_)) => {}
        _ => panic!("live Signing Keys test requires both URL and internal API key"),
    }
    KmsIntegrationSecretCipher::new(base_url(), API_KEY).unwrap()
}
