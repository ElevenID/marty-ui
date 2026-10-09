//! Synthetic remote custody boundary for repository tests. It holds opaque
//! tokens and plaintext in the test server, without any local cryptographic key.
//! Real OpenBao behavior is exercised by the opt-in live migration contract.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
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

struct TestServer {
    base_url: Url,
    ca_pem: String,
    #[allow(dead_code)] // Only process fixtures pass this trust root to a child binary.
    ca_file: PathBuf,
    _tempdir: tempfile::TempDir,
}

fn server() -> &'static TestServer {
    static SERVER: OnceLock<TestServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca_pem = certified.cert.pem();
        let key_pem = certified.signing_key.serialize_pem();
        let tempdir = tempfile::tempdir().unwrap();
        let ca_file = tempdir.path().join("integration-secret-test-ca.pem");
        std::fs::write(&ca_file, &ca_pem).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_cert = ca_pem.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
                    server_cert.into_bytes(),
                    key_pem.into_bytes(),
                )
                .await
                .unwrap();
                axum_server::from_tcp_rustls(listener, tls)
                    .unwrap()
                    .serve(router_for(API_KEY).into_make_service())
                    .await
                    .unwrap();
            });
        });
        TestServer {
            base_url: Url::parse(&format!("https://127.0.0.1:{port}/internal")).unwrap(),
            ca_pem,
            ca_file,
            _tempdir: tempdir,
        }
    })
}

/// Packaging-only remote endpoint reachable from the owned Docker bridge.
/// Live OpenBao custody is qualified separately by the restore contract.
#[allow(dead_code)] // Shared fixture is included by tests without a container.
pub(crate) struct ContainerServer {
    pub base_url: String,
    pub ca_pem: String,
}

#[allow(dead_code)] // Shared fixture is included by tests without a container.
pub(crate) async fn container_server(
    gateway: Ipv4Addr,
    api_key: &'static str,
) -> Result<ContainerServer, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec![gateway.to_string()])
        .map_err(|_| "Disposable remote-secret TLS fixture failed")?;
    let ca_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let listener = std::net::TcpListener::bind((gateway, 0))
        .map_err(|_| "Disposable remote-secret listener failed")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Disposable remote-secret listener failed")?;
    let port = listener
        .local_addr()
        .map_err(|_| "Disposable remote-secret listener failed")?
        .port();
    let server_cert = ca_pem.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("disposable remote-secret runtime");
        runtime.block_on(async {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
                server_cert.into_bytes(),
                key_pem.into_bytes(),
            )
            .await
            .expect("disposable remote-secret TLS");
            axum_server::from_tcp_rustls(listener, tls)
                .expect("disposable remote-secret listener")
                .serve(router_for(api_key).into_make_service())
                .await
                .expect("disposable remote-secret server");
        });
    });
    let base_url = format!("https://{gateway}:{port}/internal");
    let cipher = KmsIntegrationSecretCipher::new_with_ca_pem(
        Url::parse(&base_url).map_err(|_| "Disposable remote-secret URL failed")?,
        api_key,
        Some(ca_pem.as_bytes()),
    )
    .map_err(|_| "Disposable remote-secret client failed")?;
    for _ in 0..40 {
        if let Ok(envelope) = cipher
            .encrypt(
                "marty-system",
                "fixture-probe",
                "system",
                "startup_proof",
                "probe",
            )
            .await
        {
            if cipher
                .decrypt(
                    "marty-system",
                    "fixture-probe",
                    "system",
                    "startup_proof",
                    &envelope,
                )
                .await
                .is_ok_and(|plaintext| plaintext == "probe")
            {
                return Ok(ContainerServer { base_url, ca_pem });
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("Disposable remote-secret fixture did not become ready".into())
}

pub fn base_url() -> Url {
    server().base_url.clone()
}

#[allow(dead_code)] // Only process fixtures need a path; repository tests trust ca_pem directly.
pub fn ca_file() -> &'static std::path::Path {
    &server().ca_file
}

#[allow(dead_code)] // Process fixtures use the URL and key; repository fixtures use this client.
pub fn cipher() -> KmsIntegrationSecretCipher {
    match (
        std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_URL"),
        std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_API_KEY"),
    ) {
        (Ok(remote_url), Ok(api_key)) => {
            let ca_pem = std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_CA_FILE")
                .ok()
                .map(std::fs::read)
                .transpose()
                .expect("live Signing Keys test CA file");
            return KmsIntegrationSecretCipher::new_with_ca_pem(
                Url::parse(&remote_url).unwrap(),
                &api_key,
                ca_pem.as_deref(),
            )
            .expect("live Signing Keys test configuration");
        }
        (Err(_), Err(_)) => {}
        _ => panic!("live Signing Keys test requires both URL and internal API key"),
    }
    KmsIntegrationSecretCipher::new_with_ca_pem(
        base_url(),
        API_KEY,
        Some(server().ca_pem.as_bytes()),
    )
    .unwrap()
}
