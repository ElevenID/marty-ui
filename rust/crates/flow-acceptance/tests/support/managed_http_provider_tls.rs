//! The selected native clients must verify a real private-CA HTTPS listener.
//! This transport-only fixture creates no policies, grants or KMS authorities.
use axum::{routing::get, Json, Router};
use marty_flow::{HttpFlowReferenceProvider, HttpSigningProvider};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::json;
use std::{net::TcpListener, sync::Arc};

struct Endpoint {
    origin: String,
    ca: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    async fn start() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = Router::new().route("/health", get(|| async { Json(json!({"status":"ok"})) }));
        let server = axum_server::from_tcp_rustls(
            listener,
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            server.serve(router.into_make_service()).await.unwrap();
        });
        Self {
            origin: format!("https://localhost:{port}"),
            ca: ca.pem().into_bytes(),
            task,
        }
    }
}

#[tokio::test]
async fn native_flow_clients_use_only_selected_ca_and_verify_hostnames() {
    let endpoint = Endpoint::start().await;
    let references = HttpFlowReferenceProvider::with_trusted_ca(
        &endpoint.origin,
        &"a".repeat(32),
        &endpoint.origin,
        &endpoint.origin,
        &endpoint.origin,
        Some(&"s".repeat(32)),
        &endpoint.ca,
    )
    .unwrap();
    references.health_check().await.unwrap();
    let signing = HttpSigningProvider::with_trusted_ca(
        &format!("{}/internal/", endpoint.origin),
        &"r".repeat(32),
        &"w".repeat(32),
        &endpoint.ca,
    )
    .unwrap();
    signing.health_check().await.unwrap();

    let other = Endpoint::start().await;
    let wrong_ca = HttpSigningProvider::with_trusted_ca(
        &format!("{}/internal/", endpoint.origin),
        &"r".repeat(32),
        &"w".repeat(32),
        &other.ca,
    )
    .unwrap();
    assert!(wrong_ca.health_check().await.is_err());
    let wrong_name = HttpSigningProvider::with_trusted_ca(
        &endpoint.origin.replace("localhost", "127.0.0.1"),
        &"r".repeat(32),
        &"w".repeat(32),
        &endpoint.ca,
    )
    .unwrap();
    assert!(wrong_name.health_check().await.is_err());
    let no_selected_ca =
        HttpSigningProvider::new(&endpoint.origin, &"r".repeat(32), &"w".repeat(32)).unwrap();
    assert!(no_selected_ca.health_check().await.is_err());
}

#[tokio::test]
async fn selected_ca_cannot_enable_plaintext_or_accept_key_material() {
    let endpoint = Endpoint::start().await;
    for ca in [
        Vec::new(),
        b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_vec(),
        b"invalid PEM".to_vec(),
        [endpoint.ca.clone(), endpoint.ca.clone()].concat(),
        vec![b'x'; 65_537],
    ] {
        assert!(HttpSigningProvider::with_trusted_ca(
            &endpoint.origin,
            &"r".repeat(32),
            &"w".repeat(32),
            &ca
        )
        .is_err());
    }
    let plaintext = endpoint.origin.replacen("https:", "http:", 1);
    assert!(HttpSigningProvider::with_trusted_ca(
        &plaintext,
        &"r".repeat(32),
        &"w".repeat(32),
        &endpoint.ca
    )
    .is_err());
    assert!(HttpFlowReferenceProvider::with_trusted_ca(
        &endpoint.origin,
        &"a".repeat(32),
        &plaintext,
        &endpoint.origin,
        &endpoint.origin,
        Some(&"s".repeat(32)),
        &endpoint.ca
    )
    .is_err());
}
