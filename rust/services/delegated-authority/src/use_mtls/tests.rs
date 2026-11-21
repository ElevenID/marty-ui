use super::*;
use crate::use_http::{
    delegated_use_command_router, AuthenticatedDelegationUseContext, DelegationUseHttpApplication,
    DelegationUseHttpAuthenticator, DelegationUseHttpState,
};
use crate::DelegationUseCommandResponse;
use async_trait::async_trait;
use axum::{body::Body, http::Request};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

const ORG: &str = "21db588c-d2cb-4873-927e-03d1134914e7";
const ACTOR: &str = "urn:example:machine:protected-use";
const WORKLOAD: &str = "spiffe://example.test/rifare/workload-one";

struct Pki {
    ca: Certificate,
    issuer: Issuer<'static, KeyPair>,
    server: Certificate,
    server_key: KeyPair,
}
impl Pki {
    fn new() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        // The CA's SAN must never be used as a client's workload identity.
        ca_params
            .subject_alt_names
            .push(SanType::URI(WORKLOAD.try_into().unwrap()));
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server = params.signed_by(&server_key, &issuer).unwrap();
        Self {
            ca,
            issuer,
            server,
            server_key,
        }
    }
    fn client(&self, uris: &[&str], lifetime: Option<Duration>) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI((*uri).try_into().unwrap()))
            .collect();
        if let Some(lifetime) = lifetime {
            let now = std::time::SystemTime::now();
            params.not_before = (now - Duration::from_secs(60)).into();
            params.not_after = (now + lifetime).into();
        }
        let key = KeyPair::generate().unwrap();
        (params.signed_by(&key, &self.issuer).unwrap(), key)
    }
    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        roots
    }
    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(self.roots()))
            .build()
            .unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server.der().clone()],
                PrivatePkcs8KeyDer::from(self.server_key.serialize_der()).into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
    fn http_client(&self, identity: Option<(&Certificate, &KeyPair)>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_der(self.ca.der()).unwrap()])
            .no_proxy()
            .timeout(Duration::from_secs(5));
        if let Some((cert, key)) = identity {
            let pem = format!("{}{}", cert.pem(), key.serialize_pem());
            builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        builder.build().unwrap()
    }
}

#[derive(Default)]
struct Application {
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
}
#[async_trait]
impl DelegationUseHttpApplication for Application {
    async fn execute(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        assert_eq!(context.caller().organization_id().to_string(), ORG);
        assert_eq!(
            context.caller().actor().principal_type,
            PrincipalType::MachineIdentity
        );
        assert_eq!(context.caller().actor().id, ACTOR);
        assert!(context
            .workload_identity_ref()
            .unwrap()
            .starts_with("urn:marty:delegated-use:mtls:sha256:"));
        assert!(context.caller().authentication_session_ref().is_none());
        context.check(Utc::now()).unwrap();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(raw.to_vec());
        Err(DelegationUseCommandError::PreparationPending)
    }
}

fn binding(cert: &Certificate) -> DelegatedUseWorkloadBinding {
    DelegatedUseWorkloadBinding::new(
        WORKLOAD.into(),
        format!("sha256:{:x}", Sha256::digest(cert.der())),
        ACTOR.into(),
    )
    .unwrap()
}
fn authenticator(cert: &Certificate) -> Arc<DelegationUseHttpAuthenticator> {
    Arc::new(
        DelegationUseHttpAuthenticator::mutual_tls(
            ORG.parse().unwrap(),
            DelegatedUseWorkloadBindings::new(vec![binding(cert)]).unwrap(),
        )
        .unwrap(),
    )
}
fn router(cert: &Certificate, app: Arc<Application>) -> Router {
    delegated_use_command_router(DelegationUseHttpState::with_authenticator(
        app,
        authenticator(cert),
    ))
}
fn command() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({"profile":crate::DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":Uuid::new_v4(),"expected_command_digest":format!("sha256:{}","a".repeat(64))})).unwrap()
}
fn path() -> String {
    format!("/internal/v1/organizations/{ORG}/delegated-use-commands")
}
async fn server(
    pki: &Pki,
    cert: &Certificate,
    app: Arc<Application>,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let server = BoundDelegatedUseMtlsServer::bind_config(
        "127.0.0.1:0".parse().unwrap(),
        pki.server_config(),
        router(cert, app),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(server.serve(rx));
    (address, shutdown, task)
}

#[test]
fn workload_mapping_is_explicit_and_unambiguous() {
    let pin = format!("sha256:{}", "a".repeat(64));
    for uri in [
        "https://example.test/workload",
        "spiffe://example.test",
        "spiffe://example.test/a/../b",
        "spiffe://example.test/a%2fb",
        "spiffe://example.test/a?b",
        "spiffe://user@example.test/a",
        "spiffe://example.test:443/a",
        "spiffe://example.test/a//b",
    ] {
        assert!(
            DelegatedUseWorkloadBinding::new(uri.into(), pin.clone(), ACTOR.into()).is_err(),
            "{uri}"
        );
    }
    assert!(DelegatedUseWorkloadBindings::new(Vec::new()).is_err());
    let one = DelegatedUseWorkloadBinding::new(WORKLOAD.into(), pin.clone(), ACTOR.into()).unwrap();
    assert!(DelegatedUseWorkloadBindings::new(vec![one.clone(), one.clone()]).is_err());
    let duplicate_pin = DelegatedUseWorkloadBinding::new(
        "spiffe://example.test/other".into(),
        pin.clone(),
        ACTOR.into(),
    )
    .unwrap();
    assert!(DelegatedUseWorkloadBindings::new(vec![one.clone(), duplicate_pin]).is_err());
    let duplicate_uri = DelegatedUseWorkloadBinding::new(
        WORKLOAD.into(),
        format!("sha256:{}", "b".repeat(64)),
        "urn:example:other".into(),
    )
    .unwrap();
    assert!(DelegatedUseWorkloadBindings::new(vec![one, duplicate_uri]).is_err());
}

#[tokio::test]
async fn bare_http_and_identity_headers_cannot_manufacture_tls_evidence() {
    let pki = Pki::new();
    let (cert, _) = pki.client(&[WORKLOAD], None);
    let app = Arc::new(Application::default());
    for forged in [
        None,
        Some(("x-workload-identity", WORKLOAD)),
        Some(("x-marty-use-principal-id", ACTOR)),
        Some(("x-service-token", "synthetic-service-token-that-is-not-TLS")),
        Some(("x-forwarded-client-cert", "synthetic-public-certificate")),
    ] {
        let mut req = Request::builder()
            .method("POST")
            .uri(path())
            .header("content-type", "application/json");
        if let Some((name, value)) = forged {
            req = req.header(name, value);
        }
        let response = router(&cert, app.clone())
            .oneshot(req.body(Body::from(command())).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
    }
    assert_eq!(app.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn actual_mutual_tls_derives_pinned_actor_and_rejects_foreign_identity_paths() {
    let pki = Pki::new();
    let (cert, key) = pki.client(&[WORKLOAD], None);
    let app = Arc::new(Application::default());
    let (address, shutdown, task) = server(&pki, &cert, app.clone()).await;
    let endpoint = format!("https://localhost:{}{}", address.port(), path());
    let bytes = command();
    let client = pki.http_client(Some((&cert, &key)));
    let response = client
        .post(&endpoint)
        .header("content-type", "application/json")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(app.requests.lock().unwrap().as_slice(), &[bytes]);
    for (name, value) in [
        ("x-marty-use-principal-id", "urn:example:other"),
        ("x-workload-identity", WORKLOAD),
        ("authorization", "Bearer synthetic"),
        ("x-service-token", "synthetic-service-token-that-is-not-TLS"),
    ] {
        assert_eq!(
            client
                .post(&endpoint)
                .header("content-type", "application/json")
                .header(name, value)
                .body(command())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let foreign = endpoint.replace(ORG, &Uuid::new_v4().to_string());
    assert_eq!(
        client
            .post(foreign)
            .header("content-type", "application/json")
            .body(command())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(pki
        .http_client(None)
        .post(&endpoint)
        .body(command())
        .send()
        .await
        .is_err());
    // CA trust alone, an unchanged URI after rotation, or a CA SAN cannot pick
    // a machine principal without the configured exact leaf pin and leaf URI.
    for uris in [
        vec!["spiffe://example.test/other"],
        vec![WORKLOAD],
        vec![WORKLOAD, "spiffe://example.test/second"],
        vec![],
    ] {
        let (other, key) = pki.client(&uris, None);
        let response = pki
            .http_client(Some((&other, &key)))
            .post(&endpoint)
            .header("content-type", "application/json")
            .body(command())
            .send()
            .await;
        assert!(response.is_err() || response.unwrap().status() == StatusCode::FORBIDDEN);
    }
    let untrusted = Pki::new();
    let (other, key) = untrusted.client(&[WORKLOAD], None);
    assert!(pki
        .http_client(Some((&other, &key)))
        .post(&endpoint)
        .body(command())
        .send()
        .await
        .is_err());
    assert_eq!(app.calls.load(Ordering::SeqCst), 1);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn tls_observation_preserves_leaf_expiry_and_rejects_clock_regression() {
    let pki = Pki::new();
    let (cert, _) = pki.client(&[WORKLOAD], None);
    let bindings = DelegatedUseWorkloadBindings::new(vec![binding(&cert)]).unwrap();
    let mut peer = AuthenticatedUseTlsPeer::from_verified_leaf(cert.der()).unwrap();
    let now = Utc::now();
    peer.not_after = now + chrono::Duration::seconds(2);
    let (_, deadline) = bindings
        .authenticate(ORG.parse().unwrap(), &peer, now)
        .unwrap();
    assert_eq!(deadline, peer.not_after);
    assert!(bindings
        .authenticate(ORG.parse().unwrap(), &peer, peer.not_after)
        .is_err());
    peer.authenticated_at = now + chrono::Duration::seconds(1);
    assert!(bindings
        .authenticate(ORG.parse().unwrap(), &peer, now)
        .is_err());
}

#[tokio::test]
async fn certificate_expiry_during_actual_tls_body_read_never_dispatches() {
    let pki = Pki::new();
    let (cert, key) = pki.client(&[WORKLOAD], Some(Duration::from_secs(4)));
    let app = Arc::new(Application::default());
    let (address, shutdown, task) = server(&pki, &cert, app.clone()).await;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(pki.roots())
        .with_client_auth_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let bytes = command();
    let headers=format!("POST {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",path(),bytes.len());
    tls.write_all(headers.as_bytes()).await.unwrap();
    tls.write_all(&bytes[..1]).await.unwrap();
    tls.flush().await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    tls.write_all(&bytes[1..]).await.unwrap();
    tls.flush().await.unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8(response)
        .unwrap()
        .starts_with("HTTP/1.1 403"));
    assert_eq!(app.calls.load(Ordering::SeqCst), 0);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}
