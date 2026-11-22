use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    routing::any,
    Router,
};
use marty_delegated_use_client::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    RootCertStore,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ORGANIZATION: &str = "33333333-3333-4333-8333-333333333333";
pub const CHALLENGE: &str = "22222222-2222-4222-8222-222222222222";
pub const SUBMISSION: &str = "44444444-4444-4444-8444-444444444444";
pub const COMPACT: &str = "e30.e30.c2lnbmF0dXJl";
pub const CREATED: &str = "2026-11-21T15:00:00Z";
pub const RECEIVED: &str = "2026-11-21T15:00:01Z";
pub const EXPIRES: &str = "2026-11-21T15:01:00Z";

pub fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn start() -> PreparedStart {
    PreparedStart::new(
        id("11111111-1111-4111-8111-111111111111"),
        GrantReference {
            id: id("55555555-5555-4555-8555-555555555555"),
            revision: 3,
            terms_digest: digest(b"original terms"),
        },
        Operation {
            action: "urn:example:order:create".into(),
            resource_id: "urn:example:product:42".into(),
            audience: "https://merchant.example.test/api".into(),
            request_profile: "urn:example:order:v1".into(),
            request_digest: digest(b"independent operation"),
        },
    )
    .unwrap()
}
pub fn finalize() -> PreparedFinalize {
    PreparedFinalize::new(
        id("66666666-6666-4666-8666-666666666666"),
        id(CHALLENGE),
        id(SUBMISSION),
    )
    .unwrap()
}
pub fn challenge(command: &PreparedStart, recovered: bool) -> Value {
    let original: Value = serde_json::from_slice(command.bytes()).unwrap();
    json!({"profile":COMMAND_RESPONSE_PROFILE,"original_command_id":command.command_id(),
        "command_digest":command.command_digest(),"recovered":recovered,
        "result":{"kind":"CHALLENGE","challenge_id":CHALLENGE,"grant":original["grant"],
            "operation":original["operation"],"created_at":CREATED,"expires_at":EXPIRES}})
}
pub fn final_result(command: &PreparedFinalize, recovered: bool) -> Value {
    json!({"profile":COMMAND_RESPONSE_PROFILE,"original_command_id":command.command_id(),
        "command_digest":command.command_digest(),"recovered":recovered,
        "result":{"kind":"FINAL_USE","challenge_id":CHALLENGE,"decision":"PERMIT",
            "receipt_ref":format!("urn:marty:delegated-receipt:{SUBMISSION}"),
            "receipt_digest":digest(COMPACT.as_bytes()),"recorded_at":RECEIVED,
            "authorization_expires_at":EXPIRES,"semantics":EVIDENCE_SEMANTICS}})
}
pub fn receipt(command: &PreparedFinalize) -> Value {
    json!({"original_response":final_result(command,true),
        "receipt_ref":format!("urn:marty:delegated-receipt:{SUBMISSION}"),
        "receipt_digest":digest(COMPACT.as_bytes()),"compact_jws":COMPACT,"semantics":EVIDENCE_SEMANTICS})
}
pub fn submission(proof: &str) -> Value {
    json!({"submission_id":SUBMISSION,"challenge_id":CHALLENGE,"proof_digest":digest(proof.as_bytes()),
        "received_at":RECEIVED,"recovered":false})
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
    pub delay: Duration,
}
impl Reply {
    pub fn raw(content_type: &str, bytes: impl Into<Vec<u8>>) -> Self {
        let mut headers = HeaderMap::new();
        for (key, value) in [
            ("content-type", content_type),
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("x-content-type-options", "nosniff"),
        ] {
            headers.insert(
                axum::http::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        Self {
            status: StatusCode::OK,
            headers,
            bytes: bytes.into(),
            delay: Duration::ZERO,
        }
    }
    pub fn json(value: Value) -> Self {
        Self::raw("application/json", serde_json::to_vec(&value).unwrap())
    }
    pub fn link(mut self, origin: &str) -> Self {
        self.headers.insert("link", HeaderValue::from_str(&format!("<{origin}/v1/flows/instances/{CHALLENGE}/request>; rel=\"{REQUEST_LINK_RELATION}\"")).unwrap());
        self
    }
}

#[derive(Clone, Debug)]
pub struct Observed {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Default)]
struct App {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    observed: Arc<Mutex<Vec<Observed>>>,
}
async fn answer(State(state): State<App>, request: Request) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 1_000_000).await.unwrap().to_vec();
    state.observed.lock().unwrap().push(Observed {
        method: parts.method.to_string(),
        path: parts.uri.to_string(),
        headers: parts.headers,
        bytes,
    });
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| {
            let mut reply = Reply::raw("text/plain", "unexpected extra request");
            reply.status = StatusCode::INTERNAL_SERVER_ERROR;
            reply
        });
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let mut response = Response::new(Body::from(reply.bytes));
    *response.status_mut() = reply.status;
    *response.headers_mut() = reply.headers;
    response
}

pub struct Pki {
    pub ca: CertificateDer<'static>,
    server: CertificateDer<'static>,
    server_key: Vec<u8>,
    client: CertificateDer<'static>,
    client_key: Vec<u8>,
}
impl Pki {
    pub fn new() -> Self {
        let mut ca = CertificateParams::new(Vec::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = ca.self_signed(&key).unwrap();
        let issuer = Issuer::new(ca, key);
        let mut server =
            CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server = server.signed_by(&server_key, &issuer).unwrap();
        let mut client = CertificateParams::new(vec!["client.example.test".into()]).unwrap();
        client.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client = client.signed_by(&client_key, &issuer).unwrap();
        Self {
            ca: cert.der().clone(),
            server: server.der().clone(),
            server_key: server_key.serialize_der(),
            client: client.der().clone(),
            client_key: client_key.serialize_der(),
        }
    }
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        roots
    }
    pub fn mtls(&self) -> MtlsConfig {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(self.roots())
        .with_client_auth_cert(
            vec![self.client.clone(), self.ca.clone()],
            PrivatePkcs8KeyDer::from(self.client_key.clone()).into(),
        )
        .unwrap();
        MtlsConfig {
            roots: self.roots(),
            client_certificate: config.client_auth_cert_resolver,
        }
    }
    pub fn no_certificate(&self) -> MtlsConfig {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(self.roots())
        .with_no_client_auth();
        MtlsConfig {
            roots: self.roots(),
            client_certificate: config.client_auth_cert_resolver,
        }
    }
}

pub struct Host {
    pub origin: String,
    pub pki: Pki,
    app: App,
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<()>,
}
impl Host {
    pub async fn new() -> Self {
        let pki = Pki::new();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(pki.roots()),
            provider.clone(),
        )
        .build()
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![pki.server.clone(), pki.ca.clone()],
                PrivatePkcs8KeyDer::from(pki.server_key.clone()).into(),
            )
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let app = App::default();
        let router = Router::new()
            .route("/{*path}", any(answer))
            .with_state(app.clone());
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(
            listener,
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
        )
        .unwrap()
        .handle(handle.clone());
        let task = tokio::spawn(async move {
            server.serve(router.into_make_service()).await.unwrap();
        });
        Self {
            origin,
            pki,
            app,
            handle,
            task,
        }
    }
    pub fn config(&self) -> ClientConfig {
        ClientConfig {
            origin: self.origin.clone(),
            organization: id(ORGANIZATION),
            tls: self.pki.mtls(),
            timeout: Duration::from_secs(2),
        }
    }
    pub fn client(&self) -> DelegatedUseClient {
        DelegatedUseClient::new(self.config()).unwrap()
    }
    pub fn push(&self, reply: Reply) {
        self.app.replies.lock().unwrap().push_back(reply);
    }
    pub fn seen(&self) -> Vec<Observed> {
        self.app.observed.lock().unwrap().clone()
    }
    pub fn started_reply(&self, command: &PreparedStart, recovered: bool) {
        self.push(Reply::json(challenge(command, recovered)).link(&self.origin));
    }
    pub fn verified(&self) -> CallerVerifiedRequest {
        CallerVerifiedRequest {
            response_uri: format!("{}/v1/flows/instances/{CHALLENGE}/submit", self.origin),
            state: CHALLENGE.into(),
            query_id: "selected_machine".into(),
        }
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}
