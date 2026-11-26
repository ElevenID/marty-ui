use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{Duration as ClockDuration, SecondsFormat};
use ed25519_dalek::Signer as _;
use marty_signing_grant::{GrantEnvelope, GrantError};
use p256::ecdsa::{signature::Signer, SigningKey};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex,
    },
};

#[tokio::test]
async fn receipt_https_transport_uses_exact_private_ca_and_validates_hostname() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::PrivatePkcs8KeyDer;
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
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new().route(
        "/probe",
        post(|| async { Json(json!({"transport":"verified"})) }),
    );
    let server = axum_server::from_tcp_rustls(
        listener,
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
    )
    .unwrap();
    struct Task(tokio::task::JoinHandle<()>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _task = Task(tokio::spawn(async move {
        server.serve(router.into_make_service()).await.unwrap();
    }));
    let origin = format!("https://localhost:{port}");
    let key = TestKey::new("EdDSA", 1);
    let construct = |origin: &str, trusted_ca: &[u8]| {
        HttpManagedDelegatedReceiptSigner::build_with_ca(
            origin,
            "r".repeat(40),
            "s".repeat(40),
            pin("EdDSA", &key),
            Arc::new(TestMinter {
                substitute_origin: false,
                reuse_nonce: false,
            }),
            false,
            Some(trusted_ca),
        )
    };
    let pem = ca.pem();
    let signer = construct(&origin, pem.as_bytes()).unwrap();
    assert_eq!(
        signer
            .post("probe", &"r".repeat(40), json!({}), None)
            .await
            .unwrap(),
        json!({"transport":"verified"})
    );
    let wrong_name = construct(&origin.replace("localhost", "127.0.0.1"), pem.as_bytes()).unwrap();
    assert!(wrong_name
        .post("probe", &"r".repeat(40), json!({}), None)
        .await
        .is_err());
    let other_key = KeyPair::generate().unwrap();
    let other_ca = ca_params.self_signed(&other_key).unwrap().pem();
    let wrong_ca = construct(&origin, other_ca.as_bytes()).unwrap();
    assert!(wrong_ca
        .post("probe", &"r".repeat(40), json!({}), None)
        .await
        .is_err());
    assert!(construct(&origin.replacen("https:", "http:", 1), pem.as_bytes()).is_err());
    for invalid in [
        Vec::new(),
        b"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_vec(),
        b"invalid certificate".to_vec(),
        [pem.as_bytes(), pem.as_bytes()].concat(),
        vec![b'x'; 65_537],
    ] {
        assert!(construct(&origin, &invalid).is_err());
    }
}

#[derive(Clone)]
enum TestKey {
    Es(SigningKey),
    Ed(ed25519_dalek::SigningKey),
}
impl TestKey {
    fn new(algorithm: &str, seed: u8) -> Self {
        if algorithm == "ES256" {
            Self::Es(SigningKey::from_slice(&[seed; 32]).unwrap())
        } else {
            Self::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
        }
    }
    fn jwk(&self) -> Value {
        match self {
            Self::Es(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
            }
            Self::Ed(key) => {
                json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())})
            }
        }
    }
    fn sign(&self, input: &[u8], value: &mut Value) {
        match self {
            Self::Es(key) => {
                let signature: Signature = key.sign(input);
                value["signature_encoding"] = json!("der");
                value["signature_b64"] =
                    json!(URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()));
                value["signature_raw_b64"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
            }
            Self::Ed(key) => {
                let signature = key.sign(input);
                value["signature_encoding"] = json!("raw");
                value["signature_b64"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
            }
        }
    }
}
const ORG: &str = "33333333-3333-4333-8333-333333333333";
const ISSUER: &str = "did:web:receipt.example";
const KID: &str = "did:web:receipt.example#receipt-key-1";
fn issuer() -> Principal {
    Principal {
        principal_type: crate::PrincipalType::Organization,
        id: ISSUER.into(),
    }
}
fn pin(algorithm: &str, key: &TestKey) -> ManagedDelegatedReceiptKey {
    ManagedDelegatedReceiptKey::new(
        Uuid::parse_str(ORG).unwrap(),
        issuer(),
        algorithm.into(),
        KID.into(),
        "receipt-only-key".into(),
        key.jwk(),
    )
    .unwrap()
}
fn receipt_input(algorithm: &str) -> Vec<u8> {
    let now = Utc::now() - ClockDuration::seconds(1);
    let at = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let until = (now + ClockDuration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let digest = format!("sha256:{}", "1".repeat(64));
    let grant =
        json!({"id":"11111111-1111-4111-8111-111111111111","revision":2,"terms_digest":digest});
    let value = json!({"profile":delegated_decision::RECEIPT_PROFILE,"id":"22222222-2222-4222-8222-222222222222","issuer":issuer(),"decision":"PERMIT",
        "evaluation":{"profile":delegated_decision::EVALUATION_PROFILE,"organization_id":ORG,"grant":grant,"actor":{"type":"SERVICE_ACCOUNT","id":"urn:example:agent"},"subject":{"type":"ORGANIZATION","id":"urn:example:subject"},"binding":{"method":"KEY","key_thumbprint":digest},"operation":{"action":"urn:example:buy","resource_id":"urn:example:item","audience":"https://shop.example","request_profile":"urn:example:order:v1","request_digest":digest},"approval_evidence_ref":"urn:example:approval","authority_evidence_ref":"urn:example:authority","proof_evidence_ref":"urn:example:proof","challenge":"synthetic_nonce_0123456789","proof_verified_at":at,"proof_valid_until":until,"status":{"issuer":{"type":"ORGANIZATION","id":"urn:example:authority-owner"},"grant":grant,"state":"ACTIVE","checked_at":at,"valid_until":until,"evidence_ref":"urn:example:status"},"evaluated_at":at},
        "policy":{"id":"urn:example:policy","version_digest":digest},"issued_at":at,"expires_at":until});
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &json!({"typ":delegated_decision::WIRE_FORMAT,"alg":algorithm,"kid":KID})
            )
            .unwrap()
        ),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    )
    .into_bytes()
}

struct TestMinter {
    substitute_origin: bool,
    reuse_nonce: bool,
}
#[async_trait]
impl GrantMinting for TestMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        let mut grant = marty_signing_grant_test_support::AnyOriginGrantMinter
            .mint(binding)
            .await?;
        grant.claims.nonce = if self.reuse_nonce {
            "1".repeat(32)
        } else {
            Uuid::new_v4().simple().to_string()
        };
        if self.substitute_origin {
            grant.claims.origin = SigningOrigin::GatewayService;
        }
        Ok(grant)
    }
}
struct Mock {
    key: TestKey,
    algorithm: String,
    calls: Mutex<Vec<(String, HeaderMap, Value)>>,
    mode: AtomicU8,
    change: Mutex<Option<(String, Value)>>,
    consumed: Mutex<HashSet<String>>,
}
async fn resolve(
    State(state): State<Arc<Mock>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .calls
        .lock()
        .unwrap()
        .push(("resolve".into(), headers.clone(), body.clone()));
    if state.mode.load(Ordering::SeqCst) == 3 {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "http://127.0.0.1:1/never-follow")],
        )
            .into_response();
    }
    assert_eq!(headers["x-api-key"], "r".repeat(40));
    assert_eq!(
        body,
        json!({"organization_id":ORG,"issuer_did":ISSUER,"verification_method_id":KID,"key_purpose":delegated_decision::KEY_PURPOSE,"credential_format":delegated_decision::PROFILE_FORMAT,"algorithm":state.algorithm})
    );
    let mut public = state.key.jwk();
    public["kid"] = json!(KID);
    let mut value = json!({"ok":true,"organization_id":ORG,"issuer_did":ISSUER,"verification_method_id":KID,"signing_key_reference":"receipt-only-key","algorithm":state.algorithm,"key_purpose":delegated_decision::KEY_PURPOSE,"public_jwk":public,"issuer_profile":{"organization_id":ORG,"issuer_did":ISSUER,"status":"active","key_purpose":delegated_decision::KEY_PURPOSE,"credential_format":delegated_decision::PROFILE_FORMAT,"algorithm":state.algorithm,"signing_key_reference":"receipt-only-key","verification_method_id":KID},"resolver":{"public_fallback_used":false,"type":"organization_issuer_profile","source":"gateway_signing_key_registry"}});
    if state.mode.load(Ordering::SeqCst) == 1 {
        if let Some((path, replacement)) = &*state.change.lock().unwrap() {
            *value.pointer_mut(path).unwrap() = replacement.clone();
        }
    }
    Json(value).into_response()
}
async fn sign(
    State(state): State<Arc<Mock>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .calls
        .lock()
        .unwrap()
        .push(("sign".into(), headers.clone(), body.clone()));
    assert_eq!(headers["x-api-key"], "s".repeat(40));
    assert_eq!(body["expected_public_jwk"], state.key.jwk());
    assert_eq!(body["verification_method_id"], KID);
    let header = headers[HEADER_NAME].to_str().unwrap();
    let envelope = GrantEnvelope::from_header_value(header).unwrap();
    let payload = b64(body["payload_b64"].as_str().unwrap(), 100_000).unwrap();
    let binding = GrantBinding {
        origin: SigningOrigin::DelegatedDecision,
        operation_id: "22222222-2222-4222-8222-222222222222",
        organization_id: ORG,
        route: delegated_decision::SIGN_ROUTE,
        service_id: None,
        issuer_did: Some(ISSUER),
        key_reference: Some("receipt-only-key"),
        key_purpose: delegated_decision::KEY_PURPOSE,
        algorithm: &state.algorithm,
        payload: &payload,
    };
    assert!(
        marty_signing_grant::bound_input(&envelope.claims, &binding, Utc::now().timestamp())
            .is_ok()
    );
    if !state.consumed.lock().unwrap().insert(envelope.claims.nonce) {
        return StatusCode::CONFLICT.into_response();
    }
    if state.mode.load(Ordering::SeqCst) == 4 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let mut public = state.key.jwk();
    public["kid"] = json!(KID);
    let mut response = json!({"ok":true,"issuer_did":ISSUER,"verification_method_id":KID,"algorithm":state.algorithm,"public_jwk":public,"payload_length":payload.len()});
    if state.mode.load(Ordering::SeqCst) == 5 {
        TestKey::new(&state.algorithm, 9).sign(&payload, &mut response);
    } else {
        state.key.sign(&payload, &mut response);
    }
    if state.mode.load(Ordering::SeqCst) == 2 {
        if let Some((path, replacement)) = &*state.change.lock().unwrap() {
            *response.pointer_mut(path).unwrap() = replacement.clone();
        }
    }
    Json(response).into_response()
}
struct Harness {
    signer: HttpManagedDelegatedReceiptSigner,
    state: Arc<Mock>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Harness {
    async fn new(algorithm: &str, substitute_origin: bool, reuse_nonce: bool) -> Self {
        let key = TestKey::new(algorithm, 7);
        let state = Arc::new(Mock {
            key: key.clone(),
            algorithm: algorithm.into(),
            calls: Mutex::new(Vec::new()),
            mode: AtomicU8::new(0),
            change: Mutex::new(None),
            consumed: Mutex::new(HashSet::new()),
        });
        let router = Router::new()
            .route("/internal/compat/resolve-issuer-did", post(resolve))
            .route("/internal/compat/issuer-dids/sign", post(sign))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let signer = HttpManagedDelegatedReceiptSigner::build(
            &format!("http://{address}"),
            "r".repeat(40),
            "s".repeat(40),
            pin(algorithm, &key),
            Arc::new(TestMinter {
                substitute_origin,
                reuse_nonce,
            }),
            true,
        )
        .unwrap();
        Self {
            signer,
            state,
            task,
        }
    }
    async fn request(&self) -> DelegatedReceiptSigningRequest {
        let key = self
            .signer
            .resolve_key(
                Uuid::parse_str(ORG).unwrap(),
                &issuer(),
                DELEGATED_DECISION_JWS_PURPOSE,
            )
            .await
            .unwrap();
        DelegatedReceiptSigningRequest {
            organization_id: Uuid::parse_str(ORG).unwrap(),
            key,
            signing_input: receipt_input(&self.state.algorithm),
        }
    }
    fn count(&self, path: &str) -> usize {
        self.state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|x| x.0 == path)
            .count()
    }
}

#[tokio::test]
async fn both_algorithms_use_real_signatures_exact_pins_and_a_separate_bound_origin() {
    for algorithm in ["ES256", "EdDSA"] {
        let h = Harness::new(algorithm, false, false).await;
        let request = h.request().await;
        let input = request.signing_input.clone();
        let signature = h.signer.sign(request).await.unwrap();
        assert_eq!(signature.len(), 64);
        assert_eq!(h.count("resolve"), 2);
        assert_eq!(h.count("sign"), 1);
        match &h.state.key {
            TestKey::Es(key) => key
                .verifying_key()
                .verify(&input, &Signature::from_slice(&signature).unwrap())
                .unwrap(),
            TestKey::Ed(key) => key
                .verifying_key()
                .verify_strict(
                    &input,
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .unwrap(),
        };
    }
}

#[tokio::test]
async fn current_resolution_refuses_rotation_revocation_wrong_tenant_and_fallback() {
    for (path, value) in [
        (
            "/organization_id",
            json!("44444444-4444-4444-8444-444444444444"),
        ),
        ("/issuer_profile/status", json!("revoked")),
        (
            "/verification_method_id",
            json!("did:web:receipt.example#replacement"),
        ),
        ("/signing_key_reference", json!("other-key")),
        ("/public_jwk/x", TestKey::new("EdDSA", 9).jwk()["x"].clone()),
        ("/issuer_profile/key_purpose", json!("vc_jwt_issuer")),
        ("/resolver/public_fallback_used", json!(true)),
    ] {
        let h = Harness::new("EdDSA", false, false).await;
        let request = h.request().await;
        h.state.mode.store(1, Ordering::SeqCst);
        *h.state.change.lock().unwrap() = Some((path.into(), value));
        assert!(h.signer.sign(request).await.is_err());
        assert_eq!(h.count("sign"), 0);
    }
}

#[tokio::test]
async fn returned_signature_is_verified_not_trusted_by_shape_or_reported_public_key() {
    for algorithm in ["ES256", "EdDSA"] {
        let h = Harness::new(algorithm, false, false).await;
        let request = h.request().await;
        h.state.mode.store(5, Ordering::SeqCst);
        assert!(h.signer.sign(request).await.is_err());
        assert_eq!(h.count("sign"), 1);
    }
    for (path, value) in [
        ("/issuer_did", json!("did:web:other.example")),
        (
            "/verification_method_id",
            json!("did:web:receipt.example#other"),
        ),
        ("/algorithm", json!("ES256")),
        ("/payload_length", json!(1)),
        ("/signature_b64", json!(URL_SAFE_NO_PAD.encode([0; 64]))),
    ] {
        let h = Harness::new("EdDSA", false, false).await;
        let request = h.request().await;
        h.state.mode.store(2, Ordering::SeqCst);
        *h.state.change.lock().unwrap() = Some((path.into(), value));
        assert!(h.signer.sign(request).await.is_err());
        assert_eq!(h.count("sign"), 1);
    }
}

#[tokio::test]
async fn origin_substitution_replay_denial_and_uncertain_signing_never_retry() {
    let h = Harness::new("ES256", true, false).await;
    let request = h.request().await;
    assert!(h.signer.sign(request).await.is_err());
    assert_eq!(h.count("sign"), 0);
    let h = Harness::new("ES256", false, true).await;
    let request = h.request().await;
    assert!(h.signer.sign(request).await.is_ok());
    let request = h.request().await;
    assert!(h.signer.sign(request).await.is_err());
    assert_eq!(h.count("sign"), 2);
    let h = Harness::new("EdDSA", false, false).await;
    let request = h.request().await;
    h.state.mode.store(4, Ordering::SeqCst);
    assert!(h.signer.sign(request).await.is_err());
    assert_eq!(h.count("sign"), 1);
    let h = Harness::new("EdDSA", false, false).await;
    h.state.mode.store(3, Ordering::SeqCst);
    assert!(h
        .signer
        .resolve_key(
            Uuid::parse_str(ORG).unwrap(),
            &issuer(),
            DELEGATED_DECISION_JWS_PURPOSE
        )
        .await
        .is_err());
    assert_eq!(h.count("resolve"), 1);
    assert_eq!(h.count("sign"), 0);
}

#[tokio::test]
async fn malformed_or_retargeted_input_fails_before_remote_signing() {
    let h = Harness::new("EdDSA", false, false).await;
    for kind in 0..4 {
        let mut request = h.request().await;
        match kind {
            0 => request.key.purpose = "vc_jwt_issuer".into(),
            1 => request.organization_id = Uuid::new_v4(),
            2 => request.signing_input = b"arbitrary-payload".to_vec(),
            _ => request.key.key_id = "did:web:receipt.example#other".into(),
        };
        assert!(h.signer.sign(request).await.is_err());
    }
    assert_eq!(h.count("sign"), 0);
}

#[test]
fn configuration_rejects_plaintext_credential_reuse_and_private_or_weak_key_material() {
    let key = TestKey::new("EdDSA", 7);
    let pins = pin("EdDSA", &key);
    let minter = || {
        Arc::new(TestMinter {
            substitute_origin: false,
            reuse_nonce: false,
        }) as Arc<dyn GrantMinting>
    };
    for origin in [
        "http://signing.example",
        "https://user:pass@signing.example",
        "https://signing.example/prefix",
        "https://signing.example?secret=x",
    ] {
        assert!(HttpManagedDelegatedReceiptSigner::build(
            origin,
            "r".repeat(40),
            "s".repeat(40),
            pins.clone(),
            minter(),
            false
        )
        .is_err());
    }
    assert!(HttpManagedDelegatedReceiptSigner::build(
        "https://signing.example",
        "r".repeat(40),
        "r".repeat(40),
        pins,
        minter(),
        false
    )
    .is_err());
    let mut private = key.jwk();
    private["d"] = json!("rejected");
    assert!(ManagedDelegatedReceiptKey::new(
        Uuid::parse_str(ORG).unwrap(),
        issuer(),
        "EdDSA".into(),
        KID.into(),
        "key".into(),
        private
    )
    .is_err());
    let weak = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode([0;32])});
    assert!(ManagedDelegatedReceiptKey::new(
        Uuid::parse_str(ORG).unwrap(),
        issuer(),
        "EdDSA".into(),
        KID.into(),
        "key".into(),
        weak
    )
    .is_err());
    assert!(serde_json::from_slice::<UniqueValue>(br#"{"ok":true,"ok":false}"#).is_err());
}
