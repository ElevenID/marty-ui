//! Actual loopback HTTP, shared production adapters, frozen diagnostic data.
//! No crypto, deployed routing or database persistence is simulated here.
use super::*;
use crate::{
    credential::CredentialIssuanceError,
    credential_builder::{HttpDidSigner, SignRequest},
    credential_issuer::HttpIssuerContextResolver,
    signing_policy::HttpProofPolicyResolver,
    tenant_discovery::{ProofPolicyResolver, TenantDiscoveryError},
};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::HeaderMap,
    response::Response as ServerResponse,
    Router,
};
use marty_oid4vci::discovery::ProofPolicyRequest;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

#[derive(Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) content_type: String,
    bytes: Vec<u8>,
    encoding: Option<&'static str>,
}
impl Reply {
    pub(crate) fn json(status: u16, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            bytes: bytes.into(),
            encoding: None,
        }
    }
}
#[derive(Debug)]
struct RequestRecord {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}
struct PeerState {
    reply: Reply,
    requests: Vec<RequestRecord>,
}
pub(crate) struct Peer {
    pub(crate) base: reqwest::Url,
    state: Arc<Mutex<PeerState>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Peer {
    pub(crate) async fn new(reply: Reply) -> Self {
        async fn handle(
            State(state): State<Arc<Mutex<PeerState>>>,
            request: Request,
        ) -> ServerResponse {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 1_048_576).await.unwrap().to_vec();
            let mut state = state.lock().unwrap();
            state.requests.push(RequestRecord {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body,
            });
            let mut response = ServerResponse::builder()
                .status(state.reply.status)
                .header("content-type", &state.reply.content_type)
                // Following redirects would enter the same controlled peer and
                // be detected by request count/path, never the external network.
                .header("location", "/must-not-follow");
            if let Some(encoding) = state.reply.encoding {
                response = response.header("content-encoding", encoding);
            }
            response
                .body(Body::from(state.reply.bytes.clone()))
                .unwrap()
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(PeerState {
            reply,
            requests: vec![],
        }));
        let app = Router::new().fallback(handle).with_state(state.clone());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            base: format!("http://{address}/internal/").parse().unwrap(),
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub(crate) fn set(&self, reply: Reply) {
        self.state.lock().unwrap().reply = reply;
    }
    pub(crate) fn request_count(&self) -> usize {
        self.state.lock().unwrap().requests.len()
    }
    pub(crate) fn assert_last_resolution_request(&self) {
        let state = self.state.lock().unwrap();
        let request = state.requests.last().unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.uri.starts_with("/internal/resolve-issuer-did?"));
        assert!(request.uri.contains("organization_id=org-a"));
        assert!(request.body.is_empty());
    }
    fn take_requests(&self) -> Vec<RequestRecord> {
        std::mem::take(&mut self.state.lock().unwrap().requests)
    }
    pub(crate) async fn failure(body: &[u8]) -> (Self, SigningResponseFailure) {
        Self::failure_for(body, SigningOperation::Sign).await
    }
    pub(crate) async fn failure_for(
        body: &[u8],
        operation: SigningOperation,
    ) -> (Self, SigningResponseFailure) {
        let peer = Self::new(Reply::json(503, body)).await;
        let failure = peer.error(operation).await;
        (peer, failure)
    }
    async fn error(&self, operation: SigningOperation) -> SigningResponseFailure {
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(self.base.join("diagnostic").unwrap())
            .send()
            .await
            .unwrap();
        match classify(response, operation).await {
            Err(error) => error,
            Ok(_) => panic!("expected remote error"),
        }
    }
    pub(crate) async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        // Retain ownership on timeout/panic so Drop can abort the exact task.
        tokio::time::timeout(Duration::from_secs(5), self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.task.take();
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
fn operation(name: &str) -> SigningOperation {
    match name {
        "context" => SigningOperation::Context,
        "resolve" => SigningOperation::Resolve,
        "sign" => SigningOperation::Sign,
        _ => panic!("unknown frozen operation"),
    }
}

#[tokio::test]
async fn six_frozen_operations_cross_real_http_before_shared_classification() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-privacy-reference.json"
    ))
    .unwrap();
    let peer = Peer::new(Reply::json(503, b"{}".as_slice())).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut count = 0;
    for case in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] == "signing_operation_error")
    {
        let input = &case["input"];
        let observed = &case["observed"];
        peer.set(Reply::json(
            input["status"].as_u64().unwrap() as u16,
            input["body"].as_str().unwrap().as_bytes(),
        ));
        let path = observed["request_path"].as_str().unwrap();
        let response = client
            .request(
                observed["request_method"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                peer.base.join(path).unwrap(),
            )
            .send()
            .await
            .unwrap();
        let cause = match classify(response, operation(input["operation"].as_str().unwrap())).await
        {
            Err(cause) => cause,
            Ok(_) => panic!("frozen error"),
        };
        assert!(cause.is_runtime());
        assert_eq!(
            cause.scalar_detail().unwrap(),
            observed["message"].as_str().unwrap()
        );
        let requests = peer.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].method,
            observed["request_method"].as_str().unwrap()
        );
        assert_eq!(requests[0].uri, path);
        count += 1;
    }
    assert_eq!(count, 6);
    peer.close().await;
}

// The reference itself contains unpaired surrogate strings: read it with the
// existing lossless arena, not serde Value or a scalar conversion fallback.
fn field(tree: &JsonTree, id: usize, key: &str) -> Option<usize> {
    let JsonNode::Object(fields) = tree.node(id) else {
        panic!("reference object")
    };
    fields
        .iter()
        .find(|(name, _)| name.as_scalar() == Some(key))
        .map(|(_, id)| *id)
}
fn required(tree: &JsonTree, id: usize, key: &str) -> usize {
    field(tree, id, key).unwrap()
}
fn text(tree: &JsonTree, id: usize) -> PythonText {
    match tree.node(id) {
        JsonNode::Text(text) => text.clone(),
        JsonNode::Scalar(Value::String(text)) => PythonText::from(text.clone()),
        _ => panic!("reference text"),
    }
}
fn scalar(tree: &JsonTree, id: usize) -> String {
    text(tree, id).as_scalar().unwrap().into()
}
fn array(tree: &JsonTree, id: usize) -> &[usize] {
    let JsonNode::Array(values) = tree.node(id) else {
        panic!("reference array")
    };
    values
}
fn fixture() -> JsonTree {
    JsonTree::from_json_bytes(include_bytes!(
        "../../../../contracts/signing-response-python-reference.json"
    ))
    .unwrap()
}
fn fixture_reply(tree: &JsonTree, id: usize) -> Reply {
    let bytes = if let Some(depth) = field(tree, id, "nested_detail_depth") {
        let JsonNode::Scalar(Value::Number(depth)) = tree.node(depth) else {
            panic!("depth")
        };
        let depth = depth.as_u64().unwrap() as usize;
        format!(
            "{{\"detail\":{}0{}}}",
            "{\"a\":".repeat(depth),
            "}".repeat(depth)
        )
        .into_bytes()
    } else {
        let hex = scalar(tree, required(tree, id, "body_hex"));
        hex.as_bytes()
            .chunks_exact(2)
            .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
            .collect()
    };
    let JsonNode::Scalar(Value::Number(status)) = tree.node(required(tree, id, "status")) else {
        panic!("status")
    };
    Reply {
        status: status.as_u64().unwrap() as u16,
        content_type: scalar(tree, required(tree, id, "content_type")),
        bytes,
        encoding: None,
    }
}

#[tokio::test]
async fn fifteen_portable_frozen_lossless_diagnostics_cross_real_http() {
    let tree = fixture();
    let inputs = array(&tree, required(&tree, tree.root(), "inputs"));
    let peer = Peer::new(Reply::json(503, b"{}".as_slice())).await;
    let mut count = 0;
    for id in array(&tree, required(&tree, tree.root(), "details")) {
        let name = scalar(&tree, required(&tree, *id, "name"));
        // This capture records one interpreter's recursion behavior, not a
        // universal boundary. No depth10000 threshold is invented in Rust.
        if name == "json-depth-10000" {
            continue;
        }
        let input = inputs
            .iter()
            .find(|id| scalar(&tree, required(&tree, **id, "name")) == name)
            .unwrap();
        peer.set(fixture_reply(&tree, *input));
        let cause = peer.error(SigningOperation::Context).await;
        let observed = required(&tree, *id, "observed");
        if let Some(detail) = field(&tree, observed, "detail") {
            let expected = "DID issuer context resolution failed (HTTP 503): "
                .chars()
                .map(u32::from)
                .chain(text(&tree, detail).codepoints().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            assert_eq!(cause.class, SigningExceptionClass::Runtime, "{name}");
            assert_eq!(
                cause.diagnostic.codepoints().collect::<Vec<_>>(),
                expected,
                "{name}"
            );
        } else {
            assert_eq!(
                scalar(&tree, required(&tree, observed, "error_class")),
                "UnicodeError"
            );
            assert_eq!(cause.class, SigningExceptionClass::Unicode, "{name}");
            assert_eq!(
                cause.scalar_detail().unwrap(),
                scalar(&tree, required(&tree, observed, "message")),
                "{name}"
            );
        }
        assert_eq!(peer.take_requests().len(), 1, "{name}");
        count += 1;
    }
    assert_eq!(count, 15);
    peer.close().await;
}

fn sign_request() -> SignRequest {
    SignRequest {
        organization_id: "org-a".into(),
        issuer_did: "did:web:issuer.example".into(),
        credential_format: "jwt_vc_json".into(),
        key_purpose: "vc_jwt_issuer".into(),
        payload: b"controlled-public-payload".to_vec(),
        algorithm: "EdDSA".into(),
        verification_method_id: "did:web:issuer.example#key-1".into(),
    }
}
fn proof_request(did: bool) -> ProofPolicyRequest {
    ProofPolicyRequest {
        organization_id: "org-a".into(),
        issuer_did: did.then(|| "did:web:issuer.example".into()),
        credential_format: "jwt_vc_json".into(),
        key_purpose: "vc_jwt_issuer".into(),
    }
}
fn typed(error: CredentialIssuanceError) -> SigningResponseFailure {
    match error {
        CredentialIssuanceError::SigningResponse(cause) => cause,
        other => panic!("expected typed response: {other:?}"),
    }
}

#[tokio::test]
async fn three_production_owners_keep_operation_identity_requests_and_privacy() {
    let peer = Peer::new(Reply::json(
        503,
        br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
    ))
    .await;
    let resolver = HttpIssuerContextResolver::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let signer = HttpDidSigner::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let policy = HttpProofPolicyResolver::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    for status in [401, 503] {
        peer.set(Reply::json(
            status,
            br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
        ));
        for operation in [SigningOperation::Context, SigningOperation::Resolve] {
            let cause = typed(
                resolver
                    .resolve_raw_for(
                        operation,
                        "org-a",
                        "did:web:issuer.example",
                        None,
                        "jwt_vc_json",
                        "vc_jwt_issuer",
                        "EdDSA",
                    )
                    .await
                    .unwrap_err(),
            );
            assert_eq!(cause.operation, operation);
            assert_eq!(cause.class, SigningExceptionClass::Runtime);
            assert!(!format!("{cause} {cause:?}").contains("synthetic-private-diagnostic"));
            if status == 503 {
                assert!(cause
                    .scalar_detail()
                    .unwrap()
                    .ends_with("synthetic-private-diagnostic"));
            }
        }
        let cause = typed(signer.sign_did(sign_request()).await.unwrap_err());
        assert_eq!(cause.operation, SigningOperation::Sign);
        for did in [false, true] {
            assert_eq!(
                policy.resolve(&proof_request(did)).await.unwrap_err(),
                TenantDiscoveryError::ProofPolicyUnavailable
            );
        }
        let records = peer.take_requests();
        assert_eq!(records.len(), 5);
        for record in &records {
            assert_eq!(record.headers["x-api-key"], "synthetic-service-key");
            assert!(record.uri.contains("organization_id=org-a"));
            assert!(!record.uri.contains("must-not-follow"));
        }
        assert_eq!(records[0].method, "GET");
        assert!(records[0].uri.starts_with("/internal/resolve-issuer-did?"));
        assert_eq!(records[2].method, "POST");
        assert!(records[2].uri.starts_with("/internal/issuer-dids/sign?"));
        assert_eq!(
            serde_json::from_slice::<Value>(&records[2].body).unwrap(),
            json!({"issuer_did":"did:web:issuer.example", "credential_format":"jwt_vc_json", "key_purpose":"vc_jwt_issuer", "payload_b64":"Y29udHJvbGxlZC1wdWJsaWMtcGF5bG9hZA", "algorithm":"EdDSA"})
        );
        assert!(records[3].uri.starts_with("/internal/issuer-context?"));
        assert!(records[4].uri.starts_with("/internal/resolve-issuer-did?"));
    }
    peer.close().await;
}

#[tokio::test]
async fn redirects_continue_existing_success_validators_and_404_defaults() {
    let peer = Peer::new(Reply::json(302, b"{}".as_slice())).await;
    let resolver = HttpIssuerContextResolver::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let signer = HttpDidSigner::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let policy = HttpProofPolicyResolver::new(
        peer.base.clone(),
        Some("synthetic-service-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let valid = json!({"ok":true,"issuer_did":"did:web:issuer.example", "algorithm":"EdDSA", "verification_method_id":"did:web:issuer.example#key-1", "signature_raw_b64":"synthetic-signature", "issuer_profile":{"id":"profile-a", "key_attestation_policy":{"mode":"required", "required_key_storage":["hardware"]}}});
    for status in [301, 302, 303, 307, 308, 399] {
        peer.set(Reply::json(status, serde_json::to_vec(&valid).unwrap()));
        assert_eq!(
            signer.sign_did(sign_request()).await.unwrap().signature_b64,
            "synthetic-signature"
        );
        assert_eq!(
            resolver
                .resolve_raw(
                    "org-a",
                    "did:web:issuer.example",
                    None,
                    "jwt_vc_json",
                    "vc_jwt_issuer",
                    "EdDSA"
                )
                .await
                .unwrap(),
            valid
        );
        assert_eq!(
            policy
                .resolve(&proof_request(true))
                .await
                .unwrap()
                .key_storage,
            vec!["hardware"]
        );
        let records = peer.take_requests();
        assert_eq!(records.len(), 3);
        assert!(records
            .iter()
            .all(|record| !record.uri.contains("must-not-follow")));
    }
    for (field, replacement) in [
        ("ok", json!(false)),
        ("issuer_did", json!("other")),
        ("algorithm", json!("RS256")),
        ("verification_method_id", json!("other")),
        ("signature_raw_b64", json!("")),
        ("issuer_profile_id", Value::Null),
        ("service_id", Value::Null),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = replacement;
        peer.set(Reply::json(302, serde_json::to_vec(&invalid).unwrap()));
        assert!(
            matches!(
                signer.sign_did(sign_request()).await,
                Err(CredentialIssuanceError::SigningUnavailable(_))
            ),
            "{field}"
        );
        assert_eq!(peer.take_requests().len(), 1);
    }
    for status in [302, 304] {
        peer.set(Reply::json(status, b"not-json".as_slice()));
        assert_eq!(
            typed(signer.sign_did(sign_request()).await.unwrap_err()).class,
            SigningExceptionClass::Json
        );
        assert_eq!(
            policy.resolve(&proof_request(true)).await.unwrap_err(),
            TenantDiscoveryError::ProofPolicyResponseInvalid
        );
        assert_eq!(peer.take_requests().len(), 2);
    }
    peer.set(Reply::json(404, br#"{"detail":"not-found"}"#.as_slice()));
    assert_eq!(
        policy.resolve(&proof_request(true)).await.unwrap(),
        Default::default()
    );
    assert!(matches!(
        resolver
            .resolve_raw(
                "org-a",
                "did:web:issuer.example",
                None,
                "jwt_vc_json",
                "vc_jwt_issuer",
                "EdDSA"
            )
            .await,
        Err(CredentialIssuanceError::IssuerUnavailable(_))
    ));
    assert_eq!(
        typed(signer.sign_did(sign_request()).await.unwrap_err()).class,
        SigningExceptionClass::Runtime
    );
    assert_eq!(peer.take_requests().len(), 3);
    peer.close().await;
}

#[test]
fn each_existing_text_error_retains_its_python_exception_category() {
    use CanvasResponseTextError::*;
    for (error, class, name) in [
        (
            InternalCodec,
            SigningExceptionClass::Runtime,
            "RuntimeError",
        ),
        (
            Utf16MissingBom,
            SigningExceptionClass::Unicode,
            "UnicodeError",
        ),
        (
            Utf32MissingBom,
            SigningExceptionClass::Unicode,
            "UnicodeError",
        ),
        (
            PendingBufferOverflow,
            SigningExceptionClass::Unicode,
            "UnicodeError",
        ),
        (
            ContinuationOrdinalLimit { digits: 4301 },
            SigningExceptionClass::Value,
            "ValueError",
        ),
        (
            EmbeddedNullEncoding,
            SigningExceptionClass::Value,
            "ValueError",
        ),
        (
            NumberedAfterBareContinuation,
            SigningExceptionClass::Type,
            "TypeError",
        ),
        (
            BareAfterNumberedContinuation,
            SigningExceptionClass::Type,
            "TypeError",
        ),
    ] {
        assert_eq!(error.diagnostic_class(), name);
        assert_eq!(
            SigningResponseFailure::text(SigningOperation::Context, error).class,
            class
        );
    }
}

#[tokio::test]
async fn explicit_repository_reason_preserves_scalar_prefix_and_text_boundary() {
    for operation in [
        SigningOperation::Context,
        SigningOperation::Resolve,
        SigningOperation::Sign,
    ] {
        for body in [
            br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
            br#"{"detail":"\ud800"}"#.as_slice(),
            br#"{"detail":"\u0000"}"#.as_slice(),
        ] {
            let (peer, cause) = Peer::failure_for(body, operation).await;
            let before = cause.diagnostic.clone();
            let error = CredentialIssuanceError::SigningResponse(cause.clone());
            let persisted = error.repository_failure_reason();
            if body.contains(&b'\\') {
                assert_eq!(
                    persisted,
                    "Remote signing response diagnostic is not representable as database text"
                );
            } else {
                assert_eq!(
                    persisted,
                    if operation == SigningOperation::Sign {
                        CredentialIssuanceError::SigningUnavailable(
                            cause.scalar_detail().unwrap().into(),
                        )
                    } else {
                        CredentialIssuanceError::IssuerUnavailable(
                            cause.scalar_detail().unwrap().into(),
                        )
                    }
                    .to_string()
                );
            }
            assert!(!persisted.contains('\0'));
            assert_eq!(cause.diagnostic, before);
            assert!(!format!("{error} {error:?}").contains("synthetic-private-diagnostic"));
            assert_eq!(peer.take_requests().len(), 1);
            peer.close().await;
        }
    }
}

#[tokio::test]
async fn compressed_response_uses_existing_content_decoder_before_json_and_text() {
    use std::io::Write;
    let bytes = br#"{"detail":{"nested":"synthetic diagnostic"}}"#;
    let peer = Peer::new(Reply::json(503, bytes.as_slice())).await;
    let baseline = peer.error(SigningOperation::Sign).await;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(bytes).unwrap();
    let mut deflate = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    deflate.write_all(bytes).unwrap();
    for (encoding, bytes) in [
        ("gzip", gzip.finish().unwrap()),
        ("deflate", deflate.finish().unwrap()),
    ] {
        peer.set(Reply {
            encoding: Some(encoding),
            ..Reply::json(503, bytes)
        });
        assert_eq!(peer.error(SigningOperation::Sign).await, baseline);
    }
    peer.set(Reply {
        encoding: Some("gzip"),
        ..Reply::json(503, b"invalid gzip".as_slice())
    });
    assert_eq!(
        peer.error(SigningOperation::Sign).await.class,
        SigningExceptionClass::ResponseRead
    );
    assert_eq!(peer.request_count(), 4);
    peer.close().await;
}
