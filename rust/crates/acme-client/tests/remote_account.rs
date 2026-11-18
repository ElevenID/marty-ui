//! In-memory ACME transport fixtures. No CA traffic or real account creation.
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::BodyExt;
use instant_acme::{
    Account, BodyWrapper, BytesResponse, CertificateIdentifier, Error, ExternalAccountKey,
    ExternalAccountSigner, HttpClient, Identifier, NewAccount, NewOrder,
};
use ring::{
    digest, hmac,
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING,
    },
};
use serde_json::{json, Value};

const DIRECTORY: &str = "https://ca.example/directory";
const ACCOUNT: &str = "https://ca.example/account/7";
const ORDER: &str = "https://ca.example/order/13";
const TERMS: &str = "https://ca.example/terms/v1";

struct RemoteFixture {
    key: EcdsaKeyPair,
    calls: AtomicUsize,
    corrupt: bool,
}

impl RemoteFixture {
    fn new(corrupt: bool) -> Arc<Self> {
        let rng = SystemRandom::new();
        let fixture = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Arc::new(Self {
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, fixture.as_ref(), &rng)
                .unwrap(),
            calls: AtomicUsize::new(0),
            corrupt,
        })
    }
}

#[async_trait]
impl ExternalAccountSigner for RemoteFixture {
    fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }
    async fn sign(&self, input: &[u8]) -> Result<[u8; 64], Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Prove the library awaits the callback on a current-thread runtime.
        tokio::task::yield_now().await;
        let signature = self
            .key
            .sign(&SystemRandom::new(), input)
            .map_err(|_| Error::Crypto)?;
        let mut output: [u8; 64] = signature.as_ref().try_into().unwrap();
        if self.corrupt {
            output[0] ^= 1;
        }
        Ok(output)
    }
}

struct Step {
    method: Method,
    url: &'static str,
    payload: Option<Value>,
    response: Vec<u8>,
    status: u16,
    location: Option<&'static str>,
    nonce: &'static str,
    retry_after: Option<&'static str>,
}

fn step(method: Method, url: &'static str, payload: Option<Value>, response: Value) -> Step {
    Step {
        method,
        url,
        payload,
        response: serde_json::to_vec(&response).unwrap(),
        status: 200,
        location: None,
        nonce: "next-nonce",
        retry_after: None,
    }
}

fn directory() -> Step {
    step(
        Method::GET,
        DIRECTORY,
        None,
        json!({
            "newNonce":"https://ca.example/nonce", "newAccount":"https://ca.example/account",
            "newOrder":"https://ca.example/order", "keyChange":"https://ca.example/key-change",
            "renewalInfo":"https://ca.example/renewal", "meta":{
                "termsOfService":TERMS,"profiles":{"shortlived":"profile docs"}
            }
        }),
    )
}

fn nonce() -> Step {
    step(Method::HEAD, "https://ca.example/nonce", None, Value::Null)
}

fn registration() -> Step {
    let mut value = step(
        Method::POST,
        "https://ca.example/account",
        Some(json!({
            "contact":[], "termsOfServiceAgreed":true
        })),
        json!({"status":"valid"}),
    );
    value.status = 201;
    value.location = Some(ACCOUNT);
    value
}

fn order_state(status: &str) -> Value {
    json!({"status":status,"authorizations":[],"finalize":"https://ca.example/finalize/13",
        "expires":"2026-11-01T08:00:00Z",
        "identifiers":[{"type":"dns","value":"marty.example"},{"type":"ip","value":"203.0.113.7"}],
        "certificate": if status == "valid" { Some("https://ca.example/certificate/13") } else { None },
        "profile":"shortlived", "replaces":"AQ.Ag"})
}

struct FixtureState {
    steps: VecDeque<Step>,
    posts: Vec<(Value, Option<Value>)>,
    public_key: Option<Vec<u8>>,
}

#[derive(Clone)]
struct MockHttp(Arc<Mutex<FixtureState>>);

impl MockHttp {
    fn new(steps: Vec<Step>, public_key: Option<&[u8]>) -> Self {
        Self(Arc::new(Mutex::new(FixtureState {
            steps: steps.into(),
            posts: vec![],
            public_key: public_key.map(Vec::from),
        })))
    }
    fn done(&self) {
        assert!(self.0.lock().unwrap().steps.is_empty());
    }
}

impl HttpClient for MockHttp {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let state = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            let mut state = state.lock().unwrap();
            let next = state.steps.pop_front().expect("unexpected ACME operation");
            assert_eq!(parts.method, next.method);
            assert_eq!(parts.uri.to_string(), next.url);
            if parts.method == Method::POST {
                let jws: Value = serde_json::from_slice(&body).unwrap();
                let protected = jws["protected"].as_str().unwrap();
                let encoded = jws["payload"].as_str().unwrap();
                let header: Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
                let payload = (!encoded.is_empty()).then(|| {
                    serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(encoded).unwrap())
                        .unwrap()
                });
                assert_eq!(payload, next.payload);
                assert_eq!(header["alg"], "ES256");
                assert_eq!(header["url"], next.url);
                assert!(header["nonce"].as_str().is_some_and(|v| !v.is_empty()));
                let key = if let Some(jwk) = header.get("jwk") {
                    assert_eq!(jwk["crv"], "P-256");
                    assert_eq!(jwk["kty"], "EC");
                    let mut key = vec![4];
                    key.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
                    key.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
                    if let Some(expected) = &state.public_key {
                        assert_eq!(&key, expected);
                    }
                    state.public_key = Some(key.clone());
                    key
                } else {
                    assert_eq!(header["kid"], ACCOUNT);
                    state.public_key.clone().unwrap()
                };
                let signature = URL_SAFE_NO_PAD
                    .decode(jws["signature"].as_str().unwrap())
                    .unwrap();
                assert_eq!(signature.len(), 64);
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
                    .verify(format!("{protected}.{encoded}").as_bytes(), &signature)
                    .unwrap();
                state.posts.push((header, payload));
            } else {
                assert!(body.is_empty());
            }
            let mut response = Response::builder()
                .status(next.status)
                .header("Replay-Nonce", next.nonce);
            if let Some(location) = next.location {
                response = response.header("Location", location);
            }
            if let Some(retry) = next.retry_after {
                response = response.header("Retry-After", retry);
            }
            Ok(BytesResponse::from(
                response.body(BodyWrapper::from(next.response)).unwrap(),
            ))
        })
    }
}

fn new_account() -> NewAccount<'static> {
    NewAccount {
        contact: &[],
        terms_of_service_agreed: true,
        only_return_existing: false,
    }
}

#[tokio::test]
async fn external_account_uses_remote_jwk_and_cannot_roll_into_exported_local_key() {
    let signer = RemoteFixture::new(false);
    let http = MockHttp::new(
        vec![directory(), nonce(), registration()],
        Some(signer.public_key()),
    );
    let mut account = Account::builder_with_http(Box::new(http.clone()))
        .create_with_signer(&new_account(), signer.clone(), DIRECTORY.into(), None)
        .await
        .unwrap();
    assert_eq!(account.id(), ACCOUNT);
    let jwk = json!({"crv":"P-256","kty":"EC",
        "x":URL_SAFE_NO_PAD.encode(&signer.public_key()[1..33]),
        "y":URL_SAFE_NO_PAD.encode(&signer.public_key()[33..])});
    let expected = URL_SAFE_NO_PAD.encode(digest::digest(
        &digest::SHA256,
        &serde_json::to_vec(&jwk).unwrap(),
    ));
    assert_eq!(account.key_thumbprint(), expected);
    assert!(matches!(
        account.update_key().await,
        Err(Error::Unsupported(_))
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    http.done();
}

#[tokio::test]
async fn prepared_external_account_performs_only_directory_get_before_explicit_registration() {
    let signer = RemoteFixture::new(false);
    let http = MockHttp::new(
        vec![directory(), nonce(), registration()],
        Some(signer.public_key()),
    );
    let prepared = Account::builder_with_http(Box::new(http.clone()))
        .prepare_with_signer(signer.clone(), DIRECTORY.into())
        .await
        .unwrap();
    assert_eq!(prepared.terms_of_service_url(), Some(TERMS));
    prepared
        .require_terms_and_profile(TERMS, "shortlived")
        .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert!(http.0.lock().unwrap().posts.is_empty());
    assert_eq!(http.0.lock().unwrap().steps.len(), 2);
    let account = prepared
        .register(&new_account(), None, TERMS, "shortlived")
        .await
        .unwrap();
    assert_eq!(account.id(), ACCOUNT);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    http.done();
}

#[tokio::test]
async fn prepared_terms_profile_and_explicit_agreement_mismatches_make_no_registration_post() {
    for (terms, profile, agreed) in [
        ("https://ca.example/terms/old", "shortlived", true),
        (TERMS, "unsupported", true),
        (TERMS, "shortlived", false),
    ] {
        let signer = RemoteFixture::new(false);
        let http = MockHttp::new(vec![directory()], Some(signer.public_key()));
        let prepared = Account::builder_with_http(Box::new(http.clone()))
            .prepare_with_signer(signer.clone(), DIRECTORY.into())
            .await
            .unwrap();
        let mut request = new_account();
        request.terms_of_service_agreed = agreed;
        assert!(prepared
            .register(&request, None, terms, profile)
            .await
            .is_err());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        assert!(http.0.lock().unwrap().posts.is_empty());
        http.done();
    }
}

#[tokio::test]
async fn interrupted_registration_lookup_keeps_same_key_and_rejects_changed_terms() {
    let signer = RemoteFixture::new(false);
    let mut request = new_account();
    request.only_return_existing = true;
    let mut changed_directory = directory();
    let mut changed: Value = serde_json::from_slice(&changed_directory.response).unwrap();
    changed["meta"]["termsOfService"] = json!("https://ca.example/terms/v2");
    changed_directory.response = serde_json::to_vec(&changed).unwrap();
    let changed_http = MockHttp::new(vec![changed_directory], Some(signer.public_key()));
    let prepared = Account::builder_with_http(Box::new(changed_http.clone()))
        .prepare_with_signer(signer.clone(), DIRECTORY.into())
        .await
        .unwrap();
    assert!(prepared
        .register(&request, None, TERMS, "shortlived")
        .await
        .is_err());
    changed_http.done();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);

    let mut lookup = registration();
    lookup.status = 200;
    lookup.payload = Some(json!({
        "contact":[],"termsOfServiceAgreed":true,"onlyReturnExisting":true
    }));
    let http = MockHttp::new(
        vec![directory(), nonce(), lookup],
        Some(signer.public_key()),
    );
    let prepared = Account::builder_with_http(Box::new(http.clone()))
        .prepare_with_signer(signer.clone(), DIRECTORY.into())
        .await
        .unwrap();
    let account = prepared
        .register(&request, None, TERMS, "shortlived")
        .await
        .unwrap();
    assert_eq!(account.id(), ACCOUNT);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    http.done();
}

#[tokio::test]
async fn ip_profile_and_ari_use_existing_client_protocol_with_remote_signing() {
    let signer = RemoteFixture::new(false);
    let identifiers = [
        Identifier::Dns("marty.example".into()),
        Identifier::Ip("203.0.113.7".parse().unwrap()),
    ];
    let certificate_id: CertificateIdentifier<'static> = serde_json::from_str("\"AQ.Ag\"").unwrap();
    let mut create = step(
        Method::POST,
        "https://ca.example/order",
        Some(json!({
            "identifiers":[{"type":"dns","value":"marty.example"},{"type":"ip","value":"203.0.113.7"}],
            "profile":"shortlived","replaces":"AQ.Ag"
        })),
        order_state("ready"),
    );
    create.status = 201;
    create.location = Some(ORDER);
    let mut renewal = step(
        Method::GET,
        "https://ca.example/renewal/AQ.Ag",
        None,
        json!({
            "suggestedWindow":{"start":"2026-11-01T00:00:00Z","end":"2026-11-02T00:00:00Z"}
        }),
    );
    renewal.retry_after = Some("3600");
    let http = MockHttp::new(
        vec![directory(), nonce(), create, renewal],
        Some(signer.public_key()),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer.clone(), DIRECTORY.into())
        .await
        .unwrap();
    assert!(account
        .profiles()
        .any(|profile| profile.name == "shortlived"));
    let order = account
        .new_order(
            &NewOrder::new(&identifiers)
                .profile("shortlived")
                .replaces(certificate_id.clone()),
        )
        .await
        .unwrap();
    assert_eq!(order.url(), ORDER);
    let (_, retry) = account.renewal_info(&certificate_id).await.unwrap();
    assert!(retry.as_secs() >= 3590 && retry.as_secs() <= 3600);
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        1,
        "ARI GET is not a signing operation"
    );
    http.done();
}

#[tokio::test]
async fn restored_account_fetches_saved_order_and_finalizes_exact_external_csr() {
    let signer = RemoteFixture::new(false);
    // Protocol fixture only; semantic CSR/SAN validation belongs to the owner.
    let external_csr = b"exact externally signed CSR fixture";
    let get = step(Method::POST, ORDER, None, order_state("ready"));
    let finalize = step(
        Method::POST,
        "https://ca.example/finalize/13",
        Some(json!({"csr": URL_SAFE_NO_PAD.encode(external_csr)})),
        order_state("valid"),
    );
    let mut certificate = step(
        Method::POST,
        "https://ca.example/certificate/13",
        None,
        Value::Null,
    );
    certificate.response = b"public certificate fixture".to_vec();
    let http = MockHttp::new(
        vec![directory(), nonce(), get, finalize, certificate],
        Some(signer.public_key()),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer.clone(), DIRECTORY.into())
        .await
        .unwrap();
    let mut order = account.order(ORDER.into()).await.unwrap();
    order.finalize_csr(external_csr).await.unwrap();
    assert_eq!(
        order.certificate().await.unwrap().as_deref(),
        Some("public certificate fixture")
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 3);
    http.done();
}

#[tokio::test]
async fn order_response_metadata_survives_create_restore_finalize_and_refresh() {
    use std::time::{Duration, SystemTime};
    let signer = RemoteFixture::new(false);
    let identifiers = [
        Identifier::Dns("marty.example".into()),
        Identifier::Ip("203.0.113.7".parse().unwrap()),
    ];
    let mut create = step(
        Method::POST,
        "https://ca.example/order",
        Some(json!({"identifiers":identifiers})),
        order_state("ready"),
    );
    create.location = Some(ORDER);
    create.status = 201;
    create.retry_after = Some("120");
    let mut restored = step(Method::POST, ORDER, None, order_state("ready"));
    restored.retry_after = Some("Fri, 31 Dec 1999 23:59:59 GMT");
    let mut finalize = step(
        Method::POST,
        "https://ca.example/finalize/13",
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(b"exact retained CSR")})),
        order_state("processing"),
    );
    finalize.retry_after = Some("240");
    let mut refreshed = step(Method::POST, ORDER, None, order_state("valid"));
    refreshed.retry_after = Some("360");
    let http = MockHttp::new(
        vec![
            directory(),
            nonce(),
            create,
            nonce(),
            restored,
            finalize,
            refreshed,
        ],
        Some(signer.public_key()),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer, DIRECTORY.into())
        .await
        .unwrap();
    let before = SystemTime::now();
    let mut created = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .unwrap();
    assert_eq!(
        created.state().expires.as_deref(),
        Some("2026-11-01T08:00:00Z")
    );
    assert_eq!(
        created.state().identifiers.as_deref(),
        Some(identifiers.as_slice())
    );
    let hints = created.state().response_metadata.unwrap();
    assert_eq!(hints.status, 201);
    assert!(hints.retry_after.unwrap() >= before + Duration::from_secs(120));
    let mut order = account.order(created.url().into()).await.unwrap();
    assert_eq!(
        order.state().response_metadata.unwrap().retry_after,
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_799))
    );
    order.finalize_csr(b"exact retained CSR").await.unwrap();
    assert!(
        order
            .state()
            .response_metadata
            .unwrap()
            .retry_after
            .unwrap()
            >= before + Duration::from_secs(240)
    );
    order.refresh().await.unwrap();
    assert!(
        order
            .state()
            .response_metadata
            .unwrap()
            .retry_after
            .unwrap()
            >= before + Duration::from_secs(360)
    );
    http.done();
}

#[tokio::test]
async fn authorization_expiry_and_challenge_response_hints_are_available_without_extra_requests() {
    use instant_acme::{AuthorizationStatus, ChallengeType};
    use std::time::{Duration, SystemTime};
    const AUTH: &str = "https://ca.example/auth/3";
    const CHALLENGE: &str = "https://ca.example/challenge/3";
    let signer = RemoteFixture::new(false);
    let mut state = order_state("pending");
    state["authorizations"] = json!([AUTH]);
    let authorization = json!({
        "status":"pending", "identifier":{"type":"dns","value":"marty.example"},
        "expires":"2026-11-01T01:00:00Z", "challenges":[{
            "type":"http-01","url":CHALLENGE,"token":"fixture-token","status":"pending"
        }]
    });
    let mut auth = step(Method::POST, AUTH, None, authorization.clone());
    auth.retry_after = Some("60");
    let mut ready = step(
        Method::POST,
        CHALLENGE,
        Some(json!({})),
        authorization["challenges"][0].clone(),
    );
    ready.retry_after = Some("90");
    let mut validated = authorization;
    validated["status"] = json!("valid");
    let refreshed = step(Method::POST, AUTH, None, validated);
    let http = MockHttp::new(
        vec![
            directory(),
            nonce(),
            step(Method::POST, ORDER, None, state),
            auth,
            ready,
            refreshed,
        ],
        Some(signer.public_key()),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer, DIRECTORY.into())
        .await
        .unwrap();
    let before = SystemTime::now();
    let mut order = account.order(ORDER.into()).await.unwrap();
    {
        let mut authorizations = order.authorizations();
        let mut authorization = authorizations.next().await.unwrap().unwrap();
        assert_eq!(
            authorization.expires.as_deref(),
            Some("2026-11-01T01:00:00Z")
        );
        assert!(
            authorization
                .response_metadata
                .unwrap()
                .retry_after
                .unwrap()
                >= before + Duration::from_secs(60)
        );
        let response = authorization
            .challenge(ChallengeType::Http01)
            .unwrap()
            .set_ready_with_response()
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.retry_after.unwrap() >= before + Duration::from_secs(90));
    }
    let mut authorizations = order.authorizations();
    let mut authorization = authorizations.next().await.unwrap().unwrap();
    authorization.refresh().await.unwrap();
    assert_eq!(authorization.status, AuthorizationStatus::Valid);
    assert_eq!(authorization.response_metadata.unwrap().retry_after, None);
    http.done();
}

#[tokio::test]
async fn api_problem_retains_actual_http_status_and_retry_after_without_json_spoofing() {
    use std::time::{Duration, SystemTime};
    let signer = RemoteFixture::new(false);
    let mut limited = step(
        Method::POST,
        ORDER,
        None,
        json!({
            "type":"urn:ietf:params:acme:error:rateLimited", "status":503,
            "responseMetadata":{"status":200,"retryAfter":0}
        }),
    );
    limited.status = 429;
    limited.retry_after = Some("600");
    let http = MockHttp::new(
        vec![directory(), nonce(), limited],
        Some(signer.public_key()),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer, DIRECTORY.into())
        .await
        .unwrap();
    let before = SystemTime::now();
    let Err(Error::Api(problem)) = account.order(ORDER.into()).await else {
        panic!("expected API problem")
    };
    assert_eq!(problem.status, Some(503));
    let observed = problem.response_metadata.unwrap();
    assert_eq!(observed.status, 429);
    assert!(observed.retry_after.unwrap() >= before + Duration::from_secs(600));
    http.done();
}

#[tokio::test]
async fn absent_expiry_identifiers_and_invalid_retry_after_remain_explicitly_absent() {
    let signer = RemoteFixture::new(false);
    let mut state = order_state("ready");
    state.as_object_mut().unwrap().remove("expires");
    state.as_object_mut().unwrap().remove("identifiers");
    state["responseMetadata"] = json!({"status":201,"retryAfter":0});
    let mut steps = vec![directory(), nonce()];
    for retry in ["not-a-date", "18446744073709551615", ""] {
        let mut response = step(Method::POST, ORDER, None, state.clone());
        response.retry_after = Some(retry);
        steps.push(response);
    }
    let http = MockHttp::new(steps, Some(signer.public_key()));
    let account = Account::builder_with_http(Box::new(http.clone()))
        .from_signer(ACCOUNT.into(), signer, DIRECTORY.into())
        .await
        .unwrap();
    let mut order = account.order(ORDER.into()).await.unwrap();
    for index in 0..3 {
        if index > 0 {
            order.refresh().await.unwrap();
        }
        assert!(order.state().expires.is_none());
        assert!(order.state().identifiers.is_none());
        let observed = order.state().response_metadata.unwrap();
        assert_eq!(observed.status, 200);
        assert_eq!(observed.retry_after, None);
    }
    http.done();
}

#[tokio::test]
async fn bad_nonce_retry_gets_a_new_remote_signature() {
    let signer = RemoteFixture::new(false);
    let mut refused = registration();
    refused.status = 400;
    refused.location = None;
    refused.nonce = "replacement-nonce";
    refused.response =
        serde_json::to_vec(&json!({"type":"urn:ietf:params:acme:error:badNonce"})).unwrap();
    let http = MockHttp::new(
        vec![directory(), nonce(), refused, registration()],
        Some(signer.public_key()),
    );
    Account::builder_with_http(Box::new(http.clone()))
        .create_with_signer(&new_account(), signer.clone(), DIRECTORY.into(), None)
        .await
        .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    let state = http.0.lock().unwrap();
    assert_eq!(state.posts[1].0["nonce"], "replacement-nonce");
    assert_ne!(state.posts[0].0["nonce"], state.posts[1].0["nonce"]);
    drop(state);
    http.done();
}

#[tokio::test]
async fn invalid_external_signature_is_rejected_before_any_ca_post() {
    let signer = RemoteFixture::new(true);
    let http = MockHttp::new(vec![directory(), nonce()], Some(signer.public_key()));
    let result = Account::builder_with_http(Box::new(http.clone()))
        .create_with_signer(&new_account(), signer, DIRECTORY.into(), None)
        .await;
    assert!(matches!(result, Err(Error::Crypto)));
    assert!(http.0.lock().unwrap().posts.is_empty());
    http.done();
}

#[tokio::test]
async fn local_account_and_eab_keep_their_original_semantics() {
    let eab_key = [7u8; 32];
    // EAB is nested in registration. Its JWK is only known after local generation,
    // so this transport verifies the nested HMAC then delegates the outer checks.
    struct EabHttp {
        inner: MockHttp,
        key: [u8; 32],
    }
    impl HttpClient for EabHttp {
        fn request(
            &self,
            req: Request<BodyWrapper<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
            let inner = self.inner.clone();
            let key = self.key;
            Box::pin(async move {
                let (parts, body) = req.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                if parts.method == Method::POST {
                    let outer: Value = serde_json::from_slice(&bytes).unwrap();
                    let payload: Value = serde_json::from_slice(
                        &URL_SAFE_NO_PAD
                            .decode(outer["payload"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    let eab = &payload["externalAccountBinding"];
                    let header: Value = serde_json::from_slice(
                        &URL_SAFE_NO_PAD
                            .decode(eab["protected"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        header,
                        json!({"alg":"HS256","kid":"external-test","url":"https://ca.example/account"})
                    );
                    let signed = format!(
                        "{}.{}",
                        eab["protected"].as_str().unwrap(),
                        eab["payload"].as_str().unwrap()
                    );
                    hmac::verify(
                        &hmac::Key::new(hmac::HMAC_SHA256, &key),
                        signed.as_bytes(),
                        &URL_SAFE_NO_PAD
                            .decode(eab["signature"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    let outer_header: Value = serde_json::from_slice(
                        &URL_SAFE_NO_PAD
                            .decode(outer["protected"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    let inner_jwk: Value = serde_json::from_slice(
                        &URL_SAFE_NO_PAD
                            .decode(eab["payload"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(inner_jwk, outer_header["jwk"]);
                    inner.0.lock().unwrap().steps.front_mut().unwrap().payload = Some(payload);
                }
                inner
                    .request(Request::from_parts(
                        parts,
                        BodyWrapper::from(bytes.to_vec()),
                    ))
                    .await
            })
        }
    }
    let http = MockHttp::new(vec![directory(), nonce(), registration()], None);
    let (account, credentials) = Account::builder_with_http(Box::new(EabHttp {
        inner: http.clone(),
        key: eab_key,
    }))
    .create(
        &new_account(),
        DIRECTORY.into(),
        Some(&ExternalAccountKey::new("external-test".into(), &eab_key)),
    )
    .await
    .unwrap();
    assert_eq!(account.id(), ACCOUNT);
    assert!(!credentials.private_key().secret_pkcs8_der().is_empty());
    http.done();
}

/// Official binary protocol proof only. This does not qualify the shipped image,
/// restart recovery, certificate issuance by a public CA, or public reachability.
#[tokio::test]
#[ignore = "requires the verified official OpenBao 2.5.5 executable and local TCP permission"]
async fn official_openbao_255_signs_nonexportable_account_and_pins_key_version() {
    use base64::engine::general_purpose::STANDARD;
    use marty_acme_client::{OpenBaoAccountSigner, WorkloadCredentials};
    use marty_openbao_http::OpenBaoHttp;
    use reqwest::header::HeaderValue;
    use ring::rand::SecureRandom;
    use std::{
        io::Write,
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    struct Server {
        child: Child,
        files: tempfile::TempDir,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    struct FreshToken(Mutex<HeaderValue>);
    #[async_trait]
    impl WorkloadCredentials for FreshToken {
        async fn token(&self) -> Result<HeaderValue, Error> {
            Ok(self.0.lock().unwrap().clone())
        }
    }
    async fn request(
        bao: &OpenBaoHttp,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Value {
        let mut req = bao
            .client()
            .request(method, format!("{}/v1/{path}", bao.origin()))
            .header("X-Vault-Token", token);
        if let Some(body) = body {
            req = req.json(&body);
        }
        let response = req.send().await.unwrap();
        assert!(
            response.status().is_success(),
            "test setup failed at {path} with {}",
            response.status()
        );
        let raw = response.bytes().await.unwrap();
        if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw).unwrap()
        }
    }
    fn public_key(metadata: &Value, version: u32) -> [u8; 65] {
        let pem = metadata["data"]["keys"][version.to_string()]["public_key"]
            .as_str()
            .unwrap();
        let encoded: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(encoded).unwrap();
        // Strict P-256 SubjectPublicKeyInfo prefix, used only to read this fixture.
        let prefix = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        assert!(der.starts_with(&prefix));
        der[prefix.len()..].try_into().unwrap()
    }
    async fn token(bao: &OpenBaoHttp, root: &str) -> String {
        request(
            bao,
            root,
            reqwest::Method::POST,
            "auth/token/create-orphan",
            Some(json!({
                "policies":["acme-account-proof"],"no_default_policy":true,"renewable":false,
                "ttl":"60s","explicit_max_ttl":"60s"
            })),
        )
        .await["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    let executable =
        std::env::var("MARTY_TEST_OPENBAO_EXECUTABLE").expect("verified official binary path");
    let version = Command::new(&executable).arg("version").output().unwrap();
    assert!(
        version.status.success() && String::from_utf8_lossy(&version.stdout).contains("v2.5.5")
    );
    let files = tempfile::tempdir().unwrap();
    std::fs::set_permissions(files.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut random = [0u8; 32];
    SystemRandom::new().fill(&mut random).unwrap();
    let root = format!("test-only-{}", URL_SAFE_NO_PAD.encode(random));
    let child = Command::new(executable)
        .args(["server", "-dev", "-dev-tls", "-dev-no-store-token"])
        .arg(format!("-dev-listen-address={address}"))
        .arg(format!("-dev-tls-cert-dir={}", files.path().display()))
        .env("BAO_DEV_ROOT_TOKEN_ID", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server { child, files };
    let deadline = Instant::now() + Duration::from_secs(20);
    let bao = loop {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "test OpenBao exited"
        );
        assert!(Instant::now() < deadline, "test OpenBao did not start");
        if let Ok(http) = OpenBaoHttp::connect(
            &format!("https://{address}"),
            Some(&server.files.path().join("vault-ca.pem")),
            Duration::from_secs(5),
        ) {
            if let Ok(response) = http
                .client()
                .get(format!("{}/v1/sys/health", http.origin()))
                .send()
                .await
            {
                if response.status().is_success() {
                    break http;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    request(
        &bao,
        &root,
        reqwest::Method::POST,
        "sys/mounts/transit",
        Some(json!({"type":"transit"})),
    )
    .await;
    for name in ["acme-account-proof", "acme-leaf-proof"] {
        request(&bao, &root, reqwest::Method::POST, &format!("transit/keys/{name}"), Some(json!({
            "type":"ecdsa-p256","derived":false,"exportable":false,"allow_plaintext_backup":false
        }))).await;
    }
    let metadata = request(
        &bao,
        &root,
        reqwest::Method::GET,
        "transit/keys/acme-account-proof",
        None,
    )
    .await;
    assert_eq!(metadata["data"]["type"], "ecdsa-p256");
    assert_eq!(metadata["data"]["derived"], false);
    assert_eq!(metadata["data"]["exportable"], false);
    assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
    let public_v1 = public_key(&metadata, 1);
    let export = bao
        .client()
        .get(format!(
            "{}/v1/transit/export/signing-key/acme-account-proof",
            bao.origin()
        ))
        .header("X-Vault-Token", &root)
        .send()
        .await
        .unwrap();
    assert_eq!(
        export.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "even the fixture root cannot export this key"
    );
    request(
        &bao,
        &root,
        reqwest::Method::PUT,
        "sys/policies/acl/acme-account-proof",
        Some(json!({
            "policy":"path \"transit/sign/acme-account-proof\" { capabilities = [\"update\"] }"
        })),
    )
    .await;
    let first_token = token(&bao, &root).await;
    let credentials = Arc::new(FreshToken(Mutex::new(
        HeaderValue::from_str(&first_token).unwrap(),
    )));
    let signer = Arc::new(
        OpenBaoAccountSigner::new(
            bao.clone(),
            credentials.clone(),
            "acme-account-proof".into(),
            1,
            public_v1,
        )
        .unwrap(),
    );
    for path in [
        "transit/export/signing-key/acme-account-proof",
        "transit/keys/acme-account-proof",
    ] {
        let denied = bao
            .client()
            .get(format!("{}/v1/{path}", bao.origin()))
            .header("X-Vault-Token", &first_token)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    }
    let denied = bao
        .client()
        .post(format!("{}/v1/transit/sign/acme-leaf-proof", bao.origin()))
        .header("X-Vault-Token", &first_token)
        .json(&json!({"input":STANDARD.encode(b"test")}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);

    // The leaf CSR is signed inside a different nonexportable Transit key. An
    // empty-SAN CSR verifies transport/ownership only; production CSR identity
    // construction and validation must be provided by the installation owner.
    let csr = request(
        &bao,
        &root,
        reqwest::Method::POST,
        "transit/keys/acme-leaf-proof/csr",
        Some(json!({"version":1})),
    )
    .await;
    let pem = csr["data"]["csr"].as_str().unwrap();
    assert!(!pem.contains("PRIVATE KEY"));
    let mut verify = Command::new("openssl")
        .args(["req", "-verify", "-noout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    verify
        .stdin
        .take()
        .unwrap()
        .write_all(pem.as_bytes())
        .unwrap();
    assert!(
        verify.wait().unwrap().success(),
        "OpenBao CSR signature must verify independently"
    );
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let csr_der = STANDARD.decode(encoded).unwrap();
    let mut finalize = step(
        Method::POST,
        "https://ca.example/finalize/13",
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(&csr_der)})),
        order_state("valid"),
    );
    finalize.nonce = "finalized-nonce";
    let http = MockHttp::new(
        vec![
            directory(),
            nonce(),
            registration(),
            nonce(),
            step(Method::POST, ORDER, None, order_state("ready")),
            finalize,
        ],
        Some(&public_v1),
    );
    let account = Account::builder_with_http(Box::new(http.clone()))
        .create_with_signer(&new_account(), signer.clone(), DIRECTORY.into(), None)
        .await
        .unwrap();

    request(
        &bao,
        &root,
        reqwest::Method::POST,
        "transit/keys/acme-account-proof/rotate",
        Some(json!({})),
    )
    .await;
    let rotated = request(
        &bao,
        &root,
        reqwest::Method::GET,
        "transit/keys/acme-account-proof",
        None,
    )
    .await;
    assert_eq!(rotated["data"]["latest_version"], 2);
    let public_v2 = public_key(&rotated, 2);
    assert_ne!(public_v1, public_v2);
    let input = b"protected.payload";
    let signature = signer.sign(input).await.unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_v1)
        .verify(input, &signature)
        .unwrap();
    assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_v2)
        .verify(input, &signature)
        .is_err());
    let wrong = Arc::new(
        OpenBaoAccountSigner::new(
            bao.clone(),
            credentials.clone(),
            "acme-account-proof".into(),
            2,
            public_v1,
        )
        .unwrap(),
    );
    let wrong_http = MockHttp::new(vec![directory(), nonce()], Some(&public_v1));
    assert!(matches!(
        Account::builder_with_http(Box::new(wrong_http.clone()))
            .create_with_signer(&new_account(), wrong, DIRECTORY.into(), None)
            .await,
        Err(Error::Crypto)
    ));
    wrong_http.done();

    request(
        &bao,
        &root,
        reqwest::Method::POST,
        "auth/token/revoke",
        Some(json!({"token":first_token})),
    )
    .await;
    assert!(signer.sign(input).await.is_err());
    let second_token = token(&bao, &root).await;
    *credentials.0.lock().unwrap() = HeaderValue::from_str(&second_token).unwrap();
    let mut order = account.order(ORDER.into()).await.unwrap();
    order.finalize_csr(&csr_der).await.unwrap();
    http.done();
}
