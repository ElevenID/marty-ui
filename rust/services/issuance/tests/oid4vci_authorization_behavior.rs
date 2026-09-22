use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use marty_issuance_service::{
    http::router_with_oid4vci_authorization,
    oid4vci_authorization::{
        router, router_with_rate_limit, AccessTokenGrant, AuthorizationParameters,
        AuthorizationSessionWrite, DeferredCredentialLookup, DeferredCredentialRecord,
        DeferredStatus, NotificationLookup, NotificationRequest, Oid4vciAuthorizationRepository,
        Oid4vciAuthorizationRepositoryError, Oid4vciAuthorizationService,
        RegisteredAuthorizationClient,
    },
    token_exchange::{protocol_engine, DpopProofVerifier, TokenExchangeError},
    token_rate_limit::TokenRateLimiter,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct State {
    pars: HashMap<String, AuthorizationParameters>,
    clients: HashMap<(String, String), RegisteredAuthorizationClient>,
    sessions: Vec<AuthorizationSessionWrite>,
    tokens: BTreeSet<String>,
    token_jkts: HashMap<String, String>,
    deferred: HashMap<(String, String), DeferredCredentialRecord>,
    bindings: HashMap<(String, String), String>,
    notifications: BTreeSet<(String, String, String, String)>,
    fail: bool,
}

#[derive(Clone, Default)]
struct Repository(Arc<Mutex<State>>);

impl Repository {
    fn inspect<T>(&self, inspect: impl FnOnce(&State) -> T) -> T {
        inspect(&self.0.lock().unwrap())
    }
}

#[async_trait]
impl Oid4vciAuthorizationRepository for Repository {
    async fn store_par(
        &self,
        request_uri: &str,
        parameters: &AuthorizationParameters,
        ttl_seconds: u64,
    ) -> Result<bool, Oid4vciAuthorizationRepositoryError> {
        assert_eq!(ttl_seconds, 90);
        let mut state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        Ok(state
            .pars
            .insert(request_uri.to_owned(), parameters.clone())
            .is_none())
    }

    async fn consume_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationParameters>, Oid4vciAuthorizationRepositoryError> {
        let mut state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        Ok(state.pars.remove(request_uri))
    }

    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredAuthorizationClient>, Oid4vciAuthorizationRepositoryError> {
        let state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        Ok(state
            .clients
            .get(&(organization_id.to_owned(), client_id.to_owned()))
            .cloned())
    }

    async fn save_authorization_session(
        &self,
        session: &AuthorizationSessionWrite,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError> {
        let mut state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        state.sessions.push(session.clone());
        Ok(())
    }

    async fn access_token_grant(
        &self,
        access_token: &str,
    ) -> Result<Option<AccessTokenGrant>, Oid4vciAuthorizationRepositoryError> {
        let state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        Ok(state
            .tokens
            .contains(access_token)
            .then(|| AccessTokenGrant {
                dpop_jkt: state.token_jkts.get(access_token).cloned(),
            }))
    }

    async fn deferred_credential(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> Result<DeferredCredentialLookup, Oid4vciAuthorizationRepositoryError> {
        let state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        if let Some(record) = state
            .deferred
            .get(&(access_token.to_owned(), transaction_id.to_owned()))
        {
            return Ok(DeferredCredentialLookup::Bound(record.clone()));
        }
        Ok(
            if state.deferred.keys().any(|(_, id)| id == transaction_id) {
                DeferredCredentialLookup::Unbound
            } else {
                DeferredCredentialLookup::Missing
            },
        )
    }

    async fn notification_transaction(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> Result<NotificationLookup, Oid4vciAuthorizationRepositoryError> {
        let state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        if let Some(transaction_id) = state
            .bindings
            .get(&(access_token.to_owned(), notification_id.to_owned()))
        {
            return Ok(NotificationLookup::Bound(transaction_id.clone()));
        }
        Ok(
            if state.bindings.keys().any(|(_, id)| id == notification_id) {
                NotificationLookup::Unbound
            } else {
                NotificationLookup::Missing
            },
        )
    }

    async fn record_notification(
        &self,
        transaction_id: &str,
        request: &NotificationRequest,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError> {
        let mut state = self.0.lock().unwrap();
        if state.fail {
            return Err(Oid4vciAuthorizationRepositoryError);
        }
        state.notifications.insert((
            transaction_id.to_owned(),
            request.notification_id.clone(),
            request.event.as_str().to_owned(),
            request.event_description.clone().unwrap_or_default(),
        ));
        Ok(())
    }
}

struct ContractDpop;

impl DpopProofVerifier for ContractDpop {
    fn verify(
        &self,
        proof: &str,
        method: &str,
        expected_htu: &str,
    ) -> Result<String, TokenExchangeError> {
        let (observed, jkt) = proof
            .rsplit_once('|')
            .ok_or(TokenExchangeError::InvalidDpopProof)?;
        (observed == format!("{method}|{expected_htu}"))
            .then(|| jkt.to_owned())
            .ok_or(TokenExchangeError::InvalidDpopProof)
    }
}

fn app(repository: &Repository) -> axum::Router {
    router(service(repository))
}

fn service(repository: &Repository) -> Oid4vciAuthorizationService {
    service_with_ttl(repository, 60)
}

fn service_with_ttl(
    repository: &Repository,
    session_ttl_minutes: i64,
) -> Oid4vciAuthorizationService {
    Oid4vciAuthorizationService::new(
        Arc::new(repository.clone()),
        Arc::new(ContractDpop),
        protocol_engine(),
        "https://issuer.example",
        Vec::new(),
        session_ttl_minutes.into(),
    )
}

async fn send(
    app: axum::Router,
    method: &str,
    uri: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: &str,
) -> (u16, axum::http::HeaderMap, Option<Value>) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(authorization) = authorization {
        request = request.header("authorization", authorization);
    }
    let response = app
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap());
    (status, headers, body)
}

async fn send_with_dpop(
    app: axum::Router,
    uri: &str,
    authorization: &str,
    dpop: Option<&str>,
    body: &str,
) -> (u16, axum::http::HeaderMap, Option<Value>) {
    let mut request = Request::post(uri)
        .header("content-type", "application/json")
        .header("authorization", authorization);
    if let Some(dpop) = dpop {
        request = request.header("dpop", dpop);
    }
    let response = app
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap());
    (status, headers, body)
}

#[tokio::test]
async fn par_is_single_use_and_authorization_preserves_registered_redirect_queries() {
    let repository = Repository::default();
    repository.0.lock().unwrap().clients.insert(
        ("org-a".into(), "wallet-a".into()),
        RegisteredAuthorizationClient {
            active: true,
            redirect_uris: vec!["https://wallet.example/callback?channel=one".into()],
        },
    );
    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par?issuer_org=org-a",
        Some("application/x-www-form-urlencoded"),
        None,
        "response_type=code&client_id=wallet-a&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback%3Fchannel%3Done&state=state-a&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22config-a%22%7D%5D&organization_id=foreign",
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(headers["content-type"], "application/json");
    let body = body.unwrap();
    assert_eq!(body["expires_in"], 90);
    let request_uri = body["request_uri"].as_str().unwrap().to_owned();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(
        repository.inspect(|state| state.pars.values().next().unwrap().organization_id.clone()),
        Some("org-a".into())
    );
    let authorization_uri = format!(
        "/v1/issuance/authorize?request_uri={}",
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
    );
    let (status, headers, body) =
        send(app(&repository), "GET", &authorization_uri, None, None, "").await;
    assert_eq!(status, 307);
    assert!(body.is_none());
    let location = headers["location"].to_str().unwrap();
    assert!(location.starts_with("https://wallet.example/callback?channel=one&code=ac_"));
    assert!(location.contains("&iss=https%3A%2F%2Fissuer.example%2Forg%2Forg-a&state=state-a"));
    repository.inspect(|state| {
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0].organization_id.as_deref(), Some("org-a"));
        assert_eq!(
            state.sessions[0].session.credential_configuration_ids,
            ["config-a"]
        );
        assert_eq!(state.sessions[0].session.expires_in, 600);
        assert_eq!(state.sessions[0].persisted_lifetime_seconds, 3_600);
    });

    let (status, _, body) = send(app(&repository), "GET", &authorization_uri, None, None, "").await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "request_uri is invalid or expired"
    );
}

#[tokio::test]
async fn authorization_preserves_json_success_and_sanitizes_protocol_and_repository_errors() {
    let repository = Repository::default();
    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&issuer_org=org-a&state=state-json&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22config-a%22%7D%5D",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 200);
    let body = body.unwrap();
    assert!(body["code"].as_str().unwrap().starts_with("ac_"));
    assert_eq!(body["state"], "state-json");

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?client_id=wallet-a",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "response_type and client_id are required"
    );

    repository.0.lock().unwrap().clients.insert(
        ("org-a".into(), "inactive-wallet".into()),
        RegisteredAuthorizationClient {
            active: false,
            redirect_uris: vec!["https://wallet.example/callback".into()],
        },
    );
    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=inactive-wallet&issuer_org=org-a&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400, "client validation errors are not redirectable");
    assert_eq!(body.unwrap()["error"], "unauthorized_client");

    repository.0.lock().unwrap().clients.insert(
        ("org-a".into(), "active-wallet".into()),
        RegisteredAuthorizationClient {
            active: true,
            redirect_uris: vec!["https://wallet.example/registered".into()],
        },
    );
    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=active-wallet&issuer_org=org-a&redirect_uri=https%3A%2F%2Fwallet.example%2Funregistered",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "redirect_uri is not registered for this client"
    );

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=ftp%3A%2F%2Flocalhost%2Fcallback",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "redirect_uri must use HTTPS"
    );

    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%2Fcallback",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    assert!(headers["location"]
        .to_str()
        .unwrap()
        .starts_with("http://[::1]/callback?code=ac_"));

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=http%3A%2F%2F127.0.0.2%2Fcallback",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "redirect_uri must use HTTPS"
    );

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&authorization_details=%7B",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(
        status, 200,
        "syntactically invalid JSON remains projected to null"
    );
    assert!(body.unwrap()["code"].as_str().unwrap().starts_with("ac_"));

    for authorization_details in ["%7B%7D", "1"] {
        let uri = format!(
            "/v1/issuance/authorize?response_type=code&client_id=public-wallet&authorization_details={authorization_details}"
        );
        let (status, _, body) = send(app(&repository), "GET", &uri, None, None, "").await;
        assert_eq!(status, 400);
        assert_eq!(
            body.unwrap()["error_description"],
            "Invalid authorization_details"
        );
    }

    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback&state=shape-state&authorization_details=%5B1%5D",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    assert_eq!(headers["location"], "https://wallet.example/callback?error=invalid_request&error_description=Invalid+authorization_details&state=shape-state");

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&code_challenge=challenge&code_challenge_method=S512",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "Unsupported code_challenge_method"
    );

    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback&state=&code_challenge=challenge&code_challenge_method=S512",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    assert_eq!(headers["location"], "https://wallet.example/callback?error=invalid_request&error_description=Unsupported+code_challenge_method");

    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback&state=",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    let location = headers["location"].to_str().unwrap();
    assert!(!location.contains("state="));

    let unsafe_redirect = "ftp://localhost/callback";
    let service = Oid4vciAuthorizationService::new(
        Arc::new(repository.clone()),
        Arc::new(ContractDpop),
        protocol_engine(),
        "https://issuer.example",
        vec![unsafe_redirect.to_owned()],
        60_i64.into(),
    );
    let (status, _, body) = send(
        router(service),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&redirect_uri=ftp%3A%2F%2Flocalhost%2Fcallback",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(
        status, 400,
        "allowlisting cannot bypass redirect scheme safety"
    );
    assert_eq!(
        body.unwrap()["error_description"],
        "redirect_uri must use HTTPS"
    );

    repository.0.lock().unwrap().pars.insert(
        "urn:ietf:params:oauth:request_uri:error-case".into(),
        AuthorizationParameters {
            response_type: Some("token".into()),
            client_id: Some("par-wallet".into()),
            redirect_uri: Some("https://wallet.example/par-callback?channel=par".into()),
            state: Some("par-state".into()),
            ..AuthorizationParameters::default()
        },
    );
    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aerror-case&response_type=code&client_id=inline-wallet&redirect_uri=https%3A%2F%2Fwallet.example%2Finline&state=inline-state",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    assert_eq!(headers["location"], "https://wallet.example/par-callback?channel=par&error=invalid_request&error_description=response_type+must+be+code&state=par-state");

    let (status, headers, _) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=token&client_id=wallet-a&redirect_uri=https%3A%2F%2Fwallet.example%2Fcallback%3Fchannel%3Done&state=state-a",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 307);
    assert_eq!(headers["location"], "https://wallet.example/callback?channel=one&error=invalid_request&error_description=response_type+must+be+code&state=state-a");

    repository.0.lock().unwrap().fail = true;
    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Asecret",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(
        body.unwrap(),
        json!({"error":"temporarily_unavailable","error_description":"Authorization request storage is unavailable"})
    );

    let (status, _, body) = send(
        app(&repository),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=wallet-a&issuer_org=org-a",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(
        body.unwrap(),
        json!({"error":"temporarily_unavailable","error_description":"OID4VCI service is temporarily unavailable"})
    );
}

#[tokio::test]
async fn authorization_persists_the_configured_python_session_lifetime() {
    let repository = Repository::default();
    let (status, _, _) = send(
        router(service_with_ttl(&repository, 75)),
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=public-wallet&issuer_org=org-a",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 200);
    repository.inspect(|state| {
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0].session.expires_in, 600);
        assert_eq!(state.sessions[0].persisted_lifetime_seconds, 4_500);
    });
}

#[tokio::test]
async fn par_enforces_the_encoded_limit_before_storage_and_reuses_the_shared_rate_limiter() {
    let repository = Repository::default();
    let oversized = format!("state={}", "a".repeat(17_000));
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par?issuer_org=org-a",
        Some("application/x-www-form-urlencoded"),
        None,
        &oversized,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "Pushed authorization request is too large"
    );
    assert!(repository.inspect(|state| state.pars.is_empty()));

    for unicode_state in ["é".repeat(3_000), "😀".repeat(1_500)] {
        let unicode_oversized = format!("state={unicode_state}");
        let (status, _, body) = send(
            app(&repository),
            "POST",
            "/v1/issuance/par?issuer_org=org-a",
            Some("application/x-www-form-urlencoded"),
            None,
            &unicode_oversized,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(
            body.unwrap()["error_description"],
            "Pushed authorization request is too large"
        );
        assert!(repository.inspect(|state| state.pars.is_empty()));
    }

    let body_limit = format!("state={}", "a".repeat(70_000));
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par",
        Some("application/x-www-form-urlencoded"),
        None,
        &body_limit,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body.unwrap()["error"], "invalid_request");

    let ignored_extension = format!(
        "response_type=code&client_id=wallet-a&ignored_extension={}",
        "a".repeat(70_000)
    );
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par?issuer_org=org-a",
        Some("application/x-www-form-urlencoded"),
        None,
        &ignored_extension,
    )
    .await;
    assert_eq!(
        status, 201,
        "the application must not shrink the transport-owned form envelope"
    );
    assert!(body.unwrap()["request_uri"].as_str().is_some());

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par",
        None,
        None,
        "response_type=code&client_id=wallet-a",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body.unwrap()["error"], "invalid_request");

    repository.0.lock().unwrap().fail = true;
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/par",
        Some("application/x-www-form-urlencoded"),
        None,
        "response_type=code&client_id=wallet-a",
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(
        body.unwrap(),
        json!({"error":"temporarily_unavailable","error_description":"Authorization request storage is unavailable"})
    );
    repository.0.lock().unwrap().fail = false;

    let limited = router_with_rate_limit(
        service(&repository),
        TokenRateLimiter::new(0, std::time::Duration::from_secs(17)),
    );
    let (status, headers, body) = send(
        limited,
        "GET",
        "/v1/issuance/authorize?response_type=code&client_id=wallet-a",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(headers["retry-after"], "17");
    assert_eq!(body.unwrap(), json!({"detail":"Rate limit exceeded"}));
}

#[tokio::test]
async fn dpop_bound_deferred_and_notification_verify_exact_post_htu_and_jkt() {
    let repository = Repository::default();
    {
        let mut state = repository.0.lock().unwrap();
        state.tokens.insert("bound-token".into());
        state
            .token_jkts
            .insert("bound-token".into(), "wallet-jkt".into());
        state.deferred.insert(
            ("bound-token".into(), "tx-a".into()),
            DeferredCredentialRecord {
                status: DeferredStatus::Pending,
                credential: None,
            },
        );
        state.bindings.insert(
            ("bound-token".into(), "notification-a".into()),
            "tx-a".into(),
        );
    }
    for (uri, body) in [
        (
            "/v1/issuance/deferred-credential",
            r#"{"transaction_id":"tx-a"}"#,
        ),
        (
            "/v1/issuance/notification",
            r#"{"notification_id":"notification-a","event":"credential_accepted"}"#,
        ),
    ] {
        let proofs = [
            None,
            Some("POST|https://issuer.example/v1/issuance/wrong|wallet-jkt".to_owned()),
            Some(format!("POST|https://issuer.example{uri}|wrong-jkt")),
            Some("malformed-proof".to_owned()),
        ];
        for proof in &proofs {
            let (status, headers, response) = send_with_dpop(
                app(&repository),
                uri,
                "Bearer bound-token",
                proof.as_deref(),
                body,
            )
            .await;
            assert_eq!(status, 401, "{uri} {proof:?}");
            assert_eq!(headers["www-authenticate"], "Bearer");
            assert_eq!(response.unwrap()["error"], "invalid_token");
        }
        let proof = format!("POST|https://issuer.example{uri}|wallet-jkt");
        let (status, _, _) = send_with_dpop(
            app(&repository),
            uri,
            "Bearer bound-token",
            Some(&proof),
            body,
        )
        .await;
        assert!(matches!(status, 202 | 204), "{uri} returned {status}");
    }
}

#[tokio::test]
async fn deferred_credentials_require_a_bound_nonempty_token_and_preserve_status_responses() {
    let repository = Repository::default();
    {
        let mut state = repository.0.lock().unwrap();
        state.tokens.extend(["token-a".into(), "token-b".into()]);
        state.deferred.insert(
            ("token-a".into(), "tx-a".into()),
            DeferredCredentialRecord {
                status: DeferredStatus::Pending,
                credential: None,
            },
        );
        state.deferred.insert(
            ("token-a".into(), "tx-issued".into()),
            DeferredCredentialRecord {
                status: DeferredStatus::Issued,
                credential: Some("credential.jwt.value".into()),
            },
        );
        state.deferred.insert(
            ("token-a".into(), "tx-failed".into()),
            DeferredCredentialRecord {
                status: DeferredStatus::Failed,
                credential: None,
            },
        );
        state.deferred.insert(
            ("token-a".into(), "tx-issued-empty".into()),
            DeferredCredentialRecord {
                status: DeferredStatus::Issued,
                credential: None,
            },
        );
    }
    for authorization in [None, Some("Bearer "), Some("Bearer other-token")] {
        let (status, headers, body) = send(
            app(&repository),
            "POST",
            "/v1/issuance/deferred-credential",
            Some("application/json"),
            authorization,
            r#"{"transaction_id":"tx-a"}"#,
        )
        .await;
        assert_eq!(status, 401);
        assert_eq!(headers["www-authenticate"], "Bearer");
        assert_eq!(body.unwrap()["error"], "invalid_token");
    }
    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-b"),
        r#"{"transaction_id":"tx-a"}"#,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(headers["www-authenticate"], "Bearer");
    assert_eq!(body.unwrap()["error"], "invalid_token");

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        "{}",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "transaction_id is required"
    );
    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        r#"{"transaction_id":"tx-a"}"#,
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(headers["retry-after"], "5");
    assert_eq!(body.unwrap(), json!({"transaction_id":"tx-a"}));

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        r#"{"transaction_id":"tx-issued"}"#,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.unwrap(), json!({"credential":"credential.jwt.value"}));

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        r#"{"transaction_id":"tx-failed"}"#,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body.unwrap()["error_description"],
        "Transaction is in failed state"
    );

    for (body, expected) in [
        (
            r#"{"transaction_id":"tx-missing"}"#,
            "No transaction found for the given ID",
        ),
        (
            r#"{"transaction_id":"tx-issued-empty"}"#,
            "Transaction is in issued state",
        ),
    ] {
        let (status, _, response) = send(
            app(&repository),
            "POST",
            "/v1/issuance/deferred-credential",
            Some("application/json"),
            Some("Bearer token-a"),
            body,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(response.unwrap()["error_description"], expected);
    }
    let large_transaction_id = "x".repeat(17 * 1024);
    let large_deferred_body = json!({"transaction_id": large_transaction_id}).to_string();
    let (status, _, response) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        &large_deferred_body,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        response.unwrap()["error_description"],
        "No transaction found for the given ID",
        "the application must not shrink the transport-owned body envelope"
    );
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        None,
        "not-json",
    )
    .await;
    assert_eq!(status, 401, "authentication precedes body parsing");
    assert_eq!(body.unwrap()["error"], "invalid_token");

    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        "not-json",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        body.unwrap(),
        json!({"error":"invalid_request","error_description":"Invalid JSON request body"})
    );

    repository.0.lock().unwrap().fail = true;
    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/deferred-credential",
        Some("application/json"),
        Some("Bearer token-a"),
        r#"{"transaction_id":"tx-a"}"#,
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        body.unwrap(),
        json!({"error":"temporarily_unavailable","error_description":"OID4VCI service is temporarily unavailable"})
    );
}

#[tokio::test]
async fn notifications_validate_bind_persist_and_idempotently_acknowledge_supported_events() {
    let repository = Repository::default();
    {
        let mut state = repository.0.lock().unwrap();
        state.tokens.extend(["token-a".into(), "token-b".into()]);
        state
            .bindings
            .insert(("token-a".into(), "notification-a".into()), "tx-a".into());
    }
    let valid = r#"{"notification_id":"notification-a","event":"credential_accepted","event_description":"stored by wallet"}"#;
    for _ in 0..2 {
        let (status, _, body) = send(
            app(&repository),
            "POST",
            "/v1/issuance/notification",
            Some("application/json"),
            Some("Bearer token-a"),
            valid,
        )
        .await;
        assert_eq!(status, 204);
        assert!(body.is_none());
    }
    assert_eq!(repository.inspect(|state| state.notifications.len()), 1);

    let deleted = r#"{"notification_id":"notification-a","event":"credential_deleted"}"#;
    let (status, _, _) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-a"),
        deleted,
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(repository.inspect(|state| state.notifications.len()), 2);

    let failed = r#"{"notification_id":"notification-a","event":"credential_failure"}"#;
    let (status, _, _) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-a"),
        failed,
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(repository.inspect(|state| state.notifications.len()), 3);

    let large_description = "x".repeat(17 * 1024);
    let large_notification = json!({
        "notification_id": "notification-a",
        "event": "credential_accepted",
        "event_description": large_description,
    })
    .to_string();
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-a"),
        &large_notification,
    )
    .await;
    assert_eq!(status, 204);
    assert!(body.is_none());
    assert_eq!(repository.inspect(|state| state.notifications.len()), 4);

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-b"),
        valid,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body.unwrap()["error"], "invalid_token");

    let missing = r#"{"notification_id":"notification-missing","event":"credential_accepted"}"#;
    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-a"),
        missing,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body.unwrap()["error"], "invalid_notification_id");

    for body in [
        r#"{"notification_id":"notification-a","event":"accepted"}"#,
        r#"{"notification_id":"notification-a","event":"credential_deleted","event_description":"line\nbreak"}"#,
        r#"{"notification_id":"notification-a","event":"credential_deleted","extra":true}"#,
        r#"{"notification_id":"notification-a","notification_id":"notification-a","event":"credential_deleted"}"#,
    ] {
        let (status, _, response) = send(
            app(&repository),
            "POST",
            "/v1/issuance/notification",
            Some("application/json"),
            Some("Bearer token-a"),
            body,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(
            response.unwrap(),
            json!({"error":"invalid_notification_request"})
        );
    }

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("text/plain"),
        Some("Bearer token-a"),
        valid,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body.unwrap()["error"], "invalid_notification_request");

    let (status, _, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        None,
        "not-json",
    )
    .await;
    assert_eq!(status, 401, "authentication precedes body parsing");
    assert_eq!(body.unwrap()["error"], "invalid_token");

    repository.0.lock().unwrap().fail = true;
    let (status, headers, body) = send(
        app(&repository),
        "POST",
        "/v1/issuance/notification",
        Some("application/json"),
        Some("Bearer token-a"),
        valid,
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        body.unwrap(),
        json!({"error":"temporarily_unavailable","error_description":"OID4VCI service is temporarily unavailable"})
    );
}

#[tokio::test]
async fn production_composition_mounts_exact_public_routes_inside_common_transport() {
    let repository = Repository::default();
    let config = IssuanceServiceConfig::from_values([
        (
            "ISSUER_BASE_URL".to_owned(),
            "https://issuer.example".to_owned(),
        ),
        (
            "CORS_ALLOWED_ORIGINS".to_owned(),
            "https://wallet.example".to_owned(),
        ),
    ])
    .unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let app = router_with_oid4vci_authorization(
        runtime.state(),
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name),
        TransportPolicy::new(config.cors_allowed_origins),
        service(&repository),
        TokenRateLimiter::legacy_defaults(),
    );

    let response = app
        .clone()
        .oneshot(
            Request::get(
                "/v1/issuance/authorize?response_type=code&client_id=wallet-a&issuer_org=org-a",
            )
            .header("origin", "https://wallet.example")
            .header("x-request-id", "contract-id")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-request-id"], "contract-id");
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://wallet.example"
    );

    for request in [
        Request::post("/v1/issuance/par")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("response_type=code&client_id=wallet-a"))
            .unwrap(),
        Request::post("/v1/issuance/deferred-credential")
            .body(Body::empty())
            .unwrap(),
        Request::post("/v1/issuance/notification")
            .body(Body::empty())
            .unwrap(),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_ne!(response.status(), 404);
    }
    for request in [
        Request::put("/v1/issuance/oid4vci-clients"),
        Request::post("/v1/issuance/transactions/tx-a/revoke"),
        Request::get("/v1/issuance/credentials"),
    ] {
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
