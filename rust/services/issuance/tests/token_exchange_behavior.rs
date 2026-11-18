use std::{
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use marty_issuance_service::{
    client_auth::{
        RegisteredClientAuthenticator, RegisteredClientRepository, RegisteredOid4vciClient,
    },
    dpop::MartyDpopProofVerifier,
    http::{router_with_token_exchange, router_with_token_exchange_and_rate_limit},
    token_exchange::{
        DpopProofVerifier, MartyTokenGenerator, TokenAuthorizationSession, TokenExchangeError,
        TokenExchangeRepository, TokenExchangeRequest, TokenExchangeService, TokenGenerator,
        TokenTransaction, TokenTransactionStatus,
    },
    token_rate_limit::TokenRateLimiter,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::{
    discovery::StaticDiscoveryDocuments, types::TokenResponse, CodeChallengeMethod,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[derive(Clone)]
struct ContractRepository {
    state: Arc<Mutex<ContractState>>,
}

struct ContractState {
    transaction: Option<TokenTransaction>,
    authorization: Option<TokenAuthorizationSession>,
    calls: Vec<Value>,
    lose_transaction_claim: bool,
    lose_authorization_claim: bool,
    access_token: Option<String>,
    dpop_jkt: Option<String>,
    repository_unavailable: bool,
}

impl ContractRepository {
    fn new(setup: &str, inputs: &Value) -> Self {
        let transaction_status = match setup {
            "authorized_transaction" => TokenTransactionStatus::Authorized,
            "failed_transaction" => TokenTransactionStatus::Failed,
            _ => TokenTransactionStatus::Pending,
        };
        let transaction = matches!(
            setup,
            "pending_transaction"
                | "expired_transaction"
                | "authorized_transaction"
                | "failed_transaction"
                | "transaction_claim_lost"
        )
        .then(|| TokenTransaction {
            id: inputs["transaction_id"].as_str().unwrap().to_owned(),
            organization_id: inputs["organization_id"].as_str().unwrap().to_owned(),
            pre_authorized_code: inputs["pre_authorized_code"].as_str().unwrap().to_owned(),
            status: transaction_status,
            expires_at: Utc::now()
                + if setup == "expired_transaction" {
                    Duration::minutes(-1)
                } else {
                    Duration::minutes(15)
                },
            oid4vci_client_id: None,
            claims: json!({}),
        });
        let authorization = matches!(
            setup,
            "pending_authorization_session"
                | "expired_authorization_session"
                | "exchanged_authorization_session"
                | "authorization_claim_lost"
                | "redirect_authorization_session"
                | "pkce_authorization_session"
        )
        .then(|| {
            let created_at = Utc::now() - Duration::minutes(1);
            TokenAuthorizationSession {
                id: inputs["authorization_session_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                code: inputs["authorization_code"].as_str().unwrap().to_owned(),
                client_id: inputs["client_id"].as_str().unwrap().to_owned(),
                organization_id: Some(inputs["organization_id"].as_str().unwrap().to_owned()),
                redirect_uri: matches!(
                    setup,
                    "redirect_authorization_session" | "pkce_authorization_session"
                )
                .then(|| "https://wallet.example/callback".to_owned()),
                issuer_state: None,
                credential_configuration_ids: vec![],
                code_challenge: (setup == "pkce_authorization_session")
                    .then(|| URL_SAFE_NO_PAD.encode(Sha256::digest(b"correct-verifier"))),
                code_challenge_method: (setup == "pkce_authorization_session")
                    .then_some(CodeChallengeMethod::S256),
                status: if setup == "exchanged_authorization_session" {
                    "exchanged"
                } else {
                    "pending"
                }
                .to_owned(),
                created_at,
                expires_at: if setup == "expired_authorization_session" {
                    Utc::now() - Duration::seconds(1)
                } else {
                    created_at + Duration::minutes(10)
                },
            }
        });
        Self {
            state: Arc::new(Mutex::new(ContractState {
                transaction,
                authorization,
                calls: vec![],
                lose_transaction_claim: setup == "transaction_claim_lost",
                lose_authorization_claim: setup == "authorization_claim_lost",
                access_token: None,
                dpop_jkt: None,
                repository_unavailable: setup == "repository_unavailable",
            })),
        }
    }
}

#[async_trait]
impl TokenExchangeRepository for ContractRepository {
    async fn transaction_by_pre_authorized_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenTransaction>, TokenExchangeError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "get_by_pre_auth_code", "value": code}));
        if state.repository_unavailable {
            return Err(TokenExchangeError::RepositoryUnavailable);
        }
        Ok(state
            .transaction
            .as_ref()
            .filter(|transaction| transaction.pre_authorized_code == code)
            .cloned())
    }

    async fn claim_transaction(
        &self,
        transaction: &TokenTransaction,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "claim_transaction_for_token", "value": transaction.id}));
        if state.lose_transaction_claim {
            return Ok(false);
        }
        state.transaction.as_mut().unwrap().status = TokenTransactionStatus::Authorized;
        state.access_token = Some(access_token.to_owned());
        state.dpop_jkt = dpop_jkt.map(str::to_owned);
        Ok(true)
    }

    async fn authorization_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenAuthorizationSession>, TokenExchangeError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "get_authorization_session_by_code", "value": code}));
        Ok(state
            .authorization
            .as_ref()
            .filter(|session| session.code == code)
            .cloned())
    }

    async fn claim_authorization(
        &self,
        session: &TokenAuthorizationSession,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "claim_authorization_session_for_token", "value": session.id}));
        if state.lose_authorization_claim {
            return Ok(false);
        }
        state.authorization.as_mut().unwrap().status = "exchanged".to_owned();
        state.access_token = Some(access_token.to_owned());
        state.dpop_jkt = dpop_jkt.map(str::to_owned);
        Ok(true)
    }
}

#[async_trait]
impl RegisteredClientRepository for ContractRepository {
    async fn client(
        &self,
        _organization_id: &str,
        _client_id: &str,
    ) -> Result<Option<RegisteredOid4vciClient>, TokenExchangeError> {
        Ok(None)
    }

    async fn claim_assertion(
        &self,
        _organization_id: &str,
        _client_id: &str,
        _jti: &str,
        _expires_at: chrono::DateTime<Utc>,
    ) -> Result<bool, TokenExchangeError> {
        Ok(false)
    }
}

struct ContractDpop;

impl DpopProofVerifier for ContractDpop {
    fn verify(
        &self,
        proof: &str,
        _method: &str,
        _expected_htu: &str,
    ) -> Result<String, TokenExchangeError> {
        if proof == "invalid-proof" {
            Err(TokenExchangeError::InvalidDpopProof)
        } else {
            Ok("contract-dpop-jkt".to_owned())
        }
    }
}

struct ContractTokens {
    pre_authorized: String,
    authorization: String,
}

impl TokenGenerator for ContractTokens {
    fn pre_authorized(
        &self,
        _pre_authorized_code: &str,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError> {
        Ok(TokenResponse {
            access_token: self.pre_authorized.clone(),
            token_type: "Bearer".to_owned(),
            expires_in: lifetime_seconds,
            scope: None,
        })
    }

    fn authorization_code(
        &self,
        request: &TokenExchangeRequest,
        session: &TokenAuthorizationSession,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError> {
        MartyTokenGenerator.authorization_code(request, session, lifetime_seconds)?;
        Ok(TokenResponse {
            access_token: self.authorization.clone(),
            token_type: "Bearer".to_owned(),
            expires_in: lifetime_seconds,
            scope: None,
        })
    }
}

fn app(repository: ContractRepository, inputs: &Value) -> axum::Router {
    app_with_limiter(repository, inputs, None)
}

fn app_with_limiter(
    repository: ContractRepository,
    inputs: &Value,
    limiter: Option<TokenRateLimiter>,
) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let documents = StaticDiscoveryDocuments::new("https://issuer.example", "Issuer");
    let service = TokenExchangeService::new(
        Arc::new(repository.clone()),
        Arc::new(RegisteredClientAuthenticator::new(Arc::new(repository))),
        Arc::new(ContractDpop),
        Arc::new(ContractTokens {
            pre_authorized: inputs["generated_pre_authorized_token"]
                .as_str()
                .unwrap()
                .to_owned(),
            authorization: inputs["generated_authorization_code_token"]
                .as_str()
                .unwrap()
                .to_owned(),
        }),
        "https://issuer.example",
    );
    match limiter {
        Some(limiter) => router_with_token_exchange_and_rate_limit(
            runtime.state(),
            documents,
            TransportPolicy::new([]),
            service,
            limiter,
        ),
        None => router_with_token_exchange(
            runtime.state(),
            documents,
            TransportPolicy::new([]),
            service,
        ),
    }
}

fn form_body(form: &Value) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in form.as_object().unwrap() {
        serializer.append_pair(name, value.as_str().unwrap());
    }
    serializer.finish()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn text_body(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn native_token_exchange_matches_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-token-exchange.json"
    ))
    .unwrap();
    let inputs = &contract["inputs"];
    for case in contract["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(contract["failures"].as_array().unwrap())
    {
        let repository = ContractRepository::new(case["setup"].as_str().unwrap(), inputs);
        let mut request = Request::post(inputs["path"].as_str().unwrap())
            .header("content-type", "application/x-www-form-urlencoded")
            .header("host", "testserver");
        for (name, value) in case
            .get("headers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            request = request.header(name, value.as_str().unwrap());
        }
        let response = app(repository.clone(), inputs)
            .oneshot(request.body(Body::from(form_body(&case["form"]))).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            case["status_code"],
            "{}",
            case["name"]
        );
        assert_eq!(
            response.headers()["content-type"],
            "application/json",
            "{}",
            case["name"]
        );
        assert_eq!(json_body(response).await, case["body"], "{}", case["name"]);
        let state = repository.state.lock().unwrap();
        assert_eq!(
            state.calls.as_slice(),
            case["repository_calls"].as_array().unwrap(),
            "{}",
            case["name"]
        );
        if let Some(expected) = case.get("final_state") {
            let status = if expected["kind"] == "transaction" {
                match state.transaction.as_ref().unwrap().status {
                    TokenTransactionStatus::Authorized => "authorized",
                    _ => "unexpected",
                }
            } else {
                &state.authorization.as_ref().unwrap().status
            };
            assert_eq!(status, expected["status"]);
            assert_eq!(
                state.access_token.as_deref(),
                expected["access_token"].as_str()
            );
            if let Some(dpop_jkt) = expected.get("dpop_jkt") {
                assert_eq!(state.dpop_jkt.as_deref(), dpop_jkt.as_str());
            }
        }
    }
}

#[test]
fn production_dpop_verifier_is_not_the_contract_stub() {
    assert_eq!(
        MartyDpopProofVerifier.verify("invalid-proof", "POST", "https://issuer.example/token"),
        Err(TokenExchangeError::InvalidDpopProof)
    );
}

#[tokio::test]
async fn token_rate_limit_preserves_legacy_body_and_retry_after_header() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-token-exchange.json"
    ))
    .unwrap();
    let inputs = &contract["inputs"];
    let expected = &contract["rate_limit"];
    let repository = ContractRepository::new("no_state", inputs);
    let app = app_with_limiter(
        repository,
        inputs,
        Some(TokenRateLimiter::new(
            expected["requests"].as_u64().unwrap() as usize,
            StdDuration::from_secs(expected["window_seconds"].as_u64().unwrap()),
        )),
    );
    let request = || {
        Request::post(inputs["path"].as_str().unwrap())
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&expected["request"]["form"])))
            .unwrap()
    };
    for _ in 0..expected["requests"].as_u64().unwrap() {
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status().as_u16(), expected["allowed_status_code"]);
    }
    let response = app.oneshot(request()).await.unwrap();
    assert_eq!(response.status().as_u16(), expected["status_code"]);
    for (name, value) in expected["headers"].as_object().unwrap() {
        assert_eq!(response.headers()[name], value.as_str().unwrap());
    }
    assert_eq!(json_body(response).await, expected["body"]);
}

#[tokio::test]
async fn token_dependency_failures_match_the_python_oracle() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-token-exchange.json"
    ))
    .unwrap();
    let inputs = &contract["inputs"];
    for case in contract["dependency_failures"].as_array().unwrap() {
        let repository = ContractRepository::new(case["setup"].as_str().unwrap(), inputs);
        let response = app(repository.clone(), inputs)
            .oneshot(
                Request::post(inputs["path"].as_str().unwrap())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body(&case["form"])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), case["status_code"]);
        assert_eq!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
            case["content_type"]
        );
        assert_eq!(text_body(response).await, case["body"]);
        assert_eq!(
            repository.state.lock().unwrap().calls,
            case["repository_calls"].as_array().unwrap().as_slice()
        );
    }
}
