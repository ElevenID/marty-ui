use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use marty_issuance_service::{
    http::router_with_proof_nonce_and_rate_limit,
    proof_nonce::{ProofNonceError, ProofNonceGenerator, ProofNonceRepository, ProofNonceService},
    token_rate_limit::TokenRateLimiter,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Clone)]
struct ContractRepository {
    setup: Arc<str>,
    calls: Arc<Mutex<Vec<Value>>>,
}

impl ContractRepository {
    fn new(setup: &str) -> Self {
        Self {
            setup: Arc::from(setup),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ProofNonceRepository for ContractRepository {
    async fn save_proof_nonce(
        &self,
        nonce: &str,
        ttl_seconds: u64,
    ) -> Result<bool, ProofNonceError> {
        self.calls.lock().unwrap().push(json!({
            "method": "save_proof_nonce",
            "value": nonce,
            "ttl_seconds": ttl_seconds
        }));
        match self.setup.as_ref() {
            "store_returns_false" => Ok(false),
            "store_raises" => Err(ProofNonceError::RepositoryUnavailable),
            _ => Ok(true),
        }
    }

    async fn consume_proof_nonce(&self, _nonce: &str) -> Result<bool, ProofNonceError> {
        Ok(false)
    }
}

struct ContractGenerator(String);

impl ProofNonceGenerator for ContractGenerator {
    fn generate(&self) -> Result<String, ProofNonceError> {
        Ok(self.0.clone())
    }
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-proof-nonce.json"
    ))
    .unwrap()
}

fn app(repository: ContractRepository, limiter: TokenRateLimiter) -> axum::Router {
    let contract = contract();
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let service = ProofNonceService::new(
        Arc::new(repository),
        Arc::new(ContractGenerator(
            contract["inputs"]["generated_nonce"]
                .as_str()
                .unwrap()
                .to_owned(),
        )),
    );
    router_with_proof_nonce_and_rate_limit(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        service,
        limiter,
    )
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn request(path: &str) -> Request<Body> {
    Request::post(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn native_proof_nonce_matches_the_python_oracle_contract() {
    let contract = contract();
    let path = contract["inputs"]["path"].as_str().unwrap();
    let repository = ContractRepository::new("stored");
    let response = app(repository.clone(), TokenRateLimiter::legacy_defaults())
        .oneshot(request(path))
        .await
        .unwrap();
    let expected = &contract["success"];
    assert_eq!(response.status().as_u16(), expected["status_code"]);
    assert_eq!(
        response.headers()["content-type"],
        expected["content_type"].as_str().unwrap()
    );
    for (name, value) in expected["headers"].as_object().unwrap() {
        assert_eq!(response.headers()[name], value.as_str().unwrap());
    }
    assert_eq!(body(response).await, expected["body"]);
    assert_eq!(
        repository.calls.lock().unwrap().as_slice(),
        expected["repository_calls"].as_array().unwrap()
    );

    for failure in contract["failures"].as_array().unwrap() {
        let repository = ContractRepository::new(failure["setup"].as_str().unwrap());
        let response = app(repository.clone(), TokenRateLimiter::legacy_defaults())
            .oneshot(request(path))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), failure["status_code"]);
        assert_eq!(
            response.headers()["content-type"],
            failure["content_type"].as_str().unwrap()
        );
        assert_eq!(body(response).await, failure["body"]);
        assert_eq!(
            repository.calls.lock().unwrap().as_slice(),
            expected["repository_calls"].as_array().unwrap()
        );
    }
}

#[tokio::test]
async fn proof_nonce_reuses_the_legacy_oauth_rate_limit_boundary() {
    let contract = contract();
    let expected = &contract["rate_limit"];
    let repository = ContractRepository::new("stored");
    let app = app(
        repository.clone(),
        TokenRateLimiter::new(
            expected["requests"].as_u64().unwrap() as usize,
            Duration::from_secs(expected["window_seconds"].as_u64().unwrap()),
        ),
    );
    let path = contract["inputs"]["path"].as_str().unwrap();
    for _ in 0..expected["requests"].as_u64().unwrap() {
        let response = app.clone().oneshot(request(path)).await.unwrap();
        assert_eq!(response.status().as_u16(), expected["allowed_status_code"]);
    }
    let response = app.oneshot(request(path)).await.unwrap();
    assert_eq!(response.status().as_u16(), expected["status_code"]);
    for (name, value) in expected["headers"].as_object().unwrap() {
        assert_eq!(response.headers()[name], value.as_str().unwrap());
    }
    assert_eq!(body(response).await, expected["body"]);
    assert_eq!(
        repository.calls.lock().unwrap().len(),
        expected["repository_call_count"].as_u64().unwrap() as usize
    );
}

#[tokio::test]
async fn token_and_nonce_share_one_oauth_rate_limit_budget() {
    let contract = contract();
    let repository = ContractRepository::new("stored");
    let app = app(
        repository.clone(),
        TokenRateLimiter::new(1, Duration::from_secs(60)),
    );
    let token = Request::post("/v1/issuance/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=missing",
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(token).await.unwrap().status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );

    let response = app
        .oneshot(request(contract["inputs"]["path"].as_str().unwrap()))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert!(repository.calls.lock().unwrap().is_empty());
}
