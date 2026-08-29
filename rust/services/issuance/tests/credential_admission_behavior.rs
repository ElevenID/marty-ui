use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::{
    credential::{
        AllocatedCredentialStatus, BuiltCredential, CredentialAuthorizationSession,
        CredentialBuildRequest, CredentialBuilder, CredentialIssuanceError,
        CredentialIssuanceService, CredentialLifecycle, CredentialPorts, CredentialProofVerifier,
        CredentialRepository, CredentialTransaction, CredentialTransactionStatus,
        ExistingCredential, IssuedCredential, IssuerContext, IssuerContextResolver,
        NotificationIdGenerator, VerifiedCredentialProof,
    },
    http::router_with_credential_issuance,
    proof_nonce::{ProofNonceError, ProofNonceRepository},
    token_exchange::{DpopProofVerifier, TokenExchangeError},
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Map, Value};
use tower::ServiceExt;

#[derive(Clone)]
struct ContractRepository {
    state: Arc<Mutex<ContractState>>,
}

struct ContractState {
    setup: String,
    transaction: CredentialTransaction,
    calls: Vec<Value>,
}

impl ContractRepository {
    fn new(setup: &str, inputs: &Value) -> Self {
        let status = match setup {
            "issued_with_credential" | "issued_without_credential" => {
                CredentialTransactionStatus::Issued
            }
            "pending_transaction" => CredentialTransactionStatus::Pending,
            _ => CredentialTransactionStatus::Authorized,
        };
        let mut claims = Map::new();
        if setup == "dpop_bound_transaction" {
            claims.insert(
                "_dpop_jkt".to_owned(),
                Value::String("contract-dpop-jkt".to_owned()),
            );
        }
        Self {
            state: Arc::new(Mutex::new(ContractState {
                setup: setup.to_owned(),
                transaction: CredentialTransaction {
                    id: inputs["transaction_id"].as_str().unwrap().to_owned(),
                    organization_id: inputs["organization_id"].as_str().unwrap().to_owned(),
                    credential_template_id: "template-credential".to_owned(),
                    revocation_profile_id: None,
                    renewal_of_credential_id: None,
                    applicant_id: None,
                    application_id: None,
                    subject_did: None,
                    status,
                    pre_authorized_code: "pre-auth-credential".to_owned(),
                    nonce: Some(inputs["proof_nonce"].as_str().unwrap().to_owned()),
                    claims,
                    credential_type: Some(inputs["credential_type"].as_str().unwrap().to_owned()),
                    selective_disclosure_claims: vec![],
                    credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
                    wallet_configs: vec![],
                    validity_days: 365,
                    issuer_profile_id: Some("issuer-profile-1".to_owned()),
                    issuer_mode: "org_managed".to_owned(),
                    issuer_did: Some("did:web:issuer.example".to_owned()),
                    issuer_algorithm: Some("ES256".to_owned()),
                    signing_service_id: Some("managed-custody".to_owned()),
                    reserved_credential_id: None,
                },
                calls: vec![],
            })),
        }
    }

    fn calls(&self) -> Vec<Value> {
        self.state.lock().unwrap().calls.clone()
    }
}

#[async_trait]
impl CredentialRepository for ContractRepository {
    async fn transaction_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "get_by_access_token", "value": access_token}));
        if state.setup == "missing_transaction" || access_token != "access-token-credential" {
            Ok(None)
        } else {
            Ok(Some(state.transaction.clone()))
        }
    }

    async fn authorization_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialAuthorizationSession>, CredentialIssuanceError> {
        self.state.lock().unwrap().calls.push(json!({
            "method": "get_authorization_session_by_access_token",
            "value": access_token
        }));
        Ok(None)
    }

    async fn ensure_authorization_transaction(
        &self,
        _session: &CredentialAuthorizationSession,
        _access_token: &str,
    ) -> Result<CredentialTransaction, CredentialIssuanceError> {
        unreachable!("admission contract has no valid authorization session")
    }

    async fn credential_by_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ExistingCredential>, CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(json!({
            "method": "get_credential_by_transaction_id",
            "value": transaction_id
        }));
        Ok(
            (state.setup == "issued_with_credential").then(|| ExistingCredential {
                id: "credential-canonical".to_owned(),
                credential: "signed-credential".to_owned(),
            }),
        )
    }

    async fn transaction_by_id(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        unreachable!("admission contract stops before a signing claim")
    }

    async fn claim_for_signing(
        &self,
        _transaction: &CredentialTransaction,
        _credential_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        unreachable!("admission contract stops before a signing claim")
    }

    async fn finalize(
        &self,
        _transaction: &CredentialTransaction,
        _credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        unreachable!("admission contract stops before finalization")
    }

    async fn mark_failed_if_signing(
        &self,
        _transaction_id: &str,
        _reason: &str,
    ) -> Result<(), CredentialIssuanceError> {
        Ok(())
    }
}

#[async_trait]
impl ProofNonceRepository for ContractRepository {
    async fn save_proof_nonce(
        &self,
        _nonce: &str,
        _ttl_seconds: u64,
    ) -> Result<bool, ProofNonceError> {
        unreachable!("credential admission only consumes proof nonces")
    }

    async fn consume_proof_nonce(&self, nonce: &str) -> Result<bool, ProofNonceError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(json!({"method": "consume_proof_nonce", "value": nonce}));
        match state.setup.as_str() {
            "nonce_store_unavailable" => Err(ProofNonceError::RepositoryUnavailable),
            "nonce_replayed" => Ok(false),
            _ => Ok(true),
        }
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
        match proof {
            "invalid-dpop" => Err(TokenExchangeError::InvalidDpopProof),
            "other-dpop" => Ok("other-dpop-jkt".to_owned()),
            _ => Ok("contract-dpop-jkt".to_owned()),
        }
    }
}

struct ContractProofVerifier {
    setup: Arc<str>,
}

#[async_trait]
impl CredentialProofVerifier for ContractProofVerifier {
    async fn verify(
        &self,
        _proof_jwt: &str,
        _expected_nonce: &str,
        _organization_id: &str,
        _issuer: &IssuerContext,
    ) -> Result<VerifiedCredentialProof, CredentialIssuanceError> {
        if self.setup.as_ref() == "invalid_signature" {
            Err(CredentialIssuanceError::InvalidProof(
                "invalid signature".to_owned(),
            ))
        } else {
            Ok(VerifiedCredentialProof {
                holder_did: "did:key:contract-holder".to_owned(),
                holder_jwk: None,
            })
        }
    }
}

struct ContractIssuer;

#[async_trait]
impl IssuerContextResolver for ContractIssuer {
    async fn resolve(
        &self,
        _transaction: &CredentialTransaction,
        _credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        Ok(IssuerContext {
            issuer_profile_id: "issuer-profile-1".to_owned(),
            issuer_did: "did:web:issuer.example".to_owned(),
            signing_service_id: "managed-custody".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: None,
            public_jwk: None,
            certificate_chain: vec![],
            raw_context: json!({}),
        })
    }
}

struct UnreachableBuilder;

#[async_trait]
impl CredentialBuilder for UnreachableBuilder {
    async fn build(
        &self,
        _request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        unreachable!("admission contract stops before credential building")
    }
}

struct UnreachableLifecycle;

#[async_trait]
impl CredentialLifecycle for UnreachableLifecycle {
    async fn ensure_ready(
        &self,
        _transaction: &CredentialTransaction,
        _issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        unreachable!("admission contract stops before readiness")
    }

    async fn allocate_status(
        &self,
        _transaction: &CredentialTransaction,
        _credential_id: &str,
        _credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        unreachable!("admission contract stops before status allocation")
    }

    async fn after_issued(
        &self,
        _transaction: &CredentialTransaction,
        _credential: &IssuedCredential,
        _response_format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        unreachable!("admission contract stops before side effects")
    }
}

struct FixedNotification(String);

impl NotificationIdGenerator for FixedNotification {
    fn generate(&self) -> String {
        self.0.clone()
    }
}

fn app(repository: ContractRepository, setup: &str, inputs: &Value) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let service = CredentialIssuanceService::new(
        CredentialPorts {
            repository: Arc::new(repository.clone()),
            nonce_repository: Arc::new(repository),
            dpop_verifier: Arc::new(ContractDpop),
            proof_verifier: Arc::new(ContractProofVerifier {
                setup: Arc::from(setup),
            }),
            issuer_resolver: Arc::new(ContractIssuer),
            builder: Arc::new(UnreachableBuilder),
            lifecycle: Arc::new(UnreachableLifecycle),
            notification_ids: Arc::new(FixedNotification(
                inputs["notification_id"].as_str().unwrap().to_owned(),
            )),
        },
        "https://issuer.example",
    );
    router_with_credential_issuance(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        service,
    )
}

fn encode(value: Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
}

fn proof(kind: &str, inputs: &Value) -> String {
    if kind == "malformed" {
        return "malformed".to_owned();
    }
    let audience = match kind {
        "wrong_audience" => "https://issuer.example/org/other",
        "prefixed_audience" => "https://issuer.example/evil/org/org-a",
        _ => inputs["proof_audience"].as_str().unwrap(),
    };
    let mut payload = json!({"aud": audience});
    if kind != "missing_nonce" {
        payload["nonce"] = inputs["proof_nonce"].clone();
    }
    format!(
        "{}.{}.signature",
        encode(json!({"alg": "ES256"})),
        encode(payload)
    )
}

fn request(case: &Value, inputs: &Value) -> Request<Body> {
    let mut body = case["request"].clone();
    if let Some(kind) = body["proof"].as_str().map(str::to_owned) {
        body.as_object_mut().unwrap().remove("proof");
        body["proofs"] = json!({"jwt": [proof(&kind, inputs)]});
    }
    let mut builder = Request::post(inputs["path"].as_str().unwrap())
        .header("Host", "issuer.example")
        .header("Content-Type", "application/json");
    if let Some(authorization) = case["authorization"].as_str() {
        builder = builder.header("Authorization", authorization);
    }
    if let Some(headers) = case["headers"].as_object() {
        for (name, value) in headers {
            builder = builder.header(name, value.as_str().unwrap());
        }
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn native_credential_admission_matches_the_python_oracle() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-credential-admission.json"
    ))
    .unwrap();
    let inputs = &contract["inputs"];
    for case in contract["cases"].as_array().unwrap() {
        let setup = case["setup"].as_str().unwrap();
        let repository = ContractRepository::new(setup, inputs);
        let response = app(repository.clone(), setup, inputs)
            .oneshot(request(case, inputs))
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            case["status_code"].as_u64().unwrap() as u16,
            "{}",
            case["name"]
        );
        assert_eq!(body(response).await, case["body"], "{}", case["name"]);
        assert_eq!(
            repository.calls(),
            case["repository_calls"].as_array().unwrap().clone(),
            "{}",
            case["name"]
        );
    }
}
