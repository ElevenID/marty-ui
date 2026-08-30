use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::{
    credential::{
        AllocatedCredentialStatus, BuiltCredential, CredentialAuthorizationSession,
        CredentialBuildRequest, CredentialBuilder, CredentialBuilderKind, CredentialIssuanceError,
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
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;

#[derive(Clone)]
struct SigningHarness {
    state: Arc<Mutex<SigningState>>,
    build_started: Arc<Notify>,
    release_build: Arc<Notify>,
}

struct SigningState {
    transaction: CredentialTransaction,
    existing: Option<ExistingCredential>,
    events: Vec<String>,
    remote_formats: Vec<String>,
    build_request: Option<CredentialBuildRequest>,
    builder_count: usize,
    authorization_only: bool,
    ensure_transaction_count: usize,
    block_builder: bool,
}

impl SigningHarness {
    fn new(case: &Value, contract: &Value) -> Self {
        let inputs = &contract["inputs"];
        let claim_policy = &contract["claim_policy"];
        let mut claims = claim_policy["preserved_fixture"]
            .as_object()
            .unwrap()
            .clone();
        for field in claim_policy["excluded"].as_array().unwrap() {
            claims.insert(
                field.as_str().unwrap().to_owned(),
                Value::String(format!("internal-{}", field.as_str().unwrap())),
            );
        }
        claims.insert(
            "_vct".to_owned(),
            Value::String(format!(
                "https://issuer.example/credentials/{}",
                case["credential_type"].as_str().unwrap()
            )),
        );
        claims.insert(
            "_credential_subject".to_owned(),
            json!({"id": "did:key:stored-subject", "role": "member"}),
        );
        let mut document = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", case["credential_type"]]
        });
        if let Some(id) = case["credential_document_id"].as_str() {
            document["id"] = Value::String(id.to_owned());
        }
        claims.insert("_credential_document".to_owned(), document);
        Self {
            state: Arc::new(Mutex::new(SigningState {
                transaction: CredentialTransaction {
                    id: inputs["transaction_id"].as_str().unwrap().to_owned(),
                    organization_id: inputs["organization_id"].as_str().unwrap().to_owned(),
                    credential_template_id: "template-signing-contract".to_owned(),
                    revocation_profile_id: None,
                    renewal_of_credential_id: None,
                    applicant_id: Some("applicant-signing-contract".to_owned()),
                    application_id: Some("application-signing-contract".to_owned()),
                    subject_did: None,
                    idempotency_key_hash: None,
                    idempotency_request_hash: None,
                    status: CredentialTransactionStatus::Authorized,
                    pre_authorized_code: "pre-auth-signing".to_owned(),
                    nonce: Some(inputs["proof_nonce"].as_str().unwrap().to_owned()),
                    claims,
                    credential_type: Some(case["credential_type"].as_str().unwrap().to_owned()),
                    selective_disclosure_claims: vec![],
                    zk_predicate_claims: vec![],
                    credential_payload_format: case["payload_format"].as_str().unwrap().to_owned(),
                    wallet_configs: vec![],
                    validity_days: 365,
                    renewable: false,
                    renewal_window_days: 30,
                    delivery_mode: "wallet_only".to_owned(),
                    issuer_profile_id: Some("issuer-profile-contract".to_owned()),
                    issuer_mode: "org_managed".to_owned(),
                    issuer_did: Some(inputs["issuer_did"].as_str().unwrap().to_owned()),
                    issuer_algorithm: Some(case["algorithm"].as_str().unwrap().to_owned()),
                    signing_service_id: Some("managed-custody-contract".to_owned()),
                    reserved_credential_id: None,
                    oid4vci_client_id: None,
                    created_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                },
                existing: None,
                events: vec![],
                remote_formats: vec![],
                build_request: None,
                builder_count: 0,
                authorization_only: false,
                ensure_transaction_count: 0,
                block_builder: false,
            })),
            build_started: Arc::new(Notify::new()),
            release_build: Arc::new(Notify::new()),
        }
    }

    fn authorization_only(case: &Value, contract: &Value) -> Self {
        let harness = Self::new(case, contract);
        let mut state = harness.state.lock().unwrap();
        state.authorization_only = true;
        state.transaction.id = contract["authorization_code_only"]["transaction_id"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(state);
        harness
    }

    fn event(&self, event: &str) {
        self.state.lock().unwrap().events.push(event.to_owned());
    }
}

#[async_trait]
impl CredentialRepository for SigningHarness {
    async fn transaction_by_access_token(
        &self,
        _access_token: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        let state = self.state.lock().unwrap();
        Ok((!state.authorization_only).then(|| state.transaction.clone()))
    }

    async fn authorization_by_access_token(
        &self,
        _access_token: &str,
    ) -> Result<Option<CredentialAuthorizationSession>, CredentialIssuanceError> {
        let state = self.state.lock().unwrap();
        if !state.authorization_only {
            return Ok(None);
        }
        Ok(Some(CredentialAuthorizationSession {
            id: "authorization-session-race".to_owned(),
            organization_id: state.transaction.organization_id.clone(),
            issuer_state: None,
            credential_configuration_ids: vec!["OpenBadgeCredential#sd-jwt".to_owned()],
            dpop_jkt: None,
        }))
    }

    async fn ensure_authorization_transaction(
        &self,
        _session: &CredentialAuthorizationSession,
        _access_token: &str,
    ) -> Result<CredentialTransaction, CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_transaction_count += 1;
        Ok(state.transaction.clone())
    }

    async fn credential_by_transaction(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<ExistingCredential>, CredentialIssuanceError> {
        Ok(self.state.lock().unwrap().existing.clone())
    }

    async fn transaction_by_id(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        Ok(Some(self.state.lock().unwrap().transaction.clone()))
    }

    async fn claim_for_signing(
        &self,
        _transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        state
            .events
            .push("claim_transaction_for_signing".to_owned());
        if state.transaction.status != CredentialTransactionStatus::Authorized {
            return Ok(None);
        }
        state.transaction.status = CredentialTransactionStatus::Signing;
        state.transaction.reserved_credential_id = Some(credential_id.to_owned());
        Ok(Some(state.transaction.clone()))
    }

    async fn finalize(
        &self,
        _transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        state.events.push("finalize_credential_issuance".to_owned());
        state.transaction.status = CredentialTransactionStatus::Issued;
        state.transaction.nonce = None;
        state.existing = Some(ExistingCredential {
            id: credential.id.clone(),
            credential: credential.credential.clone(),
        });
        Ok(())
    }

    async fn mark_failed_if_signing(
        &self,
        _transaction_id: &str,
        _reason: &str,
    ) -> Result<(), CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        if state.transaction.status == CredentialTransactionStatus::Signing {
            state.transaction.status = CredentialTransactionStatus::Failed;
        }
        Ok(())
    }
}

#[async_trait]
impl ProofNonceRepository for SigningHarness {
    async fn save_proof_nonce(
        &self,
        _nonce: &str,
        _ttl_seconds: u64,
    ) -> Result<bool, ProofNonceError> {
        unreachable!("signing fixture only consumes a nonce")
    }

    async fn consume_proof_nonce(&self, _nonce: &str) -> Result<bool, ProofNonceError> {
        self.event("consume_nonce");
        Ok(true)
    }
}

impl DpopProofVerifier for SigningHarness {
    fn verify(
        &self,
        _proof: &str,
        _method: &str,
        _expected_htu: &str,
    ) -> Result<String, TokenExchangeError> {
        Ok("unused-dpop-jkt".to_owned())
    }
}

#[async_trait]
impl CredentialProofVerifier for SigningHarness {
    async fn verify(
        &self,
        _proof_jwt: &str,
        _expected_nonce: &str,
        _organization_id: &str,
        _issuer: &IssuerContext,
    ) -> Result<VerifiedCredentialProof, CredentialIssuanceError> {
        self.event("verify_proof");
        Ok(VerifiedCredentialProof {
            holder_did: "did:key:contract-holder".to_owned(),
            holder_jwk: Some(json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "holder-x",
                "y": "holder-y"
            })),
        })
    }
}

#[async_trait]
impl IssuerContextResolver for SigningHarness {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        self.state
            .lock()
            .unwrap()
            .remote_formats
            .push(credential_format.to_owned());
        Ok(IssuerContext {
            issuer_profile_id: "issuer-profile-contract".to_owned(),
            issuer_did: "did:web:issuer.example".to_owned(),
            signing_service_id: "managed-custody-contract".to_owned(),
            algorithm: transaction.issuer_algorithm.clone().unwrap(),
            verification_method_id: Some("did:web:issuer.example#contract-key".to_owned()),
            public_jwk: Some(json!({"kty": "OKP", "crv": "Ed25519", "x": "issuer-x"})),
            certificate_chain: vec![],
            raw_context: json!({}),
        })
    }
}

#[async_trait]
impl CredentialLifecycle for SigningHarness {
    async fn ensure_ready(
        &self,
        _transaction: &CredentialTransaction,
        _issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        self.event("canvas_readiness");
        Ok(())
    }

    async fn allocate_status(
        &self,
        _transaction: &CredentialTransaction,
        _credential_id: &str,
        _credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        self.event("allocate_status");
        Ok(AllocatedCredentialStatus::default())
    }

    async fn after_issued(
        &self,
        _transaction: &CredentialTransaction,
        _credential: &IssuedCredential,
        _response_format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        self.event("post_issuance_side_effects");
        Ok(())
    }
}

#[async_trait]
impl CredentialBuilder for SigningHarness {
    async fn build(
        &self,
        request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        let block_builder = {
            let mut state = self.state.lock().unwrap();
            state.events.push("credential_builder".to_owned());
            state.events.push("issuer_did_sign".to_owned());
            state.build_request = Some(request.clone());
            state.builder_count += 1;
            state.block_builder
        };
        if block_builder {
            self.build_started.notify_one();
            self.release_build.notified().await;
        }
        tokio::task::yield_now().await;
        let credential = if request.kind == CredentialBuilderKind::DataIntegrity {
            json!({
                "id": request.credential_id,
                "proof": {"type": "DataIntegrityProof"}
            })
            .to_string()
        } else {
            format!("contract-{}-credential", builder_name(request.kind))
        };
        Ok(BuiltCredential {
            credential_id: request.credential_id.clone(),
            credential,
        })
    }
}

struct FixedNotification(String);

impl NotificationIdGenerator for FixedNotification {
    fn generate(&self) -> String {
        self.0.clone()
    }
}

fn builder_name(kind: CredentialBuilderKind) -> &'static str {
    match kind {
        CredentialBuilderKind::SdJwt => "sd_jwt",
        CredentialBuilderKind::JwtVcJson => "jwt_vc",
        CredentialBuilderKind::DataIntegrity => "data_integrity",
        CredentialBuilderKind::Mdoc => "mdoc",
    }
}

fn app(harness: SigningHarness, contract: &Value) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let service = CredentialIssuanceService::new(
        CredentialPorts {
            repository: Arc::new(harness.clone()),
            nonce_repository: Arc::new(harness.clone()),
            dpop_verifier: Arc::new(harness.clone()),
            proof_verifier: Arc::new(harness.clone()),
            issuer_resolver: Arc::new(harness.clone()),
            builder: Arc::new(harness.clone()),
            lifecycle: Arc::new(harness),
            notification_ids: Arc::new(FixedNotification(
                contract["inputs"]["notification_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
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

fn request(case: &Value, contract: &Value) -> Request<Body> {
    let inputs = &contract["inputs"];
    let proof = format!(
        "{}.{}.signature",
        encode(json!({"alg": "ES256"})),
        encode(json!({
            "aud": inputs["proof_audience"],
            "nonce": inputs["proof_nonce"]
        }))
    );
    let body = json!({
        "credential_configuration_id": case["credential_configuration_id"],
        "proofs": {"jwt": [proof]}
    });
    Request::post(inputs["path"].as_str().unwrap())
        .header("Host", "issuer.example")
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!("Bearer {}", inputs["access_token"].as_str().unwrap()),
        )
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn assert_subsequence(actual: &[String], expected: &[Value]) {
    let mut position = 0;
    for event in actual {
        if position < expected.len() && expected[position].as_str() == Some(event) {
            position += 1;
        }
    }
    assert_eq!(position, expected.len(), "events={actual:?}");
}

#[tokio::test]
async fn native_credential_signing_matches_every_python_format_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-credential-signing.json"
    ))
    .unwrap();
    for case in contract["formats"].as_array().unwrap() {
        let harness = SigningHarness::new(case, &contract);
        let response = app(harness.clone(), &contract)
            .oneshot(request(case, &contract))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "{}", case["name"]);
        let response = body(response).await;
        assert_eq!(
            response["credentials"][0]["format"], case["response_format"],
            "{}",
            case["name"]
        );
        assert_eq!(
            response["notification_id"],
            contract["inputs"]["notification_id"]
        );

        let state = harness.state.lock().unwrap();
        let build = state.build_request.as_ref().unwrap();
        assert_eq!(builder_name(build.kind), case["builder"].as_str().unwrap());
        assert_eq!(
            build.remote_credential_format,
            case["remote_credential_format"]
        );
        assert_eq!(build.response_format, case["response_format"]);
        let expected_id = case["credential_document_id"]
            .as_str()
            .unwrap_or("urn:uuid:bfdc1781-37a5-5f2d-929d-76487fbe2241");
        assert_eq!(build.credential_id, expected_id);
        assert_eq!(
            build.claims,
            contract["claim_policy"]["preserved_fixture"]
                .as_object()
                .unwrap()
                .clone()
        );
        if case["holder_did_required"].as_bool().unwrap() {
            assert_eq!(
                build.subject_did.as_deref(),
                Some("did:key:contract-holder")
            );
        } else {
            assert_eq!(build.subject_did, None);
        }
        if case["holder_jwk_required"].as_bool().unwrap() {
            assert_eq!(build.holder_jwk.as_ref().unwrap()["kty"], "EC");
        }
        if build.kind == CredentialBuilderKind::SdJwt {
            assert_eq!(
                build.selective_disclosure_claims,
                contract["claim_policy"]["sd_jwt_default_disclosures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(
            state.remote_formats,
            vec![
                case["remote_credential_format"].as_str().unwrap(),
                case["remote_credential_format"].as_str().unwrap()
            ]
        );
        assert_subsequence(
            &state.events,
            contract["critical_order"].as_array().unwrap(),
        );
        assert_eq!(
            state.transaction.status,
            CredentialTransactionStatus::Issued
        );
        assert_eq!(state.transaction.nonce, None);
        assert_eq!(state.existing.as_ref().unwrap().id, expected_id);
    }
}

async fn assert_single_concurrent_signer(harness: SigningHarness, case: &Value, contract: &Value) {
    harness.state.lock().unwrap().block_builder = true;
    let first_app = app(harness.clone(), contract);
    let first_request = request(case, contract);
    let first = tokio::spawn(async move { first_app.oneshot(first_request).await.unwrap() });

    harness.build_started.notified().await;
    let loser = app(harness.clone(), contract)
        .oneshot(request(case, contract))
        .await
        .unwrap();
    let expected = &contract["state_machine"]["concurrent_loser"];
    assert_eq!(
        loser.status().as_u16(),
        expected["status_code"].as_u64().unwrap() as u16
    );
    assert_eq!(body(loser).await, expected["body"]);

    harness.release_build.notify_one();
    let winner = first.await.unwrap();
    assert_eq!(winner.status().as_u16(), 200);

    let state = harness.state.lock().unwrap();
    assert_eq!(state.builder_count, 1);
    assert_eq!(
        state
            .events
            .iter()
            .filter(|event| event.as_str() == "issuer_did_sign")
            .count(),
        1
    );
    assert_eq!(
        state.transaction.status,
        CredentialTransactionStatus::Issued
    );
}

#[tokio::test]
async fn concurrent_pre_authorized_requests_have_one_signer_and_exact_loser_response() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-credential-signing.json"
    ))
    .unwrap();
    let case = &contract["formats"][0];
    assert_single_concurrent_signer(SigningHarness::new(case, &contract), case, &contract).await;
}

#[tokio::test]
async fn authorization_code_only_requests_share_deterministic_transaction_and_one_signer() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-credential-signing.json"
    ))
    .unwrap();
    let case = &contract["formats"][0];
    let harness = SigningHarness::authorization_only(case, &contract);
    assert_single_concurrent_signer(harness.clone(), case, &contract).await;

    let state = harness.state.lock().unwrap();
    assert_eq!(
        state.transaction.id,
        contract["authorization_code_only"]["transaction_id"]
    );
    assert_eq!(state.ensure_transaction_count, 2);
}
