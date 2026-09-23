//! Actual candidate HTTP/admission/projector; controlled repository and delivery.
//! PostgreSQL, actual encryption and finalization have separate composed gates.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::response::IntoResponse;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
    credential_renewal::{
        self, CredentialRenewalService, RenewalRepository, RenewalRepositoryError, RenewalSource,
    },
    initiation::{
        IdempotencyBinding, InitiationApplicationClaimsResolver, InitiationClientRepository,
        InitiationClock, InitiationDependencyError, InitiationOrganizationValidator,
        InitiationPorts, InitiationRegisteredClient, InitiationRelatedResourceValidator,
        InitiationRepository, InitiationRepositoryError, InitiationReservation,
        InitiationRevocationProfileValidator, InitiationSeed, InitiationSeedGenerator,
        InitiationService, InitiationTemplate, InitiationTemplateResolver, OrganizationValidation,
    },
    initiation_http::InitiationHttpService,
    initiation_response::{
        InitiationDidcommDelivery, InitiationDidcommDeliveryError,
        InitiationDidcommDeliveryReceipt, InitiationOfferProjector,
    },
};
use serde_json::{json, Map, Value};
use tower::ServiceExt;

#[path = "support/renewal_reference_fixture.rs"]
mod reference;

struct Harness {
    source: Option<RenewalSource>,
    source_tx: Mutex<Option<CredentialTransaction>>,
    reserved: Mutex<Option<CredentialTransaction>>,
    calls: Mutex<Vec<&'static str>>,
    input: Value,
}

impl Harness {
    fn record(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
}

#[async_trait]
impl RenewalRepository for Harness {
    async fn source(&self, _: &str) -> Result<Option<RenewalSource>, RenewalRepositoryError> {
        self.record("source");
        Ok(self.source.clone())
    }
    async fn source_transaction(
        &self,
        _: &RenewalSource,
    ) -> Result<Option<CredentialTransaction>, RenewalRepositoryError> {
        self.record("source-transaction");
        Ok(self.source_tx.lock().unwrap().clone())
    }
    async fn bind_reservation(
        &self,
        transaction: &CredentialTransaction,
        source: &RenewalSource,
        application: Option<&str>,
    ) -> Result<CredentialTransaction, RenewalRepositoryError> {
        self.record("bind");
        assert_eq!(self.reserved.lock().unwrap().as_ref(), Some(transaction));
        let mut bound = transaction.clone();
        assert!(
            bound.renewal_of_credential_id.is_none()
                || bound.renewal_of_credential_id.as_deref() == Some(source.id.as_str())
        );
        bound.renewal_of_credential_id = Some(source.id.clone());
        bound.application_id = application.map(str::to_owned);
        *self.reserved.lock().unwrap() = Some(bound.clone());
        Ok(bound)
    }
}

#[async_trait]
impl InitiationRepository for Harness {
    async fn recover_idempotently(
        &self,
        organization: &str,
        binding: &IdempotencyBinding,
    ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
        self.record("recover");
        let stored = self.reserved.lock().unwrap().clone();
        if let Some(value) = &stored {
            assert_eq!(value.organization_id, organization);
            assert_eq!(
                value.idempotency_key_hash.as_deref(),
                Some(binding.key_hash.as_str())
            );
            if value.idempotency_request_hash.as_deref() != Some(binding.request_hash.as_str()) {
                return Err(InitiationRepositoryError::IdempotencyConflict);
            }
        }
        Ok(stored)
    }
    async fn reserve_idempotently(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<InitiationReservation, InitiationRepositoryError> {
        self.record("reserve");
        assert!(transaction.renewal_of_credential_id.is_none());
        assert!(transaction.application_id.is_none());
        *self.reserved.lock().unwrap() = Some(transaction.clone());
        Ok(InitiationReservation {
            transaction: transaction.clone(),
            created: true,
        })
    }
}

#[async_trait]
impl InitiationOrganizationValidator for Harness {
    async fn validate(&self, _: &str) -> OrganizationValidation {
        self.record("organization");
        OrganizationValidation::Found
    }
}
#[async_trait]
impl InitiationClientRepository for Harness {
    async fn get(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        panic!("renewal has no authorized client")
    }
}
#[async_trait]
impl InitiationTemplateResolver for Harness {
    async fn resolve(
        &self,
        template: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError> {
        self.record("template");
        assert_eq!(template, "synthetic-template");
        let mut wallets = vec![];
        if self.input["automatic"] == true {
            wallets.push(json!({"wallet_id":"didcomm", "format_variant":"didcomm_v2", "display_name":"Synthetic DIDComm"}));
        }
        if self.input["mixed"] == true {
            wallets.push(json!({"wallet_id":"ordinary", "format_variant":"w3c_vcdm_v2_sd_jwt", "display_name":"Ordinary"}));
        }
        Ok(InitiationTemplate {
            credential_type: "EmployeeCredential".into(),
            vct: Some("https://issuer.example/credentials/EmployeeCredential".into()),
            issuer_did: Some("did:example:renewal-issuer".into()),
            issuer_algorithm: Some("ES256".into()),
            revocation_profile_id: Some("synthetic-revocation-profile".into()),
            wallet_configs: wallets,
            renewable: true,
            renewal_window_days: 7,
            ..InitiationTemplate::default()
        })
    }
}
#[async_trait]
impl InitiationRevocationProfileValidator for Harness {
    async fn validate_active(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        self.record("revocation");
        Ok(())
    }
}
#[async_trait]
impl InitiationApplicationClaimsResolver for Harness {
    async fn resolve(&self, _: &str) -> Result<Option<Map<String, Value>>, ()> {
        panic!("trusted application link must not change renewal claims")
    }
}
#[async_trait]
impl InitiationRelatedResourceValidator for Harness {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        panic!("no document input")
    }
}
impl InitiationClock for Harness {
    fn now(&self) -> DateTime<Utc> {
        "2023-11-14T22:13:20+00:00".parse().unwrap()
    }
}
impl InitiationSeedGenerator for Harness {
    fn generate(&self) -> InitiationSeed {
        self.record("seed");
        InitiationSeed {
            transaction_id: "00000000-0000-0000-0000-000000000001".into(),
            pre_authorized_code: "synthetic-pre-auth-code".into(),
        }
    }
}
#[async_trait]
impl IssuerContextResolver for Harness {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        _: &str,
        _: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        self.record("issuer");
        assert!(transaction.renewal_of_credential_id.is_none());
        assert!(transaction.application_id.is_none());
        Ok(IssuerContext {
            issuer_profile_id: "synthetic-issuer-profile".into(),
            issuer_did: "did:example:renewal-issuer".into(),
            signing_service_id: "synthetic-signing-service".into(),
            algorithm: "ES256".into(),
            verification_method_id: None,
            public_jwk: None,
            certificate_chain: vec![],
            raw_context: json!({}),
        })
    }
}
#[async_trait]
impl InitiationDidcommDelivery for Harness {
    async fn deliver(
        &self,
        transaction: &CredentialTransaction,
        holder: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
        self.record("controlled-delivery");
        assert_eq!(holder, "did:example:renewal-holder");
        assert_eq!(
            transaction.renewal_of_credential_id.as_deref(),
            Some("synthetic-source-credential")
        );
        assert_eq!(
            transaction.application_id.as_deref(),
            Some("synthetic-application")
        );
        assert_eq!(self.reserved.lock().unwrap().as_ref(), Some(transaction));
        if self.input["wallet_status"] == 503 {
            return Err(InitiationDidcommDeliveryError);
        }
        Ok(InitiationDidcommDeliveryReceipt {
            service_endpoint: "https://wallet.example/renewal-inbox".into(),
            delivered: true,
        })
    }
}

fn setup(corpus: &Value, case: &Value) -> (axum::Router, Arc<Harness>) {
    let snapshot = reference::snapshot(corpus, case, "before");
    let harness = Arc::new(Harness {
        source: reference::source(snapshot),
        source_tx: Mutex::new(
            snapshot["transactions"]
                .as_array()
                .unwrap()
                .first()
                .map(reference::transaction),
        ),
        reserved: Mutex::new(None),
        calls: Mutex::new(vec![]),
        input: case["input"].clone(),
    });
    let initiation = InitiationService::new(
        InitiationPorts {
            repository: harness.clone(),
            organizations: harness.clone(),
            clients: harness.clone(),
            templates: harness.clone(),
            revocation_profiles: harness.clone(),
            applications: harness.clone(),
            related_resources: harness.clone(),
            issuer_resolver: harness.clone(),
            seeds: harness.clone(),
            clock: harness.clone(),
        },
        "https://issuer.example",
    )
    .unwrap();
    let projector =
        InitiationOfferProjector::new("https://issuer.example", harness.clone()).unwrap();
    let service = CredentialRenewalService::new(
        harness.clone(),
        InitiationHttpService::new(
            initiation,
            projector,
            Some("synthetic-renewal-management-key"),
        ),
        Some("synthetic-renewal-management-key"),
        harness.clone(),
    );
    (credential_renewal::router(service), harness)
}

async fn request(router: &axum::Router, case: &Value) -> Value {
    let guard = case["input"]["guard"].as_str().unwrap_or_default();
    let mut request = Request::post("/v1/issued-credentials/synthetic-source-credential/renew");
    if guard != "missing-key" {
        request = request.header(
            "X-API-Key",
            if guard == "wrong-key" {
                "wrong"
            } else {
                "synthetic-renewal-management-key"
            },
        );
    }
    if guard != "missing-tenant" {
        request = request.header(
            "X-Organization-ID",
            if guard == "foreign-tenant" {
                "other-org"
            } else {
                "synthetic-org"
            },
        );
    }
    if let Some(key) = case["input"]["key"].as_str() {
        request = request.header("Idempotency-Key", key);
    }
    if guard == "invalid-idempotency-key" {
        request = request.header("Idempotency-Key", "invalid key");
    }
    if guard == "direct-signing-header" {
        request = request.header("X-Signing-Service-ID", "forbidden");
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    json!({"status":status, "content_type":content_type, "body":body})
}

#[tokio::test]
async fn renewal_http_matches_frozen_guards_offers_and_explicit_native_failure_correction() {
    let corpus = reference::corpus();
    let mut observed = 0;
    for case in corpus["cases"].as_array().unwrap() {
        if case["input"]["direct_after"] == true {
            continue;
        } // Actual composed delivery gate owns this.
        observed += 1;
        let (router, harness) = setup(&corpus, case);
        let mut expected = case["responses"][0].clone();
        if case["input"]["wallet_status"] == 503 {
            expected["body"]["credential_offer_uris"]["didcomm"] =
                json!("didcomm://pending?transaction_id=00000000-0000-0000-0000-000000000001");
        }
        assert_eq!(request(&router, case).await, expected, "{}", case["case"]);
        let calls = harness.calls.lock().unwrap().clone();
        if expected["status"] != 200 {
            assert!(harness.reserved.lock().unwrap().is_none());
            assert!(!calls
                .iter()
                .any(|value| matches!(*value, "issuer" | "seed" | "controlled-delivery" | "bind")));
            if matches!(case["case"].as_str(), Some("missing-key" | "wrong-key")) {
                assert!(calls.is_empty());
            }
            if case["input"]["guard"].is_string() {
                let expected_reads: Vec<_> = case["observations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(
                        |row| match (row["repository"].as_str(), row["id"].as_str()) {
                            (Some("get_credential"), Some("synthetic-source-credential")) => {
                                Some("source")
                            }
                            (Some("get_transaction"), Some("synthetic-source-transaction")) => {
                                Some("source-transaction")
                            }
                            _ => None,
                        },
                    )
                    .collect();
                assert_eq!(
                    calls, expected_reads,
                    "ordered frozen guard reads: {}",
                    case["case"]
                );
            }
        } else {
            // Compare the complete typed admission transaction. Actual delivery
            // is controlled here; the full real delivery state is a composed gate.
            let wallet = case["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["port"] == "wallet-http");
            let snapshot = if let Some(wallet) = wallet {
                let digest = wallet["state_at_send"]["$ref"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("#/states/")
                    .unwrap();
                &corpus["states"][digest]
            } else {
                reference::snapshot(&corpus, case, "after_first")
            };
            let mut expected_transaction = reference::transaction(&snapshot["transactions"][0]);
            // RENEWAL-001: the sole admission delta from the old send snapshot.
            expected_transaction.renewal_of_credential_id =
                Some("synthetic-source-credential".into());
            expected_transaction.application_id = Some("synthetic-application".into());
            assert_eq!(
                harness.reserved.lock().unwrap().as_ref(),
                Some(&expected_transaction),
                "full admission snapshot: {}",
                case["case"]
            );
        }
        if case["input"]["retry"] == true || case["input"]["conflict"] == true {
            let before = harness.reserved.lock().unwrap().clone();
            harness.calls.lock().unwrap().clear();
            if case["input"]["conflict"] == true {
                harness
                    .source_tx
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .claims
                    .insert("name".into(), json!("Changed Synthetic Holder"));
            }
            assert_eq!(request(&router, case).await, case["responses"][1]);
            assert_eq!(*harness.reserved.lock().unwrap(), before);
            let calls = harness.calls.lock().unwrap();
            assert!(!calls.iter().any(|value| matches!(
                *value,
                "issuer" | "seed" | "template" | "controlled-delivery"
            )));
            let frozen_after = reference::snapshot(&corpus, case, "after_first");
            let frozen_tx = &frozen_after["transactions"][0];
            let transaction = before.unwrap();
            assert_eq!(
                transaction.idempotency_key_hash.as_deref(),
                frozen_tx["idempotency_key_hash"].as_str()
            );
            assert_eq!(
                transaction.idempotency_request_hash.as_deref(),
                frozen_tx["idempotency_request_hash"].as_str()
            );
        }
    }
    assert_eq!(observed, 29);
}

#[test]
fn renewal_response_contract_retains_existing_gateway_six_field_projection() {
    let fixture = reference::corpus();
    let response = &reference::case(&fixture, "ordinary-offer")["responses"][0]["body"];
    assert_eq!(response.as_object().unwrap().len(), 6);
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/gateway-issuance-response-projection.json"
    ))
    .unwrap();
    let existing = contract["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == "renewal_offer_hides_internal_codes")
        .unwrap();
    assert_eq!(
        response
            .as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>(),
        existing["expected"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
    );
}

#[tokio::test]
async fn missing_reservation_preserves_legacy_503_instead_of_binding_conflict() {
    let response =
        credential_renewal::RenewalError::Repository(RenewalRepositoryError::ReservationMissing)
            .into_response();
    assert_eq!(response.status(), 503);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"detail":"Renewal transaction was not persisted."})
    );
}
