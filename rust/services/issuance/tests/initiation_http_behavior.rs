use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
    http::router_with_initiation,
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
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Map, Value};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct ContractRepository {
    stored: Arc<Mutex<Option<CredentialTransaction>>>,
}

#[async_trait]
impl InitiationRepository for ContractRepository {
    async fn recover_idempotently(
        &self,
        _organization_id: &str,
        _binding: &IdempotencyBinding,
    ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
        Ok(None)
    }

    async fn reserve_idempotently(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<InitiationReservation, InitiationRepositoryError> {
        *self.stored.lock().unwrap() = Some(transaction.clone());
        Ok(InitiationReservation {
            transaction: transaction.clone(),
            created: true,
        })
    }
}

struct ContractOrganizations;

#[async_trait]
impl InitiationOrganizationValidator for ContractOrganizations {
    async fn validate(&self, organization_id: &str) -> OrganizationValidation {
        assert_eq!(organization_id, "org-1");
        OrganizationValidation::Found
    }
}

struct ContractClients;

#[async_trait]
impl InitiationClientRepository for ContractClients {
    async fn get(
        &self,
        _organization_id: &str,
        _client_id: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        Ok(None)
    }
}

struct ContractTemplates;

#[async_trait]
impl InitiationTemplateResolver for ContractTemplates {
    async fn resolve(
        &self,
        template_id: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError> {
        assert_eq!(template_id, "template-1");
        Ok(InitiationTemplate {
            credential_type: "EmployeeCredential".to_owned(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            revocation_profile_id: Some("profile-1".to_owned()),
            issuer_did: Some("did:web:issuer.example".to_owned()),
            issuer_algorithm: Some("ES256".to_owned()),
            ..InitiationTemplate::default()
        })
    }
}

struct ContractRevocation;

#[async_trait]
impl InitiationRevocationProfileValidator for ContractRevocation {
    async fn validate_active(
        &self,
        organization_id: &str,
        profile_id: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        assert_eq!(organization_id, "org-1");
        assert_eq!(profile_id, Some("profile-1"));
        Ok(())
    }
}

struct ContractApplications;

#[async_trait]
impl InitiationApplicationClaimsResolver for ContractApplications {
    async fn resolve(&self, _application_id: &str) -> Result<Option<Map<String, Value>>, ()> {
        Ok(None)
    }
}

struct ContractRelatedResources;

#[async_trait]
impl InitiationRelatedResourceValidator for ContractRelatedResources {
    async fn validate(
        &self,
        _credential_document: &Value,
    ) -> Result<(), InitiationDependencyError> {
        Ok(())
    }
}

struct ContractIssuer;

#[async_trait]
impl IssuerContextResolver for ContractIssuer {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        assert_eq!(
            transaction.issuer_did.as_deref(),
            Some("did:web:issuer.example")
        );
        assert_eq!(credential_format, "dc+sd-jwt");
        assert!(!force);
        Ok(IssuerContext {
            issuer_profile_id: "issuer-profile-1".to_owned(),
            issuer_did: "did:web:issuer.example".to_owned(),
            signing_service_id: "kms-service-1".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: Some("did:web:issuer.example#key-1".to_owned()),
            public_jwk: None,
            certificate_chain: Vec::new(),
            raw_context: json!({}),
        })
    }
}

struct ContractSeeds;

impl InitiationSeedGenerator for ContractSeeds {
    fn generate(&self) -> InitiationSeed {
        InitiationSeed {
            transaction_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            pre_authorized_code: "a".repeat(43),
        }
    }
}

struct ContractClock;

impl InitiationClock for ContractClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
            .single()
            .unwrap()
    }
}

struct ContractDidcomm;

#[async_trait]
impl InitiationDidcommDelivery for ContractDidcomm {
    async fn deliver(
        &self,
        _transaction: &CredentialTransaction,
        _holder_did: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
        Err(InitiationDidcommDeliveryError)
    }
}

fn app(repository: ContractRepository) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let initiation = InitiationService::new(
        InitiationPorts {
            repository: Arc::new(repository),
            organizations: Arc::new(ContractOrganizations),
            clients: Arc::new(ContractClients),
            templates: Arc::new(ContractTemplates),
            revocation_profiles: Arc::new(ContractRevocation),
            applications: Arc::new(ContractApplications),
            related_resources: Arc::new(ContractRelatedResources),
            issuer_resolver: Arc::new(ContractIssuer),
            seeds: Arc::new(ContractSeeds),
            clock: Arc::new(ContractClock),
        },
        "https://issuer.example",
    )
    .unwrap();
    let projector =
        InitiationOfferProjector::new("https://issuer.example", Arc::new(ContractDidcomm)).unwrap();
    router_with_initiation(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        InitiationHttpService::new(initiation, projector, Some("test-api-key")),
    )
}

fn request(body: impl Into<Body>, api_key: Option<&str>) -> Request<Body> {
    let mut request =
        Request::post("/v1/issuance/initiate").header("content-type", "application/json");
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    request.body(body.into()).unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn valid_request() -> Value {
    json!({
        "organization_id":"org-1",
        "credential_template_id":"template-1",
        "issuer_did":"did:web:issuer.example",
        "subject_did":"did:key:holder",
        "claims":{"role":"engineer"}
    })
}

#[tokio::test]
async fn native_initiation_http_route_projects_the_committed_transaction() {
    let repository = ContractRepository::default();
    let response = app(repository.clone())
        .oneshot(request(
            serde_json::to_vec(&valid_request()).unwrap(),
            Some("test-api-key"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = json_body(response).await;
    assert_eq!(body["id"], "00000000-0000-4000-8000-000000000001");
    assert_eq!(body["organization_id"], "org-1");
    assert_eq!(body["credential_template_id"], "template-1");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["pre_auth_code"], "a".repeat(43));
    assert!(body["credential_offer_uri"]
        .as_str()
        .unwrap()
        .starts_with("openid-credential-offer://"));
    let stored = repository.stored.lock().unwrap();
    let stored = stored.as_ref().expect("committed transaction");
    assert_eq!(stored.claims["role"], "engineer");
    assert_eq!(
        stored.issuer_profile_id.as_deref(),
        Some("issuer-profile-1")
    );
}

#[tokio::test]
async fn initiation_authentication_precedes_json_and_private_header_validation() {
    let repository = ContractRepository::default();
    let unauthorized = app(repository.clone())
        .oneshot(request("{", None))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let private_header = Request::post("/v1/issuance/initiate")
        .header("content-type", "application/json")
        .header("x-api-key", "test-api-key")
        .header("x-signing-service-id", "attacker-selected-key")
        .body(Body::from(serde_json::to_vec(&valid_request()).unwrap()))
        .unwrap();
    let private_header = app(repository.clone())
        .oneshot(private_header)
        .await
        .unwrap();
    assert_eq!(private_header.status(), 422);
    assert!(repository.stored.lock().unwrap().is_none());
}
