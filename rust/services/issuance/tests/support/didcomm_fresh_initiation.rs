//! Controlled admission dependencies only. The HTTP service, initiation owner,
//! PostgreSQL reservation and shared DIDComm graph are production implementations.
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    http::router_with_initiation,
    initiation::{
        InitiationApplicationClaimsResolver, InitiationClientRepository, InitiationClock,
        InitiationDependencyError, InitiationOrganizationValidator, InitiationPorts,
        InitiationRegisteredClient, InitiationRelatedResourceValidator,
        InitiationRevocationProfileValidator, InitiationSeed, InitiationSeedGenerator,
        InitiationService, InitiationTemplate, InitiationTemplateResolver, OrganizationValidation,
    },
    initiation_http::InitiationHttpService,
};
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

use super::{
    transaction, ControlledIssuer, InitiationOfferProjector, IssuanceRuntime,
    IssuanceServiceConfig, NativeInitiationDidcommDelivery, PostgresCredentialRepository,
    StaticDiscoveryDocuments, TransportPolicy, API_KEY, FORMAT, HOLDER, ISSUER, ORGANIZATION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scenario {
    ExplicitHolder,
    MixedWallet,
    SubjectOnly,
    MissingHolder,
    WalletRefused,
}

impl Scenario {
    pub(super) fn python_case(self) -> &'static str {
        match self {
            Self::ExplicitHolder => "success_holder",
            Self::MixedWallet => "multiple_wallets",
            Self::SubjectOnly => "subject_fallback",
            Self::MissingHolder => "missing_holder",
            // The frozen projector corpus uses a controlled delivery exception;
            // this composed case reaches the same pending result after real HTTP 503.
            Self::WalletRefused => "preflight_failure",
        }
    }
}

pub(super) struct Admission {
    id: String,
    scenario: Scenario,
    pub(super) seeds: AtomicUsize,
}

#[async_trait]
impl InitiationOrganizationValidator for Admission {
    async fn validate(&self, organization_id: &str) -> OrganizationValidation {
        assert_eq!(organization_id, ORGANIZATION);
        OrganizationValidation::Found
    }
}
#[async_trait]
impl InitiationClientRepository for Admission {
    async fn get(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        panic!("these admission requests have no registered-client selection")
    }
}
#[async_trait]
impl InitiationTemplateResolver for Admission {
    async fn resolve(&self, id: &str) -> Result<InitiationTemplate, InitiationDependencyError> {
        assert_eq!(id, "didcomm-template");
        let mut wallets = transaction(&self.id).wallet_configs;
        if self.scenario == Scenario::MixedWallet {
            wallets.push(json!({"wallet_id":"ordinary","format_variant":"default","display_name":"Ordinary Wallet","deep_link_scheme":"synthetic-wallet://open?source=fixture"}));
        }
        Ok(InitiationTemplate {
            credential_type: "EmployeeCredential".into(),
            credential_payload_format: FORMAT.into(),
            revocation_profile_id: Some("didcomm-status".into()),
            issuer_did: Some(ISSUER.into()),
            issuer_algorithm: Some("EdDSA".into()),
            wallet_configs: wallets,
            ..InitiationTemplate::default()
        })
    }
}
#[async_trait]
impl InitiationRevocationProfileValidator for Admission {
    async fn validate_active(
        &self,
        organization: &str,
        profile: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        assert_eq!(organization, ORGANIZATION);
        assert_eq!(profile, Some("didcomm-status"));
        Ok(())
    }
}
#[async_trait]
impl InitiationApplicationClaimsResolver for Admission {
    async fn resolve(&self, _: &str) -> Result<Option<Map<String, Value>>, ()> {
        panic!("explicit claims require no application lookup")
    }
}
#[async_trait]
impl InitiationRelatedResourceValidator for Admission {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        panic!("SD-JWT explicit claims require no related document lookup")
    }
}
impl InitiationSeedGenerator for Admission {
    fn generate(&self) -> InitiationSeed {
        assert_eq!(
            self.seeds.fetch_add(1, Ordering::SeqCst),
            0,
            "only one fresh HTTP initiation"
        );
        InitiationSeed {
            transaction_id: self.id.clone(),
            pre_authorized_code: format!("pre-auth-{}", self.id),
        }
    }
}
impl InitiationClock for Admission {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).single().unwrap()
    }
}

pub(super) fn router(
    repository: Arc<PostgresCredentialRepository>,
    delivery: Arc<NativeInitiationDidcommDelivery>,
    issuer: Arc<ControlledIssuer>,
    id: &str,
    scenario: Scenario,
) -> (Router, Arc<Admission>) {
    let admission = Arc::new(Admission {
        id: id.into(),
        scenario,
        seeds: AtomicUsize::new(0),
    });
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let service = InitiationService::new(
        InitiationPorts {
            repository,
            organizations: admission.clone(),
            clients: admission.clone(),
            templates: admission.clone(),
            revocation_profiles: admission.clone(),
            applications: admission.clone(),
            related_resources: admission.clone(),
            issuer_resolver: issuer,
            seeds: admission.clone(),
            clock: admission.clone(),
        },
        "https://issuer.example",
    )
    .unwrap();
    let projector = InitiationOfferProjector::new("https://issuer.example", delivery).unwrap();
    (
        router_with_initiation(
            runtime.state(),
            StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
            TransportPolicy::new([]),
            InitiationHttpService::new(service, projector, Some(API_KEY)),
        ),
        admission,
    )
}

pub(super) fn request_body(scenario: Scenario) -> Value {
    let mut body = json!({
        "organization_id":ORGANIZATION, "credential_template_id":"didcomm-template",
        "issuer_did":ISSUER, "holder_did":HOLDER, "claims":{"given_name":"Synthetic"},
    });
    if matches!(scenario, Scenario::SubjectOnly | Scenario::MissingHolder) {
        body.as_object_mut().unwrap().remove("holder_did");
    }
    if scenario == Scenario::SubjectOnly {
        body["subject_did"] = json!(HOLDER);
    }
    body
}

pub(super) async fn request(
    router: &Router,
    scenario: Scenario,
    keyed: bool,
) -> (StatusCode, Value) {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    assert_eq!(contract["surface"]["http"]["method"], "POST");
    let mut request = Request::post(contract["surface"]["http"]["path"].as_str().unwrap())
        .header("content-type", "application/json")
        .header("x-api-key", API_KEY)
        .header("x-organization-id", ORGANIZATION);
    if keyed {
        request = request.header("idempotency-key", "synthetic-fresh-didcomm-key");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(request_body(scenario).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["content-type"], "application/json");
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap(),
    )
}
