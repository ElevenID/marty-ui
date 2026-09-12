//! Genuine ordinary-wallet HTTP admission recovery against published PostgreSQL.
//! Admission dependencies are controlled; no DIDComm delivery, gateway or KMS proof.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
    credential_postgres::PostgresCredentialRepository,
    http::router_with_initiation,
    initiation::{
        InitiationApplicationClaimsResolver, InitiationClientRepository, InitiationClock,
        InitiationDependencyError, InitiationOrganizationValidator, InitiationPorts,
        InitiationRegisteredClient, InitiationRelatedResourceValidator,
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
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const ID: &str = "ordinary-admission-recovery-synthetic";
const CODE: &str = "synthetic-ordinary-recovery-pre-authorized-code";
const API_KEY: &str = "synthetic-admission-management-key";

#[derive(Default)]
struct Ports {
    calls: Mutex<Vec<&'static str>>,
    recovery_only: AtomicBool,
}

impl Ports {
    fn record(&self, stage: &'static str) {
        assert!(
            !self.recovery_only.load(Ordering::SeqCst)
                || matches!(stage, "organization" | "client"),
            "recovery/conflict must precede {stage}"
        );
        self.calls.lock().unwrap().push(stage);
    }

    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait]
impl InitiationOrganizationValidator for Ports {
    async fn validate(&self, organization: &str) -> OrganizationValidation {
        self.record("organization");
        assert_eq!(organization, "org-1");
        OrganizationValidation::Found
    }
}

#[async_trait]
impl InitiationClientRepository for Ports {
    async fn get(
        &self,
        organization: &str,
        client: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        self.record("client");
        assert_eq!((organization, client), ("org-1", "client-1"));
        Ok(Some(InitiationRegisteredClient {
            client_id: client.into(),
            active: true,
            token_endpoint_auth_method: "private_key_jwt".into(),
        }))
    }
}

#[async_trait]
impl InitiationTemplateResolver for Ports {
    async fn resolve(
        &self,
        template: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError> {
        self.record("template");
        assert_eq!(template, "template-1");
        Ok(InitiationTemplate {
            credential_type: "EmployeeCredential".into(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".into(),
            issuer_did: Some("did:web:issuer.example".into()),
            issuer_algorithm: Some("EdDSA".into()),
            wallet_configs: vec![
                json!({"wallet_id":"ordinary", "format_variant":"default", "display_name":"Ordinary Wallet"}),
            ],
            ..InitiationTemplate::default()
        })
    }
}

#[async_trait]
impl InitiationRevocationProfileValidator for Ports {
    async fn validate_active(
        &self,
        organization: &str,
        profile: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        self.record("revocation");
        assert_eq!(organization, "org-1");
        assert!(profile.is_none());
        Ok(())
    }
}

#[async_trait]
impl InitiationApplicationClaimsResolver for Ports {
    async fn resolve(&self, _: &str) -> Result<Option<Map<String, Value>>, ()> {
        panic!("explicit frozen claims require no application lookup")
    }
}

#[async_trait]
impl InitiationRelatedResourceValidator for Ports {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        panic!("ordinary explicit claims require no related document lookup")
    }
}

impl InitiationClock for Ports {
    fn now(&self) -> chrono::DateTime<Utc> {
        self.record("clock");
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
            .single()
            .unwrap()
    }
}

impl InitiationSeedGenerator for Ports {
    fn generate(&self) -> InitiationSeed {
        self.record("seed");
        InitiationSeed {
            transaction_id: ID.into(),
            pre_authorized_code: CODE.into(),
        }
    }
}

#[async_trait]
impl IssuerContextResolver for Ports {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        self.record("issuer");
        assert_eq!(transaction.organization_id, "org-1");
        assert_eq!(format, "dc+sd-jwt");
        assert!(!force);
        Ok(IssuerContext {
            issuer_profile_id: "synthetic-profile".into(),
            issuer_did: "did:web:issuer.example".into(),
            signing_service_id: "controlled-not-invoked-signer".into(),
            algorithm: "EdDSA".into(),
            verification_method_id: Some("did:web:issuer.example#signing".into()),
            public_jwk: None,
            certificate_chain: vec![],
            raw_context: json!({}),
        })
    }
}

#[async_trait]
impl InitiationDidcommDelivery for Ports {
    async fn deliver(
        &self,
        _: &CredentialTransaction,
        _: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
        panic!("ordinary-wallet admission never invokes DIDComm delivery")
    }
}

fn router(repository: Arc<PostgresCredentialRepository>, ports: Arc<Ports>, ttl: &str) -> Router {
    let config =
        IssuanceServiceConfig::from_values([("ISSUANCE_OFFER_TTL_MINUTES".into(), ttl.into())])
            .unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let service = InitiationService::new(
        InitiationPorts {
            repository,
            organizations: ports.clone(),
            clients: ports.clone(),
            templates: ports.clone(),
            revocation_profiles: ports.clone(),
            applications: ports.clone(),
            related_resources: ports.clone(),
            issuer_resolver: ports.clone(),
            seeds: ports.clone(),
            clock: ports.clone(),
        },
        "https://issuer.example",
    )
    .unwrap()
    .with_offer_ttl_minutes(config.issuance_offer_ttl_minutes.clone());
    let projector = InitiationOfferProjector::new("https://issuer.example", ports).unwrap();
    router_with_initiation(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        InitiationHttpService::new(service, projector, Some(API_KEY)),
    )
}

async fn request(app: &Router, body: &Value, key: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/issuance/initiate")
                .header("content-type", "application/json")
                .header("x-api-key", API_KEY)
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "application/json");
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap(),
    )
}

async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
        'transaction', (SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1),
        'credentials', (SELECT count(*) FROM issuance_service.issued_credentials WHERE transaction_id=$1),
        'deliveries', (SELECT count(*) FROM issuance_service.credential_delivery_records WHERE transaction_id=$1),
        'events', (SELECT count(*) FROM issuance_service.issuance_events WHERE transaction_id=$1))")
        .bind(ID).fetch_one(pool).await.unwrap()
}

fn assert_created_response(response: &Value) {
    let offer_uri = response["credential_offer_uri"].as_str().unwrap();
    let parsed = url::Url::parse(offer_uri).unwrap();
    assert_eq!(parsed.scheme(), "openid-credential-offer");
    let pairs: Vec<_> = parsed.query_pairs().collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "credential_offer");
    assert_eq!(
        serde_json::from_str::<Value>(&pairs[0].1).unwrap(),
        json!({
            "credential_issuer":"https://issuer.example/org/org-1",
            "credential_configuration_ids":["EmployeeCredential#sd-jwt"],
            "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":CODE}}
        })
    );
    assert_eq!(
        response,
        &json!({"id":ID, "organization_id":"org-1", "credential_template_id":"template-1",
        "status":"pending", "credential_offer_uri":offer_uri, "credential_offer_uris":{"ordinary":offer_uri},
        "credential_offer_labels":{"ordinary":"Ordinary Wallet"}, "pre_auth_code":CODE,
        "expires_at":"2026-08-30T12:45:00+00:00"})
    );
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='5s'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .unwrap();
    let repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        b"synthetic-admission-recovery-hmac",
    ));
    let ports = Arc::new(Ports::default());
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    let vector = &contract["idempotency"]["vector"];
    let body = &vector["request"];
    let key = vector["key"].as_str().unwrap();
    assert_eq!(
        snapshot(&pool).await,
        json!({"transaction":null, "credentials":0, "deliveries":0, "events":0})
    );
    let app = router(repository.clone(), ports.clone(), "45");
    let created = request(&app, body, key).await;
    assert_eq!(created.0, StatusCode::OK);
    assert_created_response(&created.1);
    assert_eq!(
        ports.take(),
        [
            "organization",
            "client",
            "template",
            "revocation",
            "clock",
            "seed",
            "issuer"
        ]
    );
    let stored = snapshot(&pool).await;
    assert_eq!(
        stored["transaction"]["idempotency_key_hash"],
        vector["key_hash"]
    );
    assert_eq!(
        stored["transaction"]["idempotency_request_hash"],
        vector["request_hash"]
    );
    assert_eq!(stored["transaction"]["id"], ID);
    assert_eq!(stored["transaction"]["organization_id"], "org-1");
    assert_eq!(stored["transaction"]["oid4vci_client_id"], "client-1");
    assert_eq!(stored["credentials"], 0);
    assert_eq!(stored["deliveries"], 0);
    assert_eq!(stored["events"], 0);

    // These ports now panic beyond organization/client validation. Oversized
    // valid configuration would also fail any attempted new construction.
    ports.recovery_only.store(true, Ordering::SeqCst);
    for ttl in ["45", "-5", "9223372036854775808"] {
        let changed = router(repository.clone(), ports.clone(), ttl);
        assert_eq!(request(&changed, body, key).await, created);
        assert_eq!(ports.take(), ["organization", "client"]);
        assert_eq!(snapshot(&pool).await, stored);
        let mut conflict = body.clone();
        conflict["claims"]["profile"]["level"] = json!(3);
        let rejected = request(&changed, &conflict, key).await;
        assert_eq!(
            u64::from(rejected.0.as_u16()),
            contract["idempotency"]["different_request"]["http_status"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            rejected.1,
            json!({"detail":"idempotency key was already used for a different issuance request"})
        );
        assert_eq!(ports.take(), ["organization", "client"]);
        assert_eq!(snapshot(&pool).await, stored);
    }
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM issuance_service.issuance_transactions WHERE organization_id='org-1' AND idempotency_key_hash=$1")
        .bind(vector["key_hash"].as_str().unwrap()).fetch_one(&pool).await.unwrap(), 1);
    pool.close().await;
}
