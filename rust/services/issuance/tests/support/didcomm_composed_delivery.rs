//! Real native delivery, published-schema PostgreSQL, HTTPS and canonical Core crypto.
//! Issuer context, credential signing and the local DID/status HTTP peers are controlled.
//! This is not a packaged-service/gateway cutover or independent-wallet qualification.
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_didcomm::{types::ServiceEntry, DidDocument};
use marty_issuance_service::{
    canvas_issuance_guard::CanvasGuardConfig,
    config::IssuanceServiceConfig,
    credential::{
        BuiltCredential, CredentialBuildRequest, CredentialBuilder, CredentialIssuanceError,
        CredentialRepository, CredentialTransaction, CredentialTransactionStatus, IssuerContext,
        IssuerContextResolver,
    },
    credential_lifecycle::PostgresCredentialLifecycle,
    credential_postgres::PostgresCredentialRepository,
    http::router_with_didcomm_delivery,
    initiation::{InitiationRepository, InitiationRequest, InitiationReservation},
    initiation_didcomm::{
        DidcommEndpointValidator, DidcommTransport, NativeDidcommEnvelope,
        NativeInitiationDidcommDelivery, NativeInitiationDidcommPorts,
    },
    initiation_didcomm_http::InitiationDidcommHttpService,
    initiation_response::InitiationOfferProjector,
    transport::TransportPolicy,
    IssuanceRuntime,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::{
    sync::{oneshot, Semaphore},
    task::JoinHandle,
};
use tower::ServiceExt;

use super::{
    didcomm_test_fixtures::authcrypt_parties_with_ids, didcomm_wallet_fixture::WalletFixture,
};

const ISSUER: &str = "did:web:fixture.example:issuer";
const HOLDER: &str = "did:web:fixture.example:holder";
const ORGANIZATION: &str = "didcomm-composed-org";
const SIGNED_CREDENTIAL: &str = "synthetic-controlled-signed-credential";
const API_KEY: &str = "synthetic-didcomm-management-key";
const SERVICE_TOKEN: &str = "synthetic-didcomm-status-token";
const FORMAT: &str = "w3c_vcdm_v2_sd_jwt";

#[path = "didcomm_fresh_initiation.rs"]
mod fresh_initiation;
use fresh_initiation::Scenario as FreshScenario;

struct ControlledIssuer;

#[async_trait]
impl IssuerContextResolver for ControlledIssuer {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        assert_eq!(transaction.organization_id, ORGANIZATION);
        assert_eq!(format, "dc+sd-jwt");
        Ok(IssuerContext {
            issuer_profile_id: "didcomm-profile".into(),
            issuer_did: ISSUER.into(),
            signing_service_id: "controlled-signing-port".into(),
            algorithm: "EdDSA".into(),
            verification_method_id: Some(format!("{ISSUER}#signing-1")),
            public_jwk: None,
            certificate_chain: vec![],
            raw_context: json!({}),
        })
    }
}

struct ControlledBuilder {
    calls: AtomicUsize,
    allocations: Arc<Mutex<Vec<Value>>>,
    gate: Option<Arc<BuildGate>>,
}

/// Test-only rendezvous at the already-controlled signing port, after the actual
/// PostgreSQL claim and HTTP status allocation. No scheduling sleeps or mock claims.
struct BuildGate {
    entered: Semaphore,
    release: Semaphore,
}

impl BuildGate {
    fn new() -> Self {
        Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl CredentialBuilder for ControlledBuilder {
    async fn build(
        &self,
        request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        assert_eq!(request.organization_id, ORGANIZATION);
        assert_eq!(request.subject_did.as_deref(), Some(HOLDER));
        assert_eq!(request.issuer.issuer_did, ISSUER);
        assert_eq!(request.claims["given_name"], "Synthetic");
        assert_eq!(request.status_list_entries.len(), 1);
        assert_eq!(request.status_list_entries[0]["index"], 7);
        assert_eq!(
            self.allocations.lock().unwrap().last().unwrap()["credential_id"],
            request.credential_id
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.entered.add_permits(1);
            tokio::time::timeout(Duration::from_secs(10), gate.release.acquire())
                .await
                .expect("bounded controlled signing release")
                .unwrap()
                .forget();
        }
        Ok(BuiltCredential {
            credential_id: request.credential_id.clone(),
            credential: SIGNED_CREDENTIAL.into(),
        })
    }
}

#[derive(Clone)]
struct Peers {
    sender: DidDocument,
    recipient: DidDocument,
    resolutions: Arc<AtomicUsize>,
    allocations: Arc<AtomicUsize>,
    allocation_requests: Arc<Mutex<Vec<Value>>>,
}

async fn sender(State(state): State<Peers>) -> Json<DidDocument> {
    state.resolutions.fetch_add(1, Ordering::SeqCst);
    Json(state.sender)
}

async fn recipient(State(state): State<Peers>) -> Json<DidDocument> {
    state.resolutions.fetch_add(1, Ordering::SeqCst);
    Json(state.recipient)
}

async fn allocate(
    State(state): State<Peers>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["x-service-token"], SERVICE_TOKEN);
    assert_eq!(body["organization_id"], ORGANIZATION);
    assert_eq!(body["credential_format"], "sd_jwt_vc");
    assert!(body["credential_id"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    state.allocations.fetch_add(1, Ordering::SeqCst);
    state.allocation_requests.lock().unwrap().push(body);
    Json(
        json!({"organization_id":ORGANIZATION,"index":7,"status_list_url":"https://status.example/synthetic"}),
    )
}

struct OwnedPeers {
    origin: String,
    task: JoinHandle<()>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl OwnedPeers {
    async fn start(state: Peers) -> Self {
        let app = Router::new()
            .route("/issuer/did.json", get(sender))
            .route("/holder/did.json", get(recipient))
            .route(
                "/internal/revocation-profiles/didcomm-status/reserve-index",
                post(allocate),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            origin,
            task,
            shutdown: Some(shutdown),
        }
    }

    async fn close(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for OwnedPeers {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn transaction(id: &str) -> CredentialTransaction {
    CredentialTransaction {
        id: id.into(),
        organization_id: ORGANIZATION.into(),
        credential_template_id: "didcomm-template".into(),
        revocation_profile_id: Some("didcomm-status".into()),
        renewal_of_credential_id: None,
        applicant_id: None,
        application_id: None,
        subject_did: None,
        idempotency_key_hash: None,
        idempotency_request_hash: None,
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: format!("pre-auth-{id}"),
        nonce: None,
        claims: json!({"given_name":"Synthetic"})
            .as_object()
            .unwrap()
            .clone(),
        credential_type: Some("EmployeeCredential".into()),
        selective_disclosure_claims: vec![],
        zk_predicate_claims: vec![],
        credential_payload_format: FORMAT.into(),
        wallet_configs: vec![
            json!({"wallet_id":"didcomm","format_variant":"didcomm_v2","display_name":"Synthetic Wallet"}),
        ],
        validity_days: 365,
        renewable: false,
        renewal_window_days: 30,
        delivery_mode: "wallet_only".into(),
        issuer_profile_id: Some("didcomm-profile".into()),
        issuer_mode: "org_managed".into(),
        issuer_did: Some(ISSUER.into()),
        issuer_algorithm: Some("EdDSA".into()),
        signing_service_id: Some("controlled-signing-port".into()),
        reserved_credential_id: None,
        oid4vci_client_id: None,
        created_at: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
        expires_at: Utc.timestamp_opt(1_700_003_600, 0).single().unwrap(),
    }
}

fn direct_router(delivery: Arc<NativeInitiationDidcommDelivery>) -> Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    router_with_didcomm_delivery(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        InitiationDidcommHttpService::new(delivery, Some(API_KEY)),
    )
}

struct DirectEndpoint {
    router: Router,
    gateway: bool,
}

async fn direct_response(app: &DirectEndpoint, id: &str) -> (StatusCode, Value) {
    let request = Request::post("/v1/issuance/didcomm/deliver")
        .header("content-type", "application/json")
        .header(
            "x-api-key",
            if app.gateway {
                super::didcomm_gateway_replay::CLIENT_KEY
            } else {
                API_KEY
            },
        )
        .header("x-organization-id", ORGANIZATION)
        .body(Body::from(
            json!({"organization_id":ORGANIZATION,"transaction_id":id,"holder_did":HOLDER})
                .to_string(),
        ))
        .unwrap();
    let response = app.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let body = if app.gateway && !status.is_success() {
        super::didcomm_gateway_replay::assert_service_error_projection(body)
    } else {
        body
    };
    (status, body)
}

async fn direct(app: &DirectEndpoint, id: &str) -> Value {
    let (status, body) = direct_response(app, id).await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn gateway_state_errors(pool: &PgPool, app: &DirectEndpoint, id: &str) {
    assert!(app.gateway);
    let original = snapshot(pool, id).await;
    assert_eq!(original["transaction"]["status"], "pending");
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/didcomm-direct-state-python-reference.json"
    ))
    .unwrap();
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let changed =
            sqlx::query("UPDATE issuance_service.issuance_transactions SET status=$2 WHERE id=$1")
                .bind(id)
                .bind(case["state"].as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        assert_eq!(changed.rows_affected(), 1);
        let before = snapshot(pool, id).await;
        let (status, body) = direct_response(app, id).await;
        assert_eq!(u64::from(status.as_u16()), case["status"].as_u64().unwrap());
        assert_eq!(body, case["body"]);
        assert_eq!(
            snapshot(pool, id).await,
            before,
            "gateway state error has no durable effects"
        );
    }
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='pending' WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        snapshot(pool, id).await,
        original,
        "restore only the controlled eligibility input"
    );
}

async fn snapshot(pool: &PgPool, id: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
        'transaction', (SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1),
        'credentials', (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id), '[]'::jsonb) FROM issuance_service.issued_credentials c WHERE transaction_id=$1),
        'deliveries', (SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id), '[]'::jsonb) FROM issuance_service.credential_delivery_records d WHERE transaction_id=$1),
        'events', (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id), '[]'::jsonb) FROM issuance_service.issuance_events e WHERE transaction_id=$1))")
        .bind(id).fetch_one(pool).await.unwrap()
}

fn assert_offer(response: &Value, reservation: &InitiationReservation, endpoint: &str) {
    assert_offer_result(
        response,
        reservation,
        "issued",
        &format!("didcomm://{endpoint}"),
    );
}

fn assert_materialized_binding(state: &Value, transaction_id: &str, endpoint: &str) {
    assert_eq!(state["transaction"]["id"], transaction_id);
    assert_eq!(state["transaction"]["organization_id"], ORGANIZATION);
    let credential_id = &state["credentials"][0]["id"];
    assert!(credential_id.as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(
        &state["transaction"]["reserved_credential_id"],
        credential_id
    );
    for row in [&state["credentials"][0], &state["deliveries"][0]] {
        assert_eq!(row["organization_id"], ORGANIZATION);
        assert_eq!(row["transaction_id"], transaction_id);
    }
    let delivery = &state["deliveries"][0];
    assert_eq!(&delivery["credential_id"], credential_id);
    assert_eq!(delivery["delivery_target"], "didcomm_v2");
    assert_eq!(delivery["metadata"]["protocol"], "didcomm_v2");
    assert_eq!(delivery["metadata"]["holder_did"], HOLDER);
    assert_eq!(delivery["metadata"]["service_endpoint"], endpoint);
}

fn assert_offer_result(
    response: &Value,
    reservation: &InitiationReservation,
    status: &str,
    delivery_uri: &str,
) {
    let offer_uri = response["credential_offer_uri"].as_str().unwrap();
    let parsed = url::Url::parse(offer_uri).unwrap();
    assert_eq!(parsed.scheme(), "openid-credential-offer");
    let query: Vec<_> = parsed.query_pairs().collect();
    assert_eq!(query.len(), 1);
    assert_eq!(query[0].0, "credential_offer");
    let offer: Value = serde_json::from_str(&query[0].1).unwrap();
    assert_eq!(
        offer,
        json!({"credential_issuer":format!("https://issuer.example/org/{ORGANIZATION}"),"credential_configuration_ids":["EmployeeCredential#sd-jwt"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":reservation.transaction.pre_authorized_code}}})
    );
    let mut expected = json!({
        "id":reservation.transaction.id,"organization_id":ORGANIZATION,"credential_template_id":"didcomm-template","status":status,
        "credential_offer_uri":offer_uri,"credential_offer_uris":{"didcomm":delivery_uri},"credential_offer_labels":{"didcomm":"Synthetic Wallet"},
        "pre_auth_code":reservation.transaction.pre_authorized_code,"expires_at":reservation.transaction.expires_at.to_rfc3339()
    });
    if reservation
        .transaction
        .wallet_configs
        .iter()
        .any(|wallet| wallet["wallet_id"] == "ordinary")
    {
        let encoded = offer_uri
            .strip_prefix("openid-credential-offer://?credential_offer=")
            .unwrap();
        expected["credential_offer_uris"]["ordinary"] = json!(format!(
            "synthetic-wallet://open?source=fixture&credential_offer={encoded}"
        ));
        expected["credential_offer_labels"]["ordinary"] = json!("Ordinary Wallet");
    }
    assert_eq!(response, &expected);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    HttpRefused,
    UntrustedTls,
    WrongSenderKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    ConcurrentClaim,
    EventProjection,
    TlsTrust,
}

/// Scoped to one synthetic transaction in the caller's exact-owned disposable
/// database. The outer PublishedDatabase guard removes this object on panic;
/// successful recovery explicitly removes it and verifies all catalog entries.
async fn install_event_fault(pool: &PgPool, id: &str) {
    sqlx::query(
        "CREATE TABLE issuance_service.didcomm_composed_event_fault_target
         (transaction_id text PRIMARY KEY)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO issuance_service.didcomm_composed_event_fault_target VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION issuance_service.didcomm_composed_event_fault() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN
             IF EXISTS (SELECT 1 FROM issuance_service.didcomm_composed_event_fault_target
                        WHERE transaction_id = NEW.transaction_id) THEN
                 RAISE EXCEPTION 'synthetic exact-transaction event fault';
             END IF;
             RETURN NEW;
         END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER didcomm_composed_event_fault BEFORE INSERT
         ON issuance_service.issuance_events FOR EACH ROW
         EXECUTE FUNCTION issuance_service.didcomm_composed_event_fault()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn remove_event_fault(pool: &PgPool) {
    sqlx::query("DROP TRIGGER didcomm_composed_event_fault ON issuance_service.issuance_events")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION issuance_service.didcomm_composed_event_fault()")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.didcomm_composed_event_fault_target")
        .execute(pool)
        .await
        .unwrap();
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT NOT EXISTS (SELECT 1 FROM pg_trigger
            WHERE tgrelid = 'issuance_service.issuance_events'::regclass
              AND tgname = 'didcomm_composed_event_fault')
         AND to_regprocedure('issuance_service.didcomm_composed_event_fault()') IS NULL
         AND to_regclass('issuance_service.didcomm_composed_event_fault_target') IS NULL",
    )
    .fetch_one(pool)
    .await
    .unwrap());
}

fn decrypt_capture(
    encrypted: &str,
    authenticated: bool,
    recipient_secret: &[u8; 32],
    recipient: &DidDocument,
    sender: &DidDocument,
) -> marty_didcomm::types::DidcommMessage {
    let plaintext = if authenticated {
        let decrypted = marty_didcomm::decrypt_authenticated_jwe(
            encrypted,
            recipient_secret,
            recipient,
            sender,
        )
        .unwrap();
        assert_eq!(decrypted.sender_kid, format!("{ISSUER}#key-1"));
        assert_eq!(decrypted.recipient_kid, format!("{HOLDER}#key-1"));
        decrypted.plaintext
    } else {
        marty_didcomm::decrypt_jwe(encrypted, recipient_secret).unwrap()
    };
    let message = marty_didcomm::unpack_didcomm_message(&plaintext).unwrap();
    assert_eq!(message.from.as_deref(), Some(ISSUER));
    assert_eq!(message.to, Some(vec![HOLDER.into()]));
    message
}

async fn run_case(
    pool: &PgPool,
    authenticated: bool,
    automatic: bool,
    fault: Option<Fault>,
    recovery: Option<Recovery>,
    gateway: bool,
    fresh: Option<FreshScenario>,
) {
    assert!(fault.is_none() || recovery.is_none());
    assert!(fresh.is_none() || (automatic && !gateway && fault.is_none() && recovery.is_none()));
    let mut id = format!(
        "didcomm-composed-{}-{}-{fault:?}-{}-gateway{gateway}",
        if authenticated { "auth" } else { "anon" },
        if automatic { "automatic" } else { "direct" },
        match recovery {
            None => "ordinary",
            Some(Recovery::ConcurrentClaim) => "concurrent",
            Some(Recovery::EventProjection) => "projection",
            Some(Recovery::TlsTrust) => "tls-trust",
        },
    );
    if let Some(scenario) = fresh {
        id.push_str(&format!("-fresh-{scenario:?}"));
    }
    let wallet = WalletFixture::start(
        if fault == Some(Fault::HttpRefused) || fresh == Some(FreshScenario::WalletRefused) {
            503
        } else {
            200
        },
    );
    let endpoint = format!("{}/inbox", wallet.origin);
    let (sender_document, sender_secret, mut recipient_document, recipient_secret) =
        authcrypt_parties_with_ids(ISSUER, HOLDER);
    recipient_document.service.push(
        serde_json::from_value::<ServiceEntry>(
            json!({"id":"#didcomm","type":"DIDCommMessaging","serviceEndpoint":endpoint}),
        )
        .unwrap(),
    );
    let resolutions = Arc::new(AtomicUsize::new(0));
    let allocations = Arc::new(AtomicUsize::new(0));
    let allocation_requests = Arc::new(Mutex::new(Vec::new()));
    let peers = OwnedPeers::start(Peers {
        sender: sender_document.clone(),
        recipient: recipient_document.clone(),
        resolutions: resolutions.clone(),
        allocations: allocations.clone(),
        allocation_requests: allocation_requests.clone(),
    })
    .await;
    // The wallet owns this exact temporary directory and removes the synthetic policy too.
    let policy = wallet.ca_file.parent().unwrap().join("didcomm-policy.json");
    let reload_ca = wallet
        .ca_file
        .parent()
        .unwrap()
        .join("operator-reload-ca.pem");
    let mode = if authenticated {
        json!({"mode":"authcrypt","sender_x25519_private_key":URL_SAFE_NO_PAD.encode(if fault == Some(Fault::WrongSenderKey) { [8_u8;32] } else { sender_secret })})
    } else {
        json!({"mode":"anoncrypt"})
    };
    std::fs::write(
        &policy,
        json!({"version":1,"issuers":{(ISSUER):mode}}).to_string(),
    )
    .unwrap();
    let repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        b"synthetic-composed-hmac-key",
    ));
    let seeded_reservation = if fresh.is_none() {
        let reservation = repository
            .reserve_idempotently(&transaction(&id))
            .await
            .unwrap();
        assert!(reservation.created);
        Some(reservation)
    } else {
        None
    };
    let before = snapshot(pool, &id).await;
    let gate = (recovery == Some(Recovery::ConcurrentClaim)).then(|| Arc::new(BuildGate::new()));
    let builder = Arc::new(ControlledBuilder {
        calls: AtomicUsize::new(0),
        allocations: allocation_requests.clone(),
        gate: gate.clone(),
    });
    let lifecycle = PostgresCredentialLifecycle::new(
        pool.clone(),
        url::Url::parse(&peers.origin).unwrap(),
        Some(SERVICE_TOKEN),
        Duration::from_secs(5),
        CanvasGuardConfig {
            enabled: false,
            pilot_organizations: BTreeSet::new(),
            evidence_max_age: Duration::from_secs(900),
            readiness_max_age: Duration::from_secs(900),
        },
    )
    .unwrap();
    let issuer = Arc::new(ControlledIssuer);
    let delivery = Arc::new(
        NativeInitiationDidcommDelivery::new(
            NativeInitiationDidcommPorts {
                repository: repository.clone(),
                issuer_resolver: issuer.clone(),
                builder: builder.clone(),
                lifecycle: Arc::new(lifecycle),
                envelope: Arc::new(NativeDidcommEnvelope::new(
                    None,
                    Some(&peers.origin),
                    policy.to_str(),
                )),
                endpoints: Arc::new(DidcommEndpointValidator::new(true)),
                transport: Arc::new(
                    DidcommTransport::with_timeout(
                        if fault == Some(Fault::UntrustedTls) {
                            None
                        } else if recovery == Some(Recovery::TlsTrust) {
                            reload_ca.to_str()
                        } else {
                            wallet.ca_file.to_str()
                        },
                        Duration::from_secs(5),
                    )
                    .unwrap(),
                ),
            },
            "https://issuer.example",
        )
        .unwrap(),
    );
    let native_router = direct_router(delivery.clone());
    let gateway_body =
        json!({"organization_id":ORGANIZATION,"transaction_id":id,"holder_did":HOLDER});
    let mut gateway_fixture = if gateway {
        let fixture = super::didcomm_gateway_replay::GatewayFixture::start(
            native_router.clone(),
            ORGANIZATION,
            API_KEY,
        )
        .await;
        fixture.assert_selection_and_denials(&gateway_body).await;
        Some(fixture)
    } else {
        None
    };
    let app = DirectEndpoint {
        router: gateway_fixture
            .as_ref()
            .map_or(native_router, |fixture| fixture.router.clone()),
        gateway,
    };
    if let Some(fixture) = &gateway_fixture {
        let counts = fixture.counts();
        gateway_state_errors(pool, &app, &id).await;
        assert_eq!(fixture.counts(), (counts.0 + 5, counts.1));
        assert_eq!(allocations.load(Ordering::SeqCst), 0);
        assert_eq!(builder.calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.captures().await, json!({"messages":[],"failures":0}));
    }
    let projector =
        InitiationOfferProjector::new("https://issuer.example", delivery.clone()).unwrap();
    let request = if let Some(scenario) = fresh {
        serde_json::from_value(fresh_initiation::request_body(scenario)).unwrap()
    } else {
        InitiationRequest {
            organization_id: ORGANIZATION.into(),
            issuer_did: ISSUER.into(),
            holder_did: Some(HOLDER.into()),
            ..Default::default()
        }
    };
    let (reservation, fresh_response) = if let Some(scenario) = fresh {
        assert_eq!(
            before,
            json!({"transaction":null,"credentials":[],"deliveries":[],"events":[]})
        );
        let (fresh_router, admission) =
            fresh_initiation::router(repository.clone(), delivery.clone(), issuer, &id, scenario);
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/issuance-initiation.json"
        ))
        .unwrap();
        if !authenticated
            && matches!(
                scenario,
                FreshScenario::ExplicitHolder | FreshScenario::MixedWallet
            )
        {
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_transactions")
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let rejected = fresh_initiation::request(&fresh_router, scenario, true).await;
            assert_eq!(
                u64::from(rejected.0.as_u16()),
                contract["idempotency"]["didcomm_push_with_idempotency"]["http_status"]
                    .as_u64()
                    .unwrap()
            );
            assert_eq!(
                rejected.1,
                json!({"detail":"idempotent initiation does not support DIDComm push delivery"})
            );
            assert_eq!(snapshot(pool, &id).await, before);
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM issuance_service.issuance_transactions"
                )
                .fetch_one(pool)
                .await
                .unwrap(),
                count
            );
            assert_eq!(admission.seeds.load(Ordering::SeqCst), 0);
            assert_eq!(allocations.load(Ordering::SeqCst), 0);
            assert_eq!(builder.calls.load(Ordering::SeqCst), 0);
            assert_eq!(resolutions.load(Ordering::SeqCst), 0);
            assert_eq!(wallet.captures().await, json!({"messages":[],"failures":0}));
        }
        let (status, response) = fresh_initiation::request(&fresh_router, scenario, false).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(admission.seeds.load(Ordering::SeqCst), 1);
        let committed = repository
            .transaction_by_id(&id)
            .await
            .unwrap()
            .expect("HTTP admission committed its own reservation");
        assert_eq!(committed.created_at.timestamp(), 1_700_000_000);
        assert_eq!(contract["transaction"]["offer_ttl_minutes"], 10_080);
        assert_eq!(
            committed.expires_at.timestamp(),
            1_700_000_000 + 10_080 * 60
        );
        assert_eq!(committed.pre_authorized_code, format!("pre-auth-{id}"));
        assert!(
            committed.idempotency_key_hash.is_none()
                && committed.idempotency_request_hash.is_none()
        );
        assert_eq!(
            committed.wallet_configs.len(),
            if scenario == FreshScenario::MixedWallet {
                2
            } else {
                1
            }
        );
        assert_eq!(
            committed.subject_did.as_deref(),
            (scenario == FreshScenario::SubjectOnly).then_some(HOLDER)
        );
        let python: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/didcomm-automatic-response-python-reference.json"
        ))
        .unwrap();
        let holder = python["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["case"] == scenario.python_case())
            .unwrap();
        assert_eq!(response["status"], holder["response"]["status"]);
        (
            InitiationReservation {
                transaction: committed,
                created: false,
            },
            Some(response),
        )
    } else {
        (seeded_reservation.unwrap(), None)
    };
    if matches!(
        fresh,
        Some(FreshScenario::MissingHolder | FreshScenario::WalletRefused)
    ) {
        let refused = fresh == Some(FreshScenario::WalletRefused);
        let pending_uri = format!("didcomm://pending?transaction_id={id}");
        assert_offer_result(
            fresh_response.as_ref().unwrap(),
            &reservation,
            "pending",
            &pending_uri,
        );
        let state = snapshot(pool, &id).await;
        let captured = wallet.captures().await;
        assert_eq!(captured["failures"], 0);
        assert_eq!(
            captured["messages"].as_array().unwrap().len(),
            usize::from(refused)
        );
        assert_eq!(state["events"], json!([]));
        if refused {
            assert_eq!(state["transaction"]["status"], "issued");
            assert_eq!(state["credentials"].as_array().unwrap().len(), 1);
            assert_eq!(state["deliveries"].as_array().unwrap().len(), 1);
            assert_eq!(state["deliveries"][0]["status"], "delivery_unknown");
            assert_materialized_binding(&state, &id, &endpoint);
            let encrypted = captured["messages"][0].as_str().unwrap();
            assert_eq!(
                state["deliveries"][0]["metadata"]["encrypted_message"],
                encrypted
            );
            let message = decrypt_capture(
                encrypted,
                authenticated,
                &recipient_secret,
                &recipient_document,
                &sender_document,
            );
            assert_eq!(message.thid.as_deref(), Some(id.as_str()));
            assert_eq!(
                message.id,
                state["deliveries"][0]["metadata"]["didcomm_message_id"]
            );
            assert_eq!(message.attachments.len(), 1);
            assert_eq!(
                message.attachments[0].id.as_deref(),
                state["credentials"][0]["id"].as_str()
            );
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(message.attachments[0].data.base64.as_deref().unwrap())
                    .unwrap(),
                SIGNED_CREDENTIAL.as_bytes()
            );
            for _ in 0..2 {
                assert_eq!(
                    direct_response(&app, &id).await,
                    (
                        StatusCode::CONFLICT,
                        json!({"detail":"DIDComm delivery outcome requires reconciliation"})
                    )
                );
            }
        } else {
            assert_eq!(state["transaction"]["status"], "pending");
            assert_eq!(state["credentials"], json!([]));
            assert_eq!(state["deliveries"], json!([]));
            assert!(state["transaction"]["reserved_credential_id"].is_null());
        }
        // The first HTTP response used the pending reservation before delivery.
        // The reloaded reservation is actually issued after a refused POST; its
        // projector response retains issued status, but never claims delivery.
        // This is not a second (non-idempotent) HTTP initiation request.
        for _ in 0..2 {
            let projected = serde_json::to_value(
                projector
                    .project(reservation.clone(), &request)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_offer_result(
                &projected,
                &reservation,
                if refused { "issued" } else { "pending" },
                &pending_uri,
            );
        }
        assert_eq!(
            snapshot(pool, &id).await,
            state,
            "pending recovery preserves every durable row"
        );
        assert_eq!(
            wallet.captures().await,
            captured,
            "pending recovery must not resend"
        );
        assert_eq!(allocations.load(Ordering::SeqCst), usize::from(refused));
        assert_eq!(builder.calls.load(Ordering::SeqCst), usize::from(refused));
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            if refused {
                if authenticated {
                    2
                } else {
                    1
                }
            } else {
                0
            }
        );
        peers.close().await;
        wallet.close_verified();
        return;
    }
    if let Some(fault) = fault {
        assert!(
            !automatic,
            "negative first entrypoint is direct; retry also exercises automatic"
        );
        let expected = if fault == Fault::WrongSenderKey {
            assert!(authenticated);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"detail":"DIDComm sender-authentication configuration is unavailable"}),
            )
        } else {
            (
                StatusCode::CONFLICT,
                json!({"detail":"DIDComm delivery outcome requires reconciliation"}),
            )
        };
        assert_eq!(direct_response(&app, &id).await, expected);
        let captured = wallet.captures().await;
        let state = snapshot(pool, &id).await;
        if fault == Fault::WrongSenderKey {
            assert_eq!(state, before, "wrong sender cannot reserve or issue");
            assert_eq!(captured, json!({"messages":[],"failures":0}));
            assert_eq!(allocations.load(Ordering::SeqCst), 0);
            assert_eq!(builder.calls.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(state["transaction"]["status"], "issued");
            assert_eq!(state["credentials"].as_array().unwrap().len(), 1);
            assert_eq!(state["deliveries"].as_array().unwrap().len(), 1);
            assert_eq!(state["events"], json!([]));
            assert_eq!(state["deliveries"][0]["status"], "delivery_unknown");
            assert_materialized_binding(&state, &id, &endpoint);
            assert!(state["deliveries"][0]["metadata"]["encrypted_message"]
                .as_str()
                .is_some_and(|value| !value.is_empty()));
            assert_eq!(
                captured["messages"].as_array().unwrap().len(),
                usize::from(fault == Fault::HttpRefused)
            );
            assert_eq!(
                captured["failures"],
                usize::from(fault == Fault::UntrustedTls)
            );
            assert_eq!(allocations.load(Ordering::SeqCst), 1);
            assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
            if fault == Fault::HttpRefused {
                let message = decrypt_capture(
                    captured["messages"][0].as_str().unwrap(),
                    authenticated,
                    &recipient_secret,
                    &recipient_document,
                    &sender_document,
                );
                assert_eq!(message.thid.as_deref(), Some(id.as_str()));
                assert_eq!(
                    message.id,
                    state["deliveries"][0]["metadata"]["didcomm_message_id"]
                );
                assert_eq!(
                    message.attachments[0].id.as_deref(),
                    state["credentials"][0]["id"].as_str()
                );
            }
        }
        assert_eq!(direct_response(&app, &id).await, expected);
        let projected = serde_json::to_value(
            projector
                .project(reservation.clone(), &request)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_offer_result(
            &projected,
            &reservation,
            "pending",
            &format!("didcomm://pending?transaction_id={id}"),
        );
        assert_eq!(
            snapshot(pool, &id).await,
            state,
            "failure replay cannot mutate durable state"
        );
        assert_eq!(
            wallet.captures().await,
            captured,
            "failure replay cannot resend"
        );
        let expected_materializations = usize::from(fault != Fault::WrongSenderKey);
        assert_eq!(
            allocations.load(Ordering::SeqCst),
            expected_materializations
        );
        assert_eq!(
            builder.calls.load(Ordering::SeqCst),
            expected_materializations
        );
        if let Some(mut fixture) = gateway_fixture.take() {
            assert_eq!(
                fixture.counts().1,
                1,
                "candidate never selects legacy after baseline control"
            );
            fixture
                .assert_unreachable_without_legacy_fallback(&gateway_body)
                .await;
            fixture.close().await;
        }
        peers.close().await;
        wallet.close_verified();
        return;
    }
    let first = if let Some(response) = fresh_response {
        response
    } else if recovery == Some(Recovery::TlsTrust) {
        assert!(!automatic);
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/didcomm-tls-python-reference.json"
        ))
        .unwrap();
        let mut staged: Option<Value> = None;
        for case in frozen["cases"].as_array().unwrap().iter().take(2) {
            if case["case"] == "malformed_ca" {
                std::fs::write(&reload_ca, b"synthetic-invalid-ca").unwrap();
            }
            assert_eq!(
                direct_response(&app, &id).await,
                (
                    StatusCode::from_u16(case["status"].as_u64().unwrap().try_into().unwrap())
                        .unwrap(),
                    case["body"].clone()
                )
            );
            let current = snapshot(pool, &id).await;
            assert_eq!(current["transaction"]["status"], "issued");
            assert_eq!(current["credentials"].as_array().unwrap().len(), 1);
            assert_eq!(current["deliveries"].as_array().unwrap().len(), 1);
            assert_eq!(current["deliveries"][0]["status"], "transport_retryable");
            assert_eq!(current["events"], json!([]));
            assert_materialized_binding(&current, &id, &endpoint);
            assert_eq!(wallet.captures().await, json!({"messages":[],"failures":0}));
            assert_eq!(allocations.load(Ordering::SeqCst), 1);
            assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
            if let Some(previous) = &staged {
                assert_eq!(current["transaction"], previous["transaction"]);
                assert_eq!(current["credentials"], previous["credentials"]);
                assert_eq!(
                    current["deliveries"][0]["metadata"]["encrypted_message"],
                    previous["deliveries"][0]["metadata"]["encrypted_message"]
                );
            }
            staged = Some(current);
        }
        // First certificate belongs to a different owned wallet. Success requires
        // honoring the second certificate too, not silently parsing only one PEM.
        let unrelated = WalletFixture::start(200);
        let mut bundle = std::fs::read(&unrelated.ca_file).unwrap();
        bundle.extend_from_slice(&std::fs::read(&wallet.ca_file).unwrap());
        std::fs::write(&reload_ca, bundle).unwrap();
        let response = direct(&app, &id).await;
        assert_eq!(
            unrelated.captures().await,
            json!({"messages":[],"failures":0})
        );
        unrelated.close_verified();
        let recovered = snapshot(pool, &id).await;
        let staged = staged.unwrap();
        assert_eq!(recovered["transaction"], staged["transaction"]);
        assert_eq!(recovered["credentials"], staged["credentials"]);
        assert_eq!(
            wallet.captures().await["messages"][0],
            staged["deliveries"][0]["metadata"]["encrypted_message"]
        );
        // Delivered receipt replay must not reopen trust material or resend.
        std::fs::write(&reload_ca, b"synthetic-invalid-after-delivery").unwrap();
        response
    } else if let Some(gate) = gate {
        assert!(!automatic);
        // Keep the actual request future locally owned: timeout/panic drops it,
        // rather than leaving a detached request racing database teardown.
        let pending = direct(&app, &id);
        tokio::pin!(pending);
        tokio::select! {
            _ = &mut pending => panic!("first delivery escaped the controlled signing gate"),
            entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.acquire()) => {
                entered.expect("bounded first claimed builder entry").unwrap().forget();
            }
        }
        let claimed = snapshot(pool, &id).await;
        assert_eq!(claimed["transaction"]["status"], "signing");
        assert!(claimed["transaction"]["reserved_credential_id"]
            .as_str()
            .is_some());
        for key in ["credentials", "deliveries", "events"] {
            assert_eq!(claimed[key], json!([]));
        }
        // This arriving HTTP request reloads Signing, whose frozen public
        // response is 400. A stale-read claim race instead has the separate 409
        // contract; do not conflate the two or weaken the existing state parity.
        assert_eq!(
            direct_response(&app, &id).await,
            (
                StatusCode::BAD_REQUEST,
                json!({"detail":"Transaction in signing state"})
            ),
        );
        assert_eq!(snapshot(pool, &id).await, claimed);
        assert_eq!(wallet.captures().await, json!({"messages":[],"failures":0}));
        assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
        assert_eq!(allocations.load(Ordering::SeqCst), 1);
        gate.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), &mut pending)
            .await
            .expect("bounded first delivery completion")
    } else if recovery == Some(Recovery::EventProjection) {
        assert!(
            automatic,
            "recover the direct failure through the other entrypoint"
        );
        install_event_fault(pool, &id).await;
        assert_eq!(
            direct_response(&app, &id).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"detail":"DIDComm delivery is unavailable"})
            ),
        );
        let transported = snapshot(pool, &id).await;
        assert_eq!(transported["transaction"]["status"], "issued");
        assert_eq!(transported["credentials"].as_array().unwrap().len(), 1);
        assert_eq!(transported["deliveries"].as_array().unwrap().len(), 1);
        assert_eq!(transported["deliveries"][0]["status"], "transported");
        assert_eq!(transported["events"], json!([]));
        assert_materialized_binding(&transported, &id, &endpoint);
        assert!(
            transported["deliveries"][0]["metadata"]["encrypted_message"]
                .as_str()
                .is_some()
        );
        let sent = wallet.captures().await;
        assert_eq!(sent["messages"].as_array().unwrap().len(), 1);
        assert_eq!(sent["failures"], 0);
        let resolution_count = resolutions.load(Ordering::SeqCst);
        assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
        assert_eq!(allocations.load(Ordering::SeqCst), 1);
        remove_event_fault(pool).await;
        let response = serde_json::to_value(
            projector
                .project(reservation.clone(), &request)
                .await
                .unwrap(),
        )
        .unwrap();
        let recovered = snapshot(pool, &id).await;
        assert_eq!(recovered["transaction"], transported["transaction"]);
        assert_eq!(recovered["credentials"], transported["credentials"]);
        assert_eq!(
            recovered["deliveries"][0]["id"],
            transported["deliveries"][0]["id"]
        );
        assert_eq!(
            recovered["deliveries"][0]["metadata"]["didcomm_message_id"],
            transported["deliveries"][0]["metadata"]["didcomm_message_id"]
        );
        assert_eq!(
            wallet.captures().await,
            sent,
            "projection retry must not POST again"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), resolution_count);
        response
    } else if automatic {
        serde_json::to_value(
            projector
                .project(reservation.clone(), &request)
                .await
                .unwrap(),
        )
        .unwrap()
    } else {
        direct(&app, &id).await
    };
    let captured = wallet.captures().await;
    assert_eq!(captured["failures"], 0);
    assert_eq!(captured["messages"].as_array().unwrap().len(), 1);
    let encrypted = captured["messages"][0].as_str().unwrap();
    let message = decrypt_capture(
        encrypted,
        authenticated,
        &recipient_secret,
        &recipient_document,
        &sender_document,
    );
    assert_eq!(
        message.r#type,
        "https://didcomm.org/issue-credential/3.0/issue-credential"
    );
    assert!(uuid::Uuid::parse_str(&message.id).is_ok());
    assert_eq!(message.from.as_deref(), Some(ISSUER));
    assert_eq!(message.to, Some(vec![HOLDER.into()]));
    assert_eq!(message.thid.as_deref(), Some(id.as_str()));
    assert_eq!(
        message.body,
        json!({"goal_code":"issue-vc","comment":"Here is your credential"})
    );
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].format.as_deref(), Some(FORMAT));
    assert_eq!(
        message.attachments[0].media_type.as_deref(),
        Some("application/vc+sd-jwt")
    );
    assert!(message.attachments[0].data.json.is_none());
    assert!(message.attachments[0].data.links.is_none());
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(message.attachments[0].data.base64.as_deref().unwrap())
            .unwrap(),
        SIGNED_CREDENTIAL.as_bytes()
    );
    let state = snapshot(pool, &id).await;
    assert_eq!(state["transaction"]["status"], "issued");
    for key in ["credentials", "deliveries", "events"] {
        assert_eq!(state[key].as_array().unwrap().len(), 1);
    }
    let credential = &state["credentials"][0];
    let credential_id = credential["id"].as_str().unwrap();
    assert_materialized_binding(&state, &id, &endpoint);
    assert_eq!(
        *allocation_requests.lock().unwrap(),
        vec![
            json!({"organization_id":ORGANIZATION,"credential_format":"sd_jwt_vc","credential_id":credential_id})
        ]
    );
    assert_eq!(credential["credential_jwt"], SIGNED_CREDENTIAL);
    assert_eq!(credential["subject_did"], HOLDER);
    assert_eq!(message.attachments[0].id.as_deref(), Some(credential_id));
    let record = &state["deliveries"][0];
    assert_eq!(record["status"], "delivered");
    assert_eq!(record["metadata"]["didcomm_message_id"], message.id);
    assert!(record["metadata"].get("encrypted_message").is_none());
    assert_eq!(state["events"][0]["event_type"], "credential_issued");
    assert_eq!(state["events"][0]["transaction_id"], id);
    assert_eq!(
        state["events"][0]["metadata"]["credential_id"],
        credential_id
    );
    assert_eq!(state["events"][0]["metadata"]["service_endpoint"], endpoint);
    assert_eq!(
        state["events"][0]["metadata"]["delivery_protocol"],
        "didcomm_v2"
    );
    let receipt = json!({"transaction_id":id,"credential_id":credential_id,"holder_did":HOLDER,"service_endpoint":endpoint,"didcomm_message_id":message.id,"status":"delivered","error":null});
    if automatic {
        assert_offer(&first, &reservation, &endpoint);
    } else {
        assert_eq!(first, receipt);
    }
    let resolution_count = resolutions.load(Ordering::SeqCst);
    assert_eq!(resolution_count, if authenticated { 2 } else { 1 });
    let repeated = if automatic {
        serde_json::to_value(
            projector
                .project(reservation.clone(), &request)
                .await
                .unwrap(),
        )
        .unwrap()
    } else {
        direct(&app, &id).await
    };
    assert_eq!(repeated, first);
    assert_eq!(
        direct(&app, &id).await,
        receipt,
        "cross-entrypoint receipt replay"
    );
    let cross_offer = serde_json::to_value(
        projector
            .project(reservation.clone(), &request)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_offer(&cross_offer, &reservation, &endpoint);
    assert_eq!(
        snapshot(pool, &id).await,
        state,
        "replays preserve every durable row as equal JSON values"
    );
    assert_eq!(wallet.captures().await, captured);
    assert_eq!(resolutions.load(Ordering::SeqCst), resolution_count);
    assert_eq!(allocations.load(Ordering::SeqCst), 1);
    assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
    if let Some(mut fixture) = gateway_fixture.take() {
        assert_eq!(
            fixture.counts().1,
            1,
            "candidate never selects legacy after baseline control"
        );
        fixture
            .assert_unreachable_without_legacy_fallback(&gateway_body)
            .await;
        fixture.close().await;
    }
    peers.close().await;
    wallet.close_verified();
}

pub(super) async fn run(database_url: &str) {
    run_mode(database_url, false, false).await;
}

pub(super) async fn run_gateway(database_url: &str) {
    run_mode(database_url, true, false).await;
}

pub(super) async fn run_fresh_http(database_url: &str) {
    run_mode(database_url, false, true).await;
}

async fn run_mode(database_url: &str, gateway: bool, fresh: bool) {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
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
    tokio::time::timeout(Duration::from_secs(120), async {
        if fresh {
            for authenticated in [false, true] {
                for scenario in [
                    FreshScenario::ExplicitHolder,
                    FreshScenario::SubjectOnly,
                    FreshScenario::MissingHolder,
                    FreshScenario::WalletRefused,
                ] {
                    run_case(
                        &pool,
                        authenticated,
                        true,
                        None,
                        None,
                        false,
                        Some(scenario),
                    )
                    .await;
                }
            }
            run_case(
                &pool,
                false,
                true,
                None,
                None,
                false,
                Some(FreshScenario::MixedWallet),
            )
            .await;
            return;
        }
        for authenticated in [false, true] {
            for automatic in [false, true] {
                if gateway && automatic {
                    continue;
                }
                run_case(&pool, authenticated, automatic, None, None, gateway, None).await;
            }
            for fault in [Fault::HttpRefused, Fault::UntrustedTls] {
                run_case(
                    &pool,
                    authenticated,
                    false,
                    Some(fault),
                    None,
                    gateway,
                    None,
                )
                .await;
            }
            run_case(
                &pool,
                authenticated,
                false,
                None,
                Some(Recovery::ConcurrentClaim),
                gateway,
                None,
            )
            .await;
            run_case(
                &pool,
                authenticated,
                false,
                None,
                Some(Recovery::TlsTrust),
                gateway,
                None,
            )
            .await;
            run_case(
                &pool,
                authenticated,
                true,
                None,
                Some(Recovery::EventProjection),
                gateway,
                None,
            )
            .await;
        }
        run_case(
            &pool,
            true,
            false,
            Some(Fault::WrongSenderKey),
            None,
            gateway,
            None,
        )
        .await;
    })
    .await
    .expect("bounded composed DIDComm acceptance");
    pool.close().await;
}
