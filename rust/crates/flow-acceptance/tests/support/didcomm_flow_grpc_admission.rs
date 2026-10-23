//! Actual Flow provider -> tonic -> complete native platform -> PostgreSQL.
//! This keyed-only gate does not qualify Flow orchestration or unkeyed DIDComm push.
use super::super::didcomm_native_grpc_fixture::{self, NativeInitiation, OwnedGrpc};
use super::{
    initiation, snapshot, IssuanceServiceConfig, Ports, PostgresCredentialRepository, CODE, ID,
};
use marty_flow::{
    issuance_proto::issuance_service_client::IssuanceServiceClient, FlowProviderError,
    GrpcIssuanceProvider, IssuanceInitiationRequest, IssuanceInitiationResult, IssuanceProvider,
};
use marty_issuance_service::{
    credential_management_events::{CredentialLifecycleEventBus, CredentialLifecycleEventFilter},
    credential_management_grpc::CredentialManagementGrpcService,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::BTreeMap,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
const TOKEN: &str = "synthetic-flow-native-service-token";
const HMAC: &[u8] = b"synthetic-flow-admission-hmac-key";
fn native_server(
    pool: &PgPool,
    ports: Arc<Ports>,
    events: CredentialLifecycleEventBus,
) -> CredentialManagementGrpcService {
    let repository = Arc::new(PostgresCredentialRepository::new(pool.clone(), HMAC));
    let config =
        IssuanceServiceConfig::from_values([("ISSUANCE_OFFER_TTL_MINUTES".into(), "45".into())])
            .unwrap();
    let (service, projector) = initiation(repository.clone(), ports.clone(), &config);
    didcomm_native_grpc_fixture::native_server(
        pool,
        NativeInitiation {
            repository,
            service,
            projector,
            issuer_resolver: ports,
        },
        events,
        TOKEN,
        HMAC,
    )
}
fn flow_provider(server: &OwnedGrpc, token: Option<&str>) -> GrpcIssuanceProvider {
    GrpcIssuanceProvider::new(IssuanceServiceClient::new(server.channel()), token).unwrap()
}
async fn call(
    provider: &GrpcIssuanceProvider,
    request: &IssuanceInitiationRequest,
) -> Result<IssuanceInitiationResult, FlowProviderError> {
    assert!(
        request
            .idempotency_key
            .as_deref()
            .is_some_and(|key| !key.is_empty()),
        "Flow keeps its retry key"
    );
    tokio::time::timeout(Duration::from_secs(5), provider.initiate(request))
        .await
        .unwrap()
}

fn rejected() -> FlowProviderError {
    FlowProviderError::Rejected {
        provider: "issuance",
        message: "provider rejected the operation".into(),
    }
}

fn assert_result(result: &IssuanceInitiationResult) {
    let uri = result.credential_offer_uri.as_deref().unwrap();
    super::assert_offer_uri(uri);
    assert_eq!(
        result,
        &IssuanceInitiationResult {
            transaction_id: ID.into(),
            credential_offer_uri: Some(uri.into()),
            credential_offer_uris: BTreeMap::from([("ordinary".into(), uri.into())]),
            credential_offer_labels: BTreeMap::from([(
                "ordinary".into(),
                "Ordinary Wallet".into()
            )]),
            pre_authorized_code: Some(CODE.into()),
            expires_at_ms: Some(1_788_093_900_000),
            status: "pending".into(),
        }
    );
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(3)
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
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    let vector = &contract["idempotency"]["vector"];
    let mut body = vector["request"].clone();
    body["flow_instance_id"] = json!("synthetic-flow-instance");
    body["idempotency_key"] = vector["key"].clone();
    let request: IssuanceInitiationRequest = serde_json::from_value(body).unwrap();
    let ports = Arc::new(Ports::default());
    let events = CredentialLifecycleEventBus::default();
    let mut emitted = events.subscribe(CredentialLifecycleEventFilter::new(
        Some("org-1"),
        Some("template-1"),
        ["offer_created".into()],
    ));
    let server = OwnedGrpc::start(native_server(&pool, ports.clone(), events)).await;
    let before = snapshot(&pool).await;
    assert_eq!(
        before,
        json!({"transaction":null,"credentials":0,"deliveries":0,"events":0})
    );
    for token in [None, Some("wrong-synthetic-service-token")] {
        assert_eq!(
            call(&flow_provider(&server, token), &request).await,
            Err(rejected())
        );
        assert!(ports.take().is_empty(), "authentication precedes admission");
        assert_eq!(snapshot(&pool).await, before);
    }
    let provider = flow_provider(&server, Some(TOKEN));
    let created = call(&provider, &request).await.unwrap();
    assert_result(&created);
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
    // Admission adds the governed reserved VCT after hashing the original
    // request. Preserve and assert that addition, not just the caller claims.
    let mut expected_claims = vector["request"]["claims"].clone();
    expected_claims["_vct"] = json!("https://issuer.example/credentials/EmployeeCredential");
    assert_eq!(stored["transaction"]["claims"], expected_claims);
    assert_eq!(stored["transaction"]["oid4vci_client_id"], "client-1");
    assert_eq!(stored["credentials"], 0);
    assert_eq!(stored["deliveries"], 0);
    assert_eq!(
        stored["events"], 0,
        "gRPC offer event is the existing event bus, not a fabricated database insert"
    );
    let event = tokio::time::timeout(Duration::from_secs(1), emitted.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.event_type, "offer_created");
    assert_eq!(event.transaction_id, ID);
    assert_eq!(event.organization_id, "org-1");
    assert_eq!(event.credential_template_id, "template-1");
    assert_eq!(event.status, "pending");
    ports.recovery_only.store(true, Ordering::SeqCst);
    assert_eq!(call(&provider, &request).await.unwrap(), created);
    assert_eq!(ports.take(), ["organization", "client"]);
    assert_eq!(snapshot(&pool).await, stored);
    let mut conflict = request.clone();
    conflict.claims.get_mut("profile").unwrap()["level"] = json!(3);
    assert_eq!(
        call(&provider, &conflict).await,
        Err(FlowProviderError::Conflict {
            provider: "issuance",
            message: "provider reported a conflict".into()
        })
    );
    assert_eq!(ports.take(), ["organization", "client"]);
    assert_eq!(snapshot(&pool).await, stored);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), emitted.recv())
            .await
            .is_err(),
        "recovery/conflict must not repeat offer-created events"
    );
    server.close().await;

    for mixed in [false, true] {
        let mut wallets = vec![json!({"wallet_id":"didcomm", "format_variant":"didcomm_v2"})];
        if mixed {
            wallets.push(json!({"wallet_id":"ordinary", "format_variant":"default"}));
        }
        let ports = Arc::new(Ports {
            wallet_configs: Some(wallets),
            ..Ports::default()
        });
        let events = CredentialLifecycleEventBus::default();
        let mut emitted = events.subscribe(CredentialLifecycleEventFilter::default());
        let server = OwnedGrpc::start(native_server(&pool, ports.clone(), events)).await;
        let mut keyed = request.clone();
        keyed.idempotency_key = Some(format!(
            "flow-instance-offer-v1:synthetic-{}",
            if mixed { "mixed" } else { "didcomm" }
        ));
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_transactions")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            call(&flow_provider(&server, Some(TOKEN)), &keyed).await,
            Err(rejected())
        );
        assert_eq!(
            ports.take(),
            ["organization", "client", "template", "revocation"]
        );
        assert_eq!(snapshot(&pool).await, stored);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM issuance_service.issuance_transactions"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            count
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), emitted.recv())
                .await
                .is_err(),
            "rejected pushes emit no offer-created event"
        );
        server.close().await;
    }
    pool.close().await;
}
