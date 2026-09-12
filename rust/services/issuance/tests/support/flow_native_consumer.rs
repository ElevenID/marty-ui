//! Actual Flow preparation -> actual native tonic admission -> both PostgreSQL
//! repositories. Controlled template/issuer ports do not sign or push credentials.
//! This is not packaged Flow startup, deployment selection, or public Flow auth.
use super::super::didcomm_native_grpc_fixture::{self, NativeInitiation, OwnedGrpc};
use super::{initiation_with_seeds, IssuanceServiceConfig, Ports, PostgresCredentialRepository};
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use marty_flow::{
    create_definition_record, issuance_proto::issuance_service_client::IssuanceServiceClient,
    migrate_flow_schema, parse_request, prepare_instance_start, prepare_oid4vci_retry,
    start_instance_record, ArtifactStatus, CreateFlowDefinitionRequest, CredentialTemplateProvider,
    CredentialTemplateReference, DefinitionStatus, FlowArtifactRecord, FlowDefinitionRecord,
    FlowInstanceRecord, FlowInstanceSideEffectError, FlowProviderError, FlowProviderRegistry,
    GrpcIssuanceProvider, IssuanceInitiationRequest, IssuanceInitiationResult, IssuanceProvider,
    PostgresFlowRepository, PreparedInstanceStart, StartFlowRequest,
};
use marty_issuance_service::{
    credential_management_events::CredentialLifecycleEventBus,
    initiation::{InitiationSeed, InitiationSeedGenerator},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[path = "flow_legacy_physical_http.rs"]
mod physical;

const TOKEN: &str = "synthetic-flow-composed-service-token";
const HMAC: &[u8] = b"synthetic-flow-composed-hmac";
const PUBLIC: &str = "https://issuer.example";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap()
}

struct Seeds {
    next: AtomicUsize,
    ports: Arc<Ports>,
}
impl InitiationSeedGenerator for Seeds {
    fn generate(&self) -> InitiationSeed {
        self.ports.record("seed");
        let index = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        InitiationSeed {
            transaction_id: format!("flow-composed-transaction-{index}"),
            pre_authorized_code: format!("synthetic-flow-composed-code-{index}"),
        }
    }
}

struct Templates {
    tenant: &'static str,
}
#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        assert_eq!(id, "template-1");
        Ok(serde_json::from_value(json!({
            "id":id,"organization_id":self.tenant,"status":"ACTIVE",
            "credential_type":"EmployeeCredential","vct":"https://issuer.example/credentials/EmployeeCredential",
            "issuer_did":"did:web:issuer.example","credential_format":"dc+sd-jwt",
            "issuer_algorithm":"EdDSA","wallet_configurations":[]
        })).unwrap())
    }
}

#[derive(Clone)]
struct Observation {
    request: IssuanceInitiationRequest,
    result: Result<IssuanceInitiationResult, FlowProviderError>,
}
struct ObservedProvider {
    actual: GrpcIssuanceProvider,
    calls: Mutex<Vec<Observation>>,
}
impl ObservedProvider {
    fn new(server: &OwnedGrpc, token: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            actual: GrpcIssuanceProvider::new(IssuanceServiceClient::new(server.channel()), token)
                .unwrap(),
            calls: Mutex::new(Vec::new()),
        })
    }
    fn take(&self) -> Observation {
        let mut calls = self.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "one actual native provider call");
        calls.pop().unwrap()
    }
}
#[async_trait]
impl IssuanceProvider for ObservedProvider {
    async fn initiate(
        &self,
        request: &IssuanceInitiationRequest,
    ) -> Result<IssuanceInitiationResult, FlowProviderError> {
        let result = self.actual.initiate(request).await;
        self.calls.lock().unwrap().push(Observation {
            request: request.clone(),
            result: result.clone(),
        });
        result
    }
}

fn registry(provider: Arc<ObservedProvider>, tenant: &'static str) -> FlowProviderRegistry {
    FlowProviderRegistry {
        issuance: Some(provider),
        credential_template: Some(Arc::new(Templates { tenant })),
        ..Default::default()
    }
}

fn definition(kind: &str) -> FlowDefinitionRecord {
    let mut body = json!({"organization_id":"org-1","name":"Native Flow consumer fixture",
        "flow_type":kind,"credential_template_id":"template-1"});
    if kind == "physical_document_issuance" {
        body["application_template_id"] = json!("application-template-1");
        body["delivery_destination_profile_id"] = json!("destination-1");
    }
    let request: CreateFlowDefinitionRequest = parse_request(body).unwrap();
    let mut record = create_definition_record(request, now()).unwrap();
    record.status = DefinitionStatus::Active;
    record
}

fn start(definition: &FlowDefinitionRecord, context: Value) -> FlowInstanceRecord {
    let request: StartFlowRequest = parse_request(json!({
        "organization_id":"org-1","flow_definition_id":definition.id,
        "subject_id":"applicant-1","initial_context":context
    }))
    .unwrap();
    start_instance_record(definition, request, "synthetic-user", now()).unwrap()
}

async fn prepare(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    instance: FlowInstanceRecord,
) -> Result<PreparedInstanceStart, FlowInstanceSideEffectError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        prepare_instance_start(providers, definition, instance, PUBLIC, now()),
    )
    .await
    .unwrap()
}

fn rejected() -> FlowProviderError {
    FlowProviderError::Rejected {
        provider: "issuance",
        message: "provider rejected the operation".into(),
    }
}

fn key_hash(key: &str) -> String {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    let prefix = contract["idempotency"]["key_hash_prefix"].as_str().unwrap();
    format!("{:x}", Sha256::digest(format!("{prefix}{key}").as_bytes()))
}

fn error(
    result: Result<PreparedInstanceStart, FlowInstanceSideEffectError>,
    expected: FlowProviderError,
) {
    match result {
        Err(FlowInstanceSideEffectError::Provider(actual)) => assert_eq!(actual, expected),
        _ => panic!("expected exact closed Flow provider failure"),
    }
}

async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
        'instances', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM flow_service.flow_instances t WHERE organization_id='org-1'), '[]'::jsonb),
        'artifacts', COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM flow_service.flow_instance_artifacts a JOIN flow_service.flow_instances i ON i.id=a.flow_instance_id WHERE i.organization_id='org-1'), '[]'::jsonb),
        'transactions', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issuance_transactions t WHERE organization_id='org-1'), '[]'::jsonb),
        'credentials', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issued_credentials t WHERE organization_id='org-1'), '[]'::jsonb),
        'deliveries', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.credential_delivery_records t WHERE transaction_id LIKE 'flow-composed-%'), '[]'::jsonb),
        'events', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issuance_events t WHERE transaction_id LIKE 'flow-composed-%'), '[]'::jsonb))")
        .fetch_one(pool).await.unwrap()
}

fn assert_request(observation: &Observation, instance: &FlowInstanceRecord, attempt: u32) {
    let key = if let Some(digest) = &instance.application_flow_key_hash {
        format!("application-flow-offer-v1:{digest}")
    } else {
        format!("flow-instance-offer-v1:{}", instance.id)
    };
    let key = if attempt == 1 {
        key
    } else {
        format!("{key}:{attempt}")
    };
    assert_eq!(
        observation.request,
        IssuanceInitiationRequest {
            organization_id: "org-1".into(),
            flow_instance_id: instance.id.clone(),
            credential_template_id: "template-1".into(),
            applicant_id: Some("applicant-1".into()),
            subject_did: Some("did:key:z6MkHolder".into()),
            holder_did: None,
            authorized_client_id: None,
            application_id: instance
                .context
                .get("application_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            issuer_did: "did:web:issuer.example".into(),
            delivery_mode: Some("wallet_only".into()),
            idempotency_key: Some(key),
            claims: serde_json::from_value(instance.context["claims"].clone()).unwrap(),
        }
    );
}

fn assert_prepared(
    original: &FlowInstanceRecord,
    prepared: &PreparedInstanceStart,
    result: &IssuanceInitiationResult,
    attempt: u32,
    seed_index: usize,
    timestamp: DateTime<Utc>,
) {
    let artifact = prepared.artifact.as_ref().unwrap();
    uuid::Uuid::parse_str(&artifact.id).unwrap();
    let uri = result.credential_offer_uri.clone().unwrap();
    let parsed = url::Url::parse(&uri).unwrap();
    assert_eq!(parsed.scheme(), "openid-credential-offer");
    let pairs: Vec<_> = parsed.query_pairs().collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "credential_offer");
    assert_eq!(
        serde_json::from_str::<Value>(&pairs[0].1).unwrap(),
        json!({
            "credential_issuer":"https://issuer.example/org/org-1",
            "credential_configuration_ids":["EmployeeCredential#sd-jwt"],
            "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":result.pre_authorized_code}}
        })
    );
    assert_eq!(
        result,
        &IssuanceInitiationResult {
            transaction_id: format!("flow-composed-transaction-{seed_index}"),
            credential_offer_uri: Some(uri.clone()),
            credential_offer_uris: BTreeMap::from([("ordinary".into(), uri.clone())]),
            credential_offer_labels: BTreeMap::from([(
                "ordinary".into(),
                "Ordinary Wallet".into()
            )]),
            pre_authorized_code: Some(format!("synthetic-flow-composed-code-{seed_index}")),
            expires_at_ms: Some(1_788_093_900_000),
            status: "pending".into(),
        }
    );
    assert_eq!(
        artifact,
        &FlowArtifactRecord {
            id: artifact.id.clone(),
            flow_instance_id: original.id.clone(),
            issuance_transaction_id: Some(result.transaction_id.clone()),
            credential_offer_uri: Some(uri.clone()),
            credential_offer_uris: result.credential_offer_uris.clone(),
            credential_offer_labels: result.credential_offer_labels.clone(),
            pre_authorized_code: result.pre_authorized_code.clone(),
            issuance_status: Some("pending".into()),
            qr_payload: None,
            expires_at: DateTime::from_timestamp_millis(result.expires_at_ms.unwrap() as i64),
            scanned_at: None,
            status: ArtifactStatus::Active,
            state: Some(result.transaction_id.clone()),
            wallet_metadata: json!({}),
            attempt_number: attempt,
            created_at: timestamp,
            updated_at: timestamp,
        }
    );
    let message_id = prepared.instance.context["mip_messages"]["credential_offer"]["message_id"]
        .as_str()
        .unwrap();
    uuid::Uuid::parse_str(message_id).unwrap();
    let mut expected = original.clone();
    let context = expected.context.as_object_mut().unwrap();
    for (key, value) in [
        ("oid4vci_artifact_id", json!(artifact.id)),
        (
            "credential_offer_transaction_id",
            json!(result.transaction_id),
        ),
        ("offer_id", json!(result.transaction_id)),
        ("credential_offer_uri", json!(uri)),
        ("credential_offer_uris", json!(result.credential_offer_uris)),
        (
            "credential_offer_labels",
            json!(result.credential_offer_labels),
        ),
        ("issuance_status", json!("pending")),
        ("pre_auth_code", json!(result.pre_authorized_code)),
    ] {
        context.insert(key.into(), value);
    }
    let messages = context
        .entry("mip_messages")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap();
    messages.insert("credential_offer".into(),json!({
        "mip_version":"0.3.1","message_type":"CredentialOffer","message_id":message_id,
        "correlation_id":original.id,"timestamp":timestamp.to_rfc3339(),"sender_id":PUBLIC,
        "nonce":null,"signature":null,"payload":{
            "credential_issuer":PUBLIC,"credential_configuration_ids":["template-1"],
            "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":result.pre_authorized_code}},
            "mip_flow_instance_id":original.id
        }
    }));
    assert_eq!(
        prepared.instance, expected,
        "complete Flow instance/context projection"
    );
}

async fn server(pool: &PgPool, ports: Arc<Ports>, seeds: Arc<Seeds>) -> OwnedGrpc {
    let repository = Arc::new(PostgresCredentialRepository::new(pool.clone(), HMAC));
    let config =
        IssuanceServiceConfig::from_values([("ISSUANCE_OFFER_TTL_MINUTES".into(), "45".into())])
            .unwrap();
    let (service, projector) =
        initiation_with_seeds(repository.clone(), ports.clone(), &config, seeds);
    OwnedGrpc::start(didcomm_native_grpc_fixture::native_server(
        pool,
        NativeInitiation {
            repository,
            service,
            projector,
            issuer_resolver: ports,
        },
        CredentialLifecycleEventBus::default(),
        TOKEN,
        HMAC,
    ))
    .await
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
    migrate_flow_schema(&pool).await.unwrap();
    let repository = PostgresFlowRepository::new(pool.clone());
    let definition = definition("oid4vci_pre_authorized");
    repository.save_definition(&definition).await.unwrap();
    let original = start(
        &definition,
        json!({"subject_did":"did:key:z6MkHolder",
        "claims":{"profile":{"level":2},"roles":["student","member"]},
        "mip_messages":{"keep":{"synthetic":"existing sibling"}},"keep":"unrelated context"}),
    );
    let legacy = physical::Legacy::start().await;
    let ports = Arc::new(Ports::default());
    let seeds = Arc::new(Seeds {
        next: AtomicUsize::new(0),
        ports: ports.clone(),
    });
    let native = server(&pool, ports.clone(), seeds.clone()).await;
    let before = snapshot(&pool).await;
    for token in [None, Some("wrong-synthetic-token")] {
        let provider = ObservedProvider::new(&native, token);
        error(
            prepare(
                &registry(provider.clone(), "org-1"),
                &definition,
                original.clone(),
            )
            .await,
            rejected(),
        );
        assert_request(&provider.take(), &original, 1);
        assert!(ports.take().is_empty());
        assert_eq!(snapshot(&pool).await, before);
    }
    let provider = ObservedProvider::new(&native, Some(TOKEN));
    let providers = registry(provider.clone(), "org-1");
    let created = prepare(&providers, &definition, original.clone())
        .await
        .unwrap();
    let observed = provider.take();
    assert_request(&observed, &original, 1);
    let offer = observed.result.unwrap();
    assert_prepared(&original, &created, &offer, 1, 1, now());
    assert_eq!(
        ports.take(),
        [
            "organization",
            "template",
            "revocation",
            "clock",
            "seed",
            "issuer"
        ]
    );
    assert!(repository
        .save_started_instance(&created.instance, created.artifact.as_ref())
        .await
        .unwrap());
    assert_eq!(
        repository.instance(&original.id).await.unwrap().unwrap(),
        created.instance
    );
    assert_eq!(
        repository
            .artifacts_for_instance(&original.id)
            .await
            .unwrap(),
        vec![created.artifact.clone().unwrap()]
    );
    let stored = snapshot(&pool).await;
    assert_eq!(
        stored["transactions"][0]["idempotency_key_hash"],
        key_hash(observed.request.idempotency_key.as_deref().unwrap())
    );
    let mut claims = original.context["claims"].clone();
    claims["_vct"] = json!("https://issuer.example/credentials/EmployeeCredential");
    assert_eq!(stored["transactions"][0]["claims"], claims);
    ports.recovery_only.store(true, Ordering::SeqCst);
    let recovered = prepare(&providers, &definition, original.clone())
        .await
        .unwrap();
    let observed = provider.take();
    assert_request(&observed, &original, 1);
    assert_eq!(observed.result.unwrap(), offer);
    assert_prepared(&original, &recovered, &offer, 1, 1, now());
    assert_eq!(ports.take(), ["organization"]);
    assert!(!repository
        .save_started_instance(&recovered.instance, recovered.artifact.as_ref())
        .await
        .unwrap());
    assert_eq!(snapshot(&pool).await, stored);
    // A conflicting already-persisted artifact must roll back the newly
    // inserted instance as one real repository transaction.
    let mut conflicting_instance = created.instance.clone();
    conflicting_instance.id = uuid::Uuid::new_v4().to_string();
    let mut conflicting_artifact = created.artifact.clone().unwrap();
    conflicting_artifact.flow_instance_id = conflicting_instance.id.clone();
    assert!(!repository
        .save_started_instance(&conflicting_instance, Some(&conflicting_artifact))
        .await
        .unwrap());
    assert!(repository
        .instance(&conflicting_instance.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(snapshot(&pool).await, stored);
    let mut conflict = original.clone();
    conflict.context["claims"]["profile"]["level"] = json!(3);
    error(
        prepare(&providers, &definition, conflict.clone()).await,
        FlowProviderError::Conflict {
            provider: "issuance",
            message: "provider reported a conflict".into(),
        },
    );
    assert_request(&provider.take(), &conflict, 1);
    assert_eq!(ports.take(), ["organization"]);
    assert_eq!(snapshot(&pool).await, stored);
    let mismatch = prepare(
        &registry(provider.clone(), "foreign-org"),
        &definition,
        original.clone(),
    )
    .await;
    assert!(matches!(
        mismatch,
        Err(FlowInstanceSideEffectError::InvalidResponse(
            "credential template binding"
        ))
    ));
    assert!(provider.calls.lock().unwrap().is_empty());
    assert!(ports.take().is_empty());
    assert_eq!(snapshot(&pool).await, stored);

    ports.recovery_only.store(false, Ordering::SeqCst);
    let later = now() + Duration::minutes(1);
    let mut retry_input = created.instance.clone();
    retry_input.updated_at = later;
    let retry = prepare_oid4vci_retry(
        &providers,
        &definition,
        retry_input.clone(),
        PUBLIC,
        later,
        2,
    )
    .await
    .unwrap();
    let observed = provider.take();
    assert_request(&observed, &original, 2);
    let next_offer = observed.result.unwrap();
    assert_prepared(&retry_input, &retry, &next_offer, 2, 2, later);
    assert_eq!(
        ports.take(),
        [
            "organization",
            "template",
            "revocation",
            "clock",
            "seed",
            "issuer"
        ]
    );
    ports.recovery_only.store(true, Ordering::SeqCst);
    let second = prepare_oid4vci_retry(
        &providers,
        &definition,
        retry_input.clone(),
        PUBLIC,
        later,
        2,
    )
    .await
    .unwrap();
    let observed = provider.take();
    assert_request(&observed, &original, 2);
    assert_eq!(observed.result.unwrap(), next_offer);
    assert_prepared(&retry_input, &second, &next_offer, 2, 2, later);
    assert_eq!(ports.take(), ["organization"]);
    let outcomes = tokio::join!(
        repository.replace_active_artifacts(
            &retry.instance,
            retry.artifact.as_ref().unwrap(),
            created.instance.updated_at,
            later
        ),
        repository.replace_active_artifacts(
            &second.instance,
            second.artifact.as_ref().unwrap(),
            created.instance.updated_at,
            later
        )
    );
    let outcomes = [outcomes.0.unwrap(), outcomes.1.unwrap()];
    assert_eq!(outcomes.into_iter().filter(|success| *success).count(), 1);
    let winner = if outcomes[0] { &retry } else { &second };
    assert_eq!(
        repository.instance(&original.id).await.unwrap().unwrap(),
        winner.instance
    );
    let mut prior = created.artifact.unwrap();
    prior.status = ArtifactStatus::Expired;
    prior.updated_at = later;
    let mut expected = vec![prior, winner.artifact.clone().unwrap()];
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    let mut actual = repository
        .artifacts_for_instance(&original.id)
        .await
        .unwrap();
    actual.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(actual, expected);
    let prior_state = snapshot(&pool).await;
    assert_eq!(prior_state["transactions"].as_array().unwrap().len(), 2);
    ports.recovery_only.store(false, Ordering::SeqCst);
    let mut application = start(&definition, original.context.clone());
    application.context["application_id"] = json!("application-1");
    application.application_flow_key_hash = Some("a".repeat(64));
    let application_created = prepare(&providers, &definition, application.clone())
        .await
        .unwrap();
    let observed = provider.take();
    assert_request(&observed, &application, 1);
    let application_offer = observed.result.unwrap();
    assert_prepared(
        &application,
        &application_created,
        &application_offer,
        1,
        3,
        now(),
    );
    assert_eq!(
        ports.take(),
        [
            "organization",
            "template",
            "revocation",
            "clock",
            "seed",
            "issuer"
        ]
    );
    assert!(repository
        .save_started_instance(
            &application_created.instance,
            application_created.artifact.as_ref()
        )
        .await
        .unwrap());
    assert_eq!(
        repository.instance(&application.id).await.unwrap().unwrap(),
        application_created.instance
    );
    assert_eq!(
        repository
            .artifacts_for_instance(&application.id)
            .await
            .unwrap(),
        vec![application_created.artifact.clone().unwrap()]
    );
    let final_state = snapshot(&pool).await;
    let app_transaction = &final_state["transactions"][2];
    assert_eq!(app_transaction["application_id"], "application-1");
    assert_eq!(
        app_transaction["idempotency_key_hash"],
        key_hash(observed.request.idempotency_key.as_deref().unwrap())
    );
    ports.recovery_only.store(true, Ordering::SeqCst);
    let app_recovered = prepare(&providers, &definition, application.clone())
        .await
        .unwrap();
    let observed = provider.take();
    assert_request(&observed, &application, 1);
    assert_eq!(observed.result.unwrap(), application_offer);
    assert_prepared(
        &application,
        &app_recovered,
        &application_offer,
        1,
        3,
        now(),
    );
    assert_eq!(ports.take(), ["organization"]);
    assert!(!repository
        .save_started_instance(&app_recovered.instance, app_recovered.artifact.as_ref())
        .await
        .unwrap());
    assert_eq!(snapshot(&pool).await, final_state);
    assert_eq!(final_state["transactions"].as_array().unwrap().len(), 3);
    assert_eq!(final_state["transactions"][0], stored["transactions"][0]);
    assert_eq!(
        final_state["transactions"][1],
        prior_state["transactions"][1]
    );
    assert_eq!(seeds.next.load(Ordering::SeqCst), 3);
    for name in ["credentials", "deliveries", "events"] {
        assert_eq!(final_state[name], json!([]));
    }
    native.close().await;
    error(
        prepare(&providers, &definition, original.clone()).await,
        FlowProviderError::Unavailable {
            provider: "issuance",
        },
    );
    provider.take();
    assert_eq!(snapshot(&pool).await, final_state);
    for mixed in [false, true] {
        let mut wallets = vec![json!({"wallet_id":"didcomm","format_variant":"didcomm_v2"})];
        if mixed {
            wallets.push(json!({"wallet_id":"ordinary","format_variant":"default"}));
        }
        let ports = Arc::new(Ports {
            wallet_configs: Some(wallets),
            ..Default::default()
        });
        let seeds = Arc::new(Seeds {
            next: AtomicUsize::new(0),
            ports: ports.clone(),
        });
        let native = server(&pool, ports.clone(), seeds.clone()).await;
        let provider = ObservedProvider::new(&native, Some(TOKEN));
        let instance = start(&definition, original.context.clone());
        error(
            prepare(
                &registry(provider.clone(), "org-1"),
                &definition,
                instance.clone(),
            )
            .await,
            rejected(),
        );
        assert_request(&provider.take(), &instance, 1);
        assert_eq!(ports.take(), ["organization", "template", "revocation"]);
        assert_eq!(seeds.next.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&pool).await, final_state);
        native.close().await;
    }
    legacy.assert_no_requests();
    physical::run(&legacy).await;
    assert_eq!(snapshot(&pool).await, final_state);
    legacy.close().await;
    pool.close().await;
}
