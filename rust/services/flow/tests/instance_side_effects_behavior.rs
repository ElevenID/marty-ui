use std::{
    collections::BTreeSet,
    env,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_flow::{
    apply_physical_advance_side_effect, bound_definition_for_instance, create_definition_record,
    migrate_flow_schema, parse_request, prepare_instance_start, prepare_oid4vci_retry,
    start_instance_record, start_physical_instance, CreateFlowDefinitionRequest,
    CredentialTemplateProvider, CredentialTemplateReference, DefinitionStatus, FlowProviderError,
    FlowProviderRegistry, IssuanceInitiationRequest, IssuanceInitiationResult, IssuanceProvider,
    PhysicalDocumentOperation, PhysicalDocumentProvider, PhysicalDocumentRequest,
    PhysicalDocumentResult, PhysicalDocumentRoute, PhysicalStartError, PhysicalStartInvocation,
    PostgresFlowRepository, StartFlowRequest, WalletConfiguration,
};
use marty_verification::flow::TransitionOutcome;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};

#[path = "support/flow_schema.rs"]
mod flow_schema;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    oid4vci_provider: String,
    issuance_idempotency: String,
    wallet_offer_fallback: String,
    wallet_offer_configuration_suffixes: serde_json::Map<String, Value>,
    mip_offer_message_type: String,
    mip_offer_version: String,
    artifact_instance_persistence: String,
    artifact_retry_idempotency: String,
    artifact_retry_persistence: String,
    physical_initial_context: String,
    physical_operations: Vec<String>,
    physical_success_side_effects: String,
    physical_create_issuer_did_source: String,
    physical_create_issuer_did_override: String,
    physical_create_invalid_template: String,
    provider_identity_mismatch: String,
    missing_offer_uri: String,
}

#[derive(Clone)]
struct Templates {
    organization_id: &'static str,
    physical: bool,
}

#[derive(Clone)]
struct MutablePhysicalTemplate {
    issuer_did: Arc<Mutex<String>>,
}

#[async_trait]
impl CredentialTemplateProvider for MutablePhysicalTemplate {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        let mut template = Templates {
            organization_id: "org-1",
            physical: true,
        }
        .get_template(template_id)
        .await?;
        template.issuer_did = self.issuer_did.lock().unwrap().clone();
        Ok(template)
    }
}

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            id: template_id.into(),
            organization_id: self.organization_id.into(),
            status: "ACTIVE".into(),
            credential_type: "UniversityCredential".into(),
            vct: "urn:example:university".into(),
            doctype: String::new(),
            supported_formats: if self.physical {
                vec!["ICAO_EMRTD".into()]
            } else {
                vec!["vc+sd-jwt".into(), "mso_mdoc".into()]
            },
            claims: Vec::new(),
            issuer_did: "did:web:issuer.example".into(),
            credential_format: if self.physical {
                "ICAO_EMRTD"
            } else {
                "vc+sd-jwt"
            }
            .into(),
            issuance_protocol: if self.physical {
                "PHYSICAL_DOCUMENT"
            } else {
                "OID4VCI_PRE_AUTH"
            }
            .into(),
            wallet_configurations: vec![
                WalletConfiguration {
                    wallet_id: "generic".into(),
                    deep_link_scheme: "openid-credential-offer://".into(),
                    format_variant: None,
                    display_name: Some("Any Wallet".into()),
                },
                WalletConfiguration {
                    wallet_id: "mdoc".into(),
                    deep_link_scheme: "mdoc-wallet://offers?source=marty".into(),
                    format_variant: Some("mso_mdoc".into()),
                    display_name: Some("mDoc Wallet".into()),
                },
            ],
            issuer_algorithm: Some("ES256".into()),
        })
    }
}

#[derive(Clone, Default)]
struct Issuance {
    requests: Arc<Mutex<Vec<IssuanceInitiationRequest>>>,
}

#[async_trait]
impl IssuanceProvider for Issuance {
    async fn initiate(
        &self,
        request: &IssuanceInitiationRequest,
    ) -> Result<IssuanceInitiationResult, FlowProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(IssuanceInitiationResult {
            transaction_id: "transaction-1".into(),
            credential_offer_uri: None,
            credential_offer_uris: Default::default(),
            credential_offer_labels: Default::default(),
            pre_authorized_code: Some("pre-auth-1".into()),
            expires_at_ms: None,
            status: "offer_created".into(),
        })
    }
}

#[derive(Clone, Default)]
struct Physical {
    requests: Arc<Mutex<Vec<PhysicalDocumentRequest>>>,
}

#[async_trait]
impl PhysicalDocumentProvider for Physical {
    async fn execute(
        &self,
        request: &PhysicalDocumentRequest,
    ) -> Result<PhysicalDocumentResult, FlowProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        let (method, path) = match request.operation {
            PhysicalDocumentOperation::Initialize => {
                ("POST", "/v1/passport/applications".to_owned())
            }
            operation => {
                let suffix = match operation {
                    PhysicalDocumentOperation::GenerateDataGroups => "generate-data-groups",
                    PhysicalDocumentOperation::SignSod => "generate-sod",
                    PhysicalDocumentOperation::SubmitToPersonalization => "submit-personalization",
                    PhysicalDocumentOperation::TrackProduction => "production-status",
                    PhysicalDocumentOperation::QualityVerify => "quality-verify",
                    PhysicalDocumentOperation::ActivateCredential => "activate",
                    PhysicalDocumentOperation::Initialize => unreachable!(),
                };
                let method = if operation == PhysicalDocumentOperation::TrackProduction {
                    "GET"
                } else {
                    "POST"
                };
                (
                    method,
                    format!("/v1/passport/applications/application-1/{suffix}"),
                )
            }
        };
        let mut data = [
            ("application_id".into(), json!("application-1")),
            ("flow_execution_id".into(), json!(request.flow_instance_id)),
            ("status".into(), json!("DRAFT")),
        ]
        .into_iter()
        .collect::<std::collections::BTreeMap<String, Value>>();
        if request.operation == PhysicalDocumentOperation::SignSod {
            data.insert("sod_sha256".into(), json!("signed-hash"));
            data.insert("sod_signature_verified".into(), json!(true));
        }
        Ok(PhysicalDocumentResult {
            operation: request.operation,
            status: "DRAFT".into(),
            data,
            route: Some(PhysicalDocumentRoute {
                method: method.into(),
                path,
            }),
        })
    }
}

#[derive(Clone, Default)]
struct LostNativeResponse {
    inner: Physical,
    first_response_lost: Arc<AtomicBool>,
    owned_keys: Arc<Mutex<BTreeSet<String>>>,
}

#[async_trait]
impl PhysicalDocumentProvider for LostNativeResponse {
    async fn execute(
        &self,
        request: &PhysicalDocumentRequest,
    ) -> Result<PhysicalDocumentResult, FlowProviderError> {
        let key = request
            .start_idempotency_key
            .as_deref()
            .expect("physical Flow start must bind a native key");
        self.owned_keys.lock().unwrap().insert(key.to_owned());
        let response = self.inner.execute(request).await?;
        if !self.first_response_lost.swap(true, Ordering::SeqCst) {
            return Err(FlowProviderError::Unavailable {
                provider: "physical_document",
            });
        }
        Ok(response)
    }
}

#[tokio::test]
async fn physical_service_start_recovers_lost_provider_and_flow_finalize_responses() {
    let Ok(database_url) = env::var("FLOW_POSTGRES_TEST_URL") else {
        eprintln!("FLOW_POSTGRES_TEST_URL is not configured; PostgreSQL contract skipped");
        return;
    };
    let options =
        PgConnectOptions::from_str(&database_url.replace("postgresql+asyncpg://", "postgresql://"))
            .unwrap();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("marty_atomic_test"));
    let _schema_lock = flow_schema::lock_shared_test_schemas(&options)
        .await
        .unwrap();
    let pool = PgPool::connect_with(options).await.unwrap();
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS flow_service CASCADE;
        DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;
        CREATE SCHEMA deployment_profile_service;
        CREATE TABLE deployment_profile_service.deployment_profiles(
            id text PRIMARY KEY, enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb);
        INSERT INTO deployment_profile_service.deployment_profiles(id)
            VALUES ('70000000-0000-0000-0000-000000000001');",
    )
    .execute(&pool)
    .await
    .unwrap();
    migrate_flow_schema(&pool).await.unwrap();
    let repo = PostgresFlowRepository::new(pool.clone());
    let definition = definition("physical_document_issuance");
    let request: StartFlowRequest = parse_request(json!({
        "organization_id":"org-1", "flow_definition_id":definition.id,
        "subject_id":"subject-1", "initial_context":{"physical_document":{
            "country_code":"USA", "applicant":{"name":"Synthetic"},
            "mrz":{"line1":"P<TEST"}, "data_groups":{"DG1":"MQ=="}
        }}
    }))
    .unwrap();
    let native = LostNativeResponse::default();
    let issuer_did = Arc::new(Mutex::new("did:web:issuer.example".to_owned()));
    let providers = FlowProviderRegistry {
        credential_template: Some(Arc::new(MutablePhysicalTemplate {
            issuer_did: issuer_did.clone(),
        })),
        physical_document: Some(Arc::new(native.clone())),
        ..Default::default()
    };
    let key = "stable-client-key";
    let started = start_physical_instance(
        &repo,
        &providers,
        &definition,
        PhysicalStartInvocation {
            request: request.clone(),
            actor: "actor-1",
            public_base_url: "https://issuer.example",
            now: now(),
            client_key: Some(key),
        },
    )
    .await;
    assert!(started.is_err());
    let pending = repo.pending_physical_starts("org-1", 10, 0).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key_source, "client");
    let stored_snapshot = repo
        .physical_start_snapshot_by_instance("org-1", &pending[0].instance_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_snapshot["issuer_did"], "did:web:issuer.example");
    assert_eq!(stored_snapshot["definition"]["id"], definition.id);
    let stored_bytes = stored_snapshot.to_string();
    assert!(!stored_bytes.contains("P<TEST"));
    assert!(!stored_bytes.contains("Synthetic"));
    assert!(!stored_bytes.contains("initial_context"));
    assert!(repo
        .instance(&pending[0].instance_id)
        .await
        .unwrap()
        .is_none());

    // A lost native response must retain the original graph and public issuer identity.
    let mut changed_definition = definition.clone();
    changed_definition.status = DefinitionStatus::Draft;
    changed_definition.credential_template_id = Some("template-new".into());
    changed_definition.application_template_id = Some("application-new".into());
    changed_definition.delivery_destination_profile_id = Some("delivery-new".into());
    changed_definition.steps.clear();
    changed_definition.transitions.clear();
    *issuer_did.lock().unwrap() = "did:web:other.example".into();

    sqlx::raw_sql(
        "CREATE FUNCTION flow_service.reject_test_start() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated test failure'; END $$;
        CREATE TRIGGER reject_test_start BEFORE INSERT ON flow_service.flow_instances
        FOR EACH ROW EXECUTE FUNCTION flow_service.reject_test_start();",
    )
    .execute(&pool)
    .await
    .unwrap();
    let second = start_physical_instance(
        &repo,
        &providers,
        &changed_definition,
        PhysicalStartInvocation {
            request: request.clone(),
            actor: "actor-2",
            public_base_url: "https://issuer.example",
            now: now() + chrono::Duration::seconds(61),
            client_key: Some(key),
        },
    )
    .await;
    assert!(second.is_err());
    assert!(repo
        .instance(&pending[0].instance_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repo.pending_physical_starts("org-1", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_test_start ON flow_service.flow_instances;
        DROP FUNCTION flow_service.reject_test_start();",
    )
    .execute(&pool)
    .await
    .unwrap();

    let third = start_physical_instance(
        &repo,
        &providers,
        &changed_definition,
        PhysicalStartInvocation {
            request: request.clone(),
            actor: "actor-3",
            public_base_url: "https://issuer.example",
            now: now() + chrono::Duration::seconds(122),
            client_key: Some(key),
        },
    )
    .await
    .unwrap();
    assert!(third.created);
    assert_eq!(third.instance.id, pending[0].instance_id);
    assert_eq!(third.instance.started_at, Some(now()));
    assert_eq!(third.instance.created_at, now());
    assert_eq!(third.instance.updated_at, now());
    assert_eq!(
        third.instance.expires_at,
        Some(now() + chrono::Duration::seconds(i64::from(definition.default_timeout_seconds)))
    );
    assert_eq!(third.instance.state_history[0]["actor"], "actor-1");
    assert!(third.instance.context.get("physical_document").is_none());
    assert!(repo
        .pending_physical_starts("org-1", 10, 0)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(native.owned_keys.lock().unwrap().len(), 1);
    let original = bound_definition_for_instance(&repo, &third.instance)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original, definition);
    let first_native = native.inner.requests.lock().unwrap()[0].clone();
    assert_eq!(first_native.data["issuer_did"], "did:web:issuer.example");
    assert_eq!(first_native.data["credential_template_id"], "template-1");
    assert_eq!(
        first_native.data["application_template_id"],
        "application-template-1"
    );
    assert_eq!(
        first_native.data["delivery_destination_profile_id"],
        "delivery-1"
    );
    let mut next = third.instance.clone();
    next.current_step_id = original.steps.iter().find_map(|step| {
        (step["config"]["protocol_step"] == "generate_data_groups")
            .then(|| step["id"].as_str().unwrap().to_owned())
    });
    assert!(next.current_step_id.is_some());
    let advance_providers = FlowProviderRegistry {
        physical_document: Some(Arc::new(native.inner.clone())),
        ..Default::default()
    };
    let advanced = apply_physical_advance_side_effect(
        &advance_providers,
        &original,
        next,
        TransitionOutcome::Success,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        advanced.context["physical_document_job"]["application_id"],
        "application-1"
    );
    assert_eq!(
        native
            .inner
            .requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .operation,
        PhysicalDocumentOperation::GenerateDataGroups
    );
    let native_calls = native.inner.requests.lock().unwrap().len();
    let replay = start_physical_instance(
        &repo,
        &providers,
        &changed_definition,
        PhysicalStartInvocation {
            request: request.clone(),
            actor: "actor-1",
            public_base_url: "https://issuer.example",
            now: now() + chrono::Duration::seconds(123),
            client_key: Some(key),
        },
    )
    .await
    .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.instance.id, third.instance.id);
    assert_eq!(native.inner.requests.lock().unwrap().len(), native_calls);
    let mut changed = request.clone();
    changed.initial_context["physical_document"]["applicant"]["name"] = json!("Changed");
    assert!(start_physical_instance(
        &repo,
        &providers,
        &changed_definition,
        PhysicalStartInvocation {
            request: changed,
            actor: "actor-1",
            public_base_url: "https://issuer.example",
            now: now() + chrono::Duration::seconds(124),
            client_key: Some(key),
        }
    )
    .await
    .is_err());
    assert_eq!(native.inner.requests.lock().unwrap().len(), native_calls);

    let expired_native = LostNativeResponse::default();
    let expired_providers = FlowProviderRegistry {
        credential_template: Some(Arc::new(MutablePhysicalTemplate {
            issuer_did: issuer_did.clone(),
        })),
        physical_document: Some(Arc::new(expired_native.clone())),
        ..Default::default()
    };
    let expired_key = "expired-client-key";
    let initial_at = now() + chrono::Duration::seconds(200);
    let expired_request = request;
    assert!(start_physical_instance(
        &repo,
        &expired_providers,
        &definition,
        PhysicalStartInvocation {
            request: expired_request.clone(),
            actor: "actor-first",
            public_base_url: "https://issuer.example",
            now: initial_at,
            client_key: Some(expired_key),
        },
    )
    .await
    .is_err());
    let native_before_expiry = expired_native.inner.requests.lock().unwrap().len();
    assert!(matches!(
        start_physical_instance(
            &repo,
            &expired_providers,
            &changed_definition,
            PhysicalStartInvocation {
                request: expired_request,
                actor: "actor-later",
                public_base_url: "https://issuer.example",
                now: initial_at
                    + chrono::Duration::seconds(i64::from(definition.default_timeout_seconds) + 1),
                client_key: Some(expired_key),
            },
        )
        .await,
        Err(PhysicalStartError::Expired)
    ));
    assert_eq!(
        expired_native.inner.requests.lock().unwrap().len(),
        native_before_expiry
    );
    assert_eq!(
        repo.pending_physical_starts("org-1", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS flow_service CASCADE;
        DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn definition(flow_type: &str) -> marty_flow::FlowDefinitionRecord {
    let body = if flow_type == "physical_document_issuance" {
        json!({
            "organization_id": "org-1",
            "name": "Physical issuance",
            "flow_type": flow_type,
            "credential_template_id": "template-1",
            "application_template_id": "application-template-1",
            "delivery_destination_profile_id": "delivery-1"
        })
    } else {
        json!({
            "organization_id": "org-1",
            "name": "Wallet issuance",
            "flow_type": flow_type,
            "credential_template_id": "template-1"
        })
    };
    let request: CreateFlowDefinitionRequest = parse_request(body).unwrap();
    let mut definition = create_definition_record(request, now()).unwrap();
    definition.status = DefinitionStatus::Active;
    definition
}

fn start(
    definition: &marty_flow::FlowDefinitionRecord,
    initial_context: Value,
) -> marty_flow::FlowInstanceRecord {
    let request: StartFlowRequest = parse_request(json!({
        "organization_id": "org-1",
        "flow_definition_id": definition.id,
        "subject_id": "subject-1",
        "initial_context": initial_context
    }))
    .unwrap();
    start_instance_record(definition, request, "user-1", now()).unwrap()
}

#[tokio::test]
async fn language_neutral_contract_drives_oid4vci_and_mip_behavior() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-instance-side-effects-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.oid4vci_provider, "typed_issuance_only");
    assert_eq!(contract.issuance_idempotency, "flow_instance_bound");
    assert_eq!(
        contract.wallet_offer_fallback,
        "rust_oid4vci_from_template_wallet_configurations"
    );
    assert_eq!(contract.wallet_offer_configuration_suffixes.len(), 2);
    assert_eq!(contract.mip_offer_message_type, "CredentialOffer");
    assert_eq!(contract.mip_offer_version, "0.3.1");
    assert_eq!(contract.artifact_instance_persistence, "atomic");
    assert_eq!(
        contract.artifact_retry_idempotency,
        "flow_and_attempt_bound"
    );
    assert_eq!(
        contract.artifact_retry_persistence,
        "expire_old_insert_new_and_update_instance_atomic"
    );
    assert_eq!(contract.physical_initial_context, "consumed_not_persisted");
    assert_eq!(contract.physical_operations.len(), 7);
    assert_eq!(
        contract.physical_success_side_effects,
        "before_state_transition"
    );
    assert_eq!(
        contract.physical_create_issuer_did_source,
        "active_tenant_bound_credential_template_reference"
    );
    assert_eq!(
        contract.physical_create_issuer_did_override,
        "initial_context_cannot_override_template_issuer"
    );
    assert_eq!(
        contract.physical_create_invalid_template,
        "reject_before_native_application_create"
    );
    assert_eq!(contract.provider_identity_mismatch, "fail_closed");
    assert_eq!(contract.missing_offer_uri, "fail_closed");

    let issuance = Issuance::default();
    let definition = definition("oid4vci_pre_authorized");
    let instance = start(&definition, json!({"claims": {"degree": "BSc"}}));
    let prepared = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
                physical: false,
            })),
            issuance: Some(Arc::new(issuance.clone())),
            ..Default::default()
        },
        &definition,
        instance,
        "https://issuer.example",
        now(),
    )
    .await
    .unwrap();
    let artifact = prepared.artifact.unwrap();
    assert_eq!(
        artifact.issuance_transaction_id.as_deref(),
        Some("transaction-1")
    );
    assert!(artifact.credential_offer_uris["generic"].contains("UniversityCredential%23sd-jwt"));
    assert!(artifact.credential_offer_uris["mdoc"].contains("UniversityCredential%23mdoc"));
    assert_eq!(artifact.credential_offer_labels["generic"], "Any Wallet");
    assert_eq!(
        prepared.instance.context["credential_offer_transaction_id"],
        "transaction-1"
    );
    let message = &prepared.instance.context["mip_messages"]["credential_offer"];
    assert_eq!(message["message_type"], contract.mip_offer_message_type);
    assert_eq!(message["mip_version"], contract.mip_offer_version);
    assert_eq!(
        message["payload"]["credential_issuer"],
        "https://issuer.example"
    );
    assert_eq!(
        message["payload"]["credential_configuration_ids"][0],
        "template-1"
    );
    assert_eq!(
        message["payload"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"],
        "pre-auth-1"
    );
    let retry_at = now() + chrono::Duration::microseconds(1);
    let original_timestamp = prepared.instance.updated_at;
    let retry = prepare_oid4vci_retry(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
                physical: false,
            })),
            issuance: Some(Arc::new(issuance.clone())),
            ..Default::default()
        },
        &definition,
        prepared.instance.clone(),
        "https://issuer.example",
        retry_at,
        2,
    )
    .await
    .unwrap();
    assert_eq!(prepared.instance.updated_at, original_timestamp);
    assert_eq!(retry.instance.updated_at, retry_at);
    assert!(retry.instance.updated_at > original_timestamp);
    assert_eq!(retry.instance.created_at, prepared.instance.created_at);
    let retry_artifact = retry.artifact.unwrap();
    assert_eq!(retry_artifact.attempt_number, 2);
    assert_eq!(retry_artifact.created_at, retry_at);
    let requests = issuance.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some(format!("flow-instance-offer-v1:{}", prepared.instance.id).as_str())
    );
    assert_eq!(
        requests[1].idempotency_key.as_deref(),
        Some(format!("flow-instance-offer-v1:{}:2", prepared.instance.id).as_str())
    );
}

#[tokio::test]
async fn physical_inputs_are_consumed_and_every_operation_is_typed() {
    let physical = Physical::default();
    let definition = definition("physical_document_issuance");
    let instance = start(
        &definition,
        json!({"physical_document": {
            "country_code": "USA",
            "applicant": {"name": "Example"},
            "mrz": {"line1": "P<USA"},
            "data_groups": {"DG1": "MQ==", "DG2": "Mg=="},
            "issuer_did": "did:web:untrusted.example"
        }}),
    );
    let prepared = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
                physical: true,
            })),
            physical_document: Some(Arc::new(physical.clone())),
            ..Default::default()
        },
        &definition,
        instance,
        "https://issuer.example",
        now(),
    )
    .await
    .unwrap();
    assert!(prepared.instance.context.get("physical_document").is_none());
    assert_eq!(prepared.instance.context["application_id"], "application-1");
    assert_eq!(
        physical.requests.lock().unwrap()[0].operation,
        PhysicalDocumentOperation::Initialize
    );
    assert_eq!(
        physical.requests.lock().unwrap()[0].data["issuer_did"],
        json!("did:web:issuer.example")
    );

    let providers = FlowProviderRegistry {
        physical_document: Some(Arc::new(physical.clone())),
        ..Default::default()
    };
    let mut advanced = prepared.instance;
    for (protocol_step, expected) in [
        (
            "generate_data_groups",
            PhysicalDocumentOperation::GenerateDataGroups,
        ),
        ("sign_sod", PhysicalDocumentOperation::SignSod),
        (
            "submit_to_personalization",
            PhysicalDocumentOperation::SubmitToPersonalization,
        ),
        (
            "track_production",
            PhysicalDocumentOperation::TrackProduction,
        ),
        ("quality_verify", PhysicalDocumentOperation::QualityVerify),
        (
            "activate_credential",
            PhysicalDocumentOperation::ActivateCredential,
        ),
    ] {
        advanced.current_step_id = definition.steps.iter().find_map(|step| {
            (step["config"]["protocol_step"] == protocol_step)
                .then(|| step["id"].as_str().unwrap().to_owned())
        });
        advanced = apply_physical_advance_side_effect(
            &providers,
            &definition,
            advanced,
            TransitionOutcome::Success,
            &json!({"passed": true, "failure_codes": []}),
        )
        .await
        .unwrap();
        assert_eq!(
            physical.requests.lock().unwrap().last().unwrap().operation,
            expected
        );
    }
    assert!(advanced.context["physical_document_job"].is_object());
    assert_eq!(
        advanced.context["physical_document_job"]["sod_sha256"],
        "signed-hash"
    );
    assert_eq!(
        advanced.context["physical_document_job"]["sod_signature_verified"],
        true
    );
    assert_eq!(physical.requests.lock().unwrap().len(), 7);
    assert_eq!(
        advanced.context["physical_document_route_trace"],
        json!([
            {"method": "POST", "path": "/v1/passport/applications"},
            {"method": "POST", "path": "/v1/passport/applications/application-1/generate-data-groups"},
            {"method": "POST", "path": "/v1/passport/applications/application-1/generate-sod"},
            {"method": "POST", "path": "/v1/passport/applications/application-1/submit-personalization"},
            {"method": "GET", "path": "/v1/passport/applications/application-1/production-status"},
            {"method": "POST", "path": "/v1/passport/applications/application-1/quality-verify"},
            {"method": "POST", "path": "/v1/passport/applications/application-1/activate"},
        ])
    );
}

#[tokio::test]
async fn physical_create_rejects_cross_tenant_template_before_native_call() {
    let physical = Physical::default();
    let definition = definition("physical_document_issuance");
    let instance = start(
        &definition,
        json!({"physical_document": {
            "country_code": "USA",
            "applicant": {"name": "Example"},
            "mrz": {"line1": "P<USA"},
            "data_groups": {"DG1": "MQ=="}
        }}),
    );
    let error = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-2",
                physical: true,
            })),
            physical_document: Some(Arc::new(physical.clone())),
            ..Default::default()
        },
        &definition,
        instance,
        "https://issuer.example",
        now(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("credential template binding"));
    assert!(physical.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn physical_create_rejects_a_wallet_template_before_native_call() {
    let physical = Physical::default();
    let definition = definition("physical_document_issuance");
    let instance = start(
        &definition,
        json!({"physical_document": {
            "country_code": "USA",
            "applicant": {"name": "Example"},
            "mrz": {"line1": "P<USA"},
            "data_groups": {"DG1": "MQ=="}
        }}),
    );
    let error = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
                physical: false,
            })),
            physical_document: Some(Arc::new(physical.clone())),
            ..Default::default()
        },
        &definition,
        instance,
        "https://issuer.example",
        now(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("ICAO_EMRTD"));
    assert!(physical.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cross_tenant_template_response_fails_closed() {
    let definition = definition("oid4vci_pre_authorized");
    let error = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-2",
                physical: false,
            })),
            issuance: Some(Arc::new(Issuance::default())),
            ..Default::default()
        },
        &definition,
        start(&definition, json!({})),
        "https://issuer.example",
        now(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("credential template binding"));
}
