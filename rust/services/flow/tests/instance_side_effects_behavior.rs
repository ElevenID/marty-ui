use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_flow::{
    apply_physical_advance_side_effect, create_definition_record, parse_request,
    prepare_instance_start, prepare_oid4vci_retry, start_instance_record,
    CreateFlowDefinitionRequest, CredentialTemplateProvider, CredentialTemplateReference,
    DefinitionStatus, FlowProviderError, FlowProviderRegistry, IssuanceInitiationRequest,
    IssuanceInitiationResult, IssuanceProvider, PhysicalDocumentOperation,
    PhysicalDocumentProvider, PhysicalDocumentRequest, PhysicalDocumentResult, StartFlowRequest,
    WalletConfiguration,
};
use marty_verification::flow::TransitionOutcome;
use serde::Deserialize;
use serde_json::{json, Value};

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
    provider_identity_mismatch: String,
    missing_offer_uri: String,
}

#[derive(Clone)]
struct Templates {
    organization_id: &'static str,
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
            supported_formats: vec!["vc+sd-jwt".into(), "mso_mdoc".into()],
            claims: Vec::new(),
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "vc+sd-jwt".into(),
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
        Ok(PhysicalDocumentResult {
            operation: request.operation,
            status: "DRAFT".into(),
            data: [
                ("application_id".into(), json!("application-1")),
                ("flow_execution_id".into(), json!(request.flow_instance_id)),
                ("status".into(), json!("DRAFT")),
            ]
            .into_iter()
            .collect(),
        })
    }
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
    assert_eq!(contract.provider_identity_mismatch, "fail_closed");
    assert_eq!(contract.missing_offer_uri, "fail_closed");

    let issuance = Issuance::default();
    let definition = definition("oid4vci_pre_authorized");
    let instance = start(&definition, json!({"claims": {"degree": "BSc"}}));
    let prepared = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
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
    let retry = prepare_oid4vci_retry(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-1",
            })),
            issuance: Some(Arc::new(issuance.clone())),
            ..Default::default()
        },
        &definition,
        prepared.instance.clone(),
        "https://issuer.example",
        now(),
        2,
    )
    .await
    .unwrap();
    assert_eq!(retry.artifact.unwrap().attempt_number, 2);
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
            "data_groups": {"DG1": "MQ==", "DG2": "Mg=="}
        }}),
    );
    let prepared = prepare_instance_start(
        &FlowProviderRegistry {
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
    assert_eq!(physical.requests.lock().unwrap().len(), 7);
}

#[tokio::test]
async fn cross_tenant_template_response_fails_closed() {
    let definition = definition("oid4vci_pre_authorized");
    let error = prepare_instance_start(
        &FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                organization_id: "org-2",
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
