use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: u32,
    package: String,
    implementation_owner: String,
    operation_count: usize,
    operations: Vec<String>,
    ordinary_authentication: OrdinaryAuthentication,
    workload_authenticated_operations: WorkloadOperations,
    application_event_authentication: ApplicationAuthentication,
    mutation_atomicity: MutationAtomicity,
    projection: Projection,
    streaming: Streaming,
    health: Health,
    failure_behavior: FailureBehavior,
    python_fallback: bool,
}

#[derive(Debug, Deserialize)]
struct OrdinaryAuthentication {
    service_token_header: String,
    principal_header: String,
    tenant_membership_required: bool,
    failure_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WorkloadOperations {
    start_verification: String,
    application_approved: String,
}

#[derive(Debug, Deserialize)]
struct ApplicationAuthentication {
    owner: String,
    metadata_matches_http_headers: bool,
    protobuf_string_values: String,
    durable_reservation_before_replay_consumption: bool,
    duplicate_status: String,
}

#[derive(Debug, Deserialize)]
struct MutationAtomicity {
    start_instance_and_artifact: String,
    advance_instance: String,
    cancel_instance: String,
    verification_start: String,
    application_approved: String,
}

#[derive(Debug, Deserialize)]
struct Projection {
    private_context: String,
    complex_map_values: String,
    definition_status: String,
    instance_status: String,
    timestamps: String,
}

#[derive(Debug, Deserialize)]
struct Streaming {
    capacity: usize,
    tenant_filter_required: bool,
    instance_filter_supported: bool,
    flow_type_filter_supported: bool,
    slow_subscriber_status: String,
    disconnect_cleanup: String,
}

#[derive(Debug, Deserialize)]
struct Health {
    service_token_required: bool,
    database_probe_required: bool,
    healthy_status: String,
}

#[derive(Debug, Deserialize)]
struct FailureBehavior {
    malformed_input: String,
    missing_resource: String,
    invalid_state: String,
    concurrent_mutation: String,
    provider_unavailable: String,
    repository_unavailable: String,
}

#[test]
fn released_grpc_surface_is_owned_by_one_fail_closed_rust_adapter() {
    let contract: Contract =
        serde_json::from_str(include_str!("../../../../contracts/flow-grpc-behavior.json"))
            .expect("contract");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.package, "marty.ui.flow.v1");
    assert_eq!(contract.implementation_owner, "marty-flow.grpc_service");
    assert_eq!(contract.operation_count, 16);
    assert_eq!(contract.operations.len(), contract.operation_count);
    assert_eq!(
        contract.operations.first().map(String::as_str),
        Some("CreateFlowDefinition")
    );
    assert_eq!(
        contract.operations.last().map(String::as_str),
        Some("HealthCheck")
    );
    assert!(!contract.python_fallback);

    assert_eq!(
        contract.ordinary_authentication.service_token_header,
        "x-service-token"
    );
    assert_eq!(
        contract.ordinary_authentication.principal_header,
        "x-user-id"
    );
    assert!(contract.ordinary_authentication.tenant_membership_required);
    assert_eq!(
        contract.ordinary_authentication.failure_behavior,
        "fail_closed"
    );
    assert_eq!(
        contract
            .workload_authenticated_operations
            .start_verification,
        "spiffe://marty.internal/service/auth"
    );
    assert_eq!(
        contract
            .workload_authenticated_operations
            .application_approved,
        "spiffe://marty.internal/service/applicant"
    );
}

#[test]
fn grpc_mutations_streams_and_projections_have_behavioral_gates() {
    let contract: Contract =
        serde_json::from_str(include_str!("../../../../contracts/flow-grpc-behavior.json"))
            .expect("contract");
    assert_eq!(
        contract.application_event_authentication.owner,
        "mmf-security.application_event"
    );
    assert!(
        contract
            .application_event_authentication
            .metadata_matches_http_headers
    );
    assert_eq!(
        contract
            .application_event_authentication
            .protobuf_string_values,
        "decode_json_then_preserve_legacy_string"
    );
    assert!(
        contract
            .application_event_authentication
            .durable_reservation_before_replay_consumption
    );
    assert_eq!(
        contract.application_event_authentication.duplicate_status,
        "already_exists"
    );

    assert_eq!(
        contract.mutation_atomicity.start_instance_and_artifact,
        "single_transaction"
    );
    assert_eq!(
        contract.mutation_atomicity.advance_instance,
        "compare_and_swap"
    );
    assert_eq!(
        contract.mutation_atomicity.cancel_instance,
        "terminal_state_fenced"
    );
    assert_eq!(
        contract.mutation_atomicity.verification_start,
        "insert_once"
    );
    assert_eq!(
        contract.mutation_atomicity.application_approved,
        "durable_plan_and_idempotent_offer_completion"
    );
    assert_eq!(contract.projection.private_context, "redacted");
    assert_eq!(contract.projection.complex_map_values, "compact_json");
    assert_eq!(
        contract.projection.definition_status,
        "SCREAMING_SNAKE_CASE"
    );
    assert_eq!(contract.projection.instance_status, "SCREAMING_SNAKE_CASE");
    assert_eq!(contract.projection.timestamps, "RFC3339");

    assert_eq!(contract.streaming.capacity, 256);
    assert!(contract.streaming.tenant_filter_required);
    assert!(contract.streaming.instance_filter_supported);
    assert!(contract.streaming.flow_type_filter_supported);
    assert_eq!(
        contract.streaming.slow_subscriber_status,
        "resource_exhausted"
    );
    assert_eq!(contract.streaming.disconnect_cleanup, "automatic");
    assert!(contract.health.service_token_required);
    assert!(contract.health.database_probe_required);
    assert_eq!(contract.health.healthy_status, "serving");

    assert_eq!(
        contract.failure_behavior.malformed_input,
        "invalid_argument"
    );
    assert_eq!(contract.failure_behavior.missing_resource, "not_found");
    assert_eq!(
        contract.failure_behavior.invalid_state,
        "failed_precondition"
    );
    assert_eq!(contract.failure_behavior.concurrent_mutation, "aborted");
    assert_eq!(
        contract.failure_behavior.provider_unavailable,
        "unavailable"
    );
    assert_eq!(
        contract.failure_behavior.repository_unavailable,
        "unavailable"
    );
}
