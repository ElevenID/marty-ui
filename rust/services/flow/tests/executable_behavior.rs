use marty_flow::{CallbackDeliveryConfig, FlowDependency};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    implementation_owner: String,
    listeners: Listeners,
    lifecycle: Lifecycle,
    callback_delivery: CallbackDelivery,
    required_runtime_components: Vec<String>,
    python_fallback: bool,
    deployment_during_slice: bool,
}

#[derive(Deserialize)]
struct Listeners {
    http: String,
    grpc: String,
    addresses_must_differ: bool,
    bind_before_activation: bool,
    both_required: bool,
}

#[derive(Deserialize)]
struct Lifecycle {
    dependency_probes_before_bind: bool,
    listener_bind_before_active: bool,
    grpc_health_serving_after_active: bool,
    readiness_only_while_active: bool,
    shutdown_sequence: Vec<String>,
}

#[derive(Deserialize)]
struct CallbackDelivery {
    durable_claim: String,
    destination_revalidated_per_attempt: bool,
    redirects_followed: bool,
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
    success_status: String,
    retry_statuses: Vec<String>,
    destination_rejection: String,
    delivered_payload: String,
    expired_payload: String,
    default_retention_seconds: u64,
    retention_bounds_seconds: [u64; 2],
    default_max_attempts: u32,
    max_attempt_bounds: [u32; 2],
    default_lease_seconds: u64,
    lease_bounds_seconds: [u64; 2],
    default_poll_milliseconds: u64,
    poll_bounds_milliseconds: [u64; 2],
    default_retry_base_seconds: u64,
    retry_base_bounds_seconds: [u64; 2],
    default_retry_cap_seconds: u64,
    retry_cap_bounds_seconds: [u64; 2],
    default_batch_size: u32,
    batch_bounds: [u32; 2],
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/flow-executable-behavior.json"
    ))
    .expect("contract")
}

#[test]
fn executable_activates_only_after_complete_native_composition() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.implementation_owner, "marty-flow");
    assert_eq!(
        contract.listeners.http,
        "FLOW_HTTP_ADDR_or_FLOW_SERVICE_PORT"
    );
    assert_eq!(contract.listeners.grpc, "FLOW_GRPC_ADDR_or_FLOW_GRPC_PORT");
    assert!(contract.listeners.addresses_must_differ);
    assert!(contract.listeners.bind_before_activation);
    assert!(contract.listeners.both_required);
    assert!(contract.lifecycle.dependency_probes_before_bind);
    assert!(contract.lifecycle.listener_bind_before_active);
    assert!(contract.lifecycle.grpc_health_serving_after_active);
    assert!(contract.lifecycle.readiness_only_while_active);
    assert_eq!(
        contract.lifecycle.shutdown_sequence,
        [
            "draining",
            "grpc_not_serving",
            "listener_graceful_shutdown",
            "callback_worker_shutdown",
            "stopped"
        ]
    );
    assert_eq!(
        FlowDependency::all()
            .map(|dependency| dependency.name().to_owned())
            .collect::<Vec<_>>(),
        contract.required_runtime_components
    );
    assert!(!contract.python_fallback);
    assert!(!contract.deployment_during_slice);
}

#[test]
fn callback_worker_preserves_delivery_retry_and_retention_behavior() {
    let contract = contract();
    let defaults = CallbackDeliveryConfig::default();
    let callback = contract.callback_delivery;
    assert_eq!(callback.durable_claim, "skip_locked_fenced_lease");
    assert!(callback.destination_revalidated_per_attempt);
    assert!(!callback.redirects_followed);
    assert_eq!(callback.connect_timeout_seconds, 3);
    assert_eq!(callback.request_timeout_seconds, 10);
    assert_eq!(callback.success_status, "2xx");
    assert_eq!(
        callback.retry_statuses,
        ["non_2xx", "timeout", "network_error"]
    );
    assert_eq!(callback.destination_rejection, "dead_letter");
    assert_eq!(callback.delivered_payload, "scrubbed");
    assert_eq!(callback.expired_payload, "scrubbed");
    assert_eq!(
        defaults.retention_seconds,
        callback.default_retention_seconds
    );
    assert_eq!(callback.retention_bounds_seconds, [60, 86_400]);
    assert_eq!(defaults.max_attempts, callback.default_max_attempts);
    assert_eq!(callback.max_attempt_bounds, [1, 32]);
    assert_eq!(defaults.lease_seconds, callback.default_lease_seconds);
    assert_eq!(callback.lease_bounds_seconds, [5, 300]);
    assert_eq!(
        defaults.poll_milliseconds,
        callback.default_poll_milliseconds
    );
    assert_eq!(callback.poll_bounds_milliseconds, [100, 60_000]);
    assert_eq!(
        defaults.retry_base_seconds,
        callback.default_retry_base_seconds
    );
    assert_eq!(callback.retry_base_bounds_seconds, [1, 60]);
    assert_eq!(
        defaults.retry_cap_seconds,
        callback.default_retry_cap_seconds
    );
    assert_eq!(callback.retry_cap_bounds_seconds, [1, 900]);
    assert_eq!(defaults.batch_size, callback.default_batch_size);
    assert_eq!(callback.batch_bounds, [1, 100]);
}
