use marty_flow::FlowDependency;
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    required_probes: Vec<String>,
    database: DatabaseContract,
    nonce_store: NonceStoreContract,
    grpc: GrpcContract,
    http: HttpContract,
    provider_registry_must_be_complete: bool,
    activate_only_after_all_probes: bool,
    failure_behavior: String,
}

#[derive(Deserialize)]
struct DatabaseContract {
    migration_before_healthy: bool,
    probe: String,
}

#[derive(Deserialize)]
struct NonceStoreContract {
    configured_database_wins: bool,
    probe: String,
    required_response: String,
}

#[derive(Deserialize)]
struct GrpcContract {
    connection_mode: String,
    shared_mmf_transport_only: bool,
    required_clients: usize,
}

#[derive(Deserialize)]
struct HttpContract {
    probe_path: String,
    redirects: String,
    required_providers: usize,
}

#[test]
fn flow_connection_contract_freezes_fail_closed_startup_composition() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-connection-behavior.json"
    ))
    .expect("connection contract");

    assert_eq!(contract.schema_version, 1);
    assert_eq!(
        contract.required_probes,
        FlowDependency::all()
            .map(|dependency| dependency.name().to_owned())
            .collect::<Vec<_>>()
    );
    assert!(contract.database.migration_before_healthy);
    assert_eq!(contract.database.probe, "SELECT 1");
    assert!(contract.nonce_store.configured_database_wins);
    assert_eq!(contract.nonce_store.probe, "PING");
    assert_eq!(contract.nonce_store.required_response, "PONG");
    assert_eq!(contract.grpc.connection_mode, "eager");
    assert!(contract.grpc.shared_mmf_transport_only);
    assert_eq!(contract.grpc.required_clients, 4);
    assert_eq!(contract.http.probe_path, "/health");
    assert_eq!(contract.http.redirects, "disabled");
    assert_eq!(contract.http.required_providers, 2);
    assert!(contract.provider_registry_must_be_complete);
    assert!(contract.activate_only_after_all_probes);
    assert_eq!(contract.failure_behavior, "fail_closed");
}
