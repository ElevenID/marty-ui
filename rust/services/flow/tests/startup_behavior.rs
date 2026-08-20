use std::collections::BTreeMap;

use marty_flow::{Environment, FlowConfigError, FlowServiceConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    deployed_environments: Vec<String>,
    required_always: Vec<String>,
    required_when_deployed: Vec<String>,
    minimum_secret_bytes: usize,
    secret_file_suffix: String,
    listener_port_aliases: Vec<String>,
    database_driver_alias: String,
    database_schemes: Vec<String>,
    redis_schemes: Vec<String>,
    dependency_schemes: Vec<String>,
    workload_transport: String,
    partial_tls_behavior: String,
    database_connection_bounds: Vec<u32>,
    redis_database_bounds: Vec<u32>,
    fail_closed_cases: Vec<String>,
}

fn baseline(environment: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ENVIRONMENT".into(), environment.into()),
        ("PUBLIC_BASE_URL".into(), "https://issuer.example".into()),
        (
            "FLOW_CALLBACK_DESTINATIONS".into(),
            "org-1|https://callback.example/result?nonce=__MARTY_TOKEN__".into(),
        ),
        ("DATABASE_URL".into(), "postgresql://db/flow".into()),
        ("REDIS_URL".into(), "redis://redis:6379".into()),
        ("ORG_GRPC_TARGET".into(), "organization:9002".into()),
        ("CT_GRPC_TARGET".into(), "credential-template:9003".into()),
        ("PP_GRPC_TARGET".into(), "presentation-policy:9009".into()),
        ("ISSUANCE_GRPC_TARGET".into(), "issuance:9006".into()),
        (
            "SIGNING_KEYS_INTERNAL_URL".into(),
            "http://signing-keys:8017".into(),
        ),
        (
            "CREDENTIAL_TEMPLATE_SERVICE_URL".into(),
            "http://credential-template:8003".into(),
        ),
        (
            "TRUST_PROFILE_SERVICE_URL".into(),
            "http://trust-profile:8004".into(),
        ),
        (
            "DEPLOYMENT_PROFILE_SERVICE_URL".into(),
            "http://deployment-profile:8010".into(),
        ),
        ("ISSUANCE_SERVICE_URL".into(), "http://issuance:8006".into()),
        ("GRPC_SERVICE_TOKEN".into(), "s".repeat(32)),
        ("FLOW_WEBHOOK_SECRET".into(), "w".repeat(32)),
        ("SIGNING_KEYS_INTERNAL_API_KEY".into(), "k".repeat(32)),
        ("ISSUANCE_API_KEY".into(), "i".repeat(32)),
        ("GRPC_INSECURE_ALLOWED".into(), "true".into()),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_CERT".into(),
            "/run/secrets/flow-client-cert".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_KEY".into(),
            "/run/secrets/flow-client-key".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_CERT".into(),
            "/run/secrets/flow-server-cert".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_KEY".into(),
            "/run/secrets/flow-server-key".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_CA_CERT".into(),
            "/run/secrets/workload-ca".into(),
        ),
    ])
}

#[test]
fn language_neutral_startup_contract_is_frozen() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-startup-behavior.json"
    ))
    .expect("valid startup contract");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.deployed_environments, ["beta", "production"]);
    assert_eq!(contract.required_always, ["DATABASE_URL", "REDIS_URL"]);
    assert_eq!(contract.required_when_deployed.len(), 21);
    assert_eq!(contract.minimum_secret_bytes, 32);
    assert_eq!(contract.secret_file_suffix, "_FILE");
    assert_eq!(
        contract.listener_port_aliases,
        ["FLOW_SERVICE_PORT", "FLOW_GRPC_PORT"]
    );
    assert_eq!(contract.database_driver_alias, "postgresql+asyncpg");
    assert_eq!(contract.database_schemes, ["postgres", "postgresql"]);
    assert_eq!(contract.redis_schemes, ["redis", "rediss"]);
    assert_eq!(contract.dependency_schemes, ["http", "https"]);
    assert_eq!(contract.workload_transport, "mutual_tls");
    assert_eq!(contract.partial_tls_behavior, "fail_closed");
    assert_eq!(contract.database_connection_bounds, [1, 100]);
    assert_eq!(contract.redis_database_bounds, [0, 255]);
    assert_eq!(contract.fail_closed_cases.len(), 13);
}

#[test]
fn deployed_configuration_is_complete_and_normalized() {
    let config = FlowServiceConfig::from_values(baseline("beta")).expect("valid beta config");
    assert_eq!(config.environment, Environment::Beta);
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8011");
    assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9011");
    assert_eq!(config.public_base_url, "https://issuer.example");
    assert!(!config.callback_destinations.is_empty());
    assert_eq!(config.organization_grpc_target, "http://organization:9002");
    assert!(config.workload_client_tls.is_some());
    assert!(config.workload_server_tls.is_some());
}

#[test]
fn deployed_configuration_fails_closed() {
    for required in [
        "DATABASE_URL",
        "REDIS_URL",
        "PUBLIC_BASE_URL",
        "FLOW_CALLBACK_DESTINATIONS",
        "ORG_GRPC_TARGET",
        "CT_GRPC_TARGET",
        "PP_GRPC_TARGET",
        "ISSUANCE_GRPC_TARGET",
        "SIGNING_KEYS_INTERNAL_URL",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "TRUST_PROFILE_SERVICE_URL",
        "DEPLOYMENT_PROFILE_SERVICE_URL",
        "ISSUANCE_SERVICE_URL",
        "GRPC_SERVICE_TOKEN",
        "FLOW_WEBHOOK_SECRET",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "ISSUANCE_API_KEY",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
        "GRPC_WORKLOAD_TLS_CA_CERT",
    ] {
        let mut values = baseline("production");
        values.remove(required);
        let error_name = match required {
            "ORG_GRPC_TARGET" => "ORGANIZATION_GRPC_TARGET",
            "GRPC_WORKLOAD_TLS_CLIENT_KEY" | "GRPC_WORKLOAD_TLS_CA_CERT" => {
                "GRPC_WORKLOAD_TLS_CLIENT_CERT"
            }
            "GRPC_WORKLOAD_TLS_SERVER_KEY" => "GRPC_WORKLOAD_TLS_SERVER_CERT",
            _ => required,
        };
        let expected = if required.starts_with("GRPC_WORKLOAD_TLS_") {
            FlowConfigError::Invalid { name: error_name }
        } else {
            FlowConfigError::Missing { name: error_name }
        };
        assert_eq!(FlowServiceConfig::from_values(values), Err(expected));
    }

    let mut short_secret = baseline("beta");
    short_secret.insert("FLOW_WEBHOOK_SECRET".into(), "short".into());
    assert!(matches!(
        FlowServiceConfig::from_values(short_secret),
        Err(FlowConfigError::SecretTooShort { .. })
    ));

    let mut credentialed = baseline("beta");
    credentialed.insert(
        "SIGNING_KEYS_INTERNAL_URL".into(),
        "https://user:password@signing-keys".into(),
    );
    assert_eq!(
        FlowServiceConfig::from_values(credentialed),
        Err(FlowConfigError::Invalid {
            name: "SIGNING_KEYS_INTERNAL_URL"
        })
    );

    let mut path = baseline("beta");
    path.insert(
        "SIGNING_KEYS_INTERNAL_URL".into(),
        "https://signing-keys/internal".into(),
    );
    assert_eq!(
        FlowServiceConfig::from_values(path),
        Err(FlowConfigError::Invalid {
            name: "SIGNING_KEYS_INTERNAL_URL"
        })
    );

    let mut shared = baseline("beta");
    shared.insert("FLOW_GRPC_ADDR".into(), "0.0.0.0:8011".into());
    assert_eq!(
        FlowServiceConfig::from_values(shared),
        Err(FlowConfigError::Invalid {
            name: "FLOW_GRPC_ADDR"
        })
    );

    let mut insecure = baseline("production");
    insecure.insert("GRPC_INSECURE_ALLOWED".into(), "false".into());
    assert_eq!(
        FlowServiceConfig::from_values(insecure),
        Err(FlowConfigError::Invalid {
            name: "GRPC_INSECURE_ALLOWED"
        })
    );

    let mut insecure_public_origin = baseline("production");
    insecure_public_origin.insert("PUBLIC_BASE_URL".into(), "http://issuer.example".into());
    assert_eq!(
        FlowServiceConfig::from_values(insecure_public_origin),
        Err(FlowConfigError::Invalid {
            name: "PUBLIC_BASE_URL"
        })
    );

    for malformed in [
        "; ;",
        "org-1|https://user:password@callback.example/result",
        "org-1|file:///tmp/result",
    ] {
        let mut values = baseline("production");
        values.insert("FLOW_CALLBACK_DESTINATIONS".into(), malformed.into());
        assert_eq!(
            FlowServiceConfig::from_values(values),
            Err(FlowConfigError::Invalid {
                name: "FLOW_CALLBACK_DESTINATIONS"
            })
        );
    }
}

#[test]
fn local_mode_allows_only_non_secret_dependency_defaults() {
    let values = BTreeMap::from([
        ("ENVIRONMENT".into(), "development".into()),
        ("DATABASE_URL".into(), "postgres://db/flow".into()),
        ("REDIS_URL".into(), "redis://redis".into()),
    ]);
    let config = FlowServiceConfig::from_values(values).expect("development defaults");
    assert_eq!(config.environment, Environment::Development);
    assert_eq!(config.issuance_grpc_target, "http://issuance:9006");
    assert_eq!(config.public_base_url, "http://localhost:8000");
    assert!(config.service_token.is_none());
    assert!(config.webhook_secret.is_none());
    assert!(config.callback_destinations.is_empty());
}

#[test]
fn deployed_aliases_preserve_existing_container_configuration() {
    let mut values = baseline("production");
    values.insert(
        "DATABASE_URL".into(),
        "postgresql+asyncpg://marty:secret@postgres:5432/marty".into(),
    );
    values.insert("FLOW_SERVICE_PORT".into(), "8111".into());
    values.insert("FLOW_GRPC_PORT".into(), "9111".into());
    let config = FlowServiceConfig::from_values(values).expect("container aliases");
    assert_eq!(
        config.database_url,
        "postgresql://marty:secret@postgres:5432/marty"
    );
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8111");
    assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9111");
    let debug = format!("{config:?}");
    assert!(!debug.contains("marty:secret"));
    assert!(debug.contains("[REDACTED]"));
}
