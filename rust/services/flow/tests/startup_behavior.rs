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
    application_event_auth: ApplicationEventAuth,
    verifier_profiles: VerifierProfiles,
    fail_closed_cases: Vec<String>,
}

#[derive(Deserialize)]
struct ApplicationEventAuth {
    owner: String,
    max_age_default_seconds: u32,
    replay_ttl_default_seconds: u32,
    replay_ttl_must_cover_max_age: bool,
    organization_id_default: String,
}

#[derive(Deserialize)]
struct VerifierProfiles {
    client_id_schemes: Vec<String>,
    did_methods: Vec<String>,
    issuer_did_sources: Vec<String>,
    request_length_bounds: Vec<u32>,
    x509_certificate_sources: Vec<String>,
    dc_api_expected_origins: String,
    haip_default: bool,
    strict_metadata_default: bool,
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
        ("FLOW_APPLICATION_EVENT_HMAC_KEY".into(), "a".repeat(32)),
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
    assert_eq!(contract.required_when_deployed.len(), 22);
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
    assert_eq!(
        contract.application_event_auth.owner,
        "mmf-security.application_event"
    );
    assert_eq!(contract.application_event_auth.max_age_default_seconds, 60);
    assert_eq!(
        contract.application_event_auth.replay_ttl_default_seconds,
        300
    );
    assert!(
        contract
            .application_event_auth
            .replay_ttl_must_cover_max_age
    );
    assert_eq!(
        contract.application_event_auth.organization_id_default,
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(contract.verifier_profiles.client_id_schemes.len(), 3);
    assert_eq!(contract.verifier_profiles.did_methods.len(), 3);
    assert_eq!(contract.verifier_profiles.issuer_did_sources.len(), 3);
    assert_eq!(
        contract.verifier_profiles.request_length_bounds,
        [1_024, 1_048_576]
    );
    assert_eq!(
        contract.verifier_profiles.x509_certificate_sources,
        ["VERIFIER_X509_CERT_PEM", "VERIFIER_X509_CERT_FILE"]
    );
    assert!(!contract.verifier_profiles.haip_default);
    assert!(!contract.verifier_profiles.strict_metadata_default);
    assert_eq!(
        contract.verifier_profiles.dc_api_expected_origins,
        "configured_origins_or_public_origin"
    );
    assert_eq!(contract.fail_closed_cases.len(), 22);
}

#[test]
fn deployed_configuration_is_complete_and_normalized() {
    let config = FlowServiceConfig::from_values(baseline("beta")).expect("valid beta config");
    assert_eq!(config.environment, Environment::Beta);
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8011");
    assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9011");
    assert_eq!(config.public_base_url, "https://issuer.example");
    assert_eq!(
        config.marty_organization_id,
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(config.application_event_max_age_seconds, 60);
    assert_eq!(config.application_event_replay_ttl_seconds, 300);
    assert_eq!(
        config.oid4vp_issuer_did,
        "did:web:issuer.example:orgs:marty"
    );
    assert!(!config.callback_destinations.is_empty());
    assert_eq!(
        config.oid4vp_client_id_scheme,
        marty_flow::Oid4vpClientIdScheme::DecentralizedIdentifier
    );
    assert_eq!(
        config.verifier_did_method,
        marty_flow::VerifierDidMethod::Web
    );
    assert!(!config.oid4vp_haip_enabled);
    assert_eq!(config.oid4vp_request_object_maximum_length, 8_192);
    assert_eq!(config.oid4vp_url_query_maximum_length, 8_192);
    assert_eq!(config.verifier_expected_origins, ["https://issuer.example"]);
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

    for (name, invalid_value) in [
        ("OID4VP_CLIENT_ID_PREFIX", "unknown"),
        ("VERIFIER_DID_METHOD", "did:peer"),
        ("OID4VP_ISSUER_DID", "https://not-a-did.example"),
        ("MARTY_ORG_ID", "not-a-uuid"),
        ("OID4VP_REQUEST_OBJECT_MAX_LENGTH", "1023"),
        ("OID4VP_URL_QUERY_MAX_LENGTH", "1048577"),
    ] {
        let mut values = baseline("production");
        values.insert(name.into(), invalid_value.into());
        assert_eq!(
            FlowServiceConfig::from_values(values),
            Err(FlowConfigError::Invalid { name })
        );
    }
    let mut invalid_replay_ttl = baseline("beta");
    invalid_replay_ttl.insert(
        "FLOW_APPLICATION_EVENT_MAX_AGE_SECONDS".into(),
        "120".into(),
    );
    invalid_replay_ttl.insert(
        "FLOW_APPLICATION_EVENT_REPLAY_TTL_SECONDS".into(),
        "60".into(),
    );
    assert!(FlowServiceConfig::from_values(invalid_replay_ttl).is_err());

    let mut x509_without_certificate = baseline("production");
    x509_without_certificate.insert("OID4VP_CLIENT_ID_PREFIX".into(), "x509_hash".into());
    assert_eq!(
        FlowServiceConfig::from_values(x509_without_certificate),
        Err(FlowConfigError::Missing {
            name: "VERIFIER_X509_CERT_PEM"
        })
    );

    let mut insecure_logo = baseline("production");
    insecure_logo.insert(
        "VERIFIER_LOGO_URI".into(),
        "http://verifier.example/logo.svg".into(),
    );
    assert_eq!(
        FlowServiceConfig::from_values(insecure_logo),
        Err(FlowConfigError::Invalid {
            name: "VERIFIER_LOGO_URI"
        })
    );

    let mut invalid_origin = baseline("production");
    invalid_origin.insert(
        "VERIFIER_EXPECTED_ORIGINS".into(),
        "https://verifier.example/path".into(),
    );
    assert_eq!(
        FlowServiceConfig::from_values(invalid_origin),
        Err(FlowConfigError::Invalid {
            name: "VERIFIER_EXPECTED_ORIGINS"
        })
    );
}

#[test]
fn configured_verifier_profiles_are_preserved() {
    let mut values = baseline("beta");
    values.extend([
        (
            "MARTY_ISSUER_DID".into(),
            "did:web:configured.example".into(),
        ),
        ("OID4VP_CLIENT_ID_PREFIX".into(), "x509_hash".into()),
        ("VERIFIER_DID_METHOD".into(), "did:jwk".into()),
        ("VERIFIER_X509_CERT_PEM".into(), "certificate-bundle".into()),
        ("OID4VP_HAIP_ENABLED".into(), "true".into()),
        ("OID4VP_REQUEST_OBJECT_MAX_LENGTH".into(), "16384".into()),
        ("OID4VP_URL_QUERY_MAX_LENGTH".into(), "12288".into()),
        ("OID4VP_STRICT_CLIENT_METADATA".into(), "true".into()),
        ("VERIFIER_CLIENT_ID".into(), "marty-verifier".into()),
        ("VERIFIER_DISPLAY_NAME".into(), "Marty Verifier".into()),
        (
            "VERIFIER_LOGO_URI".into(),
            "https://verifier.example/logo.svg".into(),
        ),
        (
            "VERIFIER_EXPECTED_ORIGINS".into(),
            "https://one.example/, https://two.example, https://one.example".into(),
        ),
    ]);
    let config = FlowServiceConfig::from_values(values).expect("profile configuration");
    assert_eq!(
        config.oid4vp_client_id_scheme,
        marty_flow::Oid4vpClientIdScheme::X509Hash
    );
    assert_eq!(
        config.verifier_did_method,
        marty_flow::VerifierDidMethod::Jwk
    );
    assert!(config.oid4vp_haip_enabled);
    assert!(config.oid4vp_strict_client_metadata);
    assert_eq!(config.oid4vp_issuer_did, "did:web:configured.example");
    assert_eq!(config.oid4vp_request_object_maximum_length, 16_384);
    assert_eq!(config.oid4vp_url_query_maximum_length, 12_288);
    let request_options = config.request_object_options();
    assert_eq!(
        request_options.client_id_scheme,
        config.oid4vp_client_id_scheme
    );
    assert_eq!(
        request_options.verifier_did_method,
        config.verifier_did_method
    );
    assert_eq!(request_options.verifier_display_name, "Marty Verifier");
    let start_options = config.verification_start_options();
    assert!(start_options.haip_enabled);
    assert_eq!(start_options.request_object_maximum_length, 16_384);
    assert_eq!(start_options.url_query_maximum_length, 12_288);
    assert_eq!(
        start_options.request_object.expected_origins,
        ["https://one.example", "https://two.example"]
    );
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
