use std::collections::BTreeMap;

use marty_auth::{AuthDependency, AuthRuntime, AuthServiceConfig};
use serde_json::Value;

fn baseline(environment: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ENVIRONMENT".into(), environment.into()),
        ("KEYCLOAK_REALM".into(), "marty".into()),
        ("DATABASE_URL".into(), "postgresql://db/auth".into()),
        ("REDIS_URL".into(), "redis://redis:6379/0".into()),
        ("UI_BASE_URL".into(), "https://elevenidllc.com".into()),
        (
            "UI_ALLOWED_ORIGINS".into(),
            "https://beta.elevenidllc.com".into(),
        ),
        ("CREDENTIAL_LOGIN_POLICY_ID".into(), "policy-1".into()),
        ("CREDENTIAL_LOGIN_ORGANIZATION_ID".into(), "org-1".into()),
        (
            "CREDENTIAL_LOGIN_ISSUER_DID".into(),
            "did:web:verifier.example".into(),
        ),
        ("FLOW_WEBHOOK_SECRET".into(), "s".repeat(32)),
        ("ALLOW_PLAINTEXT_GRPC".into(), "true".into()),
    ])
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/auth-executable-behavior.json"
    ))
    .unwrap()
}

#[test]
fn complete_beta_configuration_is_normalized_without_hidden_fallbacks() {
    let config = AuthServiceConfig::from_values(baseline("beta")).unwrap();
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8001");
    assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9001");
    assert_eq!(config.flow_grpc_target, "http://flow:9011");
    assert_eq!(config.organization_grpc_target, "http://organization:9002");
    assert_eq!(config.event_stream_grpc_target, "http://event-stream:9015");
    assert_eq!(config.oidc.issuer_url, "http://localhost:8180/realms/marty");
    assert_eq!(
        config.oidc.redirect_uri,
        "https://elevenidllc.com/v1/auth/callback"
    );
    assert_eq!(config.session_ttl_seconds, 86_400);
    assert_eq!(config.cookie.name, "sessionId");
}

#[test]
fn required_settings_secrets_and_production_transport_fail_closed() {
    let expected = contract()["required_configuration"]
        .as_array()
        .unwrap()
        .clone();
    for name in expected {
        let name = name.as_str().unwrap();
        let mut values = baseline("beta");
        values.remove(name);
        assert!(AuthServiceConfig::from_values(values).is_err(), "{name}");
    }
    let mut short_secret = baseline("beta");
    short_secret.insert("FLOW_WEBHOOK_SECRET".into(), "short".into());
    assert!(AuthServiceConfig::from_values(short_secret).is_err());

    let mut production = baseline("production");
    production.remove("ALLOW_PLAINTEXT_GRPC");
    assert!(AuthServiceConfig::from_values(production).is_err());

    let mut production = baseline("production");
    production.remove("ALLOW_PLAINTEXT_GRPC");
    production.insert("FLOW_GRPC_TARGET".into(), "https://flow:9011".into());
    production.insert("ORG_GRPC_TARGET".into(), "https://organization:9002".into());
    production.insert("ES_GRPC_TARGET".into(), "https://event-stream:9015".into());
    production.extend([
        ("GRPC_WORKLOAD_TLS_CA_CERT".into(), "/secrets/ca.pem".into()),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_CERT".into(),
            "/secrets/client.pem".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_KEY".into(),
            "/secrets/client-key.pem".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_CERT".into(),
            "/secrets/server.pem".into(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_KEY".into(),
            "/secrets/server-key.pem".into(),
        ),
    ]);
    assert!(AuthServiceConfig::from_values(production).is_ok());

    let mut partial = baseline("beta");
    partial.insert("GRPC_WORKLOAD_TLS_CA_CERT".into(), "/secrets/ca.pem".into());
    assert!(AuthServiceConfig::from_values(partial).is_err());
}

#[test]
fn mmf_runtime_requires_every_declared_dependency_before_activation() {
    let behavior = contract();
    let config = AuthServiceConfig::from_values(baseline("beta")).unwrap();
    let runtime = AuthRuntime::new(&config).unwrap();
    assert!(!runtime.state().readiness().unwrap().ready);
    assert!(runtime.activate().is_err());
    let actual = AuthDependency::all()
        .map(|dependency| dependency.name())
        .collect::<Vec<_>>();
    let expected = behavior["required_runtime_components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    for dependency in AuthDependency::all() {
        runtime.mark_healthy(dependency).unwrap();
    }
    runtime.activate().unwrap();
    assert!(runtime.state().readiness().unwrap().ready);
    runtime.drain().unwrap();
    assert!(!runtime.state().readiness().unwrap().ready);
    runtime.stop().unwrap();
    assert!(!behavior["python_fallback"].as_bool().unwrap());
    assert!(!behavior["deployment_during_slice"].as_bool().unwrap());
}
