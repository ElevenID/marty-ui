use std::collections::BTreeMap;

use marty_auth::{
    is_rate_limited_auth_path, AuthDependency, AuthRuntime, AuthServiceConfig, OidcProviderMode,
};
use mmf_platform::{GrpcTransportSecurity, GrpcTrustMode};
use serde_json::Value;

fn baseline(environment: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
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
        ("GRPC_SERVICE_TOKEN".into(), "g".repeat(32)),
        ("ALLOW_PLAINTEXT_GRPC".into(), "false".into()),
    ]);
    if environment == "beta" {
        values.extend(remote_tls_values());
        values.insert("FLOW_GRPC_TARGET".into(), "https://flow:9011".into());
        values.insert("ORG_GRPC_TARGET".into(), "https://organization:9002".into());
        values.insert("ES_GRPC_TARGET".into(), "https://event-stream:9015".into());
    }
    values
}

fn remote_tls_values() -> Vec<(String, String)> {
    [
        ("GRPC_WORKLOAD_TLS_CA_CERT", "/secrets/ca.pem"),
        ("GRPC_WORKLOAD_TLS_CLIENT_CERT", "/secrets/client.pem"),
        ("GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR", "https://bao:8200"),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
            "/secrets/bao-ca.pem",
        ),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
            "/secrets/client-token",
        ),
        ("GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME", "auth-client"),
        ("GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION", "1"),
        ("GRPC_WORKLOAD_TLS_SERVER_CERT", "/secrets/server.pem"),
        ("GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR", "https://bao:8200"),
        (
            "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
            "/secrets/bao-ca.pem",
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
            "/secrets/server-token",
        ),
        ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME", "auth-server"),
        ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1"),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value.into()))
    .collect()
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/auth-executable-behavior.json"
    ))
    .unwrap()
}

#[test]
fn aws_workload_tls_preserves_both_roles_and_rejects_mixed_or_missing_identity() {
    let mut values = baseline("beta");
    let arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
    for role in ["CLIENT", "SERVER"] {
        let prefix = format!("GRPC_WORKLOAD_TLS_{role}");
        for suffix in ["ADDR", "CA_CERT", "TOKEN_FILE", "KEY_NAME", "KEY_VERSION"] {
            values.remove(&format!("{prefix}_KMS_{suffix}"));
        }
        for (suffix, value) in [
            ("PROVIDER", "aws-kms"),
            ("REGION", "us-east-1"),
            ("KEY_ARN", arn),
        ] {
            values.insert(format!("{prefix}_KMS_{suffix}"), value.into());
        }
    }
    let config = AuthServiceConfig::from_values(values.clone()).unwrap();
    for tls in [
        config.workload_client_tls.unwrap(),
        config.workload_server_tls.unwrap(),
    ] {
        assert_eq!(tls.ca_certificate.to_str(), Some("/secrets/ca.pem"));
        let marty_service_runtime::RemoteTlsIdentityFiles::AwsKms(identity) = tls.identity else {
            panic!("configured AWS identity must reach runtime");
        };
        assert_eq!(identity.key_arn, arn);
        assert!(identity.kms.endpoint.is_none());
    }
    for field in [
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
    ] {
        let mut mixed = values.clone();
        mixed.insert(field.into(), "leftover-openbao".into());
        assert!(AuthServiceConfig::from_values(mixed).is_err(), "{field}");
    }
    values.remove("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_ARN");
    assert!(AuthServiceConfig::from_values(values).is_err());
}

#[test]
fn complete_beta_configuration_is_normalized_without_hidden_fallbacks() {
    let config = AuthServiceConfig::from_values(baseline("beta")).unwrap();
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8001");
    assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9001");
    assert_eq!(config.flow_grpc_target, "https://flow:9011");
    assert_eq!(config.organization_grpc_target, "https://organization:9002");
    assert_eq!(config.event_stream_grpc_target, "https://event-stream:9015");
    assert_eq!(config.grpc_service_token, "g".repeat(32));
    assert_eq!(
        config.issuance_native_service_url,
        "http://issuance-native:8005"
    );
    assert_eq!(config.oidc.issuer_url, "http://localhost:8180/realms/marty");
    assert_eq!(
        config.oidc.redirect_uri,
        "https://elevenidllc.com/v1/auth/callback"
    );
    assert_eq!(config.session_ttl_seconds, 86_400);
    assert_eq!(config.cookie.name, "sessionId");
}

fn external_values() -> BTreeMap<String, String> {
    let mut values = baseline("beta");
    values.remove("KEYCLOAK_REALM");
    values.extend([
        ("OIDC_PROVIDER_MODE".into(), "external".into()),
        (
            "OIDC_ISSUER_URL".into(),
            "https://identity.example/tenant".into(),
        ),
        ("OIDC_CLIENT_ID".into(), "installed-client".into()),
    ]);
    values
}

#[test]
fn external_oidc_starts_without_keycloak_admin_or_realm_and_retains_claim_only_policy() {
    let mut values = external_values();
    values.insert(
        "OIDC_TRUSTED_ENDPOINT_ORIGINS".into(),
        "https://login.example/,https://keys.example".into(),
    );
    let config = AuthServiceConfig::from_values(values).unwrap();
    assert_eq!(config.oidc.provider_mode, OidcProviderMode::External);
    assert_eq!(config.oidc.issuer_url, "https://identity.example/tenant");
    assert_eq!(config.oidc.external_issuer_url, config.oidc.issuer_url);
    assert_eq!(config.oidc.client_id, "installed-client");
    assert_eq!(
        config.oidc.trusted_endpoint_origins,
        ["https://login.example", "https://keys.example"]
    );
    assert!(config.keycloak_admin.is_none());
    assert!(!config.credential_login_require_existing_keycloak_user);
    assert!(!config.credential_login_create_users);
}

#[test]
fn external_oidc_rejects_missing_explicit_identity_and_keycloak_only_settings() {
    for name in ["OIDC_ISSUER_URL", "OIDC_CLIENT_ID"] {
        let mut values = external_values();
        values.remove(name);
        assert!(AuthServiceConfig::from_values(values).is_err(), "{name}");
    }
    for (name, value) in [
        ("KEYCLOAK_ADMIN_URL", "https://keycloak.example"),
        ("MARTY_API_CLIENT_ID", "marty-admin"),
        ("MARTY_API_CLIENT_SECRET", "admin-secret"),
        ("KEYCLOAK_TOKEN_EXCHANGE_ENABLED", "true"),
        ("CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER", "true"),
        ("CREDENTIAL_LOGIN_CREATE_USERS", "true"),
        ("OIDC_EXTERNAL_ISSUER_URL", "https://other.example/tenant"),
        ("OIDC_ISSUER_URL", "http://identity.example/tenant"),
        (
            "OIDC_ISSUER_URL",
            "https://identity.example/tenant?issuer=other",
        ),
        ("OIDC_PROVIDER_MODE", "unknown"),
        ("OIDC_SCOPES", "profile,email"),
        ("OIDC_CLIENT_SECRET", ""),
    ] {
        let mut values = external_values();
        values.insert(name.into(), value.into());
        assert!(AuthServiceConfig::from_values(values).is_err(), "{name}");
    }
    let default = AuthServiceConfig::from_values(baseline("beta")).unwrap();
    assert_eq!(default.oidc.provider_mode, OidcProviderMode::Keycloak);
}

#[test]
fn issuance_http_owner_prefers_native_and_preserves_legacy_production() {
    let mut production = baseline("production");
    production.insert("ISSUANCE_SERVICE_URL".into(), "http://issuance:8005".into());
    production.insert("FLOW_GRPC_TARGET".into(), "https://flow:9011".into());
    production.insert("ORG_GRPC_TARGET".into(), "https://organization:9002".into());
    production.insert("ES_GRPC_TARGET".into(), "https://event-stream:9015".into());
    production.extend(remote_tls_values());
    let config = AuthServiceConfig::from_values(production).unwrap();
    assert_eq!(config.issuance_native_service_url, "http://issuance:8005");

    let mut beta = baseline("beta");
    beta.insert("ISSUANCE_SERVICE_URL".into(), "http://issuance:8005".into());
    beta.insert(
        "ISSUANCE_NATIVE_SERVICE_URL".into(),
        "http://issuance-native:8005".into(),
    );
    let config = AuthServiceConfig::from_values(beta).unwrap();
    assert_eq!(
        config.issuance_native_service_url,
        "http://issuance-native:8005"
    );
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

    let mut short_service_token = baseline("beta");
    short_service_token.insert("GRPC_SERVICE_TOKEN".into(), "short".into());
    assert!(AuthServiceConfig::from_values(short_service_token).is_err());

    let mut invalid_service_token = baseline("beta");
    invalid_service_token.insert(
        "GRPC_SERVICE_TOKEN".into(),
        format!("{}\n{}", "g".repeat(16), "g".repeat(16)),
    );
    assert!(AuthServiceConfig::from_values(invalid_service_token).is_err());

    let mut production = baseline("production");
    production.remove("ALLOW_PLAINTEXT_GRPC");
    assert!(AuthServiceConfig::from_values(production).is_err());

    let mut production = baseline("production");
    production.remove("ALLOW_PLAINTEXT_GRPC");
    production.insert("FLOW_GRPC_TARGET".into(), "https://flow:9011".into());
    production.insert("ORG_GRPC_TARGET".into(), "https://organization:9002".into());
    production.insert("ES_GRPC_TARGET".into(), "https://event-stream:9015".into());
    production.extend(remote_tls_values());
    assert!(AuthServiceConfig::from_values(production).is_ok());

    let mut partial = baseline("beta");
    partial.remove("GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE");
    assert!(AuthServiceConfig::from_values(partial).is_err());

    let mut outbound_only = baseline("beta");
    outbound_only.retain(|name, _| !name.starts_with("GRPC_WORKLOAD_TLS_"));
    outbound_only.extend(remote_tls_values().into_iter().filter(|(name, _)| {
        name == "GRPC_WORKLOAD_TLS_CA_CERT" || name.starts_with("GRPC_WORKLOAD_TLS_CLIENT_")
    }));
    assert!(AuthServiceConfig::from_values(outbound_only.clone()).is_err());
    for (name, value) in remote_tls_values() {
        outbound_only.insert(name, value);
    }
    assert!(AuthServiceConfig::from_values(outbound_only).is_ok());
}

#[test]
fn retired_tls_private_key_files_are_rejected() {
    for name in [
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
    ] {
        let mut values = baseline("production");
        values.extend(remote_tls_values());
        values.insert(name.into(), "/secrets/retired-key".into());
        assert!(AuthServiceConfig::from_values(values).is_err(), "{name}");
    }
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

#[test]
fn unauthenticated_rate_limit_paths_match_the_language_neutral_contract() {
    let rate_limit = &contract()["rate_limit"];
    for path in rate_limit["limited_paths"].as_array().unwrap() {
        assert!(is_rate_limited_auth_path(path.as_str().unwrap()));
    }
    for path in rate_limit["excluded_paths"].as_array().unwrap() {
        assert!(!is_rate_limited_auth_path(path.as_str().unwrap()));
    }
    assert_eq!(rate_limit["backend_failure_status"], 503);
    assert_eq!(rate_limit["limit_status"], 429);
}

#[test]
fn outbound_grpc_security_is_selected_by_the_shared_mmf_factory() {
    let plaintext = marty_auth::workload_channel_factory("http://flow:9011").unwrap();
    assert_eq!(
        plaintext.config().security,
        GrpcTransportSecurity::Plaintext
    );
    assert_eq!(plaintext.config().trust, GrpcTrustMode::NativeRoots);

    let server_tls = marty_auth::workload_channel_factory("https://flow.example:9011").unwrap();
    assert_eq!(
        server_tls.config().security,
        GrpcTransportSecurity::ServerTls
    );
    assert_eq!(server_tls.config().trust, GrpcTrustMode::NativeRoots);
}
