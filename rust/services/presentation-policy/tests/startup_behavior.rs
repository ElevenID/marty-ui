use std::collections::BTreeMap;

use marty_presentation_policy::{
    PresentationPolicyConfigError, PresentationPolicyDependency, PresentationPolicyRuntime,
    PresentationPolicyServiceConfig,
};

fn values(environment: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ENVIRONMENT".into(), environment.into()),
        (
            "DATABASE_URL".into(),
            "postgresql+asyncpg://marty:secret@postgres/marty".into(),
        ),
    ])
}

#[test]
fn compose_compatible_development_configuration_is_normalized() {
    let config = PresentationPolicyServiceConfig::from_values(values("development")).unwrap();
    assert_eq!(config.http_addr.port(), 8009);
    assert_eq!(config.grpc_addr.port(), 9009);
    assert_eq!(config.organization_grpc_target, "http://organization:9002");
    assert!(config.database_url.starts_with("postgresql://"));
    assert_eq!(
        config.credential_status_url_template,
        "http://issuance:8005/v1/issuance/credentials/{credential_id}/status"
    );
    assert!(config.workload_server_tls.is_none());
}

#[test]
fn deployed_configuration_requires_secrets_and_complete_mtls() {
    let beta = values("beta");
    assert_eq!(
        PresentationPolicyServiceConfig::from_values(beta).unwrap_err(),
        PresentationPolicyConfigError::Missing {
            name: "GRPC_SERVICE_TOKEN"
        }
    );

    let mut configured = values("beta");
    configured.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
    configured.insert("ISSUANCE_API_KEY".into(), "i".repeat(32));
    assert_eq!(
        PresentationPolicyServiceConfig::from_values(configured.clone()).unwrap_err(),
        PresentationPolicyConfigError::Missing {
            name: "GRPC_WORKLOAD_TLS_SERVER_CERT"
        }
    );
    configured.insert("GRPC_WORKLOAD_TLS_SERVER_CERT".into(), "/cert.pem".into());
    assert!(matches!(
        PresentationPolicyServiceConfig::from_values(configured),
        Err(PresentationPolicyConfigError::Invalid {
            name: "GRPC_WORKLOAD_TLS_SERVER_CERT"
        })
    ));
}

#[test]
fn deployed_configuration_supports_dynamic_issuers_without_static_scope() {
    let mut configured = values("beta");
    configured.extend([
        ("GRPC_SERVICE_TOKEN".into(), "s".repeat(32)),
        ("ISSUANCE_API_KEY".into(), "i".repeat(32)),
        ("GRPC_WORKLOAD_TLS_SERVER_CERT".into(), "/cert.pem".into()),
        ("GRPC_WORKLOAD_TLS_SERVER_KEY".into(), "/key.pem".into()),
        ("GRPC_WORKLOAD_TLS_CA_CERT".into(), "/ca.pem".into()),
    ]);

    let config = PresentationPolicyServiceConfig::from_values(configured).unwrap();
    assert_eq!(
        config.credential_status_url_template,
        "http://issuance:8005/v1/issuance/credentials/{credential_id}/status"
    );
}

#[test]
fn readiness_requires_every_native_runtime_dependency() {
    let config = PresentationPolicyServiceConfig::from_values(values("test")).unwrap();
    let runtime = PresentationPolicyRuntime::new(&config).unwrap();
    assert!(runtime.activate().is_err());
    for dependency in [
        PresentationPolicyDependency::Database,
        PresentationPolicyDependency::Schema,
        PresentationPolicyDependency::ControlPlane,
        PresentationPolicyDependency::NativeVerification,
        PresentationPolicyDependency::HttpListener,
        PresentationPolicyDependency::GrpcListener,
    ] {
        runtime.mark_healthy(dependency).unwrap();
    }
    runtime.activate().unwrap();
}
