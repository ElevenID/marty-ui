use std::{collections::BTreeMap, collections::BTreeSet, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use marty_flow::{
    FlowGrpcChannelFactories, FlowProviderRegistry, FlowServiceConfig, SigningIdentity,
    REQUIRED_FLOW_PROVIDERS,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    required_providers: Vec<String>,
    reference_catalog: BTreeMap<String, [String; 3]>,
    signing_identity: SigningIdentity,
    invalid_identity_mutations: Vec<String>,
    physical_document_operations: BTreeMap<String, [String; 2]>,
    authorization: Vec<AuthorizationCase>,
}

#[test]
fn physical_document_contract_covers_the_complete_operation_surface() {
    let operations = contract().physical_document_operations;
    assert_eq!(operations.len(), 7);
    assert_eq!(
        operations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "activate_credential",
            "generate_data_groups",
            "initialize",
            "quality_verify",
            "sign_sod",
            "submit_to_personalization",
            "track_production",
        ])
    );
    assert!(operations.values().all(|route| {
        matches!(route[0].as_str(), "GET" | "POST") && route[1].starts_with("v1/passport/")
    }));
}

#[derive(Deserialize)]
struct AuthorizationCase {
    principal_id: String,
    organization_id: String,
    permission: String,
    result: String,
}

fn contract() -> Contract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/flow-provider-behavior.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn provider_composition_fails_closed_until_every_feature_port_is_present() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.required_providers, REQUIRED_FLOW_PROVIDERS);
    let registry = FlowProviderRegistry::default();
    assert_eq!(registry.missing(), REQUIRED_FLOW_PROVIDERS);
    assert!(registry.require_complete().is_err());
}

#[test]
fn reference_catalog_preserves_authoritative_routes_and_authentication() {
    let operations = contract().reference_catalog;
    assert_eq!(operations.len(), 4);
    assert_eq!(
        operations["application_template"],
        ["GET", "v1/application-templates/{id}", "x-api-key"]
    );
    assert_eq!(
        operations["delivery_destination"],
        ["GET", "v1/delivery-destinations/{id}", "x-user-id"]
    );
    assert_eq!(
        operations["trust_profile"],
        ["GET", "v1/trust-profiles/{id}", "x-user-id"]
    );
    assert_eq!(
        operations["deployment_profile"],
        ["GET", "v1/deployment-profiles/{id}", "x-user-id"]
    );
}

#[test]
fn signing_identity_is_bound_to_the_exact_public_capability_tuple() {
    let contract = contract();
    let identity = &contract.signing_identity;
    assert!(identity
        .validate_binding(
            "org-1",
            "did:web:issuer.example",
            "oid4vp_request_signing",
            "oauth-authz-req+jwt",
            Some("ES256"),
        )
        .is_ok());

    for mutation in contract.invalid_identity_mutations {
        let mut invalid = identity.clone();
        match mutation.as_str() {
            "organization_id" => invalid.organization_id = "org-2".into(),
            "issuer_did" => invalid.issuer_did = "did:web:other.example".into(),
            "verification_method_id" => {
                invalid.verification_method_id = "did:web:other.example#key".into()
            }
            "key_purpose" => invalid.key_purpose = "vc_jwt_issuer".into(),
            "credential_format" => invalid.credential_format = "jwt_vc_json".into(),
            "algorithm" => invalid.algorithm = "ES384".into(),
            "public_key_curve" => {
                invalid
                    .public_jwk
                    .insert("crv".into(), Value::String("P-384".into()));
            }
            "private_key" => {
                invalid
                    .public_jwk
                    .insert("d".into(), Value::String("secret".into()));
            }
            unknown => panic!("unknown identity mutation: {unknown}"),
        }
        assert!(
            invalid
                .validate_binding(
                    "org-1",
                    "did:web:issuer.example",
                    "oid4vp_request_signing",
                    "oauth-authz-req+jwt",
                    Some("ES256"),
                )
                .is_err(),
            "{mutation}"
        );
    }
}

struct MembershipFixture;

#[async_trait]
impl TenantMembershipProvider for MembershipFixture {
    async fn membership(
        &self,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        Ok(Some(TenantMembership {
            principal_id: principal_id.into(),
            tenant_id: "org-1".into(),
            status: "active".into(),
            role_names: BTreeSet::from(["member".into()]),
            permissions: BTreeSet::from(["flow-definition:view".into()]),
            is_owner: false,
        })
        .filter(|_| tenant_id == "org-1" || tenant_id == "org-2"))
    }
}

#[tokio::test]
async fn flow_authorization_consumes_the_shared_mmf_membership_decision() {
    let registry = FlowProviderRegistry {
        tenant_membership: Some(Arc::new(MembershipFixture)),
        ..Default::default()
    };
    for case in contract().authorization {
        let result = registry
            .authorize(
                &case.principal_id,
                &case.organization_id,
                &case.permission,
                false,
            )
            .await;
        assert_eq!(
            result.is_ok(),
            case.result == "allow",
            "{}",
            json!(case.permission)
        );
    }
}

#[tokio::test]
async fn flow_grpc_clients_consume_only_the_shared_mmf_channel_factory() {
    fn factory(target: &str) -> GrpcChannelFactory {
        GrpcChannelFactory::new(
            GrpcChannelConfig {
                target: target.into(),
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::default(),
        )
        .unwrap()
    }

    let clients = marty_flow::FlowGrpcChannelFactories {
        organization: factory("http://organization:50051"),
        credential_template: factory("http://credential-template:50052"),
        presentation_policy: factory("http://presentation-policy:50053"),
        issuance: factory("http://issuance:50054"),
    }
    .connect_lazy()
    .unwrap();
    assert!(clients.providers(Some(&"s".repeat(32))).is_ok());
}

#[test]
fn configured_factories_apply_workload_mtls_only_to_the_policy_provider() {
    let directory = std::env::temp_dir().join(format!("flow-grpc-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("ca.pem");
    let certificate = directory.join("client.pem");
    let key = directory.join("client-key.pem");
    let server_certificate = directory.join("server.pem");
    let server_key = directory.join("server-key.pem");
    std::fs::write(
        &ca,
        "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        &certificate,
        "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        &key,
        "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(
        &server_certificate,
        "-----BEGIN CERTIFICATE-----\nSERVER\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        &server_key,
        "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let config = FlowServiceConfig::from_values([
        ("ENVIRONMENT".into(), "beta".into()),
        ("DATABASE_URL".into(), "postgresql://db/flow".into()),
        ("REDIS_URL".into(), "redis://redis".into()),
        ("ORG_GRPC_TARGET".into(), "organization:9002".into()),
        ("CT_GRPC_TARGET".into(), "credential-template:9003".into()),
        ("PP_GRPC_TARGET".into(), "presentation-policy:9009".into()),
        ("ISSUANCE_GRPC_TARGET".into(), "issuance:9005".into()),
        (
            "SIGNING_KEYS_INTERNAL_URL".into(),
            "http://gateway:8000".into(),
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
        ("ISSUANCE_SERVICE_URL".into(), "http://issuance:8005".into()),
        ("GRPC_SERVICE_TOKEN".into(), "s".repeat(32)),
        ("FLOW_WEBHOOK_SECRET".into(), "w".repeat(32)),
        ("SIGNING_KEYS_INTERNAL_API_KEY".into(), "k".repeat(32)),
        ("ISSUANCE_API_KEY".into(), "i".repeat(32)),
        ("GRPC_INSECURE_ALLOWED".into(), "true".into()),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_CERT".into(),
            certificate.to_string_lossy().into_owned(),
        ),
        (
            "GRPC_WORKLOAD_TLS_CLIENT_KEY".into(),
            key.to_string_lossy().into_owned(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_CERT".into(),
            server_certificate.to_string_lossy().into_owned(),
        ),
        (
            "GRPC_WORKLOAD_TLS_SERVER_KEY".into(),
            server_key.to_string_lossy().into_owned(),
        ),
        (
            "GRPC_WORKLOAD_TLS_CA_CERT".into(),
            ca.to_string_lossy().into_owned(),
        ),
    ])
    .unwrap();
    let factories = FlowGrpcChannelFactories::from_config(&config).unwrap();
    assert_eq!(
        factories.presentation_policy.config().security,
        GrpcTransportSecurity::MutualTls
    );
    assert_eq!(
        factories.presentation_policy.config().trust,
        GrpcTrustMode::CustomCa
    );
    assert_eq!(
        factories.presentation_policy.config().target,
        "https://presentation-policy:9009"
    );
    for factory in [
        &factories.organization,
        &factories.credential_template,
        &factories.issuance,
    ] {
        assert_eq!(factory.config().security, GrpcTransportSecurity::Plaintext);
    }
    std::fs::remove_dir_all(directory).unwrap();
}
