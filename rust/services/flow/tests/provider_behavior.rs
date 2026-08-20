use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use marty_flow::{FlowProviderRegistry, SigningIdentity, REQUIRED_FLOW_PROVIDERS};
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    required_providers: Vec<String>,
    signing_identity: SigningIdentity,
    invalid_identity_mutations: Vec<String>,
    authorization: Vec<AuthorizationCase>,
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
