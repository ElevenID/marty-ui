#[path = "support/presentation_snapshot.rs"]
mod presentation_snapshot;
#[path = "support/profiled_jwt_vc.rs"]
mod profiled_jwt_vc;

use std::sync::Arc;

use async_trait::async_trait;
use marty_flow::{
    build_flow_presentation_request, CredentialClaimReference, CredentialTemplateProvider,
    CredentialTemplateReference, FlowProviderError, FlowProviderRegistry,
    PresentationEvaluationRequest, PresentationEvaluationResult, PresentationPolicyProvider,
    PresentationPolicyReference,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    policy_binding: String,
    template_binding: String,
    template_source_fields: Vec<String>,
    wallet_format_source: String,
    native_builder: String,
    outputs: Vec<String>,
    missing_requirement_template: String,
    malformed_requested_claims: String,
    provider_fallback: String,
}

#[derive(Clone)]
struct Policies {
    organization_id: &'static str,
    requirements: Vec<Value>,
}

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            holder_binding_required: false,
            prerequisite_evidence_profile: None,
            credential_authority: None,
            policy_revision: presentation_snapshot::revision(policy_id),
            id: policy_id.into(),
            organization_id: self.organization_id.into(),
            status: "ACTIVE".into(),
            credential_requirements: self.requirements.clone(),
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("request construction does not evaluate presentations")
    }
}

#[derive(Clone)]
struct Templates;

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            jwt_vc_profile: None,
            id: template_id.into(),
            organization_id: "org-1".into(),
            status: "ACTIVE".into(),
            credential_type: "MemberCredential".into(),
            vct: "https://issuer.example/member".into(),
            doctype: String::new(),
            supported_formats: vec!["sd_jwt_vc".into()],
            claims: vec![CredentialClaimReference {
                name: "email".into(),
                display_name: "Email".into(),
                description: "Member email".into(),
                required: true,
                mdoc_namespace: String::new(),
                mdoc_element_identifier: String::new(),
            }],
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "vc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        assert_eq!(organization_id, "org-1");
        Ok(vec!["dc+sd-jwt".into(), "mso_mdoc".into()])
    }
}

fn providers(organization_id: &'static str, requirements: Vec<Value>) -> FlowProviderRegistry {
    FlowProviderRegistry {
        presentation_policy: Some(Arc::new(Policies {
            organization_id,
            requirements,
        })),
        credential_template: Some(Arc::new(Templates)),
        ..Default::default()
    }
}

#[tokio::test]
async fn explicit_jwt_vc_builder_requires_owner_profile_holder_and_exact_template_capability() {
    use marty_oid4vp_contract::jwt_vc_profile::{profiled_jwt_vc_query, JwtVcSecuringProfile};
    for profile in [
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        JwtVcSecuringProfile::W3cVc2Jose2026V1,
    ] {
        for (credential_type, expected_type) in [
            ("MemberCredential", "MemberCredential"),
            ("open_badge_v3", "OpenBadgeCredential"),
            ("OPENBADGECREDENTIAL", "OpenBadgeCredential"),
        ] {
            let artifacts = build_flow_presentation_request(
                &profiled_jwt_vc::providers(profile, credential_type),
                "policy-1",
                "org-1",
            )
            .await
            .unwrap();
            assert_eq!(artifacts.presentation_definition, json!({}));
            let query = profiled_jwt_vc_query(&artifacts.dcql_query)
                .unwrap()
                .unwrap();
            assert_eq!(query.binding.securing_profile(), profile);
            assert_eq!(query.id, profiled_jwt_vc::REQUIREMENT_ID);
            assert_eq!(query.type_sets, vec![vec![expected_type.to_owned()]]);
            assert_eq!(
                artifacts.dcql_query["credentials"][0]["require_cryptographic_holder_binding"],
                true
            );
        }
        for mutation in [
            "old_owner",
            "null_profile",
            "unknown_profile",
            "unmarked",
            "crossed_format",
            "optional",
            "claims",
            "second_requirement",
            "wrong_template_format",
            "wrong_template_capability",
            "direct_template_policy",
        ] {
            let mut policy = profiled_jwt_vc::policy(profile);
            let mut template = profiled_jwt_vc::template(profile, "MemberCredential");
            match mutation {
                "old_owner" => policy.holder_binding_required = false,
                "null_profile" => {
                    policy.credential_requirements[0]["expected_securing_profile"] = json!(null)
                }
                "unknown_profile" => {
                    policy.credential_requirements[0]["expected_securing_profile"] =
                        json!("unknown")
                }
                "unmarked" => {
                    policy.credential_requirements[0]
                        .as_object_mut()
                        .unwrap()
                        .remove("expected_securing_profile");
                    if profile == JwtVcSecuringProfile::MartyNestedVc2JwtV1 {
                        continue;
                    }
                }
                "crossed_format" => {
                    policy.credential_requirements[0]["credential_payload_format"] =
                        json!("SD_JWT_VC")
                }
                "optional" => policy.credential_requirements[0]["required"] = json!(false),
                "claims" => {
                    policy.credential_requirements[0]["requested_claims"] =
                        json!([{"claim_name":"email"}])
                }
                "second_requirement" => policy
                    .credential_requirements
                    .push(policy.credential_requirements[0].clone()),
                "wrong_template_format" => template.credential_format = "sd_jwt_vc".into(),
                "wrong_template_capability" => {
                    template.supported_formats = vec!["SD_JWT_VC".into()]
                }
                "direct_template_policy" => {
                    template.jwt_vc_profile = if profile == JwtVcSecuringProfile::W3cVc2Jose2026V1 {
                        None
                    } else {
                        Some(marty_jwt_vc_issuance::JwtVcTemplatePolicy::new(300).unwrap())
                    }
                }
                _ => unreachable!(),
            }
            let ports = FlowProviderRegistry {
                presentation_policy: Some(Arc::new(profiled_jwt_vc::Policies(policy))),
                credential_template: Some(Arc::new(profiled_jwt_vc::Templates(template))),
                ..Default::default()
            };
            assert!(
                build_flow_presentation_request(&ports, "policy-1", "org-1")
                    .await
                    .is_err(),
                "{profile:?}: {mutation}"
            );
        }
    }
}

#[tokio::test]
async fn language_neutral_contract_composes_the_native_builder() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-presentation-request-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.policy_binding, "exact_id_tenant_active");
    assert_eq!(contract.template_binding, "exact_id_tenant_active");
    assert_eq!(contract.template_source_fields.len(), 5);
    assert_eq!(
        contract.wallet_format_source,
        "active_credential_template_wallet_registry"
    );
    assert_eq!(
        contract.native_builder,
        "marty_oid4vci.presentation_request.build_presentation_request"
    );
    assert_eq!(contract.outputs, ["presentation_definition", "dcql_query"]);
    assert_eq!(contract.missing_requirement_template, "fail_closed");
    assert_eq!(contract.malformed_requested_claims, "fail_closed");
    assert_eq!(contract.provider_fallback, "none");

    let artifacts = build_flow_presentation_request(
        &providers(
            "org-1",
            vec![json!({
                "id": "member",
                "display_name": "Member credential",
                "description": "Verify membership",
                "credential_template_id": "template-1",
                "requested_claims": [
                    {"claim_name": "email", "required": true},
                    {"claim_name": "nickname", "required": false}
                ]
            })],
        ),
        "policy-1",
        "org-1",
    )
    .await
    .unwrap();
    assert_eq!(
        artifacts.presentation_definition["input_descriptors"][0]["id"],
        "member"
    );
    assert_eq!(artifacts.dcql_query["credentials"][0]["id"], "member");
    assert_eq!(
        artifacts.dcql_query["credentials"][0]["format"],
        "dc+sd-jwt"
    );
    assert_eq!(
        artifacts.dcql_query["credentials"][0]["meta"]["vct_values"][0],
        "https://issuer.example/member"
    );
}

#[tokio::test]
async fn tenant_and_requirement_mismatches_fail_closed() {
    assert!(build_flow_presentation_request(
        &providers(
            "org-2",
            vec![json!({"credential_template_id": "template-1"})]
        ),
        "policy-1",
        "org-1"
    )
    .await
    .is_err());
    assert!(build_flow_presentation_request(
        &providers("org-1", vec![json!({"requested_claims": []})]),
        "policy-1",
        "org-1"
    )
    .await
    .is_err());
    assert!(build_flow_presentation_request(
        &providers(
            "org-1",
            vec![json!({
                "credential_template_id": "template-1",
                "requested_claims": "email"
            })]
        ),
        "policy-1",
        "org-1"
    )
    .await
    .is_err());
}
