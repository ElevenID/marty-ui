//! Synthetic owner responses for the real Flow profile adapters.
#![allow(dead_code)]

use async_trait::async_trait;
use marty_flow::*;
use marty_oid4vp_contract::{
    jwt_vc_profile::{policy_credential_format, JwtVcSecuringProfile},
    FrozenPolicyIdentity,
};
use serde_json::json;
use std::sync::Arc;

pub const REQUIREMENT_ID: &str = "00000000-0000-0000-0000-000000000005";

pub fn policy(profile: JwtVcSecuringProfile) -> PresentationPolicyReference {
    PresentationPolicyReference {
        id: "policy-1".into(),
        organization_id: "org-1".into(),
        status: "active".into(),
        policy_revision: FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 1,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        },
        holder_binding_required: true,
        prerequisite_evidence_profile: None,
        credential_authority: None,
        credential_requirements: vec![
            json!({"id":REQUIREMENT_ID,"credential_template_id":"template-1","required":true,"credential_payload_format":policy_credential_format(profile),"expected_securing_profile":profile,"requested_claims":[]}),
        ],
    }
}

pub fn template(
    profile: JwtVcSecuringProfile,
    credential_type: &str,
) -> CredentialTemplateReference {
    let direct = profile == JwtVcSecuringProfile::W3cVc2Jose2026V1;
    CredentialTemplateReference {
        id: "template-1".into(),
        organization_id: "org-1".into(),
        status: "active".into(),
        credential_type: credential_type.into(),
        vct: String::new(),
        doctype: String::new(),
        claims: vec![],
        issuer_did: "did:web:issuer.example".into(),
        supported_formats: vec![policy_credential_format(profile).into()],
        credential_format: if direct { "vc_jwt_direct_v1" } else { "jwt_vc" }.into(),
        jwt_vc_profile: direct
            .then(|| marty_jwt_vc_issuance::JwtVcTemplatePolicy::new(300).unwrap()),
        issuance_protocol: "OID4VCI_PRE_AUTH".into(),
        wallet_configurations: vec![],
        issuer_algorithm: Some("EdDSA".into()),
    }
}

pub struct Policies(pub PresentationPolicyReference);
#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        assert_eq!(id, self.0.id);
        Ok(self.0.clone())
    }
    async fn evaluate(
        &self,
        _: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        panic!("query construction must not evaluate a presentation")
    }
}

pub struct Templates(pub CredentialTemplateReference);
#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        assert_eq!(id, self.0.id);
        Ok(self.0.clone())
    }
    async fn wallet_formats(&self, _: &str) -> Result<Vec<String>, FlowProviderError> {
        panic!("explicit profile must not use legacy wallet-format inference")
    }
}

pub fn providers(profile: JwtVcSecuringProfile, credential_type: &str) -> FlowProviderRegistry {
    FlowProviderRegistry {
        presentation_policy: Some(Arc::new(Policies(policy(profile)))),
        credential_template: Some(Arc::new(Templates(template(profile, credential_type)))),
        ..Default::default()
    }
}
