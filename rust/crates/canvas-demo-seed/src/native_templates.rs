//! Native API inputs only. No database, Canvas authority or signing custody.
use crate::{
    badge_application_fields, badge_claim_collection_rules, badge_credential_definition, BADGE_VCT,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBadgeTemplateInput {
    pub organization_id: String,
    pub issuer_did: String,
    pub compliance_profile_id: String,
    pub trust_profile_id: String,
    pub revocation_profile_id: String,
    pub credential_template_id: Option<String>,
}

/// Render the production create contracts from the shared learning definition.
/// Actual creation, activation and profile authorization belong to native APIs.
pub fn native_badge_templates(input: &NativeBadgeTemplateInput) -> Result<Value, String> {
    for id in [
        &input.organization_id,
        &input.compliance_profile_id,
        &input.trust_profile_id,
        &input.revocation_profile_id,
    ]
    .into_iter()
    .chain(input.credential_template_id.iter())
    {
        uuid::Uuid::parse_str(id).map_err(|_| "Native badge profile/template IDs must be UUIDs")?;
    }
    if !input.issuer_did.starts_with("did:") || input.issuer_did.trim() != input.issuer_did {
        return Err("Native badge requires a resolved issuer DID".into());
    }
    let mut credential = badge_credential_definition(&input.organization_id, BADGE_VCT);
    credential.as_object_mut().unwrap().extend(
        json!({
            "issuer_did": input.issuer_did,
            "compliance_profile_id": input.compliance_profile_id,
            "trust_profile_id": input.trust_profile_id,
            "revocation_profile_id": input.revocation_profile_id,
        "validity_rules": {"default_validity_days": 365, "max_validity_days": 365, "renewable": false},
            "issuance_protocol": "openid4vci_pre_authorized"
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let application = input.credential_template_id.as_ref().map(|id| json!({
        "organization_id": input.organization_id,
        "name": "Interoperable Credentials Foundations Application",
        "description": "Canvas learning evidence and explicit scoped approval before Open Badge issuance.",
        "credential_template_id": id,
        "form_fields": badge_application_fields().into_iter().map(|(name, label, kind)| json!({
            "field_id": name, "label": label, "field_type": kind.to_ascii_uppercase(),
            "required": true, "claim_mapping": name
        })).collect::<Vec<_>>(),
        "evidence_requirements": [],
        "claim_collection_rules": badge_claim_collection_rules(BADGE_VCT, "canvas.quiz_score"),
        "required_checks": [],
        "approval_strategy": "MANUAL",
        "application_validity_days": 30,
        "notification_config": {},
        "ui_config": {"scenario": "canvas_mip_quiz_open_badge", "provider": "canvas"}
    }));
    Ok(json!({"credential": credential, "application": application}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_templates_keep_learning_claims_without_custody_or_synthetic_evidence() {
        let mut input = NativeBadgeTemplateInput {
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            issuer_did: "did:web:issuer.example".into(),
            compliance_profile_id: "00000000-0000-0000-0000-000000000002".into(),
            trust_profile_id: "00000000-0000-0000-0000-000000000003".into(),
            revocation_profile_id: "00000000-0000-0000-0000-000000000004".into(),
            credential_template_id: Some("00000000-0000-0000-0000-000000000005".into()),
        };
        let output = native_badge_templates(&input).unwrap();
        let credential = &output["credential"];
        assert_eq!(credential["claims"].as_array().unwrap().len(), 18);
        assert!(credential["claims"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "learning_context"));
        for field in [
            "id",
            "status",
            "version",
            "remote_signing_config",
            "issuer_key_id",
            "key_access_mode",
            "wallet_configs",
        ] {
            assert!(
                credential.get(field).is_none(),
                "forbidden create field {field}"
            );
        }
        assert_eq!(output["application"]["approval_strategy"], "MANUAL");
        let fields = output["application"]["form_fields"].as_array().unwrap();
        assert_eq!(fields.len(), 6);
        assert!(fields
            .iter()
            .all(|field| field["field_id"] == field["claim_mapping"]));
        assert_eq!(fields[0]["field_type"], "EMAIL");
        assert_eq!(output["application"]["evidence_requirements"], json!([]));
        let mappings = output["application"]["claim_collection_rules"]
            .as_array()
            .unwrap();
        assert_eq!(mappings.len(), 18);
        for claim in credential["claims"].as_array().unwrap() {
            assert_eq!(
                mappings
                    .iter()
                    .filter(|rule| rule["claim_name"] == claim["name"])
                    .count(),
                1
            );
        }
        assert!(mappings
            .iter()
            .filter(|rule| rule["source"] == "EVIDENCE_EXTRACTION")
            .all(|rule| rule["source_config"]["fact_type"] == "canvas.quiz_score"));
        input.compliance_profile_id = "unbound".into();
        assert!(native_badge_templates(&input).is_err());
    }
}
