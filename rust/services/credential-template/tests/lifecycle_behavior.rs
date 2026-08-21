use chrono::{TimeZone, Utc};
use marty_credential_template::{
    resolve_validity_rules, validate_claim_definitions, validate_credential_type, ClaimDefinition,
    ClaimType, CredentialFormat, CredentialTemplate, DisplayStyle, IssuerRequirements,
    PrivacyPosture, TemplateStatus, ValidityRules, ValidityRulesInput,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    credential_types: Vec<CredentialTypeCase>,
    claim_sets: Vec<ClaimSetCase>,
    validity_cases: Vec<ValidityCase>,
    transitions: Vec<TransitionCase>,
}

#[derive(Deserialize)]
struct CredentialTypeCase {
    value: String,
    accepted: bool,
}

#[derive(Deserialize)]
struct ClaimSetCase {
    name: String,
    claims: Vec<ClaimCase>,
    accepted: bool,
}

#[derive(Deserialize)]
struct ClaimCase {
    name: String,
    derived_from: Option<String>,
}

#[derive(Deserialize)]
struct ValidityCase {
    name: String,
    input: ValidityRulesInput,
    accepted: bool,
    expected: Option<Value>,
}

#[derive(Deserialize)]
struct TransitionCase {
    name: String,
    status: String,
    claim_count: usize,
    operation: String,
    accepted: bool,
    result_status: Option<String>,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-lifecycle-behavior.json"
    )))
    .expect("valid lifecycle fixture")
}

fn claim(name: &str, derived_from: Option<String>) -> ClaimDefinition {
    ClaimDefinition {
        id: format!("claim-{name}"),
        name: name.to_owned(),
        display_name: name.to_owned(),
        description: None,
        claim_type: ClaimType::String,
        required: true,
        selectively_disclosable: true,
        derivable: derived_from.is_some(),
        derived_from,
        pattern: None,
        enum_values: None,
        min_value: None,
        max_value: None,
        mdoc_namespace: None,
        mdoc_element_identifier: None,
        display_icon: None,
    }
}

fn template(status: TemplateStatus, claim_count: usize) -> CredentialTemplate {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    CredentialTemplate {
        id: "template-1".to_owned(),
        organization_id: "org-1".to_owned(),
        name: "Employee Badge".to_owned(),
        description: None,
        status,
        credential_type: "EmployeeBadge".to_owned(),
        vct: "https://issuer.example/EmployeeBadge".to_owned(),
        doctype: None,
        claims: (0..claim_count)
            .map(|index| claim(&format!("claim_{index}"), None))
            .collect(),
        privacy_posture: PrivacyPosture::SelectiveDisclosure,
        selective_disclosure_fields: Vec::new(),
        zk_predicate_claims: Vec::new(),
        derived_attributes: Vec::new(),
        display_style: DisplayStyle::default(),
        validity_rules: ValidityRules::default(),
        issuer_requirements: IssuerRequirements::default(),
        supported_formats: vec![CredentialFormat::SdJwtVc],
        credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
        wallet_configs: Vec::new(),
        compliance_profile: None,
        compliance_profile_id: Some("profile-1".to_owned()),
        application_template_id: None,
        trust_profile_id: None,
        revocation_profile_id: Some("revocation-1".to_owned()),
        issuer_algorithm: Some("ES256".to_owned()),
        issuer_did: Some("did:web:issuer.example".to_owned()),
        issuance_protocol: "oid4vci".to_owned(),
        version: 1,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn definitions_follow_the_frozen_validation_contract() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for case in contract.credential_types {
        assert_eq!(
            validate_credential_type(&case.value).is_ok(),
            case.accepted,
            "{}",
            case.value
        );
    }
    for case in contract.claim_sets {
        let claims = case
            .claims
            .into_iter()
            .map(|item| claim(&item.name, item.derived_from))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_claim_definitions(&claims).is_ok(),
            case.accepted,
            "{}",
            case.name
        );
    }
}

#[test]
fn validity_aliases_preserve_released_rounding_and_precedence() {
    for case in contract().validity_cases {
        let result = resolve_validity_rules(&case.input, None);
        assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.name);
        if let Some(expected) = case.expected {
            let actual = serde_json::to_value(result.expect("accepted validity case"))
                .expect("validity serialization");
            for (field, value) in expected.as_object().expect("expected validity object") {
                assert_eq!(actual.get(field), Some(value), "{}: {field}", case.name);
            }
        }
    }
}

#[test]
fn lifecycle_transitions_are_fail_closed_and_versioning_is_lossless() {
    let now = Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, 0).unwrap();
    for case in contract().transitions {
        let mut template = template(
            TemplateStatus::parse(&case.status).unwrap(),
            case.claim_count,
        );
        let result = match case.operation.as_str() {
            "activate" => template.activate(now),
            "mutate" => template.ensure_draft_mutation(),
            "delete" => template.ensure_deletable(),
            "deprecate" => {
                template.deprecate(now);
                Ok(())
            }
            operation => panic!("unknown operation {operation}"),
        };
        assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.name);
        if let Some(status) = case.result_status {
            assert_eq!(template.status.as_str(), status, "{}", case.name);
        }
    }

    let original = template(TemplateStatus::Active, 1);
    let version = original.new_version("template-2".to_owned(), now);
    assert_eq!(version.id, "template-2");
    assert_eq!(version.status, TemplateStatus::Draft);
    assert_eq!(version.version, original.version + 1);
    assert_eq!(version.claims, original.claims);
    assert_eq!(version.issuer_did, original.issuer_did);
    assert_eq!(version.validity_rules, original.validity_rules);
    assert_eq!(version.created_at, now);
}
