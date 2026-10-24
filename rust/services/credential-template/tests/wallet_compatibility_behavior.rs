use chrono::{TimeZone, Utc};
use marty_credential_template::{
    catalog::system_wallet_catalog,
    wallet::{derive_wallet_profile, matching_wallet_overrides, merge_wallet_profile},
    ClaimDefinition, ClaimType, CredentialFormat, CredentialTemplate, DisplayStyle,
    IssuerRequirements, MergeStrategy, PrivacyPosture, TemplateStatus, ValidityRules,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    profiles: Vec<ProfileCase>,
}

#[derive(Deserialize)]
struct ProfileCase {
    format: String,
    protocol: String,
    compliance: Option<String>,
    name: String,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-wallet-compatibility.json"
    )))
    .unwrap()
}

fn template() -> CredentialTemplate {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    CredentialTemplate {
        id: "template-1".to_owned(),
        organization_id: "org-1".to_owned(),
        name: "Employee Badge".to_owned(),
        description: None,
        status: TemplateStatus::Draft,
        credential_type: "EmployeeBadge".to_owned(),
        vct: "https://issuer.example/EmployeeBadge".to_owned(),
        doctype: None,
        claims: vec![ClaimDefinition {
            id: "claim-1".to_owned(),
            name: "family_name".to_owned(),
            display_name: "Family Name".to_owned(),
            description: None,
            claim_type: ClaimType::String,
            required: true,
            selectively_disclosable: true,
            derivable: false,
            derived_from: None,
            pattern: None,
            enum_values: None,
            min_value: None,
            max_value: None,
            mdoc_namespace: None,
            mdoc_element_identifier: None,
            display_icon: None,
        }],
        privacy_posture: PrivacyPosture::SelectiveDisclosure,
        selective_disclosure_fields: Vec::new(),
        zk_predicate_claims: Vec::new(),
        derived_attributes: Vec::new(),
        display_style: DisplayStyle::default(),
        validity_rules: ValidityRules::default(),
        issuer_requirements: IssuerRequirements::default(),
        supported_formats: vec![CredentialFormat::SdJwtVc],
        credential_payload_format: "SD_JWT_VC".to_owned(),
        wallet_configs: Vec::new(),
        compliance_profile: None,
        compliance_profile_id: Some("EUDI_PID".to_owned()),
        application_template_id: None,
        trust_profile_id: None,
        revocation_profile_id: None,
        issuer_algorithm: Some("ES256".to_owned()),
        issuer_did: Some("did:web:issuer.example".to_owned()),
        issuance_protocol: "OID4VCI_PRE_AUTH".to_owned(),
        version: 1,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn every_intended_derived_profile_and_fallback_is_preserved() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for case in contract.profiles {
        let profile =
            derive_wallet_profile(&case.format, &case.protocol, case.compliance.as_deref());
        assert_eq!(profile.name, case.name);
    }
}

#[test]
fn generic_requirements_preserve_compliance_key_for_scoped_override_matching() {
    let derived = derive_wallet_profile("SD_JWT_VC", "OID4VCI", Some(" campus_badge "));
    assert_eq!(derived.name, "Generic SD-JWT VC Wallet");
    assert_eq!(
        derived.compliance_profile_code.as_deref(),
        Some("CAMPUS_BADGE")
    );
    let mut matching = system_wallet_catalog(Utc::now()).remove(0);
    matching.id = "campus-override".into();
    matching.organization_id = Some("org-1".into());
    matching.is_override = true;
    matching.credential_format = Some("SD_JWT_VC".into());
    matching.issuance_protocol = Some("OID4VCI_PRE_AUTH".into());
    matching.compliance_profile_code = Some("CAMPUS_BADGE".into());
    let mut other_code = matching.clone();
    other_code.id = "different-compliance".into();
    other_code.compliance_profile_code = Some("EUDI_PID".into());
    let matches = matching_wallet_overrides(
        &[matching, other_code],
        "org-1",
        &derived.credential_format,
        &derived.issuance_protocol,
        derived.compliance_profile_code.as_deref(),
    );
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, "campus-override");
    let merged = merge_wallet_profile(derived, &matches, &template());
    assert_eq!(
        merged.derived_from.compliance_profile_code.as_deref(),
        Some("CAMPUS_BADGE")
    );
    assert_eq!(merged.applied_override_ids, ["campus-override"]);
}

#[test]
fn override_matching_and_merge_are_tenant_safe_and_deterministic() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut low = system_wallet_catalog(now).remove(0);
    low.id = "override-low".to_owned();
    low.organization_id = Some("org-1".to_owned());
    low.is_override = true;
    low.override_precedence = 10;
    low.credential_format = Some("SD_JWT_VC".to_owned());
    low.issuance_protocol = Some("OID4VCI".to_owned());
    low.wallet_apps = vec!["Tenant Wallet".to_owned()];

    let mut high = low.clone();
    high.id = "override-high".to_owned();
    high.override_precedence = 90;
    high.merge_strategy = MergeStrategy::Replace;
    high.wallet_apps = vec!["Primary Wallet".to_owned()];
    high.specifications = vec!["Tenant Profile".to_owned()];

    let mut other_tenant = low.clone();
    other_tenant.id = "override-other".to_owned();
    other_tenant.organization_id = Some("org-2".to_owned());
    let mut inactive = low.clone();
    inactive.id = "override-inactive".to_owned();
    inactive.is_active = false;

    let matches = matching_wallet_overrides(
        &[low, high, other_tenant, inactive],
        "org-1",
        "SD_JWT_VC",
        "OID4VCI_PRE_AUTH",
        Some("EUDI_PID"),
    );
    assert_eq!(
        matches
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["override-high", "override-low"]
    );
    let merged = merge_wallet_profile(
        derive_wallet_profile("SD_JWT_VC", "OID4VCI_PRE_AUTH", Some("EUDI_PID")),
        &matches,
        &template(),
    );
    assert_eq!(merged.id.as_deref(), Some("override-high"));
    assert_eq!(merged.override_precedence, 90);
    assert_eq!(
        merged.applied_override_ids,
        ["override-high", "override-low"]
    );
    assert_eq!(merged.wallet_apps, ["Primary Wallet", "Tenant Wallet"]);
    assert_eq!(merged.specifications, ["Tenant Profile", "OID4VCI"]);
}
