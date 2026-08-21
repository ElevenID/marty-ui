use marty_credential_template::{
    normalize_legacy_claim_type, stable_legacy_claim_id, ClaimDefinition, ClaimType, ValidityRules,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    legacy_claims: Vec<LegacyClaim>,
    legacy_claim_type_aliases: serde_json::Map<String, Value>,
    legacy_null_optional_claim: NullOptionalClaim,
    validity_round_trip_fields: Vec<String>,
}

#[derive(Deserialize)]
struct NullOptionalClaim {
    input: Value,
    expected: Value,
}

#[derive(Deserialize)]
struct LegacyClaim {
    template_id: String,
    index: usize,
    name: String,
    expected_id: String,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-persistence-behavior.json"
    )))
    .expect("valid persistence fixture")
}

#[test]
fn legacy_claim_identity_and_type_aliases_are_stable() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for claim in contract.legacy_claims {
        assert_eq!(
            stable_legacy_claim_id(&claim.template_id, claim.index, &claim.name),
            claim.expected_id
        );
    }
    for (legacy, canonical) in contract.legacy_claim_type_aliases {
        assert_eq!(
            normalize_legacy_claim_type(&legacy),
            canonical.as_str().expect("canonical claim type")
        );
    }
    assert_eq!(normalize_legacy_claim_type("STRING"), "string");
}

#[test]
fn legacy_claims_hydrate_without_silent_data_loss() {
    let claim = ClaimDefinition::from_legacy_value(
        "template-1",
        0,
        &json!({
            "name": "family_name",
            "type": "text",
            "derived_from": "legal_name",
            "required": false,
            "min_value": 1
        }),
    )
    .expect("legacy claim must hydrate");
    assert_eq!(claim.id, "96397b6e-bc9b-5210-a2c0-4d9f3ef41c81");
    assert_eq!(claim.display_name, "Family Name");
    assert_eq!(claim.claim_type, ClaimType::String);
    assert!(!claim.required);
    assert!(claim.derivable);
    assert_eq!(claim.min_value, Some(1.0));
    assert!(ClaimDefinition::from_legacy_value("template-1", 1, &json!("invalid")).is_err());

    let null_case = contract().legacy_null_optional_claim;
    let claim = ClaimDefinition::from_legacy_value("template-1", 2, &null_case.input)
        .expect("explicit null optional claim fields must hydrate");
    assert_eq!(
        json!({
            "enum_values": claim.enum_values,
            "min_value": claim.min_value,
            "max_value": claim.max_value,
        }),
        null_case.expected
    );
}

#[test]
fn validity_rules_round_trip_every_intended_field() {
    let contract = contract();
    let value = serde_json::to_value(ValidityRules {
        not_before_offset_seconds: -30,
        revalidation_interval_days: Some(7),
        ..ValidityRules::default()
    })
    .expect("validity rules serialize");
    for field in contract.validity_round_trip_fields {
        assert!(
            value.get(&field).is_some(),
            "missing validity field {field}"
        );
    }
    let hydrated: ValidityRules = serde_json::from_value(value).expect("validity rules hydrate");
    assert_eq!(hydrated.not_before_offset_seconds, -30);
    assert_eq!(hydrated.revalidation_interval_days, Some(7));
}
