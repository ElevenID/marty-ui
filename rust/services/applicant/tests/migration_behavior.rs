use marty_applicant::migration::{migrate_payload, MigrationError};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Vector {
    template_map: BTreeMap<String, String>,
    input: Value,
    expected: Value,
    unresolved_templates_fail_without_mutation: bool,
    repeat_is_noop: bool,
    backup_suffix: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "../../../../contracts/applicant-store-migration-behavior.json"
    ))
    .expect("valid applicant migration contract")
}

#[test]
fn legacy_store_vector_is_partitioned_losslessly_and_idempotently() {
    let vector = vector();
    let mut payload = vector.input;
    assert!(migrate_payload(&mut payload, &vector.template_map).unwrap());
    let application = &payload["applications"][0];
    for key in [
        "application_template_id",
        "credential_template_id",
        "status",
        "form_data",
        "integration_context",
        "system_data",
        "claim_state",
    ] {
        assert_eq!(application[key], vector.expected[key], "{key}");
    }
    assert_eq!(payload["schema_version"], vector.expected["schema_version"]);
    assert!(vector.repeat_is_noop);
    assert!(!migrate_payload(&mut payload, &vector.template_map).unwrap());
    assert_eq!(vector.backup_suffix, ".mip-0.2.bak");
}

#[test]
fn unresolved_template_fails_before_mutating_payload() {
    let vector = vector();
    let mut payload = vector.input;
    let original = payload.clone();
    let error = migrate_payload(&mut payload, &BTreeMap::new()).unwrap_err();
    assert!(matches!(error, MigrationError::UnresolvedTemplates(_)));
    assert!(vector.unresolved_templates_fail_without_mutation);
    assert_eq!(payload, original);
}
