use marty_applicant::migration::{migrate_file, migrate_payload, MigrationError};
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
        "../../../../contracts/applicant-store-migration-platform.json"
    ))
    .expect("valid applicant migration contract")
}

#[test]
fn reviewed_generic_legacy_store_is_partitioned_losslessly_and_idempotently() {
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

fn historical_payload() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../../../../contracts/applicant-store-migration-behavior.json"
    ))
    .unwrap()["input"]
        .clone()
}

#[test]
fn historical_provider_metadata_is_refused_without_relabeling_or_mutation() {
    let mut payload = historical_payload();
    let original = payload.clone();
    assert!(matches!(
        migrate_payload(&mut payload, &vector().template_map),
        Err(MigrationError::LegacyContextReviewRequired)
    ));
    assert_eq!(payload, original);
}

#[test]
fn unknown_metadata_and_context_are_not_guessed_as_form_data_or_authority() {
    for (field, value) in [
        ("metadata", serde_json::json!({"unreviewed_field": null})),
        (
            "metadata",
            serde_json::json!({"learner_identity": {"id": "untrusted"}}),
        ),
        ("metadata", serde_json::json!([])),
        (
            "integration_context",
            serde_json::json!({"unreviewed_provider": {}}),
        ),
        ("integration_context", serde_json::json!([])),
    ] {
        let mut payload = vector().input;
        payload["applications"][0][field] = value;
        let original = payload.clone();
        assert!(
            matches!(
                migrate_payload(&mut payload, &vector().template_map),
                Err(MigrationError::LegacyContextReviewRequired)
            ),
            "{field}"
        );
        assert_eq!(payload, original);
    }
}

#[test]
fn a_late_unreviewed_row_refuses_the_entire_store_before_mutation() {
    let mut payload = vector().input;
    payload["applications"]
        .as_array_mut()
        .unwrap()
        .push(historical_payload()["applications"][0].clone());
    let original = payload.clone();
    assert!(matches!(
        migrate_payload(&mut payload, &vector().template_map),
        Err(MigrationError::LegacyContextReviewRequired)
    ));
    assert_eq!(payload, original);
}

#[test]
fn current_documents_remain_untouched_including_historical_context() {
    let mut payload = serde_json::json!({"applications": [{
        "credential_template_id": "credential-1",
        "integration_context": {"historical_provider": {"retained": true}}
    }]});
    let original = payload.clone();
    assert!(!migrate_payload(&mut payload, &BTreeMap::new()).unwrap());
    assert_eq!(payload, original);
}

#[test]
fn a_refused_file_upgrade_preserves_exact_bytes_without_backup_or_temporary_output() {
    struct OwnedFile(std::path::PathBuf);
    impl Drop for OwnedFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("store.json"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "marty-applicant-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&directory).unwrap();
    let owner = OwnedFile(directory);
    let file = owner.0.join("store.json");
    let bytes = serde_json::to_vec_pretty(&historical_payload()).unwrap();
    std::fs::write(&file, &bytes).unwrap();
    assert!(matches!(
        migrate_file(&file, &vector().template_map),
        Err(MigrationError::LegacyContextReviewRequired)
    ));
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&owner.0).unwrap().count(), 1);
}
