use std::collections::BTreeSet;

use serde_json::Value;

#[test]
fn every_legacy_python_revision_has_one_explicit_rust_owner() {
    let contract: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-migration-history.json"
    )))
    .expect("valid migration-history contract");
    let owners = contract["rust_owners"].as_object().expect("owner map");
    let revisions = owners
        .values()
        .flat_map(|entries| entries.as_array().expect("revision array"))
        .map(|entry| entry.as_str().expect("revision name"))
        .collect::<Vec<_>>();
    assert_eq!(
        revisions.len(),
        contract["legacy_revision_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        revisions.iter().copied().collect::<BTreeSet<_>>().len(),
        revisions.len(),
        "a legacy migration cannot have ambiguous Rust ownership"
    );
    assert!(contract["final_state_invariants"]
        .as_array()
        .is_some_and(|invariants| invariants.len() >= 10));
}
