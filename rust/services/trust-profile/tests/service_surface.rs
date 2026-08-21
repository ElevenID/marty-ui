use std::collections::BTreeSet;

use marty_trust_profile::TRUST_PROFILE_HTTP_OPERATIONS;
use serde_json::Value;

#[test]
fn native_http_surface_matches_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    let expected = contract["http_operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| {
            (
                operation[0].as_str().unwrap().to_owned(),
                operation[1].as_str().unwrap().to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let native = TRUST_PROFILE_HTTP_OPERATIONS
        .iter()
        .map(|operation| (operation.method.to_owned(), operation.path.to_owned()))
        .collect::<BTreeSet<_>>();
    assert_eq!(native, expected);
    assert_eq!(native.len(), TRUST_PROFILE_HTTP_OPERATIONS.len());
}
