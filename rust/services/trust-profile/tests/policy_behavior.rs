use marty_trust_profile::{
    allowed_issuers_after_request, normalize_accreditations, normalize_jurisdictions,
    reject_private_custody_metadata, require_issuer_status_transition,
    sanitize_private_custody_metadata,
};
use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap()
}

#[test]
fn accreditation_and_jurisdiction_policy_matches_shared_vectors() {
    let contract = contract();
    for case in contract["domain_cases"]["accreditations"]
        .as_array()
        .unwrap()
    {
        let input = serde_json::from_value::<Vec<String>>(case["input"].clone()).unwrap();
        let result = normalize_accreditations(input);
        if case.get("error").is_some() {
            assert!(result.is_err());
        } else {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                case["expected"]
            );
        }
    }
    for case in contract["domain_cases"]["jurisdictions"]
        .as_array()
        .unwrap()
    {
        let input = serde_json::from_value::<Vec<String>>(case["input"].clone()).unwrap();
        let result = normalize_jurisdictions(input);
        if case.get("error").is_some() {
            assert!(result.is_err());
        } else {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                case["expected"]
            );
        }
    }
}

#[test]
fn issuer_allowlist_defaults_match_the_fail_closed_shared_vectors() {
    let contract = contract();
    for case in contract["domain_cases"]["allowed_issuers"]
        .as_array()
        .unwrap()
    {
        let result = allowed_issuers_after_request(
            serde_json::from_value(case["current"].clone()).unwrap(),
            case["trust_source_count"].as_u64().unwrap() as usize,
            case["allowed_was_provided"].as_bool().unwrap(),
            serde_json::from_value(case["requested"].clone()).unwrap(),
            case.get("is_update")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        assert_eq!(serde_json::to_value(result).unwrap(), case["expected"]);
    }
}

#[test]
fn custody_metadata_and_terminal_revocation_match_shared_vectors() {
    let contract = contract();
    for case in contract["domain_cases"]["custody_metadata"]
        .as_array()
        .unwrap()
    {
        let error = reject_private_custody_metadata(&case["input"]).unwrap_err();
        assert!(error
            .to_string()
            .contains(case["rejected_field"].as_str().unwrap()));
        assert_eq!(
            sanitize_private_custody_metadata(&case["input"]),
            case["sanitized"]
        );
    }
    for case in contract["domain_cases"]["issuer_status_transitions"]
        .as_array()
        .unwrap()
    {
        let current = serde_json::from_value(case["current"].clone()).unwrap();
        let requested = serde_json::from_value(case["requested"].clone()).unwrap();
        assert_eq!(
            require_issuer_status_transition(current, requested).is_ok(),
            case["allowed"].as_bool().unwrap()
        );
    }
}
