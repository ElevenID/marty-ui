use marty_demo_vendor_seed::{normalize_profile, payload_format, persistent_profile, reference};
use serde_json::Value;

#[test]
fn frozen_profiles_and_payload_formats() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/demo-vendor-seed-behavior-v1.json"
    ))
    .unwrap();
    for case in corpus["profile_cases"].as_array().unwrap() {
        let normalized = normalize_profile(case["input"].as_str().unwrap());
        assert_eq!(normalized, case["normalized"]);
        assert_eq!(persistent_profile(&normalized), case["persistent"]);
    }
    for case in corpus["payload_format_cases"].as_array().unwrap() {
        let row = serde_json::json!({"credential_payload_format": case["explicit"], "supported_formats": case["supported"]});
        assert_eq!(payload_format(&row), case["result"]);
    }
    let fixture = reference().unwrap();
    assert_eq!(
        fixture["vendor_bundle"]["credential_types"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        fixture["vendor_bundle"]["credential_templates"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
}
