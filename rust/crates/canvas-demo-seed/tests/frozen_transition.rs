use marty_canvas_demo_seed::{build_run_config, transition_display_lines, transition_summary};
use serde_json::Value;
use std::collections::HashMap;

#[test]
fn transition_summary_matches_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let summary = &contract["canvas_transition"]["summary"];
    assert_eq!(
        transition_summary(
            summary["application"].clone(),
            Some(summary["latest_fact"].clone()),
            Some(summary["issued_credential"].clone()),
            summary["delivery_records"].as_array().unwrap().clone(),
            1,
        ),
        *summary
    );
}

#[test]
fn transition_display_matches_frozen_python_demo_evidence() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["canvas_transition_print"];
    let environment = HashMap::from([
        ("MARTY_API_KEY".into(), "test-gateway-key".into()),
        (
            "ISSUANCE_INTERNAL_API_BASE_URL".into(),
            "http://issuance:8008".into(),
        ),
        ("ISSUANCE_API_KEY".into(), "test-issuance-key".into()),
        ("PUBLIC_API_URL".into(), "https://marty.example".into()),
        (
            "CANVAS_CREDENTIALS_PUBLIC_BASE_URL".into(),
            "https://canvas.example".into(),
        ),
        ("CANVAS_ACCOUNT_ID".into(), "account-1".into()),
        ("CANVAS_ORGANIZATION_ID".into(), "org-1".into()),
    ]);
    let config = build_run_config(&environment, true, false).unwrap();
    assert_eq!(
        serde_json::to_value(transition_display_lines(
            &frozen["summary"],
            &config.connector,
            &environment
        ))
        .unwrap(),
        frozen["lines"]
    );
}
