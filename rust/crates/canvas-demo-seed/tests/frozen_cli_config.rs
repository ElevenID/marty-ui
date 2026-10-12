use marty_canvas_demo_seed::build_run_config;
use serde_json::{json, Value};
use std::collections::HashMap;

#[test]
fn cli_defaults_and_flags_match_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let env = HashMap::from([
        ("MARTY_API_KEY".into(), "test-gateway-key".into()),
        (
            "ISSUANCE_INTERNAL_API_BASE_URL".into(),
            "http://issuance:8008".into(),
        ),
        ("ISSUANCE_API_KEY".into(), "test-issuance-key".into()),
    ]);
    assert_eq!(
        serde_json::to_value(build_run_config(&env, true, true).unwrap()).unwrap(),
        contract["canvas_cli_config"]
    );
}

#[test]
fn cli_rejects_gateway_service_key_and_direct_issuance_confusion() {
    let empty = HashMap::new();
    assert!(build_run_config(&empty, true, false)
        .unwrap_err()
        .contains("MARTY_API_KEY"));
    let env = HashMap::from([
        ("MARTY_API_KEY".into(), "gateway-key".into()),
        (
            "ISSUANCE_INTERNAL_API_BASE_URL".into(),
            "http://localhost:8000".into(),
        ),
        ("ISSUANCE_API_KEY".into(), "service-key".into()),
    ]);
    assert!(build_run_config(&env, true, false)
        .unwrap_err()
        .contains("must target the issuance service directly"));
    let env = HashMap::from([
        ("MARTY_API_KEY".into(), "gateway-key".into()),
        (
            "CANVAS_DEMO_APPLICATION_SEED_ENABLED".into(),
            "false".into(),
        ),
    ]);
    let config = build_run_config(&env, true, false).unwrap();
    assert_eq!(
        json!(config.connector.demo_application_seed_enabled),
        json!(false)
    );
}
