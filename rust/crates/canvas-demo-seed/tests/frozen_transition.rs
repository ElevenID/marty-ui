use marty_canvas_demo_seed::transition_summary;
use serde_json::Value;

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
