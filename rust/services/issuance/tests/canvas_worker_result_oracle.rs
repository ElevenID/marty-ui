use marty_issuance_service::canvas_sync_worker::{
    canvas_sync_result, safe_result, CanvasSyncResult,
};
use serde_json::{Map, Value};

fn oracle() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-result-oracle.json"
    ))
    .expect("frozen Python worker result oracle")
}

#[test]
fn every_result_field_replays_every_python_json_observation() {
    let fixture = oracle();
    let mut checked = 0;
    let mut failures = Vec::new();
    for group in ["allowed_fields", "unknown_fields"] {
        for field in fixture[group].as_array().expect("field names") {
            let field = field.as_str().expect("field name");
            for case in fixture["value_cases"].as_array().expect("value cases") {
                let supplied: CanvasSyncResult = serde_json::from_str(&format!(
                    "{{{}:{},\"unlisted_provider_detail\":{{\"synthetic\":\"discard\"}}}}",
                    serde_json::to_string(field).unwrap(),
                    case["input_json"].as_str().unwrap(),
                ))
                .expect("parse original JSON lexemes without intermediate numeric coercion");
                let before = serde_json::to_string(&supplied).unwrap();
                let actual = safe_result(&supplied);
                // Compare serialized JSON, not only parsed Values: parsing both
                // sides with a lossy numeric representation can hide rounding.
                let actual_json = serde_json::to_string(&actual).unwrap();
                let expected_json = if group == "unknown_fields" || case["omitted"] == true {
                    "{}".to_owned()
                } else {
                    format!(
                        "{{{}:{}}}",
                        serde_json::to_string(field).unwrap(),
                        case["expected_json"].as_str().unwrap()
                    )
                };
                if actual_json != expected_json {
                    failures.push(format!(
                        "{group}/{field}/{}: {actual_json} != {expected_json}",
                        case["name"]
                    ));
                }
                assert_eq!(
                    serde_json::to_string(&supplied).unwrap(),
                    before,
                    "input must not be mutated"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 483, "do not silently skip reconciliation cases");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn empty_and_complete_result_allowlist_match_python() {
    assert!(safe_result(&CanvasSyncResult::new()).is_empty());
    let fixture = oracle();
    let supplied: Map<String, Value> = fixture["allowed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, field)| (field.as_str().unwrap().to_owned(), Value::from(index)))
        .collect();
    let expected = serde_json::to_value(&supplied).unwrap();
    assert_eq!(
        serde_json::to_value(safe_result(&canvas_sync_result(supplied).unwrap())).unwrap(),
        expected
    );
}
