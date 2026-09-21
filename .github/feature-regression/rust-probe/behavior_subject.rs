use std::collections::BTreeMap;

use marty_issuance_service::internal_application_domain::derive_applicant_identifier;
use serde_json::{json, Map, Value};

const OPERATION_ID: &str = "internal-application.create.applicant-identifier";

fn observation(case_id: &str, applicant_data: Map<String, Value>, fallback: &str) -> Value {
    let value = derive_applicant_identifier(&applicant_data, fallback);
    let fields = BTreeMap::from([
        ("case_id", json!(case_id)),
        ("dimension", json!("public_message")),
        ("id", json!(format!("{case_id}.public_message"))),
        ("operation_id", json!(OPERATION_ID)),
        ("value", json!(value)),
    ]);
    serde_json::to_value(fields).expect("observation fields are JSON values")
}

fn applicant_object(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .expect("the frozen probe input is an object")
        .clone()
}

fn document() -> String {
    let observations = vec![
        observation(
            "named-applicant",
            applicant_object(json!({
                "given_name": " Ada ",
                "family_name": ["Lovelace"],
                "email": "ignored@example.test"
            })),
            "generated-name",
        ),
        observation(
            "email-fallback",
            applicant_object(json!({
                "given_name": "",
                "family_name": false,
                "email": " ada@example.test "
            })),
            "generated-email",
        ),
        observation(
            "generated-fallback",
            applicant_object(json!({
                "given_name": 0,
                "family_name": [],
                "email": null
            })),
            "generated-fallback-id",
        ),
    ];
    let root = BTreeMap::from([
        ("observations", json!(observations)),
        ("schema", json!("elevenid.behavior-subject-output/v2")),
    ]);
    serde_json::to_string(&root).expect("probe output is serializable")
}

fn main() {
    println!("{}", document());
}
