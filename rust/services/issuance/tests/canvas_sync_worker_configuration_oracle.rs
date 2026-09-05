//! Execute the frozen language-neutral factory corpus, including flagged gaps.

use std::collections::BTreeMap;

use marty_issuance_service::canvas_sync_worker::{
    CanvasSyncWorkerConfig, CanvasSyncWorkerConfigError,
};
use serde_json::{json, Value};

const INTEGER_FIELDS: [&str; 4] = [
    "batch_size",
    "lease_seconds",
    "schedule_limit",
    "oauth_revocation_limit",
];

fn baseline() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-configuration-oracle.json"
    ))
    .unwrap()
}

fn portable(config: &CanvasSyncWorkerConfig) -> Value {
    json!({
        "worker_id": config.worker_id,
        "batch_size": config.batch_size.as_decimal(),
        "lease_seconds": config.lease_seconds.as_decimal(),
        "job_timeout_seconds": config.job_timeout.as_secs_f64(),
        "schedule_limit": config.schedule_limit.as_decimal(),
        "oauth_revocation_limit": config.oauth_revocation_limit.as_decimal(),
        "poll_seconds": config.poll_interval.as_secs_f64(),
    })
}

fn assert_portable_configuration(config: &CanvasSyncWorkerConfig, expected: &Value, name: &Value) {
    let mut expected = expected.clone();
    // JSON 600 and 600.0 represent the same floating configuration value.
    // Normalize only the two declared duration fields, never integer strings.
    for field in ["job_timeout_seconds", "poll_seconds"] {
        expected[field] = json!(expected[field].as_f64().expect("duration number"));
    }
    assert_eq!(portable(config), expected, "{name}");
}

fn environment(case: &Value) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([(
        "CANVAS_SYNC_WORKER_ID".to_owned(),
        "oracle-worker".to_owned(),
    )]);
    for (key, value) in case["environment"].as_object().unwrap() {
        if let Some(value) = value.as_str() {
            values.insert(key.clone(), value.to_owned());
        } else {
            assert!(value.is_null());
            values.remove(key);
        }
    }
    values
}

fn assert_generated_identity(identity: &str) {
    let host = hostname::get().unwrap();
    let prefix = format!("{}-{}-", host.to_string_lossy(), std::process::id());
    let nonce = identity
        .strip_prefix(&prefix)
        .expect("OS hostname and actual PID identity");
    assert_eq!(nonce.len(), 8);
    assert!(nonce
        .chars()
        .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));
}

#[test]
fn all_15_baseline_vectors_match_the_actual_factory() {
    let fixture = baseline();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let config = CanvasSyncWorkerConfig::from_values(&environment(case))
            .expect("frozen accepted configuration");
        let mut expected = fixture["defaults"].clone();
        for (key, value) in case["expected"].as_object().unwrap() {
            expected[key] = value.clone();
        }
        for field in INTEGER_FIELDS {
            expected[field] = Value::String(expected[field].to_string());
        }
        if case["generated_identity"] == true {
            assert_generated_identity(&config.worker_id);
            expected["worker_id"] = Value::String(config.worker_id.clone());
        }
        assert_portable_configuration(&config, &expected, &case["name"]);
    }
}

#[test]
fn all_18_malformed_combinations_fail_at_configuration_without_echoing_values() {
    let fixture = baseline();
    let mut count = 0;
    for (fields, inputs) in [
        ("integer_environment", "malformed_integer_values"),
        ("float_environment", "malformed_float_values"),
    ] {
        for field in fixture[fields].as_array().unwrap() {
            for value in fixture[inputs].as_array().unwrap() {
                let name = field.as_str().unwrap();
                let values = BTreeMap::from([
                    (
                        "CANVAS_SYNC_WORKER_ID".to_owned(),
                        "oracle-worker".to_owned(),
                    ),
                    (name.to_owned(), value.as_str().unwrap().to_owned()),
                ]);
                let error = CanvasSyncWorkerConfig::from_values(&values).unwrap_err();
                assert!(
                    matches!(error, CanvasSyncWorkerConfigError::InvalidNumber { name: actual } if actual == name)
                );
                assert_eq!(
                    error.to_string(),
                    format!("invalid numeric Canvas worker configuration: {name}")
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 18);
}

#[test]
fn all_64_lexical_vectors_match_the_actual_factory_without_skips() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-numeric-lexical-oracle.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for case in cases {
        let actual = CanvasSyncWorkerConfig::from_values(&environment(case));
        if case.get("expected_error").is_some() {
            assert!(
                matches!(
                    actual,
                    Err(CanvasSyncWorkerConfigError::InvalidNumber { .. })
                ),
                "{}",
                case["name"]
            );
        } else {
            assert_portable_configuration(
                &actual.expect("accepted lexical vector"),
                &case["expected"],
                &case["name"],
            );
        }
    }
}

#[test]
fn all_36_consumer_range_inputs_are_lossless_at_startup() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-consumer-range-oracle.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 36);
    for case in cases {
        let field = case["field"].as_str().unwrap();
        let name = fixture["fields"][field].as_str().unwrap();
        let input = fixture["inputs"][case["input"].as_str().unwrap()]
            .as_str()
            .unwrap();
        let values = BTreeMap::from([
            (
                "CANVAS_SYNC_WORKER_ID".to_owned(),
                "oracle-worker".to_owned(),
            ),
            (name.to_owned(), input.to_owned()),
        ]);
        let config = CanvasSyncWorkerConfig::from_values(&values).unwrap();
        assert_eq!(portable(&config)[field], input);
    }
}

#[test]
fn generated_identity_uses_os_hostname_not_mutable_environment_hints() {
    let values = BTreeMap::from([
        ("HOSTNAME".to_owned(), "not-the-os-hostname".to_owned()),
        (
            "COMPUTERNAME".to_owned(),
            "not-the-os-hostname-either".to_owned(),
        ),
    ]);
    assert_generated_identity(
        &CanvasSyncWorkerConfig::from_values(&values)
            .unwrap()
            .worker_id,
    );
}
