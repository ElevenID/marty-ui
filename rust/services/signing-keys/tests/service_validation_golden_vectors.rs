use marty_signing_keys::validation::{validate, ValidationCheck, ValidationRequest};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    input: Value,
    expected_ok: bool,
    expected_checks: Vec<ValidationCheck>,
}

#[tokio::test]
async fn rust_matches_language_neutral_service_validation_vectors() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("fixtures/service_validation_vectors.json"))
            .expect("valid service validation fixture");

    for vector in vectors {
        let request: ValidationRequest =
            serde_json::from_value(vector.input).expect("valid validation request");
        let result = validate(request).await;
        assert_eq!(result.ok, vector.expected_ok, "{} ok", vector.name);
        assert_eq!(
            result.checks, vector.expected_checks,
            "{} checks",
            vector.name
        );
        assert!(!result.validated_at.is_empty(), "{} timestamp", vector.name);
    }
}
