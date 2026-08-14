use marty_signing_keys::registry::{
    normalize_registry, normalize_service, resolve, NormalizeRegistryRequest,
    NormalizeServiceRequest, ResolveRequest,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    normalize_service_cases: Vec<NormalizeServiceCase>,
    normalize_registry_cases: Vec<NormalizeRegistryCase>,
    resolve_cases: Vec<ResolveCase>,
    failure_cases: Vec<FailureCase>,
}

#[derive(Debug, Deserialize)]
struct NormalizeServiceCase {
    name: String,
    input: Value,
    expected: Value,
}

#[derive(Debug, Deserialize)]
struct NormalizeRegistryCase {
    name: String,
    mode: String,
    input: Value,
    expected: Value,
}

#[derive(Debug, Deserialize)]
struct ResolveCase {
    name: String,
    input: Value,
    expected: Value,
}

#[derive(Debug, Deserialize)]
struct FailureCase {
    name: String,
    input: Value,
    error_contains: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/registry_vectors.json"))
        .expect("valid registry fixture")
}

#[test]
fn service_normalization_matches_language_neutral_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.normalize_service_cases {
        let result = normalize_service(NormalizeServiceRequest {
            service: case.input,
        })
        .unwrap_or_else(|error| panic!("{} failed: {error}", case.name));
        assert_eq!(result.service, Some(case.expected), "{}", case.name);
    }
}

#[test]
fn registry_normalization_matches_language_neutral_vectors() {
    for case in fixture().normalize_registry_cases {
        let request: NormalizeRegistryRequest = serde_json::from_value(serde_json::json!({
            "registry": case.input,
            "mode": case.mode,
        }))
        .expect("normalization request");
        let result = normalize_registry(request)
            .unwrap_or_else(|error| panic!("{} failed: {error}", case.name));
        assert_eq!(result.registry, case.expected, "{}", case.name);
    }
}

#[test]
fn registry_resolution_matches_language_neutral_vectors() {
    for case in fixture().resolve_cases {
        let request: ResolveRequest =
            serde_json::from_value(case.input).expect("resolution request");
        let result =
            resolve(request).unwrap_or_else(|error| panic!("{} failed: {error}", case.name));
        assert_eq!(
            serde_json::to_value(result).expect("resolution response"),
            case.expected,
            "{}",
            case.name
        );
    }
}

#[test]
fn malformed_registry_vectors_fail_closed() {
    for case in fixture().failure_cases {
        let request: NormalizeRegistryRequest =
            serde_json::from_value(case.input).expect("failure request");
        let error = normalize_registry(request).expect_err("must fail closed");
        assert!(
            error.to_string().contains(&case.error_contains),
            "{}: {error}",
            case.name
        );
    }
}
