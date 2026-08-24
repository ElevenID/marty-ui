use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use marty_presentation_policy::{
    evaluate_verified_facts_json, normalize_credential_format, HolderBinding, PolicyDomainError,
    PolicyStatus, PresentationPolicy, GRPC_METHODS, HTTP_OPERATIONS,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
struct Contract {
    http_operations: Vec<HttpOperation>,
    grpc_methods: Vec<String>,
    statuses: Vec<String>,
    constraint_types: Vec<String>,
    request_purposes: Vec<String>,
    holder_binding_vectors: Vec<HolderVector>,
    format_vectors: Vec<FormatVector>,
    grpc_authorization: GrpcAuthorization,
    failure_behavior: String,
    decision_kernel: String,
}

#[derive(Deserialize)]
struct GrpcAuthorization {
    internal_lookup: String,
    internal_evaluation: String,
    management: String,
}

#[derive(Deserialize)]
struct HttpOperation {
    method: String,
    path: String,
}

#[derive(Deserialize)]
struct HolderVector {
    input: HolderBinding,
    expected: HolderBinding,
}

#[derive(Deserialize)]
struct FormatVector {
    input: String,
    expected: String,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/presentation-policy-service-behavior.json"
    ))
    .unwrap()
}

#[test]
fn complete_surface_and_domain_inventory_match_the_shared_contract() {
    let contract = contract();
    assert_eq!(contract.http_operations.len(), 10);
    assert_eq!(
        contract
            .http_operations
            .iter()
            .map(|operation| (operation.method.as_str(), operation.path.as_str()))
            .collect::<Vec<_>>(),
        HTTP_OPERATIONS
    );
    assert_eq!(contract.grpc_methods, GRPC_METHODS);
    assert_eq!(contract.statuses.len(), 4);
    assert_eq!(contract.constraint_types.len(), 11);
    assert_eq!(contract.request_purposes.len(), 8);
    assert_eq!(
        contract.grpc_authorization.internal_lookup,
        "service_token_and_authorized_workload_identity"
    );
    assert_eq!(
        contract.grpc_authorization.internal_evaluation,
        "service_token_and_authorized_flow_workload_identity"
    );
    assert_eq!(
        contract.grpc_authorization.management,
        "user_principal_and_organization_permission"
    );
    assert_eq!(contract.failure_behavior, "fail_closed");
    assert_eq!(
        contract.decision_kernel,
        "marty_verification::policy::evaluate_service_policy"
    );
}

#[test]
fn holder_binding_and_format_aliases_match_the_surviving_python_oracle() {
    let contract = contract();
    for vector in contract.holder_binding_vectors {
        assert_eq!(vector.input.normalize(), vector.expected);
    }
    for vector in contract.format_vectors {
        assert_eq!(normalize_credential_format(&vector.input), vector.expected);
    }
}

#[test]
fn direct_rust_kernel_matches_the_existing_cross_language_golden_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/presentation_policy_service.json"
    ))
    .unwrap();
    let output = evaluate_verified_facts_json(&fixture["request"].to_string()).unwrap();
    let output: Value = serde_json::from_str(&output).unwrap();
    let expected = &fixture["expected"];
    assert_eq!(output["result"], expected["result"]);
    assert_eq!(output["decision"], expected["decision"]);
    assert_eq!(output["required_total"], expected["required_total"]);
    assert_eq!(output["required_satisfied"], expected["required_satisfied"]);
    assert_eq!(output["verified_claims"], expected["verified_claims"]);
    assert_eq!(
        output["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|error| error["code"].clone())
            .collect::<Vec<_>>(),
        expected["error_codes"].as_array().unwrap().clone()
    );
}

#[test]
fn lifecycle_is_lossless_and_invalid_transitions_fail_closed() {
    let mut policy: PresentationPolicy = serde_json::from_value(Value::Object(
        [
            ("id".into(), Value::String(Uuid::new_v4().to_string())),
            (
                "organization_id".into(),
                Value::String(Uuid::new_v4().to_string()),
            ),
            ("name".into(), Value::String("Login".into())),
            ("description".into(), Value::Null),
            ("status".into(), Value::String("draft".into())),
            ("display_metadata".into(), serde_json::json!({"title":"Login","description":"","purpose":"identity_verification","purpose_description":null,"verifier_name":"Marty","verifier_logo_url":null,"privacy_policy_url":null,"terms_of_service_url":null})),
            ("required_claims".into(), Value::Array(vec![])),
            ("accepted_credential_types".into(), Value::Array(vec![])),
            ("credential_requirements".into(), Value::Array(vec![])),
            ("alternative_requirements".into(), Value::Array(vec![])),
            ("presentation_proof_required".into(), Value::Bool(true)),
            ("trust_profile_id".into(), Value::Null),
            ("holder_binding".into(), serde_json::json!({"required":true,"binding_methods":[],"proof_profiles":[],"proof_freshness":{}})),
            ("freshness".into(), Value::Null),
            ("issuer_constraints".into(), Value::Null),
            ("credential_ranking_strategy".into(), Value::String("FRESHEST_FIRST".into())),
            ("credential_ranking_weights".into(), Value::Null),
            ("purpose".into(), Value::String("Login".into())),
            ("compliance_profile_id".into(), Value::Null),
            ("prefer_predicates".into(), Value::Bool(false)),
            ("fallback_policy".into(), Value::Null),
            ("supported_circuits".into(), Value::Array(vec![])),
            ("version".into(), Value::Number(1.into())),
            ("created_at".into(), Value::String("2026-08-21T00:00:00Z".into())),
            ("updated_at".into(), Value::String("2026-08-21T00:00:00Z".into())),
        ]
        .into_iter()
        .collect(),
    ))
    .unwrap();
    let active_at = Utc.with_ymd_and_hms(2026, 8, 21, 1, 0, 0).unwrap();
    policy.activate(active_at).unwrap();
    assert_eq!(policy.status, PolicyStatus::Active);
    assert_eq!(
        policy.activate(active_at).unwrap_err(),
        PolicyDomainError::InvalidTransition {
            from: PolicyStatus::Active,
            to: PolicyStatus::Active
        }
    );
    policy.suspend(active_at).unwrap();
    let version = policy.new_version(Uuid::new_v4(), active_at);
    assert_eq!(version.status, PolicyStatus::Draft);
    assert_eq!(version.version, 2);
    assert_eq!(version.holder_binding, policy.holder_binding);
    assert_eq!(
        version.credential_ranking_strategy,
        policy.credential_ranking_strategy
    );
    assert_eq!(
        version.credential_ranking_weights,
        None::<BTreeMap<String, f64>>
    );
}
