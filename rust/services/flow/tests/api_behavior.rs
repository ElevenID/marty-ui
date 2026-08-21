use std::path::PathBuf;

use marty_flow::{
    parse_request, AdvanceFlowRequest, ApplicationApprovedWebhook, CreateFlowDefinitionRequest,
    DigitalCredentialSubmissionRequest, FlowApiError, SiopSubmitRequest, StartFlowRequest,
    StartSiopFlowRequest, StartVerificationFlowRequest, SubmitVerificationRequest,
    UpdateFlowDefinitionRequest,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    valid_requests: Vec<Vector>,
    invalid_requests: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    kind: String,
    payload: Value,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    field: Option<String>,
}

fn contract() -> Contract {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/flow-api-behavior.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn validate(kind: &str, payload: Value) -> Result<(), FlowApiError> {
    match kind {
        "create_definition" => parse_request::<CreateFlowDefinitionRequest>(payload).map(drop),
        "patch_definition" => parse_request::<UpdateFlowDefinitionRequest>(payload).map(drop),
        "start_flow" => parse_request::<StartFlowRequest>(payload).map(drop),
        "advance_flow" => parse_request::<AdvanceFlowRequest>(payload).map(drop),
        "start_verification" => parse_request::<StartVerificationFlowRequest>(payload).map(drop),
        "start_siop" => parse_request::<StartSiopFlowRequest>(payload).map(drop),
        "siop_submit" => parse_request::<SiopSubmitRequest>(payload).map(drop),
        "submit_verification" => parse_request::<SubmitVerificationRequest>(payload).map(drop),
        "digital_credential_submit" => {
            parse_request::<DigitalCredentialSubmissionRequest>(payload).map(drop)
        }
        "application_approved" => parse_request::<ApplicationApprovedWebhook>(payload).map(drop),
        unknown => panic!("unknown API vector kind: {unknown}"),
    }
}

#[test]
fn all_language_neutral_valid_request_vectors_are_accepted() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for vector in contract.valid_requests {
        validate(&vector.kind, vector.payload)
            .unwrap_or_else(|error| panic!("{} should pass: {error}", vector.kind));
    }
}

#[test]
fn all_language_neutral_invalid_request_vectors_fail_closed() {
    for vector in contract().invalid_requests {
        let error = validate(&vector.kind, vector.payload)
            .unwrap_err_or_else(|| panic!("{} should fail", vector.kind));
        assert_eq!(Some(error.code), vector.code.as_deref(), "{}", vector.kind);
        assert_eq!(
            Some(error.field.as_str()),
            vector.field.as_deref(),
            "{}",
            vector.kind
        );
    }
}

trait ResultExt<T, E> {
    fn unwrap_err_or_else(self, failure: impl FnOnce() -> E) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, failure: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => failure(),
            Err(error) => error,
        }
    }
}

#[test]
fn patch_preserves_unset_versus_explicit_null() {
    let request: UpdateFlowDefinitionRequest = serde_json::from_value(serde_json::json!({
        "organization_id": "org-1",
        "description": null
    }))
    .unwrap();
    assert!(request.name.is_unset());
    assert!(!request.description.is_unset());
    assert_eq!(
        serde_json::to_value(request).unwrap()["description"],
        Value::Null
    );
}

#[test]
fn callback_policy_allows_only_explicit_development_loopback_exception() {
    let localhost: StartVerificationFlowRequest = serde_json::from_value(serde_json::json!({
        "organization_id": "org-1",
        "issuer_did": "did:web:verifier.example",
        "presentation_policy_id": "policy-1",
        "callback_url": "http://localhost:8080/callback"
    }))
    .unwrap();
    assert!(localhost.validate_for_environment(false).is_err());
    assert!(localhost.validate_for_environment(true).is_ok());

    let private_ip: StartVerificationFlowRequest = serde_json::from_value(serde_json::json!({
        "organization_id": "org-1",
        "issuer_did": "did:web:verifier.example",
        "presentation_policy_id": "policy-1",
        "callback_url": "http://10.0.0.1/callback"
    }))
    .unwrap();
    assert!(private_ip.validate_for_environment(true).is_err());
}
