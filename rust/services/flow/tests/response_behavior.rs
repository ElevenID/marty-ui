use std::path::PathBuf;

use marty_flow::{
    project_artifact, project_definition, project_instance, project_verification_result,
    ArtifactProjectionInput, DefinitionProjectionInput, InstanceProjectionInput,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    definition: ProjectionCase,
    instance: InstanceCase,
    artifact: ProjectionCase,
    invalid_mutations: Vec<String>,
}

#[derive(Deserialize)]
struct ProjectionCase {
    input: Value,
    expected: Value,
}

#[derive(Deserialize)]
struct InstanceCase {
    input: Value,
    expected: Value,
    verification_expected: Value,
}

fn contract() -> Contract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/flow-response-behavior.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn public_response_projections_match_the_language_neutral_contract() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);

    let definition: DefinitionProjectionInput =
        serde_json::from_value(contract.definition.input).unwrap();
    assert_eq!(
        serde_json::to_value(project_definition(definition).unwrap()).unwrap(),
        contract.definition.expected
    );

    let instance: InstanceProjectionInput =
        serde_json::from_value(contract.instance.input).unwrap();
    assert_eq!(
        serde_json::to_value(project_instance(&instance).unwrap()).unwrap(),
        contract.instance.expected
    );
    assert_eq!(
        serde_json::to_value(project_verification_result(&instance).unwrap()).unwrap(),
        contract.instance.verification_expected
    );

    let artifact: ArtifactProjectionInput =
        serde_json::from_value(contract.artifact.input).unwrap();
    assert_eq!(
        serde_json::to_value(project_artifact(artifact).unwrap()).unwrap(),
        contract.artifact.expected
    );
}

#[test]
fn malformed_persisted_projection_state_fails_closed() {
    let contract = contract();
    assert_eq!(contract.invalid_mutations.len(), 6);
    for mutation in contract.invalid_mutations {
        let failed = match mutation.as_str() {
            "invalid_definition_timestamp" => {
                let mut input = contract.definition.input.clone();
                input["created_at"] = json!("not-a-timestamp");
                project_definition(serde_json::from_value(input).unwrap()).is_err()
            }
            "invalid_custom_extension" => {
                let mut input = contract.definition.input.clone();
                input["flow_type"] = json!("custom");
                input["extension"] = json!({"extends_flow_type": "custom", "steps": []});
                project_definition(serde_json::from_value(input).unwrap()).is_err()
            }
            "non_object_instance_context" => {
                let mut input = contract.instance.input.clone();
                input["context"] = json!([]);
                let input = serde_json::from_value(input).unwrap();
                project_instance(&input).is_err()
            }
            "invalid_protocol_flow_type" => {
                let mut input = contract.instance.input.clone();
                input["context"]["protocol_flow_type"] = json!("unknown");
                let input = serde_json::from_value(input).unwrap();
                project_instance(&input).is_err()
            }
            "invalid_current_step_index" => {
                let mut input = contract.instance.input.clone();
                input["context"]["current_step_index"] = json!(-1);
                let input = serde_json::from_value(input).unwrap();
                project_instance(&input).is_err()
            }
            "non_object_artifact_metadata" => {
                let mut input = contract.artifact.input.clone();
                input["wallet_metadata"] = json!([]);
                project_artifact(serde_json::from_value(input).unwrap()).is_err()
            }
            unknown => panic!("unknown projection mutation: {unknown}"),
        };
        assert!(failed, "{mutation}");
    }
}
