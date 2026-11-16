//! Historical native Compose down evidence, not a fresh absence observation.
//! The planner must separately inspect Docker and retain external custody and
//! writer-quiescence requirements. These records never authorize deletion.

use std::collections::BTreeSet;

use serde_json::{json, Value};

const REFUSED: &str = "Native Compose cleanup evidence is incomplete; preserve the installation";
#[cfg(target_os = "linux")]
const INTENT: &str = "uninstall-compose-down-0001-intent.json";
#[cfg(target_os = "linux")]
const RESULT: &str = "uninstall-compose-down-0001-result.json";
const OPERATION: &str = "down-0001";

pub(crate) struct DownContext {
    pub project: String,
    pub engine_id: String,
    pub configuration_sha256: String,
    pub input_files: Value,
    pub prior_resources: Value,
    pub selected_session_sha256: String,
}

pub(crate) struct DownEvidence {
    pub intent_sha256: String,
    pub result_sha256: String,
    pub selected_session_sha256: String,
    pub prior_resources: Value,
    pub retained_volumes: BTreeSet<String>,
}

fn require(ok: bool) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn decode(bytes: &[u8]) -> Result<Value, String> {
    require(!bytes.is_empty() && bytes.len() <= 2 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    // Native writers use compact JSON. This also rejects duplicate keys rather
    // than accepting a last-value-wins reinterpretation of an operation.
    require(serde_json::to_vec(&value).map_err(|_| REFUSED)? == bytes)?;
    Ok(value)
}

fn fields(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && object.keys().all(|key| expected.contains(&key.as_str()))
    })
}

/// Validate exact owner inputs and operation bytes. The context must come from
/// the current authenticated SavedSession loader, never caller-supplied JSON.
pub(crate) fn validate_down(
    context: DownContext,
    intent_bytes: &[u8],
    result_bytes: &[u8],
) -> Result<DownEvidence, String> {
    let intent = decode(intent_bytes)?;
    let result = decode(result_bytes)?;
    require(
        fields(
            &intent,
            &[
                "schema",
                "project",
                "engine_id",
                "configuration_sha256",
                "input_files",
                "command",
                "prior_resources",
                "selected_services",
                "automatic_retry",
                "installation_ready",
            ],
        ) && fields(
            &result,
            &[
                "schema",
                "project",
                "engine_id",
                "operation",
                "configuration_sha256",
                "input_files",
                "command_succeeded",
                "client_exit_code",
                "failure_class",
                "observation_validated",
                "resources",
                "status",
                "installation_ready",
            ],
        ),
    )?;
    require(
        intent["schema"] == "elevenid.installer-compose-intent/v1"
            && intent["project"] == context.project
            && intent["engine_id"] == context.engine_id
            && intent["configuration_sha256"] == context.configuration_sha256
            && intent["input_files"] == context.input_files
            && intent["prior_resources"] == context.prior_resources
            && intent["command"] == json!(["down", "--timeout", "60"])
            && intent["selected_services"] == json!([])
            && intent["automatic_retry"] == false
            && intent["installation_ready"] == false
            && result["schema"] == "elevenid.installer-compose-operation/v1"
            && result["project"] == context.project
            && result["engine_id"] == context.engine_id
            && result["operation"] == OPERATION
            && result["configuration_sha256"] == context.configuration_sha256
            && result["input_files"] == context.input_files
            && result["command_succeeded"] == true
            && result["client_exit_code"] == 0
            && result["failure_class"].is_null()
            && result["observation_validated"] == true
            && result["installation_ready"] == false
            && result["status"] == json!([]),
    )?;
    require(fields(
        &context.prior_resources,
        &["containers", "networks", "volumes"],
    ))?;
    let retained_volumes: BTreeSet<String> =
        serde_json::from_value(context.prior_resources["volumes"].clone()).map_err(|_| REFUSED)?;
    require(
        result["resources"]
            == json!({
                "containers": {}, "networks": {}, "volumes": retained_volumes,
            }),
    )?;
    Ok(DownEvidence {
        intent_sha256: crate::installer_release::sha256(intent_bytes),
        result_sha256: crate::installer_release::sha256(result_bytes),
        selected_session_sha256: context.selected_session_sha256,
        prior_resources: context.prior_resources,
        retained_volumes,
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct CurrentCleanup {
    pub selected: crate::installer_doctor::SavedSession,
    pub evidence: DownEvidence,
}

/// Uses the current generation/session owner and descriptor-bound private
/// evidence APIs. Repeats all owner/byte checks before returning the snapshot.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_current(
    locked: &crate::installer_state::LockedInspection,
    installation: &std::path::Path,
) -> Result<CurrentCleanup, String> {
    let inspect = || -> Result<_, String> {
        locked.require_path_binding(installation)?;
        locked.require_unchanged()?;
        let status = crate::installer_uninstall::status(locked)?;
        require(
            status["operations"]["down"] == "completed"
                && status["next_operations"]["down"] == "down-0002"
                && status["pending_operations"]
                    .as_object()
                    .is_some_and(|pending| pending.is_empty()),
        )?;
        let selected = crate::installer_doctor::load_session(locked, installation)?;
        require(
            selected.schema == "elevenid.installer-compose-session/v1"
                && selected.installation_id == locked.journal().installation_id().to_string()
                && selected.inputs.project == locked.journal().compose_project()
                && selected.inputs.services.is_empty(),
        )?;
        let intent = locked.diagnostic_record(INTENT, true)?.ok_or(REFUSED)?;
        let result = locked.diagnostic_record(RESULT, true)?.ok_or(REFUSED)?;
        let snapshot = serde_json::to_value(&selected).map_err(|_| REFUSED)?;
        Ok((selected, intent, result, snapshot, status))
    };
    let (selected, intent_bytes, result_bytes, snapshot, status) =
        inspect().map_err(|_| REFUSED)?;
    let evidence = validate_down(
        DownContext {
            project: selected.inputs.project.clone(),
            engine_id: selected.receipt.engine_id.clone(),
            configuration_sha256: selected.configuration_sha256.clone(),
            input_files: serde_json::to_value(&selected.receipt.input_files)
                .map_err(|_| REFUSED)?,
            prior_resources: serde_json::to_value(
                selected.receipt.resources.as_ref().ok_or(REFUSED)?,
            )
            .map_err(|_| REFUSED)?,
            selected_session_sha256: crate::installer_release::sha256(
                &serde_json::to_vec(&snapshot).map_err(|_| REFUSED)?,
            ),
        },
        &intent_bytes,
        &result_bytes,
    )?;
    let (_, latest_intent, latest_result, latest_snapshot, latest_status) =
        inspect().map_err(|_| REFUSED)?;
    require(
        latest_intent == intent_bytes
            && latest_result == result_bytes
            && latest_snapshot == snapshot
            && latest_status == status,
    )?;
    Ok(CurrentCleanup { selected, evidence })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DownContext, Value, Value) {
        let resources = json!({"containers":{"app":{"id":"synthetic-app-id"}},
            "networks":{"synthetic-project_default":"synthetic-network-id"},
            "volumes":["synthetic-project_data", "synthetic-project_socket"]});
        let inputs = json!({"/synthetic/evidence/application.env":"a".repeat(64)});
        let context = DownContext {
            project: "synthetic-project".into(),
            engine_id: "synthetic-engine".into(),
            configuration_sha256: "b".repeat(64),
            input_files: inputs.clone(),
            prior_resources: resources.clone(),
            selected_session_sha256: "c".repeat(64),
        };
        let intent = json!({"schema":"elevenid.installer-compose-intent/v1", "project":context.project,
            "engine_id":context.engine_id,"configuration_sha256":context.configuration_sha256,
            "input_files":inputs,"command":["down","--timeout","60"],"prior_resources":resources,
            "selected_services":[],"automatic_retry":false,"installation_ready":false});
        let result = json!({"schema":"elevenid.installer-compose-operation/v1", "project":context.project,
            "engine_id":context.engine_id,"configuration_sha256":context.configuration_sha256,
            "input_files":context.input_files,"operation":"down-0001","command_succeeded":true,
            "client_exit_code":0,"failure_class":null,"observation_validated":true,"resources":{
                "containers":{},"networks":{},"volumes":["synthetic-project_data","synthetic-project_socket"]},
            "status":[],"installation_ready":false});
        (context, intent, result)
    }

    #[test]
    fn exact_down_preserves_dynamic_retained_volume_scope_and_byte_hashes() {
        let (context, intent, result) = fixture();
        let intent = serde_json::to_vec(&intent).unwrap();
        let result = serde_json::to_vec(&result).unwrap();
        let evidence = validate_down(context, &intent, &result).unwrap();
        assert_eq!(
            evidence.intent_sha256,
            crate::installer_release::sha256(&intent)
        );
        assert_eq!(
            evidence.result_sha256,
            crate::installer_release::sha256(&result)
        );
        assert_eq!(evidence.retained_volumes.len(), 2);
        assert_eq!(
            evidence.prior_resources["containers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(evidence.selected_session_sha256, "c".repeat(64));
    }

    #[test]
    fn mismatched_unknown_or_uncertain_operation_fields_are_refused() {
        for field in [
            "schema",
            "project",
            "engine_id",
            "operation",
            "configuration_sha256",
            "input_files",
            "command_succeeded",
            "client_exit_code",
            "failure_class",
            "observation_validated",
            "resources",
            "status",
            "installation_ready",
            "unknown",
        ] {
            let (context, intent, mut result) = fixture();
            result[field] = json!("invalid-or-private-canary");
            assert!(
                validate_down(
                    context,
                    &serde_json::to_vec(&intent).unwrap(),
                    &serde_json::to_vec(&result).unwrap()
                )
                .is_err(),
                "{field}"
            );
        }
        for field in [
            "project",
            "engine_id",
            "configuration_sha256",
            "input_files",
            "prior_resources",
            "selected_services",
            "automatic_retry",
            "installation_ready",
            "unknown",
        ] {
            let (context, mut intent, result) = fixture();
            intent[field] = json!("invalid");
            assert!(
                validate_down(
                    context,
                    &serde_json::to_vec(&intent).unwrap(),
                    &serde_json::to_vec(&result).unwrap()
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn destructive_or_selected_commands_and_ambiguous_json_are_refused() {
        for command in [
            json!(["down", "--volumes"]),
            json!(["stop", "--timeout", "60"]),
            json!(["down", "--remove-orphans", "--timeout", "60"]),
        ] {
            let (context, mut intent, result) = fixture();
            intent["command"] = command;
            assert!(validate_down(
                context,
                &serde_json::to_vec(&intent).unwrap(),
                &serde_json::to_vec(&result).unwrap()
            )
            .is_err());
        }
        let (context, intent, result) = fixture();
        let bytes = serde_json::to_vec(&intent).unwrap();
        let mut duplicate = b"{\"automatic_retry\":false,".to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        assert!(validate_down(context, &duplicate, &serde_json::to_vec(&result).unwrap()).is_err());
    }
}
