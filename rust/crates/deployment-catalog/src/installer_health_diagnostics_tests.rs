use super::*;
use crate::installer_health::{
    load, native_rows, require, same_runtime_states, save,
    tests::{fixture, native_fixture},
    CHECKPOINT, INITIALIZED,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt},
};

fn retained(path: &std::path::Path, id: uuid::Uuid) -> Value {
    for slot in 1..=MAX_RECORDS {
        if let Ok(bytes) = fs::read(
            path.join("evidence")
                .join(format!("health-refusal-{slot:04}.json")),
        ) {
            assert!(bytes.len() <= MAX_BYTES);
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            if value["health_invocation_id"] == id.to_string() {
                return value;
            }
        }
    }
    panic!("invocation diagnostic was not retained");
}

#[test]
fn native_drift_retains_the_failed_invocation_views_without_advancing_checkpoint() {
    let (_parent, path, mut state, mut checkpoint) = fixture();
    let mut prior = None;
    save(&mut state, &mut checkpoint, &mut prior).unwrap();
    let checkpoint_before = fs::read(path.join("evidence").join(CHECKPOINT)).unwrap();
    let initial_before = fs::read(path.join("evidence").join(INITIALIZED)).unwrap();
    let (resources, before) = native_fixture();
    let mut after = before.clone();
    after[0]["Health"] = json!("unhealthy");
    after[0]["Status"] = json!("PRIVATE-UNTRUSTED-HEALTH-LOG");
    let mut trace = Trace::new(&state, true);
    let id = trace.health_invocation_id;
    trace.resources(&resources, false);
    trace.native(&resources, &before, false);
    let (loaded, _) = load(&mut state, Some(&mut trace)).unwrap();
    trace.checkpoint_sequence = Some(loaded.sequence);
    trace.checkpoint_observed_at = Some(loaded.observed_at);
    trace.resources(&resources, true);
    trace.native(&resources, &after, true);
    trace.stage = "validate_native_after";
    let error = require(
        same_runtime_states(
            &native_rows(&resources, &before).unwrap(),
            &native_rows(&resources, &after).unwrap(),
        ),
        Reason::NativeStateChanged,
    )
    .unwrap_err();
    let message = trace.failure(&mut state, error);
    assert!(message.contains("reason=native_state_changed"));
    assert!(message.ends_with("diagnostic=evidence/health-refusal-0001.json"));
    let record = retained(&path, id);
    assert_eq!(record["schema"], "elevenid.installer-health-refusal/v1");
    assert_eq!(record["reason"], "native_state_changed");
    assert_eq!(record["stage"], "validate_native_after");
    assert_eq!(record["scope"], "infrastructure");
    assert_eq!(record["native_before"]["rows"][0]["health"], "healthy");
    assert_eq!(record["native_after"]["rows"][0]["health"], "unhealthy");
    assert_eq!(
        record["resources_before"]["sha256"],
        record["resources_after"]["sha256"]
    );
    assert_eq!(
        record["checkpoint_inputs"][0]["sha256"],
        installer_release::sha256(&checkpoint_before)
    );
    assert_eq!(record["checkpoint_sequence"], checkpoint.sequence);
    assert!(!record.to_string().contains("PRIVATE-UNTRUSTED-HEALTH-LOG"));
    assert_eq!(
        fs::read(path.join("evidence").join(CHECKPOINT)).unwrap(),
        checkpoint_before
    );
    assert_eq!(
        fs::read(path.join("evidence").join(INITIALIZED)).unwrap(),
        initial_before
    );
    let evidence_path = path.join("evidence").join("health-refusal-0001.json");
    let metadata = fs::metadata(evidence_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

#[test]
fn setup_refusal_retains_only_observed_predicates_and_no_invented_after_view() {
    let (_parent, path, mut state, _checkpoint) = fixture();
    let (mut resources, mut values) = native_fixture();
    resources
        .containers
        .get_mut("migration")
        .unwrap()
        .setup_execution
        .as_mut()
        .unwrap()
        .completed_without_restart = false;
    values[1]["HealthLog"] = json!({"Output":"secret-token-and-private-key"});
    let mut trace = Trace::new(&state, false);
    trace.resources(&resources, false);
    trace.native(&resources, &values, false);
    trace.stage = "validate_native_before";
    let id = trace.health_invocation_id;
    let error = native_rows(&resources, &values).unwrap_err();
    trace.failure(&mut state, error);
    let record = retained(&path, id);
    assert_eq!(record["reason"], "native_setup_history");
    assert_eq!(record["native_before"]["rows"][1]["state"], "exited");
    assert_eq!(record["native_before"]["rows"][1]["exit_code"], 0);
    assert_eq!(
        record["resources_before"]["containers"][1]["completed_without_restart"],
        false
    );
    assert!(record["native_after"].is_null());
    assert!(record["resources_after"].is_null());
    assert!(record["checkpoint_sequence"].is_null());
    assert!(!record.to_string().contains("secret-token-and-private-key"));
}

#[test]
fn untrusted_native_values_and_excess_rows_cannot_expand_or_inject_diagnostics() {
    let (_parent, path, mut state, _checkpoint) = fixture();
    let (mut resources, _) = native_fixture();
    let secret = "PRIVATE-ENVIRONMENT-AND-CREDENTIAL-MATERIAL".repeat(100);
    resources.containers.get_mut("gateway").unwrap().image = secret.clone();
    resources
        .containers
        .get_mut("migration")
        .unwrap()
        .setup_execution
        .as_mut()
        .unwrap()
        .started_at = secret.clone();
    let mut rows = Vec::new();
    for position in 0..(MAX_ROWS + 10) {
        rows.push(
            json!({"Service":if position == 0 { "gateway" } else { secret.as_str() },
            "ID":secret,"State":secret,"Health":secret,"ExitCode":secret,
            "Env":{"TOKEN":secret},"HealthLog":[secret],"Labels":secret}),
        );
    }
    let mut trace = Trace::new(&state, true);
    let id = trace.health_invocation_id;
    trace.resources(&resources, false);
    trace.resources(&resources, true);
    trace.native(&resources, &rows, false);
    trace.native(&resources, &rows, true);
    trace.failure(&mut state, Failure::Guard(Reason::NativeRoleUnknown));
    let record = retained(&path, id);
    let serialized = record.to_string();
    assert!(!serialized.contains("PRIVATE-ENVIRONMENT-AND-CREDENTIAL-MATERIAL"));
    assert!(!serialized.contains("HealthLog"));
    assert!(!serialized.contains("TOKEN"));
    assert_eq!(record["native_before"]["row_count"], MAX_ROWS + 10);
    assert_eq!(record["native_before"]["omitted_rows"], 10);
    assert_eq!(
        record["native_before"]["rows"].as_array().unwrap().len(),
        MAX_ROWS
    );
    assert_eq!(record["native_before"]["rows"][0]["service"], "gateway");
    assert!(record["native_before"]["rows"][1]["service"].is_null());
    assert!(record["native_before"]["rows"][0]["container_id"].is_null());
    assert_eq!(record["native_before"]["rows"][0]["state"], "unrecognized");
    assert_eq!(record["native_before"]["rows"][0]["health"], "unrecognized");
    assert!(record["native_before"]["rows"][0]["exit_code"].is_null());
}

#[test]
fn unsafe_diagnostic_slots_preserve_the_primary_error_and_never_replace_evidence() {
    for link in [false, true] {
        let (_parent, path, mut state, _checkpoint) = fixture();
        let trace = Trace::new(&state, true);
        let name = "health-refusal-0001.json";
        let evidence = path.join("evidence");
        let original = b"original immutable evidence";
        if link {
            fs::write(evidence.join("original.json"), original).unwrap();
            symlink("original.json", evidence.join(name)).unwrap();
        } else {
            fs::write(evidence.join(name), original).unwrap();
        }
        let primary = "operation owner's original error";
        assert_eq!(
            trace.failure(&mut state, Failure::Operation(primary.into())),
            format!("{primary}; diagnostic=unavailable(reason=unsafe_slot)")
        );
        assert_eq!(fs::read(evidence.join(name)).unwrap(), original);
        assert!(!evidence.join("health-refusal-0002.json").exists());
    }
}

#[test]
fn repeated_failures_bound_lifetime_storage_and_preserve_the_earliest_invocation() {
    let (_parent, path, mut state, mut checkpoint) = fixture();
    let mut prior = None;
    save(&mut state, &mut checkpoint, &mut prior).unwrap();
    let evidence = path.join("evidence");
    let original_checkpoint = fs::read(evidence.join(CHECKPOINT)).unwrap();
    let mut first = Vec::new();
    for slot in 1..=(MAX_RECORDS + 5) {
        let trace = Trace::new(&state, true);
        let id = trace.health_invocation_id;
        let message = trace.failure(&mut state, Failure::Guard(Reason::NativeStateChanged));
        assert!(message.contains("reason=native_state_changed"));
        if slot <= MAX_RECORDS {
            assert!(message.ends_with(&format!(
                "diagnostic=evidence/health-refusal-{slot:04}.json"
            )));
            assert_eq!(retained(&path, id)["health_invocation_id"], id.to_string());
        } else {
            assert!(message.ends_with("diagnostic=unavailable(reason=retention_limit)"));
        }
        if slot == 1 {
            first = fs::read(evidence.join("health-refusal-0001.json")).unwrap();
        }
    }
    assert_eq!(
        fs::read(evidence.join("health-refusal-0001.json")).unwrap(),
        first
    );
    assert_eq!(
        fs::read(evidence.join(CHECKPOINT)).unwrap(),
        original_checkpoint
    );
    let records = fs::read_dir(&evidence)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("health-refusal-")
                .then_some(entry)
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), MAX_RECORDS);
    assert!(
        records
            .iter()
            .map(|entry| entry.metadata().unwrap().len())
            .sum::<u64>()
            <= (MAX_RECORDS * MAX_BYTES) as u64
    );
    assert!(!evidence.join("health-refusal-0033.json").exists());
    state.require_unchanged().unwrap();
}

#[test]
fn failure_records_are_independent_and_do_not_include_underlying_error_text() {
    let (_parent, path, mut state, _checkpoint) = fixture();
    let first = Trace::new(&state, true);
    let first_id = first.health_invocation_id;
    first.failure(&mut state, Failure::Guard(Reason::NativeSetupState));
    let first_record = retained(&path, first_id);
    let second = Trace::new(&state, true);
    let second_id = second.health_invocation_id;
    assert_ne!(first_id, second_id);
    let message = second.failure(&mut state, Failure::Operation("backend-body-secret".into()));
    assert!(message.starts_with("backend-body-secret; diagnostic=evidence/"));
    let second_record = retained(&path, second_id);
    assert_eq!(second_record["reason"], "operation_boundary");
    assert!(!second_record.to_string().contains("backend-body-secret"));
    assert_eq!(retained(&path, first_id), first_record);
}

#[test]
fn invocation_identity_accepts_only_exact_ids_and_this_installations_units() {
    let installation = uuid::Uuid::new_v4();
    let id = uuid::Uuid::new_v4().simple().to_string();
    assert_eq!(systemd_invocation(Some(&id)), Some(id.clone()));
    for value in [
        None,
        Some("TOKEN=secret"),
        Some("00000000000000000000000000000000"),
        Some("BAD-BAD"),
    ] {
        assert_eq!(systemd_invocation(value), None);
    }
    for suffix in ["", "-check", "-maintenance"] {
        let unit = format!("lifecycle-marty-{installation}{suffix}.service");
        let cgroup = format!("0::/user.slice/user@1001.service/app.slice/{unit}\n");
        assert_eq!(unit_name(Some(&cgroup), installation), Some(unit));
    }
    assert_eq!(
        unit_name(Some("0::/private-token.service"), installation),
        None
    );
    let foreign = format!("0::/lifecycle-marty-{}.service", uuid::Uuid::new_v4());
    assert_eq!(unit_name(Some(&foreign), installation), None);
    let ambiguous = format!(
        "0::/lifecycle-marty-{installation}.service/lifecycle-marty-{installation}-check.service"
    );
    assert_eq!(unit_name(Some(&ambiguous), installation), None);
}

#[test]
fn invalid_checkpoint_json_retains_hashes_without_echoing_record_contents() {
    let secret = br#"{"sequence":1,"sequence":2,"roles":{"TOKEN":"PRIVATE-CHECKPOINT"}}"#;
    let record = Record::capture(CHECKPOINT, Some(secret));
    let value = serde_json::to_value(record).unwrap();
    assert_eq!(value["sha256"], installer_release::sha256(secret));
    assert_eq!(value["bytes"], secret.len());
    assert_eq!(value["json_object_parsed"], false);
    assert!(value["sequence"].is_null());
    assert!(!value.to_string().contains("PRIVATE-CHECKPOINT"));
    assert!(!value.to_string().contains("TOKEN"));
}
