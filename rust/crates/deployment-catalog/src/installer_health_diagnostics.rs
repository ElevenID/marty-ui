//! Failure-only, bounded projections of the observations used by the health
//! owner. Never serialize a native row, inspect body, or underlying error.

use super::{digest, role_name, REFUSED};
use crate::{
    installer_compose::ProjectResources, installer_json, installer_release,
    installer_state::LockedMaintenance,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_ROWS: usize = 128;
const MAX_BYTES: usize = 262144;
const MAX_RECORDS: usize = 32;

fn now_millis() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|v| v.as_millis())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    RuntimeBindingMissing,
    RecordTooLarge,
    RecordJsonInvalid,
    RecordEncoding,
    CheckpointSchema,
    CheckpointInstallation,
    CheckpointEngine,
    CheckpointProject,
    CheckpointSequence,
    CheckpointPredecessor,
    CheckpointRoleLimit,
    CheckpointRoleName,
    CheckpointContainerId,
    CheckpointClock,
    CheckpointAttemptLimit,
    CheckpointAttemptId,
    CheckpointAttemptClock,
    InitialBinding,
    InitialConflict,
    InitialMissing,
    InitialCheckpointMismatch,
    CheckpointMissing,
    NativeRoleInvalid,
    NativeRoleUnknown,
    NativeContainerIdentity,
    NativeRoleDuplicate,
    NativeSetupState,
    NativeSetupExit,
    NativeSetupHistory,
    NativeInventoryIncomplete,
    DependencyModel,
    DependencyRole,
    ObservationClock,
    ResourceSetChanged,
    NativeStateChanged,
    RepairSelection,
    OperationBoundary,
}

impl Reason {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::RuntimeBindingMissing => "runtime_binding_missing",
            Self::RecordTooLarge => "record_too_large",
            Self::RecordJsonInvalid => "record_json_invalid",
            Self::RecordEncoding => "record_encoding",
            Self::CheckpointSchema => "checkpoint_schema",
            Self::CheckpointInstallation => "checkpoint_installation",
            Self::CheckpointEngine => "checkpoint_engine",
            Self::CheckpointProject => "checkpoint_project",
            Self::CheckpointSequence => "checkpoint_sequence",
            Self::CheckpointPredecessor => "checkpoint_predecessor",
            Self::CheckpointRoleLimit => "checkpoint_role_limit",
            Self::CheckpointRoleName => "checkpoint_role_name",
            Self::CheckpointContainerId => "checkpoint_container_id",
            Self::CheckpointClock => "checkpoint_clock",
            Self::CheckpointAttemptLimit => "checkpoint_attempt_limit",
            Self::CheckpointAttemptId => "checkpoint_attempt_id",
            Self::CheckpointAttemptClock => "checkpoint_attempt_clock",
            Self::InitialBinding => "initial_binding",
            Self::InitialConflict => "initial_conflict",
            Self::InitialMissing => "initial_missing",
            Self::InitialCheckpointMismatch => "initial_checkpoint_mismatch",
            Self::CheckpointMissing => "checkpoint_missing",
            Self::NativeRoleInvalid => "native_role_invalid",
            Self::NativeRoleUnknown => "native_role_unknown",
            Self::NativeContainerIdentity => "native_container_identity",
            Self::NativeRoleDuplicate => "native_role_duplicate",
            Self::NativeSetupState => "native_setup_state",
            Self::NativeSetupExit => "native_setup_exit",
            Self::NativeSetupHistory => "native_setup_history",
            Self::NativeInventoryIncomplete => "native_inventory_incomplete",
            Self::DependencyModel => "dependency_model",
            Self::DependencyRole => "dependency_role",
            Self::ObservationClock => "observation_clock",
            Self::ResourceSetChanged => "resource_set_changed",
            Self::NativeStateChanged => "native_state_changed",
            Self::RepairSelection => "repair_selection",
            Self::OperationBoundary => "operation_boundary",
        }
    }
}

#[derive(Debug)]
pub(super) enum Failure {
    Guard(Reason),
    // Preserve the operation owner's ordinary error for its caller. Its text
    // never becomes diagnostic evidence, even when that owner is unavailable.
    Operation(String),
}
impl From<Reason> for Failure {
    fn from(reason: Reason) -> Self {
        Self::Guard(reason)
    }
}
impl From<String> for Failure {
    fn from(error: String) -> Self {
        Self::Operation(error)
    }
}
impl Failure {
    fn reason(&self) -> Reason {
        match self {
            Self::Guard(reason) => *reason,
            Self::Operation(_) => Reason::OperationBoundary,
        }
    }
    pub(super) fn message(&self) -> String {
        match self {
            Self::Guard(reason) => format!("{REFUSED} (reason={})", reason.code()),
            Self::Operation(error) => error.clone(),
        }
    }
}

#[derive(Serialize)]
struct Record {
    name: &'static str,
    present: bool,
    bytes: usize,
    sha256: Option<String>,
    json_object_parsed: bool,
    sequence: Option<u64>,
    observed_at: Option<u64>,
    previous_sha256: Option<String>,
    role_count: Option<usize>,
}
impl Record {
    fn capture(name: &'static str, bytes: Option<&[u8]>) -> Self {
        let value = bytes
            .filter(|bytes| bytes.len() <= MAX_BYTES)
            .and_then(|bytes| installer_json::decode(bytes).ok());
        let value = value.as_ref();
        Self {
            name,
            present: bytes.is_some(),
            bytes: bytes.map_or(0, <[u8]>::len),
            sha256: bytes.map(installer_release::sha256),
            json_object_parsed: value.is_some_and(Value::is_object),
            sequence: value.and_then(|v| v["sequence"].as_u64()),
            observed_at: value.and_then(|v| v["observed_at"].as_u64()),
            previous_sha256: value
                .and_then(|v| v["previous_sha256"].as_str())
                .filter(|v| digest(v))
                .map(str::to_owned),
            role_count: value.and_then(|v| v["roles"].as_object().map(|roles| roles.len())),
        }
    }
}

#[derive(Serialize)]
struct NativeRow {
    position: usize,
    service: Option<String>,
    recognized_role: bool,
    container_id: Option<String>,
    state: &'static str,
    health: &'static str,
    exit_code: Option<i64>,
}

fn state_label(value: &Value) -> &'static str {
    match value.as_str() {
        Some("created") => "created",
        Some("running") => "running",
        Some("paused") => "paused",
        Some("restarting") => "restarting",
        Some("removing") => "removing",
        Some("exited") => "exited",
        Some("dead") => "dead",
        _ if value.is_null() => "absent",
        _ => "unrecognized",
    }
}
fn health_label(value: &Value) -> &'static str {
    match value.as_str() {
        Some("healthy") => "healthy",
        Some("unhealthy") => "unhealthy",
        Some("starting") => "starting",
        Some("") => "none",
        _ if value.is_null() => "absent",
        _ => "unrecognized",
    }
}

#[derive(Serialize)]
struct NativeObservation {
    captured_at_unix_ms: Option<u128>,
    row_count: usize,
    omitted_rows: usize,
    rows: Vec<NativeRow>,
}
impl NativeObservation {
    fn capture(resources: &ProjectResources, rows: &[Value]) -> Self {
        Self {
            captured_at_unix_ms: now_millis(),
            row_count: rows.len(),
            omitted_rows: rows.len().saturating_sub(MAX_ROWS),
            rows: rows
                .iter()
                .take(MAX_ROWS)
                .enumerate()
                .map(|(position, row)| {
                    // Never echo an unknown native service name. Only names
                    // from the admitted resource inventory may be projected.
                    let service = row["Service"]
                        .as_str()
                        .filter(|name| role_name(name) && resources.containers.contains_key(*name));
                    NativeRow {
                        position,
                        service: service.map(str::to_owned),
                        recognized_role: service.is_some(),
                        container_id: row["ID"]
                            .as_str()
                            .filter(|id| digest(id))
                            .map(str::to_owned),
                        state: state_label(&row["State"]),
                        health: health_label(&row["Health"]),
                        exit_code: row["ExitCode"].as_i64(),
                    }
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Container {
    service: Option<String>,
    container_id: Option<String>,
    setup: bool,
    completed_without_restart: Option<bool>,
    health_required: bool,
}
#[derive(Serialize)]
struct Resources {
    captured_at_unix_ms: Option<u128>,
    sha256: Option<String>,
    container_count: usize,
    network_count: usize,
    volume_count: usize,
    omitted_containers: usize,
    containers: Vec<Container>,
}

fn serialized_sha256(value: &impl Serialize) -> Option<String> {
    struct Sink(Sha256);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(Sha256::new());
    serde_json::to_writer(&mut sink, value).ok()?;
    Some(format!("{:x}", sink.0.finalize()))
}
impl Resources {
    fn capture(resources: &ProjectResources) -> Self {
        Self {
            captured_at_unix_ms: now_millis(),
            sha256: serialized_sha256(resources),
            container_count: resources.containers.len(),
            network_count: resources.networks.len(),
            volume_count: resources.volumes.len(),
            omitted_containers: resources.containers.len().saturating_sub(MAX_ROWS),
            containers: resources
                .containers
                .iter()
                .take(MAX_ROWS)
                .map(|(name, container)| Container {
                    service: role_name(name).then(|| name.clone()),
                    container_id: digest(&container.id).then(|| container.id.clone()),
                    setup: container.setup,
                    completed_without_restart: container
                        .setup_execution
                        .as_ref()
                        .map(|execution| execution.completed_without_restart),
                    health_required: container.health_required,
                })
                .collect(),
        }
    }
}

fn proc_text(path: &str, limit: usize) -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= limit)
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}
fn systemd_invocation(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
                && uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil())
        })
        .map(str::to_owned)
}
fn unit_name(cgroup: Option<&str>, installation: uuid::Uuid) -> Option<String> {
    let allowed = [
        format!("lifecycle-marty-{installation}.service"),
        format!("lifecycle-marty-{installation}-check.service"),
        format!("lifecycle-marty-{installation}-maintenance.service"),
    ];
    let observed = cgroup?
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .flat_map(|path| path.split('/'))
        .filter(|segment| allowed.iter().any(|allowed| allowed == segment))
        .collect::<std::collections::BTreeSet<_>>();
    (observed.len() == 1).then(|| (*observed.first().unwrap()).to_owned())
}

#[derive(Serialize)]
pub(super) struct Trace {
    schema: &'static str,
    health_invocation_id: uuid::Uuid,
    installation_id: uuid::Uuid,
    source_sha: String,
    release_tag: Option<String>,
    release_tag_sha256: String,
    boot_id: Option<uuid::Uuid>,
    systemd_invocation_id: Option<String>,
    observed_unit: Option<String>,
    identity_observation: &'static str,
    scope: &'static str,
    started_at_unix_ms: Option<u128>,
    failed_at_unix_ms: Option<u128>,
    pub(super) stage: &'static str,
    reason: Option<Reason>,
    checkpoint_inputs: Vec<Record>,
    pub(super) checkpoint_sequence: Option<u64>,
    pub(super) checkpoint_observed_at: Option<u64>,
    pub(super) observation_unix_seconds: Option<u64>,
    resources_before: Option<Resources>,
    resources_after: Option<Resources>,
    native_before: Option<NativeObservation>,
    native_after: Option<NativeObservation>,
    observations_are_atomic: bool,
    raw_native_output_retained: bool,
}
impl Trace {
    pub(super) fn new(state: &LockedMaintenance, infrastructure: bool) -> Self {
        let installation = state.journal().installation_id();
        let identity = state.journal().identity();
        Self {
            schema: "elevenid.installer-health-refusal/v1",
            health_invocation_id: uuid::Uuid::new_v4(),
            installation_id: installation,
            source_sha: identity.source_sha.clone(),
            release_tag: (identity.release_tag.len() <= 128).then(|| identity.release_tag.clone()),
            release_tag_sha256: installer_release::sha256(identity.release_tag.as_bytes()),
            boot_id: proc_text("/proc/sys/kernel/random/boot_id", 37)
                .and_then(|value| uuid::Uuid::parse_str(value.trim()).ok()),
            systemd_invocation_id: systemd_invocation(std::env::var("INVOCATION_ID").ok().as_deref()),
            observed_unit: unit_name(proc_text("/proc/self/cgroup", 8192).as_deref(), installation),
            identity_observation: "boot_and_cgroup_from_proc; invocation_id_from_validated_environment; missing_values_are_not_inferred",
            scope: if infrastructure { "infrastructure" } else { "runtime" },
            started_at_unix_ms: now_millis(),
            failed_at_unix_ms: None,
            stage: "path_binding",
            reason: None,
            checkpoint_inputs: Vec::new(),
            checkpoint_sequence: None,
            checkpoint_observed_at: None,
            observation_unix_seconds: None,
            resources_before: None,
            resources_after: None,
            native_before: None,
            native_after: None,
            observations_are_atomic: false,
            raw_native_output_retained: false,
        }
    }
    pub(super) fn checkpoint(&mut self, name: &'static str, bytes: Option<&[u8]>) {
        // Exactly the current, initialized, and pending inputs read by load.
        if self.checkpoint_inputs.len() < 3 {
            self.checkpoint_inputs.push(Record::capture(name, bytes));
        }
    }
    pub(super) fn resources(&mut self, resources: &ProjectResources, after: bool) {
        let destination = if after {
            &mut self.resources_after
        } else {
            &mut self.resources_before
        };
        *destination = Some(Resources::capture(resources));
    }
    pub(super) fn native(&mut self, resources: &ProjectResources, rows: &[Value], after: bool) {
        let destination = if after {
            &mut self.native_after
        } else {
            &mut self.native_before
        };
        *destination = Some(NativeObservation::capture(resources, rows));
    }
    pub(super) fn failure(mut self, state: &mut LockedMaintenance, error: Failure) -> String {
        let primary = error.message();
        self.reason = Some(error.reason());
        self.failed_at_unix_ms = now_millis();
        let retained = serde_json::to_vec(&self)
            .map_err(|_| "encoding")
            .and_then(|bytes| retain(state, &bytes));
        match retained {
            Ok(name) => format!("{primary}; diagnostic=evidence/{name}"),
            // Storage exhaustion, an unsafe slot, or a poisoned writer must
            // never replace the primary refusal or authorize further work.
            Err(reason) => format!("{primary}; diagnostic=unavailable(reason={reason})"),
        }
    }
}

fn retain(state: &mut LockedMaintenance, bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("record_bound");
    }
    // A fixed append-only set also bounds lifetime growth from persistent
    // five-minute failures. Earliest records are never replaced or pruned.
    for slot in 1..=MAX_RECORDS {
        let name = format!("health-refusal-{slot:04}.json");
        if let Some(existing) = state.read_evidence(&name).map_err(|_| "unsafe_slot")? {
            let record = (existing.len() <= MAX_BYTES)
                .then(|| installer_json::decode(&existing).ok())
                .flatten()
                .ok_or("unsafe_slot")?;
            if record["schema"] != "elevenid.installer-health-refusal/v1"
                || record["installation_id"] != state.journal().installation_id().to_string()
                || !record["health_invocation_id"]
                    .as_str()
                    .is_some_and(|value| {
                        uuid::Uuid::parse_str(value)
                            .is_ok_and(|id| !id.is_nil() && id.to_string() == value)
                    })
            {
                return Err("unsafe_slot");
            }
            continue;
        }
        // No retry after a failed exclusive create: an uncertain write keeps
        // the maintenance writer poisoned under its existing custody rules.
        state
            .write_evidence_exclusive(&name, bytes)
            .map_err(|_| "write_failed")?;
        return Ok(name);
    }
    Err("retention_limit")
}

#[cfg(test)]
#[path = "installer_health_diagnostics_tests.rs"]
mod tests;
