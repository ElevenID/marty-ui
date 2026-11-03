//! Bounded repair of an owned process that remains alive but unhealthy.
//! Docker remains the owner of ordinary process-exit restart policy.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeSession, ProjectResources},
    installer_doctor, installer_json, installer_release,
    installer_state::{LockedInspection, LockedMaintenance},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "installer_health_diagnostics.rs"]
mod diagnostics;
use diagnostics::{Failure, Reason, Trace};

type Result<T> = std::result::Result<T, Failure>;
const REFUSED: &str =
    "Bounded health recovery refused; preserve the health checkpoint and native operation evidence";
const CHECKPOINT: &str = "health-checkpoint.json";
const PENDING: &str = "health-checkpoint-next.json";
const INITIALIZED: &str = "health-initialized.json";
const SUSTAINED: u64 = 600;
const COOLDOWN: u64 = 1800;
const WINDOW: u64 = 86400;
const INFRASTRUCTURE: [&str; 3] = ["openbao", "openbao-unseal", "installer-acme-http01"];
const OBSERVATION_ATTEMPTS: usize = 3;
const OBSERVATION_BUDGET: Duration = Duration::from_secs(60);

fn require(ok: bool, reason: Reason) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn role_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-' || v == b'_')
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Reason::RecordEncoding.into())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(bytes.len() <= 262144, Reason::RecordTooLarge)?;
    serde_json::from_value(installer_json::decode(bytes).map_err(|_| Reason::RecordJsonInvalid)?)
        .map_err(|_| Reason::RecordJsonInvalid.into())
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    IntentRecorded,
    HealthyObserved,
    FailedOrUnconfirmed,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Attempt {
    operation: String,
    started_at: u64,
    outcome: Outcome,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Role {
    container_id: String,
    unhealthy_since: Option<u64>,
    attempts: Vec<Attempt>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    project: String,
    sequence: u64,
    previous_sha256: Option<String>,
    observed_at: u64,
    roles: BTreeMap<String, Role>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Initial {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    first_checkpoint_sha256: String,
}

fn validate(checkpoint: &Checkpoint, state: &LockedInspection) -> Result<()> {
    require(
        checkpoint.schema == "elevenid.installer-health-checkpoint/v1",
        Reason::CheckpointSchema,
    )?;
    require(
        checkpoint.installation_id == state.journal().installation_id(),
        Reason::CheckpointInstallation,
    )?;
    require(
        checkpoint.engine_id
            == state
                .journal()
                .runtime()
                .ok_or(Reason::RuntimeBindingMissing)?
                .engine_id,
        Reason::CheckpointEngine,
    )?;
    require(
        checkpoint.project == state.journal().compose_project(),
        Reason::CheckpointProject,
    )?;
    require(
        checkpoint.sequence > 0
            && (checkpoint.sequence == 1) == checkpoint.previous_sha256.is_none(),
        Reason::CheckpointSequence,
    )?;
    require(
        checkpoint
            .previous_sha256
            .as_ref()
            .is_none_or(|value| digest(value)),
        Reason::CheckpointPredecessor,
    )?;
    require(checkpoint.roles.len() <= 128, Reason::CheckpointRoleLimit)?;
    for (name, role) in &checkpoint.roles {
        require(role_name(name), Reason::CheckpointRoleName)?;
        require(digest(&role.container_id), Reason::CheckpointContainerId)?;
        require(
            role.unhealthy_since
                .is_none_or(|at| at <= checkpoint.observed_at),
            Reason::CheckpointClock,
        )?;
        require(role.attempts.len() <= 2, Reason::CheckpointAttemptLimit)?;
        let mut previous = None;
        for attempt in &role.attempts {
            let id = attempt
                .operation
                .strip_prefix("repair-")
                .ok_or(Reason::CheckpointAttemptId)?;
            require(
                uuid::Uuid::parse_str(id).is_ok_and(|id| id.to_string() == attempt.operation[7..]),
                Reason::CheckpointAttemptId,
            )?;
            require(
                attempt.started_at <= checkpoint.observed_at
                    && previous.is_none_or(|prior| prior <= attempt.started_at),
                Reason::CheckpointAttemptClock,
            )?;
            previous = Some(attempt.started_at);
        }
    }
    Ok(())
}

fn validate_initial(bytes: &[u8], state: &LockedInspection) -> Result<Initial> {
    let initial: Initial = decode(bytes)?;
    require(
        initial.schema == "elevenid.installer-health-initialized/v1"
            && initial.installation_id == state.journal().installation_id()
            && initial.engine_id
                == state
                    .journal()
                    .runtime()
                    .ok_or(Reason::RuntimeBindingMissing)?
                    .engine_id
            && digest(&initial.first_checkpoint_sha256),
        Reason::InitialBinding,
    )?;
    Ok(initial)
}

fn initialize(state: &mut LockedMaintenance, first: &[u8]) -> Result<()> {
    let expected = Initial {
        schema: "elevenid.installer-health-initialized/v1".into(),
        installation_id: state.journal().installation_id(),
        engine_id: state
            .journal()
            .runtime()
            .ok_or(Reason::RuntimeBindingMissing)?
            .engine_id
            .clone(),
        first_checkpoint_sha256: installer_release::sha256(first),
    };
    let bytes = encode(&expected)?;
    if let Some(existing) = state.read_evidence(INITIALIZED)? {
        require(existing == bytes, Reason::InitialConflict)
    } else {
        Ok(state.write_evidence_exclusive(INITIALIZED, &bytes)?)
    }
}

/// Only an exact pending successor can complete a lost atomic publication.
/// The checkpoint is bounded; successful no-op timer runs create no history
/// files. Rare native restart attempts retain their own immutable receipts.
fn load(
    state: &mut LockedMaintenance,
    mut trace: Option<&mut Trace>,
) -> Result<(Checkpoint, Option<Vec<u8>>)> {
    let mut current = state.read_evidence(CHECKPOINT)?;
    if let Some(trace) = trace.as_deref_mut() {
        trace.checkpoint(CHECKPOINT, current.as_deref());
    }
    let initial = state.read_evidence(INITIALIZED)?;
    if let Some(trace) = trace.as_deref_mut() {
        trace.stage = "load_initialized";
        trace.checkpoint(INITIALIZED, initial.as_deref());
    }
    if let Some(bytes) = &initial {
        validate_initial(bytes, state.inspection())?;
    }
    let pending = state.read_evidence(PENDING)?;
    if let Some(trace) = trace.as_deref_mut() {
        trace.stage = "load_pending_checkpoint";
        trace.checkpoint(PENDING, pending.as_deref());
    }
    if let Some(pending) = pending {
        let next: Checkpoint = decode(&pending)?;
        validate(&next, state.inspection())?;
        let prior = current
            .as_ref()
            .map(|bytes| decode::<Checkpoint>(bytes))
            .transpose()?;
        if let Some(prior) = &prior {
            validate(prior, state.inspection())?;
        }
        require(
            next.previous_sha256
                == current
                    .as_ref()
                    .map(|bytes| installer_release::sha256(bytes)),
            Reason::CheckpointPredecessor,
        )?;
        require(
            next.sequence
                == prior
                    .as_ref()
                    .map_or(Some(1), |prior| prior.sequence.checked_add(1))
                    .ok_or(Reason::CheckpointSequence)?,
            Reason::CheckpointSequence,
        )?;
        require(
            prior
                .as_ref()
                .is_none_or(|prior| next.observed_at >= prior.observed_at),
            Reason::CheckpointClock,
        )?;
        if current.is_none() {
            initialize(state, &pending)?;
        } else {
            require(initial.is_some(), Reason::InitialMissing)?;
        }
        state.publish_health_checkpoint(current.as_deref(), &pending)?;
        current = Some(pending);
    }
    if let Some(trace) = trace {
        trace.stage = "load_checkpoint";
    }
    if let Some(bytes) = &current {
        let checkpoint: Checkpoint = decode(bytes)?;
        validate(&checkpoint, state.inspection())?;
        let initial = validate_initial(
            &state
                .read_evidence(INITIALIZED)?
                .ok_or(Reason::InitialMissing)?,
            state.inspection(),
        )?;
        require(
            checkpoint.sequence != 1
                || initial.first_checkpoint_sha256 == installer_release::sha256(bytes),
            Reason::InitialCheckpointMismatch,
        )?;
        return Ok((checkpoint, current));
    }
    require(initial.is_none(), Reason::CheckpointMissing)?;
    Ok((
        Checkpoint {
            schema: "elevenid.installer-health-checkpoint/v1".into(),
            installation_id: state.journal().installation_id(),
            engine_id: state
                .journal()
                .runtime()
                .ok_or(Reason::RuntimeBindingMissing)?
                .engine_id
                .clone(),
            project: state.journal().compose_project(),
            sequence: 0,
            previous_sha256: None,
            observed_at: 0,
            roles: BTreeMap::new(),
        },
        None,
    ))
}

fn save(
    state: &mut LockedMaintenance,
    checkpoint: &mut Checkpoint,
    prior: &mut Option<Vec<u8>>,
) -> Result<()> {
    checkpoint.sequence = checkpoint
        .sequence
        .checked_add(1)
        .ok_or(Reason::CheckpointSequence)?;
    checkpoint.previous_sha256 = prior.as_ref().map(|bytes| installer_release::sha256(bytes));
    validate(checkpoint, state.inspection())?;
    let bytes = encode(checkpoint)?;
    if prior.is_none() {
        state.write_evidence_exclusive(PENDING, &bytes)?;
        initialize(state, &bytes)?;
    }
    state.publish_health_checkpoint(prior.as_deref(), &bytes)?;
    *prior = Some(bytes);
    Ok(())
}

fn native_rows<'a>(
    resources: &ProjectResources,
    values: &'a [Value],
) -> Result<BTreeMap<String, &'a Value>> {
    let mut result = BTreeMap::new();
    for row in values {
        let name = row["Service"].as_str().ok_or(Reason::NativeRoleInvalid)?;
        let container = resources
            .containers
            .get(name)
            .ok_or(Reason::NativeRoleUnknown)?;
        require(row["ID"] == container.id, Reason::NativeContainerIdentity)?;
        require(
            result.insert(name.into(), row).is_none(),
            Reason::NativeRoleDuplicate,
        )?;
        if container.setup {
            require(row["State"] == "exited", Reason::NativeSetupState)?;
            require(row["ExitCode"] == 0, Reason::NativeSetupExit)?;
            require(
                container
                    .setup_execution
                    .as_ref()
                    .is_some_and(|execution| execution.completed_without_restart),
                Reason::NativeSetupHistory,
            )?;
        }
    }
    require(
        result.len() == resources.containers.len(),
        Reason::NativeInventoryIncomplete,
    )?;
    Ok(result)
}

fn blocked_dependencies(
    model: &Value,
    role: &str,
    rows: &BTreeMap<String, &Value>,
) -> Result<Vec<String>> {
    let Some(dependencies) = model["services"][role].get("depends_on") else {
        return Ok(vec![]);
    };
    let dependencies = dependencies.as_object().ok_or(Reason::DependencyModel)?;
    let mut blocked = Vec::new();
    for (dependency, condition) in dependencies {
        require(role_name(dependency), Reason::DependencyRole)?;
        let observed = rows.get(dependency);
        let ready = observed.is_some_and(|row| match condition["condition"].as_str() {
            Some("service_started") => row["State"] == "running",
            Some("service_healthy") => row["State"] == "running" && row["Health"] == "healthy",
            Some("service_completed_successfully") => {
                row["State"] == "exited" && row["ExitCode"] == 0
            }
            _ => false,
        });
        if !ready {
            blocked.push(dependency.clone());
        }
    }
    Ok(blocked)
}

fn eligibility(role: &Role, now: u64, dependencies: &[String]) -> &'static str {
    if !dependencies.is_empty() {
        return "dependency_unavailable";
    }
    if role
        .unhealthy_since
        .is_none_or(|since| now.saturating_sub(since) < SUSTAINED)
    {
        return "unhealthy_observation_window";
    }
    if role.attempts.len() >= 2 {
        return "daily_repair_limit";
    }
    if role
        .attempts
        .last()
        .is_some_and(|attempt| now.saturating_sub(attempt.started_at) < COOLDOWN)
    {
        return "repair_cooldown";
    }
    "eligible"
}

fn same_runtime_states(
    before: &BTreeMap<String, &Value>,
    after: &BTreeMap<String, &Value>,
) -> bool {
    before.len() == after.len()
        && before.iter().all(|(name, row)| {
            after.get(name).is_some_and(|current| {
                ["ID", "State", "Health", "ExitCode"]
                    .into_iter()
                    .all(|field| row[field] == current[field])
            })
        })
}

/// Only an uncommitted native-state observation may be repeated. Publication of
/// a new repair decision and repair execution are outside this closure. All
/// operation and other guard errors return immediately; every attempt shares the
/// same Docker observation deadline.
fn reobserve_native_states<T>(
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut observe: impl FnMut(usize) -> Result<T>,
) -> Result<T> {
    let mut attempt = 0;
    loop {
        if now() >= deadline {
            return Err("Docker inspection deadline exceeded".to_owned().into());
        }
        attempt += 1;
        match observe(attempt) {
            Err(Failure::Guard(Reason::NativeStateChanged))
                if attempt < OBSERVATION_ATTEMPTS && now() < deadline => {}
            Ok(_) if now() >= deadline => {
                return Err("Docker inspection deadline exceeded".to_owned().into());
            }
            result => return result,
        }
    }
}

fn retain_observation_resources(
    admitted: &mut Option<ProjectResources>,
    observed: &ProjectResources,
) -> Result<()> {
    match admitted {
        Some(original) => require(original == observed, Reason::ResourceSetChanged),
        None => {
            *admitted = Some(observed.clone());
            Ok(())
        }
    }
}

struct RepairDecision {
    unhealthy: Vec<Value>,
    selected: Option<String>,
    operation: Option<String>,
}

fn plan_repair(
    checkpoint: &mut Checkpoint,
    resources: &ProjectResources,
    rows: &BTreeMap<String, &Value>,
    model: &Value,
    now: u64,
    infrastructure_only: bool,
) -> Result<RepairDecision> {
    let mut unhealthy = Vec::new();
    let mut selected = None;
    let mut present = BTreeSet::new();
    for (name, container) in &resources.containers {
        if container.setup {
            continue;
        }
        present.insert(name.clone());
        let row = rows.get(name).ok_or(Reason::NativeInventoryIncomplete)?;
        let role = checkpoint.roles.entry(name.clone()).or_default();
        if role.container_id != container.id {
            role.container_id = container.id.clone();
            role.unhealthy_since = None;
        }
        role.attempts
            .retain(|attempt| now.saturating_sub(attempt.started_at) < WINDOW);
        if row["State"] != "running" || !container.health_required || row["Health"] != "unhealthy" {
            role.unhealthy_since = None;
            continue;
        }
        role.unhealthy_since.get_or_insert(now);
        let dependencies = blocked_dependencies(model, name, rows)?;
        let decision = eligibility(role, now, &dependencies);
        let in_scope = !infrastructure_only || INFRASTRUCTURE.contains(&name.as_str());
        if in_scope && decision == "eligible" && selected.is_none() {
            selected = Some(name.clone());
        }
        unhealthy.push(json!({"service":name,"since":role.unhealthy_since,
            "decision":if in_scope { decision } else { "application_reconciliation_pending" },
            "blocking_dependencies":dependencies,"attempts_in_last_day":role.attempts.len()}));
    }
    checkpoint.roles.retain(|name, _| present.contains(name));
    let operation = selected
        .as_ref()
        .map(|_| format!("repair-{}", uuid::Uuid::new_v4()));
    if let Some(role) = &selected {
        checkpoint
            .roles
            .get_mut(role)
            .ok_or(Reason::RepairSelection)?
            .attempts
            .push(Attempt {
                operation: operation.clone().ok_or(Reason::RepairSelection)?,
                started_at: now,
                outcome: Outcome::IntentRecorded,
            });
    }
    Ok(RepairDecision {
        unhealthy,
        selected,
        operation,
    })
}

struct HealthObservation {
    saved: installer_doctor::SavedSession,
    checkpoint: Checkpoint,
    prior: Option<Vec<u8>>,
    now: u64,
    decision: RepairDecision,
}

pub(crate) fn reconcile_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> std::result::Result<Value, String> {
    reconcile(installation, docker, state, false)
}
pub(crate) fn reconcile_infrastructure_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> std::result::Result<Value, String> {
    reconcile(installation, docker, state, true)
}
fn reconcile(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    infrastructure_only: bool,
) -> std::result::Result<Value, String> {
    let mut trace = Trace::new(state, infrastructure_only);
    reconcile_observed(installation, docker, state, infrastructure_only, &mut trace)
        .map_err(|error| trace.failure(state, error))
}

fn prepare_observation(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    infrastructure_only: bool,
    trace: &mut Trace,
    admitted: &mut Option<ProjectResources>,
    deadline: Instant,
) -> Result<HealthObservation> {
    state.inspection().require_path_binding(installation)?;
    trace.stage = "open_session";
    let (saved, session) = installer_doctor::open_session_with_deadline(
        state.inspection(),
        installation,
        docker,
        Some(deadline),
    )?;
    trace.stage = "observe_resources_before";
    let resources = session.observe_resources()?;
    trace.resources(&resources, false);
    retain_observation_resources(admitted, &resources)?;
    trace.stage = "observe_native_before";
    let values = session.status()?;
    trace.native(&resources, &values, false);
    trace.stage = "validate_native_before";
    let rows = native_rows(&resources, &values)?;
    trace.stage = "load_checkpoint";
    // Reload retained policy, including exact pending-publication recovery. No
    // speculative decision from a discarded observation is carried forward.
    let (mut checkpoint, prior) = load(state, Some(&mut *trace))?;
    trace.checkpoint_sequence = Some(checkpoint.sequence);
    trace.checkpoint_observed_at = Some(checkpoint.observed_at);
    trace.stage = "observation_clock";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Reason::ObservationClock)?
        .as_secs();
    trace.observation_unix_seconds = Some(now);
    require(now >= checkpoint.observed_at, Reason::ObservationClock)?;
    checkpoint.observed_at = now;
    trace.stage = "repair_eligibility";
    let decision = plan_repair(
        &mut checkpoint,
        &resources,
        &rows,
        &saved.model,
        now,
        infrastructure_only,
    )?;
    trace.stage = "observe_resources_after";
    let after_resources = session.observe_resources()?;
    trace.resources(&after_resources, true);
    require(after_resources == resources, Reason::ResourceSetChanged)?;
    // Compose also emits human-readable age/status strings. Those may change
    // between two observations without any native state transition.
    trace.stage = "observe_native_after";
    let after_values = session.status()?;
    trace.native(&resources, &after_values, true);
    trace.stage = "validate_native_after";
    let after_rows = native_rows(&resources, &after_values)?;
    require(
        same_runtime_states(&rows, &after_rows),
        Reason::NativeStateChanged,
    )?;
    Ok(HealthObservation {
        saved,
        checkpoint,
        prior,
        now,
        decision,
    })
}

fn reconcile_observed(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    infrastructure_only: bool,
    trace: &mut Trace,
) -> Result<Value> {
    let deadline = Instant::now() + OBSERVATION_BUDGET;
    let mut admitted = None;
    let HealthObservation {
        saved,
        mut checkpoint,
        mut prior,
        now,
        decision,
    } = reobserve_native_states(deadline, Instant::now, |attempt| {
        if attempt > 1 {
            // A final refusal describes one complete attempt, not mixed snapshots.
            *trace = Trace::new(state, infrastructure_only);
        }
        prepare_observation(
            installation,
            docker,
            state,
            infrastructure_only,
            trace,
            &mut admitted,
            deadline,
        )
    })?;
    let RepairDecision {
        unhealthy,
        selected,
        operation,
    } = decision;
    trace.stage = "publish_checkpoint";
    state.inspection().require_path_binding(installation)?;
    save(state, &mut checkpoint, &mut prior)?;
    let mut repair = Value::Null;
    if let Some(role) = selected {
        let operation = operation.ok_or(Reason::RepairSelection)?;
        let mut inputs = saved.inputs.clone();
        inputs.profiles.clear();
        inputs.services = vec![role.clone()];
        let runtime = ComposeSession::new(
            docker,
            state
                .journal()
                .runtime()
                .ok_or(Reason::RuntimeBindingMissing)?,
            inputs,
        )?;
        trace.stage = "repair_owned_unhealthy";
        let outcome = runtime.restart_owned_unhealthy(state, &operation, Duration::from_secs(120));
        let observed = if outcome.is_ok() {
            Outcome::HealthyObserved
        } else {
            Outcome::FailedOrUnconfirmed
        };
        checkpoint
            .roles
            .get_mut(&role)
            .ok_or(Reason::RepairSelection)?
            .attempts
            .last_mut()
            .ok_or(Reason::RepairSelection)?
            .outcome = observed.clone();
        state.require_unchanged()?;
        trace.stage = "publish_repair_outcome";
        save(state, &mut checkpoint, &mut prior)?;
        repair = json!({"service":role,"operation":operation,"outcome":observed,
            "evidence_prefix":format!("health-compose-{operation}"),"setup_replayed":false});
    }
    Ok(
        json!({"schema":"elevenid.installer-health-reconciliation/v1",
        "installation_id":checkpoint.installation_id,"observed_at":now,
        "scope":if infrastructure_only { "infrastructure" } else { "runtime" },
        "sustained_unhealthy_seconds":SUSTAINED,"cooldown_seconds":COOLDOWN,
        "per_service_repairs_per_24h":2,"maximum_repairs_this_invocation":1,
        "unhealthy_services":unhealthy,"repair":repair,"installation_ready":false}),
    )
}

#[cfg(test)]
#[path = "installer_health_tests.rs"]
mod tests;
