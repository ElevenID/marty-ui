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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Bounded health recovery refused; preserve the health checkpoint and native operation evidence";
const CHECKPOINT: &str = "health-checkpoint.json";
const PENDING: &str = "health-checkpoint-next.json";
const INITIALIZED: &str = "health-initialized.json";
const SUSTAINED: u64 = 600;
const COOLDOWN: u64 = 1800;
const WINDOW: u64 = 86400;
const INFRASTRUCTURE: [&str; 3] = ["openbao", "openbao-unseal", "installer-acme-http01"];

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
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
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(bytes.len() <= 262144)?;
    serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
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
        checkpoint.schema == "elevenid.installer-health-checkpoint/v1"
            && checkpoint.installation_id == state.journal().installation_id()
            && checkpoint.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
            && checkpoint.project == state.journal().compose_project()
            && checkpoint.sequence > 0
            && (checkpoint.sequence == 1) == checkpoint.previous_sha256.is_none()
            && checkpoint
                .previous_sha256
                .as_ref()
                .is_none_or(|value| digest(value))
            && checkpoint.roles.len() <= 128,
    )?;
    for (name, role) in &checkpoint.roles {
        require(
            role_name(name)
                && digest(&role.container_id)
                && role
                    .unhealthy_since
                    .is_none_or(|at| at <= checkpoint.observed_at)
                && role.attempts.len() <= 2,
        )?;
        let mut previous = None;
        for attempt in &role.attempts {
            let id = attempt.operation.strip_prefix("repair-").ok_or(REFUSED)?;
            require(
                uuid::Uuid::parse_str(id).is_ok_and(|id| id.to_string() == attempt.operation[7..])
                    && attempt.started_at <= checkpoint.observed_at
                    && previous.is_none_or(|prior| prior <= attempt.started_at),
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
            && initial.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
            && digest(&initial.first_checkpoint_sha256),
    )?;
    Ok(initial)
}

fn initialize(state: &mut LockedMaintenance, first: &[u8]) -> Result<()> {
    let expected = Initial {
        schema: "elevenid.installer-health-initialized/v1".into(),
        installation_id: state.journal().installation_id(),
        engine_id: state.journal().runtime().ok_or(REFUSED)?.engine_id.clone(),
        first_checkpoint_sha256: installer_release::sha256(first),
    };
    let bytes = encode(&expected)?;
    if let Some(existing) = state.read_evidence(INITIALIZED)? {
        require(existing == bytes)
    } else {
        state.write_evidence_exclusive(INITIALIZED, &bytes)
    }
}

/// Only an exact pending successor can complete a lost atomic publication.
/// The checkpoint is bounded; successful no-op timer runs create no history
/// files. Rare native restart attempts retain their own immutable receipts.
fn load(state: &mut LockedMaintenance) -> Result<(Checkpoint, Option<Vec<u8>>)> {
    let mut current = state.read_evidence(CHECKPOINT)?;
    let initial = state.read_evidence(INITIALIZED)?;
    if let Some(bytes) = &initial {
        validate_initial(bytes, state.inspection())?;
    }
    if let Some(pending) = state.read_evidence(PENDING)? {
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
                    .map(|bytes| installer_release::sha256(bytes))
                && next.sequence
                    == prior
                        .as_ref()
                        .map_or(Some(1), |prior| prior.sequence.checked_add(1))
                        .ok_or(REFUSED)?
                && prior
                    .as_ref()
                    .is_none_or(|prior| next.observed_at >= prior.observed_at),
        )?;
        if current.is_none() {
            initialize(state, &pending)?;
        } else {
            require(initial.is_some())?;
        }
        state.publish_health_checkpoint(current.as_deref(), &pending)?;
        current = Some(pending);
    }
    if let Some(bytes) = &current {
        let checkpoint: Checkpoint = decode(bytes)?;
        validate(&checkpoint, state.inspection())?;
        let initial = validate_initial(
            &state.read_evidence(INITIALIZED)?.ok_or(REFUSED)?,
            state.inspection(),
        )?;
        require(
            checkpoint.sequence != 1
                || initial.first_checkpoint_sha256 == installer_release::sha256(bytes),
        )?;
        return Ok((checkpoint, current));
    }
    require(initial.is_none())?;
    Ok((
        Checkpoint {
            schema: "elevenid.installer-health-checkpoint/v1".into(),
            installation_id: state.journal().installation_id(),
            engine_id: state.journal().runtime().ok_or(REFUSED)?.engine_id.clone(),
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
    checkpoint.sequence = checkpoint.sequence.checked_add(1).ok_or(REFUSED)?;
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
        let name = row["Service"].as_str().ok_or(REFUSED)?;
        let container = resources.containers.get(name).ok_or(REFUSED)?;
        require(row["ID"] == container.id && result.insert(name.into(), row).is_none())?;
        if container.setup {
            require(
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && container
                        .setup_execution
                        .as_ref()
                        .is_some_and(|execution| execution.completed_without_restart),
            )?;
        }
    }
    require(result.len() == resources.containers.len())?;
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
    let dependencies = dependencies.as_object().ok_or(REFUSED)?;
    let mut blocked = Vec::new();
    for (dependency, condition) in dependencies {
        require(role_name(dependency))?;
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

pub(crate) fn reconcile_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<Value> {
    reconcile(installation, docker, state, false)
}
pub(crate) fn reconcile_infrastructure_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<Value> {
    reconcile(installation, docker, state, true)
}
fn reconcile(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    infrastructure_only: bool,
) -> Result<Value> {
    state.inspection().require_path_binding(installation)?;
    let (saved, session) =
        installer_doctor::open_session(state.inspection(), installation, docker)?;
    let resources = session.observe_resources()?;
    let values = session.status()?;
    let rows = native_rows(&resources, &values)?;
    let (mut checkpoint, mut prior) = load(state)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    require(now >= checkpoint.observed_at)?;
    checkpoint.observed_at = now;
    let mut unhealthy = Vec::new();
    let mut selected = None;
    let mut present = BTreeSet::new();
    for (name, container) in &resources.containers {
        if container.setup {
            continue;
        }
        present.insert(name.clone());
        let row = rows.get(name).ok_or(REFUSED)?;
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
        let dependencies = blocked_dependencies(&saved.model, name, &rows)?;
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
            .ok_or(REFUSED)?
            .attempts
            .push(Attempt {
                operation: operation.clone().ok_or(REFUSED)?,
                started_at: now,
                outcome: Outcome::IntentRecorded,
            });
    }
    require(session.observe_resources()? == resources)?;
    // Compose also emits human-readable age/status strings. Those may change
    // between two observations without any native state transition.
    let after_values = session.status()?;
    let after_rows = native_rows(&resources, &after_values)?;
    require(same_runtime_states(&rows, &after_rows))?;
    state.inspection().require_path_binding(installation)?;
    save(state, &mut checkpoint, &mut prior)?;
    let mut repair = Value::Null;
    if let Some(role) = selected {
        let operation = operation.ok_or(REFUSED)?;
        let mut inputs = saved.inputs.clone();
        inputs.profiles.clear();
        inputs.services = vec![role.clone()];
        let runtime =
            ComposeSession::new(docker, state.journal().runtime().ok_or(REFUSED)?, inputs)?;
        let outcome = runtime.restart_owned_unhealthy(state, &operation, Duration::from_secs(120));
        let observed = if outcome.is_ok() {
            Outcome::HealthyObserved
        } else {
            Outcome::FailedOrUnconfirmed
        };
        checkpoint
            .roles
            .get_mut(&role)
            .ok_or(REFUSED)?
            .attempts
            .last_mut()
            .ok_or(REFUSED)?
            .outcome = observed.clone();
        state.require_unchanged()?;
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
