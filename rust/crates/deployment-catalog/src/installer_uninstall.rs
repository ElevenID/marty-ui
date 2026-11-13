//! Native Compose stop/down for a completely bound installation project.
//! No per-container scheduler, force/remove loop, orphan purge or host deletion.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeReceipt, ComposeSession, ProjectResources},
    installer_doctor::{self, SavedSession},
    installer_state::{LockedInspection, LockedMaintenance},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Compose maintenance refused or has an uncertain result; preserve the installation and native Compose operation evidence. No automatic retry or purge was attempted";
const STOP_GRACE: Duration = Duration::from_secs(60);
const START_WAIT: Duration = Duration::from_secs(720);

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

struct Arguments {
    installation: PathBuf,
    docker: PathBuf,
}
fn arguments(args: &[String]) -> Result<Arguments> {
    require(args.len().is_multiple_of(2))?;
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--docker-bin"].contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*values.get("--install-dir").ok_or(REFUSED)?);
    let docker = PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    require(installation.is_absolute() && docker.is_absolute())?;
    Ok(Arguments {
        installation,
        docker,
    })
}

/// The saved native union includes earlier completed jobs as well as the normal
/// runtime. Compose therefore owns their removal without --remove-orphans.
fn union_scope(saved: &SavedSession, resources: &ProjectResources) -> Result<()> {
    require(saved.inputs.services.is_empty())?;
    let services = saved.model["services"].as_object().ok_or(REFUSED)?;
    require(
        resources
            .containers
            .keys()
            .all(|role| services.contains_key(role)),
    )?;
    for (kind, names) in [
        (
            "networks",
            resources.networks.keys().cloned().collect::<BTreeSet<_>>(),
        ),
        ("volumes", resources.volumes.clone()),
    ] {
        let declared = saved.model[kind]
            .as_object()
            .into_iter()
            .flat_map(|m| m.values())
            .filter_map(|v| v["name"].as_str())
            .collect::<BTreeSet<_>>();
        require(names.iter().all(|name| declared.contains(name.as_str())))?;
    }
    Ok(())
}

/// Setup execution may have changed credentials or ownership. Normal Compose
/// shutdown never interrupts a setup job; uncertain bootstrap requires recovery.
fn no_active_setup(resources: &ProjectResources, rows: &[Value]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row in rows {
        let role = row["Service"].as_str().ok_or(REFUSED)?;
        let identity = resources.containers.get(role).ok_or(REFUSED)?;
        require(row["ID"] == identity.id && seen.insert(role))?;
        let state = row["State"].as_str().ok_or(REFUSED)?;
        require(["running", "created", "exited", "restarting", "paused"].contains(&state))?;
        if identity.setup {
            require(state == "exited" || state == "created")?;
        }
    }
    require(seen.len() == resources.containers.len())
}

fn unchanged(state: &LockedInspection, installation: &Path, saved: &SavedSession) -> Result<()> {
    require(
        serde_json::to_value(saved).map_err(|_| REFUSED)?
            == serde_json::to_value(installer_doctor::load_session(state, installation)?)
                .map_err(|_| REFUSED)?,
    )?;
    state.require_unchanged()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconciliation {
    schema: String,
    installation_id: uuid::Uuid,
    project: String,
    engine_id: String,
    operation: String,
    configuration_sha256: String,
    intent_sha256: String,
    result_sha256: Option<String>,
    selected_services: Vec<String>,
    resources: ProjectResources,
    previous_command_result_known: bool,
    action_replayed: bool,
    installation_ready: bool,
}

fn verify_reconciliation(
    state: &LockedInspection,
    action: &str,
    operation: &str,
    intent_bytes: &[u8],
    result_bytes: Option<&[u8]>,
    bytes: &[u8],
) -> Result<()> {
    require(["start", "stop"].contains(&action))?;
    let intent = crate::installer_json::decode(intent_bytes).map_err(|_| REFUSED)?;
    let observed: Reconciliation =
        serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let resources: ProjectResources =
        serde_json::from_value(intent["prior_resources"].clone()).map_err(|_| REFUSED)?;
    let selected: Vec<String> =
        serde_json::from_value(intent["selected_services"].clone()).map_err(|_| REFUSED)?;
    require(
        !resources.containers.is_empty()
            && resources.containers.values().all(|container| {
                !container.setup
                    || container
                        .setup_execution
                        .as_ref()
                        .is_some_and(|execution| execution.completed_without_restart)
            })
            && ((action == "stop" && selected.is_empty())
                || (action == "start"
                    && !selected.is_empty()
                    && selected.iter().collect::<BTreeSet<_>>().len() == selected.len()
                    && selected.iter().all(|role| {
                        resources
                            .containers
                            .get(role)
                            .is_some_and(|container| !container.setup)
                    }))),
    )?;
    require(
        observed.schema == "elevenid.installer-compose-idempotent-reconciliation/v1"
            && observed.installation_id == state.journal().installation_id()
            && observed.project == state.journal().compose_project()
            && observed.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
            && observed.operation == operation
            && intent["configuration_sha256"] == observed.configuration_sha256
            && observed.intent_sha256 == crate::installer_release::sha256(intent_bytes)
            && observed.result_sha256 == result_bytes.map(crate::installer_release::sha256)
            && observed.resources == resources
            && observed.selected_services == selected
            && !observed.previous_command_result_known
            && !observed.action_replayed
            && !observed.installation_ready,
    )
}

/// A partial runtime start must retain the authenticated complete model: the
/// ingress binding and every existing setup/runtime identity still need to be
/// visible even when only infrastructure is being started. Ordinary full starts
/// keep their historical runtime-only model and profile selection.
fn start_session(
    docker: &Path,
    binding: &crate::installer_state::RuntimeBinding,
    saved: &SavedSession,
    selected: Vec<String>,
    complete_model: bool,
) -> Result<ComposeSession> {
    let mut inputs = saved.inputs.clone();
    inputs.services = selected;
    if complete_model {
        let session = ComposeSession::new_runtime_recovery(docker, binding, inputs)?;
        require(
            session.model() == &saved.model
                && session.configuration_sha256() == saved.configuration_sha256,
        )?;
        Ok(session)
    } else {
        inputs.profiles.clear();
        ComposeSession::new(docker, binding, inputs)
    }
}

/// A lost start/stop response does not make those idempotent operations unsafe
/// forever. Reconstruct the exact original selection, reobserve every retained
/// identity and completed setup job, and retire only that uncertain attempt.
/// Removal and setup jobs never enter this continuation path.
fn reconcile_pending(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    saved: &SavedSession,
) -> Result<()> {
    let history = status(state.inspection())?;
    require(history["operations"]["down"] == "not_started")?;
    for action in ["start", "stop"] {
        let Some(operation) = history["pending_operations"][action].as_str() else {
            continue;
        };
        require(saved.schema != installer_doctor::FAILED_RUNTIME_SESSION_SCHEMA)?;
        let intent_bytes = state
            .read_evidence(&format!("uninstall-compose-{operation}-intent.json"))?
            .ok_or(REFUSED)?;
        let result_bytes =
            state.read_evidence(&format!("uninstall-compose-{operation}-result.json"))?;
        let intent = crate::installer_json::decode(&intent_bytes).map_err(|_| REFUSED)?;
        let selected: Vec<String> =
            serde_json::from_value(intent["selected_services"].clone()).map_err(|_| REFUSED)?;
        require(
            (action == "start" && !selected.is_empty())
                || (action == "stop" && selected.is_empty()),
        )?;
        let binding = state.journal().runtime().ok_or(REFUSED)?;
        let session = if action == "start" {
            // The immutable intent identifies which exact model was used.
            // Preserve legacy runtime-only intents; a new partial start binds
            // the saved complete model and its full retained-resource census.
            start_session(
                docker,
                binding,
                saved,
                selected.clone(),
                intent["configuration_sha256"] == saved.configuration_sha256,
            )?
        } else {
            let mut inputs = saved.inputs.clone();
            inputs.services = selected.clone();
            ComposeSession::new(docker, binding, inputs)?
        };
        if action == "start" {
            session.require_runtime_selection()?;
        }
        require(
            intent["configuration_sha256"] == session.configuration_sha256()
                && intent["input_files"]
                    == serde_json::to_value(session.input_files()).map_err(|_| REFUSED)?,
        )?;
        let resources = session.observe_resources()?;
        let prior: ProjectResources =
            serde_json::from_value(intent["prior_resources"].clone()).map_err(|_| REFUSED)?;
        require(resources == prior)?;
        union_scope(saved, &resources)?;
        no_active_setup(&resources, &session.status()?)?;
        require(session.observe_resources()? == resources)?;
        unchanged(state.inspection(), installation, saved)?;
        let observation = Reconciliation {
            schema: "elevenid.installer-compose-idempotent-reconciliation/v1".into(),
            installation_id: state.journal().installation_id(),
            project: state.journal().compose_project(),
            engine_id: state.journal().runtime().ok_or(REFUSED)?.engine_id.clone(),
            operation: operation.into(),
            configuration_sha256: session.configuration_sha256().into(),
            intent_sha256: crate::installer_release::sha256(&intent_bytes),
            result_sha256: result_bytes
                .as_deref()
                .map(crate::installer_release::sha256),
            selected_services: selected,
            resources,
            previous_command_result_known: false,
            action_replayed: false,
            installation_ready: false,
        };
        let bytes = serde_json::to_vec(&observation).map_err(|_| REFUSED)?;
        verify_reconciliation(
            state.inspection(),
            action,
            operation,
            &intent_bytes,
            result_bytes.as_deref(),
            &bytes,
        )?;
        state.write_evidence_exclusive(
            &format!("uninstall-compose-{operation}-reconciled.json"),
            &bytes,
        )?;
    }
    Ok(())
}

fn next_operation(state: &LockedInspection, action: &str) -> Result<String> {
    let history = status(state)?;
    require(
        history["operations"]
            .as_object()
            .ok_or(REFUSED)?
            .values()
            .all(|v| v != "uncertain")
            && history["operations"]["down"] == "not_started",
    )?;
    history["next_operations"][action]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| REFUSED.into())
}

fn retained(resources: &ProjectResources) -> Value {
    json!({"named_volumes":resources.volumes,"images":true,"host_data":true,
        "credentials":true,"backups_and_evidence":true,"secure_erasure_performed":false})
}

/// Read-only point-in-time preview. No intent is written and no resource changes.
pub fn plan(args: &[String]) -> Result<String> {
    preview(args).map_err(|_| REFUSED.into())
}
fn preview(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let state = LockedMaintenance::open(&args.installation)?;
    let (saved, session) =
        installer_doctor::open_session(state.inspection(), &args.installation, &args.docker)?;
    next_operation(state.inspection(), "down")?;
    let resources = session.observe_resources()?;
    union_scope(&saved, &resources)?;
    no_active_setup(&resources, &session.status()?)?;
    require(session.observe_resources()? == resources)?;
    unchanged(state.inspection(), &args.installation, &saved)?;
    serde_json::to_string(
        &json!({"schema":"elevenid.installer-compose-uninstall-preview/v1",
        "installation_id":saved.installation_id,"project":saved.inputs.project,
        "engine_id":saved.receipt.engine_id,"configuration_sha256":saved.configuration_sha256,
        "operation":"docker_compose_down","grace_seconds":STOP_GRACE.as_secs(),
        "ordinary_stop_may_escalate_after_grace":true,"active_setup_jobs":0,
        "containers":resources.containers,"networks":resources.networks,
        "retained":retained(&resources),"remove_orphans":false,"purge_supported":false,
        "automatic_retry":false,"point_in_time":true,"installation_ready":false}),
    )
    .map_err(|_| REFUSED.into())
}

pub fn stop(args: &[String]) -> Result<String> {
    execute(args, "stop").map_err(|_| REFUSED.into())
}
/// Resume only already-created runtime containers. The runtime layer and
/// explicit non-setup selection prevent privileged initialization from replaying.
pub fn start(args: &[String]) -> Result<String> {
    execute(args, "start").map_err(|_| REFUSED.into())
}
pub fn uninstall(args: &[String]) -> Result<String> {
    execute(args, "down").map_err(|_| REFUSED.into())
}
fn execute(args: &[String], action: &str) -> Result<String> {
    let args = arguments(args)?;
    let mut state = LockedMaintenance::open(&args.installation)?;
    crate::installer_operator_upgrade::require_selected_caller(
        state.inspection(),
        &args.installation,
    )?;
    crate::installer_lifecycle::record_manual_intent_if_configured(
        &mut state,
        &args.installation,
        &args.docker,
        action,
    )?;
    if action == "start" {
        if let Some(report) = crate::installer_lifecycle::start_if_configured(
            &mut state,
            &args.installation,
            &args.docker,
        )? {
            return Ok(report);
        }
    }
    execute_locked(&args.installation, &args.docker, action, &mut state)
}

/// Systemd reuses the held installation lock and native ownership checks. Its
/// shutdown path deliberately bypasses the manual durable-pause hook above.
pub(crate) fn execute_locked(
    installation: &Path,
    docker: &Path,
    action: &str,
    state: &mut LockedMaintenance,
) -> Result<String> {
    if action == "stop" {
        if let Some(report) = crate::installer_generation_maintenance::stop_pending_locked(
            installation,
            docker,
            state,
        )? {
            return serde_json::to_string(&report).map_err(|_| REFUSED.into());
        }
    }
    execute_selection_locked(installation, docker, action, None, state)
}

/// The cold recovery owner starts its infrastructure group before application
/// credential reconciliation. This cannot create containers or select setup.
pub(crate) fn start_selected_locked(
    installation: &Path,
    docker: &Path,
    selected: &[String],
    state: &mut LockedMaintenance,
) -> Result<String> {
    require(!selected.is_empty())?;
    execute_selection_locked(installation, docker, "start", Some(selected), state)
}

fn runtime_satisfied(
    resources: &ProjectResources,
    rows: &[Value],
    action: &str,
    selected: Option<&[String]>,
) -> bool {
    if !["start", "stop"].contains(&action) || no_active_setup(resources, rows).is_err() {
        return false;
    }
    let runtime: BTreeSet<&str> = resources
        .containers
        .iter()
        .filter(|(_, container)| !container.setup)
        .filter(|(role, _)| selected.is_none_or(|roles| roles.contains(role)))
        .map(|(role, _)| role.as_str())
        .collect();
    !runtime.is_empty()
        && selected.is_none_or(|roles| roles.len() == runtime.len())
        && rows
            .iter()
            .filter(|row| {
                row["Service"]
                    .as_str()
                    .is_some_and(|role| runtime.contains(role))
            })
            .all(|row| {
                if action == "start" {
                    let role = row["Service"].as_str().unwrap();
                    row["State"] == "running"
                        && (!resources.containers[role].health_required
                            || row["Health"] == "healthy")
                } else {
                    row["State"] == "exited" || row["State"] == "created"
                }
            })
}

fn execute_selection_locked(
    installation: &Path,
    docker: &Path,
    action: &str,
    selected: Option<&[String]>,
    state: &mut LockedMaintenance,
) -> Result<String> {
    require(["start", "stop", "down"].contains(&action))?;
    require(selected.is_none() || action == "start")?;
    crate::installer_operator_upgrade::require_selected_caller(state.inspection(), installation)?;
    let (saved, session) =
        installer_doctor::open_session(state.inspection(), installation, docker)?;
    if action != "down" {
        reconcile_pending(installation, docker, state, &saved)?;
    }
    let operation = next_operation(state.inspection(), action)?;
    let resources = session.observe_resources()?;
    union_scope(&saved, &resources)?;
    let statuses = session.status()?;
    no_active_setup(&resources, &statuses)?;
    unchanged(state.inspection(), installation, &saved)?;
    if action != "down" && runtime_satisfied(&resources, &statuses, action, selected) {
        require(session.observe_resources()? == resources)?;
        return serde_json::to_string(&json!({"schema":"elevenid.installer-compose-maintenance/v1",
            "installation_id":saved.installation_id,"project":saved.inputs.project,"operation":action,
            "evidence_operation":null,"outcome":"already_observed","command_succeeded":true,"observation_validated":true,
            "command_invoked":false,"retained":retained(&resources),"automatic_retry":false,
            "host_files_deleted":false,"images_deleted":false,"named_volumes_deleted":false,"installation_ready":false})).map_err(|_| REFUSED.into());
    }
    let result = match action {
        "down" => session.down(state, &operation, STOP_GRACE)?,
        "stop" => session.stop(state, &operation, STOP_GRACE)?,
        "start" => {
            require(saved.schema != installer_doctor::FAILED_RUNTIME_SESSION_SCHEMA)?;
            let services = selected.map(<[String]>::to_vec).unwrap_or_else(|| {
                resources
                    .containers
                    .values()
                    .filter(|c| !c.setup)
                    .map(|c| c.service.clone())
                    .collect()
            });
            require(!services.is_empty())?;
            let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
            let runtime = start_session(docker, &binding, &saved, services, selected.is_some())?;
            runtime.start_existing(state, &operation, START_WAIT)?
        }
        _ => return Err(REFUSED.into()),
    };
    unchanged(state.inspection(), installation, &saved)?;
    serde_json::to_string(&json!({"schema":"elevenid.installer-compose-maintenance/v1",
        "installation_id":saved.installation_id,"project":result.project,
        "operation":action,"evidence_operation":operation,"command_succeeded":result.command_succeeded,"command_invoked":true,
        "observation_validated":result.observation_validated,"retained":retained(&resources),
        "automatic_retry":false,"host_files_deleted":false,"images_deleted":false,
        "named_volumes_deleted":false,"installation_ready":false})).map_err(|_| REFUSED.into())
}

/// Historical command evidence only. An uncertain start/stop can be retired by
/// its separately validated ownership reconciliation; this never claims that
/// its missing client response was successful. Down remains non-replayable.
pub fn status(state: &LockedInspection) -> Result<Value> {
    let mut operations = BTreeMap::new();
    let mut next = BTreeMap::new();
    let mut pending = BTreeMap::new();
    for action in ["start", "stop", "down"] {
        let mut observed = "not_started";
        for ordinal in 1..=10000 {
            let operation = format!("{action}-{ordinal:04}");
            let intent = state
                .diagnostic_record(&format!("uninstall-compose-{operation}-intent.json"), true)?;
            let result = state
                .diagnostic_record(&format!("uninstall-compose-{operation}-result.json"), true)?;
            let reconciliation = state.diagnostic_record(
                &format!("uninstall-compose-{operation}-reconciled.json"),
                true,
            )?;
            require(intent.is_some() || (result.is_none() && reconciliation.is_none()))?;
            if intent.is_none() {
                next.insert(action, operation);
                break;
            }
            let intent_bytes = intent.ok_or(REFUSED)?;
            let intent = crate::installer_json::decode(&intent_bytes).map_err(|_| REFUSED)?;
            let command = if action == "start" {
                json!([
                    "start",
                    "--wait",
                    "--wait-timeout",
                    START_WAIT.as_secs().to_string()
                ])
            } else {
                json!([action, "--timeout", STOP_GRACE.as_secs().to_string()])
            };
            require(
                intent["schema"] == "elevenid.installer-compose-intent/v1"
                    && intent["project"] == state.journal().compose_project()
                    && intent["engine_id"] == state.journal().runtime().ok_or(REFUSED)?.engine_id
                    && intent["automatic_retry"] == false
                    && intent["installation_ready"] == false
                    && intent["command"] == command,
            )?;
            observed = if let Some(bytes) = &result {
                let receipt: ComposeReceipt = serde_json::from_value(
                    crate::installer_json::decode(bytes).map_err(|_| REFUSED)?,
                )
                .map_err(|_| REFUSED)?;
                require(
                    (receipt.schema == "elevenid.installer-compose-operation/v1"
                        || (action != "start"
                            && receipt.schema == crate::installer_compose::CLEANUP_RECEIPT_SCHEMA))
                        && receipt.project == state.journal().compose_project()
                        && receipt.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
                        && receipt.operation == operation
                        && !receipt.installation_ready
                        && intent["configuration_sha256"] == receipt.configuration_sha256
                        && intent["input_files"]
                            == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?,
                )?;
                if receipt.command_succeeded
                    && receipt.client_exit_code == Some(0)
                    && receipt.failure_class.is_none()
                    && receipt.observation_validated
                    && receipt.resources.is_some()
                {
                    "completed"
                } else {
                    "uncertain"
                }
            } else {
                "uncertain"
            };
            if let Some(bytes) = reconciliation {
                require(observed == "uncertain")?;
                verify_reconciliation(
                    state,
                    action,
                    &operation,
                    &intent_bytes,
                    result.as_deref(),
                    &bytes,
                )?;
                observed = "reconciled";
            }
            if observed == "uncertain" {
                pending.insert(action, operation);
                break;
            }
        }
        operations.insert(action, observed);
    }
    state.require_unchanged()?;
    Ok(
        json!({"operations":operations,"next_operations":next,"pending_operations":pending,"historical_evidence_only":true,"automatic_retry":false,
        "host_data_credentials_images_and_named_volumes_retained":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_compose::{ContainerIdentity, SetupExecution};
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding, RuntimeProfile};
    fn resources() -> ProjectResources {
        ProjectResources {
            containers: [(
                "job".into(),
                ContainerIdentity {
                    id: "a".repeat(64),
                    service: "job".into(),
                    image: format!("example.invalid/test@sha256:{}", "b".repeat(64)),
                    config_hash: "c".repeat(64),
                    setup: true,
                    health_required: false,
                    setup_execution: Some(SetupExecution {
                        started_at: "2026-10-30T00:00:01Z".into(),
                        finished_at: "2026-10-30T00:00:02Z".into(),
                        completed_without_restart: true,
                    }),
                    cap_add: BTreeSet::new(),
                    cap_drop: BTreeSet::from(["ALL".into()]),
                    read_only: true,
                    memory_limit: 64 * 1024 * 1024,
                },
            )]
            .into(),
            ..ProjectResources::default()
        }
    }
    #[test]
    fn closed_arguments_cannot_enable_force_purge_or_other_projects() {
        let valid = vec!["--install-dir".into(), "/private/install".into()];
        assert!(arguments(&valid).is_ok());
        for extra in [
            ["--force", "true"],
            ["--volumes", "true"],
            ["--rmi", "all"],
            ["--remove-orphans", "true"],
            ["--project-name", "other"],
            ["--install-dir", "/other"],
        ] {
            let mut args = valid.clone();
            args.extend(extra.map(String::from));
            assert!(arguments(&args).is_err());
        }
    }
    #[test]
    fn active_or_unidentified_setup_never_enters_normal_stop() {
        for state in ["created", "exited"] {
            no_active_setup(
                &resources(),
                &[json!({"Service":"job","ID":"a".repeat(64),"State":state})],
            )
            .unwrap();
        }
        for state in ["running", "restarting", "paused", "dead"] {
            assert!(no_active_setup(
                &resources(),
                &[json!({"Service":"job","ID":"a".repeat(64),"State":state})]
            )
            .is_err());
        }
        assert!(no_active_setup(&resources(), &[]).is_err());
        assert!(no_active_setup(
            &resources(),
            &[json!({"Service":"job","ID":"d".repeat(64),"State":"exited"})]
        )
        .is_err());
        let row = json!({"Service":"job","ID":"a".repeat(64),"State":"exited"});
        assert!(no_active_setup(&resources(), &[row.clone(), row]).is_err());
    }

    fn history_fixture() -> (tempfile::TempDir, PathBuf, InstallerState) {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("installation");
        let mut state = InstallerState::create_with_runtime(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v0.0.0".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "fixture-engine".into(),
                openbao_port: 18443,
                profile: RuntimeProfile::Rootful,
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        (parent, path, state)
    }

    fn completed_record(state: &mut InstallerState, action: &str, ordinal: u32, result: bool) {
        let operation = format!("{action}-{ordinal:04}");
        let command = if action == "start" {
            json!(["start", "--wait", "--wait-timeout", "720"])
        } else {
            json!([action, "--timeout", "60"])
        };
        let intent = json!({"schema":"elevenid.installer-compose-intent/v1",
            "project":state.journal().compose_project(),"engine_id":"fixture-engine",
            "automatic_retry":false,"installation_ready":false,"command":command,
            "configuration_sha256":"c".repeat(64),"input_files":{}});
        state
            .write_evidence(
                &format!("uninstall-compose-{operation}-intent.json"),
                &serde_json::to_vec(&intent).unwrap(),
            )
            .unwrap();
        if result {
            let receipt = ComposeReceipt {
                schema: "elevenid.installer-compose-operation/v1".into(),
                project: state.journal().compose_project(),
                engine_id: "fixture-engine".into(),
                operation: operation.clone(),
                configuration_sha256: "c".repeat(64),
                input_files: BTreeMap::new(),
                command_succeeded: true,
                client_exit_code: Some(0),
                failure_class: None,
                observation_validated: true,
                resources: Some(ProjectResources::default()),
                status: Vec::new(),
                installation_ready: false,
            };
            state
                .write_evidence(
                    &format!("uninstall-compose-{operation}-result.json"),
                    &serde_json::to_vec(&receipt).unwrap(),
                )
                .unwrap();
        }
    }

    #[test]
    fn successful_stop_start_cycles_keep_distinct_evidence() {
        let (_parent, path, mut state) = history_fixture();
        completed_record(&mut state, "stop", 1, true);
        completed_record(&mut state, "start", 1, true);
        completed_record(&mut state, "stop", 2, true);
        drop(state);
        let state = LockedInspection::open(&path).unwrap();
        assert_eq!(next_operation(&state, "start").unwrap(), "start-0002");
        assert_eq!(next_operation(&state, "stop").unwrap(), "stop-0003");
        assert!(state
            .read_evidence("uninstall-compose-stop-0001-result.json")
            .is_ok());
    }

    #[test]
    fn reconciled_start_keeps_unknown_response_honest_and_binds_every_retained_identity() {
        let (_parent, path, mut state) = history_fixture();
        let mut retained = resources();
        let mut app = retained.containers["job"].clone();
        app.id = "d".repeat(64);
        app.service = "app".into();
        app.setup = false;
        app.setup_execution = None;
        retained.containers.insert("app".into(), app);
        let intent = serde_json::to_vec(&json!({"schema":"elevenid.installer-compose-intent/v1",
            "project":state.journal().compose_project(),"engine_id":"fixture-engine",
            "automatic_retry":false,"installation_ready":false,"command":["start","--wait","--wait-timeout","720"],
            "configuration_sha256":"c".repeat(64),"input_files":{},"selected_services":["app"],"prior_resources":retained})).unwrap();
        state
            .write_evidence("uninstall-compose-start-0001-intent.json", &intent)
            .unwrap();
        let record = Reconciliation {
            schema: "elevenid.installer-compose-idempotent-reconciliation/v1".into(),
            installation_id: state.journal().installation_id(),
            project: state.journal().compose_project(),
            engine_id: "fixture-engine".into(),
            operation: "start-0001".into(),
            configuration_sha256: "c".repeat(64),
            intent_sha256: crate::installer_release::sha256(&intent),
            result_sha256: None,
            selected_services: vec!["app".into()],
            resources: retained,
            previous_command_result_known: false,
            action_replayed: false,
            installation_ready: false,
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        state
            .with_inspection(|view| {
                verify_reconciliation(view, "start", "start-0001", &intent, None, &bytes)?;
                assert!(
                    verify_reconciliation(view, "down", "start-0001", &intent, None, &bytes)
                        .is_err()
                );
                let mut changed = serde_json::to_value(&record).unwrap();
                changed["resources"]["containers"]["app"]["id"] = json!("e".repeat(64));
                assert!(verify_reconciliation(
                    view,
                    "start",
                    "start-0001",
                    &intent,
                    None,
                    &serde_json::to_vec(&changed).unwrap()
                )
                .is_err());
                let mut claimed = serde_json::to_value(&record).unwrap();
                claimed["previous_command_result_known"] = json!(true);
                assert!(verify_reconciliation(
                    view,
                    "start",
                    "start-0001",
                    &intent,
                    None,
                    &serde_json::to_vec(&claimed).unwrap()
                )
                .is_err());
                assert!(verify_reconciliation(
                    view,
                    "start",
                    "start-0001",
                    &intent,
                    Some(b"late or changed result"),
                    &bytes
                )
                .is_err());
                Ok(())
            })
            .unwrap();
        state
            .write_evidence("uninstall-compose-start-0001-reconciled.json", &bytes)
            .unwrap();
        drop(state);
        let inspection = LockedInspection::open(&path).unwrap();
        assert_eq!(
            status(&inspection).unwrap()["operations"]["start"],
            "reconciled"
        );
        assert_eq!(next_operation(&inspection, "start").unwrap(), "start-0002");
        assert!(inspection
            .diagnostic_record("uninstall-compose-start-0001-result.json", true)
            .unwrap()
            .is_none());
    }

    #[test]
    fn an_already_running_group_requires_complete_identified_health_observation() {
        let mut retained = resources();
        let mut app = retained.containers["job"].clone();
        app.id = "d".repeat(64);
        app.service = "app".into();
        app.setup = false;
        app.setup_execution = None;
        app.health_required = true;
        retained.containers.insert("app".into(), app);
        let mut rows = vec![
            json!({"Service":"job","ID":"a".repeat(64),"State":"exited"}),
            json!({"Service":"app","ID":"d".repeat(64),"State":"running","Health":"healthy"}),
        ];
        assert!(runtime_satisfied(&retained, &rows, "start", None));
        assert!(!runtime_satisfied(&retained, &rows[..1], "start", None));
        assert!(!runtime_satisfied(
            &retained,
            &rows,
            "start",
            Some(&["job".into()])
        ));
        rows[1]["Health"] = json!("unhealthy");
        assert!(!runtime_satisfied(&retained, &rows, "start", None));
        rows[1]["State"] = json!("exited");
        assert!(runtime_satisfied(&retained, &rows, "stop", None));
        rows[1]["ID"] = json!("foreign");
        assert!(!runtime_satisfied(&retained, &rows, "stop", None));
    }

    #[test]
    fn infrastructure_start_can_observe_stopped_application_without_hiding_it() {
        let mut retained = resources();
        let mut rows = vec![json!({"Service":"job","ID":"a".repeat(64),"State":"exited"})];
        for (role, id, status) in [("openbao", "d", "running"), ("app", "e", "exited")] {
            let mut runtime = retained.containers["job"].clone();
            runtime.id = id.repeat(64);
            runtime.service = role.into();
            runtime.setup = false;
            runtime.setup_execution = None;
            runtime.health_required = true;
            retained.containers.insert(role.into(), runtime);
            rows.push(json!({"Service":role,"ID":id.repeat(64),"State":status,"Health":"healthy"}));
        }
        let selected = ["openbao".into()];
        assert!(runtime_satisfied(
            &retained,
            &rows,
            "start",
            Some(&selected)
        ));
        assert!(!runtime_satisfied(&retained, &rows, "start", None));
        assert!(!runtime_satisfied(
            &retained,
            &rows[..2],
            "start",
            Some(&selected)
        ));
        rows[2]["ID"] = json!("f".repeat(64));
        assert!(!runtime_satisfied(
            &retained,
            &rows,
            "start",
            Some(&selected)
        ));
    }

    #[test]
    fn uncertain_maintenance_blocks_every_further_mutation() {
        let (_parent, path, mut state) = history_fixture();
        completed_record(&mut state, "stop", 1, true);
        completed_record(&mut state, "start", 1, false);
        drop(state);
        let state = LockedInspection::open(&path).unwrap();
        assert_eq!(status(&state).unwrap()["operations"]["start"], "uncertain");
        for action in ["start", "stop", "down"] {
            assert!(next_operation(&state, action).is_err());
        }
    }
}
