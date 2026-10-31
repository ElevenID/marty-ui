//! Native Compose stop/down for a completely bound installation project.
//! No per-container scheduler, force/remove loop, orphan purge or host deletion.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeReceipt, ComposeSession, ProjectResources},
    installer_doctor::{self, SavedSession},
    installer_state::{LockedInspection, LockedMaintenance},
};
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
    let (saved, session) =
        installer_doctor::open_session(state.inspection(), &args.installation, &args.docker)?;
    let operation = next_operation(state.inspection(), action)?;
    let resources = session.observe_resources()?;
    union_scope(&saved, &resources)?;
    no_active_setup(&resources, &session.status()?)?;
    unchanged(state.inspection(), &args.installation, &saved)?;
    let result = match action {
        "down" => session.down(&mut state, &operation, STOP_GRACE)?,
        "stop" => session.stop(&mut state, &operation, STOP_GRACE)?,
        "start" => {
            require(saved.schema != installer_doctor::FAILED_RUNTIME_SESSION_SCHEMA)?;
            let mut inputs = saved.inputs.clone();
            inputs.profiles.clear();
            inputs.services = resources
                .containers
                .values()
                .filter(|c| !c.setup)
                .map(|c| c.service.clone())
                .collect();
            require(!inputs.services.is_empty())?;
            let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
            let runtime = ComposeSession::new(&args.docker, &binding, inputs)?;
            runtime.start_existing(&mut state, &operation, START_WAIT)?
        }
        _ => return Err(REFUSED.into()),
    };
    unchanged(state.inspection(), &args.installation, &saved)?;
    serde_json::to_string(&json!({"schema":"elevenid.installer-compose-maintenance/v1",
        "installation_id":saved.installation_id,"project":result.project,
        "operation":action,"evidence_operation":operation,"command_succeeded":result.command_succeeded,
        "observation_validated":result.observation_validated,"retained":retained(&resources),
        "automatic_retry":false,"host_files_deleted":false,"images_deleted":false,
        "named_volumes_deleted":false,"installation_ready":false})).map_err(|_| REFUSED.into())
}

/// Historical command evidence only. It does not authorize a retry or substitute
/// for current resource observations; in-progress and failed operations stay uncertain.
pub fn status(state: &LockedInspection) -> Result<Value> {
    let mut operations = BTreeMap::new();
    let mut next = BTreeMap::new();
    for action in ["start", "stop", "down"] {
        let mut observed = "not_started";
        for ordinal in 1..=10000 {
            let operation = format!("{action}-{ordinal:04}");
            let intent = state
                .diagnostic_record(&format!("uninstall-compose-{operation}-intent.json"), true)?;
            let result = state
                .diagnostic_record(&format!("uninstall-compose-{operation}-result.json"), true)?;
            require(intent.is_some() || result.is_none())?;
            if intent.is_none() {
                next.insert(action, operation);
                break;
            }
            let intent =
                crate::installer_json::decode(&intent.ok_or(REFUSED)?).map_err(|_| REFUSED)?;
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
            observed = if let Some(bytes) = result {
                let receipt: ComposeReceipt = serde_json::from_value(
                    crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?,
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
            if observed == "uncertain" {
                break;
            }
        }
        operations.insert(action, observed);
    }
    state.require_unchanged()?;
    Ok(
        json!({"operations":operations,"next_operations":next,"historical_evidence_only":true,"automatic_retry":false,
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
