//! Read-only native Compose observations of the bound installation.
//! Compose owns ordering and health waits; this module reports one snapshot.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{self, ComposeInputs, ComposeReceipt, ComposeSession, ProjectResources},
    installer_state::{LockedInspection, RuntimeBinding},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, String>;
type SessionRecords = Vec<(&'static str, Vec<u8>)>;
const REFUSED: &str = "Installer service inspection refused; preserve the bound Compose inputs and operation evidence";
pub(crate) const SESSION_RECORD: &str = "compose-session.json";
pub(crate) const FAILED_RUNTIME_SESSION_SCHEMA: &str =
    "elevenid.installer-failed-runtime-cleanup-session/v1";

/// The final native model is a read-only snapshot, never a generated executable
/// Compose document. The original authenticated layers remain the command inputs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSession {
    pub schema: String,
    pub installation_id: String,
    pub inputs: ComposeInputs,
    pub model: Value,
    pub configuration_sha256: String,
    pub receipt: ComposeReceipt,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn validate_saved(
    saved: &SavedSession,
    installation: &Path,
    id: &str,
    project: &str,
    binding: &RuntimeBinding,
    approved_images: &BTreeSet<String>,
) -> Result<()> {
    let receipt = &saved.receipt;
    #[cfg(feature = "installer-development")]
    if let Some(image) = &saved.inputs.development_image {
        image.require_inputs(&saved.inputs)?;
        let services = saved.model["services"].as_object().ok_or(REFUSED)?;
        require(
            services.contains_key(crate::installer_development_image::ROLE)
                && services.iter().all(|(role, service)| {
                    service["image"]
                        .as_str()
                        .is_some_and(|reference| saved.inputs.permits_image(role, reference))
                }),
        )?;
    }
    require(
        [
            "elevenid.installer-compose-session/v1",
            FAILED_RUNTIME_SESSION_SCHEMA,
        ]
        .contains(&saved.schema.as_str())
            && saved.installation_id == id
            && saved.inputs.installation == installation
            && saved.inputs.project == project
            && saved.model["name"] == project
            && binding.profile == crate::installer_state::RuntimeProfile::Rootless
            && &saved.inputs.approved_images == approved_images
            && receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.project == project
            && receipt.engine_id == binding.engine_id
            && receipt.observation_validated
            && !receipt.installation_ready
            && installer_compose::model_sha256(&saved.model)? == saved.configuration_sha256
            && serde_json::to_value(&saved.inputs.prior).map_err(|_| REFUSED)?
                == serde_json::to_value(Some(receipt)).map_err(|_| REFUSED)?,
    )?;
    if saved.schema == FAILED_RUNTIME_SESSION_SCHEMA {
        installer_compose::validate_failed_runtime_cleanup(receipt, &saved.model)?;
    } else {
        require(
            receipt.command_succeeded
                && receipt.client_exit_code == Some(0)
                && receipt.failure_class.is_none()
                && saved.configuration_sha256 == receipt.configuration_sha256,
        )?;
    }
    let resources = receipt.resources.as_ref().ok_or(REFUSED)?;
    require(
        !resources.containers.is_empty()
            && resources.containers.len() <= 128
            && resources
                .containers
                .values()
                .map(|v| &v.id)
                .collect::<BTreeSet<_>>()
                .len()
                == resources.containers.len()
            && resources.containers.iter().all(|(role, container)| {
                name(role)
                    && container.service == *role
                    && identifier(&container.id)
                    && identifier(&container.config_hash)
                    && saved.inputs.permits_image(role, &container.image)
            })
            && resources.networks.values().all(|id| identifier(id)),
    )?;
    for file in saved
        .inputs
        .files
        .iter()
        .chain(std::iter::once(&saved.inputs.environment))
        .chain(&saved.inputs.bound_inputs)
    {
        require(receipt.input_files.get(&file.path) == Some(&file.sha256))?;
    }
    Ok(())
}

/// Rebind the private session to the release inventory, journal, exact files,
/// and native model. This does not contact Docker or grant lifecycle authority.
pub(crate) fn load_session(state: &LockedInspection, installation: &Path) -> Result<SavedSession> {
    state.require_path_binding(installation)?;
    let session_bytes = state.diagnostic_record(SESSION_RECORD, true)?;
    let (mut saved, mut records) = if let Some(bytes) = &session_bytes {
        let saved: SavedSession =
            serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        require(saved.schema == "elevenid.installer-compose-session/v1")?;
        (saved, vec![(SESSION_RECORD, bytes.clone())])
    } else {
        failed_runtime_session(state, installation)?
    };
    let inventory_bytes = state.read_evidence("installer-inventory.json")?;
    let journal = state.journal();
    require(
        format!(
            "sha256:{}",
            crate::installer_release::sha256(&inventory_bytes)
        ) == journal.identity().inventory_sha256,
    )?;
    let inventory = crate::installer_release::parse_inventory(&inventory_bytes)?;
    require(
        inventory.source_sha == journal.identity().source_sha
            && inventory.release_tag == journal.identity().release_tag,
    )?;
    let binding = journal.runtime().ok_or(REFUSED)?;
    binding.validate()?;
    let approved_images = inventory.images.values().cloned().collect::<BTreeSet<_>>();
    #[cfg(feature = "installer-development")]
    let approved_images = {
        let mut images = approved_images;
        let development = crate::installer_development_image::load(state)?;
        require(development == saved.inputs.development_image)?;
        if let Some(image) = development {
            image.require_inputs(&saved.inputs)?;
            images.insert(image.image_id);
        }
        images
    };
    validate_saved(
        &saved,
        installation,
        &journal.installation_id().to_string(),
        &journal.compose_project(),
        binding,
        &approved_images,
    )?;
    if let Some(original) = &session_bytes {
        let (extended, extensions) =
            crate::installer_foundation_registration::extend_session(state, original, saved)?;
        saved = extended;
        records.extend(extensions);
        validate_saved(
            &saved,
            installation,
            &journal.installation_id().to_string(),
            &journal.compose_project(),
            binding,
            &approved_images,
        )?;
    }
    installer_compose::verify_input_files(installation, &saved.receipt.input_files)?;
    for (name, bytes) in records {
        require(bytes == state.read_evidence(name)?)?;
    }
    require(
        session_bytes == state.diagnostic_record(SESSION_RECORD, true)?
            && inventory_bytes == state.read_evidence("installer-inventory.json")?,
    )?;
    state.require_unchanged()?;
    Ok(saved)
}

fn failed_runtime_session(
    state: &LockedInspection,
    installation: &Path,
) -> Result<(SavedSession, SessionRecords)> {
    let plan_bytes = state.read_evidence(installer_compose::RUNTIME_CLEANUP_PLAN)?;
    let result_bytes = state.read_evidence("compose-application-up-result.json")?;
    let intent_bytes = state.read_evidence("compose-application-up-intent.json")?;
    let plan: installer_compose::RuntimeCleanupPlan =
        serde_json::from_value(crate::installer_json::decode(&plan_bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let receipt: ComposeReceipt =
        serde_json::from_value(crate::installer_json::decode(&result_bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let intent = crate::installer_json::decode(&intent_bytes).map_err(|_| REFUSED)?;
    let plan_path = installation
        .join("evidence")
        .join(installer_compose::RUNTIME_CLEANUP_PLAN);
    require(
        plan.schema == "elevenid.installer-runtime-cleanup-plan/v1"
            && plan.installation_id == state.journal().installation_id().to_string()
            && plan.inputs.installation == installation
            && plan.inputs.services.is_empty()
            && plan.application_configuration_sha256 == receipt.configuration_sha256
            && installer_compose::model_sha256(&plan.model)? == plan.configuration_sha256
            && receipt.input_files.get(&plan_path)
                == Some(&crate::installer_release::sha256(&plan_bytes))
            && intent["schema"] == "elevenid.installer-compose-intent/v1"
            && intent["project"] == receipt.project
            && intent["engine_id"] == receipt.engine_id
            && intent["configuration_sha256"] == receipt.configuration_sha256
            && intent["input_files"]
                == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
            && intent["command"]
                == json!([
                    "up",
                    "--no-build",
                    "--pull",
                    "never",
                    "--no-recreate",
                    "--wait",
                    "--wait-timeout",
                    "720"
                ])
            && intent["automatic_retry"] == false
            && intent["installation_ready"] == false,
    )?;
    let before = plan.inputs.prior.as_ref().ok_or(REFUSED)?;
    let prior_resources = before.resources.as_ref().ok_or(REFUSED)?;
    let after = receipt.resources.as_ref().ok_or(REFUSED)?;
    require(
        before.command_succeeded
            && before.observation_validated
            && before.client_exit_code == Some(0)
            && before.failure_class.is_none()
            && before.project == receipt.project
            && before.engine_id == receipt.engine_id
            && before
                .input_files
                .iter()
                .all(|(path, hash)| receipt.input_files.get(path) == Some(hash))
            && intent["prior_resources"]
                == serde_json::to_value(prior_resources).map_err(|_| REFUSED)?
            && prior_resources
                .containers
                .iter()
                .all(|(role, identity)| after.containers.get(role) == Some(identity))
            && prior_resources
                .networks
                .iter()
                .all(|(name, id)| after.networks.get(name) == Some(id))
            && prior_resources.volumes.is_subset(&after.volumes),
    )?;
    installer_compose::validate_failed_runtime_cleanup(&receipt, &plan.model)?;
    let mut inputs = plan.inputs;
    inputs.prior = Some(receipt.clone());
    let saved = SavedSession {
        schema: FAILED_RUNTIME_SESSION_SCHEMA.into(),
        installation_id: plan.installation_id,
        inputs,
        model: plan.model,
        configuration_sha256: plan.configuration_sha256,
        receipt,
    };
    Ok((
        saved,
        vec![
            (installer_compose::RUNTIME_CLEANUP_PLAN, plan_bytes),
            ("compose-application-up-result.json", result_bytes),
            ("compose-application-up-intent.json", intent_bytes),
        ],
    ))
}

pub(crate) fn open_session(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
) -> Result<(SavedSession, ComposeSession)> {
    open_session_with_deadline(state, installation, docker, None)
}
fn open_session_with_deadline(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
    deadline: Option<Instant>,
) -> Result<(SavedSession, ComposeSession)> {
    let saved = load_session(state, installation)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    let session = if saved.schema == FAILED_RUNTIME_SESSION_SCHEMA {
        ComposeSession::for_failed_runtime_cleanup(docker, binding, saved.inputs.clone(), deadline)?
    } else if let Some(deadline) = deadline {
        ComposeSession::new_with_deadline(docker, binding, saved.inputs.clone(), deadline)?
    } else {
        ComposeSession::new(docker, binding, saved.inputs.clone())?
    };
    require(
        session.model() == &saved.model
            && session.configuration_sha256() == saved.configuration_sha256,
    )?;
    Ok((saved, session))
}

/// Only fixed fields from native `compose ps` are public; command text, health
/// logs, paths, environment and untrusted error bodies never enter this report.
pub(crate) fn summarize(resources: &ProjectResources, rows: &[Value]) -> Result<Value> {
    let mut by_role = BTreeMap::new();
    for row in rows {
        let role = row["Service"].as_str().ok_or(REFUSED)?;
        let identity = resources.containers.get(role).ok_or(REFUSED)?;
        require(row["ID"] == identity.id && by_role.insert(role, row).is_none())?;
    }
    let mut services = BTreeMap::new();
    let mut passed = true;
    for (role, identity) in &resources.containers {
        let Some(row) = by_role.get(role.as_str()) else {
            passed = false;
            services.insert(
                role.clone(),
                json!({"container_id":identity.id,"status":"missing",
                "configuration_verified":true,"expected_state_observed":false}),
            );
            continue;
        };
        let status = row["State"].as_str().ok_or(REFUSED)?;
        require(
            [
                "created",
                "running",
                "exited",
                "paused",
                "restarting",
                "dead",
                "removing",
            ]
            .contains(&status),
        )?;
        let health = row["Health"].as_str().ok_or(REFUSED)?;
        require(["", "healthy", "unhealthy", "starting"].contains(&health))?;
        let exit = row["ExitCode"].as_i64().ok_or(REFUSED)?;
        let (expected, satisfied) = if identity.setup {
            ("exited_zero", status == "exited" && exit == 0)
        } else if identity.health_required {
            ("healthy", status == "running" && health == "healthy")
        } else {
            ("running_only", status == "running")
        };
        passed &= satisfied;
        services.insert(
            role.clone(),
            json!({"container_id":identity.id,"status":status,
            "health":if health.is_empty() { Value::Null } else { json!(health) },"exit_code":exit,
            "expected":expected,"expected_state_observed":satisfied,"configuration_verified":true,
            "observation_source":"docker_compose_ps","oom_kill_history_observed":false,
            "restart_history_observed":false}),
        );
    }
    Ok(
        json!({"services_observed":true,"all_expected_states_observed":passed,
        "services":services,"not_atomic_snapshot":true,"installation_ready":false}),
    )
}

pub fn services(state: &LockedInspection, installation: &Path, docker: &Path) -> Result<Value> {
    inspect(state, installation, docker, None).map_err(|_| REFUSED.into())
}
pub(crate) fn services_with_deadline(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
    deadline: Instant,
) -> Result<Value> {
    inspect(state, installation, docker, Some(deadline)).map_err(|_| REFUSED.into())
}
fn inspect(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
    deadline: Option<Instant>,
) -> Result<Value> {
    if state.diagnostic_record(SESSION_RECORD, true)?.is_none()
        && state
            .diagnostic_record(installer_compose::RUNTIME_CLEANUP_PLAN, true)?
            .is_none()
    {
        return Ok(
            json!({"services_observed":false,"reason":"compose_session_incomplete",
            "installation_ready":false}),
        );
    }
    let (saved, session) = open_session_with_deadline(state, installation, docker, deadline)?;
    let before = session.observe_resources()?;
    let statuses = session.status()?;
    let result = summarize(&before, &statuses)?;
    require(
        before == session.observe_resources()?
            && serde_json::to_value(&saved).map_err(|_| REFUSED)?
                == serde_json::to_value(load_session(state, installation)?).map_err(|_| REFUSED)?,
    )?;
    state.require_unchanged()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_compose::{ContainerIdentity, SetupExecution};

    fn resources() -> ProjectResources {
        ProjectResources {
            containers: [
                ("database", false, true),
                ("setup-job", true, false),
                ("worker", false, false),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, (role, setup, health_required))| {
                (
                    role.into(),
                    ContainerIdentity {
                        id: format!("{i:064x}"),
                        service: role.into(),
                        image: format!("example.invalid/image@sha256:{}", "a".repeat(64)),
                        config_hash: "b".repeat(64),
                        setup,
                        health_required,
                        setup_execution: setup.then(|| SetupExecution {
                            started_at: "2026-10-30T00:00:01Z".into(),
                            finished_at: "2026-10-30T00:00:02Z".into(),
                            completed_without_restart: true,
                        }),
                        cap_add: BTreeSet::new(),
                        cap_drop: BTreeSet::from(["ALL".into()]),
                        read_only: true,
                        memory_limit: 64 * 1024 * 1024,
                    },
                )
            })
            .collect(),
            ..ProjectResources::default()
        }
    }
    fn statuses() -> Vec<Value> {
        resources().containers.values().map(|v| json!({"ID":v.id,"Service":v.service,
            "State":if v.setup {"exited"} else {"running"},"Health":if v.health_required {"healthy"} else {""},
            "ExitCode":0,"Command":"private command sentinel","Publishers":["private metadata sentinel"]})).collect()
    }
    #[test]
    fn native_status_uses_recorded_completion_contract_without_a_role_table() {
        let report = summarize(&resources(), &statuses()).unwrap();
        assert_eq!(report["all_expected_states_observed"], true);
        assert_eq!(report["services"]["worker"]["expected"], "running_only");
        assert_eq!(report["services"]["setup-job"]["expected"], "exited_zero");
        assert_eq!(report["installation_ready"], false);
        assert!(!report.to_string().contains("sentinel"));
        assert_eq!(
            report["services"]["database"]["restart_history_observed"],
            false
        );
    }
    #[test]
    fn failed_setup_missing_service_and_unhealthy_service_do_not_pass() {
        let mut rows = statuses();
        rows.iter_mut()
            .find(|r| r["Service"] == "setup-job")
            .unwrap()["ExitCode"] = json!(1);
        assert_eq!(
            summarize(&resources(), &rows).unwrap()["all_expected_states_observed"],
            false
        );
        let mut rows = statuses();
        rows.retain(|r| r["Service"] != "worker");
        assert_eq!(
            summarize(&resources(), &rows).unwrap()["all_expected_states_observed"],
            false
        );
        let mut rows = statuses();
        rows.iter_mut()
            .find(|r| r["Service"] == "database")
            .unwrap()["Health"] = json!("unhealthy");
        assert_eq!(
            summarize(&resources(), &rows).unwrap()["all_expected_states_observed"],
            false
        );
    }
    #[test]
    fn status_identity_duplicates_unknown_roles_and_untrusted_states_refuse() {
        for mutation in 0..5 {
            let mut rows = statuses();
            match mutation {
                0 => rows.push(rows[0].clone()),
                1 => rows[0]["ID"] = json!("f".repeat(64)),
                2 => rows[0]["Service"] = json!("foreign"),
                3 => rows[0]["State"] = json!("private state sentinel"),
                _ => rows[0]["ExitCode"] = json!(false),
            }
            assert!(summarize(&resources(), &rows).is_err());
        }
    }
    fn saved_fixture() -> (SavedSession, RuntimeBinding) {
        let installation = Path::new("/private/install");
        let project = "marty-install-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let model = json!({"name":project,"services":{"worker":{"image":resources().containers["worker"].image}}});
        let hash = installer_compose::model_sha256(&model).unwrap();
        let files = vec![installer_compose::BoundFile {
            path: installation.join("bundle/compose.yml"),
            sha256: "c".repeat(64),
        }];
        let environment = installer_compose::BoundFile {
            path: installation.join("evidence/application.env"),
            sha256: "d".repeat(64),
        };
        let receipt = ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: project.into(),
            engine_id: "engine".into(),
            operation: "runtime".into(),
            configuration_sha256: hash.clone(),
            input_files: files
                .iter()
                .chain(std::iter::once(&environment))
                .map(|f| (f.path.clone(), f.sha256.clone()))
                .collect(),
            command_succeeded: true,
            client_exit_code: Some(0),
            failure_class: None,
            observation_validated: true,
            resources: Some(resources()),
            status: statuses(),
            installation_ready: false,
        };
        let inputs = ComposeInputs {
            installation: installation.into(),
            project: project.into(),
            files,
            environment,
            bound_inputs: Vec::new(),
            profiles: vec!["setup".into()],
            services: vec![],
            approved_images: resources()
                .containers
                .values()
                .map(|c| c.image.clone())
                .collect(),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            prior: Some(receipt.clone()),
        };
        (
            SavedSession {
                schema: "elevenid.installer-compose-session/v1".into(),
                installation_id: "installation".into(),
                inputs,
                model,
                configuration_sha256: hash,
                receipt,
            },
            RuntimeBinding {
                docker_host: "unix:///run/user/1001/docker.sock".into(),
                engine_id: "engine".into(),
                openbao_port: 18200,
                profile: crate::installer_state::RuntimeProfile::Rootless,
            },
        )
    }
    #[test]
    fn saved_session_binds_inventory_runtime_content_and_successful_receipt() {
        let (saved, binding) = saved_fixture();
        let approved = saved.inputs.approved_images.clone();
        let check = |candidate: &SavedSession| {
            validate_saved(
                candidate,
                Path::new("/private/install"),
                "installation",
                "marty-install-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &binding,
                &approved,
            )
        };
        check(&saved).unwrap();
        for mutation in 0..10 {
            let mut bad = saved.clone();
            match mutation {
                0 => bad.installation_id = "other".into(),
                1 => bad.inputs.project = "other".into(),
                2 => bad.receipt.engine_id = "other".into(),
                3 => bad.receipt.client_exit_code = Some(1),
                4 => bad.receipt.failure_class = Some("uncertain".into()),
                5 => bad
                    .inputs
                    .approved_images
                    .insert(format!("example.invalid/foreign@sha256:{}", "f".repeat(64)))
                    .then_some(())
                    .unwrap(),
                6 => bad.model["services"]["worker"]["image"] = json!("changed"),
                7 => {
                    bad.receipt
                        .resources
                        .as_mut()
                        .unwrap()
                        .containers
                        .get_mut("worker")
                        .unwrap()
                        .id = "0".repeat(64)
                }
                8 => {
                    bad.receipt.input_files.remove(&bad.inputs.environment.path);
                }
                _ => bad.receipt.observation_validated = false,
            }
            bad.inputs.prior = Some(bad.receipt.clone());
            assert!(check(&bad).is_err(), "mutation {mutation}");
        }
        let mut bad = saved.clone();
        bad.inputs.prior.as_mut().unwrap().operation = "different".into();
        assert!(check(&bad).is_err());
    }
    #[test]
    fn saved_session_rejects_duplicate_and_unrecognized_receipt_fields() {
        assert!(
            crate::installer_json::decode(br#"{"receipt":{"engine_id":"a","engine_id":"b"}}"#)
                .is_err()
        );
        let (saved, _) = saved_fixture();
        let mut value = serde_json::to_value(saved).unwrap();
        value["receipt"]["unreviewed_create_id"] = json!("a".repeat(64));
        assert!(serde_json::from_value::<SavedSession>(value).is_err());
    }

    #[test]
    #[cfg(feature = "installer-development")]
    fn development_saved_session_keeps_exact_layer_role_and_native_identity() {
        let (mut saved, binding) = saved_fixture();
        let image = crate::installer_development_image::test_fixture();
        image.bind_inputs(&mut saved.inputs).unwrap();
        saved.model["services"]["signing-keys"] = json!({"image":image.image_id});
        let mut resource = saved.receipt.resources.as_ref().unwrap().containers["worker"].clone();
        resource.id = "f".repeat(64);
        resource.service = "signing-keys".into();
        resource.image = image.image_id.clone();
        saved
            .receipt
            .resources
            .as_mut()
            .unwrap()
            .containers
            .insert("signing-keys".into(), resource);
        for file in saved.inputs.files.iter().chain(&saved.inputs.bound_inputs) {
            saved
                .receipt
                .input_files
                .insert(file.path.clone(), file.sha256.clone());
        }
        let seal = |candidate: &mut SavedSession| {
            candidate.configuration_sha256 =
                installer_compose::model_sha256(&candidate.model).unwrap();
            candidate.receipt.configuration_sha256 = candidate.configuration_sha256.clone();
            candidate.inputs.prior = Some(candidate.receipt.clone());
        };
        seal(&mut saved);
        let approved = saved.inputs.approved_images.clone();
        let check = |candidate: &SavedSession| {
            validate_saved(
                candidate,
                Path::new("/private/install"),
                "installation",
                "marty-install-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &binding,
                &approved,
            )
        };
        check(&saved).unwrap();
        for mutation in 0..4 {
            let mut changed = saved.clone();
            match mutation {
                0 => {
                    changed.inputs.files.pop();
                }
                1 => changed.model["services"]["worker"]["image"] = json!(image.image_id),
                2 => {
                    changed.model["services"]["signing-keys"]["image"] =
                        saved.model["services"]["worker"]["image"].clone()
                }
                _ => {
                    changed
                        .receipt
                        .resources
                        .as_mut()
                        .unwrap()
                        .containers
                        .get_mut("worker")
                        .unwrap()
                        .image = image.image_id.clone()
                }
            }
            seal(&mut changed);
            assert!(check(&changed).is_err(), "mutation {mutation}");
        }
        // A finite partial start retains exactly the same binding; missing
        // containers do not turn its planned development role into another image.
        saved
            .receipt
            .resources
            .as_mut()
            .unwrap()
            .containers
            .remove("signing-keys");
        seal(&mut saved);
        check(&saved).unwrap();
    }
}
