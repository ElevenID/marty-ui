//! Read-only inspection of recorded workloads. Configuration identity is separate
//! from health; no resource is adopted, restarted, removed, or marked Ready.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_graph::{self as graph, Completion},
    installer_application_model::ApplicationModelPlan,
    installer_application_observation as observation, installer_generation_binding as generation,
    installer_runtime::DockerRunner,
    installer_state::LockedInspection,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Installer service inspection refused; preserve recorded resources and recovery evidence";
const BAO: [&str; 4] = [
    "openbao",
    "openbao-bootstrap",
    "openbao-tls-init",
    "openbao-unseal",
];
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| REFUSED.into())
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| REFUSED.into())
}
fn one(raw: &str) -> Result<Value> {
    let v: Value = parse(raw.as_bytes())?;
    let a = v.as_array().ok_or(REFUSED)?;
    require(a.len() == 1 && a[0].is_object())?;
    Ok(a[0].clone())
}
fn ids(raw: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for line in raw.lines() {
        require(id(line) && result.insert(line.into()))?;
    }
    Ok(result)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPlan {
    model: Value,
    selected_services: Vec<String>,
    expected_network_id: String,
    installation_ready: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    containers: BTreeMap<String, String>,
    redis_volume: String,
    network_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaoCreated {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    image: String,
    image_id: String,
    network_id: String,
    container_ids: BTreeMap<String, String>,
}

fn container_ids(map: &BTreeMap<String, String>, roles: &[String]) -> Result<()> {
    require(
        map.keys().cloned().collect::<BTreeSet<_>>() == roles.iter().cloned().collect()
            && map.values().all(|v| id(v))
            && map.values().collect::<BTreeSet<_>>().len() == map.len(),
    )
}

/// Closed fields only: never return Docker error bodies, environment or health logs.
fn lifecycle(c: &Value, completion: Completion) -> Result<Value> {
    let state = &c["State"];
    let status = text(&state["Status"])?;
    require(
        [
            "created",
            "running",
            "exited",
            "paused",
            "restarting",
            "dead",
        ]
        .contains(&status),
    )?;
    let running = state["Running"].as_bool().ok_or(REFUSED)?;
    let paused = state["Paused"].as_bool().ok_or(REFUSED)?;
    let restarting = state["Restarting"].as_bool().ok_or(REFUSED)?;
    let oom = state["OOMKilled"].as_bool().ok_or(REFUSED)?;
    let exit = state["ExitCode"].as_i64().ok_or(REFUSED)?;
    let restarts = c["RestartCount"].as_u64().ok_or(REFUSED)?;
    let health = state["Health"]["Status"].as_str();
    require(health.is_none_or(|h| ["healthy", "unhealthy", "starting"].contains(&h)))?;
    let stable = !paused && !restarting && !oom && restarts == 0;
    let expected = match completion {
        Completion::Healthy => "healthy",
        Completion::ExitedZero => "exited_zero",
        Completion::Running => "running_only",
    };
    let satisfied = stable
        && match completion {
            Completion::Healthy => status == "running" && running && health == Some("healthy"),
            Completion::ExitedZero => status == "exited" && !running && exit == 0,
            Completion::Running => status == "running" && running,
        };
    Ok(
        json!({"status":status,"running":running,"paused":paused,"restarting":restarting,
        "oom_killed":oom,"exit_code":exit,"restart_count":restarts,"health":health,
        "expected":expected,"expected_state_observed":satisfied}),
    )
}

/// A bounded summary of Docker's inspected container configuration. This is
/// emitted only after the complete owned-container observation succeeds. Do not
/// include environment values, mount paths, command arguments or option text.
fn security_posture(c: &Value) -> Result<Value> {
    let host = &c["HostConfig"];
    let user = text(&c["Config"]["User"])?;
    let principal = user.split(':').next().ok_or(REFUSED)?;
    let uid = principal.parse::<u32>().ok();
    let user_class = if principal.is_empty() || principal == "root" || uid == Some(0) {
        "root"
    } else if uid.is_some() {
        "numeric_non_root"
    } else {
        "named_unresolved"
    };
    let options = host["SecurityOpt"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let dropped = host["CapDrop"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let added = host["CapAdd"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mounts = c["Mounts"].as_array().ok_or(REFUSED)?;
    let writable_mounts = mounts.iter().try_fold(0usize, |count, mount| {
        mount["RW"]
            .as_bool()
            .map(|writable| count + usize::from(writable))
            .ok_or_else(|| REFUSED.to_owned())
    })?;
    let ports = &host["PortBindings"];
    let published_ports = if ports.is_null() {
        0
    } else {
        ports.as_object().ok_or(REFUSED)?.len()
    };
    Ok(json!({
        "source":"docker_inspect",
        "user_class":user_class,
        "privileged":host["Privileged"].as_bool().ok_or(REFUSED)?,
        "read_only_rootfs":host["ReadonlyRootfs"].as_bool().ok_or(REFUSED)?,
        "no_new_privileges":options.iter().any(|v| v == "no-new-privileges:true"),
        "cap_drop_all":dropped.iter().any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("all"))),
        "cap_add_count":added.len(),
        "device_count":host["Devices"].as_array().map_or(0, Vec::len),
        "writable_inspected_mount_count":writable_mounts,
        "published_port_count":published_ports,
    }))
}
fn inventory(
    docker: &DockerRunner,
    projects: &[String],
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let all = ids(&docker.run_checked(&["ps", "-aq", "--no-trunc"])?)?;
    let mut scoped = BTreeSet::new();
    for project in projects {
        scoped.extend(ids(&docker.run_checked(&[
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
        ])?)?);
    }
    Ok((all, scoped))
}
fn check_inventory(
    all: &BTreeSet<String>,
    scoped: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> Result<()> {
    require(scoped.is_subset(expected) && scoped.is_subset(all))
}

/// The existing caller owns the installation lock and host observation. Absence
/// of creation receipts is reported as incomplete, never inferred as no resources.
pub fn services(
    state: &LockedInspection,
    installation: &Path,
    docker: &DockerRunner,
) -> Result<Value> {
    inspect(state, installation, docker).map_err(|_| REFUSED.to_owned())
}
fn inspect(state: &LockedInspection, installation: &Path, docker: &DockerRunner) -> Result<Value> {
    if state.cleanup_status()?.state != crate::installer_state::CleanupState::NotStarted {
        return Ok(
            json!({"services_observed":false,"reason":"cleanup_recorded",
            "installation_ready":false}),
        );
    }
    let began = Instant::now();
    let journal = state.journal();
    let engine = &journal.runtime().ok_or(REFUSED)?.engine_id;
    let project = journal.compose_project();
    let installation_id = journal.installation_id().to_string();
    let names = [
        (true, "application-plan.json"),
        (true, "application-compose.json"),
        (true, "application-created-resources.json"),
        (false, "openbao-created.json"),
        (false, "openbao-compose-model.json"),
    ];
    let mut sources = BTreeMap::new();
    for (evidence, name) in names {
        sources.insert(name, state.diagnostic_record(name, evidence)?);
    }
    if sources.values().any(Option::is_none) {
        for (evidence, name) in names {
            require(state.diagnostic_record(name, evidence)? == sources[name])?;
        }
        state.require_unchanged()?;
        return Ok(
            json!({"services_observed":false,"reason":"recorded_creation_inventory_incomplete",
            "missing_records":sources.iter().filter_map(|(k,v)| v.is_none().then_some(*k)).collect::<Vec<_>>(),
            "installation_ready":false}),
        );
    }
    let bytes = |name| sources.get(name).and_then(Option::as_deref).ok_or(REFUSED);
    let saved: SavedPlan = parse(bytes("application-plan.json")?)?;
    let plan = ApplicationModelPlan {
        model: saved.model,
        selected_services: saved.selected_services,
        expected_network_id: saved.expected_network_id,
        installation_ready: saved.installation_ready,
    };
    require(
        !plan.installation_ready
            && plan.model["name"] == project
            && id(&plan.expected_network_id)
            && bytes("application-compose.json")?
                == crate::installer_application::compose_document(&plan.model)?,
    )?;
    let selected = generation::load_verified(installation, &installation_id, engine)?;
    if let Some(g) = &selected {
        generation::verify_model(installation, g, &plan)?;
    } else {
        crate::installer_uninstall::require_no_selected_generation(installation, &plan)?;
    }
    let roles = graph::startup_order(&plan.model, &plan.selected_services)?;
    let created: Created = parse(bytes("application-created-resources.json")?)?;
    container_ids(&created.containers, &roles)?;
    require(
        created.network_id == plan.expected_network_id
            && created.redis_volume == format!("{project}_redis-socket"),
    )?;
    let bao: BaoCreated = parse(bytes("openbao-created.json")?)?;
    let bao_project = format!("{project}-bao");
    require(
        bao.schema == "elevenid.installer-openbao-created/v1"
            && bao.installation_id == installation_id
            && bao.engine_id == *engine
            && bao.project == bao_project
            && bao.network_id == created.network_id
            && bao.image_id.strip_prefix("sha256:").is_some_and(id),
    )?;
    container_ids(
        &bao.container_ids,
        &BAO.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
    )?;
    let bao_model: Value = parse(bytes("openbao-compose-model.json")?)?;
    require(
        bao_model["name"] == bao_project
            && bao_model["services"]
                .as_object()
                .ok_or(REFUSED)?
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BAO.into_iter().collect()
            && bao_model["services"]
                .as_object()
                .ok_or(REFUSED)?
                .values()
                .all(|v| v["image"] == bao.image),
    )?;
    let bao_plan = ApplicationModelPlan {
        model: bao_model,
        selected_services: BAO.iter().map(|r| r.to_string()).collect(),
        expected_network_id: created.network_id.clone(),
        installation_ready: false,
    };
    let expected: BTreeSet<_> = created
        .containers
        .values()
        .chain(bao.container_ids.values())
        .cloned()
        .collect();
    require(expected.len() == created.containers.len() + bao.container_ids.len())?;
    let projects = [project.clone(), bao_project.clone()];
    let (all, scoped) = inventory(docker, &projects)?;
    check_inventory(&all, &scoped, &expected)?;
    let network = one(&docker.run_checked(&["network", "inspect", &created.network_id])?)?;
    let network_name = format!("{bao_project}_default");
    require(
        network["Id"] == created.network_id
            && network["Name"] == network_name
            && plan.model["networks"]["default"]["name"] == network_name
            && bao_plan.model["networks"]["default"]["name"] == network_name
            && network["Labels"]["com.docker.compose.project"] == bao_project
            && network["Labels"]["com.docker.compose.network"] == "default"
            && network["Containers"]
                .as_object()
                .ok_or(REFUSED)?
                .keys()
                .all(|v| expected.contains(v)),
    )?;
    observation::validate_volume(
        &one(&docker.run_checked(&["volume", "inspect", &created.redis_volume])?)?,
        &plan,
    )?;
    let mut images = BTreeMap::new();
    let mut services = BTreeMap::new();
    for (is_bao, model, containers) in [
        (false, &plan, &created.containers),
        (true, &bao_plan, &bao.container_ids),
    ] {
        for (role, container) in containers {
            require(began.elapsed() < Duration::from_secs(120))?;
            if !all.contains(container) {
                services.insert(
                    role.clone(),
                    json!({"container_id":container,"status":"missing",
                    "configuration_verified":false,"expected_state_observed":false}),
                );
                continue;
            }
            let image_name = text(&model.model["services"][role]["image"])?;
            if !images.contains_key(image_name) {
                images.insert(
                    image_name.to_string(),
                    one(&docker.run_checked(&["image", "inspect", image_name])?)?,
                );
            }
            let image = images.get(image_name).ok_or(REFUSED)?;
            let c = one(&docker.run_checked(&["inspect", "--type", "container", container])?)?;
            if is_bao {
                require(image["Id"] == bao.image_id)?;
                observation::validate_openbao_container_for_cleanup(
                    &c, container, role, model, image,
                )?;
            } else {
                observation::validate_container_for_logs(&c, container, role, model, image)?;
            }
            let completion = if is_bao {
                if ["openbao-bootstrap", "openbao-tls-init"].contains(&role.as_str()) {
                    Completion::ExitedZero
                } else if role == "openbao" {
                    Completion::Healthy
                } else {
                    Completion::Running
                }
            } else {
                graph::completion(&plan.model, role)?
            };
            let mut result = lifecycle(&c, completion)?;
            // Diagnostic admission checks configured ports; observed publications
            // must also match before describing a published service as healthy.
            if result["expected_state_observed"] == true {
                if let Some(ports) = c["HostConfig"]["PortBindings"].as_object() {
                    if ports
                        .iter()
                        .any(|(p, v)| c["NetworkSettings"]["Ports"].get(p) != Some(v))
                    {
                        result["expected_state_observed"] = json!(false);
                    }
                }
            }
            result["container_id"] = json!(container);
            result["configuration_verified"] = json!(true);
            result["security_posture"] = security_posture(&c)?;
            services.insert(role.clone(), result);
        }
    }
    let (after, after_scoped) = inventory(docker, &projects)?;
    check_inventory(&after, &after_scoped, &expected)?;
    require(
        all.intersection(&expected)
            .eq(after.intersection(&expected))
            && scoped == after_scoped,
    )?;
    for (evidence, name) in names {
        require(state.diagnostic_record(name, evidence)? == sources[name])?;
    }
    require(
        serde_json::to_vec(&selected).map_err(|_| REFUSED)?
            == serde_json::to_vec(&generation::load_verified(
                installation,
                &installation_id,
                engine,
            )?)
            .map_err(|_| REFUSED)?,
    )?;
    state.require_unchanged()?;
    Ok(
        json!({"services_observed":true,"scope":"recorded_application_and_openbao",
        "not_atomic_snapshot":true,"services":services,"network_id":created.network_id,
        "redis_volume":created.redis_volume,"all_expected_states_observed":services.values().all(|v|v["expected_state_observed"]==true),
        "installation_ready":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn fixture(mode: &str) -> tempfile::TempDir {
        let (root, _) = crate::installer_uninstall::tests::mock(mode);
        let path = root.path().join("ledger.json");
        let mut ledger: Value = parse(&fs::read(&path).unwrap()).unwrap();
        for c in ledger["containers"].as_object_mut().unwrap().values_mut() {
            c["RestartCount"] = json!(0);
            c["State"]["Paused"] = json!(false);
            c["State"]["Restarting"] = json!(false);
            c["State"]["ExitCode"] = json!(0);
            c["State"]["Health"] =
                json!({"Status":"healthy","Log":[{"Output":"private-health-output"}]});
            let role = c["Config"]["Labels"]["com.docker.compose.service"]
                .as_str()
                .unwrap();
            if [
                "openbao-bootstrap",
                "openbao-tls-init",
                "db-migrate",
                "revocation-profile-migrate",
                "kms-initialize",
                "keycloak-configurator",
                "issuance-migrations",
            ]
            .contains(&role)
            {
                c["State"]["Status"] = json!("exited");
                c["State"]["Running"] = json!(false);
            }
        }
        fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        root
    }
    fn inspect_fixture(root: &tempfile::TempDir) -> Result<Value> {
        let installation = root.path().join("install");
        let state = LockedInspection::open(&installation)?;
        let binding = state.journal().runtime().unwrap();
        let docker = DockerRunner::new(
            &root.path().join("docker-stub"),
            &binding.docker_host,
            &binding.engine_id,
            &installation,
        )?;
        docker.preflight()?;
        services(&state, &installation, &docker)
    }
    fn assert_read_only(root: &tempfile::TempDir) {
        let v: Value = parse(&fs::read(root.path().join("ledger.json")).unwrap()).unwrap();
        assert_eq!(v["mutations"], json!([]));
        assert!(v["commands"].as_array().unwrap().iter().all(|a| [
            "info", "compose", "ps", "network", "volume", "image", "inspect"
        ]
        .contains(&a[0].as_str().unwrap())));
        assert_eq!(
            fs::read(root.path().join("install/retained-data")).unwrap(),
            b"private data stays"
        );
    }
    #[test]
    fn actual_mocked_routing_reports_health_missing_and_oom_without_mutation() {
        let root = fixture("success");
        let result = inspect_fixture(&root).unwrap();
        assert_eq!(result["services"].as_object().unwrap().len(), 34);
        assert_eq!(result["all_expected_states_observed"], true);
        assert_eq!(result["installation_ready"], false);
        let postgres_security = &result["services"]["postgres"]["security_posture"];
        assert_eq!(postgres_security["source"], "docker_inspect");
        assert_eq!(postgres_security["privileged"], false);
        assert!(postgres_security["writable_inspected_mount_count"].is_number());
        assert!(postgres_security["published_port_count"].is_number());
        assert!(!result.to_string().contains("private-health-output"));
        let path = root.path().join("ledger.json");
        let mut v: Value = parse(&fs::read(&path).unwrap()).unwrap();
        let map = v["containers"].as_object_mut().unwrap();
        let missing = map
            .iter()
            .find(|(_, c)| c["Config"]["Labels"]["com.docker.compose.service"] == "gateway")
            .unwrap()
            .0
            .clone();
        map.remove(&missing);
        let postgres = map
            .values_mut()
            .find(|c| c["Config"]["Labels"]["com.docker.compose.service"] == "postgres")
            .unwrap();
        postgres["State"]["OOMKilled"] = json!(true);
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
        let result = inspect_fixture(&root).unwrap();
        assert_eq!(result["services"]["gateway"]["status"], "missing");
        assert!(result["services"]["gateway"]
            .get("security_posture")
            .is_none());
        assert_eq!(result["services"]["postgres"]["oom_killed"], true);
        assert_eq!(result["all_expected_states_observed"], false);
        assert_read_only(&root);
    }
    #[test]
    fn security_summary_omits_sensitive_runtime_strings_and_rejects_bad_mount_state() {
        let mut container = json!({
            "Config":{"User":"1001:1001","Env":["CANARY=private-secret"]},
            "HostConfig":{"Privileged":false,"ReadonlyRootfs":true,
                "SecurityOpt":["no-new-privileges:true","private-secret"],
                "CapDrop":["ALL"],"CapAdd":[],"Devices":[],"PortBindings":{}},
            "Mounts":[{"Source":"/private-secret","Destination":"/run/secrets/private-secret","RW":false}]
        });
        let summary = security_posture(&container).unwrap();
        assert_eq!(summary["user_class"], "numeric_non_root");
        assert_eq!(summary["no_new_privileges"], true);
        assert_eq!(summary["cap_drop_all"], true);
        assert_eq!(summary["writable_inspected_mount_count"], 0);
        assert!(!summary.to_string().contains("private-secret"));
        container["HostConfig"]["SecurityOpt"] = Value::Null;
        container["HostConfig"]["CapDrop"] = Value::Null;
        container["HostConfig"]["Devices"] = Value::Null;
        let defaults = security_posture(&container).unwrap();
        assert_eq!(defaults["no_new_privileges"], false);
        assert_eq!(defaults["cap_drop_all"], false);
        assert_eq!(defaults["device_count"], 0);
        container["Mounts"][0]["RW"] = json!("unknown");
        assert!(security_posture(&container).is_err());
    }
    #[test]
    fn actual_mocked_routing_refuses_replacement_foreign_attachment_and_command_failure() {
        for mode in [
            "replacement",
            "unknown",
            "foreign-attachment",
            "command-failure",
        ] {
            let root = fixture(mode);
            assert!(inspect_fixture(&root).is_err(), "{mode}");
            assert_read_only(&root);
        }
        let root = fixture("success");
        let path = root.path().join("ledger.json");
        let mut v: Value = parse(&fs::read(&path).unwrap()).unwrap();
        v["containers"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()["Config"]["Env"] = json!(["UNADMITTED=value"]);
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(inspect_fixture(&root).is_err());
        assert_read_only(&root);
    }
    #[test]
    fn partial_inventory_is_unobserved_and_linked_record_refused() {
        use std::os::unix::fs::symlink;
        let root = fixture("success");
        let evidence = root.path().join("install/evidence");
        let path = evidence.join("application-created-resources.json");
        let held = evidence.join("held-created.json");
        fs::rename(&path, &held).unwrap();
        let result = inspect_fixture(&root).unwrap();
        assert_eq!(result["services_observed"], false);
        symlink(&held, &path).unwrap();
        assert!(inspect_fixture(&root).is_err());
        assert_read_only(&root);
    }
    fn running() -> Value {
        json!({"RestartCount":0,"State":{"Status":"running","Running":true,
        "Paused":false,"Restarting":false,"OOMKilled":false,"ExitCode":0,"Health":{"Status":"healthy","Log":["private"]}}})
    }
    #[test]
    fn diagnostic_identity_is_not_health() {
        let mut c = running();
        assert_eq!(
            lifecycle(&c, Completion::Healthy).unwrap()["expected_state_observed"],
            true
        );
        for field in ["OOMKilled", "Paused", "Restarting"] {
            c = running();
            c["State"][field] = json!(true);
            assert_eq!(
                lifecycle(&c, Completion::Healthy).unwrap()["expected_state_observed"],
                false
            );
        }
        c = running();
        c["RestartCount"] = json!(1);
        assert_eq!(
            lifecycle(&c, Completion::Healthy).unwrap()["expected_state_observed"],
            false
        );
        c = running();
        c["State"]["Health"]["Status"] = json!("unhealthy");
        assert_eq!(
            lifecycle(&c, Completion::Healthy).unwrap()["expected_state_observed"],
            false
        );
        assert_eq!(
            lifecycle(&c, Completion::Running).unwrap()["expected"],
            "running_only"
        );
        assert!(!lifecycle(&c, Completion::Running)
            .unwrap()
            .to_string()
            .contains("private"));
    }
    #[test]
    fn initializer_requires_terminal_zero_and_no_oom() {
        let mut c = running();
        assert_eq!(
            lifecycle(&c, Completion::ExitedZero).unwrap()["expected_state_observed"],
            false
        );
        c["State"]["Status"] = json!("exited");
        c["State"]["Running"] = json!(false);
        assert_eq!(
            lifecycle(&c, Completion::ExitedZero).unwrap()["expected_state_observed"],
            true
        );
        c["State"]["ExitCode"] = json!(1);
        assert_eq!(
            lifecycle(&c, Completion::ExitedZero).unwrap()["expected_state_observed"],
            false
        );
    }
    #[test]
    fn recorded_ids_cannot_be_duplicated_or_replaced_by_project_discovery() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let expected = BTreeSet::from([a.clone()]);
        check_inventory(&BTreeSet::new(), &BTreeSet::new(), &expected).unwrap();
        assert!(check_inventory(
            &BTreeSet::from([b.clone()]),
            &BTreeSet::from([b.clone()]),
            &expected
        )
        .is_err());
        assert!(container_ids(
            &BTreeMap::from([("one".into(), a.clone()), ("two".into(), a)]),
            &["one".into(), "two".into()]
        )
        .is_err());
        assert!(container_ids(&BTreeMap::from([("other".into(), b)]), &["one".into()]).is_err());
    }
}
