//! Create an entire owned application before starting any workload. No adoption,
//! recreation, automatic cleanup or retry after uncertain mutation is permitted.
//! This stage reports observed startup only, never installation readiness.
#![cfg(target_os = "linux")]
use crate::{
    installer_application::{compose_document, PreparedApplication},
    installer_application_graph::{self as graph, Completion},
    installer_application_model::ApplicationModelPlan,
    installer_application_observation::{self as observation, ContainerPhase},
    installer_openbao::{self, OpenBaoInventory},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_verify,
};
use chrono::DateTime;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    thread,
    time::{Duration, Instant},
};
use uuid::{Variant, Version};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Application startup refused; preserve owned resources and installation evidence for recovery";
const ROLE_TIMEOUT: Duration = Duration::from_secs(600);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Serialize)]
pub struct ApplicationStartReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub project: String,
    pub engine_id: String,
    pub network_id: String,
    pub containers: BTreeMap<String, String>,
    pub redis_volume: String,
    pub completed_initializers: Vec<String>,
    pub healthy_services: Vec<String>,
    pub running_workers: Vec<String>,
    pub installation_ready: bool,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn validate_selected_inputs(
    plan: &ApplicationModelPlan,
    installation: &Path,
    bundle: &Path,
    state: &InstallerState,
) -> Result<()> {
    let journal = state.journal();
    let generation = crate::installer_generation_binding::load_verified(
        installation,
        &journal.installation_id().to_string(),
        &journal.runtime().ok_or(REFUSED)?.engine_id,
    )?;
    observation::validate_inputs_with_generation(plan, installation, bundle, generation.as_ref())
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| REFUSED.into())
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn object_output(output: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(output).map_err(|_| REFUSED)?;
    let array = v.as_array().ok_or(REFUSED)?;
    require(array.len() == 1 && array[0].is_object())?;
    Ok(array[0].clone())
}
/// Capture creation-time identity evidence available for a Docker volume.
/// Docker does not expose an immutable volume ID, so later removal must also
/// recheck the exact engine, name, timestamp and complete label map.
fn volume_creation_evidence(
    observed: &Value,
    installation_id: &str,
    engine_id: &str,
    name: &str,
) -> Result<Value> {
    let owner = uuid::Uuid::parse_str(installation_id).map_err(|_| REFUSED)?;
    let project = format!("marty-install-{}", owner.simple());
    require(
        owner.get_version() == Some(Version::Random)
            && owner.get_variant() == Variant::RFC4122
            && name == format!("{project}_redis-socket")
            && !engine_id.is_empty()
            && engine_id.len() <= 128
            && engine_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b)),
    )?;
    let created_at = text(&observed["CreatedAt"])?;
    let labels = observed["Labels"].as_object().ok_or(REFUSED)?;
    require(
        observed["Name"] == name
            && observed["Driver"] == "local"
            && observed["Scope"] == "local"
            && (observed["Options"].is_null() || observed["Options"] == json!({}))
            && created_at.len() <= 64
            && DateTime::parse_from_rfc3339(created_at).is_ok()
            && (2..=8).contains(&labels.len())
            && labels.get("com.docker.compose.project") == Some(&json!(project))
            && labels.get("com.docker.compose.volume") == Some(&json!("redis-socket"))
            && labels.iter().all(|(key, value)| {
                !key.is_empty()
                    && key.len() <= 128
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && value
                        .as_str()
                        .is_some_and(|v| v.len() <= 256 && !v.chars().any(char::is_control))
            }),
    )?;
    Ok(json!({
        "schema": "elevenid.installer-created-volume/v1",
        "installation_id": installation_id,
        "engine_id": engine_id,
        "name": name,
        "created_at": created_at,
        "labels": labels,
        "driver": "local",
        "scope": "local"
    }))
}
fn inspect(docker: &DockerRunner, container: &str) -> Result<Value> {
    require(id(container))?;
    object_output(&docker.run_checked(&["inspect", "--type", "container", container])?)
}
fn identifiers(output: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for line in output.lines() {
        require(id(line) && result.insert(line.to_owned()))?;
    }
    Ok(result)
}
fn project_ids(docker: &DockerRunner, project: &str) -> Result<BTreeSet<String>> {
    let label = format!("label=com.docker.compose.project={project}");
    identifiers(&docker.run_checked(&["ps", "-aq", "--no-trunc", "--filter", &label])?)
}
fn application_name_filter(project: &str, roles: &[String]) -> String {
    format!(
        "name=^/{}-({})-1$",
        regex::escape(project),
        roles
            .iter()
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|")
    )
}
fn fresh(docker: &DockerRunner, project: &str, volume: &str, roles: &[String]) -> Result<()> {
    require(project_ids(docker, project)?.is_empty())?;
    let names = application_name_filter(project, roles);
    require(
        docker
            .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &names])?
            .trim()
            .is_empty(),
    )?;
    let label = format!("label=com.docker.compose.project={project}");
    let volume_name = format!("name=^{volume}$");
    for args in [
        vec!["volume", "ls", "-q", "--filter", &label],
        vec!["volume", "ls", "-q", "--filter", &volume_name],
        vec!["network", "ls", "-q", "--filter", &label],
    ] {
        require(docker.run_checked(&args)?.trim().is_empty())?;
    }
    Ok(())
}
fn persist(state: &mut InstallerState, name: &str, value: &impl Serialize) -> Result<()> {
    state.write_evidence(name, &serde_json::to_vec(value).map_err(|_| REFUSED)?)
}
fn bound_document(installation: &Path, plan: &ApplicationModelPlan) -> Result<()> {
    require(
        installer_verify::read_private_bytes(
            &installation.join("evidence/application-compose.json"),
            4 * 1024 * 1024,
        )? == compose_document(&plan.model)?,
    )?;
    require(
        installer_verify::read_private_bytes(
            &installation.join("evidence/application-plan.json"),
            4 * 1024 * 1024,
        )? == serde_json::to_vec(plan).map_err(|_| REFUSED)?,
    )
}
fn image_for<'a>(
    plan: &ApplicationModelPlan,
    images: &'a BTreeMap<String, Value>,
    role: &str,
) -> Result<&'a Value> {
    images
        .get(text(&plan.model["services"][role]["image"])?)
        .ok_or_else(|| REFUSED.into())
}
fn container_map(
    observed: &[Value],
    project: &str,
    roles: &[String],
) -> Result<BTreeMap<String, String>> {
    let expected: BTreeSet<_> = roles.iter().cloned().collect();
    require(expected.len() == roles.len())?;
    let mut mapped = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for c in observed {
        let container = text(&c["Id"])?;
        let labels = &c["Config"]["Labels"];
        let role = text(&labels["com.docker.compose.service"])?;
        require(
            id(container)
                && ids.insert(container.to_owned())
                && labels["com.docker.compose.project"] == project
                && expected.contains(role)
                && mapped
                    .insert(role.to_owned(), container.to_owned())
                    .is_none(),
        )?;
    }
    require(mapped.keys().cloned().collect::<BTreeSet<_>>() == expected)?;
    Ok(mapped)
}
/// Return a validated stable phase, refusing failed/restarted/paused workloads.
/// A running initializer or a healthy-service start period may still be pending.
fn readiness(c: &Value, completion: Completion) -> Result<bool> {
    require(
        c["RestartCount"] == 0
            && c["State"]["OOMKilled"] == false
            && c["State"]["Paused"] == false
            && c["State"]["Restarting"] == false,
    )?;
    match (completion, c["State"]["Status"].as_str()) {
        (Completion::ExitedZero, Some("exited")) => {
            require(c["State"]["ExitCode"] == 0 && c["State"]["Running"] == false)?;
            Ok(true)
        }
        (Completion::ExitedZero, Some("running")) => Ok(false),
        (Completion::Running, Some("running")) => {
            require(c["State"]["Running"] == true)?;
            Ok(true)
        }
        (Completion::Healthy, Some("running")) => match c["State"]["Health"]["Status"].as_str() {
            Some("healthy") => Ok(true),
            Some("starting") => Ok(false),
            _ => Err(REFUSED.into()),
        },
        _ => Err(REFUSED.into()),
    }
}
fn observed_role(
    docker: &DockerRunner,
    plan: &ApplicationModelPlan,
    images: &BTreeMap<String, Value>,
    role: &str,
    container: &str,
) -> Result<bool> {
    let c = inspect(docker, container)?;
    let completion = graph::completion(&plan.model, role)?;
    let ready = readiness(&c, completion)?;
    let phase = if c["State"]["Status"] == "exited" {
        ContainerPhase::ExitedSuccessfully
    } else {
        ContainerPhase::Running
    };
    observation::validate_container(
        &c,
        container,
        role,
        plan,
        image_for(plan, images, role)?,
        phase,
    )?;
    Ok(ready)
}
fn check_dependencies(
    docker: &DockerRunner,
    plan: &ApplicationModelPlan,
    images: &BTreeMap<String, Value>,
    containers: &BTreeMap<String, String>,
    role: &str,
) -> Result<()> {
    if let Some(deps) = plan.model["services"][role]["depends_on"].as_object() {
        for dependency in deps.keys() {
            require(observed_role(
                docker,
                plan,
                images,
                dependency,
                containers.get(dependency).ok_or(REFUSED)?,
            )?)?;
        }
    }
    Ok(())
}

/// Caller must hold the installation lock and provide the freshly prepared,
/// authenticated plan. Every mutation has exclusive durable evidence first.
/// On error leave all containers, volumes and inputs intact; recovery is explicit.
pub fn start(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    prepared: PreparedApplication,
) -> Result<ApplicationStartReceipt> {
    state.require_live_phase(Phase::Provisioning)?;
    let PreparedApplication {
        plan,
        origin: _,
        port_reservations,
    } = prepared;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let project = state.journal().compose_project();
    let installation_id = state.journal().installation_id().to_string();
    require(
        plan.model["name"] == project
            && plan.expected_network_id == bao.network_id
            && !plan.installation_ready,
    )?;
    let roles = graph::startup_order(&plan.model, &plan.selected_services)?;
    let volume = text(&plan.model["volumes"]["redis-socket"]["name"])?.to_owned();
    require(volume == format!("{project}_redis-socket"))?;
    bound_document(installation, &plan)?;
    validate_selected_inputs(&plan, installation, bundle, state)?;
    let docker = DockerRunner::new(
        dockerpath,
        &binding.docker_host,
        &binding.engine_id,
        installation,
    )?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    fresh(&docker, &project, &volume, &roles)?;
    persist(
        state,
        "application-start-intent.json",
        &json!({"schema":"elevenid.installer-application-start-intent/v1",
        "installation_id":installation_id,"project":project,"engine_id":binding.engine_id,
        "network_id":plan.expected_network_id,"roles":roles,"redis_volume":volume,"installation_ready":false}),
    )?;
    let mut images = BTreeMap::new();
    for role in &roles {
        let reference = text(&plan.model["services"][role]["image"])?;
        require(
            reference
                .split_once("@sha256:")
                .is_some_and(|(repo, digest)| {
                    !repo.is_empty() && !repo.starts_with('-') && id(digest)
                }),
        )?;
        if images.contains_key(reference) {
            continue;
        }
        state.require_live_phase(Phase::Provisioning)?;
        docker.run_checked_with_timeout(&["pull", reference], Duration::from_secs(600))?;
        let image = object_output(&docker.run_checked(&["image", "inspect", reference])?)?;
        observation::validate_image_digest(&image, reference)?;
        images.insert(reference.to_owned(), image);
    }
    bound_document(installation, &plan)?;
    validate_selected_inputs(&plan, installation, bundle, state)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    fresh(&docker, &project, &volume, &roles)?;
    state.require_live_phase(Phase::Provisioning)?;
    let document = installation.join("evidence/application-compose.json");
    let env = installation.join("evidence/application.env");
    let mut args = vec![
        "compose",
        "--project-name",
        &project,
        "--env-file",
        env.to_str().ok_or(REFUSED)?,
        "-f",
        document.to_str().ok_or(REFUSED)?,
        "--profile",
        "*",
        "create",
        "--no-build",
        "--pull",
        "never",
    ];
    args.extend(roles.iter().map(String::as_str));
    docker.run_checked_with_timeout(&args, Duration::from_secs(600))?;
    let discovered = project_ids(&docker, &project)?;
    // Persist even an incomplete set before inspecting. A create failure above
    // leaves the prior intent; neither path is safe to rerun automatically.
    persist(
        state,
        "application-discovered-resources.json",
        &json!({"container_ids":discovered,"redis_volume":volume}),
    )?;
    let observed = discovered
        .iter()
        .map(|container| inspect(&docker, container))
        .collect::<Result<Vec<_>>>()?;
    let containers = container_map(&observed, &project, &roles)?;
    persist(
        state,
        "application-created-resources.json",
        &json!({"containers":containers,"redis_volume":volume,"network_id":plan.expected_network_id}),
    )?;
    let volume_observed = object_output(&docker.run_checked(&["volume", "inspect", &volume])?)?;
    observation::validate_volume(&volume_observed, &plan)?;
    let volume_identity = volume_creation_evidence(
        &volume_observed,
        &installation_id,
        &binding.engine_id,
        &volume,
    )?;
    persist(state, "application-created-volume.json", &volume_identity)?;
    for c in &observed {
        let role = text(&c["Config"]["Labels"]["com.docker.compose.service"])?;
        observation::validate_container(
            c,
            containers.get(role).ok_or(REFUSED)?,
            role,
            &plan,
            image_for(&plan, &images, role)?,
            ContainerPhase::Created,
        )?;
        require(c["RestartCount"] == 0)?;
    }
    // Last complete filesystem admission precedes the first workload. Legitimate
    // postgres/redis initialization can change ownership of their state roots.
    validate_selected_inputs(&plan, installation, bundle, state)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    require(project_ids(&docker, &project)? == discovered)?;
    persist(
        state,
        "application-prestart-admission.json",
        &json!({"containers":containers,"network_id":plan.expected_network_id,"all_created":true}),
    )?;
    let began = Instant::now();
    let mut reservations = Some(port_reservations);
    for role in &roles {
        require(began.elapsed() < STARTUP_TIMEOUT)?;
        state.require_live_phase(Phase::Provisioning)?;
        installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
        require(project_ids(&docker, &project)? == discovered)?;
        check_dependencies(&docker, &plan, &images, &containers, role)?;
        let container = containers.get(role).ok_or(REFUSED)?;
        observation::validate_container(
            &inspect(&docker, container)?,
            container,
            role,
            &plan,
            image_for(&plan, &images, role)?,
            ContainerPhase::Created,
        )?;
        persist(
            state,
            &format!("application-start-{role}.json"),
            &json!({"service":role,"container_id":container}),
        )?;
        if role == "installer-ingress" {
            drop(reservations.take());
        }
        docker.run_checked(&["start", container])?;
        let started = Instant::now();
        loop {
            require(started.elapsed() < ROLE_TIMEOUT && began.elapsed() < STARTUP_TIMEOUT)?;
            if observed_role(&docker, &plan, &images, role, container)? {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        persist(
            state,
            &format!("application-observed-{role}.json"),
            &json!({"service":role,"container_id":container,
            "completed_successfully":graph::completion(&plan.model,role)? == Completion::ExitedZero,"installation_ready":false}),
        )?;
    }
    let mut completed_initializers = Vec::new();
    let mut healthy_services = Vec::new();
    let mut running_workers = Vec::new();
    for role in &roles {
        require(observed_role(
            &docker,
            &plan,
            &images,
            role,
            containers.get(role).ok_or(REFUSED)?,
        )?)?;
        match graph::completion(&plan.model, role)? {
            Completion::ExitedZero => completed_initializers.push(role.clone()),
            Completion::Healthy => healthy_services.push(role.clone()),
            Completion::Running => running_workers.push(role.clone()),
        }
    }
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    require(project_ids(&docker, &project)? == discovered)?;
    let final_volume = object_output(&docker.run_checked(&["volume", "inspect", &volume])?)?;
    observation::validate_volume(&final_volume, &plan)?;
    require(
        volume_creation_evidence(&final_volume, &installation_id, &binding.engine_id, &volume)?
            == volume_identity,
    )?;
    let receipt = ApplicationStartReceipt {
        schema: "elevenid.installer-application-start/v1",
        installation_id,
        project,
        engine_id: binding.engine_id,
        network_id: plan.expected_network_id,
        containers,
        redis_volume: volume,
        completed_initializers,
        healthy_services,
        running_workers,
        installation_ready: false,
    };
    persist(state, "application-start-result.json", &receipt)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collision_filter_excludes_existing_bao_but_includes_exact_application_names() {
        let filter = application_name_filter(
            "marty-install-owned",
            &["postgres".into(), "installer-ingress".into()],
        );
        let regex = regex::Regex::new(filter.strip_prefix("name=").unwrap()).unwrap();
        assert!(regex.is_match("/marty-install-owned-postgres-1"));
        assert!(regex.is_match("/marty-install-owned-installer-ingress-1"));
        assert!(!regex.is_match("/marty-install-owned-bao-openbao-1"));
        assert!(!regex.is_match("/marty-install-foreign-postgres-1"));
    }
    #[test]
    fn persisted_full_model_is_bound_beyond_small_receipt_limit() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let evidence = root.path().join("evidence");
        fs::create_dir(&evidence).unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).unwrap();
        let plan = ApplicationModelPlan {
            model: json!({"synthetic_large_document":"x".repeat(70000)}),
            selected_services: vec![],
            expected_network_id: "a".repeat(64),
            installation_ready: false,
        };
        for (name, bytes) in [
            (
                "application-compose.json",
                compose_document(&plan.model).unwrap(),
            ),
            ("application-plan.json", serde_json::to_vec(&plan).unwrap()),
        ] {
            let path = evidence.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        bound_document(root.path(), &plan).unwrap();
        fs::write(evidence.join("application-compose.json"), b"{}").unwrap();
        assert!(bound_document(root.path(), &plan).is_err());
    }
    #[test]
    fn inventory_requires_exact_unique_roles_and_ids() {
        let c = |role: &str, id: &str| json!({"Id":id,"Config":{"Labels":{"com.docker.compose.project":"owned","com.docker.compose.service":role}}});
        let roles = vec!["a".into(), "b".into()];
        let good = vec![c("a", &"a".repeat(64)), c("b", &"b".repeat(64))];
        assert_eq!(container_map(&good, "owned", &roles).unwrap().len(), 2);
        for bad in [
            vec![good[0].clone()],
            vec![good[0].clone(), good[0].clone()],
            vec![good[0].clone(), c("c", &"c".repeat(64))],
            vec![good[0].clone(), c("b", &"a".repeat(64))],
        ] {
            assert!(container_map(&bad, "owned", &roles).is_err());
        }
        assert!(container_map(&good, "foreign", &roles).is_err());
    }
    #[test]
    fn readiness_requires_success_health_and_no_restarts() {
        let base = json!({"RestartCount":0,"State":{"Status":"running","Running":true,"OOMKilled":false,"Paused":false,"Restarting":false,"Health":{"Status":"starting"}}});
        assert!(!readiness(&base, Completion::Healthy).unwrap());
        assert!(readiness(&base, Completion::Running).unwrap());
        let mut c = base.clone();
        c["State"]["Health"]["Status"] = json!("healthy");
        assert!(readiness(&c, Completion::Healthy).unwrap());
        c["RestartCount"] = json!(1);
        assert!(readiness(&c, Completion::Healthy).is_err());
        assert!(readiness(&c, Completion::Running).is_err());
        c = base.clone();
        c["State"]["Health"]["Status"] = json!("unhealthy");
        assert!(readiness(&c, Completion::Healthy).is_err());
        c = base;
        c["State"]["Status"] = json!("exited");
        c["State"]["Running"] = json!(false);
        c["State"]["ExitCode"] = json!(0);
        assert!(readiness(&c, Completion::ExitedZero).unwrap());
        assert!(readiness(&c, Completion::Healthy).is_err());
        c["State"]["ExitCode"] = json!(1);
        assert!(readiness(&c, Completion::ExitedZero).is_err());
    }
    #[test]
    fn output_decoders_reject_ambiguous_or_partial_identity() {
        assert!(identifiers("short\n").is_err());
        assert!(identifiers(&format!("{0}\n{0}\n", "a".repeat(64))).is_err());
        assert!(object_output("[]").is_err());
        assert!(object_output("[{},{}]").is_err());
        assert!(object_output("[null]").is_err());
        assert!(object_output("[{}]").is_ok());
    }
    #[test]
    fn volume_creation_evidence_binds_full_identity_without_host_mountpoint() {
        let installation_id = "12345678-1234-4234-8234-123456789abc";
        let project = "marty-install-12345678123442348234123456789abc";
        let name = format!("{project}_redis-socket");
        let observed = json!({
            "Name": &name,
            "Driver": "local",
            "Scope": "local",
            "CreatedAt": "2026-10-27T12:30:00Z",
            "Options": null,
            "Mountpoint": "/var/lib/docker/volumes/private-data/_data",
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.volume": "redis-socket",
                "com.docker.compose.version": "2.39.0"
            }
        });
        let receipt =
            volume_creation_evidence(&observed, installation_id, "engine", &name).unwrap();
        assert_eq!(receipt["created_at"], observed["CreatedAt"]);
        assert_eq!(receipt["labels"], observed["Labels"]);
        assert_eq!(receipt["engine_id"], "engine");
        assert!(!receipt.to_string().contains("/var/lib/docker"));
        for (field, value) in [
            ("Name", json!("foreign")),
            ("Driver", json!("remote")),
            ("Scope", json!("global")),
            ("CreatedAt", json!("not-a-timestamp")),
            ("Options", json!({"device": "/foreign"})),
        ] {
            let mut changed = observed.clone();
            changed[field] = value;
            assert!(
                volume_creation_evidence(&changed, installation_id, "engine", &name).is_err(),
                "{field}"
            );
        }
        let mut changed = observed.clone();
        changed["Labels"]["com.docker.compose.version"] = json!("unsafe\nlabel");
        assert!(volume_creation_evidence(&changed, installation_id, "engine", &name).is_err());
        let mut changed = observed.clone();
        changed["Labels"]["com.docker.compose.project"] = json!("foreign");
        assert!(volume_creation_evidence(&changed, installation_id, "engine", &name).is_err());
        assert!(volume_creation_evidence(&observed, "not-a-uuid", "engine", &name).is_err());
        assert!(volume_creation_evidence(&observed, installation_id, "bad engine", &name).is_err());
    }
}
