//! Scoped runtime removal. Host data, credentials, image cache and the Redis
//! volume are deliberately retained. A separate pre-application mode removes
//! only recorded Bao resources after proving all application resources absent.
//! Other incomplete provisioning and live helpers still require separate recovery.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_graph as graph,
    installer_application_model::ApplicationModelPlan,
    installer_application_observation::{
        validate_container_for_logs, validate_openbao_container_for_cleanup, validate_volume,
    },
    installer_runtime::DockerRunner,
    installer_state::{LockedMaintenance, Phase},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Scoped uninstall refused or interrupted; preserve installation data and cleanup receipts. Incomplete provisioning helpers require explicit recovery";
const BAO: [&str; 4] = [
    "openbao-unseal",
    "openbao",
    "openbao-bootstrap",
    "openbao-tls-init",
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
fn object(output: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(output).map_err(|_| REFUSED)?;
    let a = v.as_array().ok_or(REFUSED)?;
    require(a.len() == 1 && a[0].is_object())?;
    Ok(a[0].clone())
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| REFUSED.into())
}
fn ids(output: &str) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for line in output.lines() {
        require(id(line) && set.insert(line.into()))?;
    }
    Ok(set)
}
struct Arguments {
    installation: PathBuf,
    docker: PathBuf,
}
fn arguments(args: &[String]) -> Result<Arguments> {
    require(args.len().is_multiple_of(2))?;
    let mut map = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--docker-bin"].contains(&pair[0].as_str())
                && map.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*map.get("--install-dir").ok_or(REFUSED)?);
    let docker = PathBuf::from(*map.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    require(installation.is_absolute() && docker.is_absolute())?;
    Ok(Arguments {
        installation,
        docker,
    })
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
struct StartIntent {
    schema: String,
    installation_id: String,
    project: String,
    engine_id: String,
    network_id: String,
    roles: Vec<String>,
    redis_volume: String,
    installation_ready: bool,
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Resource {
    role: String,
    container_id: String,
    bao: bool,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CleanupPlan {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    network_id: String,
    network_name: String,
    retained_redis_volume: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    absent_redis_volume: Option<String>,
    resources: Vec<Resource>,
    source_hashes: BTreeMap<String, String>,
}
impl CleanupPlan {
    fn pre_application(&self) -> bool {
        self.schema == "elevenid.installer-uninstall-pre-application-plan/v1"
    }
}
struct Loaded {
    installation: PathBuf,
    generation: Option<crate::installer_generation_binding::GenerationBinding>,
    plan: CleanupPlan,
    application: ApplicationModelPlan,
    bao: ApplicationModelPlan,
    bao_image_id: String,
    sources: BTreeMap<String, Vec<u8>>,
    helper_ids: BTreeSet<String>,
}
// Legacy installations may lack renewal only when no stage data exists.
// read_record deliberately refuses directories, links and unreadable entries:
// in the absence branch any such marker means an uncertain partial stage.
fn renewal_present(state: &LockedMaintenance) -> Result<bool> {
    if state
        .read_evidence("renewal-container-removed.json")?
        .is_some()
    {
        return Ok(true);
    }
    for marker in [
        "renewal-pending.json",
        "renewal-container.json",
        "renewal-result.json",
    ] {
        require(state.read_evidence(marker)?.is_none())?;
    }
    for marker in ["renewal-inputs", "renewal-transfer"] {
        require(state.read_record(marker)?.is_none())?;
    }
    Ok(false)
}
// Candidate production is separate from activation. Even without an active
// candidate, a partial helper must block normal uninstall and retain custody.
fn generation_present(state: &LockedMaintenance) -> Result<bool> {
    if state
        .read_evidence("generation-container-removed.json")?
        .is_some()
    {
        require(renewal_present(state)?)?;
        return Ok(true);
    }
    for marker in [
        "generation-pending.json",
        "generation-container.json",
        "generation-result.json",
        "generation-observation.json",
    ] {
        require(state.read_evidence(marker)?.is_none())?;
    }
    for marker in [
        "generation-inputs",
        "generation-identity",
        "generation-transfer",
    ] {
        require(state.read_record(marker)?.is_none())?;
    }
    Ok(false)
}
fn source(
    state: &LockedMaintenance,
    root: bool,
    name: &str,
    sources: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    let bytes = if root {
        state.read_record(name)?
    } else {
        state.read_evidence(name)?
    }
    .ok_or(REFUSED)?;
    sources.insert(
        format!("{}/{name}", if root { "root" } else { "evidence" }),
        bytes.clone(),
    );
    Ok(bytes)
}
pub(crate) fn require_no_selected_generation(
    installation: &Path,
    plan: &ApplicationModelPlan,
) -> Result<()> {
    let root = installation.join("application-generation");
    let check = |value: &Value| -> Result<()> {
        let value = text(value)?;
        require(!value.replace("$$", "").contains('$'))?;
        require(!Path::new(&value.replace("$$", "$")).starts_with(&root))
    };
    if let Some(declarations) = plan.model.get("secrets") {
        for declaration in declarations.as_object().ok_or(REFUSED)?.values() {
            check(&declaration["file"])?;
        }
    }
    for service in plan.model["services"].as_object().ok_or(REFUSED)?.values() {
        for mount in service["volumes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if mount["type"] == "bind" {
                check(&mount["source"])?;
            }
        }
    }
    Ok(())
}
fn load(state: &LockedMaintenance, installation: &Path) -> Result<Loaded> {
    let journal = state.journal();
    let binding = journal.runtime().ok_or(REFUSED)?;
    let project = journal.compose_project();
    let installation_id = journal.installation_id().to_string();
    let mut sources = BTreeMap::new();
    let saved: SavedPlan = parse(&source(
        state,
        false,
        "application-plan.json",
        &mut sources,
    )?)?;
    require(
        !saved.installation_ready
            && saved.model["name"] == project
            && id(&saved.expected_network_id),
    )?;
    let application = ApplicationModelPlan {
        model: saved.model,
        selected_services: saved.selected_services,
        expected_network_id: saved.expected_network_id,
        installation_ready: false,
    };
    let generation = crate::installer_generation_binding::load_verified(
        installation,
        &installation_id,
        &binding.engine_id,
    )?;
    if let Some(generation) = &generation {
        require(generation_present(state)?)?;
        crate::installer_generation_binding::verify_model(installation, generation, &application)?;
        for name in [
            "application-generation-pending.json",
            "application-generation.json",
            "application-generation-selection.json",
        ] {
            source(state, false, name, &mut sources)?;
        }
    } else {
        require_no_selected_generation(installation, &application)?;
    }
    let mut order = crate::installer_application_graph::startup_order(
        &application.model,
        &application.selected_services,
    )?;
    let pre_application = state
        .read_evidence("application-created-resources.json")?
        .is_none();
    let (containers, redis_volume, network_id) = if pre_application {
        require(journal.phase() == Phase::Provisioning)?;
        pre_application_records_absent(state, &order)?;
        let intent: StartIntent = parse(&source(
            state,
            false,
            "application-start-intent.json",
            &mut sources,
        )?)?;
        require(
            intent.schema == "elevenid.installer-application-start-intent/v1"
                && intent.installation_id == installation_id
                && intent.project == project
                && intent.engine_id == binding.engine_id
                && intent.network_id == application.expected_network_id
                && intent.roles == order
                && intent.redis_volume == format!("{project}_redis-socket")
                && !intent.installation_ready,
        )?;
        (BTreeMap::new(), intent.redis_volume, intent.network_id)
    } else {
        let created: Created = parse(&source(
            state,
            false,
            "application-created-resources.json",
            &mut sources,
        )?)?;
        require(
            created.network_id == application.expected_network_id
                && created.redis_volume == format!("{project}_redis-socket")
                && created.containers.keys().cloned().collect::<BTreeSet<_>>()
                    == order.iter().cloned().collect(),
        )?;
        (created.containers, created.redis_volume, created.network_id)
    };
    require(
        source(state, false, "application-compose.json", &mut sources)?
            == crate::installer_application::compose_document(&application.model)?,
    )?;
    let bao_created: BaoCreated =
        parse(&source(state, true, "openbao-created.json", &mut sources)?)?;
    require(
        bao_created.schema == "elevenid.installer-openbao-created/v1"
            && bao_created.installation_id == installation_id
            && bao_created.engine_id == binding.engine_id
            && bao_created.project == format!("{project}-bao")
            && bao_created.network_id == network_id
            && bao_created.image_id.strip_prefix("sha256:").is_some_and(id)
            && bao_created
                .container_ids
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BAO.into_iter().collect(),
    )?;
    let model: Value = parse(&source(
        state,
        true,
        "openbao-compose-model.json",
        &mut sources,
    )?)?;
    let network_name = format!("{project}-bao_default");
    require(
        model["name"] == bao_created.project
            && model["networks"]["default"]["name"] == network_name
            && application.model["networks"]["default"]["name"] == network_name,
    )?;
    let model_roles = model["services"].as_object().ok_or(REFUSED)?;
    require(
        model_roles
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BAO.into_iter().collect()
            && model_roles
                .values()
                .all(|s| s["image"] == bao_created.image),
    )?;
    let bao = ApplicationModelPlan {
        model,
        selected_services: BAO.iter().map(|s| s.to_string()).collect(),
        expected_network_id: network_id.clone(),
        installation_ready: false,
    };
    let mut helper_ids = BTreeSet::new();
    let mut helpers = vec![
        ("keycloak", "elevenid.installer-keycloak/v1"),
        ("tls", "elevenid.installer-tls/v1"),
        ("ingress", "elevenid.installer-ingress-host/v1"),
    ];
    if renewal_present(state)? {
        helpers.push(("renewal", "elevenid.installer-renewal-host/v1"));
    }
    if generation_present(state)? {
        helpers.push(("generation", "elevenid.installer-generation-host/v1"));
    }
    for (stage, schema) in helpers {
        let record: Value = parse(&source(
            state,
            false,
            &format!("{stage}-container-removed.json"),
            &mut sources,
        )?)?;
        let container = text(&record["container_id"])?;
        require(
            record["schema"] == schema
                && record["installation_id"] == installation_id
                && record["engine_id"] == binding.engine_id
                && record["network_id"] == network_id
                && record["container_removed"] == true
                && id(container)
                && helper_ids.insert(container.to_owned()),
        )?;
        if pre_application {
            let mut result: Value = parse(&source(
                state,
                false,
                &format!("{stage}-result.json"),
                &mut sources,
            )?)?;
            require(result["container_removed"] == false && result["installation_ready"] == false)?;
            result["container_removed"] = json!(true);
            require(result == record)?;
        }
    }
    order.reverse();
    let mut resources = Vec::new();
    for role in order.into_iter().filter(|_| !pre_application) {
        resources.push(Resource {
            container_id: containers[&role].clone(),
            role,
            bao: false,
        });
    }
    for role in BAO {
        resources.push(Resource {
            container_id: bao_created.container_ids[role].clone(),
            role: role.into(),
            bao: true,
        });
    }
    let unique: BTreeSet<_> = resources.iter().map(|r| r.container_id.as_str()).collect();
    require(
        resources.len() == if pre_application { 4 } else { 34 }
            && unique.len() == resources.len()
            && unique.iter().all(|s| id(s))
            && helper_ids.iter().all(|s| !unique.contains(s.as_str())),
    )?;
    let hashes = sources
        .iter()
        .map(|(name, bytes)| (name.clone(), format!("{:x}", Sha256::digest(bytes))))
        .collect();
    Ok(Loaded {
        installation: installation.into(),
        generation,
        plan: CleanupPlan {
            schema: if pre_application {
                "elevenid.installer-uninstall-pre-application-plan/v1"
            } else {
                "elevenid.installer-uninstall-plan/v1"
            }
            .into(),
            installation_id,
            engine_id: binding.engine_id.clone(),
            project,
            network_id,
            network_name,
            retained_redis_volume: (!pre_application).then(|| redis_volume.clone()),
            absent_redis_volume: pre_application.then_some(redis_volume),
            resources,
            source_hashes: hashes,
        },
        application,
        bao,
        bao_image_id: bao_created.image_id,
        sources,
        helper_ids,
    })
}
fn pre_application_records_absent(state: &LockedMaintenance, roles: &[String]) -> Result<()> {
    for name in [
        "application-created-resources.json",
        "application-discovered-resources.json",
        "application-prestart-admission.json",
        "application-start-result.json",
    ] {
        require(state.read_evidence(name)?.is_none())?;
    }
    for role in roles {
        for prefix in ["application-start", "application-observed"] {
            require(
                state
                    .read_evidence(&format!("{prefix}-{role}.json"))?
                    .is_none(),
            )?;
        }
    }
    Ok(())
}
fn unchanged(state: &LockedMaintenance, loaded: &Loaded) -> Result<()> {
    state.require_unchanged()?;
    if loaded.plan.pre_application() {
        require(state.journal().phase() == Phase::Provisioning)?;
        pre_application_records_absent(
            state,
            &graph::startup_order(
                &loaded.application.model,
                &loaded.application.selected_services,
            )?,
        )?;
    }
    let generation = crate::installer_generation_binding::load_verified(
        &loaded.installation,
        &loaded.plan.installation_id,
        &loaded.plan.engine_id,
    )?;
    require(
        serde_json::to_vec(&generation).map_err(|_| REFUSED)?
            == serde_json::to_vec(&loaded.generation).map_err(|_| REFUSED)?,
    )?;
    if let Some(generation) = &generation {
        crate::installer_generation_binding::verify_model(
            &loaded.installation,
            generation,
            &loaded.application,
        )?;
    }
    require(
        generation_present(state)?
            == loaded
                .sources
                .contains_key("evidence/generation-container-removed.json"),
    )?;
    require(
        renewal_present(state)?
            == loaded
                .sources
                .contains_key("evidence/renewal-container-removed.json"),
    )?;
    for (key, bytes) in &loaded.sources {
        let (location, name) = key.split_once('/').ok_or(REFUSED)?;
        let current = if location == "root" {
            state.read_record(name)?
        } else {
            state.read_evidence(name)?
        };
        require(current.as_ref() == Some(bytes))?;
    }
    Ok(())
}
fn receipt(state: &LockedMaintenance, name: &str, value: &Value) -> Result<bool> {
    if let Some(bytes) = state.read_evidence(name)? {
        require(parse::<Value>(&bytes)? == *value)?;
        Ok(true)
    } else {
        Ok(false)
    }
}
fn record(state: &mut LockedMaintenance, name: &str, value: &Value) -> Result<()> {
    if !receipt(state, name, value)? {
        state.write_evidence_exclusive(name, &serde_json::to_vec(value).map_err(|_| REFUSED)?)?;
    }
    Ok(())
}
fn operation(plan: &CleanupPlan, kind: &str, resource: &str) -> Value {
    json!({"schema":"elevenid.installer-uninstall-operation/v1","installation_id":plan.installation_id,"engine_id":plan.engine_id,"operation":kind,"resource_id":resource})
}
fn removal_name(id: &str) -> String {
    format!("uninstall-remove-{id}.json")
}
fn removal_intent(state: &LockedMaintenance, plan: &CleanupPlan, id: &str) -> Result<bool> {
    receipt(
        state,
        &removal_name(id),
        &operation(plan, "remove-container", id),
    )
}
fn present(docker: &DockerRunner, id: &str) -> Result<bool> {
    require(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let values =
        ids(&docker.run_checked(&["ps", "-aq", "--no-trunc", "--filter", &format!("id={id}")])?)?;
    require(values.is_empty() || values == BTreeSet::from([id.to_owned()]))?;
    Ok(!values.is_empty())
}
fn listed(docker: &DockerRunner, kind: &str, filter: &str) -> Result<BTreeSet<String>> {
    let out = if kind == "container" {
        docker.run_checked(&["ps", "-aq", "--no-trunc", "--filter", filter])?
    } else {
        docker.run_checked(&[kind, "ls", "-q", "--no-trunc", "--filter", filter])?
    };
    ids(&out)
}
fn network_present(docker: &DockerRunner, plan: &CleanupPlan) -> Result<bool> {
    let found = listed(docker, "network", &format!("id={}", plan.network_id))?;
    require(found.is_empty() || found == BTreeSet::from([plan.network_id.clone()]))?;
    Ok(!found.is_empty())
}
fn scope(
    docker: &DockerRunner,
    state: &LockedMaintenance,
    loaded: &Loaded,
) -> Result<BTreeSet<String>> {
    let p = &loaded.plan;
    let mut live = BTreeSet::new();
    let mut expected_app = BTreeSet::new();
    let mut expected_bao = BTreeSet::new();
    // One successful bounded inventory establishes presence/absence, without
    // interpreting inspect errors as disappearance or querying every peer.
    let observed_ids = ids(&docker.run_checked(&["ps", "-aq", "--no-trunc"])?)?;
    for r in &p.resources {
        if observed_ids.contains(&r.container_id) {
            live.insert(r.container_id.clone());
            if r.bao {
                expected_bao.insert(r.container_id.clone());
            } else {
                expected_app.insert(r.container_id.clone());
            }
        } else {
            require(removal_intent(state, p, &r.container_id)?)?;
        }
    }
    for (project, expected) in [
        (&p.project, expected_app),
        (&format!("{}-bao", p.project), expected_bao),
    ] {
        require(
            listed(
                docker,
                "container",
                &format!("label=com.docker.compose.project={project}"),
            )? == expected,
        )?;
    }
    require(
        listed(
            docker,
            "container",
            &format!("name=^/{}-", regex::escape(&p.project)),
        )? == live,
    )?;
    require(
        listed(
            docker,
            "container",
            &format!("label=com.elevenid.installer.id={}", p.installation_id),
        )?
        .is_empty(),
    )?;
    for helper in &loaded.helper_ids {
        require(!observed_ids.contains(helper))?;
    }
    let exists = network_present(docker, p)?;
    let expected_networks = if exists {
        BTreeSet::from([p.network_id.clone()])
    } else {
        BTreeSet::new()
    };
    require(
        listed(
            docker,
            "network",
            &format!("label=com.docker.compose.project={}-bao", p.project),
        )? == expected_networks
            && listed(
                docker,
                "network",
                &format!("label=com.docker.compose.project={}", p.project),
            )?
            .is_empty()
            && listed(
                docker,
                "network",
                &format!("name=^{}", regex::escape(&p.project)),
            )? == expected_networks,
    )?;
    if exists {
        let network = object(&docker.run_checked(&["network", "inspect", &p.network_id])?)?;
        require(
            network["Id"] == p.network_id
                && network["Name"] == p.network_name
                && network["Driver"] == "bridge"
                && network["Labels"]["com.docker.compose.project"] == format!("{}-bao", p.project)
                && network["Labels"]["com.docker.compose.network"] == "default",
        )?;
        let attached = network["Containers"].as_object().ok_or(REFUSED)?;
        require(attached.keys().all(|s| live.contains(s)))?;
    } else {
        require(
            live.is_empty()
                && receipt(
                    state,
                    "uninstall-network-remove.json",
                    &operation(p, "remove-network", &p.network_id),
                )?,
        )?;
    }
    for (project, expected) in [
        (
            &p.project,
            p.retained_redis_volume.iter().cloned().collect(),
        ),
        (&format!("{}-bao", p.project), BTreeSet::new()),
    ] {
        let output = docker.run_checked(&[
            "volume",
            "ls",
            "-q",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
        ])?;
        let found: BTreeSet<_> = output.lines().map(String::from).collect();
        require(found == expected)?;
    }
    if let Some(name) = &p.retained_redis_volume {
        let volume = object(&docker.run_checked(&["volume", "inspect", name])?)?;
        validate_volume(&volume, &loaded.application)?;
    } else {
        require(p.pre_application() && p.absent_redis_volume.is_some())?;
        // Successful global enumeration also detects an unlabelled volume with
        // the intended name. An inspect error is never absence evidence.
        let output = docker.run_checked(&["volume", "ls", "-q"])?;
        let names: BTreeSet<_> = output.lines().collect();
        require(names.len() == output.lines().count())?;
        for name in names {
            require(
                !name.is_empty()
                    && name.len() <= 255
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            )?;
            require(
                !name.starts_with(&p.project) && Some(name) != p.absent_redis_volume.as_deref(),
            )?;
        }
    }
    Ok(live)
}
fn observe(docker: &DockerRunner, loaded: &Loaded, r: &Resource) -> Result<Value> {
    let plan = if r.bao {
        &loaded.bao
    } else {
        &loaded.application
    };
    let image = object(&docker.run_checked(&[
        "image",
        "inspect",
        text(&plan.model["services"][&r.role]["image"])?,
    ])?)?;
    if r.bao {
        require(image["Id"] == loaded.bao_image_id)?;
    }
    let container =
        object(&docker.run_checked(&["inspect", "--type", "container", &r.container_id])?)?;
    if r.bao {
        validate_openbao_container_for_cleanup(&container, &r.container_id, &r.role, plan, &image)?;
    } else {
        validate_container_for_logs(&container, &r.container_id, &r.role, plan, &image)?;
    }
    Ok(container)
}
fn pre_application_mutation_guard(
    docker: &DockerRunner,
    state: &LockedMaintenance,
    loaded: &Loaded,
) -> Result<()> {
    if loaded.plan.pre_application() {
        unchanged(state, loaded)?;
        let live = scope(docker, state, loaded)?;
        for resource in &loaded.plan.resources {
            if live.contains(&resource.container_id) {
                observe(docker, loaded, resource)?;
            }
        }
        require(scope(docker, state, loaded)? == live)?;
        unchanged(state, loaded)?;
    }
    Ok(())
}
/// Remove a complete runtime or the proven pre-application boundary, retaining data.
/// A retry resumes this cleanup transaction; it never resumes provisioning.
pub fn uninstall(args: &[String]) -> Result<String> {
    uninstall_inner(args).map_err(|_| REFUSED.to_owned())
}
fn uninstall_inner(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let mut state = LockedMaintenance::open(&args.installation)?;
    let loaded = load(&state, &args.installation)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    let docker = DockerRunner::new(
        &args.docker,
        &binding.docker_host,
        &binding.engine_id,
        &args.installation,
    )?;
    docker.preflight()?;
    let plan_value = serde_json::to_value(&loaded.plan).map_err(|_| REFUSED)?;
    let saved_plan = state.read_evidence("uninstall-plan.json")?;
    if let Some(saved) = &saved_plan {
        require(parse::<CleanupPlan>(saved)? == loaded.plan)?;
    }
    let live = scope(&docker, &state, &loaded)?;
    require(saved_plan.is_some() || live.len() == loaded.plan.resources.len())?;
    for r in &loaded.plan.resources {
        if live.contains(&r.container_id) {
            observe(&docker, &loaded, r)?;
        }
    }
    unchanged(&state, &loaded)?;
    record(&mut state, "uninstall-plan.json", &plan_value)?;
    for r in &loaded.plan.resources {
        unchanged(&state, &loaded)?;
        let live = scope(&docker, &state, &loaded)?;
        if live.contains(&r.container_id) {
            let observed = observe(&docker, &loaded, r)?;
            let status = text(&observed["State"]["Status"])?;
            require(!matches!(
                status,
                "paused" | "restarting" | "removing" | "dead"
            ))?;
            if status == "running" {
                record(
                    &mut state,
                    &format!("uninstall-stop-{}.json", r.container_id),
                    &operation(&loaded.plan, "stop-container", &r.container_id),
                )?;
                unchanged(&state, &loaded)?;
                pre_application_mutation_guard(&docker, &state, &loaded)?;
                docker.run_checked(&["stop", "--time", "30", &r.container_id])?;
            }
            let stopped = observe(&docker, &loaded, r)?;
            require(
                matches!(
                    stopped["State"]["Status"].as_str(),
                    Some("exited" | "created")
                ) && stopped["State"]["Running"] == false,
            )?;
            record(
                &mut state,
                &format!("uninstall-stopped-{}.json", r.container_id),
                &operation(&loaded.plan, "observed-stopped", &r.container_id),
            )?;
            record(
                &mut state,
                &removal_name(&r.container_id),
                &operation(&loaded.plan, "remove-container", &r.container_id),
            )?;
            unchanged(&state, &loaded)?;
            pre_application_mutation_guard(&docker, &state, &loaded)?;
            docker.run_checked(&["rm", &r.container_id])?;
            require(!present(&docker, &r.container_id)?)?;
        } else {
            require(removal_intent(&state, &loaded.plan, &r.container_id)?)?;
        }
        record(
            &mut state,
            &format!("uninstall-removed-{}.json", r.container_id),
            &operation(&loaded.plan, "observed-absent", &r.container_id),
        )?;
    }
    unchanged(&state, &loaded)?;
    require(scope(&docker, &state, &loaded)?.is_empty())?;
    record(
        &mut state,
        "uninstall-network-remove.json",
        &operation(&loaded.plan, "remove-network", &loaded.plan.network_id),
    )?;
    if network_present(&docker, &loaded.plan)? {
        let network =
            object(&docker.run_checked(&["network", "inspect", &loaded.plan.network_id])?)?;
        require(
            network["Containers"]
                .as_object()
                .is_some_and(|c| c.is_empty()),
        )?;
        unchanged(&state, &loaded)?;
        pre_application_mutation_guard(&docker, &state, &loaded)?;
        docker.run_checked(&["network", "rm", &loaded.plan.network_id])?;
    }
    require(!network_present(&docker, &loaded.plan)?)?;
    record(
        &mut state,
        "uninstall-network-removed.json",
        &operation(
            &loaded.plan,
            "observed-network-absent",
            &loaded.plan.network_id,
        ),
    )?;
    require(scope(&docker, &state, &loaded)?.is_empty())?;
    unchanged(&state, &loaded)?;
    let mut result = json!({"schema":if loaded.plan.pre_application() {"elevenid.installer-uninstall-pre-application-result/v1"} else {"elevenid.installer-uninstall-result/v1"},"installation_id":loaded.plan.installation_id,"engine_id":loaded.plan.engine_id,"containers_removed":loaded.plan.resources.len(),"network_removed":true,"host_data_retained":true,"credentials_retained":true,"images_retained":true,"redis_volume_retained":loaded.plan.retained_redis_volume,"installation_ready":false});
    if let Some(name) = &loaded.plan.absent_redis_volume {
        result["redis_volume_absent"] = json!(name);
    }
    record(&mut state, "uninstall-result.json", &result)?;
    serde_json::to_string(&result).map_err(|_| REFUSED.into())
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
    use std::{fs, os::unix::fs::PermissionsExt};
    fn save(path: impl AsRef<std::path::Path>, value: &Value) {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }
    pub(crate) fn mock(mode: &str) -> (tempfile::TempDir, Vec<String>) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installation = root.path().join("install");
        let mut state = InstallerState::create_with_runtime(
            &installation,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18200,
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        let project = state.journal().compose_project();
        let owner = state.journal().installation_id().to_string();
        let network = format!("{project}-bao_default");
        let network_id = "c".repeat(64);
        let digest = format!("example.test/services@sha256:{}", "a".repeat(64));
        let image_id = format!("sha256:{}", "b".repeat(64));
        let mut services = serde_json::Map::new();
        for role in [
            "gateway",
            "postgres",
            "redis",
            "revocation-profile-migrate",
            "db-migrate",
            "kms-initialize",
            "keycloak-configurator",
            "issuance-migrations",
            "cloudflared",
            "cloudflared-beta",
            "tunnel-nginx-proxy",
        ] {
            services.insert(
                role.into(),
                json!({"image":digest,"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        for i in 0..22 {
            services.insert(
                format!("synthetic-{i}"),
                json!({"image":digest,"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        services["kms-initialize"]["depends_on"] = json!({"postgres":{"condition":"service_healthy"},"redis":{"condition":"service_healthy"},"db-migrate":{"condition":"service_completed_successfully"},"revocation-profile-migrate":{"condition":"service_completed_successfully"}});
        services["kms-initialize"]["profiles"] = json!(["kms-init"]);
        services["kms-initialize"]["environment"] = json!({"MARTY_KMS_BOOTSTRAP_ENABLED":"true","BAO_TOKEN_FILE":"/run/secrets/openbao_bootstrap_token"});
        let selected: Vec<String> = services
            .keys()
            .filter(|s| {
                ![
                    "kms-initialize",
                    "cloudflared",
                    "cloudflared-beta",
                    "tunnel-nginx-proxy",
                ]
                .contains(&s.as_str())
            })
            .cloned()
            .collect();
        let application = ApplicationModelPlan {
            model: json!({"name":project,"services":services,"networks":{"default":{"name":network}},"volumes":{"redis-socket":{"name":format!("{project}_redis-socket")}}}),
            selected_services: selected,
            expected_network_id: network_id.clone(),
            installation_ready: false,
        };
        let order = crate::installer_application_graph::startup_order(
            &application.model,
            &application.selected_services,
        )
        .unwrap();
        let containers: BTreeMap<String, String> = order
            .iter()
            .enumerate()
            .map(|(i, r)| (r.clone(), format!("{:064x}", i + 1)))
            .collect();
        state
            .write_evidence(
                "application-plan.json",
                &serde_json::to_vec(&application).unwrap(),
            )
            .unwrap();
        state
            .write_evidence(
                "application-compose.json",
                &crate::installer_application::compose_document(&application.model).unwrap(),
            )
            .unwrap();
        state.write_evidence("application-created-resources.json",&serde_json::to_vec(&json!({"containers":containers,"redis_volume":format!("{project}_redis-socket"),"network_id":network_id})).unwrap()).unwrap();
        for (i, (stage, schema)) in [
            ("keycloak", "elevenid.installer-keycloak/v1"),
            ("tls", "elevenid.installer-tls/v1"),
            ("ingress", "elevenid.installer-ingress-host/v1"),
        ]
        .into_iter()
        .enumerate()
        {
            state.write_evidence(&format!("{stage}-container-removed.json"),&serde_json::to_vec(&json!({"schema":schema,"installation_id":owner,"engine_id":"test-engine","network_id":network_id,"container_id":format!("{:064x}",100+i),"container_removed":true})).unwrap()).unwrap();
        }
        let bao_ids: BTreeMap<String, String> = BAO
            .iter()
            .enumerate()
            .map(|(i, r)| (r.to_string(), format!("{:064x}", 40 + i)))
            .collect();
        let mut bao_services = serde_json::Map::new();
        for role in BAO {
            bao_services.insert(
                role.into(),
                json!({"image":digest,"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        let bao_model = json!({"name":format!("{project}-bao"),"services":bao_services,"networks":{"default":{"name":network}}});
        for (name, value) in [
            (
                "openbao-created.json",
                json!({"schema":"elevenid.installer-openbao-created/v1","installation_id":owner,"engine_id":"test-engine","project":format!("{project}-bao"),"image":digest,"image_id":image_id,"network_id":network_id,"container_ids":bao_ids}),
            ),
            ("openbao-compose-model.json", bao_model),
        ] {
            let path = installation.join(name);
            save(&path, &value);
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(installation.join("retained-data"), b"private data stays").unwrap();
        drop(state);
        let mut observed = serde_json::Map::new();
        for (bao, map) in [(false, &containers), (true, &bao_ids)] {
            for (role, id) in map {
                let p = if bao {
                    format!("{project}-bao")
                } else {
                    project.clone()
                };
                let mut c = json!({"Id":id,"Image":image_id,"Name":format!("/{p}-{role}-1"),"Config":{"Image":digest,"Labels":{"com.docker.compose.project":p,"com.docker.compose.service":role,"com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False"},"Env":[],"Entrypoint":[],"Cmd":[],"User":"","WorkingDir":"","Healthcheck":{"Test":["CMD","true"]}},"HostConfig":{"Privileged":false,"ReadonlyRootfs":false,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"IpcMode":"private","NetworkMode":network},"NetworkSettings":{"Networks":{network.clone():{"NetworkID":network_id,"Aliases":[format!("{p}-{role}-1"),role]}},"Ports":{}},"Mounts":[],"State":{"Status":"running","Running":true,"OOMKilled":false}});
                if bao {
                    c["HostConfig"]["Tmpfs"] = json!({"/openbao/file":"rw,noexec,nosuid,nodev,size=1048576,mode=0700","/openbao/logs":"rw,noexec,nosuid,nodev,size=1048576,mode=0700"});
                }
                if role == "kms-initialize" {
                    c["Config"]["Env"] = json!([
                        "MARTY_KMS_BOOTSTRAP_ENABLED=true",
                        "BAO_TOKEN_FILE=/run/secrets/openbao_bootstrap_token"
                    ]);
                }
                observed.insert(id.clone(), c);
            }
        }
        if mode == "replacement" {
            let old = containers["gateway"].clone();
            let mut c = observed.remove(&old).unwrap();
            c["Id"] = json!("e".repeat(64));
            observed.insert("e".repeat(64), c);
        }
        if mode == "unknown" {
            let mut c = observed[&containers["gateway"]].clone();
            c["Id"] = json!("e".repeat(64));
            c["Name"] = json!(format!("/{project}-foreign-1"));
            observed.insert("e".repeat(64), c);
        }
        save(
            root.path().join("ledger.json"),
            &json!({"project":project,"mode":mode,"containers":observed,"network_exists":true,"network_id":network_id,"network_name":network,"mutations":[],"interrupted":false,"fail_ps":false,"volume":{"Name":format!("{project}_redis-socket"),"Driver":"local","Scope":"local","Options":null,"Labels":{"com.docker.compose.project":project,"com.docker.compose.volume":"redis-socket"}},"image":{"Id":image_id,"RepoDigests":[digest],"Config":{"Env":[],"Entrypoint":[],"Cmd":[],"User":"","WorkingDir":""}}}),
        );
        // Test-only Python models Docker JSON and persists command effects. The
        // production installer has no Python or shell orchestration dependency.
        let backend = r#"import sys,json,re
from pathlib import Path
p=Path(__file__).parent/'ledger.json'
s=json.loads(p.read_text()); a=sys.argv[1:]
s.setdefault('commands',[]).append(a)
p.write_text(json.dumps(s))
def persist(): p.write_text(json.dumps(s))
def out(v): print(json.dumps(v))
def filt(): return a[a.index('--filter')+1] if '--filter' in a else None
if a[0]=='info': out({'id':'test-engine','os':'linux','architecture':'x86_64','server_version':'28.0.0','security_options':['name=seccomp,profile=builtin']})
elif a[:2]==['compose','version']: print('2.40.3')
elif a[0]=='ps':
 if s['mode']=='command-failure' or s['fail_ps']:
  s['fail_ps']=False;persist();sys.exit(19)
 f=filt()
 for i,c in s['containers'].items():
  if f is None: print(i)
  elif f.startswith('id=') and i==f[3:]: print(i)
  elif f.startswith('name=') and re.search(f[5:],c['Name']): print(i)
  elif f.startswith('label='):
   k,v=f[6:].split('=',1)
   if c['Config']['Labels'].get(k)==v: print(i)
elif a[:2]==['network','ls']:
 if s['network_exists']:
  f=filt()
  if f=='id='+s['network_id'] or f=='label=com.docker.compose.project='+s['project']+'-bao' or (f.startswith('name=') and re.search(f[5:],s['network_name'])): print(s['network_id'])
elif a[:2]==['network','inspect']:
 if not s['network_exists'] or a[2]!=s['network_id']: sys.exit(20)
 attached={i:{} for i,c in s['containers'].items() if c['State']['Running']}
 if s['mode']=='foreign-attachment': attached['f'*64]={}
 out([{'Id':s['network_id'],'Name':s['network_name'],'Driver':'bridge','Labels':{'com.docker.compose.project':s['project']+'-bao','com.docker.compose.network':'default'},'Containers':attached}])
elif a[:2]==['volume','ls']:
 if s['mode']=='volume-command-failure': sys.exit(22)
 if s['volume'] and (filt() is None or filt()=='label=com.docker.compose.project='+s['volume'].get('Labels',{}).get('com.docker.compose.project','')): print(s['volume']['Name'])
elif a[:2]==['volume','inspect']: out([s['volume']])
elif a[:2]==['image','inspect']: out([s['image']])
elif a[:3]==['inspect','--type','container']:
 if a[3] not in s['containers']: sys.exit(21)
 out([s['containers'][a[3]]])
elif a[0]=='stop':
 assert a[1:3]==['--time','30'] and len(a)==4
 c=s['containers'][a[3]];c['State'].update(Status='exited',Running=False,ExitCode=137)
 if s['mode']=='volume-drift': s['volume']={'Name':s['project']+'_redis-socket','Labels':{}}
 if s['mode']=='record-drift': (p.parent/'install/evidence/application-discovered-resources.json').write_text('{}')
 if s['mode']=='stop-interruption' and not s['interrupted']: s['interrupted']=True;s['fail_ps']=True
 s['mutations'].append(a);persist();print(a[3])
elif a[0]=='rm':
 assert len(a)==2 and not s['containers'][a[1]]['State']['Running']
 del s['containers'][a[1]];s['mutations'].append(a)
 if s['mode']=='interruption' and not s['interrupted']: s['interrupted']=True;s['fail_ps']=True
 persist();print(a[1])
elif a[:2]==['network','rm']:
 assert len(a)==3 and a[2]==s['network_id'] and not s['containers']
 s['network_exists']=False;s['mutations'].append(a);persist();print(a[2])
else: sys.exit(98)
"#;
        fs::write(root.path().join("docker.py"), backend).unwrap();
        let exe = root.path().join("docker-stub");
        fs::write(
            &exe,
            format!(
                "#!/bin/sh\nexec /usr/bin/python3 '{}' \"$@\"\n",
                root.path().join("docker.py").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        let args = vec![
            "--install-dir".into(),
            installation.to_str().unwrap().into(),
            "--docker-bin".into(),
            exe.to_str().unwrap().into(),
        ];
        (root, args)
    }
    fn ledger(root: &tempfile::TempDir) -> Value {
        parse(&fs::read(root.path().join("ledger.json")).unwrap()).unwrap()
    }
    fn pre_application_mock(mode: &str) -> (tempfile::TempDir, Vec<String>) {
        let (root, args) = mock(mode);
        let installation = root.path().join("install");
        let evidence = installation.join("evidence");
        let identity = InstallerState::inspect(&installation)
            .unwrap()
            .identity()
            .clone();
        let mut initializing = InstallerState::resume(&installation, &identity).unwrap();
        initializing.advance(Phase::Verified).unwrap();
        initializing.advance(Phase::Provisioning).unwrap();
        drop(initializing);
        let state = LockedMaintenance::open(&installation).unwrap();
        let loaded = load(&state, &installation).unwrap();
        let order = graph::startup_order(
            &loaded.application.model,
            &loaded.application.selected_services,
        )
        .unwrap();
        let intent = json!({"schema":"elevenid.installer-application-start-intent/v1","installation_id":loaded.plan.installation_id,"project":loaded.plan.project,"engine_id":loaded.plan.engine_id,"network_id":loaded.plan.network_id,"roles":order,"redis_volume":loaded.plan.retained_redis_volume,"installation_ready":false});
        drop(state);
        fs::remove_file(evidence.join("application-created-resources.json")).unwrap();
        save(evidence.join("application-start-intent.json"), &intent);
        fs::set_permissions(
            evidence.join("application-start-intent.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        for stage in ["keycloak", "tls", "ingress"] {
            let removed = evidence.join(format!("{stage}-container-removed.json"));
            let mut record: Value = parse(&fs::read(&removed).unwrap()).unwrap();
            record["installation_ready"] = json!(false);
            save(&removed, &record);
            record["container_removed"] = json!(false);
            let result = evidence.join(format!("{stage}-result.json"));
            save(&result, &record);
            fs::set_permissions(result, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut saved = ledger(&root);
        saved["containers"].as_object_mut().unwrap().retain(|_, c| {
            c["Config"]["Labels"]["com.docker.compose.project"]
                .as_str()
                .unwrap()
                .ends_with("-bao")
        });
        saved["volume"] = Value::Null;
        save(root.path().join("ledger.json"), &saved);
        (root, args)
    }
    #[test]
    fn pre_application_cleanup_and_interrupted_retry_keep_data_and_status() {
        use crate::installer_state::{CleanupState, LockedInspection};
        for mode in ["success", "interruption"] {
            let (root, args) = pre_application_mock(mode);
            let installation = root.path().join("install");
            let before = fs::read(installation.join("installation.json")).unwrap();
            let identity = InstallerState::inspect(&installation)
                .unwrap()
                .identity()
                .clone();
            if mode == "interruption" {
                assert!(uninstall_inner(&args).is_err());
                assert_eq!(ledger(&root)["containers"].as_object().unwrap().len(), 3);
                let inspection = LockedInspection::open(&installation).unwrap();
                assert_eq!(
                    inspection.cleanup_status().unwrap().state,
                    CleanupState::InProgress
                );
                drop(inspection);
            }
            let result: Value = parse(uninstall_inner(&args).unwrap().as_bytes()).unwrap();
            assert_eq!(result["containers_removed"], 4);
            assert!(result["redis_volume_retained"].is_null());
            assert!(result["redis_volume_absent"]
                .as_str()
                .unwrap()
                .ends_with("_redis-socket"));
            assert_eq!(result["installation_ready"], false);
            let saved = ledger(&root);
            assert!(saved["containers"].as_object().unwrap().is_empty());
            assert_eq!(saved["network_exists"], false);
            assert!(saved["volume"].is_null());
            assert_eq!(saved["mutations"].as_array().unwrap().len(), 9);
            assert_eq!(
                fs::read(installation.join("installation.json")).unwrap(),
                before
            );
            assert_eq!(
                fs::read(installation.join("retained-data")).unwrap(),
                b"private data stays"
            );
            let inspection = LockedInspection::open(&installation).unwrap();
            assert_eq!(
                inspection.cleanup_status().unwrap().state,
                CleanupState::Completed
            );
            drop(inspection);
            assert!(InstallerState::resume(&installation, &identity).is_err());
            assert!(uninstall_inner(&args).is_ok());
            assert_eq!(ledger(&root)["mutations"], saved["mutations"]);
        }
    }
    #[test]
    fn pre_application_absence_is_proven_not_inferred() {
        for mode in [
            "foreign-attachment",
            "command-failure",
            "volume-command-failure",
            "unlabelled-volume",
            "unlabelled-container",
            "foreign-image",
        ] {
            let (root, args) = pre_application_mock(mode);
            let mut saved = ledger(&root);
            if mode == "unlabelled-volume" {
                saved["volume"] = json!({"Name":format!("{}_redis-socket",saved["project"].as_str().unwrap()),"Labels":{}});
            } else if mode == "unlabelled-container" {
                let mut c = saved["containers"]
                    .as_object()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                c["Id"] = json!("e".repeat(64));
                c["Name"] = json!(format!("/{}-gateway-1", saved["project"].as_str().unwrap()));
                c["Config"]["Labels"] = json!({});
                saved["containers"]["e".repeat(64)] = c;
            } else if mode == "foreign-image" {
                saved["image"]["Id"] = json!(format!("sha256:{}", "e".repeat(64)));
            }
            save(root.path().join("ledger.json"), &saved);
            assert!(uninstall_inner(&args).is_err(), "{mode}");
            assert!(
                ledger(&root)["mutations"].as_array().unwrap().is_empty(),
                "{mode}"
            );
            assert!(!root
                .path()
                .join("install/evidence/uninstall-plan.json")
                .exists());
        }
    }
    #[test]
    fn pre_application_retry_after_stop_never_restarts_or_repeats_stop() {
        let (root, args) = pre_application_mock("stop-interruption");
        assert!(uninstall_inner(&args).is_err());
        let before = ledger(&root);
        assert_eq!(before["containers"].as_object().unwrap().len(), 4);
        assert_eq!(before["mutations"].as_array().unwrap().len(), 1);
        let stopped_id = before["mutations"][0][3].as_str().unwrap();
        assert_eq!(
            before["containers"][stopped_id]["State"]["Status"],
            "exited"
        );
        assert!(uninstall_inner(&args).is_ok());
        let after = ledger(&root);
        assert_eq!(after["mutations"].as_array().unwrap().len(), 9);
        assert_eq!(
            after["mutations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|args| args[0] == "stop" && args[3] == stopped_id)
                .count(),
            1
        );
    }
    // Synthetic credentials and proof records exercise the production binding
    // decoder, not live cryptographic validation or a real installed runtime.
    fn selected_pre_application_mock() -> (tempfile::TempDir, Vec<String>) {
        use crate::installer_generation_binding::{
            GenerationBinding, GenerationFile, GenerationSource,
        };
        let (root, args) = pre_application_mock("success");
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let loaded = load(&state, &installation).unwrap();
        drop(state);
        let owner = &loaded.plan.installation_id;
        let project = &loaded.plan.project;
        let network = &loaded.plan.network_id;
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "a".repeat(64)
        );
        let put = |path: PathBuf, bytes: &[u8], mode| {
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let record = |name: &str, value: &Value| {
            put(
                installation.join("evidence").join(name),
                &serde_json::to_vec(value).unwrap(),
                0o600,
            );
        };
        for name in [
            "secrets",
            "generation-inputs",
            "generation-identity",
            "generation-transfer",
            "generation-transfer/delivered",
            "application-generation",
        ] {
            let path = installation.join(name);
            if !path.exists() {
                fs::create_dir(&path).unwrap();
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let hashes = |values: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, String> {
            values
                .iter()
                .map(|(name, bytes)| (name.clone(), format!("{:x}", Sha256::digest(bytes))))
                .collect()
        };
        let current: BTreeMap<String, Vec<u8>> =
            crate::installer_renewal_bootstrap::current_inputs()
                .into_iter()
                .map(|name| {
                    let bytes = if name.ends_with("_token") {
                        format!("old-synthetic-credential-{name}")
                    } else {
                        format!(
                            "-----BEGIN CERTIFICATE-----\nold-{name}\n-----END CERTIFICATE-----"
                        )
                    };
                    (name, bytes.into_bytes())
                })
                .collect();
        let outputs: BTreeMap<String, Vec<u8>> = current
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    if name == "workload_identity_ca_cert" {
                        bytes.clone()
                    } else {
                        String::from_utf8(bytes.clone())
                            .unwrap()
                            .replace("old-", "new-")
                            .into_bytes()
                    },
                )
            })
            .collect();
        let identity: BTreeMap<String, Vec<u8>> = [
            "renewal-role-id",
            "renewal-secret-id",
            "renewal-leaf-policies.json",
        ]
        .into_iter()
        .map(|name| (name.into(), format!("identity-{name}").into_bytes()))
        .collect();
        for (name, bytes) in &current {
            put(installation.join("secrets").join(name), bytes, 0o444);
            put(
                installation.join("generation-inputs").join(name),
                bytes,
                0o444,
            );
            put(
                installation
                    .join("generation-transfer/delivered")
                    .join(name),
                &outputs[name],
                0o444,
            );
            put(
                installation.join("application-generation").join(name),
                &outputs[name],
                0o444,
            );
        }
        for (name, bytes) in &identity {
            put(
                installation.join("generation-identity").join(name),
                bytes,
                0o600,
            );
        }
        let keycloak = json!({"schema":"elevenid.installer-keycloak/v1","installation_id":owner,"engine_id":"test-engine","container_id":format!("{:064x}",100),"container_name":format!("{project}-keycloak-inputs"),"network_id":network,"image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}","c".repeat(64)),"nonce":"0123456789ab","outputs":crate::installer_keycloak_bridge::OUTPUTS,"container_removed":true,"installation_ready":false});
        let keycloak_bytes = serde_json::to_vec(&keycloak).unwrap();
        record("keycloak-observation.json", &keycloak);
        record("keycloak-container-removed.json", &keycloak);
        let mut keycloak_result = keycloak.clone();
        keycloak_result["container_removed"] = json!(false);
        record("keycloak-result.json", &keycloak_result);
        for (name, value) in [
            (
                "pending.json",
                json!({"schema":"elevenid.installer-generation-intent/v1","installation_id":owner,"nonce":"0123456789ab","input_sha256":hashes(&current),"identity_sha256":hashes(&identity),"keycloak_receipt_sha256":format!("{:x}",Sha256::digest(&keycloak_bytes)),"root_retired":false,"activated":false}),
            ),
            (
                "validated.json",
                json!({"schema":"elevenid.installer-generation-validation/v1","installation_id":owner,"output_sha256":hashes(&outputs),"orphan_tokens":21,"remote_key_version":1,"ca_changed":false}),
            ),
            (
                "completed.json",
                json!({"schema":"elevenid.installer-generation-result/v1","installation_id":owner,"files":40,"changed_files":39,"orphan_tokens":21,"transient_revoked":true,"activated":false,"root_retired":false,"ingress_renewal":false,"installation_ready":false}),
            ),
        ] {
            put(
                installation
                    .join("generation-transfer/delivered")
                    .join(name),
                &serde_json::to_vec(&value).unwrap(),
                0o600,
            );
        }
        let renewal = serde_json::to_value(crate::installer_renewal::RenewalReceipt {
            schema: "elevenid.installer-renewal-host/v1",
            installation_id: owner.clone(),
            engine_id: "test-engine".into(),
            container_id: "e".repeat(64),
            container_name: format!("{project}-renewal-inputs"),
            network_id: network.clone(),
            image: image.clone(),
            root_retired: false,
            ingress_renewal: false,
            private_identity_validated: true,
            outputs: identity.keys().cloned().collect(),
            container_removed: true,
            installation_ready: false,
        })
        .unwrap();
        let generation =
            serde_json::to_value(crate::installer_generation_host::GenerationReceipt {
                schema: "elevenid.installer-generation-host/v1",
                installation_id: owner.clone(),
                engine_id: "test-engine".into(),
                container_id: "f".repeat(64),
                container_name: format!("{project}-generation-inputs"),
                network_id: network.clone(),
                image,
                candidate_validated: true,
                outputs: outputs.keys().cloned().collect(),
                candidate_sha256: hashes(&outputs),
                activated: false,
                root_retired: false,
                ingress_renewal: false,
                container_removed: true,
                installation_ready: false,
            })
            .unwrap();
        for (stage, removed) in [("renewal", &renewal), ("generation", &generation)] {
            record(&format!("{stage}-container-removed.json"), removed);
            let mut completed = removed.clone();
            completed["container_removed"] = json!(false);
            record(&format!("{stage}-result.json"), &completed);
        }
        let mut files: BTreeMap<String, GenerationFile> = outputs
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    GenerationFile {
                        source: GenerationSource::Candidate,
                        sha256: format!("{:x}", Sha256::digest(bytes)),
                        size: bytes.len() as u64,
                        source_mode: 0o444,
                        mode: 0o444,
                    },
                )
            })
            .collect();
        let scalar = b"unchanged-synthetic-scalar";
        for dir in ["secrets", "application-generation"] {
            put(
                installation.join(dir).join("postgres_password"),
                scalar,
                0o444,
            );
        }
        files.insert(
            "postgres_password".into(),
            GenerationFile {
                source: GenerationSource::Original,
                sha256: format!("{:x}", Sha256::digest(scalar)),
                size: scalar.len() as u64,
                source_mode: 0o444,
                mode: 0o444,
            },
        );
        let binding = GenerationBinding {
            schema: "elevenid.installer-application-generation/v1".into(),
            installation_id: owner.clone(),
            engine_id: "test-engine".into(),
            network_id: network.clone(),
            generation_receipt_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&generation).unwrap())
            ),
            files,
            activated: false,
            root_retired: false,
            installation_ready: false,
        };
        let mut plan = loaded.application;
        plan.model["secrets"] = json!({});
        let mut references = Vec::new();
        for name in binding.files.keys() {
            plan.model["secrets"][name] =
                json!({"file":installation.join("secrets").join(name).to_str().unwrap()});
            references.push(json!({"source":name}));
        }
        plan.model["services"]["gateway"]["secrets"] = json!(references);
        crate::installer_generation_binding::apply_model(&installation, &binding, &mut plan)
            .unwrap();
        record(
            "application-plan.json",
            &serde_json::to_value(&plan).unwrap(),
        );
        put(
            installation.join("evidence/application-compose.json"),
            &crate::installer_application::compose_document(&plan.model).unwrap(),
            0o600,
        );
        let source_env = format!(
            "SELFHOST_SECRET_DIR='{}'\n",
            installation.join("secrets").display()
        )
        .into_bytes();
        let env = crate::installer_application_env::select_generation(&source_env, &installation)
            .unwrap();
        put(
            installation.join("evidence/application-source.env"),
            &source_env,
            0o600,
        );
        put(installation.join("evidence/application.env"), &env, 0o600);
        let binding_value = serde_json::to_value(&binding).unwrap();
        record("application-generation.json", &binding_value);
        record("application-generation-pending.json", &binding_value);
        let hash_file = |name: &str| {
            format!(
                "{:x}",
                Sha256::digest(fs::read(installation.join("evidence").join(name)).unwrap())
            )
        };
        record(
            "application-generation-selection.json",
            &json!({"schema":"elevenid.installer-application-generation-selection/v1","installation_id":owner,"engine_id":"test-engine","binding_sha256":hash_file("application-generation.json"),"plan_sha256":hash_file("application-plan.json"),"compose_sha256":hash_file("application-compose.json"),"env_sha256":hash_file("application.env"),"activated":false,"installation_ready":false}),
        );
        (root, args)
    }
    #[test]
    fn pre_application_selected_generation_and_five_helpers_are_bound() {
        use crate::installer_state::{CleanupState, LockedInspection};
        let (root, args) = selected_pre_application_mock();
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let loaded = load(&state, &installation).unwrap();
        assert_eq!(loaded.helper_ids.len(), 5);
        assert_eq!(loaded.generation.as_ref().unwrap().files.len(), 41);
        unchanged(&state, &loaded).unwrap();
        drop(state);
        for stage in ["renewal", "generation"] {
            let path = installation
                .join("evidence")
                .join(format!("{stage}-result.json"));
            let original = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(uninstall_inner(&args).is_err());
            fs::write(&path, &original).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let mut bad: Value = parse(&original).unwrap();
            bad["network_id"] = json!("d".repeat(64));
            save(&path, &bad);
            assert!(uninstall_inner(&args).is_err());
            fs::write(&path, &original).unwrap();
            assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
        }
        assert!(uninstall_inner(&args).is_ok());
        let inspection = LockedInspection::open(&installation).unwrap();
        assert_eq!(
            inspection.cleanup_status().unwrap().state,
            CleanupState::Completed
        );
        assert_eq!(
            fs::read(installation.join("application-generation/postgres_password")).unwrap(),
            b"unchanged-synthetic-scalar"
        );
        assert_eq!(ledger(&root)["mutations"].as_array().unwrap().len(), 9);
    }
    #[test]
    fn pre_application_records_and_mid_cleanup_drift_refuse() {
        for name in [
            "application-discovered-resources.json",
            "application-prestart-admission.json",
            "application-start-gateway.json",
            "application-observed-gateway.json",
            "application-start-result.json",
        ] {
            let (root, args) = pre_application_mock("success");
            save(root.path().join("install/evidence").join(name), &json!({}));
            assert!(uninstall_inner(&args).is_err());
            assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
        }
        for name in [
            "application-start-intent.json",
            "tls-result.json",
            "ingress-container-removed.json",
        ] {
            let (root, args) = pre_application_mock("success");
            fs::remove_file(root.path().join("install/evidence").join(name)).unwrap();
            assert!(uninstall_inner(&args).is_err());
            assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
        }
        for (field, value) in [
            ("schema", json!("unknown")),
            ("installation_id", json!(uuid::Uuid::new_v4().to_string())),
            ("engine_id", json!("other-engine")),
            ("network_id", json!("d".repeat(64))),
            ("project", json!("other-project")),
            ("roles", json!([])),
            ("redis_volume", json!("other-volume")),
            ("installation_ready", json!(true)),
        ] {
            let (root, args) = pre_application_mock("success");
            let path = root
                .path()
                .join("install/evidence/application-start-intent.json");
            let mut intent: Value = parse(&fs::read(&path).unwrap()).unwrap();
            intent[field] = value;
            save(&path, &intent);
            assert!(uninstall_inner(&args).is_err(), "{field}");
            assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
        }
        for mode in ["volume-drift", "record-drift"] {
            let (root, args) = pre_application_mock(mode);
            assert!(uninstall_inner(&args).is_err());
            let saved = ledger(&root);
            assert_eq!(saved["mutations"].as_array().unwrap().len(), 1);
            assert_eq!(saved["containers"].as_object().unwrap().len(), 4);
            assert!(root
                .path()
                .join("install/evidence/uninstall-plan.json")
                .exists());
            assert!(!root
                .path()
                .join("install/evidence/uninstall-result.json")
                .exists());
            assert!(uninstall_inner(&args).is_err());
            assert_eq!(ledger(&root)["mutations"], saved["mutations"]);
        }
    }
    #[test]
    fn application_generation_partial_selection_refuses_without_mutation() {
        use std::os::unix::fs::PermissionsExt;
        let (root, _) = mock("success");
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let legacy = load(&state, &installation).unwrap();
        let mut changed = ApplicationModelPlan {
            model: legacy.application.model.clone(),
            selected_services: legacy.application.selected_services.clone(),
            expected_network_id: legacy.application.expected_network_id.clone(),
            installation_ready: false,
        };
        changed.model["secrets"]["marty_db_password"]["file"] =
            json!(installation.join("application-generation/marty_db_password"));
        assert!(require_no_selected_generation(&installation, &changed).is_err());
        for marker in [
            "application-generation-pending.json",
            "application-generation.json",
            "application-generation-selection.json",
        ] {
            let path = installation.join("evidence").join(marker);
            fs::write(&path, b"{}").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(load(&state, &installation).is_err());
            assert!(unchanged(&state, &legacy).is_err());
            fs::remove_file(path).unwrap();
        }
        let path = installation.join("application-generation");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(load(&state, &installation).is_err());
        assert!(unchanged(&state, &legacy).is_err());
        assert_eq!(ledger(&root)["mutations"], json!([]));
    }

    #[test]
    fn selected_generation_graph_preserves_initializer_barrier_and_exact_exclusions() {
        let (root, _) = mock("success");
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let loaded = load(&state, &installation).unwrap();
        let plan = loaded.application;
        let order =
            crate::installer_application_graph::startup_order(&plan.model, &plan.selected_services)
                .unwrap();
        let mut selected = plan.model.clone();
        for name in ["cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"] {
            selected["services"].as_object_mut().unwrap().remove(name);
        }
        assert_eq!(
            crate::installer_application_graph::startup_order(&selected, &plan.selected_services)
                .unwrap(),
            order
        );
        let mut partial = selected.clone();
        partial["services"]["cloudflared"] = plan.model["services"]["cloudflared"].clone();
        assert!(crate::installer_application_graph::startup_order(
            &partial,
            &plan.selected_services
        )
        .is_err());
        selected["services"]
            .as_object_mut()
            .unwrap()
            .remove("kms-initialize");
        assert!(crate::installer_application_graph::startup_order(
            &selected,
            &plan.selected_services
        )
        .is_err());
    }
    #[test]
    fn renewal_cleanup_requires_complete_removal_and_rechecks_legacy_absence() {
        use std::os::unix::fs::PermissionsExt;
        let (root, args) = mock("success");
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let legacy = load(&state, &installation).unwrap();
        assert_eq!(legacy.helper_ids.len(), 3);
        for marker in [
            "renewal-pending.json",
            "renewal-container.json",
            "renewal-result.json",
        ] {
            let path = installation.join("evidence").join(marker);
            std::fs::write(&path, b"{}").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(load(&state, &installation).is_err());
            assert!(unchanged(&state, &legacy).is_err());
            std::fs::remove_file(path).unwrap();
        }
        for marker in ["renewal-inputs", "renewal-transfer"] {
            let path = installation.join(marker);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(load(&state, &installation).is_err());
            std::fs::remove_dir(path).unwrap();
        }
        let ingress: Value = serde_json::from_slice(
            &std::fs::read(installation.join("evidence/ingress-container-removed.json")).unwrap(),
        )
        .unwrap();
        let mut receipt = serde_json::to_value(crate::installer_renewal::RenewalReceipt {
            schema: "elevenid.installer-renewal-host/v1",
            installation_id: legacy.plan.installation_id.clone(),
            engine_id: legacy.plan.engine_id.clone(),
            container_id: "e".repeat(64),
            container_name: format!("{}-renewal-inputs", legacy.plan.project),
            network_id: legacy.plan.network_id.clone(),
            image: ingress["image"].as_str().unwrap_or("fixture-image").into(),
            root_retired: false,
            ingress_renewal: false,
            private_identity_validated: true,
            outputs: [
                "renewal-role-id",
                "renewal-secret-id",
                "renewal-leaf-policies.json",
            ]
            .map(String::from)
            .to_vec(),
            container_removed: true,
            installation_ready: false,
        })
        .unwrap();
        let path = installation.join("evidence/renewal-container-removed.json");
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let renewed = load(&state, &installation).unwrap();
        assert_eq!(renewed.helper_ids.len(), 4);
        assert_eq!(renewed.plan.resources.len(), 34);
        assert_eq!(renewed.plan.source_hashes.len(), 9);
        assert!(unchanged(&state, &legacy).is_err());
        receipt["container_removed"] = json!(false);
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(load(&state, &installation).is_err());
        assert!(unchanged(&state, &renewed).is_err());
        receipt["container_removed"] = json!(true);
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        drop(state);
        let mut saved = ledger(&root);
        let mut live = saved["containers"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        live["Id"] = receipt["container_id"].clone();
        live["Name"] = json!(format!("/{}", receipt["container_name"].as_str().unwrap()));
        saved["containers"]["e".repeat(64)] = live;
        fs::write(
            root.path().join("ledger.json"),
            serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
        assert_eq!(uninstall(&args).unwrap_err(), REFUSED);
        assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
    }
    #[test]
    fn generation_cleanup_refuses_partial_stage_and_tracks_completed_helper() {
        use std::os::unix::fs::PermissionsExt;
        let (root, args) = mock("success");
        let installation = root.path().join("install");
        let state = LockedMaintenance::open(&installation).unwrap();
        let legacy = load(&state, &installation).unwrap();
        let put = |name: &str, value: &Value| {
            let path = installation.join("evidence").join(name);
            fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        };
        for name in [
            "generation-pending.json",
            "generation-container.json",
            "generation-result.json",
            "generation-observation.json",
        ] {
            put(name, &json!({}));
            assert!(load(&state, &installation).is_err());
            assert!(unchanged(&state, &legacy).is_err());
            fs::remove_file(installation.join("evidence").join(name)).unwrap();
        }
        for name in [
            "generation-inputs",
            "generation-identity",
            "generation-transfer",
        ] {
            let path = installation.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(load(&state, &installation).is_err());
            assert!(unchanged(&state, &legacy).is_err());
            fs::remove_dir(path).unwrap();
        }
        let receipt = crate::installer_generation_host::GenerationReceipt {
            schema: "elevenid.installer-generation-host/v1",
            installation_id: legacy.plan.installation_id.clone(),
            engine_id: legacy.plan.engine_id.clone(),
            container_id: "f".repeat(64),
            container_name: format!("{}-generation-inputs", legacy.plan.project),
            network_id: legacy.plan.network_id.clone(),
            image: "fixture-image".into(),
            candidate_validated: true,
            outputs: crate::installer_renewal_bootstrap::current_inputs()
                .into_iter()
                .collect(),
            candidate_sha256: crate::installer_renewal_bootstrap::current_inputs()
                .into_iter()
                .map(|name| (name, "a".repeat(64)))
                .collect(),
            activated: false,
            root_retired: false,
            ingress_renewal: false,
            container_removed: true,
            installation_ready: false,
        };
        let candidate = serde_json::to_value(receipt).unwrap();
        put("generation-container-removed.json", &candidate);
        assert!(
            load(&state, &installation).is_err(),
            "generation cannot lack renewal evidence"
        );
        // The production generation receipt and historical renewal identity
        // must both participate in cleanup's immutable source closure.
        let renewal = serde_json::to_value(crate::installer_renewal::RenewalReceipt {
            schema: "elevenid.installer-renewal-host/v1",
            installation_id: legacy.plan.installation_id.clone(),
            engine_id: legacy.plan.engine_id.clone(),
            container_id: "e".repeat(64),
            container_name: format!("{}-renewal-inputs", legacy.plan.project),
            network_id: legacy.plan.network_id.clone(),
            image: "fixture-image".into(),
            root_retired: false,
            ingress_renewal: false,
            private_identity_validated: true,
            outputs: [
                "renewal-role-id",
                "renewal-secret-id",
                "renewal-leaf-policies.json",
            ]
            .map(String::from)
            .to_vec(),
            container_removed: true,
            installation_ready: false,
        })
        .unwrap();
        put("renewal-container-removed.json", &renewal);
        let complete = load(&state, &installation).unwrap();
        assert_eq!(complete.helper_ids.len(), 5);
        assert_eq!(complete.plan.source_hashes.len(), 10);
        assert_eq!(complete.plan.resources.len(), 34);
        assert!(unchanged(&state, &legacy).is_err());
        drop(state);
        let mut saved = ledger(&root);
        let mut live = saved["containers"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        live["Id"] = candidate["container_id"].clone();
        live["Name"] = json!(format!(
            "/{}",
            candidate["container_name"].as_str().unwrap()
        ));
        saved["containers"]["f".repeat(64)] = live;
        fs::write(
            root.path().join("ledger.json"),
            serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
        assert_eq!(uninstall(&args).unwrap_err(), REFUSED);
        assert!(ledger(&root)["mutations"].as_array().unwrap().is_empty());
    }
    #[test]
    fn full_mocked_cleanup_retains_data_and_recovers_interrupted_removal() {
        for mode in ["success", "interruption"] {
            let (root, args) = mock(mode);
            if mode == "interruption" {
                assert_eq!(uninstall(&args).unwrap_err(), REFUSED);
                let s = ledger(&root);
                assert_eq!(s["containers"].as_object().unwrap().len(), 33);
                assert!(root
                    .path()
                    .join("install/evidence/uninstall-plan.json")
                    .exists());
                assert!(!root
                    .path()
                    .join("install/evidence/uninstall-result.json")
                    .exists());
            }
            let output = uninstall_inner(&args).unwrap_or_else(|error| {
                let saved = ledger(&root);
                let commands = saved["commands"].as_array().unwrap();
                panic!(
                    "mock {mode} failed: {error}; last synthetic commands={:?}; mutations={}",
                    &commands[commands.len().saturating_sub(8)..],
                    saved["mutations"]
                )
            });
            let result: Value = parse(output.as_bytes()).unwrap();
            assert_eq!(result["containers_removed"], 34);
            assert_eq!(result["host_data_retained"], true);
            let inspection =
                crate::installer_state::LockedInspection::open(&root.path().join("install"))
                    .unwrap();
            let cleanup = inspection.cleanup_status().unwrap();
            assert_eq!(
                cleanup.state,
                crate::installer_state::CleanupState::Completed
            );
            assert!(!cleanup.runtime_observed);
            assert_eq!(cleanup.data_retained, Some(true));
            drop(inspection);
            let s = ledger(&root);
            assert!(s["containers"].as_object().unwrap().is_empty());
            assert_eq!(s["network_exists"], false);
            assert!(s["volume"].is_object());
            assert!(s["image"].is_object());
            assert_eq!(
                fs::read(root.path().join("install/retained-data")).unwrap(),
                b"private data stays"
            );
            let mutations = s["mutations"].as_array().unwrap();
            assert_eq!(mutations.iter().filter(|a| a[0] == "rm").count(), 34);
            assert_eq!(mutations.iter().filter(|a| a[0] == "stop").count(), 34);
            assert_eq!(mutations.iter().filter(|a| a[0] == "network").count(), 1);
            assert_eq!(mutations.len(), 69);
            assert!(uninstall(&args).is_ok());
            assert_eq!(ledger(&root)["mutations"], s["mutations"]);
        }
    }
    #[test]
    fn full_mocked_cleanup_refuses_foreign_or_uncertain_inventory_without_mutation() {
        for mode in [
            "foreign-attachment",
            "unknown",
            "replacement",
            "command-failure",
        ] {
            let (root, args) = mock(mode);
            assert_eq!(uninstall(&args).unwrap_err(), REFUSED, "{mode}");
            assert!(
                ledger(&root)["mutations"].as_array().unwrap().is_empty(),
                "{mode}"
            );
            assert!(!root
                .path()
                .join("install/evidence/uninstall-result.json")
                .exists());
        }
    }
    #[test]
    fn cleanup_receipts_survive_reopen_and_refuse_rebinding() {
        use crate::installer_state::{Identity, InstallerState};
        use std::{fs, os::unix::fs::PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("install");
        let mut initial = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        initial.create_private_directory("evidence").unwrap();
        drop(initial);
        let intent = json!({"operation":"remove-container","resource_id":"c".repeat(64)});
        let mut first = LockedMaintenance::open(&path).unwrap();
        assert!(!receipt(&first, "uninstall-test.json", &intent).unwrap());
        record(&mut first, "uninstall-test.json", &intent).unwrap();
        drop(first); // Simulate interruption after durable intent, before result.
        let mut resumed = LockedMaintenance::open(&path).unwrap();
        assert!(receipt(&resumed, "uninstall-test.json", &intent).unwrap());
        record(&mut resumed, "uninstall-test.json", &intent).unwrap();
        let replacement = json!({"operation":"remove-container","resource_id":"d".repeat(64)});
        assert!(record(&mut resumed, "uninstall-test.json", &replacement).is_err());
        assert!(receipt(&resumed, "uninstall-test.json", &intent).unwrap());
        assert!(resumed
            .read_evidence("uninstall-result.json")
            .unwrap()
            .is_none());
    }
    #[test]
    fn closed_arguments_never_enable_purge_or_force() {
        for args in [
            vec!["--install-dir", "/private/install", "--purge", "true"],
            vec!["--install-dir", "relative"],
            vec!["--install-dir", "/a", "--install-dir", "/b"],
            vec!["--install-dir", "/a", "--docker-bin", "docker"],
        ] {
            assert!(arguments(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
        assert!(arguments(&["--install-dir".into(), "/private/install".into()]).is_ok());
    }
    #[test]
    fn identity_inventory_rejects_partial_and_ambiguous_responses() {
        let a = "a".repeat(64);
        assert_eq!(ids(&format!("{a}\n")).unwrap(), BTreeSet::from([a.clone()]));
        assert!(ids(&format!("{a}\n{a}\n")).is_err());
        assert!(ids("No such container").is_err());
        assert!(object("[]").is_err());
        assert!(object("[{},{ }]").is_err());
    }
    #[test]
    fn immutable_cleanup_plan_binds_exact_order_and_source_hashes() {
        let plan = CleanupPlan {
            schema: "elevenid.installer-uninstall-plan/v1".into(),
            installation_id: "owner".into(),
            engine_id: "engine".into(),
            project: "project".into(),
            network_id: "a".repeat(64),
            network_name: "network".into(),
            retained_redis_volume: Some("redis".into()),
            absent_redis_volume: None,
            resources: vec![Resource {
                role: "gateway".into(),
                container_id: "b".repeat(64),
                bao: false,
            }],
            source_hashes: BTreeMap::from([("root/openbao-created.json".into(), "c".repeat(64))]),
        };
        let mut changed = serde_json::to_value(&plan).unwrap();
        changed["resources"][0]["container_id"] = json!("d".repeat(64));
        assert!(parse::<CleanupPlan>(&serde_json::to_vec(&changed).unwrap()).unwrap() != plan);
        changed = serde_json::to_value(&plan).unwrap();
        changed["purge"] = json!(true);
        assert!(parse::<CleanupPlan>(&serde_json::to_vec(&changed).unwrap()).is_err());
        assert_ne!(
            operation(&plan, "remove-container", "id"),
            operation(&plan, "observed-absent", "id")
        );
    }
}
