//! Prepare application inputs without starting services or claiming readiness.
//! Ports remain reserved until the caller deliberately releases them for startup.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_env::{self, ApplicationParameters},
    installer_application_model::{self, ApplicationModelParameters, ApplicationModelPlan},
    installer_openbao::{self, OpenBaoInventory},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_tls_outputs::bundle_text,
};
use serde_json::json;
use std::{collections::BTreeMap, net::TcpListener, path::Path};
type Result<T> = std::result::Result<T, String>;

pub struct PreparedApplication {
    pub plan: ApplicationModelPlan,
    pub origin: String,
    pub port_reservations: Vec<TcpListener>,
}

/// Preserve Compose's normalized interpolation escaping when serializing its
/// model again. The real-source Compose roundtrip test verifies execution fields;
/// escaping dollars again would alter runtime credential-variable templates.
pub fn compose_document(model: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(model).map_err(|_| "cannot serialize application Compose document".into())
}

pub fn prepare(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    images: &BTreeMap<String, String>,
) -> Result<PreparedApplication> {
    prepare_inner(dockerpath, installation, bundle, state, bao, images, false)
}

/// Explicit generation selection, still without starting any application services.
pub fn prepare_with_generation(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    images: &BTreeMap<String, String>,
) -> Result<PreparedApplication> {
    prepare_inner(dockerpath, installation, bundle, state, bao, images, true)
}
fn prepare_inner(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    images: &BTreeMap<String, String>,
    select_generation: bool,
) -> Result<PreparedApplication> {
    state.require_live_phase(Phase::Provisioning)?;
    let binding = state
        .journal()
        .runtime()
        .ok_or("installer runtime binding absent")?
        .clone();
    let docker = DockerRunner::new(
        dockerpath,
        &binding.docker_host,
        &binding.engine_id,
        installation,
    )?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let mut reservations = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..4 {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "cannot reserve application port")?;
        let port = listener
            .local_addr()
            .map_err(|_| "cannot inspect application port")?
            .port();
        if port < 1024 || port == binding.openbao_port {
            return Err("application port conflicts with runtime binding".into());
        }
        ports.push(port);
        reservations.push(listener);
    }
    let origin = format!("https://localhost:{}", ports[0]);
    let parameters = ApplicationParameters {
        installation: installation.into(),
        version: state.journal().identity().release_tag.clone(),
        origin: origin.clone(),
        gateway_port: ports[1],
        keycloak_port: ports[2],
        edge_port: ports[3],
        openbao_port: binding.openbao_port,
    };
    let example = bundle_text(bundle, ".env.selfhost.production.example", 16384)?;
    let compose = bundle_text(bundle, "docker-compose.yml", 262144)?;
    let tls_fragment = crate::installer_verify::read_private_record(
        &installation.join("evidence/selfhost-tls-kms.env.fragment"),
    )?;
    let env = installer_application_env::render(
        &example,
        &compose,
        std::str::from_utf8(&tls_fragment).map_err(|_| "invalid TLS environment receipt")?,
        &parameters,
        images,
    )?;
    let nginx = crate::installer_ingress_config::render(
        &bundle_text(bundle, "docker/nginx-selfhost.prod.conf.template", 131072)?,
        &origin,
    )?;
    let project = state.journal().compose_project();
    state.write_evidence("application-intent.json", &serde_json::to_vec(&json!({
        "schema":"elevenid.installer-application-intent/v1", "installation_id":state.journal().installation_id(),
        "project":project, "origin":origin, "engine_id":binding.engine_id,
        "openbao_network_name":bao.network_name, "openbao_network_id":bao.network_id,
        "render_only_ports":ports[1..], "directories":env.required_private_directories,
        "optional_empty_secrets":env.optional_empty_secrets, "installation_ready":false,
    })).map_err(|_| "cannot serialize application intent")?)?;
    state.prepare_application_storage()?;
    state.persist_application_storage_creation_receipt(installation)?;
    state.stage_operator_password()?;
    let source_env = if select_generation {
        "application-source.env"
    } else {
        "application.env"
    };
    state.write_evidence(source_env, &env.env_bytes)?;
    state.write_evidence("installer-nginx.conf", nginx.as_bytes())?;
    let env_path = installation.join("evidence").join(source_env);
    let compose_path = bundle.join("docker-compose.yml");
    let output = docker.run_checked(&[
        "compose",
        "--project-name",
        &project,
        "--env-file",
        env_path.to_str().ok_or("invalid environment path")?,
        "-f",
        compose_path.to_str().ok_or("invalid Compose path")?,
        "--profile",
        "*",
        "config",
        "--format",
        "json",
    ])?;
    let model = serde_json::from_str(&output).map_err(|_| "invalid application Compose model")?;
    let mut plan = installer_application_model::prepare(
        &model,
        images,
        &ApplicationModelParameters {
            installation: installation.into(),
            bundle: bundle.into(),
            compose_project: project,
            openbao_network_name: bao.network_name.clone(),
            openbao_network_id: bao.network_id.clone(),
            origin: origin.clone(),
        },
    )?;
    crate::installer_ingress_model::add(
        &mut plan,
        installation,
        &state.journal().installation_id().to_string(),
        &origin,
        images
            .get("gateway")
            .ok_or("admitted ingress image absent")?,
    )?;
    let mut selected_binding = None;
    if select_generation {
        let generation = crate::installer_generation_binding::stage(installation, state, &plan)?;
        crate::installer_generation_binding::apply_model(installation, &generation, &mut plan)?;
        let selected_env =
            installer_application_env::select_generation(&env.env_bytes, installation)?;
        state.write_evidence("application.env", &selected_env)?;
        crate::installer_generation_binding::verify(installation, &generation)?;
        selected_binding = Some(generation);
    }
    state.write_evidence("application-compose.json", &compose_document(&plan.model)?)?;
    state.write_evidence(
        "application-plan.json",
        &serde_json::to_vec(&plan).map_err(|_| "cannot serialize application plan")?,
    )?;
    if let Some(generation) = selected_binding {
        crate::installer_generation_binding::publish_selection(installation, state, &generation)?;
    }
    Ok(PreparedApplication {
        plan,
        origin,
        port_reservations: reservations,
    })
}
