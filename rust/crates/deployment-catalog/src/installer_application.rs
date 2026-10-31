//! Dynamic installation inputs and credential selection around native Compose.
//! Service topology, limits and lifecycle dependencies live in verified YAML.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_env::{self, ApplicationParameters},
    installer_compose::{
        BoundFile, ComposeInputs, ComposeReceipt, ComposeSession, RuntimeCleanupPlan,
        RUNTIME_CLEANUP_PLAN,
    },
    installer_openbao::OpenBaoInventory,
    installer_state::{InstallerState, Phase},
    installer_tls_outputs::bundle_text,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::TcpListener,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const LAYERS: &str = "deploy-config/compose/selfhost-installer";
fn encode(value: &str) -> Result<String> {
    if value
        .chars()
        .any(|c| c.is_control() || c == '\'' || c == '\\')
    {
        return Err("installation value cannot be encoded safely".into());
    }
    Ok(format!("'{value}'"))
}
fn append(env: &mut Vec<u8>, key: &str, value: &str) -> Result<()> {
    let line = format!("{key}={}", encode(value)?);
    let text = std::str::from_utf8(env).map_err(|_| "invalid installation environment")?;
    if let Some(existing) = text.lines().find(|l| l.starts_with(&format!("{key}="))) {
        if existing != line {
            return Err("conflicting installation environment input".into());
        }
    } else {
        env.extend_from_slice(format!("{line}\n").as_bytes());
    }
    Ok(())
}
fn path(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| "installation path is not UTF-8".into())
}
pub(crate) fn bound(path: PathBuf) -> Result<BoundFile> {
    let bytes = crate::installer_verify::read_private_bytes(&path, 2 * 1024 * 1024)?;
    Ok(BoundFile {
        path,
        sha256: crate::installer_release::sha256(&bytes),
    })
}
fn bundle_bound(bundle: &Path, name: &str) -> Result<BoundFile> {
    let text = bundle_text(bundle, name, 2 * 1024 * 1024)?;
    Ok(BoundFile {
        path: bundle.join(name),
        sha256: crate::installer_release::sha256(text.as_bytes()),
    })
}
/// Only installation-specific values are generated. All layers must already
/// belong to the authenticated bundle (or explicit unsigned development scope).
pub(crate) fn bootstrap_inputs(
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    images: &BTreeMap<String, String>,
    nonce: &str,
) -> Result<ComposeInputs> {
    let binding = state.journal().runtime().ok_or("runtime binding absent")?;
    let mut env = Vec::new();
    for (name, value) in [
        ("MARTY_INSTALLATION_DIR", path(installation)?.to_owned()),
        (
            "MARTY_INSTALLATION_ID",
            state.journal().installation_id().to_string(),
        ),
        (
            "MARTY_INSTALLER_SERVICES_IMAGE",
            images.get("gateway").ok_or("gateway image absent")?.clone(),
        ),
        (
            "MARTY_OPENBAO_DIDCOMM_IMAGE",
            images
                .get("openbao_didcomm_image")
                .ok_or("OpenBao image absent")?
                .clone(),
        ),
        ("MARTY_KEYCLOAK_NONCE", nonce.into()),
        (
            "MARTY_SELFHOST_PROJECT",
            format!(
                "marty-selfhost-disposable-{}",
                state.journal().installation_id().simple()
            ),
        ),
        (
            "SELFHOST_OPENBAO_STATE_DIR",
            path(&installation.join("openbao-state"))?.into(),
        ),
        (
            "SELFHOST_SECRET_DIR",
            path(&installation.join("secrets"))?.into(),
        ),
        (
            "SELFHOST_OPENBAO_HOST_PORT",
            binding.openbao_port.to_string(),
        ),
    ] {
        append(&mut env, name, &value)?;
    }
    let port = binding.openbao_port;
    state.write_evidence("bootstrap.env", &env)?;
    let writable_bind_roots = [
        "secrets",
        "openbao-state",
        "keycloak-output",
        "tls-output",
        "ingress-output",
        "renewal-transfer",
        "generation-transfer",
        "state",
        "backups",
        "openbao-exports",
        "openbao-snapshot-identity",
    ]
    .into_iter()
    .map(|n| installation.join(n))
    .collect();
    let mut readonly_bind_roots: BTreeSet<_> = [
        "marty-deploy",
        "evidence",
        "renewal-inputs",
        "generation-inputs",
        "generation-identity",
        "application-generation",
    ]
    .into_iter()
    .map(|n| installation.join(n))
    .collect();
    readonly_bind_roots.insert(bundle.into());
    Ok(ComposeInputs {
        installation: installation.into(),
        project: state.journal().compose_project(),
        files: vec![
            bundle_bound(bundle, "docker-compose.selfhost.openbao.yml")?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.bootstrap.yml"))?,
        ],
        bound_inputs: Vec::new(),
        environment: bound(installation.join("evidence/bootstrap.env"))?,
        profiles: vec!["setup".into()],
        services: vec![],
        approved_images: images.values().cloned().collect(),
        writable_bind_roots,
        readonly_bind_roots,
        allowed_loopback_ports: BTreeSet::from([port]),
        prior: None,
    })
}
pub(crate) fn job_inputs(
    base: &ComposeInputs,
    prior: ComposeReceipt,
    service: &str,
) -> ComposeInputs {
    let mut inputs = base.clone();
    inputs.prior = Some(prior);
    inputs.services = vec![service.into()];
    inputs
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound provisioning inputs explicit at this boundary."
)]
pub fn start(
    docker_path: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    images: &BTreeMap<String, String>,
    bootstrap: &ComposeInputs,
    prior: ComposeReceipt,
) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    crate::installer_openbao::require_binding(state, bao)?;
    let binding = state
        .journal()
        .runtime()
        .ok_or("runtime binding absent")?
        .clone();
    let mut reservations = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..4 {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "cannot reserve loopback port")?;
        let port = listener
            .local_addr()
            .map_err(|_| "loopback reservation unavailable")?
            .port();
        if port < 1024 || port == binding.openbao_port {
            return Err("loopback port conflicts with runtime".into());
        }
        ports.push(port);
        reservations.push(listener);
    }
    let origin = format!("https://localhost:{}", ports[0]);
    let group = crate::installer_state::applicant_container_group(&binding)?;
    let parameters = ApplicationParameters {
        installation: installation.into(),
        applicant_container_group: group,
        version: state.journal().identity().release_tag.clone(),
        origin: origin.clone(),
        gateway_port: ports[1],
        keycloak_port: ports[2],
        edge_port: ports[3],
        openbao_port: binding.openbao_port,
    };
    let tls = crate::installer_verify::read_private_record(
        &installation.join("evidence/selfhost-tls-kms.env.fragment"),
    )?;
    let env = installer_application_env::render(
        &bundle_text(bundle, ".env.selfhost.production.example", 16384)?,
        &bundle_text(bundle, "docker-compose.yml", 262144)?,
        std::str::from_utf8(&tls).map_err(|_| "invalid TLS environment fragment")?,
        &parameters,
        images,
    )?;
    state.prepare_application_storage()?;
    if state.validate_applicant_storage()? != group.host_gid() {
        return Err("applicant state group changed".into());
    }
    state.persist_application_storage_creation_receipt(installation)?;
    state.stage_operator_password()?;
    let nginx = crate::installer_ingress_config::render(
        &bundle_text(bundle, "docker/nginx-selfhost.prod.conf.template", 131072)?,
        &origin,
    )?;
    state.write_evidence("installer-nginx.conf", nginx.as_bytes())?;
    state.write_evidence("application-intent.json",&serde_json::to_vec(&json!({"schema":"elevenid.installer-application-intent/v2",
        "installation_id":state.journal().installation_id(),"project":state.journal().compose_project(),"origin":origin,
        "engine_id":binding.engine_id,"directories":env.required_private_directories,"installation_ready":false})).map_err(|_| "cannot encode application intent")?)?;
    let mut source_env = env.env_bytes;
    let bootstrap_env =
        crate::installer_verify::read_private_bytes(&bootstrap.environment.path, 65536)?;
    for line in std::str::from_utf8(&bootstrap_env)
        .map_err(|_| "invalid bootstrap environment")?
        .lines()
    {
        let (key, quoted) = line.split_once('=').ok_or("invalid bootstrap input")?;
        let value = quoted
            .strip_prefix('\'')
            .and_then(|v| v.strip_suffix('\''))
            .ok_or("invalid quoted bootstrap input")?;
        append(&mut source_env, key, value)?;
    }
    for (key, value) in [
        (
            "MARTY_INSTALLER_ID",
            state.journal().installation_id().to_string(),
        ),
        (
            "MARTY_INSTALLER_APPLICANT_CONTAINER_GID",
            group.container_gid().to_string(),
        ),
        (
            "MARTY_INSTALLER_NGINX_CONFIG",
            path(&installation.join("evidence/installer-nginx.conf"))?.into(),
        ),
        (
            "MARTY_INSTALLER_HELPER_IMAGE",
            images.get("gateway").ok_or("gateway image absent")?.clone(),
        ),
        ("MARTY_INSTALLER_HTTPS_PORT", ports[0].to_string()),
        (
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            crate::installer_ingress_provision::resource_name(
                &state.journal().installation_id().to_string(),
            )?,
        ),
    ] {
        append(&mut source_env, key, &value)?;
    }
    state.write_evidence("application-source.env", &source_env)?;
    let mut inputs = bootstrap.clone();
    inputs.prior = Some(prior);
    inputs.services.clear();
    inputs.profiles = vec!["installer-init".into()];
    inputs.allowed_loopback_ports.extend(ports.iter().copied());
    inputs.files = vec![
        bundle_bound(bundle, "docker-compose.yml")?,
        bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
    ];
    inputs.environment = bound(installation.join("evidence/application-source.env"))?;
    let source = ComposeSession::new(docker_path, &binding, inputs.clone())?;
    let generation = crate::installer_generation_binding::stage(
        installation,
        state,
        source.model(),
        &bao.network_id,
    )?;
    state.write_evidence(
        "application.env",
        &installer_application_env::select_generation(&source_env, installation)?,
    )?;
    inputs.environment = bound(installation.join("evidence/application.env"))?;
    let application = ComposeSession::new(docker_path, &binding, inputs.clone())?;
    crate::installer_generation_binding::verify_model(
        installation,
        &generation,
        application.model(),
        &bao.network_id,
    )?;
    state.write_evidence(
        "application-native-model.json",
        &serde_json::to_vec(application.model()).map_err(|_| "cannot record native model")?,
    )?;
    crate::installer_generation_binding::publish_selection(installation, state, &generation)?;
    // Authenticate and save the whole removal scope BEFORE any application
    // mutation. A later finite runtime failure never fabricates a success receipt.
    let mut maintenance_inputs = inputs.clone();
    maintenance_inputs.profiles = vec!["setup".into(), "installer-init".into()];
    maintenance_inputs.files = vec![
        bundle_bound(bundle, "docker-compose.yml")?,
        bundle_bound(bundle, "docker-compose.selfhost.openbao.yml")?,
        bundle_bound(bundle, &format!("{LAYERS}/compose.bootstrap.yml"))?,
        bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
        bundle_bound(bundle, &format!("{LAYERS}/compose.runtime.yml"))?,
    ];
    let planned = ComposeSession::new(docker_path, &binding, maintenance_inputs.clone())?;
    let cleanup_plan = RuntimeCleanupPlan {
        schema: "elevenid.installer-runtime-cleanup-plan/v1".into(),
        installation_id: state.journal().installation_id().to_string(),
        inputs: maintenance_inputs.clone(),
        model: planned.model().clone(),
        configuration_sha256: planned.configuration_sha256().into(),
        application_configuration_sha256: application.configuration_sha256().into(),
    };
    state.write_evidence(
        RUNTIME_CLEANUP_PLAN,
        &serde_json::to_vec(&cleanup_plan).map_err(|_| "cannot record runtime cleanup plan")?,
    )?;
    inputs
        .bound_inputs
        .extend(maintenance_inputs.files.iter().cloned());
    inputs.bound_inputs.push(bound(
        installation.join("evidence").join(RUNTIME_CLEANUP_PLAN),
    )?);
    let application = ComposeSession::new(docker_path, &binding, inputs)?;
    application.pull()?;
    drop(reservations);
    let started = application.up_wait(state, "application-up", Duration::from_secs(720))?;
    // The maintenance union includes every retained setup role, but is resolved
    // and observed only. It is never used to start or replay initialization.
    maintenance_inputs.prior = Some(started);
    let maintenance = ComposeSession::new(docker_path, &binding, maintenance_inputs.clone())?;
    let receipt = maintenance.checkpoint(state, "maintenance-checkpoint")?;
    maintenance_inputs.prior = Some(receipt.clone());
    state.write_evidence("compose-session.json",&serde_json::to_vec(&json!({
        "schema":"elevenid.installer-compose-session/v1","installation_id":state.journal().installation_id(),
        "inputs":maintenance_inputs,"model":maintenance.model(),"configuration_sha256":maintenance.configuration_sha256(),"receipt":receipt,
    })).map_err(|_| "cannot record maintenance session")?)?;
    Ok(())
}
