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
use marty_selfhost_identity::origin::PublicOrigin;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::TcpListener,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const LAYERS: &str = "deploy-config/compose/selfhost-installer";

/// An ACME order may remain pending across operator processes. Application
/// storage and the password projection are created by the original installer
/// before that boundary, and are only observed by continuation.
pub(crate) fn require_acme_preparation(
    state: &crate::installer_state::LockedInspection,
    installation: &Path,
) -> Result<()> {
    crate::installer_acme_preparation::verify(state, installation)
}
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
    let foundation = state.with_inspection(crate::installer_foundation::load)?;
    let hosting = state.with_inspection(crate::installer_hosting::resolve)?;
    let binding = state
        .journal()
        .runtime()
        .ok_or("runtime binding absent")?
        .clone();
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
            "MARTY_SELFHOST_PROJECT",
            format!(
                "marty-selfhost-disposable-{}",
                state.journal().installation_id().simple()
            ),
        ),
        (
            "SELFHOST_SECRET_DIR",
            path(&installation.join("secrets"))?.into(),
        ),
        (
            "MARTY_INSTALLER_INGRESS_DNS_NAME",
            hosting.certificate_dns_name().unwrap_or_default().into(),
        ),
        (
            "MARTY_INSTALLER_INGRESS_IP_ADDRESS",
            hosting
                .certificate_ip_address()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
        ),
    ] {
        append(&mut env, name, &value)?;
    }
    if foundation.is_none() {
        for (name, value) in [
            (
                "MARTY_OPENBAO_DIDCOMM_IMAGE",
                images
                    .get("openbao_didcomm_image")
                    .ok_or("OpenBao image absent")?
                    .clone(),
            ),
            ("MARTY_KEYCLOAK_NONCE", nonce.into()),
            (
                "MARTY_OPENBAO_CONTROL_ATTEMPT_ID",
                uuid::Uuid::new_v4().to_string(),
            ),
            (
                "MARTY_OPENBAO_STATIC_INIT_ATTEMPT_ID",
                uuid::Uuid::new_v4().to_string(),
            ),
            (
                "SELFHOST_OPENBAO_STATE_DIR",
                path(&installation.join("openbao-state"))?.into(),
            ),
            (
                "SELFHOST_OPENBAO_HOST_PORT",
                binding.openbao_port.to_string(),
            ),
        ] {
            append(&mut env, name, &value)?;
        }
    }
    let port = binding.openbao_port;
    state.write_evidence("bootstrap.env", &env)?;
    let writable_bind_roots = [
        "secrets",
        "openbao-state",
        "openbao-control",
        "openbao-seal/initialization",
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
        "openbao-seal/key",
    ]
    .into_iter()
    .map(|n| installation.join(n))
    .collect();
    readonly_bind_roots.insert(bundle.into());
    let mut inputs = ComposeInputs {
        installation: installation.into(),
        project: state.journal().compose_project(),
        files: if foundation.is_some() {
            vec![
                bundle_bound(bundle, "docker-compose.yml")?,
                bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
                bundle_bound(bundle, crate::installer_foundation::LAYER)?,
            ]
        } else {
            vec![
                bundle_bound(bundle, "docker-compose.selfhost.openbao.yml")?,
                bundle_bound(bundle, &format!("{LAYERS}/compose.bootstrap.yml"))?,
            ]
        },
        bound_inputs: Vec::new(),
        environment: bound(installation.join("evidence/bootstrap.env"))?,
        profiles: vec!["setup".into()],
        services: vec![],
        approved_images: images.values().cloned().collect(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots,
        readonly_bind_roots,
        allowed_loopback_ports: if foundation.is_some() {
            BTreeSet::new()
        } else {
            BTreeSet::from([port])
        },
        ingress_listener: None,
        prior: None,
    };
    if let Some(foundation) = foundation {
        foundation.bind_inputs(&mut inputs);
        inputs.bound_inputs.push(bound(
            installation
                .join("evidence")
                .join(crate::installer_foundation::RECORD),
        )?);
    }
    hosting.bind_inputs(&mut inputs)?;
    Ok(inputs)
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

pub(crate) fn public_ingress_inputs(
    installation: &Path,
    state: &mut InstallerState,
    base: &ComposeInputs,
    plan: &crate::installer_public_ingress::PublicIngressPlan,
) -> Result<ComposeInputs> {
    state.require_live_phase(Phase::Provisioning)?;
    let plan_path = plan.record_for_install(installation, state)?;
    let mut environment =
        crate::installer_verify::read_private_bytes(&base.environment.path, 65536)?;
    append(
        &mut environment,
        crate::installer_public_ingress::PLAN_DIGEST_ENV,
        &plan.sha256()?,
    )?;
    let name = "acme-production-public-ingress.env";
    state.write_evidence(name, &environment)?;
    let mut inputs = base.clone();
    inputs.environment = bound(installation.join("evidence").join(name))?;
    inputs.bound_inputs.push(bound(plan_path)?);
    Ok(inputs)
}

pub(crate) fn public_renewal_inputs(
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    base: &ComposeInputs,
    plan: &crate::installer_public_ingress::PublicRenewalAuthorityPlan,
) -> Result<ComposeInputs> {
    state.require_live_phase(Phase::Provisioning)?;
    let hosting = state.with_inspection(crate::installer_hosting::resolve)?;
    let port = hosting
        .http01_host_port()
        .ok_or("ACME HTTP-01 port is absent")?;
    if base.allowed_loopback_ports.contains(&port)
        || port == hosting.listener().port
        || port
            == state
                .journal()
                .runtime()
                .ok_or("runtime binding absent")?
                .openbao_port
    {
        return Err("ACME HTTP-01 port conflicts with a selected service listener".into());
    }
    let plan_path = plan.record_for_install(installation, state)?;
    let mut environment =
        crate::installer_verify::read_private_bytes(&base.environment.path, 65536)?;
    if crate::installer_release::sha256(&environment) != base.environment.sha256 {
        return Err("bound bootstrap environment changed".into());
    }
    for (key, value) in [
        (
            crate::installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
            plan.sha256()?,
        ),
        (
            "MARTY_ACME_CANONICAL_ORIGIN",
            plan.canonical_origin().into(),
        ),
        (
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN",
            plan.public_entry_origin().unwrap_or_default().into(),
        ),
        ("MARTY_ACME_HTTP01_HOST_PORT", port.to_string()),
    ] {
        append(&mut environment, key, &value)?;
    }
    let name = "acme-public-renewal-authority.env";
    state.write_evidence(name, &environment)?;
    let mut inputs = base.clone();
    inputs.environment = bound(installation.join("evidence").join(name))?;
    inputs.bound_inputs.push(bound(plan_path)?);
    inputs
        .files
        .push(bundle_bound(bundle, crate::installer_acme_host::LAYER)?);
    inputs.allowed_loopback_ports.insert(port);
    Ok(inputs)
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
    start_inner(
        docker_path,
        installation,
        bundle,
        state,
        Some(bao),
        images,
        bootstrap,
        Some(prior),
    )
}

pub(crate) fn start_aws(
    docker_path: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    images: &BTreeMap<String, String>,
    bootstrap: &ComposeInputs,
) -> Result<()> {
    start_inner(
        docker_path,
        installation,
        bundle,
        state,
        None,
        images,
        bootstrap,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Selected infrastructure shares the existing application/generation/lifecycle owner."
)]
fn start_inner(
    docker_path: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: Option<&OpenBaoInventory>,
    images: &BTreeMap<String, String>,
    bootstrap: &ComposeInputs,
    prior: Option<ComposeReceipt>,
) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    let foundation = state.with_inspection(crate::installer_foundation::load)?;
    let hosting = state.with_inspection(crate::installer_hosting::resolve)?;
    let public_acme =
        hosting.certificate_source() == crate::installer_hosting::CertificateSource::Acme;
    match (bao, foundation.as_ref()) {
        (Some(bao), None) => crate::installer_openbao::require_binding(state, bao)?,
        (None, Some(_)) => {}
        _ => return Err("infrastructure selection differs from the fresh installation".into()),
    }
    let binding = state
        .journal()
        .runtime()
        .ok_or("runtime binding absent")?
        .clone();
    let mut reservations = Vec::new();
    let mut ports = Vec::new();
    for ordinal in 0..4 {
        let selected_listener = if ordinal == 0 {
            hosting.listener()
        } else {
            crate::installer_hosting::Listener {
                bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 0,
            }
        };
        let listener = TcpListener::bind(selected_listener.socket_address())
            .map_err(|_| "cannot reserve the selected hosting or private service port")?;
        let port = listener
            .local_addr()
            .map_err(|_| "listener reservation unavailable")?
            .port();
        if port < 1024 || port == binding.openbao_port || ports.contains(&port) {
            return Err("listener port conflicts with runtime".into());
        }
        ports.push(port);
        reservations.push(listener);
    }
    let public_origin = hosting.resolve_origin(ports[0])?;
    let origin = public_origin.to_string();
    let healthcheck_host = if matches!(public_origin.ip_address(), Some(std::net::IpAddr::V6(_))) {
        format!("[{}]", public_origin.host())
    } else {
        public_origin.host().to_owned()
    };
    let ingress_listener = crate::installer_hosting::Listener {
        bind_address: hosting.listener().bind_address,
        port: ports[0],
    };
    let group = crate::installer_state::applicant_container_group(&binding)?;
    let parameters = ApplicationParameters {
        installation: installation.into(),
        applicant_container_group: group,
        version: state.journal().identity().release_tag.clone(),
        origin: origin.clone(),
        https_listener_port: ports[0],
        gateway_port: ports[1],
        keycloak_port: ports[2],
        edge_port: ports[3],
        openbao_port: binding.openbao_port,
    };
    let tls = if foundation.is_some() {
        Vec::new()
    } else {
        crate::installer_verify::read_private_record(
            &installation.join("evidence/selfhost-tls-kms.env.fragment"),
        )?
    };
    let env = installer_application_env::render_selected(
        &bundle_text(bundle, ".env.selfhost.production.example", 16384)?,
        &bundle_text(bundle, "docker-compose.yml", 262144)?,
        std::str::from_utf8(&tls).map_err(|_| "invalid TLS environment fragment")?,
        &parameters,
        images,
        foundation.as_ref(),
        Some(&hosting),
    )?;
    if public_acme {
        state.with_inspection(|view| require_acme_preparation(view, installation))?;
    } else {
        state.prepare_application_storage()?;
        state.persist_application_storage_creation_receipt(installation)?;
        if foundation.is_none() {
            state.stage_operator_password()?;
        }
    }
    if state.validate_applicant_storage()? != group.host_gid() {
        return Err("applicant state group changed".into());
    }
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
            "MARTY_INSTALLER_UI_ENABLED_SECTIONS",
            hosting.enabled_web_sections().to_owned(),
        ),
        (
            "MARTY_INSTALLER_PUBLIC_ENTRY_ORIGIN",
            hosting
                .public_entry_origin()
                .map(PublicOrigin::as_str)
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "MARTY_INSTALLER_PUBLIC_ENTRY_ORIGINS",
            serde_json::to_string(
                &hosting
                    .public_entry_origin()
                    .into_iter()
                    .map(PublicOrigin::as_str)
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| "cannot encode public entry origin")?,
        ),
        (
            "MARTY_INSTALLER_HTTPS_BIND_ADDRESS",
            ingress_listener.bind_address.to_string(),
        ),
        (
            "MARTY_INSTALLER_INGRESS_CONNECT_TO",
            format!("{healthcheck_host}:{}:127.0.0.1:8443", public_origin.port()),
        ),
    ] {
        append(&mut source_env, key, &value)?;
    }
    if foundation.is_none() {
        append(
            &mut source_env,
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            &crate::installer_ingress_provision::resource_name(
                &state.journal().installation_id().to_string(),
            )?,
        )?;
    }
    for (key, value) in state.with_inspection(crate::installer_hosting_addon::environment)? {
        append(&mut source_env, &key, &value)?;
    }
    state.write_evidence("application-source.env", &source_env)?;
    let mut inputs = bootstrap.clone();
    inputs.prior = prior;
    inputs.services.clear();
    inputs.profiles = vec!["installer-init".into()];
    inputs
        .allowed_loopback_ports
        .extend(ports.iter().skip(1).copied());
    if ingress_listener.bind_address.is_loopback() {
        inputs.allowed_loopback_ports.insert(ingress_listener.port);
    }
    inputs.ingress_listener = hosting.is_recorded().then_some(ingress_listener);
    hosting.bind_connector(&mut inputs)?;
    inputs.files = vec![
        bundle_bound(bundle, "docker-compose.yml")?,
        bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
    ];
    if public_acme {
        inputs.files.push(bundle_bound(
            bundle,
            &format!("{LAYERS}/compose.acme-runtime.yml"),
        )?);
    }
    if foundation.is_some() {
        inputs
            .files
            .push(bundle_bound(bundle, crate::installer_foundation::LAYER)?);
    }
    crate::installer_hosting_addon::bind_inputs(&mut inputs)?;
    #[cfg(feature = "installer-development")]
    if let Some(image) = state.with_inspection(crate::installer_development_image::load)? {
        image.bind_inputs(&mut inputs)?;
    }
    inputs.environment = bound(installation.join("evidence/application-source.env"))?;
    let source = ComposeSession::new(docker_path, &binding, inputs.clone())?;
    let generation = crate::installer_generation_binding::stage(
        installation,
        state,
        source.model(),
        bao.map(|v| v.network_id.as_str()),
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
        bao.map(|v| v.network_id.as_str()),
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
    maintenance_inputs.files = if foundation.is_some() {
        vec![
            bundle_bound(bundle, "docker-compose.yml")?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.runtime.yml"))?,
            bundle_bound(bundle, crate::installer_foundation::LAYER)?,
        ]
    } else {
        vec![
            bundle_bound(bundle, "docker-compose.yml")?,
            bundle_bound(bundle, "docker-compose.selfhost.openbao.yml")?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.bootstrap.yml"))?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.installer.yml"))?,
            bundle_bound(bundle, &format!("{LAYERS}/compose.runtime.yml"))?,
        ]
    };
    if public_acme {
        for file in ["compose.acme.yml", "compose.acme-runtime.yml"] {
            maintenance_inputs
                .files
                .push(bundle_bound(bundle, &format!("{LAYERS}/{file}"))?);
        }
    }
    crate::installer_hosting_addon::bind_inputs(&mut maintenance_inputs)?;
    #[cfg(feature = "installer-development")]
    if let Some(image) = &maintenance_inputs.development_image {
        maintenance_inputs
            .files
            .push(image.layer_file(installation)?);
    }
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
    for file in &maintenance_inputs.files {
        if let Some(existing) = inputs
            .files
            .iter()
            .chain(&inputs.bound_inputs)
            .find(|bound| bound.path == file.path)
        {
            if existing.sha256 != file.sha256 {
                return Err("maintenance input changed".into());
            }
            continue;
        }
        inputs.bound_inputs.push(file.clone());
    }
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
