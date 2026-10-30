//! Explicit credential barriers around native Compose-managed OpenBao phases.
//! Existing authenticated OpenBao initialization remains unchanged. There is no
//! per-service scheduler or host health-polling loop here.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt, ComposeSession},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase, SCALAR_SECRETS},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenBaoInventory {
    pub installation_id: String,
    pub engine_id: String,
    pub project: String,
    pub image: String,
    pub host_port: u16,
    pub network_name: String,
    pub network_id: String,
    pub container_ids: BTreeMap<String, String>,
    pub pending_receipt: PathBuf,
}
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "OpenBao intent exists or cannot be saved")?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "OpenBao evidence write failed")?;
    File::open(path.parent().ok_or("OpenBao evidence parent absent")?)
        .and_then(|p| p.sync_all())
        .map_err(|_| "OpenBao evidence directory sync failed".into())
}
/// Identity only; the shared Compose driver re-observes cumulative exact runtime
/// resources. This function must not create or adopt any Docker resource.
pub(crate) fn require_binding(state: &InstallerState, bao: &OpenBaoInventory) -> Result<()> {
    let journal = state.journal();
    let binding = journal.runtime().ok_or("OpenBao runtime absent")?;
    require(
        bao.installation_id == journal.installation_id().to_string()
            && bao.engine_id == binding.engine_id
            && bao.project == journal.compose_project()
            && bao.host_port == binding.openbao_port
            && bao.network_name == format!("{}_default", journal.compose_project()),
        "OpenBao observation differs from installation binding",
    )
}
pub fn start_openbao(
    docker_path: &Path,
    installation: &Path,
    state: &mut InstallerState,
    plugin_image: &str,
    mut inputs: ComposeInputs,
) -> Result<(OpenBaoInventory, ComposeReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    let journal = state.journal().clone();
    require(
        InstallerState::inspect(installation)? == journal,
        "OpenBao journal changed",
    )?;
    let binding = journal.runtime().ok_or("OpenBao runtime absent")?;
    require(
        inputs.prior.is_none()
            && inputs.project == journal.compose_project()
            && inputs.approved_images.contains(plugin_image),
        "OpenBao requires fresh admitted project",
    )?;
    let secrets = installation.join("secrets");
    let names = fs::read_dir(&secrets)
        .map_err(|_| "scalar secrets unavailable")?
        .map(|e| {
            e.map(|v| v.file_name().to_string_lossy().into_owned())
                .map_err(|_| "secret inventory unavailable")
        })
        .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
    require(
        names == SCALAR_SECRETS.iter().map(|v| v.to_string()).collect(),
        "fresh scalar secret set differs",
    )?;
    for name in SCALAR_SECRETS {
        let m = fs::symlink_metadata(secrets.join(name)).map_err(|_| "scalar credential absent")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o7777 == 0o444
                && m.len() == 64,
            "scalar credential custody differs",
        )?;
    }
    state.create_private_directory("openbao-state")?;
    state.persist_openbao_state_creation_receipt(installation)?;
    let state_before = fs::symlink_metadata(installation.join("openbao-state"))
        .map_err(|_| "OpenBao initial directory identity unavailable")?;
    let pending = installation.join("openbao-pending.json");
    exclusive(&pending, &serde_json::to_vec(&json!({"schema":"elevenid.installer-openbao-intent/v2",
        "installation_id":journal.installation_id(),"engine_id":binding.engine_id,"project":inputs.project,
        "image":plugin_image,"automatic_retry":false})).map_err(|_| "OpenBao intent encode failed")?)?;
    inputs.services = vec!["openbao-tls-init".into()];
    let tls = ComposeSession::new(docker_path, binding, inputs.clone())?;
    tls.pull()?;
    let mut receipt = tls.run_setup_job(state, "openbao-tls-init")?;
    let resources = receipt
        .resources
        .as_ref()
        .ok_or("OpenBao TLS resources absent")?;
    let initialized = resources
        .containers
        .get("openbao-tls-init")
        .ok_or("TLS initializer absent")?;
    let completed = serde_json::to_vec(
        &json!({"role":"openbao-tls-init","container_id":initialized.id,"exit_code":0}),
    )
    .map_err(|_| "TLS completion encode failed")?;
    exclusive(
        &installation.join("openbao-completed-openbao-tls-init.json"),
        &completed,
    )?;
    let docker = DockerRunner::from_binding(docker_path, binding, installation)?;
    let local: Vec<serde_json::Value> =
        serde_json::from_str(&docker.run_checked(&["image", "inspect", plugin_image])?)
            .map_err(|_| "OpenBao image metadata invalid")?;
    require(local.len() == 1, "OpenBao image identity ambiguous")?;
    state.persist_openbao_owner_transition_receipt(
        installation,
        &binding.engine_id,
        plugin_image,
        local[0]["Id"].as_str().ok_or("OpenBao image ID absent")?,
        &initialized.id,
        &completed,
    )?;
    inputs
        .bound_inputs
        .push(crate::installer_compose::record_openbao_custody(
            installation,
            state,
            &receipt,
            &state_before,
        )?);
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao".into()];
    let api = ComposeSession::new(docker_path, binding, inputs.clone())?;
    receipt = api.up_wait(state, "openbao-api", Duration::from_secs(180))?;
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao-bootstrap".into()];
    let bootstrap = ComposeSession::new(docker_path, binding, inputs.clone())?;
    receipt = bootstrap.run_setup_job(state, "openbao-bootstrap")?;
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao-unseal".into()];
    let ready = ComposeSession::new(docker_path, binding, inputs)?;
    receipt = ready.up_wait(state, "openbao-ready", Duration::from_secs(180))?;
    for name in [
        "openbao_service_token",
        "openbao_bootstrap_token",
        "signing_keys_openbao_token",
        "didcomm_issuance_openbao_token",
        "notification_openbao_token",
        "haip_kms_token",
        "openbao_tls_ca_cert",
    ] {
        let m = fs::symlink_metadata(secrets.join(name)).map_err(|_| "OpenBao output absent")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.len() > 0
                && m.len() <= 65536
                && m.mode() & 0o022 == 0,
            "OpenBao output custody differs",
        )?;
    }
    let observed = receipt
        .resources
        .as_ref()
        .ok_or("OpenBao resources absent")?;
    let network_name = format!("{}_default", journal.compose_project());
    let result = OpenBaoInventory {
        installation_id: journal.installation_id().to_string(),
        engine_id: binding.engine_id.clone(),
        project: journal.compose_project(),
        image: plugin_image.into(),
        host_port: binding.openbao_port,
        network_id: observed
            .networks
            .get(&network_name)
            .ok_or("OpenBao default network absent")?
            .clone(),
        network_name,
        container_ids: observed
            .containers
            .iter()
            .map(|(r, c)| (r.clone(), c.id.clone()))
            .collect(),
        pending_receipt: pending,
    };
    Ok((result, receipt))
}
