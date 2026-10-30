//! Compose-managed first-install setup; completed jobs and uncertain outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_helper_output, installer_jobs,
    installer_openbao::OpenBaoInventory,
    installer_state::{InstallerState, Phase},
    installer_tls_outputs,
};
use serde::Serialize;
use serde_json::json;
use std::{fs::File, path::Path};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Tls provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct TlsReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub bootstrap_project: String,
    pub outputs: Vec<String>,
    pub compose_receipt_sha256: String,
    pub job_completed_successfully: bool,
    pub container_removed: bool,
    pub installation_ready: bool,
}

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound provisioning inputs explicit at this boundary."
)]
pub fn provision(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    inputs: ComposeInputs,
    expected_operator_sha: &str,
) -> Result<(ComposeReceipt, TlsReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    let project = format!(
        "marty-selfhost-disposable-{}",
        state.journal().installation_id().simple()
    );
    let secrets = directory(&installation.join("secrets"))?;
    installer_tls_outputs::preflight(&secrets, bundle)?;
    state.create_private_directory("tls-output")?;
    let output = directory(&installation.join("tls-output"))?;
    state.write_evidence(
        "tls-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-tls-intent/v2", "installation_id":owner,
            "engine_id":binding.engine_id,"operator_sha256":expected_operator_sha
        }))
        .map_err(|_| REFUSAL)?,
    )?;
    let job = installer_jobs::run(
        dockerpath,
        installation,
        bundle,
        state,
        bao,
        inputs,
        "installer-tls",
        services_image,
        expected_operator_sha,
    )?;
    let validated = installer_tls_outputs::validate_and_transfer(
        &output,
        &secrets,
        bundle,
        installer_helper_output::expected_host_uid(&binding)?,
    )?;
    state.write_evidence("selfhost-tls-kms-roles.json", &validated.metadata_bytes)?;
    state.write_evidence(
        "selfhost-tls-kms.env.fragment",
        validated.env_fragment.as_bytes(),
    )?;
    let receipt = TlsReceipt {
        schema: "elevenid.installer-tls/v2",
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        bootstrap_project: project,
        outputs: validated.outputnames,
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "tls-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}
