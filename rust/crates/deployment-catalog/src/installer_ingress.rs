//! Compose-managed first-install setup; completed jobs and uncertain outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_helper_output, installer_ingress_outputs, installer_jobs,
    installer_openbao::OpenBaoInventory,
    installer_state::{InstallerState, Phase},
};
use serde::Serialize;
use serde_json::json;
use std::{fs::File, path::Path};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Ingress provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct IngressReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub authority_name: String,
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
) -> Result<(ComposeReceipt, IngressReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    let authority_name = crate::installer_ingress_provision::resource_name(&owner)?;
    let secrets = directory(&installation.join("secrets"))?;
    installer_ingress_outputs::preflight(&secrets)?;
    state.create_private_directory("ingress-output")?;
    let output = directory(&installation.join("ingress-output"))?;
    state.write_evidence(
        "ingress-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-ingress-intent/v2", "installation_id":owner,
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
        "installer-ingress-provision",
        services_image,
        expected_operator_sha,
    )?;
    let validated = installer_ingress_outputs::validate_and_transfer(
        &output,
        &secrets,
        &owner,
        installer_helper_output::expected_host_uid(&binding)?,
    )?;
    state.write_evidence("installer-ingress.json", &validated.metadata_bytes)?;
    let receipt = IngressReceipt {
        schema: "elevenid.installer-ingress-host/v2",
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        authority_name,
        outputs: validated.outputnames,
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "ingress-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn held_output_directory_refuses_aliases_and_nonprivate_mode() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("output");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(directory(&path).is_ok());
        let alias = temp.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(directory(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(directory(&path).is_err());
    }
}
