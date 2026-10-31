//! Product-specific setup outputs stay with their provisioning modules; Compose
//! owns pulling, creating, starting and retaining each explicitly selected job.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt, ComposeSession},
    installer_openbao::OpenBaoInventory,
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_verify,
};
use serde_json::Value;
use std::{fs::File, path::Path};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Installer setup job refused; preserve its Compose evidence and outputs";

pub(crate) struct CompletedJob {
    pub compose: ComposeReceipt,
    pub container_id: String,
    pub container_name: String,
    pub image: String,
}

/// Matches the exact Value representation written by ComposeSession::receipt.
pub(crate) fn receipt_digest(receipt: &ComposeReceipt) -> Result<String> {
    let value = serde_json::to_value(receipt).map_err(|_| REFUSED)?;
    Ok(crate::installer_release::sha256(
        &serde_json::to_vec(&value).map_err(|_| REFUSED)?,
    ))
}

/// Bind a retained product-specific receipt to the successful native operation
/// and to the cumulative identity receipt supplied for the next phase.
pub(crate) fn previous_job(
    inputs: &ComposeInputs,
    evidence: &File,
    service: &str,
    container_id: &str,
    image: &str,
    expected_receipt_sha256: &str,
) -> Result<()> {
    let bytes = crate::installer_host_fs::read_entry(
        evidence,
        &format!("compose-setup-{service}-result.json"),
        0o600,
        false,
        REFUSED,
    )?;
    require(crate::installer_release::sha256(&bytes) == expected_receipt_sha256)?;
    let result: ComposeReceipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    let prior = inputs.prior.as_ref().ok_or(REFUSED)?;
    let identity = result
        .resources
        .as_ref()
        .ok_or(REFUSED)?
        .containers
        .get(service)
        .ok_or(REFUSED)?;
    require(
        result.schema == "elevenid.installer-compose-operation/v1"
            && result.operation == format!("setup-{service}")
            && result.project == inputs.project
            && result.engine_id == prior.engine_id
            && result.command_succeeded
            && result.observation_validated
            && result.client_exit_code == Some(0)
            && result.failure_class.is_none()
            && !result.installation_ready
            && identity.setup
            && identity.id == container_id
            && identity.image == image
            && prior
                .resources
                .as_ref()
                .ok_or(REFUSED)?
                .containers
                .get(service)
                == Some(identity),
    )
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

// This checks inherited image policy, not a second service/mount definition.
// Every declared image volume must already be covered by the admitted Compose
// service so pulling a helper cannot silently allocate anonymous storage.
fn image_policy(image: &Value, service: &Value, keycloak: bool, tls: bool) -> Result<()> {
    if let Some(volumes) = image["Config"]["Volumes"].as_object() {
        for target in volumes.keys() {
            let covered = service["volumes"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|v| v["target"] == target.as_str())
                || service["tmpfs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|v| v.split(':').next() == Some(target.as_str()));
            require(covered)?;
        }
    } else {
        require(image["Config"]["Volumes"].is_null())?;
    }
    if !keycloak {
        if tls {
            let inherited =
                crate::installer_container::environment_map(&image["Config"]["Env"], REFUSED)?;
            require(!inherited.keys().any(|key| {
                ["BAO_", "MARTY_TLS_", "MARTY_SELFHOST_", "SELFHOST_TLS_"]
                    .iter()
                    .any(|prefix| key.starts_with(prefix))
            }))?;
        } else {
            crate::installer_container::bootstrap_environment(&image["Config"]["Env"], REFUSED)?;
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound provisioning inputs explicit at this boundary."
)]
pub(crate) fn run(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    inputs: ComposeInputs,
    service: &str,
    expected_image: &str,
    expected_operator_sha: &str,
) -> Result<CompletedJob> {
    state.require_live_phase(Phase::Provisioning)?;
    require(
        InstallerState::inspect(installation)? == *state.journal()
            && inputs.installation == installation
            && inputs.project == state.journal().compose_project()
            && inputs.services == [service]
            && inputs.profiles == ["setup"]
            && inputs.prior.is_some(),
    )?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let prior = inputs
        .prior
        .as_ref()
        .ok_or(REFUSED)?
        .resources
        .as_ref()
        .ok_or(REFUSED)?;
    require(
        bao.installation_id == state.journal().installation_id().to_string()
            && bao.engine_id == binding.engine_id
            && bao.project == inputs.project
            && prior.networks.get(&bao.network_name) == Some(&bao.network_id)
            && bao
                .container_ids
                .iter()
                .all(|(role, id)| prior.containers.get(role).is_some_and(|c| &c.id == id)),
    )?;
    let docker = DockerRunner::from_binding(dockerpath, &binding, installation)?;
    require(bundle.starts_with(installation))?;
    let operator = installation.join("marty-deploy");
    require(installer_verify::operator_digest(&operator)? == expected_operator_sha)?;
    let session = ComposeSession::new(dockerpath, &binding, inputs)?;
    let model = &session.model()["services"][service];
    require(model["image"] == expected_image)?;
    session.pull()?;
    let images: Vec<Value> =
        serde_json::from_str(&docker.run_checked(&["image", "inspect", expected_image])?)
            .map_err(|_| REFUSED)?;
    require(
        images.len() == 1
            && images[0]["RepoDigests"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v == expected_image)),
    )?;
    image_policy(
        &images[0],
        model,
        service == "installer-keycloak",
        service == "installer-tls",
    )?;
    require(installer_verify::operator_digest(&operator)? == expected_operator_sha)?;
    let receipt = session.run_setup_job(state, service)?;
    state.require_live_phase(Phase::Provisioning)?;
    let identity = receipt
        .resources
        .as_ref()
        .ok_or(REFUSED)?
        .containers
        .get(service)
        .ok_or(REFUSED)?;
    require(identity.setup && identity.image == expected_image)?;
    let statuses: Vec<_> = receipt
        .status
        .iter()
        .filter(|row| row["Service"] == service)
        .collect();
    require(
        statuses.len() == 1
            && statuses[0]["ID"] == identity.id
            && statuses[0]["State"] == "exited"
            && statuses[0]["ExitCode"] == 0,
    )?;
    let container_id = identity.id.clone();
    let container_name = statuses[0]["Name"].as_str().ok_or(REFUSED)?.to_owned();
    require(container_name == format!("{}-{service}-1", receipt.project))?;
    Ok(CompletedJob {
        compose: receipt,
        container_id,
        container_name,
        image: expected_image.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn image_volumes_require_explicit_native_compose_coverage() {
        let image = json!({"Config":{"Volumes":{"/openbao/file":{},"/openbao/logs":{}}}});
        let model = json!({"tmpfs":["/openbao/file:rw,noexec","/openbao/logs:rw,noexec"]});
        image_policy(&image, &model, true, false).unwrap();
        assert!(image_policy(&image, &json!({"tmpfs":["/openbao/file:rw"]}), true, false).is_err());
        assert!(image_policy(
            &json!({"Config":{"Volumes":["/foreign"]}}),
            &model,
            true,
            false
        )
        .is_err());
    }

    #[test]
    fn setup_image_authority_and_proxy_overrides_remain_rejected() {
        for env in [
            "BAO_TOKEN=secret",
            "HTTPS_PROXY=https://proxy.invalid",
            "LD_PRELOAD=/foreign",
            "SELFHOST_PROFILE=other",
        ] {
            assert!(
                image_policy(&json!({"Config":{"Env":[env]}}), &json!({}), false, false).is_err()
            );
        }
        for env in [
            "BAO_ADDR=foreign",
            "MARTY_TLS_PROFILE=other",
            "MARTY_SELFHOST_PROJECT=other",
            "SELFHOST_TLS_OUTPUT_DIR=/foreign",
        ] {
            assert!(
                image_policy(&json!({"Config":{"Env":[env]}}), &json!({}), false, true).is_err()
            );
        }
        image_policy(
            &json!({"Config":{"Env":["PATH=/usr/bin:/bin"]}}),
            &json!({}),
            false,
            false,
        )
        .unwrap();
    }
}
