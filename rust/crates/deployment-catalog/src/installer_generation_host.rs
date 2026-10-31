//! Compose-managed first-install setup; completed jobs and uncertain outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_helper_output::{self, HelperOutputOwner},
    installer_jobs,
    installer_openbao::OpenBaoInventory,
    installer_renewal_bootstrap,
    installer_state::{InstallerState, Phase},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Generation provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct GenerationReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub root_retired: bool,
    pub ingress_renewal: bool,
    pub candidate_validated: bool,
    pub activated: bool,
    pub candidate_sha256: BTreeMap<String, String>,
    pub outputs: Vec<String>,
    pub compose_receipt_sha256: String,
    pub job_completed_successfully: bool,
    pub container_removed: bool,
    pub installation_ready: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalEvidence {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    container_name: String,
    network_id: String,
    image: String,
    root_retired: bool,
    ingress_renewal: bool,
    private_identity_validated: bool,
    outputs: Vec<String>,
    compose_receipt_sha256: String,
    job_completed_successfully: bool,
    container_removed: bool,
    installation_ready: bool,
}

const IDENTITY_FILES: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}

fn file_names(dir: &File) -> Result<BTreeSet<String>> {
    crate::installer_host_fs::file_names(dir, REFUSAL)
}

fn read_entry(dir: &File, name: &str, mode: u32, allow_root: bool) -> Result<Vec<u8>> {
    crate::installer_host_fs::read_entry(dir, name, mode, allow_root, REFUSAL)
}

fn read_inputs(secrets: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    let values = installer_renewal_bootstrap::current_inputs()
        .into_iter()
        .map(|name| {
            let value = read_entry(secrets, &name, 0o444, true)?;
            Ok((name, value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    installer_renewal_bootstrap::validate_current(&values).map_err(|_| REFUSAL)?;
    Ok(values)
}

fn stage_inputs(secrets: &File, output: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    crate::installer_host_fs::stage_inputs(secrets, output, read_inputs, REFUSAL)
}

fn read_identity(source: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(
        file_names(source)?
            == IDENTITY_FILES
                .into_iter()
                .chain(["pending.json", "completed.json"])
                .map(String::from)
                .collect(),
    )?;
    let mut values = BTreeMap::new();
    for name in IDENTITY_FILES {
        values.insert(name.into(), read_entry(source, name, 0o600, false)?);
    }
    let mut credentials = BTreeSet::new();
    for name in ["renewal-role-id", "renewal-secret-id"] {
        let value = std::str::from_utf8(&values[name])
            .map_err(|_| REFUSAL)?
            .trim();
        require(
            (20..=512).contains(&value.len())
                && value.bytes().all(|v| v.is_ascii_graphic())
                && credentials.insert(value.to_owned()),
        )?;
    }
    let policies: Vec<String> =
        serde_json::from_slice(&values["renewal-leaf-policies.json"]).map_err(|_| REFUSAL)?;
    require(
        policies.len() == 21
            && policies.iter().collect::<BTreeSet<_>>().len() == 21
            && policies.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 160
                    && !["root", "default", "selfhost-kms-renewal"].contains(&p.as_str())
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
    )?;
    Ok(values)
}

fn stage_identity(values: &BTreeMap<String, Vec<u8>>, output: &File) -> Result<()> {
    require(
        file_names(output)?.is_empty()
            && values.keys().map(String::as_str).collect::<BTreeSet<_>>() == IDENTITY_FILES.into(),
    )?;
    for (name, value) in values {
        let name = CString::new(name.as_str()).map_err(|_| REFUSAL)?;
        let fd = unsafe {
            libc::openat(
                output.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        output.sync_all().map_err(|_| REFUSAL)?;
        file.write_all(value)
            .and_then(|_| file.sync_all())
            .and_then(|_| output.sync_all())
            .map_err(|_| REFUSAL)?;
    }
    Ok(())
}

fn staged_identity(output: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(file_names(output)? == IDENTITY_FILES.map(String::from).into())?;
    IDENTITY_FILES
        .into_iter()
        .map(|n| Ok((n.into(), read_entry(output, n, 0o600, false)?)))
        .collect()
}

fn validate_delivered(
    delivered: &File,
    proof: &crate::installer_generation::GenerationProof<'_>,
) -> Result<BTreeMap<String, String>> {
    let mut expected = installer_renewal_bootstrap::current_inputs();
    expected.extend(["pending.json", "validated.json", "completed.json"].map(String::from));
    require(file_names(delivered)? == expected)?;
    let outputs = read_inputs(delivered)?;
    // Every transferred file is owned by this installer, not merely root-readable.
    for name in installer_renewal_bootstrap::current_inputs() {
        read_entry(delivered, &name, 0o444, false)?;
    }
    let mut records = BTreeMap::new();
    for name in ["pending.json", "validated.json", "completed.json"] {
        records.insert(name.into(), read_entry(delivered, name, 0o600, false)?);
    }
    crate::installer_generation::validate_records(&records, &outputs, proof)
}

fn require_directory_binding(path: &Path, held: &File) -> Result<()> {
    crate::installer_host_fs::require_directory_binding(path, held, REFUSAL)
}

fn open_child(parent: &File, name: &str, flags: i32) -> Result<File> {
    crate::installer_host_fs::open_child(parent, name, flags, REFUSAL)
}

fn validate_retained_entries(held: &File, expected_host_uid: HelperOutputOwner) -> Result<()> {
    for (name, is_dir, mode) in [
        ("output", true, 0o700),
        ("transfer-pending.json", false, 0o600),
    ] {
        let m = open_child(held, name, libc::O_PATH)?
            .metadata()
            .map_err(|_| REFUSAL)?;
        require(
            !m.file_type().is_symlink()
                && m.is_dir() == is_dir
                && (is_dir || (m.is_file() && m.nlink() == 1))
                && m.uid() == expected_host_uid.uid()
                && m.mode() & 0o7777 == mode,
        )?;
    }
    Ok(())
}

fn validate_delivery(
    parent: &Path,
    held: &File,
    proof: &crate::installer_generation::GenerationProof<'_>,
    expected_host_uid: HelperOutputOwner,
) -> Result<BTreeMap<String, String>> {
    require_directory_binding(parent, held)?;
    require(
        file_names(held)?
            == BTreeSet::from([
                "transfer-pending.json".into(),
                "output".into(),
                "delivered".into(),
            ]),
    )?;
    validate_retained_entries(held, expected_host_uid)?;
    let delivered = open_child(held, "delivered", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let m = delivered.metadata().map_err(|_| REFUSAL)?;
    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)?;
    let result = validate_delivered(&delivered, proof)?;
    require_directory_binding(parent, held)?;
    Ok(result)
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
) -> Result<(ComposeReceipt, GenerationReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    crate::installer_ingress_provision::resource_name(&owner)?;
    let secrets = directory(&installation.join("secrets"))?;
    let evidence = directory(&installation.join("evidence"))?;
    let keycloak_receipt = read_entry(&evidence, "keycloak-observation.json", 0o600, false)?;
    crate::installer_generation::original_nonce(&keycloak_receipt, &owner)?;
    let kc: Value = serde_json::from_slice(&keycloak_receipt).map_err(|_| REFUSAL)?;
    require(
        kc["engine_id"] == binding.engine_id
            && kc["network_id"] == bao.network_id
            && kc["image"] == bao.image,
    )?;
    installer_jobs::previous_job(
        &inputs,
        &evidence,
        "installer-keycloak",
        kc["container_id"].as_str().ok_or(REFUSAL)?,
        &bao.image,
        kc["compose_receipt_sha256"].as_str().ok_or(REFUSAL)?,
    )?;
    let renewal_receipt = read_entry(&evidence, "renewal-result.json", 0o600, false)?;
    let renewal: RenewalEvidence = serde_json::from_slice(&renewal_receipt).map_err(|_| REFUSAL)?;
    require(
        renewal.schema == "elevenid.installer-renewal-host/v2"
            && renewal.installation_id == owner
            && renewal.engine_id == binding.engine_id
            && renewal.network_id == bao.network_id
            && renewal.image == services_image
            && renewal.container_name
                == format!("{}-installer-renewal-1", state.journal().compose_project())
            && id(&renewal.container_id)
            && !renewal.container_removed
            && renewal.job_completed_successfully
            && renewal.private_identity_validated
            && !renewal.root_retired
            && !renewal.ingress_renewal
            && !renewal.installation_ready
            && renewal.outputs == IDENTITY_FILES,
    )?;
    installer_jobs::previous_job(
        &inputs,
        &evidence,
        "installer-renewal",
        &renewal.container_id,
        services_image,
        &renewal.compose_receipt_sha256,
    )?;
    let identity_source_path = installation.join("renewal-transfer/delivered");
    let identity_source = directory(&identity_source_path)?;
    let identity_snapshot = read_identity(&identity_source)?;
    state.create_private_directory("generation-transfer")?;
    state.create_private_directory("generation-inputs")?;
    state.create_private_directory("generation-identity")?;
    let identity_staged = directory(&installation.join("generation-identity"))?;
    stage_identity(&identity_snapshot, &identity_staged)?;
    let staged = directory(&installation.join("generation-inputs"))?;
    let source_snapshot = stage_inputs(&secrets, &staged)?;
    let output_path = installation.join("generation-transfer");
    let output = directory(&output_path)?;
    state.write_evidence(
        "generation-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-generation-host-intent/v2", "installation_id":owner,
            "engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,
            "keycloak_receipt_sha256":format!("{:x}",Sha256::digest(&keycloak_receipt)),
            "renewal_receipt_sha256":format!("{:x}",Sha256::digest(&renewal_receipt)),
            "input_sha256":crate::installer_generation::hashes(&source_snapshot),
            "identity_sha256":crate::installer_generation::hashes(&identity_snapshot)
        }))
        .map_err(|_| REFUSAL)?,
    )?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&identity_source_path, &identity_source)?;
    require_directory_binding(&installation.join("evidence"), &evidence)?;
    require_directory_binding(&installation.join("generation-identity"), &identity_staged)?;
    require_directory_binding(&output_path, &output)?;
    require(
        file_names(&staged)? == installer_renewal_bootstrap::current_inputs()
            && read_inputs(&staged)? == source_snapshot
            && read_inputs(&secrets)? == source_snapshot
            && read_identity(&identity_source)? == identity_snapshot
            && staged_identity(&identity_staged)? == identity_snapshot
            && read_entry(&evidence, "keycloak-observation.json", 0o600, false)?
                == keycloak_receipt
            && read_entry(&evidence, "renewal-result.json", 0o600, false)? == renewal_receipt,
    )?;
    let job = installer_jobs::run(
        dockerpath,
        installation,
        bundle,
        state,
        Some(bao),
        inputs,
        "installer-generation",
        services_image,
        expected_operator_sha,
    )?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&installation.join("generation-inputs"), &staged)?;
    require_directory_binding(&identity_source_path, &identity_source)?;
    require_directory_binding(&installation.join("evidence"), &evidence)?;
    require_directory_binding(&installation.join("generation-identity"), &identity_staged)?;
    require(
        read_inputs(&secrets)? == source_snapshot
            && read_inputs(&staged)? == source_snapshot
            && read_identity(&identity_source)? == identity_snapshot
            && staged_identity(&identity_staged)? == identity_snapshot
            && read_entry(&evidence, "keycloak-observation.json", 0o600, false)?
                == keycloak_receipt
            && read_entry(&evidence, "renewal-result.json", 0o600, false)? == renewal_receipt,
    )?;
    let proof = crate::installer_generation::GenerationProof {
        owner: &owner,
        current: &source_snapshot,
        identity: &identity_snapshot,
        keycloak_receipt: &keycloak_receipt,
    };
    let delivered = validate_delivery(
        &output_path,
        &output,
        &proof,
        installer_helper_output::expected_host_uid(&binding)?,
    )?;
    let receipt = GenerationReceipt {
        schema: "elevenid.installer-generation-host/v2",
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        root_retired: false,
        ingress_renewal: false,
        candidate_validated: true,
        activated: false,
        candidate_sha256: delivered.clone(),
        outputs: delivered.keys().cloned().collect(),
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "generation-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn host_output_owner_for_test() -> installer_helper_output::HelperOutputOwner {
        let uid = unsafe { libc::geteuid() };
        let profile = if uid == 0 {
            crate::installer_state::RuntimeProfile::Rootful
        } else {
            crate::installer_state::RuntimeProfile::Rootless
        };
        installer_helper_output::expected_host_uid(&crate::installer_state::RuntimeBinding {
            docker_host: if uid == 0 {
                "unix:///var/run/docker.sock".into()
            } else {
                format!("unix:///run/user/{uid}/docker.sock")
            },
            engine_id: "engine-identity-123".into(),
            openbao_port: 18200,
            profile,
        })
        .unwrap()
    }

    #[test]
    fn retained_container_outputs_bind_host_owner_and_remain_private() {
        let owner = host_output_owner_for_test();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(owner.uid(), uid);
        let rootful =
            installer_helper_output::expected_host_uid(&crate::installer_state::RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "engine-identity-123".into(),
                openbao_port: 18200,
                profile: crate::installer_state::RuntimeProfile::Rootful,
            })
            .unwrap();
        assert_eq!(rootful.uid(), 0);
        for mutation in [
            "none",
            "pending-mode",
            "output-mode",
            "pending-link",
            "output-link",
            "hardlink",
            "pending-directory",
            "output-file",
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = temp.path().join("output");
            let pending = temp.path().join("transfer-pending.json");
            std::fs::create_dir(&output).unwrap();
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(&pending, b"synthetic retained transfer intent").unwrap();
            std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600)).unwrap();
            let held = directory(temp.path()).unwrap();
            let snapshot = |path: &Path| {
                let m = std::fs::symlink_metadata(path).unwrap();
                (
                    m.dev(),
                    m.ino(),
                    m.uid(),
                    m.gid(),
                    m.mode(),
                    m.nlink(),
                    m.len(),
                )
            };
            let before = (snapshot(&output), snapshot(&pending));
            validate_retained_entries(&held, owner).unwrap();
            if uid != 0 {
                // Rootful UID 0 is not an alternate accepted owner on rootless hosts.
                assert!(validate_retained_entries(&held, rootful).is_err());
            }
            assert_eq!((snapshot(&output), snapshot(&pending)), before);
            assert_eq!(
                std::fs::read(&pending).unwrap(),
                b"synthetic retained transfer intent"
            );
            match mutation {
                "none" => continue,
                "pending-mode" => {
                    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                "output-mode" => {
                    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o750))
                        .unwrap()
                }
                "pending-link" => {
                    let original = temp.path().join("original-pending");
                    std::fs::rename(&pending, &original).unwrap();
                    symlink(original, &pending).unwrap();
                }
                "output-link" => {
                    let original = temp.path().join("original-output");
                    std::fs::rename(&output, &original).unwrap();
                    symlink(original, &output).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&pending, temp.path().join("linked-pending")).unwrap()
                }
                "pending-directory" => {
                    std::fs::remove_file(&pending).unwrap();
                    std::fs::create_dir(&pending).unwrap();
                    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                "output-file" => {
                    std::fs::remove_dir(&output).unwrap();
                    std::fs::write(&output, b"not a directory").unwrap();
                    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                validate_retained_entries(&held, owner).is_err(),
                "accepted {mutation}"
            );
        }
    }
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

    #[test]
    fn held_transfer_binding_refuses_same_mode_replacement() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("transfer");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&path).unwrap();
        require_directory_binding(&path, &held).unwrap();
        std::fs::rename(&path, temp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_directory_binding(&path, &held).is_err());
    }

    #[test]
    fn identity_staging_is_private_exclusive_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory(temp.path()).unwrap();
        let values = IDENTITY_FILES
            .into_iter()
            .map(|name| (name.to_owned(), format!("synthetic-{name}").into_bytes()))
            .collect();
        stage_identity(&values, &dir).unwrap();
        assert_eq!(staged_identity(&dir).unwrap(), values);
        assert!(stage_identity(&values, &dir).is_err());
        for name in IDENTITY_FILES {
            assert_eq!(
                std::fs::metadata(temp.path().join(name)).unwrap().mode() & 0o7777,
                0o600
            );
        }
        std::fs::write(temp.path().join("extra"), b"extra").unwrap();
        assert!(staged_identity(&dir).is_err());
    }
}
