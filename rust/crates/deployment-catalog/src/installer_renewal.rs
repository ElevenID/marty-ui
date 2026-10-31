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
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Renewal provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct RenewalReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub root_retired: bool,
    pub ingress_renewal: bool,
    pub private_identity_validated: bool,
    pub outputs: Vec<String>,
    pub compose_receipt_sha256: String,
    pub job_completed_successfully: bool,
    pub container_removed: bool,
    pub installation_ready: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema: String,
    installation_id: String,
    root_retired: bool,
    ingress_renewal: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    schema: String,
    installation_id: String,
    identity_files: Vec<String>,
    policy_count: u64,
    scoped_login_verified: bool,
    verification_token_revoked: bool,
    root_retired: bool,
    ingress_renewal: bool,
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
    owner: &str,
    expected_host_uid: HelperOutputOwner,
) -> Result<Vec<String>> {
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
    let result = validate_delivered(&delivered, owner)?;
    require_directory_binding(parent, held)?;
    Ok(result)
}

fn validate_delivered(delivered: &File, owner: &str) -> Result<Vec<String>> {
    let expected: BTreeSet<String> = IDENTITY_FILES
        .into_iter()
        .chain(["pending.json", "completed.json"])
        .map(String::from)
        .collect();
    require(file_names(delivered)? == expected)?;
    let pending: Pending =
        serde_json::from_slice(&read_entry(delivered, "pending.json", 0o600, false)?)
            .map_err(|_| REFUSAL)?;
    require(
        pending.schema == "elevenid.installer-renewal-bootstrap-intent/v1"
            && pending.installation_id == owner
            && !pending.root_retired
            && !pending.ingress_renewal,
    )?;
    let completed: Completed =
        serde_json::from_slice(&read_entry(delivered, "completed.json", 0o600, false)?)
            .map_err(|_| REFUSAL)?;
    require(
        completed.schema == "elevenid.installer-renewal-bootstrap-result/v1"
            && completed.installation_id == owner
            && completed.identity_files == IDENTITY_FILES
            && completed.policy_count == 21
            && completed.scoped_login_verified
            && completed.verification_token_revoked
            && !completed.root_retired
            && !completed.ingress_renewal,
    )?;
    let mut credentials = BTreeSet::new();
    for name in ["renewal-role-id", "renewal-secret-id"] {
        let raw = read_entry(delivered, name, 0o600, false)?;
        let value = std::str::from_utf8(&raw).map_err(|_| REFUSAL)?.trim();
        require(
            (20..=512).contains(&value.len())
                && value.bytes().all(|v| v.is_ascii_graphic())
                && credentials.insert(value.to_owned()),
        )?;
    }
    let policies: Vec<String> = serde_json::from_slice(&read_entry(
        delivered,
        "renewal-leaf-policies.json",
        0o600,
        false,
    )?)
    .map_err(|_| REFUSAL)?;
    require(
        policies.len() == 21
            && policies.iter().collect::<BTreeSet<_>>().len() == 21
            && policies.iter().all(|v| {
                !v.is_empty()
                    && v.len() <= 160
                    && !["root", "default", "selfhost-kms-renewal"].contains(&v.as_str())
                    && v.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
    )?;
    Ok(IDENTITY_FILES.map(String::from).to_vec())
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
) -> Result<(ComposeReceipt, RenewalReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    crate::installer_ingress_provision::resource_name(&owner)?;
    let secrets = directory(&installation.join("secrets"))?;
    state.create_private_directory("renewal-transfer")?;
    state.create_private_directory("renewal-inputs")?;
    let staged = directory(&installation.join("renewal-inputs"))?;
    let source_snapshot = stage_inputs(&secrets, &staged)?;
    let output_path = installation.join("renewal-transfer");
    let output = directory(&output_path)?;
    state.write_evidence(
        "renewal-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-renewal-intent/v2", "installation_id":owner,
            "engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,
            "input_sha256":crate::installer_generation::hashes(&source_snapshot)
        }))
        .map_err(|_| REFUSAL)?,
    )?;
    require_directory_binding(&output_path, &output)?;
    require(
        file_names(&staged)? == installer_renewal_bootstrap::current_inputs()
            && read_inputs(&staged)? == source_snapshot
            && read_inputs(&secrets)? == source_snapshot,
    )?;
    let job = installer_jobs::run(
        dockerpath,
        installation,
        bundle,
        state,
        bao,
        inputs,
        "installer-renewal",
        services_image,
        expected_operator_sha,
    )?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&installation.join("renewal-inputs"), &staged)?;
    require(read_inputs(&secrets)? == source_snapshot && read_inputs(&staged)? == source_snapshot)?;
    let delivered = validate_delivery(
        &output_path,
        &output,
        &owner,
        installer_helper_output::expected_host_uid(&binding)?,
    )?;
    let receipt = RenewalReceipt {
        schema: "elevenid.installer-renewal-host/v2",
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        root_retired: false,
        ingress_renewal: false,
        private_identity_validated: true,
        outputs: delivered,
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "renewal-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const OWNER: &str = "12345678-1234-4234-8234-123456789abc";
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
    fn private() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    fn held_transfer_directory_rejects_replacement_and_linked_delivery() {
        let temp = private();
        let transfer = temp.path().join("transfer");
        std::fs::create_dir(&transfer).unwrap();
        std::fs::set_permissions(&transfer, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&transfer).unwrap();
        require_directory_binding(&transfer, &held).unwrap();
        std::fs::rename(&transfer, temp.path().join("original")).unwrap();
        std::fs::create_dir(&transfer).unwrap();
        std::fs::set_permissions(&transfer, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_directory_binding(&transfer, &held).is_err());
        assert!(validate_delivery(&transfer, &held, OWNER, host_output_owner_for_test()).is_err());
        symlink(&transfer, temp.path().join("original/delivered")).unwrap();
        assert!(open_child(&held, "delivered", libc::O_RDONLY | libc::O_DIRECTORY).is_err());
    }

    fn put(root: &Path, name: &str, value: &[u8], mode: u32) {
        std::fs::write(root.join(name), value).unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn exact_snapshot_is_exclusive_and_preserves_only_reviewed_inputs() {
        let source = private();
        let target = private();
        for (i, name) in installer_renewal_bootstrap::current_inputs()
            .iter()
            .enumerate()
        {
            let value = if name.ends_with("_token") {
                format!("token-{i:040}")
            } else {
                "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
            };
            put(source.path(), name, value.as_bytes(), 0o444);
        }
        put(
            source.path(),
            "operator_bootstrap_password",
            b"not-copied",
            0o444,
        );
        let src = directory(source.path()).unwrap();
        let dst = directory(target.path()).unwrap();
        let snapshot = stage_inputs(&src, &dst).unwrap();
        assert_eq!(snapshot.len(), 40);
        assert_eq!(
            file_names(&dst).unwrap(),
            installer_renewal_bootstrap::current_inputs()
        );
        assert!(stage_inputs(&src, &dst).is_err());
        let name = snapshot.keys().find(|n| n.ends_with("_token")).unwrap();
        std::fs::set_permissions(
            target.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(read_inputs(&dst).is_err());
    }

    #[test]
    fn delivered_identity_requires_private_files_complete_receipt_and_exact_inventory() {
        let temp = private();
        let dir = directory(temp.path()).unwrap();
        let pending = json!({"schema":"elevenid.installer-renewal-bootstrap-intent/v1","installation_id":OWNER,"root_retired":false,"ingress_renewal":false});
        let completed = json!({"schema":"elevenid.installer-renewal-bootstrap-result/v1","installation_id":OWNER,"identity_files":IDENTITY_FILES,"policy_count":21,"scoped_login_verified":true,"verification_token_revoked":true,"root_retired":false,"ingress_renewal":false});
        put(
            temp.path(),
            "pending.json",
            &serde_json::to_vec(&pending).unwrap(),
            0o600,
        );
        put(
            temp.path(),
            "completed.json",
            &serde_json::to_vec(&completed).unwrap(),
            0o600,
        );
        put(
            temp.path(),
            "renewal-role-id",
            b"11111111-1111-4111-8111-111111111111\n",
            0o600,
        );
        put(
            temp.path(),
            "renewal-secret-id",
            b"22222222-2222-4222-8222-222222222222\n",
            0o600,
        );
        put(
            temp.path(),
            "renewal-leaf-policies.json",
            &serde_json::to_vec(&(0..21).map(|i| format!("policy-{i}")).collect::<Vec<_>>())
                .unwrap(),
            0o600,
        );
        assert_eq!(validate_delivered(&dir, OWNER).unwrap().len(), 3);
        for (field, value) in [
            ("root_retired", json!(true)),
            ("verification_token_revoked", json!(false)),
            ("installation_id", json!("foreign")),
            ("extra", json!(true)),
        ] {
            let mut bad = completed.clone();
            bad[field] = value;
            put(
                temp.path(),
                "completed.json",
                &serde_json::to_vec(&bad).unwrap(),
                0o600,
            );
            assert!(validate_delivered(&dir, OWNER).is_err());
        }
        put(
            temp.path(),
            "completed.json",
            &serde_json::to_vec(&completed).unwrap(),
            0o600,
        );
        std::fs::set_permissions(
            temp.path().join("renewal-secret-id"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(validate_delivered(&dir, OWNER).is_err());
        std::fs::set_permissions(
            temp.path().join("renewal-secret-id"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        put(temp.path(), "unexpected", b"extra", 0o600);
        assert!(validate_delivered(&dir, OWNER).is_err());
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
}
