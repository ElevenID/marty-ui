//! Compose-managed first-install setup; completed jobs and uncertain outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_helper_output, installer_jobs,
    installer_keycloak_bridge::OUTPUTS,
    installer_openbao::OpenBaoInventory,
    installer_state::{InstallerState, Phase},
};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Keycloak provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct KeycloakReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub nonce: String,
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

fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name).map_err(|_| REFUSAL)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(REFUSAL.into())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn read_outputs(directory: &File, owner: u32) -> Result<BTreeMap<String, Vec<u8>>> {
    let held = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let names = std::fs::read_dir(held)
        .map_err(|_| REFUSAL)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSAL)
                .and_then(|e| e.file_name().into_string().map_err(|_| REFUSAL))
        })
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    require(names == OUTPUTS.into_iter().map(str::to_owned).collect())?;
    let mut result = BTreeMap::new();
    let mut tokens = BTreeSet::new();
    for name in OUTPUTS {
        let file = open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let m = file.metadata().map_err(|_| REFUSAL)?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o444
                && m.len() > 0
                && m.len() <= 65536,
        )?;
        let mut bytes = Vec::new();
        (&file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSAL)?;
        require(bytes.len() as u64 == m.len())?;
        let after = file.metadata().map_err(|_| REFUSAL)?;
        require(
            after.dev() == m.dev()
                && after.ino() == m.ino()
                && after.uid() == owner
                && after.nlink() == m.nlink()
                && after.mode() == m.mode()
                && after.len() == m.len()
                && after.mtime() == m.mtime()
                && after.mtime_nsec() == m.mtime_nsec(),
        )?;
        let value = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
        require(value.is_ascii() && !value.contains("PRIVATE KEY"))?;
        if name.ends_with("_token") {
            require(
                (20..=2048).contains(&value.len())
                    && !value
                        .bytes()
                        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                    && tokens.insert(value.to_owned()),
            )?;
        } else {
            require(
                value.starts_with("-----BEGIN CERTIFICATE-----")
                    && value.trim_end().ends_with("-----END CERTIFICATE-----"),
            )?;
        }
        result.insert(name.to_owned(), bytes);
    }
    Ok(result)
}

fn transfer(secrets: &File, outputs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for name in OUTPUTS {
        let mut file = open_at(
            secrets,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        secrets.sync_all().map_err(|_| REFUSAL)?;
        file.write_all(outputs.get(name).ok_or(REFUSAL)?)
            .map_err(|_| REFUSAL)?;
        file.sync_all().map_err(|_| REFUSAL)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
        file.sync_all()
            .and_then(|_| secrets.sync_all())
            .map_err(|_| REFUSAL)?;
    }
    Ok(())
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
    inputs: ComposeInputs,
    nonce: &str,
    expected_operator_sha: &str,
) -> Result<(ComposeReceipt, KeycloakReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    require(
        InstallerState::inspect(installation)? == *state.journal()
            && nonce.len() == 12
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    let secrets = directory(&installation.join("secrets"))?;
    for name in OUTPUTS {
        let name = CString::new(name).unwrap();
        let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                secrets.as_raw_fd(),
                name.as_ptr(),
                m.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        require(
            result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        )?;
    }
    state.create_private_directory("keycloak-output")?;
    let output = directory(&installation.join("keycloak-output"))?;
    state.write_evidence(
        "keycloak-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-keycloak-intent/v2", "installation_id":owner,
            "engine_id":binding.engine_id,"nonce":nonce,"operator_sha256":expected_operator_sha
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
        "installer-keycloak",
        &bao.image,
        expected_operator_sha,
    )?;
    let values = read_outputs(
        &output,
        installer_helper_output::expected_host_uid(&binding)?.uid(),
    )?;
    transfer(&secrets, &values)?;
    let receipt = KeycloakReceipt {
        schema: "elevenid.installer-keycloak/v2",
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        nonce: nonce.into(),
        outputs: OUTPUTS.into_iter().map(str::to_owned).collect(),
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "keycloak-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn private() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn write_outputs(path: &Path) {
        for (index, name) in OUTPUTS.iter().enumerate() {
            let content = if name.ends_with("_token") {
                format!("leaf-{index}-{}", "a".repeat(30))
            } else {
                "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
            };
            let file = path.join(name);
            std::fs::write(&file, content).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
    }

    #[test]
    fn output_transfer_is_exclusive_and_retains_originals() {
        let source = private();
        let destination = private();
        write_outputs(source.path());
        let outputs = read_outputs(&directory(source.path()).unwrap(), unsafe {
            libc::geteuid()
        })
        .unwrap();
        let target = directory(destination.path()).unwrap();
        transfer(&target, &outputs).unwrap();
        assert!(transfer(&target, &outputs).is_err());
        for name in OUTPUTS {
            assert_eq!(
                std::fs::read(source.path().join(name)).unwrap(),
                std::fs::read(destination.path().join(name)).unwrap()
            );
            assert_eq!(
                std::fs::metadata(destination.path().join(name))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o444
            );
        }
    }

    #[test]
    fn rootless_profile_accepts_only_its_expected_host_owner() {
        let uid = unsafe { libc::geteuid() };
        let binding = crate::installer_state::RuntimeBinding {
            docker_host: format!("unix:///run/user/{uid}/docker.sock"),
            engine_id: "engine-identity-123".into(),
            openbao_port: 8200,
            profile: crate::installer_state::RuntimeProfile::Rootless,
        };
        if uid == 0 {
            assert!(installer_helper_output::expected_host_uid(&binding).is_err());
            return;
        }
        let source = private();
        write_outputs(source.path());
        let owner = installer_helper_output::expected_host_uid(&binding)
            .unwrap()
            .uid();
        assert!(read_outputs(&directory(source.path()).unwrap(), owner).is_ok());
        assert!(read_outputs(&directory(source.path()).unwrap(), owner.wrapping_add(1)).is_err());
    }

    #[test]
    fn output_inventory_refuses_links_wrong_owner_modes_and_extra_files() {
        for mutation in [
            "link", "hardlink", "owner", "mode", "extra", "size", "private",
        ] {
            let source = private();
            write_outputs(source.path());
            let path = source.path().join(OUTPUTS[0]);
            let owner = if mutation == "owner" {
                unsafe { libc::geteuid() }.wrapping_add(1)
            } else {
                unsafe { libc::geteuid() }
            };
            match mutation {
                "link" => {
                    std::fs::remove_file(&path).unwrap();
                    symlink(source.path().join(OUTPUTS[3]), &path).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&path, source.path().join("extra-link")).unwrap();
                }
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "extra" => std::fs::write(source.path().join("extra"), b"x").unwrap(),
                "size" | "private" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::write(
                        &path,
                        if mutation == "size" {
                            vec![b'a'; 65537]
                        } else {
                            b"PRIVATE KEY forbidden content".to_vec()
                        },
                    )
                    .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
                        .unwrap();
                }
                _ => (),
            }
            assert!(
                read_outputs(&directory(source.path()).unwrap(), owner).is_err(),
                "accepted {mutation}"
            );
        }
    }
}
