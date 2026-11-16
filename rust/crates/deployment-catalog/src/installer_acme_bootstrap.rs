//! Fixed-path, one-shot container bridges for ACME custody and machine credentials.
//! The host records the public plan before creating this owned setup job.
//! Bootstrap root is consumed only here and never returned to the host.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_credentials, installer_acme_custody, installer_host_fs, installer_release,
};
use marty_openbao_http::OpenBaoHttp;
use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME bootstrap bridge refused; retain its owned setup job, public plan and private outputs for reconciliation";
const PLAN: &str = "/input/acme-plan.json";
const ROOT: &str = "/input/root.token";
const CA: &str = "/input/ca.crt";
const OUTPUT: &str = "/output";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && (
            left.dev(),
            left.ino(),
            left.uid(),
            left.gid(),
            left.mode(),
            left.nlink(),
            left.len(),
            left.mtime(),
            left.mtime_nsec(),
            left.ctime(),
            left.ctime_nsec(),
        ) == (
            right.dev(),
            right.ino(),
            right.uid(),
            right.gid(),
            right.mode(),
            right.nlink(),
            right.len(),
            right.mtime(),
            right.mtime_nsec(),
            right.ctime(),
            right.ctime_nsec(),
        )
}

struct Input {
    path: PathBuf,
    held: File,
    metadata: Metadata,
    bytes: Vec<u8>,
}

impl Input {
    fn read(path: &Path, maximum: u64, modes: &[u32], root_owned: bool) -> Result<Self> {
        require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
        let mut held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| REFUSED)?;
        let metadata = held.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_file()
                && metadata.nlink() == 1
                && (1..=maximum).contains(&metadata.len())
                && modes.contains(&(metadata.mode() & 0o7777))
                && (!root_owned || (metadata.uid() == 0 && metadata.gid() == 0)),
        )?;
        let mut bytes = Vec::new();
        (&mut held)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        require(
            bytes.len() as u64 == metadata.len()
                && bytes.is_ascii()
                && !bytes.contains(&0)
                && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
        )?;
        let input = Self {
            path: path.into(),
            held,
            metadata,
            bytes,
        };
        input.require_unchanged()?;
        Ok(input)
    }

    fn require_unchanged(&self) -> Result<()> {
        require(
            same_file(&self.metadata, &self.held.metadata().map_err(|_| REFUSED)?)
                && same_file(
                    &self.metadata,
                    &std::fs::symlink_metadata(&self.path).map_err(|_| REFUSED)?,
                ),
        )
    }
}

fn installation(value: &str) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| REFUSED)?;
    require(
        id.to_string() == value
            && id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122,
    )?;
    Ok(id)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// This entry point has no URL, authority, file, environment or policy override.
/// Its only arguments are public values from the host's retained setup intent.
pub async fn provision_credentials(
    installation_id: &str,
    expected_plan_sha256: &str,
) -> Result<usize> {
    provision(installation_id, expected_plan_sha256, false).await
}

/// Separate setup transaction: only public custody output leaves this helper.
pub async fn provision_custody(installation_id: &str, expected_plan_sha256: &str) -> Result<usize> {
    provision(installation_id, expected_plan_sha256, true).await
}

enum Plan {
    Custody(installer_acme_custody::CustodyResourcePlan),
    Credentials(installer_acme_credentials::CredentialResourcePlan),
}

async fn provision(
    installation_id: &str,
    expected_plan_sha256: &str,
    custody: bool,
) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0)?;
    let owner = installation(installation_id)?;
    require(digest(expected_plan_sha256))?;
    let plan_input = Input::read(Path::new(PLAN), 32 * 1024, &[0o600], true)?;
    let plan = if custody {
        Plan::Custody(
            installer_acme_custody::CustodyResourcePlan::parse_authenticated(
                &plan_input.bytes,
                expected_plan_sha256,
            )?,
        )
    } else {
        Plan::Credentials(
            installer_acme_credentials::CredentialResourcePlan::parse_authenticated(
                &plan_input.bytes,
                expected_plan_sha256,
            )?,
        )
    };
    let plan_owner = match &plan {
        Plan::Custody(plan) => plan.installation_id(),
        Plan::Credentials(plan) => plan.installation_id(),
    };
    require(
        plan_owner == owner && installer_release::sha256(&plan_input.bytes) == expected_plan_sha256,
    )?;
    let root = Input::read(Path::new(ROOT), 4096, &[0o400], true)?;
    let authority = std::str::from_utf8(&root.bytes)
        .map_err(|_| REFUSED)?
        .trim();
    require(
        (20..=4096).contains(&authority.len())
            && authority
                .bytes()
                .all(|b| !b.is_ascii_whitespace() && !b.is_ascii_control()),
    )?;
    let ca = Input::read(Path::new(CA), 65_536, &[0o444, 0o644], false)?;
    crate::installer_ingress_provision::certificate(
        std::str::from_utf8(&ca.bytes).map_err(|_| REFUSED)?,
    )?;
    let output = installer_host_fs::directory(Path::new(OUTPUT), REFUSED)?;
    require(installer_host_fs::file_names(&output, REFUSED)?.is_empty())?;
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new(CA)),
        Duration::from_secs(5),
    )
    .map_err(|_| REFUSED)?;
    for input in [&plan_input, &root, &ca] {
        input.require_unchanged()?;
    }
    let before_transfer = || -> Result<()> {
        for input in [&plan_input, &root, &ca] {
            input.require_unchanged()?;
        }
        installer_host_fs::require_directory_binding(Path::new(OUTPUT), &output, REFUSED)
    };
    let count = tokio::time::timeout(Duration::from_secs(90), async {
        match &plan {
            Plan::Custody(plan) => {
                let provisioned =
                    installer_acme_custody::provision_resources(plan, &bao, authority).await?;
                before_transfer()?;
                provisioned.write_public_transfer(Path::new(OUTPUT))?;
                Ok::<_, String>(2)
            }
            Plan::Credentials(plan) => {
                let provisioned =
                    installer_acme_credentials::provision_resources(plan, &bao, authority).await?;
                before_transfer()?;
                provisioned.write_private_transfer(Path::new(OUTPUT))?;
                Ok(3)
            }
        }
    })
    .await
    .map_err(|_| REFUSED)?
    .map_err(|_| REFUSED)?;
    for input in [&plan_input, &root, &ca] {
        input.require_unchanged()?;
    }
    installer_host_fs::require_directory_binding(Path::new(OUTPUT), &output, REFUSED)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn public_arguments_never_select_a_path_authority_or_foreign_identifier() {
        installation("2e052c77-efe8-44c6-9421-9ef15fe8ee7c").unwrap();
        for value in [
            "../input/root.token",
            "00000000-0000-0000-0000-000000000000",
            "2E052C77-EFE8-44C6-9421-9EF15FE8EE7C",
        ] {
            assert!(installation(value).is_err());
        }
        assert!(digest(&"a".repeat(64)));
        for value in ["a".repeat(63), "A".repeat(64), "../input/root.token".into()] {
            assert!(!digest(&value));
        }
    }

    #[test]
    fn fixed_input_custody_rejects_aliases_links_replacement_and_private_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        std::fs::write(&path, b"{\"public\":true}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let held = Input::read(&path, 32 * 1024, &[0o600], false).unwrap();
        let alias = directory.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(Input::read(&alias, 32 * 1024, &[0o600], false).is_err());
        let hardlink = directory.path().join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(Input::read(&path, 32 * 1024, &[0o600], false).is_err());
        std::fs::remove_file(hardlink).unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, &held.bytes).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert!(held.require_unchanged().is_err());
        std::fs::write(&path, b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert!(Input::read(&path, 32 * 1024, &[0o600], false).is_err());
        std::fs::write(&path, b"public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Input::read(&path, 32 * 1024, &[0o600], false).is_err());
    }
}
