//! Durable guest-local candidate consumption. This is not global replay prevention:
//! the controller must also consume its transaction outside the disposable guest.
//! Preserve this registry across installation paths, failures and uninstall.
#![cfg(target_os = "linux")]

use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Candidate nonce consumption refused; preserve the controller transaction and guest registry";

#[derive(Serialize)]
pub struct Consumption {
    pub nonce: String,
    pub authorization_sha256: String,
    pub context_sha256: String,
    pub installation_id: uuid::Uuid,
    pub engine_id: String,
}

/// Holds the registry lock through provisioning. Dropping it never removes the
/// durable claim, including after failed or uncertain provisioning.
pub struct ConsumedNonce {
    _directory: File,
    owner_pid: libc::pid_t,
    pub consumption_id: String,
}

impl Drop for ConsumedNonce {
    fn drop(&mut self) {
        // Release explicitly even if a just-forked child inherited the open
        // description before its close-on-exec boundary.
        if unsafe { libc::getpid() } == self.owner_pid {
            while unsafe { libc::flock(self._directory.as_raw_fd(), libc::LOCK_UN) } != 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

pub fn consume(registry: &Path, claim: &Consumption) -> Result<ConsumedNonce> {
    let hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    require(
        hex(&claim.nonce)
            && hex(&claim.authorization_sha256)
            && hex(&claim.context_sha256)
            && claim.installation_id.get_version() == Some(uuid::Version::Random)
            && claim.installation_id.get_variant() == uuid::Variant::RFC4122,
    )?;
    require(
        regex::Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9:-]{7,127}\z")
            .unwrap()
            .is_match(&claim.engine_id),
    )?;
    crate::installer_runtime::private_parent(registry)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(registry)
        .map_err(|_| REFUSED)?;
    let info = directory.metadata().map_err(|_| REFUSED)?;
    require(
        info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o7777 == 0o700,
    )?;
    require(unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)?;
    let mut consumed = ConsumedNonce {
        _directory: directory,
        owner_pid: unsafe { libc::getpid() },
        consumption_id: String::new(),
    };
    crate::installer_runtime::private_parent(registry)?;
    let current = std::fs::symlink_metadata(registry).map_err(|_| REFUSED)?;
    require(current.dev() == info.dev() && current.ino() == info.ino())?;
    let name = std::ffi::CString::new(format!("{}.json", claim.nonce)).map_err(|_| REFUSED)?;
    // Exclusive creation is the consumption point. Even a partial write burns
    // this nonce; never unlink it or turn a failed claim into a retry.
    let raw = unsafe {
        libc::openat(
            consumed._directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(raw >= 0)?;
    use std::os::fd::FromRawFd;
    let mut file = unsafe { File::from_raw_fd(raw) };
    consumed._directory.sync_all().map_err(|_| REFUSED)?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema":"elevenid.installer-candidate-consumption/v1", "scope":"guest-local",
        "claim":claim,
    }))
    .map_err(|_| REFUSED)?;
    require(bytes.len() <= 4096)?;
    file.write_all(&bytes).map_err(|_| REFUSED)?;
    file.sync_all().map_err(|_| REFUSED)?;
    consumed._directory.sync_all().map_err(|_| REFUSED)?;
    consumed.consumption_id = crate::installer_release::sha256(&bytes);
    Ok(consumed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn claim() -> Consumption {
        Consumption {
            nonce: "a".repeat(64),
            authorization_sha256: "b".repeat(64),
            context_sha256: "c".repeat(64),
            installation_id: uuid::Uuid::new_v4(),
            engine_id: "test-engine-12345678".into(),
        }
    }
    fn registry() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    #[test]
    fn consumed_nonce_survives_lock_release_and_refuses_different_installation() {
        let directory = registry();
        let first = claim();
        let held = consume(directory.path(), &first).unwrap();
        let mut other = claim();
        other.nonce = "d".repeat(64);
        assert!(consume(directory.path(), &other).is_err());
        // Model an inherited descriptor retaining the same open description.
        let duplicate = held._directory.try_clone().unwrap();
        drop(held);
        let mut replay = claim();
        replay.engine_id = "different-engine-12345".into();
        assert!(consume(directory.path(), &replay).is_err());
        assert!(consume(directory.path(), &other).is_ok());
        drop(duplicate);
        assert!(directory
            .path()
            .join(format!("{}.json", first.nonce))
            .is_file());
    }
    #[test]
    fn partial_claim_and_symlink_registry_are_never_reused() {
        let directory = registry();
        let first = claim();
        std::fs::write(directory.path().join(format!("{}.json", first.nonce)), b"").unwrap();
        assert!(consume(directory.path(), &first).is_err());
        let parent = registry();
        let link = parent.path().join("linked");
        symlink(directory.path(), &link).unwrap();
        assert!(consume(&link, &first).is_err());
    }
}
