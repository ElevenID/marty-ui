//! Exclusive custody of the opt-in feature profile's immutable input files.
//! The private directory is never a workload mount. Only admitted individual
//! files are projected into the service that owns the corresponding authority.
#![cfg(target_os = "linux")]

use crate::{
    installer_filesystem::DeviceBinding,
    installer_host_fs,
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "feature credential custody changed or is incomplete; preserve installation state";
pub(crate) const DIRECTORY: &str = "feature-profile-secrets";
pub(crate) const RECORD: &str = "feature-profile-credentials.json";
const SCHEMA: &str = "elevenid.installer-feature-credentials/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: DeviceBinding,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl DirectoryIdentity {
    fn observe(file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(REFUSED.into());
        }
        Ok(Self {
            device: DeviceBinding::observe(file, REFUSED)?,
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
        })
    }

    fn retained_matches(&self, mut current: Self) -> bool {
        if !self.device.matches(current.device) {
            return false;
        }
        current.device = self.device;
        current == *self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fingerprint {
    sha256: String,
    bytes: u64,
}

fn fingerprint(bytes: &[u8]) -> Fingerprint {
    Fingerprint {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    feature_profile_sha256: String,
    directory: DirectoryIdentity,
    files: BTreeMap<String, Fingerprint>,
}

/// This type has no public constructor that adopts an existing directory.
/// It keeps the original FD and exact device/inode observation until sealing.
pub(crate) struct FeatureCredentialDirectory {
    path: PathBuf,
    directory: File,
    original: DirectoryIdentity,
    installation_id: uuid::Uuid,
    engine_id: String,
    profile_sha256: String,
    files: BTreeMap<String, Fingerprint>,
    failed: bool,
}

fn valid_name(name: &str) -> bool {
    name.starts_with("feature_")
        && name.len() <= 127
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn valid_bytes(name: &str, bytes: &[u8]) -> bool {
    if name == "feature_workload_client_ca_der" {
        use x509_cert::der::Decode;
        return !bytes.is_empty()
            && bytes.len() <= 16_384
            && x509_cert::Certificate::from_der(bytes).is_ok();
    }
    !bytes.is_empty()
        && bytes.len() <= 65_536
        && bytes.is_ascii()
        && !bytes.contains(&0)
        && !bytes.windows(11).any(|part| part == b"PRIVATE KEY")
}

impl FeatureCredentialDirectory {
    pub(crate) fn create(state: &mut InstallerState, installation: &Path) -> Result<Self> {
        state.require_live_phase(Phase::Provisioning)?;
        state.with_inspection(|view| view.require_path_binding(installation))?;
        let profile_sha256 = state
            .journal()
            .feature_profile_sha256()
            .ok_or(REFUSED)?
            .to_owned();
        let installation_id = state.journal().installation_id();
        let engine_id = state.journal().runtime().ok_or(REFUSED)?.engine_id.clone();
        let directory = state.create_feature_directory(DIRECTORY)?;
        let original = DirectoryIdentity::observe(&directory)?;
        let result = Self {
            path: installation.join(DIRECTORY),
            directory,
            original,
            installation_id,
            engine_id,
            profile_sha256,
            files: BTreeMap::new(),
            failed: false,
        };
        result.require_current()?;
        Ok(result)
    }

    fn require_current(&self) -> Result<()> {
        if self.failed || DirectoryIdentity::observe(&self.directory)? != self.original {
            return Err(REFUSED.into());
        }
        installer_host_fs::require_directory_binding(&self.path, &self.directory, REFUSED)
    }

    pub(crate) fn write(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.require_current()?;
        if !valid_name(name) || !valid_bytes(name, bytes) || self.files.contains_key(name) {
            return Err(REFUSED.into());
        }
        self.failed = true;
        let child = CString::new(name).map_err(|_| REFUSED)?;
        // Exclusive creation relative to the original descriptor: failed or
        // uncertain outputs remain evidence and cannot be silently retried.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                child.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(REFUSED.into());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        self.directory.sync_all().map_err(|_| REFUSED)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| REFUSED)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
            return Err(REFUSED.into());
        }
        file.sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| REFUSED)?;
        let admitted = read_feature_entry(&self.directory, name)?;
        if admitted != bytes {
            return Err(REFUSED.into());
        }
        self.files.insert(name.into(), fingerprint(bytes));
        self.failed = false;
        self.require_current()
    }

    pub(crate) fn seal(
        self,
        state: &mut InstallerState,
        expected_names: &BTreeSet<String>,
    ) -> Result<()> {
        state.require_live_phase(Phase::Provisioning)?;
        self.require_current()?;
        if self.installation_id != state.journal().installation_id()
            || state.journal().feature_profile_sha256() != Some(self.profile_sha256.as_str())
            || state.journal().runtime().map(|r| r.engine_id.as_str())
                != Some(self.engine_id.as_str())
            || self.files.is_empty()
            || self.files.keys().cloned().collect::<BTreeSet<_>>() != *expected_names
            || inspect_files(&self.directory, expected_names)? != self.files
        {
            return Err(REFUSED.into());
        }
        let manifest = Manifest {
            schema: SCHEMA.into(),
            installation_id: self.installation_id,
            engine_id: self.engine_id,
            feature_profile_sha256: self.profile_sha256,
            directory: self.original,
            files: self.files,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| REFUSED)?;
        state.write_evidence(RECORD, &bytes)?;
        state.with_inspection(|view| verify(view, expected_names).map(|_| ()))
    }
}

fn read_feature_entry(directory: &File, name: &str) -> Result<Vec<u8>> {
    if name != "feature_workload_client_ca_der" {
        return installer_host_fs::read_entry(directory, name, 0o444, false, REFUSED);
    }
    // One public certificate adapter needs DER. This exact filename admits a
    // strictly parsed certificate only; generic credential readers stay ASCII
    // and continue rejecting all private-key material.
    let file =
        installer_host_fs::open_child(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
    let metadata = file.metadata().map_err(|_| REFUSED)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o444
        || !(1..=16_384).contains(&metadata.len())
    {
        return Err(REFUSED.into());
    }
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    if bytes.len() as u64 != metadata.len() || !valid_bytes(name, &bytes) {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}

fn inspect_files(
    directory: &File,
    expected_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Fingerprint>> {
    if expected_names.is_empty()
        || expected_names.len() > 128
        || expected_names.iter().any(|name| !valid_name(name))
        || installer_host_fs::file_names(directory, REFUSED)? != *expected_names
    {
        return Err(REFUSED.into());
    }
    expected_names
        .iter()
        .map(|name| {
            let bytes = read_feature_entry(directory, name)?;
            Ok((name.clone(), fingerprint(&bytes)))
        })
        .collect()
}

fn verify_held(
    installation: &File,
    journal: &Journal,
    bytes: &[u8],
    expected_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let manifest: Manifest =
        serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let directory = installer_host_fs::open_child(
        installation,
        DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let original = DirectoryIdentity::observe(&directory)?;
    if manifest.schema != SCHEMA
        || manifest.installation_id != journal.installation_id()
        || journal.feature_profile_sha256() != Some(manifest.feature_profile_sha256.as_str())
        || journal.runtime().map(|r| r.engine_id.as_str()) != Some(manifest.engine_id.as_str())
        || !manifest.directory.retained_matches(original.clone())
        || manifest.files.keys().cloned().collect::<BTreeSet<_>>() != *expected_names
        || expected_names.is_empty()
        || expected_names.len() > 128
        || expected_names.iter().any(|name| !valid_name(name))
        || installer_host_fs::file_names(&directory, REFUSED)? != *expected_names
    {
        return Err(REFUSED.into());
    }
    let values: BTreeMap<String, Vec<u8>> = expected_names
        .iter()
        .map(|name| {
            let bytes = read_feature_entry(&directory, name)?;
            if manifest.files.get(name) != Some(&fingerprint(&bytes)) {
                return Err(REFUSED.into());
            }
            Ok((name.clone(), bytes))
        })
        .collect::<Result<_>>()?;
    let current = installer_host_fs::open_child(
        installation,
        DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    if DirectoryIdentity::observe(&current)? != original {
        return Err(REFUSED.into());
    }
    Ok(values)
}

pub(crate) fn verify(
    view: &LockedInspection,
    expected_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let bytes = view.read_evidence(RECORD)?;
    let result = verify_held(
        view.installation_directory(),
        view.journal(),
        &bytes,
        expected_names,
    )?;
    view.require_unchanged()?;
    Ok(result)
}

/// Read-only Compose admission already executes under its caller's installation
/// lock. This variant takes no second flock and never mutates retained inputs.
pub(crate) fn verify_at(
    installation: &Path,
    expected_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let journal = InstallerState::inspect(installation)?;
    let held = installer_host_fs::directory(installation, REFUSED)?;
    let evidence = installer_host_fs::open_child(
        &held,
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    DirectoryIdentity::observe(&evidence)?;
    let bytes = installer_host_fs::read_entry(&evidence, RECORD, 0o600, false, REFUSED)?;
    let result = verify_held(&held, &journal, &bytes, expected_names)?;
    installer_host_fs::require_directory_binding(installation, &held, REFUSED)?;
    if InstallerState::inspect(installation)? != journal {
        return Err(REFUSED.into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    fn fixture() -> (tempfile::TempDir, FeatureCredentialDirectory) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join(DIRECTORY);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = installer_host_fs::directory(&path, REFUSED).unwrap();
        let original = DirectoryIdentity::observe(&directory).unwrap();
        (
            temp,
            FeatureCredentialDirectory {
                path,
                directory,
                original,
                installation_id: uuid::Uuid::new_v4(),
                engine_id: "test".into(),
                profile_sha256: "a".repeat(64),
                files: BTreeMap::new(),
                failed: false,
            },
        )
    }

    #[test]
    fn replacement_directory_cannot_be_adopted_during_population() {
        let (temp, mut owner) = fixture();
        owner.write("feature_first", b"first").unwrap();
        fs::rename(&owner.path, temp.path().join("retained")).unwrap();
        fs::create_dir(&owner.path).unwrap();
        fs::set_permissions(&owner.path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(owner.write("feature_second", b"second").is_err());
        assert!(!owner.path.join("feature_second").exists());
        assert_eq!(
            fs::read(temp.path().join("retained/feature_first")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn only_exact_immutable_non_key_inventory_is_admitted() {
        let (temp, mut owner) = fixture();
        assert!(owner.write("../outside", b"x").is_err());
        assert!(owner
            .write("feature_key", b"-----BEGIN PRIVATE KEY-----")
            .is_err());
        assert!(owner.write("feature_empty", b"").is_err());
        owner.write("feature_token", b"opaque-token").unwrap();
        let names = BTreeSet::from(["feature_token".into()]);
        assert_eq!(
            inspect_files(&owner.directory, &names).unwrap(),
            owner.files
        );
        assert!(owner.write("feature_token", b"replacement").is_err());
        fs::hard_link(owner.path.join("feature_token"), temp.path().join("alias")).unwrap();
        assert!(inspect_files(&owner.directory, &names).is_err());
    }

    #[test]
    fn unexpected_files_and_symlinks_refuse_without_reading_the_target() {
        let (temp, mut owner) = fixture();
        owner.write("feature_token", b"opaque-token").unwrap();
        fs::write(temp.path().join("outside"), "sensitive").unwrap();
        symlink(
            temp.path().join("outside"),
            owner.path.join("feature_other"),
        )
        .unwrap();
        let names = BTreeSet::from(["feature_token".into(), "feature_other".into()]);
        assert!(inspect_files(&owner.directory, &names).is_err());
        assert!(
            inspect_files(&owner.directory, &BTreeSet::from(["feature_token".into()])).is_err()
        );
    }

    #[test]
    fn retained_uuid_matching_never_relaxes_same_process_identity() {
        let (_temp, owner) = fixture();
        let mut original = owner.original;
        original.device = DeviceBinding::ext4_for_test(123, [7; 16]);
        let mut after_boot = original.clone();
        after_boot.device = DeviceBinding::ext4_for_test(456, [7; 16]);
        assert_ne!(original, after_boot);
        assert!(original.retained_matches(after_boot.clone()));
        after_boot.inode += 1;
        assert!(!original.retained_matches(after_boot));
    }
}
