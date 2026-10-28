//! Read-only verification of the initial local creation receipt against held
//! directories. Local historical evidence is not cryptographic authentication
//! or deletion authorization. Later installer resources remain outside scope.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // No purge coordinator exists yet.

use crate::{
    installer_creation_identity::{
        observe, observe_operator, ObservedDirectory, ObservedFile, APPLICATION_RECEIPT,
        CREDENTIAL_RECEIPT, RECEIPT,
    },
    installer_purge_host::{HostIdentity, Kind},
    installer_state::LockedInspection,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

const LIMIT: usize = 4096;
type Result<T> = std::result::Result<T, ()>;
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn child(parent: &File, entry: &str, flags: i32) -> Result<Option<File>> {
    let name = CString::new(entry).map_err(|_| ())?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x01 | 0x04 | 0x08,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(())
        };
    }
    Ok(Some(unsafe { File::from_raw_fd(fd as i32) }))
}
fn read_regular(held: &File) -> Result<Vec<u8>> {
    let m = held.metadata().map_err(|_| ())?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
        || m.len() == 0
        || m.len() > LIMIT as u64
    {
        return Err(());
    }
    // Only reopen after O_PATH metadata proved that open cannot operate on a
    // device or FIFO. The procfs descriptor refers to this exact held inode.
    let proc = File::open("/proc/self/fd").map_err(|_| ())?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0 || info.f_type as i64 != 0x9fa0 {
        return Err(());
    }
    let name = CString::new(held.as_raw_fd().to_string()).map_err(|_| ())?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let current = file.metadata().map_err(|_| ())?;
    if current.dev() != m.dev()
        || current.ino() != m.ino()
        || current.mode() != m.mode()
        || current.uid() != m.uid()
        || current.gid() != m.gid()
        || current.nlink() != 1
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(());
    }
    Ok(bytes)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    kind: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirectory {
    identity: RawIdentity,
    mount_id: u64,
}
impl RawDirectory {
    fn matches(&self, observed: &ObservedDirectory) -> bool {
        let m = &self.identity;
        let expected = HostIdentity {
            dev: m.dev,
            ino: m.ino,
            uid: m.uid,
            gid: m.gid,
            mode: m.mode,
            kind: Kind::Directory,
        };
        self.mount_id != 0
            && self.mount_id == observed.mount_id
            && m.kind == "directory"
            && observed.identity == expected
            && m.mode == 0o700
            && m.uid == unsafe { libc::geteuid() }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    root: RawDirectory,
    evidence: RawDirectory,
    downloads: RawDirectory,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
/// Private metadata only. This observation is point-in-time and authorizes no
/// deletion; a complete inventory and separate coordinator are still required.
#[derive(PartialEq, Eq)]
pub(crate) struct ObservedInitialCreation {
    pub root: ObservedDirectory,
    pub evidence: ObservedDirectory,
    pub downloads: ObservedDirectory,
    pub receipt_sha256: String,
}
pub(crate) enum InspectionOutcome {
    Missing,
    Unusable,
    MatchedLocalReceipt(ObservedInitialCreation),
}
fn verify(
    locked: &LockedInspection,
    installation: &Path,
) -> Result<Option<ObservedInitialCreation>> {
    locked.require_path_binding(installation).map_err(|_| ())?;
    let root = locked.installation_directory();
    let Some(evidence) = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)? else {
        return Ok(None);
    };
    let Some(record) = child(&evidence, RECEIPT, libc::O_PATH)? else {
        return Ok(None);
    };
    let bytes = read_regular(&record)?;
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| ())?;
    // Re-encoding rejects duplicate fields, alternate encodings and trailing
    // material, matching the producer's exact compact serialization contract.
    if serde_json::to_vec(&receipt).map_err(|_| ())? != bytes
        || receipt.schema != "elevenid.installer-created-identity/v1"
        || receipt.installation_id != locked.journal().installation_id()
        || receipt.source_sha != locked.journal().identity().source_sha
        || !receipt.local_historical_evidence
        || receipt.deletion_authorized
    {
        return Err(());
    }
    let downloads = child(root, "downloads", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let observed_root = observe(root).map_err(|_| ())?;
    let observed_evidence = observe(&evidence).map_err(|_| ())?;
    let observed_downloads = observe(&downloads).map_err(|_| ())?;
    if !receipt.root.matches(&observed_root)
        || !receipt.evidence.matches(&observed_evidence)
        || !receipt.downloads.matches(&observed_downloads)
        || observed_root.mount_id != observed_evidence.mount_id
        || observed_root.mount_id != observed_downloads.mount_id
        || observed_evidence == observed_downloads
    {
        return Err(());
    }
    let current_evidence = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let current_downloads =
        child(root, "downloads", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let current_record = child(&current_evidence, RECEIPT, libc::O_PATH)?.ok_or(())?;
    let before = record.metadata().map_err(|_| ())?;
    let after = current_record.metadata().map_err(|_| ())?;
    if observe(root).map_err(|_| ())? != observed_root
        || observe(&current_evidence).map_err(|_| ())? != observed_evidence
        || observe(&current_downloads).map_err(|_| ())? != observed_downloads
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || read_regular(&current_record)? != bytes
    {
        return Err(());
    }
    locked.require_path_binding(installation).map_err(|_| ())?;
    locked.require_unchanged().map_err(|_| ())?;
    Ok(Some(ObservedInitialCreation {
        root: observed_root,
        evidence: observed_evidence,
        downloads: observed_downloads,
        receipt_sha256: format!("{:x}", Sha256::digest(&bytes)),
    }))
}
pub(crate) fn inspect(locked: &LockedInspection, installation: &Path) -> InspectionOutcome {
    let result = verify(locked, installation);
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return InspectionOutcome::Unusable;
    }
    match result {
        Ok(Some(receipt)) => InspectionOutcome::MatchedLocalReceipt(receipt),
        Ok(None) => InspectionOutcome::Missing,
        Err(()) => InspectionOutcome::Unusable,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    identity: RawIdentity,
    mount_id: u64,
}
impl RawFile {
    fn matches(&self, observed: &ObservedFile) -> bool {
        let m = &self.identity;
        let expected = HostIdentity {
            dev: m.dev,
            ino: m.ino,
            uid: m.uid,
            gid: m.gid,
            mode: m.mode,
            kind: Kind::File,
        };
        self.mount_id != 0
            && self.mount_id == observed.mount_id
            && m.kind == "file"
            && observed.identity == expected
            && m.mode == 0o600
            && m.uid == unsafe { libc::geteuid() }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    secrets: RawDirectory,
    operator_password: RawFile,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
/// Current local identity evidence only. Password/scalar contents are never
/// read. This does not inventory the contents of the secrets directory.
#[derive(PartialEq, Eq)]
pub(crate) struct ObservedCredentialCreation {
    pub initial: ObservedInitialCreation,
    pub secrets: ObservedDirectory,
    pub operator_password: ObservedFile,
    pub receipt_sha256: String,
}
pub(crate) enum CredentialInspectionOutcome {
    Missing,
    Unusable,
    MatchedLocalReceipt(Box<ObservedCredentialCreation>),
}
fn verify_credentials(
    locked: &LockedInspection,
    installation: &Path,
) -> Result<Option<ObservedCredentialCreation>> {
    let Some(initial) = verify(locked, installation)? else {
        return Ok(None);
    };
    let root = locked.installation_directory();
    let evidence = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let Some(record) = child(&evidence, CREDENTIAL_RECEIPT, libc::O_PATH)? else {
        return Ok(None);
    };
    let bytes = read_regular(&record)?;
    let receipt: CredentialReceipt = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if serde_json::to_vec(&receipt).map_err(|_| ())? != bytes
        || receipt.schema != "elevenid.installer-created-credentials/v1"
        || receipt.installation_id != locked.journal().installation_id()
        || receipt.source_sha != locked.journal().identity().source_sha
        || !receipt.local_historical_evidence
        || receipt.deletion_authorized
        || observe(&evidence).map_err(|_| ())? != initial.evidence
    {
        return Err(());
    }
    let secrets = child(root, "secrets", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let operator = child(root, "operator-password", libc::O_PATH)?.ok_or(())?;
    let observed_secrets = observe(&secrets).map_err(|_| ())?;
    let observed_operator = observe_operator(&operator).map_err(|_| ())?;
    if !receipt.secrets.matches(&observed_secrets)
        || !receipt.operator_password.matches(&observed_operator)
        || observed_secrets.mount_id != initial.root.mount_id
        || observed_operator.mount_id != initial.root.mount_id
    {
        return Err(());
    }
    let latest_secrets = child(root, "secrets", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let latest_operator = child(root, "operator-password", libc::O_PATH)?.ok_or(())?;
    let latest_record = child(&evidence, CREDENTIAL_RECEIPT, libc::O_PATH)?.ok_or(())?;
    let before = record.metadata().map_err(|_| ())?;
    let after = latest_record.metadata().map_err(|_| ())?;
    if observe(&latest_secrets).map_err(|_| ())? != observed_secrets
        || observe_operator(&latest_operator).map_err(|_| ())? != observed_operator
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || read_regular(&latest_record)? != bytes
    {
        return Err(());
    }
    let latest_initial = verify(locked, installation)?.ok_or(())?;
    if latest_initial.root != initial.root
        || latest_initial.evidence != initial.evidence
        || latest_initial.downloads != initial.downloads
        || latest_initial.receipt_sha256 != initial.receipt_sha256
    {
        return Err(());
    }
    Ok(Some(ObservedCredentialCreation {
        initial,
        secrets: observed_secrets,
        operator_password: observed_operator,
        receipt_sha256: format!("{:x}", Sha256::digest(&bytes)),
    }))
}
pub(crate) fn inspect_credentials(
    locked: &LockedInspection,
    installation: &Path,
) -> CredentialInspectionOutcome {
    let result = verify_credentials(locked, installation);
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return CredentialInspectionOutcome::Unusable;
    }
    match result {
        Ok(Some(observed)) => CredentialInspectionOutcome::MatchedLocalReceipt(Box::new(observed)),
        Ok(None) => CredentialInspectionOutcome::Missing,
        Err(()) => CredentialInspectionOutcome::Unusable,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApplicationRoots {
    state: RawDirectory,
    backups: RawDirectory,
    openbao_exports: RawDirectory,
    openbao_snapshot_identity: RawDirectory,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    roots: RawApplicationRoots,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
/// Four fixed root identities only; their current descendants are left to the
/// complete tree observer after writers have been stopped.
pub(crate) struct ObservedApplicationCreation {
    pub credentials: ObservedCredentialCreation,
    pub roots: BTreeMap<&'static str, ObservedDirectory>,
    pub receipt_sha256: String,
}
pub(crate) enum ApplicationInspectionOutcome {
    Missing,
    Unusable,
    MatchedLocalReceipt(Box<ObservedApplicationCreation>),
}
fn verify_application(
    locked: &LockedInspection,
    installation: &Path,
) -> Result<Option<ObservedApplicationCreation>> {
    let Some(credentials) = verify_credentials(locked, installation)? else {
        return Ok(None);
    };
    let root = locked.installation_directory();
    let evidence = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let Some(record) = child(&evidence, APPLICATION_RECEIPT, libc::O_PATH)? else {
        return Ok(None);
    };
    let bytes = read_regular(&record)?;
    let receipt: ApplicationReceipt = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if serde_json::to_vec(&receipt).map_err(|_| ())? != bytes
        || receipt.schema != "elevenid.installer-created-application-storage/v1"
        || receipt.installation_id != locked.journal().installation_id()
        || receipt.source_sha != locked.journal().identity().source_sha
        || !receipt.local_historical_evidence
        || receipt.deletion_authorized
        || observe(&evidence).map_err(|_| ())? != credentials.initial.evidence
    {
        return Err(());
    }
    let mut held = Vec::new();
    for (name, expected) in [
        ("state", &receipt.roots.state),
        ("backups", &receipt.roots.backups),
        ("openbao-exports", &receipt.roots.openbao_exports),
        (
            "openbao-snapshot-identity",
            &receipt.roots.openbao_snapshot_identity,
        ),
    ] {
        let file = child(root, name, libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
        let observed = observe(&file).map_err(|_| ())?;
        if !expected.matches(&observed) || observed.mount_id != credentials.initial.root.mount_id {
            return Err(());
        }
        held.push((name, observed, file));
    }
    let mut roots = BTreeMap::new();
    for (name, observed, file) in held {
        let latest = child(root, name, libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
        if observe(&file).map_err(|_| ())? != observed
            || observe(&latest).map_err(|_| ())? != observed
        {
            return Err(());
        }
        roots.insert(name, observed);
    }
    let latest_record = child(&evidence, APPLICATION_RECEIPT, libc::O_PATH)?.ok_or(())?;
    let before = record.metadata().map_err(|_| ())?;
    let after = latest_record.metadata().map_err(|_| ())?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || read_regular(&latest_record)? != bytes
        || verify_credentials(locked, installation)?.ok_or(())? != credentials
    {
        return Err(());
    }
    Ok(Some(ObservedApplicationCreation {
        credentials,
        roots,
        receipt_sha256: format!("{:x}", Sha256::digest(&bytes)),
    }))
}
pub(crate) fn inspect_application(
    locked: &LockedInspection,
    installation: &Path,
) -> ApplicationInspectionOutcome {
    let result = verify_application(locked, installation);
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return ApplicationInspectionOutcome::Unusable;
    }
    match result {
        Ok(Some(observed)) => ApplicationInspectionOutcome::MatchedLocalReceipt(Box::new(observed)),
        Ok(None) => ApplicationInspectionOutcome::Missing,
        Err(()) => ApplicationInspectionOutcome::Unusable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };
    fn fixture() -> (tempfile::TempDir, PathBuf, InstallerState) {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("installation");
        let mut state = InstallerState::create_with_runtime(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.1.263".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "synthetic-engine".into(),
                openbao_port: 8200,
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        state.create_private_directory("downloads").unwrap();
        state.persist_initial_creation_receipt(&path).unwrap();
        (parent, path, state)
    }
    fn inspect_state(state: &InstallerState, path: &Path) -> InspectionOutcome {
        state
            .with_inspection(|locked| Ok(inspect(locked, path)))
            .unwrap()
    }
    #[test]
    fn exact_local_receipt_matches_without_changing_bytes() {
        let (_parent, path, state) = fixture();
        let before = fs::read(path.join("evidence").join(RECEIPT)).unwrap();
        let InspectionOutcome::MatchedLocalReceipt(observed) = inspect_state(&state, &path) else {
            panic!("expected matched local evidence")
        };
        assert_eq!(
            observed.receipt_sha256,
            format!("{:x}", Sha256::digest(&before))
        );
        assert_eq!(observed.root, observe(&File::open(&path).unwrap()).unwrap());
        assert_ne!(observed.evidence, observed.downloads);
        assert_eq!(
            fs::read(path.join("evidence").join(RECEIPT)).unwrap(),
            before
        );
    }
    #[test]
    fn altered_identity_flags_and_duplicate_fields_are_unusable() {
        for field in ["mount", "source", "authorization", "unknown", "duplicate"] {
            let (_parent, path, state) = fixture();
            let receipt = path.join("evidence").join(RECEIPT);
            let original = fs::read(&receipt).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            match field {
                "mount" => value["downloads"]["mount_id"] = 0.into(),
                "source" => value["source_sha"] = "c".repeat(40).into(),
                "authorization" => value["deletion_authorized"] = true.into(),
                "unknown" => value["extra"] = true.into(),
                "duplicate" => {}
                _ => unreachable!(),
            }
            let bytes = if field == "duplicate" {
                String::from_utf8(original)
                    .unwrap()
                    .replacen('{', "{\"deletion_authorized\":false,", 1)
                    .into_bytes()
            } else {
                serde_json::to_vec(&value).unwrap()
            };
            fs::write(&receipt, &bytes).unwrap();
            assert!(
                matches!(inspect_state(&state, &path), InspectionOutcome::Unusable),
                "{field}"
            );
            assert_eq!(fs::read(&receipt).unwrap(), bytes);
        }
    }
    #[test]
    fn replaced_directory_or_receipt_link_is_unusable() {
        let (_parent, path, state) = fixture();
        fs::rename(path.join("downloads"), path.join("saved-downloads")).unwrap();
        fs::create_dir(path.join("downloads")).unwrap();
        fs::set_permissions(path.join("downloads"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            inspect_state(&state, &path),
            InspectionOutcome::Unusable
        ));
        let (_parent, path, state) = fixture();
        let receipt = path.join("evidence").join(RECEIPT);
        let saved = path.join("saved-receipt");
        fs::rename(&receipt, &saved).unwrap();
        symlink(&saved, &receipt).unwrap();
        assert!(matches!(
            inspect_state(&state, &path),
            InspectionOutcome::Unusable
        ));
    }
    #[test]
    fn fifo_and_hardlinked_receipts_are_unusable_without_reading() {
        for fifo in [true, false] {
            let (_parent, path, state) = fixture();
            let receipt = path.join("evidence").join(RECEIPT);
            if fifo {
                fs::remove_file(&receipt).unwrap();
                let name = CString::new(receipt.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            } else {
                fs::hard_link(&receipt, path.join("linked-receipt")).unwrap();
            }
            assert!(matches!(
                inspect_state(&state, &path),
                InspectionOutcome::Unusable
            ));
        }
    }
    #[test]
    fn missing_receipt_stays_missing() {
        let (_parent, path, state) = fixture();
        let receipt = path.join("evidence").join(RECEIPT);
        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            inspect_state(&state, &path),
            InspectionOutcome::Missing
        ));
        assert!(!receipt.exists());
    }
    fn credential_fixture() -> (tempfile::TempDir, PathBuf, InstallerState) {
        use crate::installer_state::{Phase, PASSWORD_POLICY};
        let (parent, path, mut state) = fixture();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy":PASSWORD_POLICY}))
            .unwrap();
        state.persist_credential_creation_receipt(&path).unwrap();
        (parent, path, state)
    }
    fn inspect_credential_state(
        state: &InstallerState,
        path: &Path,
    ) -> CredentialInspectionOutcome {
        state
            .with_inspection(|locked| Ok(inspect_credentials(locked, path)))
            .unwrap()
    }
    #[test]
    fn credential_receipt_matches_metadata_without_changing_secret_bytes() {
        let (_parent, path, state) = credential_fixture();
        let password = fs::read(path.join("operator-password")).unwrap();
        let receipt = fs::read(path.join("evidence").join(CREDENTIAL_RECEIPT)).unwrap();
        let CredentialInspectionOutcome::MatchedLocalReceipt(observed) =
            inspect_credential_state(&state, &path)
        else {
            panic!("expected local credential evidence")
        };
        assert_eq!(
            observed.secrets,
            observe(&File::open(path.join("secrets")).unwrap()).unwrap()
        );
        assert_eq!(observed.operator_password.identity.kind, Kind::File);
        assert_eq!(
            observed.initial.root.mount_id,
            observed.operator_password.mount_id
        );
        assert_eq!(
            observed.receipt_sha256,
            format!("{:x}", Sha256::digest(&receipt))
        );
        assert_eq!(fs::read(path.join("operator-password")).unwrap(), password);
        assert_eq!(
            fs::read(path.join("evidence").join(CREDENTIAL_RECEIPT)).unwrap(),
            receipt
        );
    }
    #[test]
    fn changed_credential_path_or_fifo_receipt_is_unusable() {
        let (_parent, path, state) = credential_fixture();
        fs::rename(path.join("secrets"), path.join("saved-secrets")).unwrap();
        fs::create_dir(path.join("secrets")).unwrap();
        fs::set_permissions(path.join("secrets"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
        let (_parent, path, state) = credential_fixture();
        let receipt = path.join("evidence").join(CREDENTIAL_RECEIPT);
        fs::remove_file(&receipt).unwrap();
        let name = CString::new(receipt.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
        let (_parent, path, state) = credential_fixture();
        let password = path.join("operator-password");
        fs::remove_file(&password).unwrap();
        let name = CString::new(password.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
    }
    #[test]
    fn missing_or_tampered_credential_evidence_never_adopts_paths() {
        let (_parent, path, state) = credential_fixture();
        let receipt = path.join("evidence").join(CREDENTIAL_RECEIPT);
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
        data["deletion_authorized"] = true.into();
        let bytes = serde_json::to_vec(&data).unwrap();
        fs::write(&receipt, &bytes).unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
        assert_eq!(fs::read(&receipt).unwrap(), bytes);
        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Missing
        ));
        assert!(!receipt.exists());
    }
    fn application_fixture() -> (tempfile::TempDir, PathBuf, InstallerState) {
        let (parent, path, mut state) = credential_fixture();
        state.prepare_application_storage().unwrap();
        state
            .persist_application_storage_creation_receipt(&path)
            .unwrap();
        (parent, path, state)
    }
    fn inspect_application_state(
        state: &InstallerState,
        path: &Path,
    ) -> ApplicationInspectionOutcome {
        state
            .with_inspection(|locked| Ok(inspect_application(locked, path)))
            .unwrap()
    }
    #[test]
    fn application_receipt_matches_four_roots_without_reading_descendants() {
        let (_parent, path, state) = application_fixture();
        fs::write(
            path.join("backups/private-child-canary"),
            b"private-content-canary",
        )
        .unwrap();
        let before = fs::read(path.join("evidence").join(APPLICATION_RECEIPT)).unwrap();
        let ApplicationInspectionOutcome::MatchedLocalReceipt(observed) =
            inspect_application_state(&state, &path)
        else {
            panic!("expected local application evidence")
        };
        assert_eq!(observed.roots.len(), 4);
        assert_eq!(
            observed.receipt_sha256,
            format!("{:x}", Sha256::digest(&before))
        );
        for (name, identity) in &observed.roots {
            assert_eq!(
                *identity,
                observe(&File::open(path.join(name)).unwrap()).unwrap()
            );
            assert_eq!(
                identity.mount_id,
                observed.credentials.initial.root.mount_id
            );
        }
        assert_eq!(
            fs::read(path.join("backups/private-child-canary")).unwrap(),
            b"private-content-canary"
        );
        assert_eq!(
            fs::read(path.join("evidence").join(APPLICATION_RECEIPT)).unwrap(),
            before
        );
    }
    #[test]
    fn application_receipt_refuses_changed_roots_and_changed_prior_evidence() {
        let (_parent, path, state) = application_fixture();
        fs::rename(path.join("backups"), path.join("saved-backups")).unwrap();
        fs::create_dir(path.join("backups")).unwrap();
        fs::set_permissions(path.join("backups"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            inspect_application_state(&state, &path),
            ApplicationInspectionOutcome::Unusable
        ));
        let (_parent, path, state) = application_fixture();
        fs::write(
            path.join("evidence").join(CREDENTIAL_RECEIPT),
            b"private-invalid-canary",
        )
        .unwrap();
        assert!(matches!(
            inspect_application_state(&state, &path),
            ApplicationInspectionOutcome::Unusable
        ));
    }
    #[test]
    fn application_missing_and_fifo_receipts_do_not_grant_scope() {
        let (_parent, path, state) = application_fixture();
        let receipt = path.join("evidence").join(APPLICATION_RECEIPT);
        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            inspect_application_state(&state, &path),
            ApplicationInspectionOutcome::Missing
        ));
        let name = CString::new(receipt.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            inspect_application_state(&state, &path),
            ApplicationInspectionOutcome::Unusable
        ));
    }
}
