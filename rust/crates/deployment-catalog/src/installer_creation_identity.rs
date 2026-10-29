//! Local historical identity evidence captured from directories created by
//! this installer process. A private file is not cryptographic authentication
//! or deletion authority. Missing or interrupted evidence must fail closed.
#![cfg(target_os = "linux")]

use crate::installer_purge_host::{HostIdentity, Kind};
use serde::Serialize;
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

const REFUSED: &str = "installer creation identity could not be recorded";
pub(crate) const RECEIPT: &str = "installation-created-identity.json";
pub(crate) const CREDENTIAL_RECEIPT: &str = "credential-created-identity.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ObservedDirectory {
    pub identity: HostIdentity,
    pub mount_id: u64,
}

fn mount_id(file: &File) -> Result<u64, String> {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let proc = File::open("/proc/self/fdinfo").map_err(|_| REFUSED)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0
        || info.f_type as i64 != PROC_SUPER_MAGIC
    {
        return Err(REFUSED.into());
    }
    let name = CString::new(file.as_raw_fd().to_string()).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(REFUSED.into());
    }
    let mut bytes = Vec::new();
    unsafe { File::from_raw_fd(fd) }
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    if bytes.len() > 4096 {
        return Err(REFUSED.into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let raw = ids.next().ok_or(REFUSED)?.trim_ascii();
    if ids.next().is_some() || raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(REFUSED.into());
    }
    let id = raw.parse::<u64>().map_err(|_| REFUSED)?;
    if id == 0 {
        return Err(REFUSED.into());
    }
    Ok(id)
}

pub(crate) fn observe(file: &File) -> Result<ObservedDirectory, String> {
    let meta = file.metadata().map_err(|_| REFUSED)?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
        return Err(REFUSED.into());
    }
    let identity = HostIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
        kind: Kind::Directory,
    };
    Ok(ObservedDirectory {
        identity,
        mount_id: mount_id(file)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ObservedFile {
    pub identity: HostIdentity,
    pub mount_id: u64,
}

fn observe_operator(file: &File) -> Result<ObservedFile, String> {
    let meta = file.metadata().map_err(|_| REFUSED)?;
    if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.len() != 69 || meta.nlink() != 1 {
        return Err(REFUSED.into());
    }
    Ok(ObservedFile {
        identity: HostIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
            kind: Kind::File,
        },
        mount_id: mount_id(file)?,
    })
}

/// The in-memory creation chain is never restored from a journal or receipt.
/// Both entries must be captured from held descriptors after durable creation.
#[derive(Clone)]
pub(crate) struct NewCredentials {
    root: ObservedDirectory,
    evidence: Option<ObservedDirectory>,
    initial_receipt: Option<Vec<u8>>,
    secrets: Option<ObservedDirectory>,
    operator: Option<ObservedFile>,
}

impl NewCredentials {
    pub fn new(root: &File) -> Result<Self, String> {
        Ok(Self {
            root: observe(root)?,
            evidence: None,
            initial_receipt: None,
            secrets: None,
            operator: None,
        })
    }

    pub fn capture_evidence(&mut self, evidence: &File) -> Result<(), String> {
        if self.evidence.is_some() {
            return Err(REFUSED.into());
        }
        let observed = observe(evidence)?;
        if observed.mount_id != self.root.mount_id
            || observed.identity.dev != self.root.identity.dev
            || observed.identity.ino == self.root.identity.ino
        {
            return Err(REFUSED.into());
        }
        self.evidence = Some(observed);
        Ok(())
    }

    pub fn remember_initial_receipt(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        if self.evidence.is_none() || self.initial_receipt.is_some() || bytes.is_empty() {
            return Err(REFUSED.into());
        }
        self.initial_receipt = Some(bytes);
        Ok(())
    }

    pub fn initial_receipt(&self) -> Result<&[u8], String> {
        self.initial_receipt.as_deref().ok_or(REFUSED.into())
    }

    pub fn capture(&mut self, secrets: &File, operator: &File) -> Result<(), String> {
        if self.secrets.is_some() || self.operator.is_some() {
            return Err(REFUSED.into());
        }
        let secret_identity = observe(secrets)?;
        let operator_identity = observe_operator(operator)?;
        let recorded_evidence = self.evidence.as_ref().ok_or(REFUSED)?;
        if secret_identity.mount_id != self.root.mount_id
            || operator_identity.mount_id != self.root.mount_id
            || secret_identity.identity.dev != self.root.identity.dev
            || operator_identity.identity.dev != self.root.identity.dev
            || secret_identity.identity.ino == self.root.identity.ino
            || operator_identity.identity.ino == self.root.identity.ino
            || operator_identity.identity.ino == secret_identity.identity.ino
            || secret_identity.identity.ino == recorded_evidence.identity.ino
            || operator_identity.identity.ino == recorded_evidence.identity.ino
        {
            return Err(REFUSED.into());
        }
        self.secrets = Some(secret_identity);
        self.operator = Some(operator_identity);
        Ok(())
    }

    pub fn receipt_bytes(
        &self,
        installation_id: uuid::Uuid,
        source_sha: &str,
        root: &File,
        evidence: &File,
        secrets: &File,
        operator: &File,
    ) -> Result<Vec<u8>, String> {
        let recorded_evidence = self.evidence.as_ref().ok_or(REFUSED)?;
        self.initial_receipt()?;
        let recorded_secrets = self.secrets.as_ref().ok_or(REFUSED)?;
        let recorded_operator = self.operator.as_ref().ok_or(REFUSED)?;
        if observe(root)? != self.root
            || observe(evidence)? != *recorded_evidence
            || observe(secrets)? != *recorded_secrets
            || observe_operator(operator)? != *recorded_operator
            || source_sha.len() != 40
            || !source_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(REFUSED.into());
        }
        #[derive(Serialize)]
        struct Receipt<'a> {
            schema: &'static str,
            installation_id: uuid::Uuid,
            source_sha: &'a str,
            secrets: &'a ObservedDirectory,
            operator_password: &'a ObservedFile,
            local_historical_evidence: bool,
            deletion_authorized: bool,
        }
        serde_json::to_vec(&Receipt {
            schema: "elevenid.installer-created-credentials/v1",
            installation_id,
            source_sha,
            secrets: recorded_secrets,
            operator_password: recorded_operator,
            local_historical_evidence: true,
            deletion_authorized: false,
        })
        .map_err(|_| REFUSED.into())
    }
}

#[derive(Clone)]
pub(crate) struct NewInstallation {
    pub root: ObservedDirectory,
    pub evidence: Option<ObservedDirectory>,
    pub downloads: Option<ObservedDirectory>,
}
impl NewInstallation {
    pub fn new(root: &File) -> Result<Self, String> {
        Ok(Self {
            root: observe(root)?,
            evidence: None,
            downloads: None,
        })
    }
    pub fn capture(&mut self, name: &str, directory: &File) -> Result<(), String> {
        let current = observe(directory)?;
        if current.mount_id != self.root.mount_id
            || current.identity.dev != self.root.identity.dev
            || current.identity.ino == self.root.identity.ino
        {
            return Err(REFUSED.into());
        }
        match name {
            "evidence" if self.evidence.is_none() => self.evidence = Some(current),
            "downloads" if self.downloads.is_none() => self.downloads = Some(current),
            _ => return Err(REFUSED.into()),
        }
        Ok(())
    }
    pub fn receipt_bytes(
        &self,
        installation_id: uuid::Uuid,
        source_sha: &str,
        root: &File,
        evidence: &File,
        downloads: &File,
    ) -> Result<Vec<u8>, String> {
        let recorded_evidence = self.evidence.as_ref().ok_or(REFUSED)?;
        let recorded_downloads = self.downloads.as_ref().ok_or(REFUSED)?;
        if observe(root)? != self.root
            || observe(evidence)? != *recorded_evidence
            || observe(downloads)? != *recorded_downloads
            || recorded_evidence == recorded_downloads
            || source_sha.len() != 40
            || !source_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(REFUSED.into());
        }
        #[derive(Serialize)]
        struct Receipt<'a> {
            schema: &'static str,
            installation_id: uuid::Uuid,
            source_sha: &'a str,
            root: &'a ObservedDirectory,
            evidence: &'a ObservedDirectory,
            downloads: &'a ObservedDirectory,
            local_historical_evidence: bool,
            deletion_authorized: bool,
        }
        serde_json::to_vec(&Receipt {
            schema: "elevenid.installer-created-identity/v1",
            installation_id,
            source_sha,
            root: &self.root,
            evidence: recorded_evidence,
            downloads: recorded_downloads,
            local_historical_evidence: true,
            deletion_authorized: false,
        })
        .map_err(|_| REFUSED.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{
        Identity, InstallerState, Phase, RuntimeBinding, PASSWORD_POLICY,
    };
    use std::{
        fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        path::PathBuf,
    };

    fn identity() -> Identity {
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.1.263".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        }
    }
    fn fresh() -> (tempfile::TempDir, PathBuf, InstallerState) {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installation = parent.path().join("installation");
        let state = InstallerState::create_with_runtime(
            &installation,
            identity(),
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "synthetic-engine".into(),
                openbao_port: 8200,
            },
        )
        .unwrap();
        (parent, installation, state)
    }

    fn credential_setup() -> (tempfile::TempDir, PathBuf, InstallerState) {
        let (parent, installation, mut state) = fresh();
        state.create_private_directory("evidence").unwrap();
        state.create_private_directory("downloads").unwrap();
        state
            .persist_initial_creation_receipt(&installation)
            .unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
            .unwrap();
        (parent, installation, state)
    }

    #[test]
    fn fresh_credential_receipt_records_only_metadata_after_durable_creation() {
        let (_parent, installation, mut state) = credential_setup();
        state
            .persist_credential_creation_receipt(&installation)
            .unwrap();
        let path = installation.join("evidence").join(CREDENTIAL_RECEIPT);
        let bytes = fs::read(&path).unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            receipt["schema"],
            "elevenid.installer-created-credentials/v1"
        );
        assert_eq!(
            receipt["installation_id"],
            state.journal().installation_id().to_string()
        );
        assert_eq!(receipt["source_sha"], identity().source_sha);
        assert_eq!(receipt["deletion_authorized"], false);
        assert_eq!(receipt["local_historical_evidence"], true);
        assert_eq!(receipt.as_object().unwrap().len(), 7);
        let secret = observe(&File::open(installation.join("secrets")).unwrap()).unwrap();
        let operator_path = installation.join("operator-password");
        let operator = observe_operator(&File::open(&operator_path).unwrap()).unwrap();
        assert_eq!(receipt["secrets"]["identity"]["ino"], secret.identity.ino);
        assert_eq!(
            receipt["operator_password"]["identity"]["ino"],
            operator.identity.ino
        );
        assert_eq!(receipt["secrets"]["mount_id"], secret.mount_id);
        assert_eq!(receipt["operator_password"]["mount_id"], operator.mount_id);
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o600);
        let password = fs::read(operator_path).unwrap();
        assert!(!bytes
            .windows(password.len())
            .any(|window| window == password));
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
    }

    #[test]
    fn foreign_partial_credential_receipt_is_preserved_and_poisons_writer() {
        let (_parent, installation, mut state) = credential_setup();
        let path = installation.join("evidence").join(CREDENTIAL_RECEIPT);
        fs::write(&path, b"partial foreign data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"partial foreign data");
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn changed_initial_receipt_is_refused_before_credential_receipt() {
        let (_parent, installation, mut state) = credential_setup();
        fs::write(installation.join("evidence").join(RECEIPT), b"{} ").unwrap();
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
        assert!(!installation
            .join("evidence")
            .join(CREDENTIAL_RECEIPT)
            .exists());
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn substituted_operator_fifo_is_refused_without_read_open() {
        let (_parent, installation, mut state) = credential_setup();
        let operator = installation.join("operator-password");
        fs::rename(&operator, installation.join("saved-operator")).unwrap();
        let name = CString::new(operator.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
        assert!(!installation
            .join("evidence")
            .join(CREDENTIAL_RECEIPT)
            .exists());
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn replaced_operator_file_is_refused_before_credential_receipt() {
        let (_parent, installation, mut state) = credential_setup();
        fs::rename(
            installation.join("operator-password"),
            installation.join("saved-operator"),
        )
        .unwrap();
        fs::write(
            installation.join("operator-password"),
            b"Aa1!xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        )
        .unwrap();
        fs::set_permissions(
            installation.join("operator-password"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
        assert!(!installation
            .join("evidence")
            .join(CREDENTIAL_RECEIPT)
            .exists());
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn replaced_evidence_with_copied_initial_receipt_is_refused() {
        let (_parent, installation, mut state) = credential_setup();
        fs::rename(
            installation.join("evidence"),
            installation.join("saved-evidence"),
        )
        .unwrap();
        fs::create_dir(installation.join("evidence")).unwrap();
        fs::set_permissions(
            installation.join("evidence"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::copy(
            installation.join("saved-evidence").join(RECEIPT),
            installation.join("evidence").join(RECEIPT),
        )
        .unwrap();
        assert!(state
            .persist_credential_creation_receipt(&installation)
            .is_err());
        assert!(!installation
            .join("evidence")
            .join(CREDENTIAL_RECEIPT)
            .exists());
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn resumed_provisioning_cannot_synthesize_credential_creation() {
        let (_parent, installation, state) = credential_setup();
        drop(state);
        assert!(InstallerState::resume(&installation, &identity()).is_err());
        assert!(!installation
            .join("evidence")
            .join(CREDENTIAL_RECEIPT)
            .exists());
    }

    #[test]
    fn fresh_normal_install_records_exact_root_evidence_downloads_only() {
        let (_parent, installation, mut state) = fresh();
        let before_journal = fs::read(installation.join("installation.json")).unwrap();
        state.create_private_directory("evidence").unwrap();
        state.create_private_directory("downloads").unwrap();
        state
            .persist_initial_creation_receipt(&installation)
            .unwrap();
        let receipt_path = installation.join("evidence").join(RECEIPT);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["schema"], "elevenid.installer-created-identity/v1");
        assert_eq!(
            receipt["installation_id"],
            state.journal().installation_id().to_string()
        );
        assert_eq!(receipt["source_sha"], identity().source_sha);
        assert_eq!(receipt["deletion_authorized"], false);
        assert_eq!(receipt["local_historical_evidence"], true);
        let root = observe(&File::open(&installation).unwrap()).unwrap();
        let evidence = observe(&File::open(installation.join("evidence")).unwrap()).unwrap();
        let downloads = observe(&File::open(installation.join("downloads")).unwrap()).unwrap();
        assert_eq!(receipt["root"]["identity"]["ino"], root.identity.ino);
        assert_eq!(
            receipt["evidence"]["identity"]["ino"],
            evidence.identity.ino
        );
        assert_eq!(
            receipt["downloads"]["identity"]["ino"],
            downloads.identity.ino
        );
        assert_eq!(receipt["root"]["mount_id"], root.mount_id);
        assert_eq!(fs::metadata(&receipt_path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(
            fs::read(installation.join("installation.json")).unwrap(),
            before_journal
        );
        assert!(state
            .persist_initial_creation_receipt(&installation)
            .is_err());
    }

    #[test]
    fn foreign_or_interrupted_receipt_is_preserved_and_poisons_writer() {
        let (_parent, installation, mut state) = fresh();
        state.create_private_directory("evidence").unwrap();
        state.create_private_directory("downloads").unwrap();
        let receipt_path = installation.join("evidence").join(RECEIPT);
        fs::write(&receipt_path, b"partial foreign data").unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(state
            .persist_initial_creation_receipt(&installation)
            .is_err());
        assert_eq!(fs::read(&receipt_path).unwrap(), b"partial foreign data");
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }

    #[test]
    fn interrupted_creation_and_resume_cannot_synthesize_provenance() {
        let (_parent, installation, mut state) = fresh();
        state.create_private_directory("evidence").unwrap();
        assert!(state
            .persist_initial_creation_receipt(&installation)
            .is_err());
        assert!(!installation.join("evidence").join(RECEIPT).exists());
        drop(state);
        let mut resumed = InstallerState::resume(&installation, &identity()).unwrap();
        resumed.create_private_directory("downloads").unwrap();
        assert!(resumed
            .persist_initial_creation_receipt(&installation)
            .is_err());
        assert!(!installation.join("evidence").join(RECEIPT).exists());
    }

    #[test]
    fn replaced_downloads_is_refused_before_receipt_write() {
        let (_parent, installation, mut state) = fresh();
        state.create_private_directory("evidence").unwrap();
        state.create_private_directory("downloads").unwrap();
        fs::rename(
            installation.join("downloads"),
            installation.join("saved-downloads"),
        )
        .unwrap();
        fs::create_dir(installation.join("downloads")).unwrap();
        fs::set_permissions(
            installation.join("downloads"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(state
            .persist_initial_creation_receipt(&installation)
            .is_err());
        assert!(!installation.join("evidence").join(RECEIPT).exists());
        assert!(state.with_inspection(|_| Ok(())).is_err());
    }
}
