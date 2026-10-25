//! Linux installation journal. No provisioning or resource deletion occurs here.
//! Hold this object across all mutations. Enter Provisioning durably BEFORE any
//! non-idempotent operation; a crashed provisioning attempt requires reconciliation.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

pub type Result<T> = std::result::Result<T, String>;
const LIMIT: u64 = 65536;
const JOURNAL: &str = "installation.json";
const SCHEMA: &str = "elevenid.installer-state/v1";
pub const PASSWORD_POLICY: &str =
    "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)";
pub const SCALAR_SECRETS: [&str; 17] = [
    "device_registration_gateway_key",
    "device_registration_signing_keys_key",
    "flow_application_event_hmac_key",
    "flow_webhook_secret",
    "grpc_service_token",
    "issuance_api_key",
    "keycloak_admin_password",
    "keycloak_db_password",
    "marty_api_client_secret",
    "marty_db_password",
    "notification_applicant_event_token",
    "notification_webhook_secret",
    "postgres_password",
    "signing_keys_integration_secret_key",
    "signing_keys_issuer_sign_key",
    "signing_keys_service_sign_gateway_key",
    "token_hmac_key",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub source_sha: String,
    pub release_tag: String,
    pub inventory_sha256: String,
}
impl Identity {
    fn validate(&self) -> Result<()> {
        let valid =
            |value: &str, pattern: &str| regex::Regex::new(pattern).unwrap().is_match(value);
        if !valid(&self.source_sha, r"\A[0-9a-f]{40}\z")
            || !valid(&self.inventory_sha256, r"\Asha256:[0-9a-f]{64}\z")
            || !valid(
                &self.release_tag,
                r"\Av[0-9]+\.[0-9]+\.[0-9]+(?:-nightly\.20[0-9]{6}\.[1-9][0-9]*)?\z",
            )
        {
            return Err("invalid installation identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Initialized,
    Verified,
    Provisioning,
    Provisioned,
    Ready,
}

/// Immutable local daemon/port selection, committed before any Docker mutation.
/// The runtime must re-observe this engine ID before every mutation. This is
/// intent, not evidence that containers or networks exist or are owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub docker_host: String,
    pub engine_id: String,
    pub openbao_port: u16,
}
impl RuntimeBinding {
    pub fn validate(&self) -> Result<()> {
        let socket = self
            .docker_host
            .strip_prefix("unix://")
            .ok_or("installer requires a local Unix Docker socket")?;
        if !socket.starts_with('/')
            || socket == "/"
            || socket.len() > 4096
            || socket
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || socket
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !regex::Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9:-]{7,127}\z")
                .unwrap()
                .is_match(&self.engine_id)
            || self.openbao_port < 1024
        {
            return Err("invalid local installer runtime binding".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    schema: String,
    installation_id: uuid::Uuid,
    identity: Identity,
    phase: Phase,
    revision: u64,
    #[serde(default)]
    runtime: Option<RuntimeBinding>,
}
impl Journal {
    pub fn installation_id(&self) -> uuid::Uuid {
        self.installation_id
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn runtime(&self) -> Option<&RuntimeBinding> {
        self.runtime.as_ref()
    }
    pub fn compose_project(&self) -> String {
        format!("marty-install-{}", self.installation_id.simple())
    }
    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        if let Some(runtime) = &self.runtime {
            runtime.validate()?;
        }
        let revision = match self.phase {
            Phase::Initialized => 0,
            Phase::Verified => 1,
            Phase::Provisioning => 2,
            Phase::Provisioned => 3,
            Phase::Ready => 4,
        };
        if self.schema != SCHEMA
            || self.installation_id.get_version_num() != 4
            || self.installation_id.get_variant() != uuid::Variant::RFC4122
            || self.revision != revision
        {
            return Err("unsupported or inconsistent installation journal".into());
        }
        Ok(())
    }
}

fn error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}
fn name(value: &str) -> CString {
    CString::new(value).expect("internal file name")
}
fn open_at(parent: &File, entry: &CString, flags: i32, mode: u32) -> Result<File> {
    // SAFETY: valid owned directory descriptor and NUL-terminated name; returned
    // descriptor is exclusively transferred into File.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(error("open installation path"))
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if m.uid() != uid
        || (m.mode() & 0o7777) != if directory { 0o700 } else { 0o600 }
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
    {
        return Err("installation state is not private, owned, ordinary data".into());
    }
    Ok(())
}
fn parent(path: &Path) -> Result<(File, CString)> {
    if !path.is_absolute() {
        return Err("installation path must be absolute".into());
    }
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err("invalid installation path".into());
    }
    let mut names = Vec::new();
    for part in parts {
        match part {
            Component::Normal(value) => {
                names.push(CString::new(value.as_bytes()).map_err(|_| "invalid path")?)
            }
            _ => return Err("installation path must not contain traversal".into()),
        }
    }
    let leaf = names.pop().ok_or("cannot install at filesystem root")?;
    let mut directory = File::open("/").map_err(|e| e.to_string())?;
    for part in names {
        directory = open_at(&directory, &part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let m = directory.metadata().map_err(|e| e.to_string())?;
        let uid = unsafe { libc::geteuid() };
        // Root-owned sticky directories (e.g. /tmp) are safe to traverse using
        // descriptors; the exclusively created child is still private.
        if (m.uid() != uid && m.uid() != 0)
            || ((m.mode() & 0o022) != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err("installation ancestor is writable by another owner".into());
        }
    }
    Ok((directory, leaf))
}
fn lock(directory: &File) -> Result<()> {
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(error("installation is locked"));
    }
    Ok(())
}
fn read(directory: &File) -> Result<Journal> {
    let file = open_at(
        directory,
        &name(JOURNAL),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    private(&file, false)?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("installation journal exceeds limit".into());
    }
    // Typed serde rejects duplicate struct fields as well as unknown fields.
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    journal.validate()?;
    Ok(journal)
}

pub struct InstallerState {
    directory: File,
    journal: Journal,
    poisoned: bool,
}
impl InstallerState {
    /// Preserve the caller's authenticated release operator for recovery after
    /// bootstrap cleanup. The caller supplies current_exe and the signed digest.
    /// Partial copies remain non-executable and are never silently overwritten.
    /// A failure after publication may leave an authenticated executable; the
    /// poisoned transaction requires reconciliation rather than another copy.
    pub fn persist_operator(&mut self, source: &Path, expected_sha256: &str) -> Result<()> {
        self.require_live_phase(Phase::Initialized)?;
        if !regex::Regex::new(r"\A[0-9a-f]{64}\z")
            .unwrap()
            .is_match(expected_sha256)
        {
            return Err("invalid operator digest".into());
        }
        self.poisoned = true;
        let (source_parent, leaf) = parent(source)?;
        private(&source_parent, true)?;
        let mut input = open_at(&source_parent, &leaf, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let metadata = input
            .metadata()
            .map_err(|_| "operator metadata unavailable")?;
        const MAX: u64 = 512 * 1024 * 1024;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
            || metadata.len() == 0
            || metadata.len() > MAX
        {
            return Err("operator source must be owned ordinary executable data".into());
        }
        let partial = name("marty-deploy.partial");
        let target = name("marty-deploy");
        let mut output = open_at(
            &self.directory,
            &partial,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&output, false)?;
        self.directory
            .sync_all()
            .map_err(|_| "persist operator partial name")?;
        let mut digest = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = input
                .read(&mut buffer)
                .map_err(|_| "read operator source")?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > MAX {
                return Err("operator exceeds size limit".into());
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| "write operator partial")?;
            digest.update(&buffer[..count]);
        }
        output.sync_all().map_err(|_| "persist operator bytes")?;
        if copied != metadata.len() || format!("{:x}", digest.finalize()) != expected_sha256 {
            return Err("operator digest or size differs".into());
        }
        // Publish authenticated bytes while still non-executable. A crash before
        // chmod leaves a safe, non-executable final file requiring reconciliation.
        // NOREPLACE also rejects existing links and leaves partial mode 0600.
        if unsafe {
            libc::renameat2(
                self.directory.as_raw_fd(),
                partial.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(error("publish operator without replacement"));
        }
        self.directory
            .sync_all()
            .map_err(|_| "persist published operator name")?;
        if unsafe { libc::fchmod(output.as_raw_fd(), 0o700) } != 0 {
            return Err(error("make authenticated operator executable"));
        }
        output
            .sync_all()
            .map_err(|_| "persist operator permissions")?;
        self.directory
            .sync_all()
            .map_err(|_| "persist published operator name")?;
        self.poisoned = false;
        Ok(())
    }
    pub fn require_live_phase(&self, phase: Phase) -> Result<()> {
        if self.poisoned || self.journal.phase != phase || read(&self.directory)? != self.journal {
            return Err("installer transaction is not live at the required phase".into());
        }
        Ok(())
    }
    /// Create one owned runtime/staging directory without adopting existing data.
    pub fn create_private_directory(&mut self, entry: &str) -> Result<()> {
        if self.poisoned
            || !["downloads", "evidence", "openbao-state", "keycloak-output"].contains(&entry)
        {
            return Err("invalid or uncertain installer directory operation".into());
        }
        self.poisoned = true;
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name(entry).as_ptr(), 0o700) } != 0 {
            return Err(error("create installer subdirectory"));
        }
        let child = open_at(
            &self.directory,
            &name(entry),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&child, true)?;
        child
            .sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| "persist installer subdirectory")?;
        self.poisoned = false;
        Ok(())
    }
    /// Preserve exact authenticated records/receipts before remote side effects.
    /// Partial writes stay private and poison this transaction; never overwrite.
    pub fn write_evidence(&mut self, entry: &str, bytes: &[u8]) -> Result<()> {
        if self.poisoned
            || bytes.is_empty()
            || bytes.len() > 4 * 1024 * 1024
            || !regex::Regex::new(r"\A[a-z0-9][a-z0-9._-]{0,127}\z")
                .unwrap()
                .is_match(entry)
        {
            return Err("invalid or uncertain installer evidence operation".into());
        }
        let directory = open_at(
            &self.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&directory, true)?;
        self.poisoned = true;
        let mut file = open_at(
            &directory,
            &name(entry),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&file, false)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| "persist installer evidence")?;
        self.poisoned = false;
        Ok(())
    }
    /// Atomic journal snapshot for status/doctor, including uncertain phases.
    /// This proves stored state only, not running containers or live readiness.
    pub fn inspect(path: &Path) -> Result<Journal> {
        let (parent, leaf) = parent(path)?;
        let directory = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        read(&directory)
    }

    /// Generate local disposable scalars using the existing self-host contract.
    /// Remote keys/tokens and workload certificates are provisioned separately.
    /// Call only after the durable Provisioning transition. Partial output is
    /// preserved and poisons the transaction; it is never silently regenerated.
    pub fn generate_local_credentials(&mut self, realm: &serde_json::Value) -> Result<()> {
        if self.poisoned || self.journal.phase != Phase::Provisioning {
            return Err("credential generation requires a live provisioning transaction".into());
        }
        if realm
            .get("passwordPolicy")
            .and_then(serde_json::Value::as_str)
            != Some(PASSWORD_POLICY)
        {
            return Err("shipped operator password policy needs review".into());
        }
        self.poisoned = true;
        private(&self.directory, true)?;
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name("secrets").as_ptr(), 0o700) }
            != 0
        {
            return Err(error("create new secret directory"));
        }
        let secrets = open_at(
            &self.directory,
            &name("secrets"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&secrets, true)?;
        self.directory
            .sync_all()
            .map_err(|_| "sync secret directory")?;
        let mut random = File::open("/dev/urandom").map_err(|_| "OS randomness unavailable")?;
        let mut seen = std::collections::BTreeSet::new();
        for entry in SCALAR_SECRETS.into_iter().chain(["operator-password"]) {
            let mut entropy = [0u8; 32];
            random
                .read_exact(&mut entropy)
                .map_err(|_| "OS randomness unavailable")?;
            let hex: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
            if !seen.insert(hex.clone()) {
                return Err("OS randomness repeated a credential".into());
            }
            let operator = entry == "operator-password";
            let value = if operator {
                format!("Aa1!{hex}\n")
            } else {
                hex
            };
            let directory = if operator { &self.directory } else { &secrets };
            let mut output = open_at(
                directory,
                &name(entry),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            private(&output, false)?;
            output
                .write_all(value.as_bytes())
                .map_err(|_| "write credential")?;
            // Private parent is 0700; different container UIDs need read access
            // to the explicitly bind-mounted scalar files, matching old helper.
            if !operator && unsafe { libc::fchmod(output.as_raw_fd(), 0o444) } != 0 {
                return Err(error("set container-readable credential mode"));
            }
            output.sync_all().map_err(|_| "sync credential")?;
        }
        secrets.sync_all().map_err(|_| "sync credentials")?;
        self.directory
            .sync_all()
            .map_err(|_| "sync operator credential")?;
        self.poisoned = false;
        Ok(())
    }

    /// Creates a NEW directory only. Existing empty directories are not adopted.
    /// Failure may leave a private directory requiring explicit inspection.
    pub fn create(path: &Path, identity: Identity) -> Result<Self> {
        Self::create_internal(path, identity, None)
    }
    pub fn create_with_runtime(
        path: &Path,
        identity: Identity,
        runtime: RuntimeBinding,
    ) -> Result<Self> {
        runtime.validate()?;
        Self::create_internal(path, identity, Some(runtime))
    }
    fn create_internal(
        path: &Path,
        identity: Identity,
        runtime: Option<RuntimeBinding>,
    ) -> Result<Self> {
        identity.validate()?;
        let (parent, leaf) = parent(path)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            return Err(error("create new installation directory"));
        }
        let directory = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        lock(&directory)?;
        parent.sync_all().map_err(|e| e.to_string())?;
        let journal = Journal {
            schema: SCHEMA.into(),
            installation_id: uuid::Uuid::new_v4(),
            identity,
            phase: Phase::Initialized,
            revision: 0,
            runtime,
        };
        let mut state = Self {
            directory,
            journal: journal.clone(),
            poisoned: false,
        };
        state.persist(&journal)?;
        Ok(state)
    }
    /// Only resumes an exact known candidate. Provisioning in progress is never
    /// automatically replayed: callers need a separate reviewed reconciliation.
    pub fn resume(path: &Path, identity: &Identity) -> Result<Self> {
        identity.validate()?;
        let (parent, leaf) = parent(path)?;
        let directory = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        lock(&directory)?;
        let journal = read(&directory)?;
        if &journal.identity != identity {
            return Err("installation candidate differs".into());
        }
        if journal.phase == Phase::Provisioning {
            return Err("provisioning outcome is indeterminate; reconciliation required".into());
        }
        Ok(Self {
            directory,
            journal,
            poisoned: false,
        })
    }
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
    pub fn advance(&mut self, next: Phase) -> Result<()> {
        if self.poisoned {
            return Err("journal write outcome uncertain; reopen for inspection".into());
        }
        if read(&self.directory)? != self.journal {
            return Err("installation journal changed unexpectedly".into());
        }
        if !matches!(
            (self.journal.phase, next),
            (Phase::Initialized, Phase::Verified)
                | (Phase::Verified, Phase::Provisioning)
                | (Phase::Provisioning, Phase::Provisioned)
                | (Phase::Provisioned, Phase::Ready)
        ) {
            return Err("invalid installation phase transition".into());
        }
        let mut journal = self.journal.clone();
        journal.phase = next;
        journal.revision += 1;
        self.persist(&journal)?;
        self.journal = journal;
        Ok(())
    }
    fn persist(&mut self, journal: &Journal) -> Result<()> {
        // Once writing starts, any error may represent an uncertain disk outcome.
        self.poisoned = true;
        private(&self.directory, true)?;
        let temporary = name(&format!(".journal-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = open_at(
            &self.directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&file, false)?;
        let bytes = serde_json::to_vec(journal).map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                name(JOURNAL).as_ptr(),
            )
        } != 0
        {
            return Err(error("commit installation journal"));
        }
        self.directory.sync_all().map_err(|e| e.to_string())?;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn identity() -> Identity {
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        }
    }
    fn operator_fixture(root: &Path) -> std::path::PathBuf {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source-operator");
        std::fs::write(&source, b"authenticated release operator").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        source
    }
    fn operator_digest() -> String {
        format!("{:x}", Sha256::digest(b"authenticated release operator"))
    }
    #[test]
    fn operator_copy_persists_authenticated_bytes_and_private_executable_mode() {
        let root = tempfile::tempdir().unwrap();
        let source = operator_fixture(root.path());
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.persist_operator(&source, &operator_digest()).unwrap();
        state.require_live_phase(Phase::Initialized).unwrap();
        drop(state);
        let file = path.join("marty-deploy");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"authenticated release operator"
        );
        let metadata = std::fs::metadata(&file).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.nlink(), 1);
        assert!(!path.join("marty-deploy.partial").exists());
        assert_eq!(
            InstallerState::inspect(&path).unwrap().phase(),
            Phase::Initialized
        );
    }
    #[test]
    fn wrong_operator_hash_keeps_nonexecutable_partial_and_poisons_transaction() {
        let root = tempfile::tempdir().unwrap();
        let source = operator_fixture(root.path());
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        assert!(state.persist_operator(&source, &"0".repeat(64)).is_err());
        assert!(!path.join("marty-deploy").exists());
        assert_eq!(
            std::fs::metadata(path.join("marty-deploy.partial"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(state.require_live_phase(Phase::Initialized).is_err());
        assert!(state.persist_operator(&source, &operator_digest()).is_err());
    }
    #[test]
    fn operator_publication_never_replaces_files_or_links() {
        for linked in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = operator_fixture(root.path());
            let path = root.path().join("install");
            let mut state = InstallerState::create(&path, identity()).unwrap();
            let destination = path.join("marty-deploy");
            if linked {
                symlink(&source, &destination).unwrap();
            } else {
                std::fs::write(&destination, b"existing").unwrap();
            }
            assert!(state.persist_operator(&source, &operator_digest()).is_err());
            assert_eq!(
                std::fs::metadata(path.join("marty-deploy.partial"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o600
            );
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                if linked {
                    b"authenticated release operator".as_slice()
                } else {
                    b"existing".as_slice()
                }
            );
            assert!(state.require_live_phase(Phase::Initialized).is_err());
        }
    }
    #[test]
    fn operator_copy_refuses_linked_sources_and_existing_partial() {
        for variant in [
            "symlink",
            "hardlink",
            "partial",
            "mode",
            "oversized",
            "phase",
        ] {
            let root = tempfile::tempdir().unwrap();
            let source = operator_fixture(root.path());
            let path = root.path().join("install");
            let mut state = InstallerState::create(&path, identity()).unwrap();
            let mut input = source.clone();
            match variant {
                "symlink" => {
                    input = root.path().join("linked");
                    symlink(&source, &input).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&source, root.path().join("linked")).unwrap();
                }
                "partial" => {
                    std::fs::write(path.join("marty-deploy.partial"), b"preserve").unwrap();
                }
                "mode" => {
                    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                "oversized" => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&source)
                        .unwrap()
                        .set_len(512 * 1024 * 1024 + 1)
                        .unwrap();
                }
                _ => {
                    state.advance(Phase::Verified).unwrap();
                }
            }
            assert!(
                state.persist_operator(&input, &operator_digest()).is_err(),
                "accepted {variant}"
            );
            assert!(!path.join("marty-deploy").exists());
            if variant == "partial" {
                assert_eq!(
                    std::fs::read(path.join("marty-deploy.partial")).unwrap(),
                    b"preserve"
                );
            }
        }
    }
    #[test]
    fn runtime_intent_survives_reopen_and_is_never_rebound() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let runtime = RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "01234567-89ab-cdef".into(),
            openbao_port: 18200,
        };
        let mut state =
            InstallerState::create_with_runtime(&path, identity(), runtime.clone()).unwrap();
        let project = state.journal().compose_project();
        assert!(project.starts_with("marty-install-"));
        assert_eq!(project.len(), 46);
        state.advance(Phase::Verified).unwrap();
        drop(state);
        let state = InstallerState::resume(&path, &identity()).unwrap();
        assert_eq!(state.journal().runtime(), Some(&runtime));
        assert_eq!(state.journal().compose_project(), project);
        assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
    }
    #[test]
    fn invalid_runtime_is_refused_before_directory_creation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        for host in [
            "tcp://localhost:2375",
            "unix:///",
            "unix:///run/../docker.sock",
            "unix:///run//docker.sock",
            "unix:///run/docker.sock\n",
        ] {
            let runtime = RuntimeBinding {
                docker_host: host.into(),
                engine_id: "engine-id".into(),
                openbao_port: 18200,
            };
            assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
            assert!(!path.exists());
        }
        for (engine, port) in [("", 18200), ("engine id", 18200), ("engine-id", 443)] {
            let runtime = RuntimeBinding {
                docker_host: "unix:///run/docker.sock".into(),
                engine_id: engine.into(),
                openbao_port: port,
            };
            assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
            assert!(!path.exists());
        }
    }
    #[test]
    fn evidence_is_private_durable_and_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        assert!(state.create_private_directory("../outside").is_err());
        state.create_private_directory("evidence").unwrap();
        assert!(state.write_evidence("../outside", b"bad").is_err());
        state.write_evidence("record.json", b"original").unwrap();
        let file = path.join("evidence/record.json");
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        assert!(state.write_evidence("record.json", b"replacement").is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"original");
        assert!(state.require_live_phase(Phase::Initialized).is_err());
        assert!(state.advance(Phase::Verified).is_err());
        drop(state);
        assert_eq!(InstallerState::inspect(&path).unwrap().revision(), 0);
    }
    #[test]
    fn corrupt_persisted_runtime_is_rejected_on_inspection_and_resume() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let state = InstallerState::create_with_runtime(
            &path,
            identity(),
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "engine-id".into(),
                openbao_port: 18200,
            },
        )
        .unwrap();
        drop(state);
        let journal_path = path.join(JOURNAL);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
        value["runtime"]["docker_host"] = serde_json::json!("tcp://other-host:2375");
        std::fs::write(&journal_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(InstallerState::inspect(&path).is_err());
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn survives_reopen_and_refuses_existing_or_concurrent_owner() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        let id = state.journal().installation_id();
        assert!(InstallerState::create(&path, identity()).is_err());
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert!(state.advance(Phase::Ready).is_err());
        state.advance(Phase::Verified).unwrap();
        drop(state);
        let state = InstallerState::resume(&path, &identity()).unwrap();
        assert_eq!(state.journal().installation_id(), id);
        assert_eq!(state.journal().phase(), Phase::Verified);
    }
    #[test]
    fn crash_during_provisioning_refuses_replay() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        drop(state);
        assert_eq!(
            InstallerState::inspect(&path).unwrap().phase(),
            Phase::Provisioning
        );
        assert!(InstallerState::resume(&path, &identity())
            .unwrap_err_string()
            .contains("indeterminate"));
    }
    #[test]
    fn generates_distinct_private_credentials_without_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        let realm = serde_json::json!({"passwordPolicy": PASSWORD_POLICY});
        assert!(state.generate_local_credentials(&realm).is_err());
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        assert!(state
            .generate_local_credentials(&serde_json::json!({}))
            .is_err());
        assert!(!path.join("secrets").exists());
        state.generate_local_credentials(&realm).unwrap();
        let mut values = std::collections::BTreeSet::new();
        for entry in SCALAR_SECRETS {
            let file = path.join("secrets").join(entry);
            let value = std::fs::read_to_string(&file).unwrap();
            assert!(regex::Regex::new(r"\A[0-9a-f]{64}\z")
                .unwrap()
                .is_match(&value));
            assert!(values.insert(value));
            assert_eq!(std::fs::metadata(file).unwrap().mode() & 0o777, 0o444);
        }
        assert_eq!(std::fs::read_dir(path.join("secrets")).unwrap().count(), 17);
        assert_eq!(
            std::fs::metadata(path.join("secrets")).unwrap().mode() & 0o777,
            0o700
        );
        let operator = path.join("operator-password");
        let password = std::fs::read(&operator).unwrap();
        assert!(password.starts_with(b"Aa1!"));
        assert_eq!(password.len(), 69);
        assert_eq!(std::fs::metadata(&operator).unwrap().mode() & 0o777, 0o600);
        assert!(state.generate_local_credentials(&realm).is_err());
        assert_eq!(std::fs::read(operator).unwrap(), password);
        assert!(state.advance(Phase::Provisioned).is_err());
    }
    #[test]
    fn completed_installation_preserves_identity_and_ready_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        for phase in [
            Phase::Verified,
            Phase::Provisioning,
            Phase::Provisioned,
            Phase::Ready,
        ] {
            state.advance(phase).unwrap();
        }
        drop(state);
        let mut other = identity();
        other.source_sha = "c".repeat(40);
        assert!(InstallerState::resume(&path, &other).is_err());
        assert_eq!(
            InstallerState::resume(&path, &identity())
                .unwrap()
                .journal()
                .revision(),
            4
        );
    }
    #[test]
    fn refuses_symlinks_public_modes_and_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        drop(InstallerState::create(&path, identity()).unwrap());
        let alias = root.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(InstallerState::resume(&alias, &identity()).is_err());
        assert!(InstallerState::create(&alias.join("child"), identity()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(path.join(JOURNAL), root.path().join("linked")).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn refuses_unknown_duplicate_and_inconsistent_journal_fields() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        drop(InstallerState::create(&path, identity()).unwrap());
        let original = std::fs::read_to_string(path.join(JOURNAL)).unwrap();
        for content in [
            original.replacen('{', "{\"extra\":1,", 1),
            original.replacen('{', "{\"schema\":\"duplicate\",", 1),
            original.replace("\"revision\":0", "\"revision\":4"),
        ] {
            std::fs::write(path.join(JOURNAL), content).unwrap();
            assert!(InstallerState::resume(&path, &identity()).is_err());
        }
    }
    // Avoid requiring Debug on a live lock-owning InstallerState merely for tests.
    trait ErrorString {
        fn unwrap_err_string(self) -> String;
    }
    impl ErrorString for Result<InstallerState> {
        fn unwrap_err_string(self) -> String {
            match self {
                Err(e) => e,
                Ok(_) => panic!("expected refusal"),
            }
        }
    }
}
