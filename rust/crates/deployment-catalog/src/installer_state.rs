//! Linux installation journal. No provisioning or resource deletion occurs here.
//! Hold this object across all mutations. Enter Provisioning durably BEFORE any
//! non-idempotent operation; a crashed provisioning attempt requires reconciliation.
#![cfg(target_os = "linux")]

use crate::installer_creation_identity::{
    ApplicationHandles, NewApplicationStorage, NewCredentials, NewInstallation, NewOpenBaoState,
    APPLICATION_RECEIPT, CREDENTIAL_RECEIPT, OPENBAO_OWNER_TRANSITION_RECEIPT,
    OPENBAO_STATE_RECEIPT, RECEIPT as CREATION_RECEIPT,
};
use crate::installer_openbao_owner_transition::{self, Evidence as OpenBaoOwnerEvidence};
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
    time::{Duration, Instant},
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
pub(crate) const LOCAL_AUTH_SCALAR_SECRETS: [&str; 3] = [
    "keycloak_admin_password",
    "keycloak_db_password",
    "marty_api_client_secret",
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    #[default]
    Rootful,
    Rootless,
}

impl RuntimeProfile {
    fn is_rootful(&self) -> bool {
        *self == Self::Rootful
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub docker_host: String,
    pub engine_id: String,
    pub openbao_port: u16,
    // Omitted for historical rootful journals, preserving their exact bytes.
    #[serde(default, skip_serializing_if = "RuntimeProfile::is_rootful")]
    pub profile: RuntimeProfile,
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
            || (self.profile == RuntimeProfile::Rootless
                && (unsafe { libc::geteuid() } == 0
                    || self.docker_host
                        != format!("unix:///run/user/{}/docker.sock", unsafe {
                            libc::geteuid()
                        })))
        {
            return Err("invalid local installer runtime binding".into());
        }
        Ok(())
    }
}

/// Local scope evidence, not cryptographic authorization or nonce consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScope {
    pub authorization_sha256: String,
    pub context_sha256: String,
    pub consumption_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_evidence_sha256: Option<std::collections::BTreeMap<String, String>>,
}
pub(crate) const ACCEPTANCE_AUTHENTICATED_EVIDENCE: [&str; 9] = [
    "installer-candidate-authorization.json",
    "installer-candidate-authorization.json.sigstore.json",
    "installer-candidate-authorization.json.provenance.jsonl",
    "installer-controller-consumption.json",
    "installer-controller-consumption.json.sigstore.json",
    "installer-controller-consumption.json.provenance.jsonl",
    "installer-inventory.json",
    "installer-inventory.json.sigstore.json",
    "installer-inventory.json.provenance.jsonl",
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTestScope {
    pub inventory_sha256: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
}
#[cfg(feature = "installer-development")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedDevelopmentScope {
    pub fixture: CandidateTestScope,
    pub artifact_sha256: String,
}
#[cfg(feature = "installer-development")]
impl UnsignedDevelopmentScope {
    fn validate(&self) -> Result<()> {
        self.fixture.validate()?;
        if !crate::installer_development_image::digest(&self.artifact_sha256, 64) {
            return Err("invalid unsigned development image scope".into());
        }
        Ok(())
    }
}
impl CandidateTestScope {
    fn validate(&self) -> Result<()> {
        if self.inventory_sha256.len() != 64
            || !self
                .inventory_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.build_run_id == 0
            || self.build_run_attempt == 0
        {
            return Err("invalid candidate test scope".into());
        }
        Ok(())
    }
}
impl AcceptanceScope {
    pub(crate) fn authenticated_evidence(
        &self,
    ) -> Result<&std::collections::BTreeMap<String, String>> {
        self.validate()?;
        self.authenticated_evidence_sha256
            .as_ref()
            .ok_or_else(|| "historical acceptance scope has no authenticated file binding".into())
    }

    fn validate(&self) -> Result<()> {
        for value in [
            &self.authorization_sha256,
            &self.context_sha256,
            &self.consumption_id,
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid acceptance execution scope".into());
            }
        }
        if let Some(evidence) = &self.authenticated_evidence_sha256 {
            if evidence.len() != ACCEPTANCE_AUTHENTICATED_EVIDENCE.len()
                || ACCEPTANCE_AUTHENTICATED_EVIDENCE
                    .iter()
                    .any(|name| !evidence.contains_key(*name))
                || evidence.values().any(|value| {
                    value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err("invalid authenticated acceptance evidence binding".into());
            }
        }
        Ok(())
    }
}

/// Historical journals carry no proven admission classification. Absence of
/// this field cannot establish that candidate evidence was never present.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutionScope {
    #[default]
    Unclassified,
    AcceptanceOnly(AcceptanceScope),
    CandidateTest(CandidateTestScope),
    #[cfg(feature = "installer-development")]
    UnsignedDevelopment(UnsignedDevelopmentScope),
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
    #[serde(default)]
    scope: ExecutionScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosting_selection_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosting_addon_sha256: Option<String>,
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
    pub fn execution_scope(&self) -> &ExecutionScope {
        &self.scope
    }
    pub fn hosting_selection_sha256(&self) -> Option<&str> {
        self.hosting_selection_sha256.as_deref()
    }
    pub fn hosting_addon_sha256(&self) -> Option<&str> {
        self.hosting_addon_sha256.as_deref()
    }
    pub fn compose_project(&self) -> String {
        format!("marty-install-{}", self.installation_id.simple())
    }
    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        if self.hosting_selection_sha256.as_ref().is_some_and(|value| {
            self.phase == Phase::Initialized
                || value.len() != 64
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) {
            return Err("invalid hosting selection binding".into());
        }
        if self.hosting_addon_sha256.as_ref().is_some_and(|value| {
            self.hosting_selection_sha256.is_none()
                || value.len() != 64
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) {
            return Err("invalid hosting add-on binding".into());
        }
        match &self.scope {
            ExecutionScope::AcceptanceOnly(scope) => scope.validate()?,
            ExecutionScope::CandidateTest(scope) => {
                scope.validate()?;
                if self.identity.inventory_sha256 != format!("sha256:{}", scope.inventory_sha256) {
                    return Err("candidate test inventory identity differs".into());
                }
            }
            #[cfg(feature = "installer-development")]
            ExecutionScope::UnsignedDevelopment(scope) => {
                scope.validate()?;
                if self.identity.inventory_sha256
                    != format!("sha256:{}", scope.fixture.inventory_sha256)
                    || self
                        .runtime
                        .as_ref()
                        .is_none_or(|runtime| runtime.profile != RuntimeProfile::Rootless)
                {
                    return Err("unsigned development fixture or runtime identity differs".into());
                }
            }
            ExecutionScope::Unclassified => {}
        }
        if !matches!(self.scope, ExecutionScope::Unclassified) && self.phase == Phase::Ready {
            return Err("test execution cannot claim installation Ready".into());
        }
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

/// Host ownership for the applicant directory. A nonroot installer shares its
/// nonzero effective host group; a root installer provisions image group 10001.
/// Container supplemental groups must use the runtime projection below.
pub fn applicant_state_gid() -> Result<u32> {
    let uid = unsafe { libc::geteuid() };
    let gid = if uid == 0 {
        10001
    } else {
        unsafe { libc::getegid() }
    };
    if gid == 0 {
        return Err("applicant state requires a nonroot group".into());
    }
    Ok(gid)
}

/// A validated namespace projection, not an arbitrary numeric group override.
/// Host ownership and the container's supplemental group are distinct values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicantContainerGroup {
    host_gid: u32,
    container_gid: u32,
}

impl ApplicantContainerGroup {
    pub fn host_gid(self) -> u32 {
        self.host_gid
    }

    pub fn container_gid(self) -> u32 {
        self.container_gid
    }
}

/// Project the reviewed host group into a previously observed local runtime.
/// Rootless qualification proves namespace group zero maps to the ordinary
/// installer group. The image retains its nonroot user and primary group;
/// supplemental group zero here is not host group zero. Rootful behavior keeps
/// the existing host group, including ordinary callers of a rootful daemon.
pub fn applicant_container_group(binding: &RuntimeBinding) -> Result<ApplicantContainerGroup> {
    binding.validate()?;
    let host_gid = applicant_state_gid()?;
    Ok(ApplicantContainerGroup {
        host_gid,
        container_gid: match binding.profile {
            RuntimeProfile::Rootful => host_gid,
            RuntimeProfile::Rootless => 0,
        },
    })
}

fn require_applicant_storage(directory: &File, gid: u32) -> Result<()> {
    let metadata = directory
        .metadata()
        .map_err(|_| "inspect applicant state ownership")?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o2770
        || !metadata.is_dir()
    {
        return Err("applicant state ownership differs from the reviewed contract".into());
    }
    Ok(())
}
/// Reopen a held, already policy-checked ordinary inode for reading. O_PATH
/// classification must precede any read-open: O_NONBLOCK alone does not avoid
/// device open side effects. Ownership/mode policy stays with each caller.
fn reopen_regular(held: &File) -> Result<File> {
    const REFUSED: &str = "installer record cannot be safely opened";
    let before = held.metadata().map_err(|_| REFUSED)?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(REFUSED.into());
    }
    let proc = File::open("/proc/self/fd").map_err(|_| REFUSED)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0 || info.f_type as i64 != 0x9fa0 {
        return Err(REFUSED.into());
    }
    let entry = name(&held.as_raw_fd().to_string());
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            entry.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(REFUSED.into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let after = file.metadata().map_err(|_| REFUSED)?;
    if !after.is_file()
        || after.nlink() != 1
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
    {
        return Err(REFUSED.into());
    }
    Ok(file)
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
/// flock belongs to the open file description, which a concurrent fork can
/// inherit until exec despite CLOEXEC. Explicit unlock ends this owner's
/// critical section even while an inherited descriptor remains open.
pub(crate) struct LockedDirectory {
    file: File,
    owner_pid: libc::pid_t,
    unlock_on_drop: bool,
}
impl std::ops::Deref for LockedDirectory {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
impl Drop for LockedDirectory {
    fn drop(&mut self) {
        // A forked child's destructor must not release its parent's live lock.
        if !self.unlock_on_drop || unsafe { libc::getpid() } != self.owner_pid {
            return;
        }
        loop {
            if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}
pub(crate) fn lock(directory: File) -> Result<LockedDirectory> {
    lock_with_wait(directory, None)?.ok_or_else(|| "installation lock unexpectedly deferred".into())
}

/// Only the scheduled lifecycle entry point opts into waiting. Keep the same
/// held directory and exclusive lock; neither contention nor EINTR permits a
/// journal read or an operation without acquiring it.
fn lock_with_wait(directory: File, wait: Option<Duration>) -> Result<Option<LockedDirectory>> {
    let started = Instant::now();
    let mut last_error: Option<std::io::Error> = None;
    loop {
        if let (Some(limit), Some(cause)) = (wait, last_error.as_ref()) {
            if started.elapsed() >= limit {
                return if cause.kind() == std::io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(format!("installation is locked: {cause}"))
                };
            }
        }
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(LockedDirectory {
                file: directory,
                owner_pid: unsafe { libc::getpid() },
                unlock_on_drop: true,
            }));
        }
        let cause = std::io::Error::last_os_error();
        let Some(limit) = wait else {
            return Err(format!("installation is locked: {cause}"));
        };
        if !matches!(
            cause.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(format!("installation is locked: {cause}"));
        }
        last_error = Some(cause);
        std::thread::sleep(
            limit
                .saturating_sub(started.elapsed())
                .min(Duration::from_millis(50)),
        );
    }
}
fn read(directory: &File) -> Result<Journal> {
    let file = open_at(directory, &name(JOURNAL), libc::O_PATH, 0)?;
    private(&file, false)?;
    let file = reopen_regular(&file)?;
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

/// Read-only recovery view. Holding this guard excludes an active installer or
/// another lifecycle operation, including while the journal is Provisioning.
/// It intentionally exposes no phase transition or provisioning replay API.
pub struct LockedInspection {
    directory: LockedDirectory,
    journal: Journal,
}

fn cleanup_open_optional(
    directory: &File,
    entry: &str,
    is_directory: bool,
) -> Result<Option<File>> {
    let flags = if is_directory {
        libc::O_RDONLY | libc::O_DIRECTORY
    } else {
        libc::O_PATH
    } | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name(entry).as_ptr(), flags) };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("cleanup evidence cannot be safely inspected".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private(&file, is_directory)?;
    Ok(Some(if is_directory {
        file
    } else {
        reopen_regular(&file)?
    }))
}
// Presence alone blocks provisioning replay. Old cleanup markers remain a
// refusal boundary, without preserving their obsolete service/resource catalog.
fn maintenance_started(directory: &File) -> Result<bool> {
    let Some(evidence) = cleanup_open_optional(directory, "evidence", true)? else {
        return Ok(false);
    };
    for entry in [
        "lifecycle-configuration.json",
        "acme-staging-000000.json",
        "acme-production-000000.json",
        "acme-custody-staging-intent.json",
        "acme-custody-production-intent.json",
        "acme-credentials-staging-intent.json",
        "acme-credentials-production-intent.json",
        "uninstall-plan.json",
        "uninstall-result.json",
        "uninstall-compose-stop-intent.json",
        "uninstall-compose-stop-result.json",
        "uninstall-compose-down-intent.json",
        "uninstall-compose-down-result.json",
        "uninstall-compose-start-0001-intent.json",
        "uninstall-compose-start-0001-result.json",
        "uninstall-compose-stop-0001-intent.json",
        "uninstall-compose-stop-0001-result.json",
        "uninstall-compose-down-0001-intent.json",
        "uninstall-compose-down-0001-result.json",
    ] {
        if cleanup_open_optional(&evidence, entry, false)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
impl LockedInspection {
    /// Append one bounded private diagnostic report; never replace lifecycle evidence.
    pub(crate) fn save_validation_report(&self, bytes: &[u8]) -> Result<String> {
        self.require_unchanged()?;
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err("invalid validation report size".into());
        }
        let evidence = open_at(
            &self.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&evidence, true)?;
        let entry = format!("validation-{}.json", uuid::Uuid::new_v4());
        let mut output = open_at(
            &evidence,
            &name(&entry),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&output, false)?;
        output
            .write_all(bytes)
            .and_then(|_| output.sync_all())
            .and_then(|_| evidence.sync_all())
            .map_err(|_| "cannot persist validation report")?;
        self.require_validation_report_binding(&evidence, &entry, &output, bytes)?;
        self.require_unchanged()?;
        Ok(entry)
    }
    fn require_validation_report_binding(
        &self,
        held: &File,
        entry: &str,
        output: &File,
        bytes: &[u8],
    ) -> Result<()> {
        let current = open_at(
            &self.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&current, true)?;
        let same = |a: &File, b: &File| -> Result<bool> {
            let a = a.metadata().map_err(|_| "validation record unavailable")?;
            let b = b.metadata().map_err(|_| "validation record unavailable")?;
            Ok(a.dev() == b.dev() && a.ino() == b.ino())
        };
        if !same(held, &current)? {
            return Err("validation evidence directory changed".into());
        }
        let file = open_at(&current, &name(entry), libc::O_PATH, 0)?;
        private(&file, false)?;
        if !same(output, &file)? {
            return Err("validation report replaced".into());
        }
        let file = reopen_regular(&file)?;
        let mut observed = Vec::new();
        file.take(65537)
            .read_to_end(&mut observed)
            .map_err(|_| "validation report unreadable")?;
        if observed != bytes {
            return Err("validation report changed".into());
        }
        Ok(())
    }
    /// Bind path-based read-only helpers to the installation held by this lock.
    pub(crate) fn require_path_binding(&self, path: &Path) -> Result<()> {
        self.require_unchanged()?;
        let (ancestor, leaf) = parent(path)?;
        let current = open_at(&ancestor, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&current, true)?;
        let held = self
            .directory
            .metadata()
            .map_err(|_| "held installation unavailable")?;
        let observed = current
            .metadata()
            .map_err(|_| "installation path unavailable")?;
        if held.dev() != observed.dev() || held.ino() != observed.ino() {
            return Err("installation path no longer names the locked directory".into());
        }
        Ok(())
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_lock_wait(path, None)?
            .ok_or_else(|| "installation lock unexpectedly deferred".into())
    }
    fn open_with_lock_wait(path: &Path, wait: Option<Duration>) -> Result<Option<Self>> {
        let (ancestor, leaf) = parent(path)?;
        let directory = open_at(&ancestor, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        let Some(directory) = lock_with_wait(directory, wait)? else {
            return Ok(None);
        };
        let journal = read(&directory)?;
        let inspection = Self { directory, journal };
        if wait.is_some() {
            // A caller may have waited while the installation path changed.
            // Rebind it to the held inode before permitting any scheduled work.
            inspection.require_path_binding(path)?;
        }
        Ok(Some(inspection))
    }
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
    /// The held descriptor keeps read-only inventory walks inside this installation.
    pub(crate) fn installation_directory(&self) -> &File {
        &self.directory
    }
    /// Read credentials for diagnostic filtering without following user paths.
    /// Root-created scoped outputs may be readable immutable files; private
    /// unreadable outputs are refused, never skipped or read via escalation.
    pub(crate) fn read_secret(&self, entry: &str) -> Result<Vec<u8>> {
        self.require_unchanged()?;
        if !regex::Regex::new(r"\A[a-z0-9][a-z0-9._-]{0,127}\z")
            .unwrap()
            .is_match(entry)
        {
            return Err("invalid diagnostic credential name".into());
        }
        let secrets = open_at(
            &self.directory,
            &name("secrets"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&secrets, true)?;
        let file = open_at(&secrets, &name(entry), libc::O_PATH, 0)?;
        let metadata = file
            .metadata()
            .map_err(|_| "diagnostic credential metadata unavailable")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || ![unsafe { libc::geteuid() }, 0].contains(&metadata.uid())
            || !([0o400, 0o444, 0o600].contains(&(metadata.mode() & 0o7777))
                || (entry == "openbao_tls_ca_cert" && metadata.mode() & 0o7777 == 0o644))
        {
            return Err("diagnostic credential must be ordinary protected data".into());
        }
        let bytes = self.read_credential_bytes(
            reopen_regular(&file)?,
            crate::installer_application_env::OPTIONAL_EMPTY_SECRETS.contains(&entry),
        )?;
        if entry == "openbao_tls_ca_cert" {
            use x509_cert::der::DecodePem;
            let pem = std::str::from_utf8(&bytes).map_err(|_| "invalid public CA certificate")?;
            if !regex::Regex::new(r"\A-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\z")
                .unwrap().is_match(pem)
                || x509_cert::Certificate::from_pem(&bytes).is_err() {
                return Err("invalid public CA certificate".into());
            }
        }
        Ok(bytes)
    }
    pub(crate) fn read_operator_password(&self) -> Result<Vec<u8>> {
        self.require_unchanged()?;
        let file = open_at(&self.directory, &name("operator-password"), libc::O_PATH, 0)?;
        private(&file, false)?;
        self.read_credential_bytes(reopen_regular(&file)?, false)
    }
    fn read_credential_bytes(&self, file: File, allow_empty: bool) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read diagnostic credential")?;
        if (!allow_empty && bytes.is_empty()) || bytes.len() as u64 > LIMIT {
            return Err("diagnostic credential exceeds bounds".into());
        }
        self.require_unchanged()?;
        Ok(bytes)
    }
    pub fn require_unchanged(&self) -> Result<()> {
        private(&self.directory, true)?;
        if read(&self.directory)? != self.journal {
            return Err("installation changed during recovery inspection".into());
        }
        Ok(())
    }
    /// Evidence is read relative to the held installation descriptor, with
    /// no-follow, ordinary-file, ownership, link-count and byte-limit checks.
    pub fn read_evidence(&self, entry: &str) -> Result<Vec<u8>> {
        self.require_unchanged()?;
        if !regex::Regex::new(r"\A[a-z0-9][a-z0-9._-]{0,127}\z")
            .unwrap()
            .is_match(entry)
        {
            return Err("invalid recovery evidence name".into());
        }
        let evidence = open_at(
            &self.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&evidence, true)?;
        let file = open_at(&evidence, &name(entry), libc::O_PATH, 0)?;
        private(&file, false)?;
        let file = reopen_regular(&file)?;
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read recovery evidence")?;
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err("recovery evidence exceeds bounds".into());
        }
        self.require_unchanged()?;
        Ok(bytes)
    }

    /// Read-only diagnostics distinguish an absent receipt from invalid evidence.
    /// Root records and evidence remain confined to the held installation FD.
    pub(crate) fn diagnostic_record(&self, entry: &str, evidence: bool) -> Result<Option<Vec<u8>>> {
        self.require_unchanged()?;
        let entry = LockedMaintenance::entry(entry)?;
        let directory = if evidence {
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name("evidence").as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    self.require_unchanged()?;
                    return Ok(None);
                }
                return Err("cannot inspect diagnostic evidence directory".into());
            }
            unsafe { File::from_raw_fd(fd) }
        } else {
            self.directory
                .try_clone()
                .map_err(|_| "cannot hold diagnostic directory")?
        };
        private(&directory, true)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                entry.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                self.require_unchanged()?;
                return Ok(None);
            }
            return Err("cannot read diagnostic record".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file, false)?;
        let file = reopen_regular(&file)?;
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read diagnostic record")?;
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err("diagnostic record exceeds bounds".into());
        }
        self.require_unchanged()?;
        Ok(Some(bytes))
    }
}

/// Exclusive maintenance access with append-only receipts. This deliberately has no
/// phase-advance or provisioning-resume API, including for uncertain journals.
pub(crate) struct LockedMaintenance {
    inspection: LockedInspection,
    poisoned: bool,
}
impl LockedMaintenance {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            inspection: LockedInspection::open(path)?,
            poisoned: false,
        })
    }
    pub(crate) fn open_waiting(path: &Path, wait: Duration) -> Result<Option<Self>> {
        Ok(
            LockedInspection::open_with_lock_wait(path, Some(wait))?.map(|inspection| Self {
                inspection,
                poisoned: false,
            }),
        )
    }
    pub(crate) fn journal(&self) -> &Journal {
        self.inspection.journal()
    }
    /// Share the held read-only installation descriptor with inventory checks
    /// without taking a second, conflicting lifecycle lock.
    pub(crate) fn inspection(&self) -> &LockedInspection {
        &self.inspection
    }
    pub(crate) fn require_unchanged(&self) -> Result<()> {
        if self.poisoned {
            return Err("uncertain maintenance receipt; reopen and reconcile".into());
        }
        self.inspection.require_unchanged()
    }
    /// The owning component performs one authenticated atomic publication.
    /// An error or panic after entering this boundary keeps the writer poisoned
    /// and its lock held, so an uncertain rename cannot be followed by another
    /// mutation in the same invocation. Reopening requires reconciliation.
    pub(crate) fn with_atomic_publication<T>(
        &mut self,
        operation: impl FnOnce(&LockedInspection) -> Result<T>,
    ) -> Result<T> {
        self.require_unchanged()?;
        self.poisoned = true;
        let result = operation(&self.inspection)?;
        self.inspection.require_unchanged()?;
        self.poisoned = false;
        Ok(result)
    }
    fn entry(entry: &str) -> Result<CString> {
        if !regex::Regex::new(r"\A[a-z0-9][a-z0-9._-]{0,127}\z")
            .unwrap()
            .is_match(entry)
        {
            return Err("invalid maintenance record name".into());
        }
        Ok(name(entry))
    }
    fn evidence(&self) -> Result<File> {
        let directory = open_at(
            &self.inspection.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&directory, true)?;
        Ok(directory)
    }
    fn read_optional(&self, directory: &File, entry: &str) -> Result<Option<Vec<u8>>> {
        self.require_unchanged()?;
        let entry = Self::entry(entry)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                entry.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let failure = std::io::Error::last_os_error();
            if failure.raw_os_error() == Some(libc::ENOENT) {
                self.require_unchanged()?;
                return Ok(None);
            }
            return Err("cannot inspect maintenance record".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file, false)?;
        let file = reopen_regular(&file)?;
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read maintenance record")?;
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err("maintenance record exceeds bounds".into());
        }
        self.require_unchanged()?;
        Ok(Some(bytes))
    }
    pub(crate) fn read_evidence(&self, entry: &str) -> Result<Option<Vec<u8>>> {
        self.read_optional(&self.evidence()?, entry)
    }
    pub(crate) fn write_evidence_exclusive(&mut self, entry: &str, bytes: &[u8]) -> Result<()> {
        self.require_unchanged()?;
        let filename = Self::entry(entry)?;
        if !(entry.starts_with("uninstall-")
            || entry.starts_with("lifecycle-")
            || entry.starts_with("acme-")
            || entry.starts_with("generation-")
            || entry.starts_with("health-")
            || entry.starts_with("openbao-tls-recovery-")
            || entry.starts_with("openbao-root-retirement-")
            || entry.starts_with("rootless-canary-")
            || entry.starts_with("kms-registration-"))
            || bytes.is_empty()
            || bytes.len() > 4 * 1024 * 1024
        {
            return Err("invalid maintenance evidence".into());
        }
        let directory = self.evidence()?;
        self.poisoned = true;
        let mut output = open_at(
            &directory,
            &filename,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&output, false)?;
        output
            .write_all(bytes)
            .and_then(|_| output.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| "cannot persist maintenance evidence")?;
        self.inspection.require_unchanged()?;
        self.poisoned = false;
        Ok(())
    }

    /// The health observer has one bounded checkpoint and one recoverable
    /// pending publication. This is deliberately not a generic evidence
    /// overwrite facility. The policy reader authenticates the checkpoint's
    /// installation, sequence and predecessor before calling this method.
    pub(crate) fn publish_health_checkpoint(
        &mut self,
        expected: Option<&[u8]>,
        bytes: &[u8],
    ) -> Result<()> {
        self.publish_health_checkpoint_observed(expected, bytes, || {})
    }

    fn require_held_evidence(&self, held: &File) -> Result<()> {
        self.inspection.require_unchanged()?;
        let current = open_at(
            &self.inspection.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&current, true)?;
        private(held, true)?;
        let current = current
            .metadata()
            .map_err(|_| "cannot observe evidence directory")?;
        let held = held
            .metadata()
            .map_err(|_| "cannot observe held evidence directory")?;
        if (
            current.dev(),
            current.ino(),
            current.uid(),
            current.gid(),
            current.mode(),
        ) != (held.dev(), held.ino(), held.uid(), held.gid(), held.mode())
        {
            return Err("evidence directory binding changed".into());
        }
        Ok(())
    }

    fn publish_health_checkpoint_observed(
        &mut self,
        expected: Option<&[u8]>,
        bytes: &[u8],
        mut publication_boundary: impl FnMut(),
    ) -> Result<()> {
        const CURRENT: &str = "health-checkpoint.json";
        const NEXT: &str = "health-checkpoint-next.json";
        if bytes.is_empty() || bytes.len() > 262144 {
            return Err("health checkpoint exceeds its bound".into());
        }
        let directory = self.evidence()?;
        if self.read_optional(&directory, CURRENT)?.as_deref() != expected {
            return Err("health checkpoint changed".into());
        }
        if let Some(pending) = self.read_optional(&directory, NEXT)? {
            if pending != bytes {
                return Err("pending health checkpoint requires reconciliation".into());
            }
        } else {
            self.write_evidence_exclusive(NEXT, bytes)?;
        }
        if self.read_optional(&directory, CURRENT)?.as_deref() != expected
            || self.read_optional(&directory, NEXT)?.as_deref() != Some(bytes)
        {
            return Err("health checkpoint publication changed".into());
        }
        publication_boundary();
        self.require_held_evidence(&directory)?;
        self.poisoned = true;
        let mode = if expected.is_none() {
            crate::installer_host_fs::RenameMode::NoReplace
        } else {
            crate::installer_host_fs::RenameMode::Replace
        };
        if crate::installer_host_fs::rename_at(
            &directory,
            &name(NEXT),
            &directory,
            &name(CURRENT),
            mode,
        )
        .is_err()
        {
            return Err("health checkpoint publication uncertain".into());
        }
        directory
            .sync_all()
            .map_err(|_| "health checkpoint durability uncertain")?;
        publication_boundary();
        self.require_held_evidence(&directory)?;
        self.inspection.require_unchanged()?;
        self.poisoned = false;
        if self.read_optional(&directory, CURRENT)?.as_deref() != Some(bytes) {
            self.poisoned = true;
            return Err("published health checkpoint changed".into());
        }
        Ok(())
    }
}

pub struct InstallerState {
    directory: LockedDirectory,
    journal: Journal,
    poisoned: bool,
    /// In-memory capture exists only for a newly created normal installation.
    /// Resumed and legacy installations can never reconstruct creation proof.
    creation: Option<NewInstallation>,
    /// Captured only while this fresh normal installer owns the creation chain.
    credential_creation: Option<NewCredentials>,
    /// Four application roots can be recorded only by their original writer.
    application_creation: Option<NewApplicationStorage>,
    /// The OpenBao state root must be captured at its exclusive creation.
    openbao_creation: Option<NewOpenBaoState>,
}
impl InstallerState {
    /// Borrow the writer's lock for diagnostics without reacquiring or unlocking it.
    /// The temporary duplicate is CLOEXEC and never owns explicit LOCK_UN.
    pub(crate) fn with_inspection<T>(
        &self,
        operation: impl FnOnce(&LockedInspection) -> Result<T>,
    ) -> Result<T> {
        if self.poisoned || read(&self.directory)? != self.journal {
            return Err("uncertain installation cannot be inspected".into());
        }
        let view = LockedInspection {
            directory: LockedDirectory {
                file: self
                    .directory
                    .file
                    .try_clone()
                    .map_err(|_| "cannot borrow installation lock")?,
                owner_pid: self.directory.owner_pid,
                unlock_on_drop: false,
            },
            journal: self.journal.clone(),
        };
        let result = operation(&view);
        view.require_unchanged()?;
        result
    }
    /// Run a scoped maintenance transaction under the fresh installer's lock.
    /// A panic, uncertain append or changed journal poisons the writer. The
    /// borrowed descriptor cannot unlock the original installation guard.
    pub(crate) fn with_maintenance<T>(
        &mut self,
        operation: impl FnOnce(&mut LockedMaintenance) -> Result<T>,
    ) -> Result<T> {
        if self.poisoned || read(&self.directory)? != self.journal {
            return Err("uncertain installation cannot enter maintenance".into());
        }
        let mut view = LockedMaintenance {
            inspection: LockedInspection {
                directory: LockedDirectory {
                    file: self
                        .directory
                        .file
                        .try_clone()
                        .map_err(|_| "cannot borrow installation lock")?,
                    owner_pid: self.directory.owner_pid,
                    unlock_on_drop: false,
                },
                journal: self.journal.clone(),
            },
            poisoned: false,
        };
        self.poisoned = true;
        let result = operation(&mut view);
        view.require_unchanged()?;
        self.poisoned = false;
        result
    }
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
        let input = open_at(&source_parent, &leaf, libc::O_PATH, 0)?;
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
        let mut input = reopen_regular(&input)?;
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
        crate::installer_host_fs::rename_at(
            &self.directory,
            &partial,
            &self.directory,
            &target,
            crate::installer_host_fs::RenameMode::NoReplace,
        )
        .map_err(|failure| format!("publish operator without replacement: {failure}"))?;
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
            || ![
                "downloads",
                "evidence",
                "openbao-state",
                "openbao-control",
                "openbao-seal",
                "acme-custody-transfer",
                "acme-credentials-transfer",
                "keycloak-output",
                "tls-output",
                "ingress-output",
                "renewal-inputs",
                "renewal-transfer",
                "generation-inputs",
                "generation-identity",
                "generation-transfer",
                "application-generation",
                "organization-bootstrap-output",
            ]
            .contains(&entry)
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
        if matches!(entry, "evidence" | "downloads") {
            if let Some(creation) = &mut self.creation {
                creation.capture(entry, &child)?;
            }
        }
        if entry == "evidence" {
            if let Some(creation) = &mut self.credential_creation {
                creation.capture_evidence(&child)?;
            }
            if let Some(creation) = &mut self.application_creation {
                creation.capture_evidence(&child)?;
            }
            if let Some(creation) = &mut self.openbao_creation {
                creation.capture_evidence(&child)?;
            }
        }
        if entry == "openbao-state" {
            if let Some(creation) = &mut self.openbao_creation {
                creation.capture_state(&child)?;
            }
        }
        self.poisoned = false;
        Ok(())
    }
    /// Create the two private control mounts for a fresh managed OpenBao node.
    /// Only the socket child may later change to the mapped image owner. The
    /// installation root, outer directory and credential identity stay private
    /// to the installer user. Existing directories are never adopted.
    pub(crate) fn prepare_openbao_control(&mut self) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        self.create_private_directory("openbao-control")?;
        self.poisoned = true;
        let control = open_at(
            &self.directory,
            &name("openbao-control"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&control, true)?;
        let mut observed = serde_json::Map::new();
        for entry in ["socket", "identity"] {
            if unsafe { libc::mkdirat(control.as_raw_fd(), name(entry).as_ptr(), 0o700) } != 0 {
                return Err(error("create OpenBao control child"));
            }
            let child = open_at(
                &control,
                &name(entry),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            private(&child, true)?;
            child
                .sync_all()
                .map_err(|_| "persist OpenBao control child")?;
            let metadata = child
                .metadata()
                .map_err(|_| "OpenBao control metadata unavailable")?;
            observed.insert(
                entry.into(),
                serde_json::json!({
                    "device": metadata.dev(), "inode": metadata.ino(),
                    "owner_uid": metadata.uid(), "owner_gid": metadata.gid(), "mode": 0o700,
                }),
            );
        }
        control
            .sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| "persist OpenBao control directories")?;
        let metadata = control
            .metadata()
            .map_err(|_| "OpenBao control metadata unavailable")?;
        let receipt = serde_json::to_vec(&serde_json::json!({
            "schema": "elevenid.installer-openbao-control-created/v1",
            "installation_id": self.journal.installation_id(),
            "device": metadata.dev(), "inode": metadata.ino(),
            "owner_uid": metadata.uid(), "owner_gid": metadata.gid(), "mode": 0o700,
            "children": observed, "enrolled": false,
        }))
        .map_err(|_| "cannot encode OpenBao control creation")?;
        self.poisoned = false;
        self.write_evidence("openbao-control-created.json", &receipt)
    }
    /// Persist creation-time identities for only the fresh root and the two
    /// fixed directories created immediately after it. This receipt is local
    /// historical evidence, never cryptographic authorization or purge scope.
    /// An interrupted write poisons this writer; a resumed installation lacks
    /// the in-memory capture and cannot mint the receipt retroactively.
    pub(crate) fn persist_initial_creation_receipt(&mut self, installation: &Path) -> Result<()> {
        self.require_live_phase(Phase::Initialized)?;
        let creation = self
            .creation
            .as_ref()
            .ok_or("creation-time identity is unavailable")?
            .clone();
        let prepared = (|| {
            self.with_inspection(|view| view.require_path_binding(installation))?;
            let evidence = open_at(
                &self.directory,
                &name("evidence"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let downloads = open_at(
                &self.directory,
                &name("downloads"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            private(&evidence, true)?;
            private(&downloads, true)?;
            creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &downloads,
            )
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.write_evidence(CREATION_RECEIPT, &bytes)?;
        let confirmed = (|| {
            let evidence = open_at(
                &self.directory,
                &name("evidence"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let downloads = open_at(
                &self.directory,
                &name("downloads"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            if creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &downloads,
            )? != bytes
            {
                return Err("creation identity changed after receipt write".into());
            }
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(CREATION_RECEIPT)? != bytes {
                    return Err("creation identity receipt changed".into());
                }
                Ok(())
            })
        })();
        if confirmed.is_err() {
            self.poisoned = true;
            return Err("creation identity receipt cannot be confirmed".into());
        }
        if let Some(application_creation) = &mut self.application_creation {
            if let Err(error) = application_creation.remember_initial_receipt(&bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        if let Some(openbao_creation) = &mut self.openbao_creation {
            if let Err(error) = openbao_creation.remember_initial_receipt(&bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        if let Some(credential_creation) = &mut self.credential_creation {
            if let Err(error) = credential_creation.remember_initial_receipt(bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.creation = None;
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
        self.generate_local_scalar_credentials(true)
    }

    /// External authentication has no local operator or Keycloak password.
    /// Scalar entropy, exclusive writes and creation receipts share one owner.
    pub(crate) fn generate_external_auth_credentials(&mut self) -> Result<()> {
        self.generate_local_scalar_credentials(false)
    }

    fn generate_local_scalar_credentials(&mut self, local_auth: bool) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
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
        let mut operator_output = None;
        let scalars = SCALAR_SECRETS
            .into_iter()
            .filter(|entry| local_auth || !LOCAL_AUTH_SCALAR_SECRETS.contains(entry));
        for entry in scalars.chain(local_auth.then_some("operator-password")) {
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
            if operator {
                operator_output = Some(output);
            }
        }
        secrets.sync_all().map_err(|_| "sync credentials")?;
        self.directory
            .sync_all()
            .map_err(|_| "sync operator credential")?;
        if let Some(creation) = &mut self.credential_creation {
            creation.capture(&secrets, operator_output.as_ref())?;
        }
        self.poisoned = false;
        Ok(())
    }

    fn optional_operator_password(&self) -> Result<Option<File>> {
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name("operator-password").as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err("operator credential observation unavailable".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file, false)?;
        Ok(Some(file))
    }

    /// Record only secrets-directory and optional operator-file creation identity.
    /// This requires fresh in-memory capture; resume cannot mint provenance.
    pub(crate) fn persist_credential_creation_receipt(
        &mut self,
        installation: &Path,
    ) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        let creation = match self.credential_creation.as_ref() {
            Some(creation) => creation.clone(),
            None if !matches!(self.journal.execution_scope(), ExecutionScope::Unclassified) => {
                return Ok(());
            }
            None => return Err("credential creation identity is unavailable".into()),
        };
        let prepared = (|| {
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(CREATION_RECEIPT)? != creation.initial_receipt()? {
                    return Err("initial creation identity receipt changed".into());
                }
                Ok(())
            })?;
            let evidence = open_at(
                &self.directory,
                &name("evidence"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let secrets = open_at(
                &self.directory,
                &name("secrets"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let operator = self.optional_operator_password()?;
            private(&evidence, true)?;
            private(&secrets, true)?;
            creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &secrets,
                operator.as_ref(),
            )
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.write_evidence(CREDENTIAL_RECEIPT, &bytes)?;
        let confirmed = (|| {
            let evidence = open_at(
                &self.directory,
                &name("evidence"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let secrets = open_at(
                &self.directory,
                &name("secrets"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let operator = self.optional_operator_password()?;
            if creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &secrets,
                operator.as_ref(),
            )? != bytes
            {
                return Err("credential identity changed after receipt write".into());
            }
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(CREDENTIAL_RECEIPT)? != bytes {
                    return Err("credential identity receipt changed".into());
                }
                Ok(())
            })
        })();
        if confirmed.is_err() {
            self.poisoned = true;
            return Err("credential identity receipt cannot be confirmed".into());
        }
        if let Some(application_creation) = &mut self.application_creation {
            if let Err(error) = application_creation.remember_credential_receipt(&bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        if let Some(openbao_creation) = &mut self.openbao_creation {
            if let Err(error) = openbao_creation.remember_credential_receipt(&bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.credential_creation = None;
        Ok(())
    }

    /// Import preprovisioned application inputs into the same private scalar
    /// custody owner. No private keys or rotating web-identity tokens belong
    /// here; those credentials stay with their external producer.
    pub(crate) fn stage_application_inputs(
        &mut self,
        values: &std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        if values.is_empty()
            || values.len() > 64
            || values.iter().any(|(entry, bytes)| {
                !regex::Regex::new(r"\A[a-z0-9][a-z0-9_-]{0,127}\z")
                    .unwrap()
                    .is_match(entry)
                    || bytes.len() > 65_536
                    || (bytes.is_empty() && entry != "external_oidc_client_secret")
                    || bytes.windows(11).any(|value| value == b"PRIVATE KEY")
            })
        {
            return Err("application input import refused".into());
        }
        let secrets = open_at(
            &self.directory,
            &name("secrets"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&secrets, true)?;
        self.poisoned = true;
        for (entry, bytes) in values {
            let mut file = open_at(
                &secrets,
                &name(entry),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            private(&file, false)?;
            file.write_all(bytes)
                .map_err(|_| "application input import failed")?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
                return Err("application input projection failed".into());
            }
            file.sync_all()
                .and_then(|_| secrets.sync_all())
                .map_err(|_| "application input import uncertain")?;
        }
        self.poisoned = false;
        Ok(())
    }

    /// Create only the fixed application directories and disabled-integration
    /// placeholders. Existing state is never adopted; partial writes poison the
    /// transaction and remain available for explicit recovery.
    pub fn prepare_application_storage(&mut self) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        private(&self.directory, true)?;
        let secrets = open_at(
            &self.directory,
            &name("secrets"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&secrets, true)?;
        self.poisoned = true;
        let make = |parent: &File, entry: &str| -> Result<File> {
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name(entry).as_ptr(), 0o700) } != 0 {
                return Err(error("create application directory"));
            }
            let child = open_at(parent, &name(entry), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            private(&child, true)?;
            child
                .sync_all()
                .and_then(|_| parent.sync_all())
                .map_err(|_| "persist application directory")?;
            Ok(child)
        };
        let state = make(&self.directory, "state")?;
        for entry in ["postgres", "redis"] {
            make(&state, entry)?;
        }
        let applicant = make(&state, "applicant")?;
        let gid = applicant_state_gid()?;
        if unsafe { libc::fchown(applicant.as_raw_fd(), !0, gid) } != 0
            || unsafe { libc::fchmod(applicant.as_raw_fd(), 0o2770) } != 0
        {
            return Err(error("provision applicant state ownership"));
        }
        require_applicant_storage(&applicant, gid)?;
        applicant
            .sync_all()
            .and_then(|_| state.sync_all())
            .map_err(|_| "persist applicant state ownership")?;
        let backups = make(&self.directory, "backups")?;
        let exports = make(&self.directory, "openbao-exports")?;
        let snapshot_identity = make(&self.directory, "openbao-snapshot-identity")?;
        for entry in crate::installer_application_env::OPTIONAL_EMPTY_SECRETS {
            let file = open_at(
                &secrets,
                &name(entry),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            private(&file, false)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
                return Err(error("set disabled integration input mode"));
            }
            file.sync_all()
                .map_err(|_| "persist disabled integration input")?;
        }
        secrets
            .sync_all()
            .map_err(|_| "persist application placeholders")?;
        if let Some(creation) = &mut self.application_creation {
            creation.capture(&state, &backups, &exports, &snapshot_identity)?;
        }
        self.poisoned = false;
        Ok(())
    }

    /// Reopen the exact held installation child without following links before
    /// a prepared model can start containers, including after a resumed run.
    pub fn validate_applicant_storage(&self) -> Result<u32> {
        private(&self.directory, true)?;
        let state = open_at(
            &self.directory,
            &name("state"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&state, true)?;
        let applicant = open_at(
            &state,
            &name("applicant"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let gid = applicant_state_gid()?;
        require_applicant_storage(&applicant, gid)?;
        Ok(gid)
    }

    /// Publish only the four fixed application-root creation identities.
    /// Prior local receipts are compared byte-for-byte; no path is adopted on
    /// resume, and this receipt grants no deletion authority.
    pub(crate) fn persist_application_storage_creation_receipt(
        &mut self,
        installation: &Path,
    ) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        let creation = match self.application_creation.as_ref() {
            Some(creation) => creation.clone(),
            None if !matches!(self.journal.execution_scope(), ExecutionScope::Unclassified) => {
                return Ok(());
            }
            None => return Err("application root creation identity is unavailable".into()),
        };
        let prepared = (|| {
            let (initial, credentials) = creation.prior_receipts()?;
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(CREATION_RECEIPT)? != initial
                    || view.read_evidence(CREDENTIAL_RECEIPT)? != credentials
                {
                    return Err("prior creation identity receipt changed".into());
                }
                Ok(())
            })?;
            let open = |entry: &str| open_at(&self.directory, &name(entry), libc::O_PATH, 0);
            let evidence = open("evidence")?;
            let state = open("state")?;
            let backups = open("backups")?;
            let exports = open("openbao-exports")?;
            let snapshot_identity = open("openbao-snapshot-identity")?;
            for directory in [&evidence, &state, &backups, &exports, &snapshot_identity] {
                private(directory, true)?;
            }
            creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                ApplicationHandles {
                    root: &self.directory,
                    evidence: &evidence,
                    state: &state,
                    backups: &backups,
                    exports: &exports,
                    snapshot_identity: &snapshot_identity,
                },
            )
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.write_evidence(APPLICATION_RECEIPT, &bytes)?;
        let confirmed = (|| {
            let open = |entry: &str| open_at(&self.directory, &name(entry), libc::O_PATH, 0);
            let evidence = open("evidence")?;
            let state = open("state")?;
            let backups = open("backups")?;
            let exports = open("openbao-exports")?;
            let snapshot_identity = open("openbao-snapshot-identity")?;
            if creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                ApplicationHandles {
                    root: &self.directory,
                    evidence: &evidence,
                    state: &state,
                    backups: &backups,
                    exports: &exports,
                    snapshot_identity: &snapshot_identity,
                },
            )? != bytes
            {
                return Err("application root identity changed after receipt write".into());
            }
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(APPLICATION_RECEIPT)? != bytes {
                    return Err("application root receipt changed".into());
                }
                Ok(())
            })
        })();
        if confirmed.is_err() {
            self.poisoned = true;
            return Err("application root identity receipt cannot be confirmed".into());
        }
        self.application_creation = None;
        Ok(())
    }

    /// Commit the freshly created OpenBao state root before its first writer.
    /// This local historical receipt is never a deletion grant.
    pub(crate) fn persist_openbao_state_creation_receipt(
        &mut self,
        installation: &Path,
    ) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        let creation = match self.openbao_creation.as_ref() {
            Some(creation) => creation.clone(),
            None if !matches!(self.journal.execution_scope(), ExecutionScope::Unclassified) => {
                return Ok(());
            }
            None => return Err("OpenBao state creation identity is unavailable".into()),
        };
        let prepared = (|| {
            let (initial, credentials) = creation.prior_receipts()?;
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(CREATION_RECEIPT)? != initial
                    || view.read_evidence(CREDENTIAL_RECEIPT)? != credentials
                {
                    return Err("prior creation identity receipt changed".into());
                }
                Ok(())
            })?;
            let evidence = open_at(&self.directory, &name("evidence"), libc::O_PATH, 0)?;
            let state = open_at(&self.directory, &name("openbao-state"), libc::O_PATH, 0)?;
            private(&evidence, true)?;
            private(&state, true)?;
            creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &state,
            )
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.write_evidence(OPENBAO_STATE_RECEIPT, &bytes)?;
        let confirmed = (|| {
            let evidence = open_at(&self.directory, &name("evidence"), libc::O_PATH, 0)?;
            let state = open_at(&self.directory, &name("openbao-state"), libc::O_PATH, 0)?;
            if creation.receipt_bytes(
                self.journal.installation_id(),
                &self.journal.identity().source_sha,
                &self.directory,
                &evidence,
                &state,
            )? != bytes
            {
                return Err("OpenBao state identity changed after receipt write".into());
            }
            self.with_inspection(|view| {
                view.require_path_binding(installation)?;
                if view.read_evidence(OPENBAO_STATE_RECEIPT)? != bytes {
                    return Err("OpenBao state receipt changed".into());
                }
                Ok(())
            })
        })();
        if confirmed.is_err() {
            self.poisoned = true;
            return Err("OpenBao state identity receipt cannot be confirmed".into());
        }
        if let Some(creation) = &mut self.openbao_creation {
            if let Err(error) = creation.remember_state_receipt(&bytes) {
                self.poisoned = true;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Record the exact metadata observed after the retained TLS initializer
    /// completed. The initial creation receipt remains immutable; this later
    /// local observation is neither ownership authentication nor deletion grant.
    pub(crate) fn persist_openbao_owner_transition_receipt(
        &mut self,
        installation: &Path,
        observed_engine_id: &str,
        image: &str,
        image_id: &str,
        container_id: &str,
        completion_bytes: &[u8],
    ) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        if !matches!(self.journal.execution_scope(), ExecutionScope::Unclassified) {
            return Ok(());
        }
        let creation = self
            .openbao_creation
            .as_ref()
            .ok_or("fresh OpenBao transition capability unavailable")?
            .clone();
        let binding = self
            .journal
            .runtime()
            .ok_or("OpenBao runtime binding absent")?;
        binding.validate()?;
        if observed_engine_id != binding.engine_id {
            self.poisoned = true;
            return Err("OpenBao engine binding changed".into());
        }
        let engine_id = binding.engine_id.clone();
        let prepare = |this: &Self| -> Result<Vec<u8>> {
            this.with_inspection(|view| view.require_path_binding(installation))?;
            let completion = open_at(
                &this.directory,
                &name("openbao-completed-openbao-tls-init.json"),
                libc::O_PATH,
                0,
            )?;
            private(&completion, false)?;
            let mut bytes = Vec::new();
            reopen_regular(&completion)?
                .take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "OpenBao TLS completion record unavailable")?;
            if bytes != completion_bytes || bytes.is_empty() || bytes.len() as u64 > LIMIT {
                return Err("OpenBao TLS completion record changed".into());
            }
            let saved = creation.transition_chain()?;
            let (initial, credential, state_creation) = this.with_inspection(|view| {
                Ok((
                    view.read_evidence(CREATION_RECEIPT)?,
                    view.read_evidence(CREDENTIAL_RECEIPT)?,
                    view.read_evidence(OPENBAO_STATE_RECEIPT)?,
                ))
            })?;
            if initial != saved.initial_receipt
                || credential != saved.credential_receipt
                || state_creation != saved.state_receipt
            {
                return Err("OpenBao prior creation receipts changed".into());
            }
            let evidence = open_at(&this.directory, &name("evidence"), libc::O_PATH, 0)?;
            let state = open_at(&this.directory, &name("openbao-state"), libc::O_PATH, 0)?;
            private(&evidence, true)?;
            let root_observed = crate::installer_creation_identity::observe(&this.directory)?;
            let evidence_observed = crate::installer_creation_identity::observe(&evidence)?;
            let state_observed = crate::installer_creation_identity::observe(&state)?;
            if root_observed != *saved.root
                || evidence_observed != *saved.evidence
                || state_observed.mount_id != saved.state.mount_id
                || state_observed.identity.dev != saved.state.identity.dev
                || state_observed.identity.ino != saved.state.identity.ino
                || state_observed.identity.kind != saved.state.identity.kind
                || state_observed.identity.mode != saved.state.identity.mode
            {
                return Err("OpenBao creation inode changed before owner transition".into());
            }
            installer_openbao_owner_transition::receipt_bytes(&OpenBaoOwnerEvidence {
                initial_bytes: &initial,
                state_bytes: &state_creation,
                completion_bytes: &bytes,
                installation_id: this.journal.installation_id(),
                source_sha: &this.journal.identity().source_sha,
                engine_id: &engine_id,
                image,
                image_id,
                container_id,
                root: &root_observed,
                evidence: &evidence_observed,
                state: &state_observed,
            })
        };
        let bytes = match prepare(self) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.write_evidence(OPENBAO_OWNER_TRANSITION_RECEIPT, &bytes)?;
        if prepare(self).as_ref() != Ok(&bytes) {
            self.poisoned = true;
            return Err("OpenBao owner transition changed after receipt write".into());
        }
        if !matches!(
            self.with_inspection(|view| view.read_evidence(OPENBAO_OWNER_TRANSITION_RECEIPT)),
            Ok(confirmed) if confirmed == bytes
        ) {
            self.poisoned = true;
            return Err("OpenBao owner transition receipt cannot be confirmed".into());
        }
        self.openbao_creation = None;
        Ok(())
    }

    /// Stage the operator password for one narrowly mounted configurator input.
    /// The user-facing original remains 0600; the 0444 copy stays inside the
    /// private secrets directory so a different container UID can read its bind.
    /// Call after OpenBao's initial scalar-inventory admission. Never replay an
    /// uncertain account bootstrap or replace an existing staged credential.
    pub fn stage_operator_password(&mut self) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        private(&self.directory, true)?;
        let source = open_at(&self.directory, &name("operator-password"), libc::O_PATH, 0)?;
        private(&source, false)?;
        let mut source = reopen_regular(&source)?;
        let metadata = source
            .metadata()
            .map_err(|_| "operator credential unavailable")?;
        if metadata.len() != 69 {
            return Err("operator credential differs from generated contract".into());
        }
        let mut password = [0u8; 69];
        source
            .read_exact(&mut password)
            .map_err(|_| "operator credential unavailable")?;
        if !password.starts_with(b"Aa1!")
            || password[68] != b'\n'
            || !password[4..68]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("operator credential differs from generated contract".into());
        }
        let secrets = open_at(
            &self.directory,
            &name("secrets"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&secrets, true)?;
        self.poisoned = true;
        let mut destination = open_at(
            &secrets,
            &name("operator_bootstrap_password"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&destination, false)?;
        destination
            .write_all(&password)
            .map_err(|_| "stage operator credential")?;
        if unsafe { libc::fchmod(destination.as_raw_fd(), 0o444) } != 0 {
            return Err(error("set configurator credential mode"));
        }
        destination
            .sync_all()
            .map_err(|_| "sync configurator credential")?;
        secrets
            .sync_all()
            .map_err(|_| "sync configurator secret directory")?;
        self.poisoned = false;
        Ok(())
    }

    /// Creates a NEW directory only. Existing empty directories are not adopted.
    /// Failure may leave a private directory requiring explicit inspection.
    pub fn create(path: &Path, identity: Identity) -> Result<Self> {
        Self::create_internal(
            path,
            identity,
            None,
            ExecutionScope::Unclassified,
            uuid::Uuid::new_v4(),
        )
    }
    pub fn create_with_runtime(
        path: &Path,
        identity: Identity,
        runtime: RuntimeBinding,
    ) -> Result<Self> {
        runtime.validate()?;
        Self::create_internal(
            path,
            identity,
            Some(runtime),
            ExecutionScope::Unclassified,
            uuid::Uuid::new_v4(),
        )
    }
    /// Caller must authenticate and durably consume the candidate authorization
    /// separately. This constructor records scope; it grants no execution right.
    pub fn create_candidate_with_runtime(
        path: &Path,
        identity: Identity,
        runtime: RuntimeBinding,
        scope: AcceptanceScope,
        installation_id: uuid::Uuid,
    ) -> Result<Self> {
        runtime.validate()?;
        scope.validate()?;
        if installation_id.get_version_num() != 4
            || installation_id.get_variant() != uuid::Variant::RFC4122
        {
            return Err("candidate installation identity must be UUIDv4".into());
        }
        Self::create_internal(
            path,
            identity,
            Some(runtime),
            ExecutionScope::AcceptanceOnly(scope),
            installation_id,
        )
    }
    /// An explicitly selected public nightly test has no consumer admission.
    /// The caller verifies the signed inventory and operator before creating it.
    pub fn create_test_with_runtime(
        path: &Path,
        identity: Identity,
        runtime: RuntimeBinding,
        scope: CandidateTestScope,
    ) -> Result<Self> {
        runtime.validate()?;
        scope.validate()?;
        if identity.inventory_sha256 != format!("sha256:{}", scope.inventory_sha256) {
            return Err("candidate test inventory identity differs".into());
        }
        Self::create_internal(
            path,
            identity,
            Some(runtime),
            ExecutionScope::CandidateTest(scope),
            uuid::Uuid::new_v4(),
        )
    }
    /// Only the opted-in fresh test harness can create this unsigned scope.
    /// Released CLI entry points cannot select or resume it.
    #[cfg(all(test, feature = "installer-development"))]
    pub(crate) fn create_development_with_runtime(
        path: &Path,
        identity: Identity,
        runtime: RuntimeBinding,
        scope: UnsignedDevelopmentScope,
    ) -> Result<Self> {
        runtime.validate()?;
        scope.validate()?;
        if runtime.profile != RuntimeProfile::Rootless
            || identity.inventory_sha256 != format!("sha256:{}", scope.fixture.inventory_sha256)
        {
            return Err("unsigned development fixture or runtime identity differs".into());
        }
        Self::create_internal(
            path,
            identity,
            Some(runtime),
            ExecutionScope::UnsignedDevelopment(scope),
            uuid::Uuid::new_v4(),
        )
    }
    fn create_internal(
        path: &Path,
        identity: Identity,
        runtime: Option<RuntimeBinding>,
        scope: ExecutionScope,
        installation_id: uuid::Uuid,
    ) -> Result<Self> {
        identity.validate()?;
        let (parent, leaf) = parent(path)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            return Err(error("create new installation directory"));
        }
        let directory = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        let directory = lock(directory)?;
        parent.sync_all().map_err(|e| e.to_string())?;
        let creation = if runtime.is_some() && matches!(&scope, ExecutionScope::Unclassified) {
            Some(NewInstallation::new(&directory)?)
        } else {
            None
        };
        let credential_creation = if creation.is_some() {
            Some(NewCredentials::new(&directory)?)
        } else {
            None
        };
        let application_creation = if creation.is_some() {
            Some(NewApplicationStorage::new(&directory)?)
        } else {
            None
        };
        let openbao_creation = if creation.is_some() {
            Some(NewOpenBaoState::new(&directory)?)
        } else {
            None
        };
        let journal = Journal {
            schema: SCHEMA.into(),
            installation_id,
            identity,
            phase: Phase::Initialized,
            revision: 0,
            runtime,
            scope,
            hosting_selection_sha256: None,
            hosting_addon_sha256: None,
        };
        let mut state = Self {
            directory,
            journal: journal.clone(),
            poisoned: false,
            creation,
            credential_creation,
            application_creation,
            openbao_creation,
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
        let directory = lock(directory)?;
        let journal = read(&directory)?;
        if &journal.identity != identity {
            return Err("installation candidate differs".into());
        }
        if !matches!(journal.scope, ExecutionScope::Unclassified) {
            return Err("test execution cannot use ordinary provisioning resume".into());
        }
        // Cleanup and provisioning are separate lifecycles. Even a historical
        // Ready journal must never authorize recreation after cleanup begins.
        if maintenance_started(&directory)? {
            return Err("cleanup has begun; provisioning resume is refused".into());
        }
        if journal.phase == Phase::Provisioning {
            return Err("provisioning outcome is indeterminate; reconciliation required".into());
        }
        Ok(Self {
            directory,
            journal,
            poisoned: false,
            creation: None,
            credential_creation: None,
            application_creation: None,
            openbao_creation: None,
        })
    }

    /// Continue only the completed pre-ACME boundary while retaining the same
    /// installation lock. This is not ordinary provisioning replay: the host
    /// bridge must prove both setup jobs and its immutable prepared receipt,
    /// and application creation must already have been completed by the
    /// original writer. No fresh-creation capability is reconstructed.
    pub(crate) fn continue_acme_enrolment(
        inspection: LockedInspection,
        installation: &Path,
        identity: &Identity,
    ) -> Result<Self> {
        const REFUSED: &str = "ACME continuation requires its complete prepared boundary before application generation; preserve partial state for reconciliation";
        identity.validate()?;
        inspection.require_path_binding(installation)?;
        crate::installer_acme_preparation::require_supported_scope(&inspection)?;
        if inspection.journal.identity() != identity
            || inspection.journal.phase() != Phase::Provisioning
            || !inspection
                .journal
                .runtime()
                .is_some_and(|runtime| runtime.profile == RuntimeProfile::Rootless)
            || !crate::installer_acme_host::continuation_available(&inspection)?
        {
            return Err(REFUSED.into());
        }
        crate::installer_application::require_acme_preparation(&inspection, installation)?;
        let evidence = open_at(
            &inspection.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        private(&evidence, true)?;
        for entry in crate::installer_host_fs::file_names(&evidence, REFUSED)? {
            // Renewal-authority enrollment is part of preparation. Generation,
            // application activation and lifecycle operations are separate
            // owners whose uncertain outcomes cannot be replayed here.
            if entry.starts_with("generation-")
                || (entry.starts_with("application-") && entry != APPLICATION_RECEIPT)
                || entry.starts_with("compose-generation-")
                || entry.starts_with("compose-application-")
                || entry.starts_with("lifecycle-")
                || entry.starts_with("uninstall-")
                || entry == "compose-session.json"
                || entry == "installer-nginx.conf"
            {
                return Err(REFUSED.into());
            }
        }
        inspection.require_path_binding(installation)?;
        Ok(Self {
            directory: inspection.directory,
            journal: inspection.journal,
            poisoned: false,
            creation: None,
            credential_creation: None,
            application_creation: None,
            openbao_creation: None,
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
        if next == Phase::Ready && !matches!(self.journal.scope, ExecutionScope::Unclassified) {
            return Err("test execution requires external runtime qualification; installation Ready is not granted".into());
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
    /// Bind a fresh installation's hosting evidence before any ingress side
    /// effects. The phase revision stays unchanged; absence remains meaningful
    /// for journals created before hosting configuration was introduced.
    pub(crate) fn bind_hosting_selection(&mut self, digest: &str) -> Result<()> {
        self.require_live_phase(Phase::Verified)?;
        if self.journal.hosting_selection_sha256.is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("hosting selection can be bound only once".into());
        }
        let mut journal = self.journal.clone();
        journal.hosting_selection_sha256 = Some(digest.into());
        self.persist(&journal)?;
        self.journal = journal;
        Ok(())
    }
    /// Optional connector artifacts are independently authenticated and bound
    /// only after the hosting selection, before provisioning begins.
    pub(crate) fn bind_hosting_addon(&mut self, digest: &str) -> Result<()> {
        self.require_live_phase(Phase::Verified)?;
        if self.journal.hosting_selection_sha256.is_none()
            || self.journal.hosting_addon_sha256.is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("hosting add-on can be bound only once after hosting selection".into());
        }
        let mut journal = self.journal.clone();
        journal.hosting_addon_sha256 = Some(digest.into());
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
    #[test]
    fn classified_read_reopens_held_inode_and_refuses_special_entries() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("record");
        std::fs::write(&path, b"held-record-canary").unwrap();
        let directory = File::open(root.path()).unwrap();
        let held = open_at(&directory, &name("record"), libc::O_PATH, 0).unwrap();
        std::fs::rename(&path, root.path().join("saved-record")).unwrap();
        let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut observed = Vec::new();
        reopen_regular(&held)
            .unwrap()
            .read_to_end(&mut observed)
            .unwrap();
        assert_eq!(observed, b"held-record-canary");
        let special = open_at(&directory, &name("record"), libc::O_PATH, 0).unwrap();
        assert!(reopen_regular(&special).is_err());
        std::fs::hard_link(
            root.path().join("saved-record"),
            root.path().join("linked-record"),
        )
        .unwrap();
        assert!(reopen_regular(&held).is_err());
    }
    #[test]
    fn private_record_surfaces_refuse_fifo_without_consuming_it() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let mut writer = InstallerState::create(&path, identity()).unwrap();
        writer.create_private_directory("evidence").unwrap();
        drop(writer);
        let fifo = |target: &Path| {
            let name = CString::new(target.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        };
        fifo(&path.join("evidence/uninstall-plan.json"));
        fifo(&path.join("operator-password"));
        fifo(&path.join("root-record.json"));
        let view = LockedInspection::open(&path).unwrap();
        assert!(view.read_evidence("uninstall-plan.json").is_err());
        assert!(view.diagnostic_record("uninstall-plan.json", true).is_err());
        assert!(view.diagnostic_record("root-record.json", false).is_err());
        assert!(maintenance_started(&view.directory).is_err());
        assert!(view.read_operator_password().is_err());
        drop(view);
        let maintenance = LockedMaintenance::open(&path).unwrap();
        assert!(maintenance.read_evidence("uninstall-plan.json").is_err());
        drop(maintenance);
        std::fs::remove_file(path.join(JOURNAL)).unwrap();
        fifo(&path.join(JOURNAL));
        assert!(LockedInspection::open(&path).is_err());
        assert!(std::fs::symlink_metadata(path.join(JOURNAL))
            .unwrap()
            .file_type()
            .is_fifo());
    }
    #[test]
    fn diagnostic_view_never_unlocks_writer_on_success_error_or_panic() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let state = InstallerState::create(&path, identity()).unwrap();
        state
            .with_inspection(|view| {
                view.require_path_binding(&path)?;
                Ok(())
            })
            .unwrap();
        assert!(LockedInspection::open(&path).is_err());
        let result: Result<()> = state.with_inspection(|_| Err("failed diagnostic".into()));
        assert!(result.is_err() && LockedInspection::open(&path).is_err());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<()> = state.with_inspection(|_| panic!("diagnostic panic"));
        }));
        assert!(panic.is_err() && LockedInspection::open(&path).is_err());
        drop(state);
        assert!(LockedInspection::open(&path).is_ok());
    }
    #[test]
    fn borrowed_maintenance_preserves_lock_and_propagates_uncertain_writes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("installation");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        let before = std::fs::read(path.join(JOURNAL)).unwrap();
        state
            .with_maintenance(|view| {
                assert!(LockedMaintenance::open(&path).is_err());
                view.write_evidence_exclusive("acme-staging-000000.json", b"retained intent")
            })
            .unwrap();
        assert!(LockedInspection::open(&path).is_err());
        let error: Result<()> = state.with_maintenance(|_| Err("validation failed".into()));
        assert!(error.is_err() && !state.poisoned);
        assert!(state
            .with_maintenance(|view| {
                view.write_evidence_exclusive("acme-staging-000000.json", b"overwrite")
            })
            .is_err());
        assert!(state.poisoned && LockedInspection::open(&path).is_err());
        assert!(state.advance(Phase::Verified).is_err());
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), before);
        drop(state);
        let view = LockedMaintenance::open(&path).unwrap();
        assert_eq!(
            view.read_evidence("acme-staging-000000.json")
                .unwrap()
                .unwrap(),
            b"retained intent"
        );
        drop(view);
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn borrowed_maintenance_panic_poisoning_does_not_release_the_writer_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("installation");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<()> = state.with_maintenance(|_| panic!("maintenance interrupted"));
        }));
        assert!(panic.is_err() && state.poisoned);
        assert!(LockedMaintenance::open(&path).is_err());
        assert!(state.advance(Phase::Verified).is_err());
        drop(state);
        assert!(LockedInspection::open(&path).is_ok());
    }
    #[test]
    fn uncertain_generation_publication_cannot_continue_or_release_the_writer_lock() {
        for panic_after_publication in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("installation");
            let mut writer = InstallerState::create(&path, identity()).unwrap();
            writer.create_private_directory("evidence").unwrap();
            drop(writer);
            let mut state = LockedMaintenance::open(&path).unwrap();
            state
                .with_atomic_publication(|view| view.require_path_binding(&path))
                .unwrap();
            assert!(state.require_unchanged().is_ok());
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.with_atomic_publication(|view| {
                    view.require_path_binding(&path)?;
                    std::fs::write(path.join("evidence/publication-observed"), b"retained")
                        .map_err(|error| error.to_string())?;
                    if panic_after_publication {
                        panic!("interrupted after publication");
                    }
                    Err::<(), _>("lost publication response".to_owned())
                })
            }));
            if panic_after_publication {
                assert!(outcome.is_err());
            } else {
                assert!(outcome.unwrap().is_err());
            }
            assert!(state.require_unchanged().is_err());
            assert!(state
                .write_evidence_exclusive("generation-followup.json", b"{}")
                .is_err());
            assert!(LockedInspection::open(&path).is_err());
            assert_eq!(
                std::fs::read(path.join("evidence/publication-observed")).unwrap(),
                b"retained"
            );
            drop(state);
            assert!(LockedInspection::open(&path).is_ok());
        }
    }
    #[test]
    fn validation_reports_are_private_append_only_and_reject_replaced_paths() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let mut writer = InstallerState::create(&path, identity()).unwrap();
        writer.create_private_directory("evidence").unwrap();
        drop(writer);
        let state = LockedInspection::open(&path).unwrap();
        let first = state.save_validation_report(b"first").unwrap();
        let second = state.save_validation_report(b"second").unwrap();
        assert_ne!(first, second);
        assert_eq!(
            std::fs::read(path.join("evidence").join(&first)).unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::metadata(path.join("evidence").join(&first))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let held = open_at(
            &state.directory,
            &name("evidence"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .unwrap();
        let output = File::open(path.join("evidence").join(&first)).unwrap();
        let target = path.join("evidence").join(&first);
        std::fs::write(&target, b"changed").unwrap();
        assert!(state
            .require_validation_report_binding(&held, &first, &output, b"first")
            .is_err());
        std::fs::write(&target, b"first").unwrap();
        let hardlink = path.join("linked-report");
        std::fs::hard_link(&target, &hardlink).unwrap();
        assert!(state
            .require_validation_report_binding(&held, &first, &output, b"first")
            .is_err());
        std::fs::remove_file(hardlink).unwrap();
        std::fs::rename(path.join("evidence"), path.join("old-evidence")).unwrap();
        std::fs::create_dir(path.join("evidence")).unwrap();
        std::fs::set_permissions(
            path.join("evidence"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(state
            .require_validation_report_binding(&held, &first, &output, b"first")
            .is_err());
        std::fs::remove_dir(path.join("evidence")).unwrap();
        symlink(path.join("old-evidence"), path.join("evidence")).unwrap();
        assert!(state.save_validation_report(b"blocked").is_err());
    }

    fn acceptance_scope() -> AcceptanceScope {
        AcceptanceScope {
            authorization_sha256: "a".repeat(64),
            context_sha256: "b".repeat(64),
            consumption_id: "c".repeat(64),
            authenticated_evidence_sha256: None,
        }
    }
    #[test]
    fn acceptance_authenticated_evidence_is_closed_and_legacy_bytes_are_preserved() {
        let legacy = acceptance_scope();
        legacy.validate().unwrap();
        let bytes = serde_json::to_vec(&legacy).unwrap();
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains("authenticated_evidence"));
        let restored: AcceptanceScope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        assert!(restored.authenticated_evidence().is_err());
        let mut bound = legacy;
        bound.authenticated_evidence_sha256 = Some(
            ACCEPTANCE_AUTHENTICATED_EVIDENCE
                .iter()
                .map(|name| ((*name).into(), "d".repeat(64)))
                .collect(),
        );
        bound.authenticated_evidence().unwrap();
        for mutation in ["missing", "extra", "uppercase", "short"] {
            let mut invalid = bound.clone();
            let map = invalid.authenticated_evidence_sha256.as_mut().unwrap();
            match mutation {
                "missing" => {
                    map.remove(ACCEPTANCE_AUTHENTICATED_EVIDENCE[0]);
                }
                "extra" => {
                    map.insert("other.json".into(), "d".repeat(64));
                }
                "uppercase" => {
                    map.insert(ACCEPTANCE_AUTHENTICATED_EVIDENCE[0].into(), "D".repeat(64));
                }
                "short" => {
                    map.insert(ACCEPTANCE_AUTHENTICATED_EVIDENCE[0].into(), "d".repeat(63));
                }
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "accepted {mutation}");
        }
    }
    fn acceptance_runtime() -> RuntimeBinding {
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "01234567-89ab-cdef".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        }
    }
    #[test]
    fn runtime_profile_preserves_legacy_rootful_bytes_and_requires_explicit_rootless_binding() {
        let old = br#"{"docker_host":"unix:///var/run/docker.sock","engine_id":"01234567-89ab-cdef","openbao_port":18200}"#;
        let restored: RuntimeBinding = serde_json::from_slice(old).unwrap();
        assert_eq!(restored, acceptance_runtime());
        assert_eq!(serde_json::to_vec(&restored).unwrap(), old);
        let mut rootless = restored.clone();
        rootless.profile = RuntimeProfile::Rootless;
        rootless.docker_host = format!("unix:///run/user/{}/docker.sock", unsafe {
            libc::geteuid()
        });
        if unsafe { libc::geteuid() } == 0 {
            assert!(rootless.validate().is_err());
        } else {
            rootless.validate().unwrap();
            let bytes = serde_json::to_vec(&rootless).unwrap();
            assert!(bytes
                .windows(b"\"profile\":\"rootless\"".len())
                .any(|w| w == b"\"profile\":\"rootless\""));
            assert_eq!(
                serde_json::from_slice::<RuntimeBinding>(&bytes).unwrap(),
                rootless
            );
            rootless.docker_host = "unix:///var/run/docker.sock".into();
            assert!(rootless.validate().is_err());
        }
    }
    #[test]
    fn acceptance_scope_persists_initially_and_cannot_resume_or_claim_ready() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("candidate");
        let installation_id = uuid::Uuid::new_v4();
        let mut state = InstallerState::create_candidate_with_runtime(
            &path,
            identity(),
            acceptance_runtime(),
            acceptance_scope(),
            installation_id,
        )
        .unwrap();
        let expected = ExecutionScope::AcceptanceOnly(acceptance_scope());
        assert_eq!(state.journal().execution_scope(), &expected);
        assert_eq!(state.journal().installation_id(), installation_id);
        let disk = InstallerState::inspect(&path).unwrap();
        assert_eq!(disk.execution_scope(), &expected);
        for phase in [Phase::Verified, Phase::Provisioning, Phase::Provisioned] {
            state.advance(phase).unwrap();
            assert_eq!(state.journal().execution_scope(), &expected);
        }
        let before = std::fs::read(path.join("installation.json")).unwrap();
        assert!(state.advance(Phase::Ready).is_err());
        assert_eq!(
            std::fs::read(path.join("installation.json")).unwrap(),
            before
        );
        drop(state);
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert_eq!(
            InstallerState::inspect(&path).unwrap().execution_scope(),
            &expected
        );
    }
    #[test]
    fn public_candidate_test_scope_cannot_resume_or_claim_ready() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("nightly-test");
        let scope = CandidateTestScope {
            inventory_sha256: "b".repeat(64),
            build_run_id: 42,
            build_run_attempt: 1,
        };
        let mut wrong = scope.clone();
        wrong.inventory_sha256 = "a".repeat(64);
        assert!(InstallerState::create_test_with_runtime(
            &path,
            identity(),
            acceptance_runtime(),
            wrong,
        )
        .is_err());
        assert!(!path.exists());
        let mut state = InstallerState::create_test_with_runtime(
            &path,
            identity(),
            acceptance_runtime(),
            scope.clone(),
        )
        .unwrap();
        assert_eq!(
            state.journal().execution_scope(),
            &ExecutionScope::CandidateTest(scope.clone())
        );
        for phase in [Phase::Verified, Phase::Provisioning, Phase::Provisioned] {
            state.advance(phase).unwrap();
        }
        assert!(state.advance(Phase::Ready).is_err());
        drop(state);
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert_eq!(
            InstallerState::inspect(&path).unwrap().execution_scope(),
            &ExecutionScope::CandidateTest(scope)
        );
    }

    #[test]
    #[cfg(not(feature = "installer-development"))]
    fn released_journal_rejects_unsigned_development_scope() {
        let scope = serde_json::json!({"kind":"unsigned-development",
            "fixture":{"inventory_sha256":"b".repeat(64),"build_run_id":42,"build_run_attempt":1},
            "artifact_sha256":"c".repeat(64)});
        assert!(serde_json::from_value::<ExecutionScope>(scope).is_err());
    }

    #[test]
    #[cfg(feature = "installer-development")]
    fn unsigned_scope_cannot_create_rootful_or_mismatched_fixture_installations() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let scope = UnsignedDevelopmentScope {
            fixture: CandidateTestScope {
                inventory_sha256: "b".repeat(64),
                build_run_id: 42,
                build_run_attempt: 1,
            },
            artifact_sha256: "c".repeat(64),
        };
        scope.validate().unwrap();
        let directory = root.path().join("unsigned");
        assert!(InstallerState::create_development_with_runtime(
            &directory,
            identity(),
            acceptance_runtime(),
            scope.clone()
        )
        .is_err());
        assert!(!directory.exists());
        let mut malformed = scope;
        malformed.artifact_sha256 = "not-a-digest".into();
        assert!(malformed.validate().is_err());
    }
    #[test]
    fn acceptance_scope_rejects_invalid_hashes_before_directory_creation() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for field in 0..3 {
            for bad in ["", "a", &"A".repeat(64), &"g".repeat(64)] {
                let mut scope = acceptance_scope();
                match field {
                    0 => scope.authorization_sha256 = bad.into(),
                    1 => scope.context_sha256 = bad.into(),
                    _ => scope.consumption_id = bad.into(),
                }
                let path = root.path().join("refused");
                assert!(InstallerState::create_candidate_with_runtime(
                    &path,
                    identity(),
                    acceptance_runtime(),
                    scope,
                    uuid::Uuid::new_v4(),
                )
                .is_err());
                assert!(!path.exists());
            }
        }
        for invalid_id in [
            uuid::Uuid::nil(),
            uuid::Uuid::parse_str("00000000-0000-1000-8000-000000000001").unwrap(),
        ] {
            let path = root.path().join("invalid-id");
            assert!(InstallerState::create_candidate_with_runtime(
                &path,
                identity(),
                acceptance_runtime(),
                acceptance_scope(),
                invalid_id,
            )
            .is_err());
            assert!(!path.exists());
        }
    }
    #[test]
    fn historical_scope_is_unclassified_and_candidate_schema_is_closed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = InstallerState::create(&root.path().join("legacy"), identity()).unwrap();
        let mut encoded = serde_json::to_value(state.journal()).unwrap();
        encoded.as_object_mut().unwrap().remove("scope");
        let historical: Journal = serde_json::from_value(encoded.clone()).unwrap();
        historical.validate().unwrap();
        assert_eq!(historical.execution_scope(), &ExecutionScope::Unclassified);
        encoded["scope"] =
            serde_json::to_value(ExecutionScope::AcceptanceOnly(acceptance_scope())).unwrap();
        let candidate: Journal = serde_json::from_value(encoded.clone()).unwrap();
        candidate.validate().unwrap();
        encoded["phase"] = serde_json::json!("ready");
        encoded["revision"] = serde_json::json!(4);
        assert!(serde_json::from_value::<Journal>(encoded.clone())
            .unwrap()
            .validate()
            .is_err());
        encoded["scope"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Journal>(encoded).is_err());
    }

    #[test]
    fn lock_owner_drop_unlocks_despite_inherited_open_file_description() {
        let root = tempfile::tempdir().unwrap();
        let guard = lock(File::open(root.path()).unwrap()).unwrap();
        let inherited = guard.file.try_clone().unwrap();
        assert!(lock(File::open(root.path()).unwrap()).is_err());
        drop(guard);
        let successor = lock(File::open(root.path()).unwrap()).unwrap();
        // Closing the older duplicate must not release the new owner's lock.
        drop(inherited);
        assert!(lock(File::open(root.path()).unwrap()).is_err());
        drop(successor);
        assert!(lock(File::open(root.path()).unwrap()).is_ok());
    }
    #[test]
    fn lock_guard_releases_on_post_acquisition_error_path() {
        let root = tempfile::tempdir().unwrap();
        let mut inherited = None;
        let outcome: Result<()> = (|| {
            let guard = lock(File::open(root.path()).unwrap())?;
            inherited = Some(guard.file.try_clone().unwrap());
            // Match failed journal/schema/candidate validation after acquire.
            Err("synthetic post-lock validation refusal".into())
        })();
        assert!(outcome.is_err());
        assert!(inherited.is_some());
        assert!(lock(File::open(root.path()).unwrap()).is_ok());
    }
    #[test]
    fn scheduled_lock_wait_acquires_only_after_the_actual_owner_releases() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let owner = InstallerState::create(&path, identity()).unwrap();
        let waiting_path = path.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(LockedMaintenance::open_waiting(
                    &waiting_path,
                    Duration::from_secs(5),
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(LockedInspection::open(&path).is_err());
        drop(owner);
        let acquired = done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
        assert_eq!(acquired.journal().identity(), &identity());
        assert!(LockedInspection::open(&path).is_err());
        drop(acquired);
        assert!(LockedInspection::open(&path).is_ok());
    }
    #[test]
    fn scheduled_lock_wait_exhaustion_preserves_the_owner_and_journal() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let owner = InstallerState::create(&path, identity()).unwrap();
        let before = std::fs::read(path.join(JOURNAL)).unwrap();
        assert!(
            LockedMaintenance::open_waiting(&path, Duration::from_millis(20))
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), before);
        assert!(LockedInspection::open(&path).is_err());
        drop(owner);
        assert!(LockedInspection::open(&path).is_ok());
    }
    #[test]
    fn scheduled_lock_wait_does_not_hide_descriptor_permissions_or_journal_errors() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(root.path()).unwrap();
        let path_only =
            open_at(&directory, &name("."), libc::O_PATH | libc::O_DIRECTORY, 0).unwrap();
        // flock on O_PATH is EBADF, not contention. It must not become a defer.
        assert!(lock_with_wait(path_only, Some(Duration::from_secs(1))).is_err());
        let path = root.path().join("installation");
        let owner = InstallerState::create(&path, identity()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(LockedMaintenance::open_waiting(&path, Duration::ZERO).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(owner);
        std::fs::write(path.join(JOURNAL), b"invalid journal").unwrap();
        assert!(LockedMaintenance::open_waiting(&path, Duration::from_secs(1)).is_err());
        // The error after acquisition still releases the lock.
        assert!(lock(File::open(&path).unwrap()).is_ok());
    }
    #[test]
    fn different_process_guard_drop_does_not_unlock_parent_description() {
        let root = tempfile::tempdir().unwrap();
        let mut guard = lock(File::open(root.path()).unwrap()).unwrap();
        let inherited = guard.file.try_clone().unwrap();
        // Exercise the post-fork PID mismatch branch without unsafe fork in a
        // multithreaded test runner. The retained duplicate models the parent.
        guard.owner_pid = -1;
        drop(guard);
        assert!(lock(File::open(root.path()).unwrap()).is_err());
        assert_eq!(
            unsafe { libc::flock(inherited.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        assert!(lock(File::open(root.path()).unwrap()).is_ok());
    }
    use std::os::unix::fs::{symlink, FileTypeExt, PermissionsExt};
    fn identity() -> Identity {
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        }
    }
    #[test]
    fn missing_fresh_transition_capability_cannot_be_rebuilt_from_disk() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let installation = root.path().join("installation");
        let mut state = InstallerState::create_with_runtime(
            &installation,
            identity(),
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18200,
                profile: RuntimeProfile::Rootful,
            },
        )
        .unwrap();
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
        state
            .persist_credential_creation_receipt(&installation)
            .unwrap();
        state.create_private_directory("openbao-state").unwrap();
        state
            .persist_openbao_state_creation_receipt(&installation)
            .unwrap();
        state.openbao_creation = None;
        let container = "c".repeat(64);
        let completion = serde_json::to_vec(
            &serde_json::json!({"role":"openbao-tls-init","container_id":container,"exit_code":0}),
        )
        .unwrap();
        let completed = installation.join("openbao-completed-openbao-tls-init.json");
        std::fs::write(&completed, &completion).unwrap();
        std::fs::set_permissions(&completed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
            "b".repeat(64)
        );
        let image_id = format!("sha256:{}", "d".repeat(64));
        assert!(state
            .persist_openbao_owner_transition_receipt(
                &installation,
                "test-engine",
                &image,
                &image_id,
                &container,
                &completion
            )
            .is_err());
        assert!(!installation
            .join("evidence")
            .join(OPENBAO_OWNER_TRANSITION_RECEIPT)
            .exists());
        drop(state);
        assert!(InstallerState::resume(&installation, &identity()).is_err());
    }
    #[test]
    fn old_and_native_maintenance_markers_block_provisioning_replay() {
        for entry in [
            "lifecycle-configuration.json",
            "acme-staging-000000.json",
            "acme-production-000000.json",
            "acme-custody-staging-intent.json",
            "acme-custody-production-intent.json",
            "acme-credentials-staging-intent.json",
            "acme-credentials-production-intent.json",
            "uninstall-plan.json",
            "uninstall-result.json",
            "uninstall-compose-stop-intent.json",
            "uninstall-compose-stop-result.json",
            "uninstall-compose-down-intent.json",
            "uninstall-compose-down-result.json",
            "uninstall-compose-start-0001-intent.json",
            "uninstall-compose-start-0001-result.json",
            "uninstall-compose-stop-0001-intent.json",
            "uninstall-compose-stop-0001-result.json",
            "uninstall-compose-down-0001-intent.json",
            "uninstall-compose-down-0001-result.json",
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("install");
            let mut state = InstallerState::create(&path, identity()).unwrap();
            state.create_private_directory("evidence").unwrap();
            drop(state);
            drop(InstallerState::resume(&path, &identity()).unwrap());
            let journal = std::fs::read(path.join(JOURNAL)).unwrap();
            std::fs::write(
                path.join("evidence").join(entry),
                b"unparsed uncertain operation",
            )
            .unwrap();
            std::fs::set_permissions(
                path.join("evidence").join(entry),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert!(
                InstallerState::resume(&path, &identity()).is_err(),
                "{entry}"
            );
            assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), journal);
        }
    }
    #[test]
    fn absent_maintenance_is_distinct_from_link_directory_and_permission_failure() {
        for kind in ["link", "directory", "permissions"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("install");
            let mut state = InstallerState::create(&path, identity()).unwrap();
            state.create_private_directory("evidence").unwrap();
            drop(state);
            let target = path.join("evidence/uninstall-compose-down-intent.json");
            match kind {
                "link" => symlink("absent.json", &target).unwrap(),
                "directory" => std::fs::create_dir(&target).unwrap(),
                _ => {
                    std::fs::write(&target, b"{}").unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
            }
            assert!(InstallerState::resume(&path, &identity()).is_err());
        }
    }
    #[test]
    fn maintenance_is_locked_append_only_and_never_resumes_provisioning() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        assert!(LockedMaintenance::open(&path).is_err());
        drop(state);
        let before = std::fs::read(path.join(JOURNAL)).unwrap();
        let mut maintenance = LockedMaintenance::open(&path).unwrap();
        assert!(LockedInspection::open(&path).is_err());
        assert_eq!(maintenance.journal().phase(), Phase::Provisioning);
        assert!(maintenance
            .read_evidence("uninstall-absent.json")
            .unwrap()
            .is_none());
        assert!(maintenance
            .write_evidence_exclusive("application-plan.json", b"replace")
            .is_err());
        maintenance
            .write_evidence_exclusive("uninstall-intent.json", b"exact resource intent")
            .unwrap();
        assert_eq!(
            maintenance
                .read_evidence("uninstall-intent.json")
                .unwrap()
                .unwrap(),
            b"exact resource intent"
        );
        assert!(maintenance
            .write_evidence_exclusive("uninstall-intent.json", b"replacement")
            .is_err());
        assert!(maintenance.require_unchanged().is_err());
        drop(maintenance);
        let maintenance = LockedMaintenance::open(&path).unwrap();
        assert_eq!(
            maintenance
                .read_evidence("uninstall-intent.json")
                .unwrap()
                .unwrap(),
            b"exact resource intent"
        );
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), before);
        drop(maintenance);
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn maintenance_absence_is_not_a_link_permission_or_content_failure() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        drop(state);
        let maintenance = LockedMaintenance::open(&path).unwrap();
        assert!(maintenance.read_evidence("absent.json").unwrap().is_none());
        assert!(maintenance.read_evidence("../outside").is_err());
        let evidence = path.join("evidence");
        symlink("absent.json", evidence.join("linked.json")).unwrap();
        assert!(maintenance.read_evidence("linked.json").is_err());
        let record = evidence.join("record.json");
        std::fs::write(&record, b"{}").unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(maintenance.read_evidence("record.json").is_err());
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            maintenance.read_evidence("record.json").unwrap().unwrap(),
            b"{}"
        );
        std::fs::hard_link(&record, evidence.join("hard.json")).unwrap();
        assert!(maintenance.read_evidence("record.json").is_err());
        std::fs::write(path.join(JOURNAL), b"{}").unwrap();
        assert!(maintenance.read_evidence("absent.json").is_err());
    }
    #[test]
    fn diagnostic_credentials_are_bounded_nofollow_and_protected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let state = InstallerState::create(&path, identity()).unwrap();
        std::fs::create_dir(path.join("secrets")).unwrap();
        std::fs::set_permissions(path.join("secrets"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        drop(state);
        let secret = path.join("secrets/token");
        std::fs::write(&secret, b"credential").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o444)).unwrap();
        let inspection = LockedInspection::open(&path).unwrap();
        assert_eq!(inspection.read_secret("token").unwrap(), b"credential");
        for entry in crate::installer_application_env::OPTIONAL_EMPTY_SECRETS {
            let optional = path.join("secrets").join(entry);
            std::fs::write(&optional, b"").unwrap();
            std::fs::set_permissions(&optional, std::fs::Permissions::from_mode(0o444)).unwrap();
            assert!(inspection.read_secret(entry).unwrap().is_empty());
        }
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&secret, b"").unwrap();
        assert!(inspection.read_secret("token").is_err());
        std::fs::write(&secret, b"credential").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o444)).unwrap();
        let ca = path.join("secrets/openbao_tls_ca_cert");
        let public = include_bytes!("../tests/fixtures/installer-log-public-ca.txt");
        std::fs::write(&ca, public).unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            inspection.read_secret("openbao_tls_ca_cert").unwrap(),
            public
        );
        std::fs::write(&ca, b"not-a-certificate-secret").unwrap();
        assert!(inspection.read_secret("openbao_tls_ca_cert").is_err());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(inspection.read_secret("token").is_err());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(inspection.read_secret("../installation.json").is_err());
        symlink(&secret, path.join("secrets/linked")).unwrap();
        assert!(inspection.read_secret("linked").is_err());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(inspection.read_secret("token").is_err());
        std::fs::write(&secret, vec![b'x'; 65537]).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(inspection.read_secret("token").is_err());
        std::fs::write(&secret, b"credential").unwrap();
        std::fs::hard_link(&secret, path.join("secrets/hard")).unwrap();
        assert!(inspection.read_secret("token").is_err());
    }
    #[test]
    fn recovery_inspection_locks_uncertain_state_without_enabling_resume() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        state
            .write_evidence("owned.json", b"owned evidence")
            .unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        assert!(LockedInspection::open(&path).is_err());
        drop(state);
        let before = std::fs::read(path.join(JOURNAL)).unwrap();
        let inspection = LockedInspection::open(&path).unwrap();
        assert_eq!(inspection.journal().phase(), Phase::Provisioning);
        assert_eq!(
            inspection.read_evidence("owned.json").unwrap(),
            b"owned evidence"
        );
        assert!(LockedInspection::open(&path).is_err());
        assert!(InstallerState::resume(&path, &identity()).is_err());
        drop(inspection);
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), before);
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn recovery_evidence_rejects_links_traversal_and_oversize() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        state
            .write_evidence("owned.json", b"owned evidence")
            .unwrap();
        drop(state);
        let inspection = LockedInspection::open(&path).unwrap();
        let evidence = path.join("evidence");
        symlink(evidence.join("owned.json"), evidence.join("linked.json")).unwrap();
        assert!(inspection.read_evidence("linked.json").is_err());
        assert!(inspection.read_evidence("../installation.json").is_err());
        std::fs::hard_link(evidence.join("owned.json"), evidence.join("hard.json")).unwrap();
        assert!(inspection.read_evidence("owned.json").is_err());
        let large = evidence.join("large.json");
        std::fs::write(&large, vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
        std::fs::set_permissions(&large, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(inspection.read_evidence("large.json").is_err());
        std::fs::write(path.join(JOURNAL), b"{}").unwrap();
        assert!(inspection.require_unchanged().is_err());
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
            profile: crate::installer_state::RuntimeProfile::Rootful,
        };
        let mut state =
            InstallerState::create_with_runtime(&path, identity(), runtime.clone()).unwrap();
        let project = state.journal().compose_project();
        assert!(project.starts_with("marty-install-"));
        assert_eq!(project.len(), 46);
        state.advance(Phase::Verified).unwrap();
        drop(state);
        let raw = std::fs::read(path.join(JOURNAL)).unwrap();
        assert!(!raw
            .windows(b"\"profile\"".len())
            .any(|v| v == b"\"profile\""));
        let state = InstallerState::resume(&path, &identity()).unwrap();
        assert_eq!(state.journal().runtime(), Some(&runtime));
        assert_eq!(state.journal().compose_project(), project);
        assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
    }
    #[test]
    fn explicit_rootless_runtime_profile_survives_private_journal_reopen() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("rootless-intent");
        let binding = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: "rootless-engine-identity".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootless,
        };
        let state =
            InstallerState::create_with_runtime(&path, identity(), binding.clone()).unwrap();
        drop(state);
        let raw = std::fs::read(path.join(JOURNAL)).unwrap();
        assert!(raw
            .windows(b"\"profile\":\"rootless\"".len())
            .any(|v| v == b"\"profile\":\"rootless\""));
        let resumed = InstallerState::resume(&path, &identity()).unwrap();
        assert_eq!(resumed.journal().runtime(), Some(&binding));
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
                profile: crate::installer_state::RuntimeProfile::Rootful,
            };
            assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
            assert!(!path.exists());
        }
        for (engine, port) in [("", 18200), ("engine id", 18200), ("engine-id", 443)] {
            let runtime = RuntimeBinding {
                docker_host: "unix:///run/docker.sock".into(),
                engine_id: engine.into(),
                openbao_port: port,
                profile: crate::installer_state::RuntimeProfile::Rootful,
            };
            assert!(InstallerState::create_with_runtime(&path, identity(), runtime).is_err());
            assert!(!path.exists());
        }
    }
    #[test]
    fn openbao_control_is_fresh_private_and_never_adopted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.create_private_directory("evidence").unwrap();
        assert!(state.prepare_openbao_control().is_err());
        assert!(!path.join("openbao-control").exists());
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state.prepare_openbao_control().unwrap();
        for entry in [
            "openbao-control",
            "openbao-control/socket",
            "openbao-control/identity",
        ] {
            let metadata = std::fs::symlink_metadata(path.join(entry)).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.mode() & 0o7777, 0o700);
        }
        let receipt = state
            .with_inspection(|view| view.read_evidence("openbao-control-created.json"))
            .unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        assert_eq!(
            receipt["installation_id"],
            state.journal().installation_id().to_string()
        );
        assert_eq!(receipt["enrolled"], false);
        assert!(state.prepare_openbao_control().is_err());
        assert!(state.require_live_phase(Phase::Provisioning).is_err());
    }
    #[test]
    fn renewal_directories_are_private_and_never_adopted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        for entry in [
            "renewal-inputs",
            "renewal-transfer",
            "generation-inputs",
            "generation-identity",
            "generation-transfer",
            "application-generation",
        ] {
            state.create_private_directory(entry).unwrap();
            assert_eq!(
                std::fs::metadata(path.join(entry)).unwrap().mode() & 0o777,
                0o700
            );
        }
        assert!(state.create_private_directory("renewal-transfer").is_err());
        assert!(state.require_live_phase(Phase::Initialized).is_err());
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
                profile: crate::installer_state::RuntimeProfile::Rootful,
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
        let scalar_pattern = regex::Regex::new(r"\A[0-9a-f]{64}\z").unwrap();
        for entry in SCALAR_SECRETS {
            let file = path.join("secrets").join(entry);
            let value = std::fs::read_to_string(&file).unwrap();
            assert!(scalar_pattern.is_match(&value));
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
    fn application_storage_is_private_exclusive_and_keeps_disabled_inputs_empty() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        assert!(state.prepare_application_storage().is_err());
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
            .unwrap();
        state.prepare_application_storage().unwrap();
        for entry in [
            "state",
            "state/postgres",
            "state/redis",
            "backups",
            "openbao-exports",
            "openbao-snapshot-identity",
        ] {
            let metadata = std::fs::metadata(path.join(entry)).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        let applicant = std::fs::metadata(path.join("state/applicant")).unwrap();
        assert_eq!(applicant.uid(), unsafe { libc::geteuid() });
        assert_eq!(applicant.gid(), applicant_state_gid().unwrap());
        assert_eq!(applicant.mode() & 0o7777, 0o2770);
        assert_eq!(
            state.validate_applicant_storage().unwrap(),
            applicant_state_gid().unwrap()
        );
        std::fs::set_permissions(
            path.join("state/applicant"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(state.validate_applicant_storage().is_err());
        for entry in crate::installer_application_env::OPTIONAL_EMPTY_SECRETS {
            let metadata = std::fs::metadata(path.join("secrets").join(entry)).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.len(), 0);
            assert_eq!(metadata.mode() & 0o777, 0o444);
        }
        assert!(state.prepare_application_storage().is_err());
        assert!(state.advance(Phase::Provisioned).is_err());
    }
    #[test]
    fn applicant_container_group_projects_only_a_validated_runtime() {
        let host_gid = applicant_state_gid().unwrap();
        let mut binding = RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        };
        let rootful = applicant_container_group(&binding).unwrap();
        assert_eq!(rootful.host_gid(), host_gid);
        assert_eq!(rootful.container_gid(), host_gid);
        assert_ne!(rootful.container_gid(), 0);
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(rootful.container_gid(), 10001);
        }
        binding.profile = RuntimeProfile::Rootless;
        binding.docker_host = format!("unix:///run/user/{}/docker.sock", unsafe {
            libc::geteuid()
        });
        if unsafe { libc::geteuid() } == 0 {
            assert!(applicant_container_group(&binding).is_err());
        } else {
            let rootless = applicant_container_group(&binding).unwrap();
            assert_eq!(rootless.host_gid(), host_gid);
            assert_ne!(rootless.host_gid(), 0);
            assert_eq!(rootless.container_gid(), 0);
        }
        binding.docker_host = "unix:///var/run/docker.sock".into();
        assert!(applicant_container_group(&binding).is_err());
        binding.profile = RuntimeProfile::Rootful;
        binding.engine_id = "bad".into();
        assert!(applicant_container_group(&binding).is_err());
    }

    #[test]
    fn applicant_state_group_is_nonroot_and_legacy_directory_is_not_adopted() {
        let expected = if unsafe { libc::geteuid() } == 0 {
            10001
        } else {
            unsafe { libc::getegid() }
        };
        assert_eq!(applicant_state_gid().unwrap(), expected);
        assert_ne!(expected, 0);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
            .unwrap();
        std::fs::create_dir(path.join("state")).unwrap();
        std::fs::create_dir(path.join("state/applicant")).unwrap();
        assert!(state.prepare_application_storage().is_err());
        assert!(path.join("state/applicant").is_dir());
        assert!(state.advance(Phase::Provisioned).is_err());
    }
    #[test]
    fn application_storage_never_follows_existing_state_link() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let mut state = InstallerState::create(&path, identity()).unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
            .unwrap();
        std::os::unix::fs::symlink(&outside, path.join("state")).unwrap();
        assert!(state.prepare_application_storage().is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert!(state.advance(Phase::Provisioned).is_err());
    }
    #[test]
    fn staged_operator_credential_preserves_private_original_and_refuses_replay() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = InstallerState::create(&path, identity()).unwrap();
        assert!(state.stage_operator_password().is_err());
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state
            .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
            .unwrap();
        state.stage_operator_password().unwrap();
        let original = path.join("operator-password");
        let staged = path.join("secrets/operator_bootstrap_password");
        assert_eq!(
            std::fs::read(&original).unwrap(),
            std::fs::read(&staged).unwrap()
        );
        assert_eq!(std::fs::metadata(&original).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&staged).unwrap().mode() & 0o777, 0o444);
        assert_eq!(
            std::fs::metadata(path.join("secrets")).unwrap().mode() & 0o777,
            0o700
        );
        assert!(state.stage_operator_password().is_err());
        assert!(state.advance(Phase::Provisioned).is_err());
    }
    #[test]
    fn staged_operator_credential_rejects_links_and_changed_values_before_writing() {
        for mutation in ["symlink", "hardlink", "public", "fifo", "value"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("install");
            let mut state = InstallerState::create(&path, identity()).unwrap();
            state.advance(Phase::Verified).unwrap();
            state.advance(Phase::Provisioning).unwrap();
            state
                .generate_local_credentials(&serde_json::json!({"passwordPolicy": PASSWORD_POLICY}))
                .unwrap();
            let original = path.join("operator-password");
            match mutation {
                "symlink" => {
                    std::fs::rename(&original, path.join("saved")).unwrap();
                    std::os::unix::fs::symlink(path.join("saved"), &original).unwrap();
                }
                "hardlink" => std::fs::hard_link(&original, path.join("saved")).unwrap(),
                "fifo" => {
                    std::fs::remove_file(&original).unwrap();
                    assert_eq!(
                        unsafe {
                            libc::mkfifo(
                                CString::new(original.as_os_str().as_bytes())
                                    .unwrap()
                                    .as_ptr(),
                                0o600,
                            )
                        },
                        0
                    );
                }
                "public" => {
                    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                _ => std::fs::write(&original, [b'x'; 69]).unwrap(),
            }
            assert!(
                state.stage_operator_password().is_err(),
                "accepted {mutation}"
            );
            assert!(!path.join("secrets/operator_bootstrap_password").exists());
        }
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

#[cfg(test)]
mod health_checkpoint_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn detached_evidence_never_reports_a_successful_health_publication() {
        for exchange_at in [1, 2] {
            let parent = tempfile::tempdir().unwrap();
            let path = parent.path().join("installation");
            let mut initial = InstallerState::create_with_runtime(
                &path,
                Identity {
                    source_sha: "a".repeat(40),
                    release_tag: "v1.2.3".into(),
                    inventory_sha256: format!("sha256:{}", "b".repeat(64)),
                },
                RuntimeBinding {
                    docker_host: "unix:///var/run/docker.sock".into(),
                    engine_id: "fixture-engine".into(),
                    openbao_port: 18443,
                    profile: RuntimeProfile::Rootful,
                },
            )
            .unwrap();
            initial.create_private_directory("evidence").unwrap();
            initial
                .write_evidence("health-checkpoint.json", b"current")
                .unwrap();
            drop(initial);
            let mut state = LockedMaintenance::open(&path).unwrap();
            let mut count = 0;
            let result =
                state.publish_health_checkpoint_observed(Some(b"current"), b"next", || {
                    count += 1;
                    if count == exchange_at {
                        std::fs::rename(path.join("evidence"), path.join("detached-evidence"))
                            .unwrap();
                        std::fs::create_dir(path.join("evidence")).unwrap();
                        std::fs::set_permissions(
                            path.join("evidence"),
                            std::fs::Permissions::from_mode(0o700),
                        )
                        .unwrap();
                        std::fs::write(path.join("evidence/health-checkpoint.json"), b"current")
                            .unwrap();
                        std::fs::set_permissions(
                            path.join("evidence/health-checkpoint.json"),
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }
                });
            assert_eq!(result.unwrap_err(), "evidence directory binding changed");
            assert_eq!(
                std::fs::read(path.join("evidence/health-checkpoint.json")).unwrap(),
                b"current"
            );
            // An uncertain publication poisons this writer before any caller
            // can treat the unchanged live budget as a successful debit.
            if exchange_at == 2 {
                assert!(state.require_unchanged().is_err());
            }
        }
    }
}
