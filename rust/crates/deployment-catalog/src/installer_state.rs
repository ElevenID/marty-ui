//! Linux installation journal. No provisioning or resource deletion occurs here.
//! Hold this object across all mutations. Enter Provisioning durably BEFORE any
//! non-idempotent operation; a crashed provisioning attempt requires reconciliation.
#![cfg(target_os = "linux")]

use crate::installer_creation_identity::{NewInstallation, RECEIPT as CREATION_RECEIPT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
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

/// Local scope evidence, not cryptographic authorization or nonce consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScope {
    pub authorization_sha256: String,
    pub context_sha256: String,
    pub consumption_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTestScope {
    pub inventory_sha256: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
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
    pub fn compose_project(&self) -> String {
        format!("marty-install-{}", self.installation_id.simple())
    }
    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        match &self.scope {
            ExecutionScope::AcceptanceOnly(scope) => scope.validate()?,
            ExecutionScope::CandidateTest(scope) => {
                scope.validate()?;
                if self.identity.inventory_sha256 != format!("sha256:{}", scope.inventory_sha256) {
                    return Err("candidate test inventory identity differs".into());
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
struct LockedDirectory {
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
fn lock(directory: File) -> Result<LockedDirectory> {
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(error("installation is locked"));
    }
    Ok(LockedDirectory {
        file: directory,
        owner_pid: unsafe { libc::getpid() },
        unlock_on_drop: true,
    })
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

/// Read-only recovery view. Holding this guard excludes an active installer or
/// another lifecycle operation, including while the journal is Provisioning.
/// It intentionally exposes no phase transition or provisioning replay API.
pub struct LockedInspection {
    directory: LockedDirectory,
    journal: Journal,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    NotStarted,
    InProgress,
    Completed,
}
/// Summary of durable cleanup records, never an observation of current Docker
/// resources. The installation journal remains historical and unchanged.
#[derive(Debug, Serialize)]
pub struct CleanupStatus {
    pub state: CleanupState,
    pub runtime_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_retained: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupResource {
    role: String,
    container_id: String,
    bao: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPlanRecord {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    network_id: String,
    network_name: String,
    retained_redis_volume: Option<String>,
    #[serde(default)]
    absent_redis_volume: Option<String>,
    resources: Vec<CleanupResource>,
    source_hashes: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupResultRecord {
    schema: String,
    installation_id: String,
    engine_id: String,
    containers_removed: u32,
    network_removed: bool,
    host_data_retained: bool,
    credentials_retained: bool,
    images_retained: bool,
    redis_volume_retained: Option<String>,
    #[serde(default)]
    redis_volume_absent: Option<String>,
    installation_ready: bool,
}
fn cleanup_open_optional(
    directory: &File,
    entry: &str,
    is_directory: bool,
) -> Result<Option<File>> {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if is_directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name(entry).as_ptr(), flags) };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("cleanup evidence cannot be safely inspected".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private(&file, is_directory)?;
    Ok(Some(file))
}
type CleanupRecords = (Option<Vec<u8>>, Option<Vec<u8>>);
fn cleanup_records(directory: &File) -> Result<CleanupRecords> {
    let Some(evidence) = cleanup_open_optional(directory, "evidence", true)? else {
        return Ok((None, None));
    };
    let mut records = Vec::new();
    for entry in ["uninstall-plan.json", "uninstall-result.json"] {
        let bytes = if let Some(file) = cleanup_open_optional(&evidence, entry, false)? {
            let mut bytes = Vec::new();
            file.take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "cleanup evidence cannot be read")?;
            if bytes.is_empty() || bytes.len() as u64 > LIMIT {
                return Err("cleanup evidence exceeds bounds".into());
            }
            Some(bytes)
        } else {
            None
        };
        records.push(bytes);
    }
    let result = records.pop().unwrap();
    let plan = records.pop().unwrap();
    Ok((plan, result))
}
fn cleanup_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn cleanup_summary(
    journal: &Journal,
    plan: Option<&[u8]>,
    result: Option<&[u8]>,
) -> Result<CleanupStatus> {
    const INVALID: &str = "cleanup evidence is invalid or differs from installation identity";
    let Some(plan) = plan else {
        if result.is_some() {
            return Err(INVALID.into());
        }
        return Ok(CleanupStatus {
            state: CleanupState::NotStarted,
            runtime_observed: false,
            data_retained: None,
        });
    };
    let plan: CleanupPlanRecord = serde_json::from_slice(plan).map_err(|_| INVALID)?;
    let pre_application = plan.schema == "elevenid.installer-uninstall-pre-application-plan/v1";
    let count = if pre_application { 4 } else { 34 };
    let binding = journal.runtime().ok_or(INVALID)?;
    let project = journal.compose_project();
    let roles: BTreeSet<_> = plan.resources.iter().map(|r| r.role.as_str()).collect();
    let identifiers: BTreeSet<_> = plan
        .resources
        .iter()
        .map(|r| r.container_id.as_str())
        .collect();
    let bao: BTreeSet<_> = plan
        .resources
        .iter()
        .filter(|r| r.bao)
        .map(|r| r.role.as_str())
        .collect();
    let mut expected_sources = BTreeSet::from([
        "evidence/application-plan.json",
        "evidence/application-compose.json",
        "evidence/application-created-resources.json",
        "root/openbao-created.json",
        "root/openbao-compose-model.json",
        "evidence/keycloak-container-removed.json",
        "evidence/tls-container-removed.json",
        "evidence/ingress-container-removed.json",
    ]);
    if plan
        .source_hashes
        .contains_key("evidence/renewal-container-removed.json")
    {
        expected_sources.insert("evidence/renewal-container-removed.json");
    }
    if plan
        .source_hashes
        .contains_key("evidence/generation-container-removed.json")
    {
        if !expected_sources.contains("evidence/renewal-container-removed.json") {
            return Err("generation cleanup lacks renewal authority evidence".into());
        }
        expected_sources.insert("evidence/generation-container-removed.json");
    }
    if plan
        .source_hashes
        .contains_key("evidence/application-generation.json")
    {
        if !expected_sources.contains("evidence/generation-container-removed.json") {
            return Err("application generation cleanup lacks candidate evidence".into());
        }
        expected_sources.insert("evidence/application-generation.json");
        expected_sources.insert("evidence/application-generation-pending.json");
        expected_sources.insert("evidence/application-generation-selection.json");
    }
    if pre_application {
        expected_sources.remove("evidence/application-created-resources.json");
        expected_sources.insert("evidence/application-start-intent.json");
        for (removed, completed) in [
            (
                "evidence/keycloak-container-removed.json",
                "evidence/keycloak-result.json",
            ),
            (
                "evidence/tls-container-removed.json",
                "evidence/tls-result.json",
            ),
            (
                "evidence/ingress-container-removed.json",
                "evidence/ingress-result.json",
            ),
            (
                "evidence/renewal-container-removed.json",
                "evidence/renewal-result.json",
            ),
            (
                "evidence/generation-container-removed.json",
                "evidence/generation-result.json",
            ),
        ] {
            if expected_sources.contains(removed) {
                expected_sources.insert(completed);
            }
        }
    }
    let redis = format!("{project}_redis-socket");
    let volume_valid = if pre_application {
        plan.retained_redis_volume.is_none()
            && plan.absent_redis_volume.as_deref() == Some(redis.as_str())
    } else {
        plan.retained_redis_volume.as_deref() == Some(redis.as_str())
            && plan.absent_redis_volume.is_none()
    };
    if (!pre_application && plan.schema != "elevenid.installer-uninstall-plan/v1")
        || (pre_application && journal.phase() != Phase::Provisioning)
        || plan.installation_id != journal.installation_id().to_string()
        || plan.engine_id != binding.engine_id
        || plan.project != project
        || !cleanup_hex(&plan.network_id)
        || plan.network_name != format!("{project}-bao_default")
        || !volume_valid
        || plan.resources.len() != count
        || roles.len() != count
        || identifiers.len() != count
        || !identifiers.iter().all(|s| cleanup_hex(s))
        || bao
            != BTreeSet::from([
                "openbao",
                "openbao-bootstrap",
                "openbao-tls-init",
                "openbao-unseal",
            ])
        || plan.resources.iter().any(|r| {
            r.role.is_empty()
                || r.role.len() > 128
                || !r
                    .role
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || plan
            .source_hashes
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_sources
        || !plan.source_hashes.values().all(|s| cleanup_hex(s))
    {
        return Err(INVALID.into());
    }
    let state = if let Some(bytes) = result {
        let result: CleanupResultRecord = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
        if result.schema
            != if pre_application {
                "elevenid.installer-uninstall-pre-application-result/v1"
            } else {
                "elevenid.installer-uninstall-result/v1"
            }
            || result.installation_id != plan.installation_id
            || result.engine_id != plan.engine_id
            || result.containers_removed as usize != plan.resources.len()
            || !result.network_removed
            || !result.host_data_retained
            || !result.credentials_retained
            || !result.images_retained
            || result.redis_volume_retained != plan.retained_redis_volume
            || result.redis_volume_absent != plan.absent_redis_volume
            || result.installation_ready
        {
            return Err(INVALID.into());
        }
        CleanupState::Completed
    } else {
        CleanupState::InProgress
    };
    let retained = if state == CleanupState::Completed {
        Some(true)
    } else {
        None
    };
    Ok(CleanupStatus {
        state,
        runtime_observed: false,
        data_retained: retained,
    })
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
        let file = open_at(&current, &name(entry), libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        private(&file, false)?;
        if !same(output, &file)? {
            return Err("validation report replaced".into());
        }
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
        let (ancestor, leaf) = parent(path)?;
        let directory = open_at(&ancestor, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&directory, true)?;
        let directory = lock(directory)?;
        let journal = read(&directory)?;
        Ok(Self { directory, journal })
    }
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
    /// The held descriptor keeps read-only inventory walks inside this installation.
    pub(crate) fn installation_directory(&self) -> &File {
        &self.directory
    }
    pub fn cleanup_status(&self) -> Result<CleanupStatus> {
        self.require_unchanged()?;
        let (plan, result) = cleanup_records(&self.directory)?;
        let summary = cleanup_summary(&self.journal, plan.as_deref(), result.as_deref())?;
        self.require_unchanged()?;
        Ok(summary)
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
        let file = open_at(&secrets, &name(entry), libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
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
            file,
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
        let file = open_at(
            &self.directory,
            &name("operator-password"),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        private(&file, false)?;
        self.read_credential_bytes(file, false)
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
        let file = open_at(
            &evidence,
            &name(entry),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        private(&file, false)?;
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
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
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

/// Exclusive cleanup access with append-only receipts. This deliberately has no
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
    pub(crate) fn journal(&self) -> &Journal {
        self.inspection.journal()
    }
    pub(crate) fn require_unchanged(&self) -> Result<()> {
        if self.poisoned {
            return Err("uncertain maintenance receipt; reopen and reconcile".into());
        }
        self.inspection.require_unchanged()
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
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
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
    pub(crate) fn read_record(&self, entry: &str) -> Result<Option<Vec<u8>>> {
        self.read_optional(&self.inspection.directory, entry)
    }
    pub(crate) fn read_evidence(&self, entry: &str) -> Result<Option<Vec<u8>>> {
        self.read_optional(&self.evidence()?, entry)
    }
    pub(crate) fn write_evidence_exclusive(&mut self, entry: &str, bytes: &[u8]) -> Result<()> {
        self.require_unchanged()?;
        let filename = Self::entry(entry)?;
        if !entry.starts_with("uninstall-") || bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
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
}

pub struct InstallerState {
    directory: LockedDirectory,
    journal: Journal,
    poisoned: bool,
    /// In-memory capture exists only for a newly created normal installation.
    /// Resumed and legacy installations can never reconstruct creation proof.
    creation: Option<NewInstallation>,
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
            // Call the Linux syscall directly: some musl versions do not export
            // a renameat2 libc wrapper. Preserve atomic NOREPLACE semantics;
            // unsupported kernels fail closed instead of falling back to rename.
            libc::syscall(
                libc::SYS_renameat2,
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
            || ![
                "downloads",
                "evidence",
                "openbao-state",
                "keycloak-output",
                "tls-output",
                "ingress-output",
                "renewal-inputs",
                "renewal-transfer",
                "generation-inputs",
                "generation-identity",
                "generation-transfer",
                "application-generation",
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
        self.poisoned = false;
        Ok(())
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
        for entry in ["postgres", "redis", "applicant"] {
            make(&state, entry)?;
        }
        for entry in ["backups", "openbao-exports", "openbao-snapshot-identity"] {
            make(&self.directory, entry)?;
        }
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
        self.poisoned = false;
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
        let mut source = open_at(
            &self.directory,
            &name("operator-password"),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        private(&source, false)?;
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
        let journal = Journal {
            schema: SCHEMA.into(),
            installation_id,
            identity,
            phase: Phase::Initialized,
            revision: 0,
            runtime,
            scope,
        };
        let mut state = Self {
            directory,
            journal: journal.clone(),
            poisoned: false,
            creation,
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
        let (cleanup_plan, cleanup_result) = cleanup_records(&directory)?;
        if cleanup_plan.is_some() || cleanup_result.is_some() {
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
        }
    }
    fn acceptance_runtime() -> RuntimeBinding {
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "01234567-89ab-cdef".into(),
            openbao_port: 18200,
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
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn identity() -> Identity {
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        }
    }
    fn cleanup_test_records(journal: &Journal) -> (serde_json::Value, serde_json::Value) {
        use serde_json::json;
        let project = journal.compose_project();
        let mut resources:Vec<_>=(0..30).map(|i|json!({"role":format!("app-{i}"),"container_id":format!("{:064x}",i+1),"bao":false})).collect();
        for (i, role) in [
            "openbao",
            "openbao-unseal",
            "openbao-bootstrap",
            "openbao-tls-init",
        ]
        .into_iter()
        .enumerate()
        {
            resources.push(json!({"role":role,"container_id":format!("{:064x}",i+40),"bao":true}));
        }
        let sources: BTreeMap<_, _> = [
            "evidence/application-plan.json",
            "evidence/application-compose.json",
            "evidence/application-created-resources.json",
            "root/openbao-created.json",
            "root/openbao-compose-model.json",
            "evidence/keycloak-container-removed.json",
            "evidence/tls-container-removed.json",
            "evidence/ingress-container-removed.json",
        ]
        .into_iter()
        .map(|s| (s, "a".repeat(64)))
        .collect();
        let plan = json!({"schema":"elevenid.installer-uninstall-plan/v1","installation_id":journal.installation_id(),"engine_id":journal.runtime().unwrap().engine_id,"project":project,"network_id":"b".repeat(64),"network_name":format!("{project}-bao_default"),"retained_redis_volume":format!("{project}_redis-socket"),"resources":resources,"source_hashes":sources});
        let result = json!({"schema":"elevenid.installer-uninstall-result/v1","installation_id":journal.installation_id(),"engine_id":journal.runtime().unwrap().engine_id,"containers_removed":34,"network_removed":true,"host_data_retained":true,"credentials_retained":true,"images_retained":true,"redis_volume_retained":format!("{project}_redis-socket"),"installation_ready":false});
        (plan, result)
    }
    fn cleanup_test_state(path: &Path) -> InstallerState {
        InstallerState::create_with_runtime(
            path,
            identity(),
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18200,
            },
        )
        .unwrap()
    }
    #[test]
    fn cleanup_summary_accepts_exact_renewal_receipt_hash_but_no_unknown_sources() {
        let root = tempfile::tempdir().unwrap();
        let state = cleanup_test_state(&root.path().join("install"));
        let (mut plan, result) = cleanup_test_records(state.journal());
        plan["source_hashes"]["evidence/renewal-container-removed.json"] =
            serde_json::json!("b".repeat(64));
        let summary = cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            Some(&serde_json::to_vec(&result).unwrap()),
        )
        .unwrap();
        assert_eq!(summary.state, CleanupState::Completed);
        plan["source_hashes"]["evidence/generation-container-removed.json"] =
            serde_json::json!("d".repeat(64));
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            None
        )
        .is_ok());
        plan["source_hashes"]["evidence/application-generation.json"] =
            serde_json::json!("e".repeat(64));
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            None
        )
        .is_err());
        plan["source_hashes"]["evidence/application-generation-pending.json"] =
            serde_json::json!("f".repeat(64));
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            None
        )
        .is_err());
        plan["source_hashes"]["evidence/application-generation-selection.json"] =
            serde_json::json!("a".repeat(64));
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            None
        )
        .is_ok());
        let mut missing_candidate = plan.clone();
        missing_candidate["source_hashes"]
            .as_object_mut()
            .unwrap()
            .remove("evidence/generation-container-removed.json");
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&missing_candidate).unwrap()),
            None
        )
        .is_err());
        let mut missing_renewal = plan.clone();
        missing_renewal["source_hashes"]
            .as_object_mut()
            .unwrap()
            .remove("evidence/renewal-container-removed.json");
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&missing_renewal).unwrap()),
            None
        )
        .is_err());
        plan["source_hashes"]["evidence/unknown-container-removed.json"] =
            serde_json::json!("c".repeat(64));
        assert!(cleanup_summary(
            state.journal(),
            Some(&serde_json::to_vec(&plan).unwrap()),
            None
        )
        .is_err());
    }
    #[test]
    fn cleanup_summary_tracks_records_without_changing_historical_ready_journal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let mut state = cleanup_test_state(&path);
        for phase in [
            Phase::Verified,
            Phase::Provisioning,
            Phase::Provisioned,
            Phase::Ready,
        ] {
            state.advance(phase).unwrap();
        }
        state.create_private_directory("evidence").unwrap();
        let (plan, result) = cleanup_test_records(state.journal());
        state
            .write_evidence("uninstall-plan.json", &serde_json::to_vec(&plan).unwrap())
            .unwrap();
        drop(state);
        let before = std::fs::read(path.join(JOURNAL)).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
        let inspection = LockedInspection::open(&path).unwrap();
        let status = inspection.cleanup_status().unwrap();
        assert_eq!(status.state, CleanupState::InProgress);
        assert!(!status.runtime_observed);
        assert!(status.data_retained.is_none());
        drop(inspection);
        let mut maintenance = LockedMaintenance::open(&path).unwrap();
        maintenance
            .write_evidence_exclusive(
                "uninstall-result.json",
                &serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
        drop(maintenance);
        let inspection = LockedInspection::open(&path).unwrap();
        let status = inspection.cleanup_status().unwrap();
        assert_eq!(status.state, CleanupState::Completed);
        assert_eq!(status.data_retained, Some(true));
        assert_eq!(inspection.journal().phase(), Phase::Ready);
        drop(inspection);
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), before);
    }
    #[test]
    fn cleanup_absence_allows_initialized_resume_but_uncertain_records_refuse() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        drop(cleanup_test_state(&path));
        let inspection = LockedInspection::open(&path).unwrap();
        assert_eq!(
            inspection.cleanup_status().unwrap().state,
            CleanupState::NotStarted
        );
        drop(inspection);
        let mut resumed = InstallerState::resume(&path, &identity()).unwrap();
        resumed.create_private_directory("evidence").unwrap();
        drop(resumed);
        let target = path.join("evidence/uninstall-plan.json");
        std::fs::write(&target, b"malformed").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert!(LockedInspection::open(&path)
            .unwrap()
            .cleanup_status()
            .is_err());
        std::fs::remove_file(&target).unwrap();
        symlink("absent.json", &target).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
        assert!(LockedInspection::open(&path)
            .unwrap()
            .cleanup_status()
            .is_err());
        std::fs::remove_file(&target).unwrap();
        std::fs::write(&target, b"{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(InstallerState::resume(&path, &identity()).is_err());
    }
    #[test]
    fn cleanup_summary_refuses_orphan_result_and_identity_or_binding_changes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let state = cleanup_test_state(&path);
        let (plan, result) = cleanup_test_records(state.journal());
        let encode = |v: &serde_json::Value| serde_json::to_vec(v).unwrap();
        let valid_plan = encode(&plan);
        let valid_result = encode(&result);
        assert!(cleanup_summary(state.journal(), None, Some(&valid_result)).is_err());
        for (field, value) in [
            ("installation_id", serde_json::json!(uuid::Uuid::new_v4())),
            ("engine_id", serde_json::json!("other")),
            ("project", serde_json::json!("other")),
            ("network_name", serde_json::json!("other")),
        ] {
            let mut bad = plan.clone();
            bad[field] = value;
            assert!(cleanup_summary(state.journal(), Some(&encode(&bad)), None).is_err());
        }
        for (field, value) in [
            ("installation_id", serde_json::json!(uuid::Uuid::new_v4())),
            ("engine_id", serde_json::json!("other")),
            ("redis_volume_retained", serde_json::json!("other")),
            ("containers_removed", serde_json::json!(33)),
            ("host_data_retained", serde_json::json!(false)),
        ] {
            let mut bad = result.clone();
            bad[field] = value;
            assert!(
                cleanup_summary(state.journal(), Some(&valid_plan), Some(&encode(&bad))).is_err()
            );
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
        assert!(maintenance.read_record("absent.json").unwrap().is_none());
        assert!(maintenance.read_record("../outside").is_err());
        symlink("absent.json", path.join("linked.json")).unwrap();
        assert!(maintenance.read_record("linked.json").is_err());
        let record = path.join("record.json");
        std::fs::write(&record, b"{}").unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(maintenance.read_record("record.json").is_err());
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            maintenance.read_record("record.json").unwrap().unwrap(),
            b"{}"
        );
        std::fs::hard_link(&record, path.join("hard.json")).unwrap();
        assert!(maintenance.read_record("record.json").is_err());
        std::fs::write(path.join(JOURNAL), b"{}").unwrap();
        assert!(maintenance.read_record("absent.json").is_err());
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
            "state/applicant",
            "backups",
            "openbao-exports",
            "openbao-snapshot-identity",
        ] {
            let metadata = std::fs::metadata(path.join(entry)).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
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
