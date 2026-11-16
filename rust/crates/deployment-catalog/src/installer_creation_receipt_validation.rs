//! Read-only local creation evidence for the seven storage boundaries, including
//! the OpenBao initializer's recorded owner transition. Historical evidence is
//! not cryptographic authentication or deletion authorization. Current children,
//! full installation coverage and lifecycle readiness remain outside this module.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // No purge coordinator exists yet.

use crate::{
    installer_creation_identity::{
        observe, observe_operator, ObservedDirectory, ObservedFile, APPLICATION_RECEIPT,
        CREDENTIAL_RECEIPT, OPENBAO_OWNER_TRANSITION_RECEIPT, OPENBAO_STATE_RECEIPT, RECEIPT,
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
    operator_password: Option<RawFile>,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
/// Current local identity evidence only. Password/scalar contents are never
/// read. This does not inventory the contents of the secrets directory.
#[derive(PartialEq, Eq)]
pub(crate) struct ObservedCredentialCreation {
    pub initial: ObservedInitialCreation,
    pub secrets: ObservedDirectory,
    pub operator_password: Option<ObservedFile>,
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
        || !matches!(
            receipt.schema.as_str(),
            "elevenid.installer-created-credentials/v1"
                | "elevenid.installer-created-credentials/v2"
        )
        || (receipt.schema == "elevenid.installer-created-credentials/v1"
            && receipt.operator_password.is_none())
        || receipt.installation_id != locked.journal().installation_id()
        || receipt.source_sha != locked.journal().identity().source_sha
        || !receipt.local_historical_evidence
        || receipt.deletion_authorized
        || observe(&evidence).map_err(|_| ())? != initial.evidence
    {
        return Err(());
    }
    let secrets = child(root, "secrets", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let operator = child(root, "operator-password", libc::O_PATH)?;
    let observed_secrets = observe(&secrets).map_err(|_| ())?;
    let observed_operator = operator
        .as_ref()
        .map(observe_operator)
        .transpose()
        .map_err(|_| ())?;
    if !receipt.secrets.matches(&observed_secrets)
        || !match (&receipt.operator_password, &observed_operator) {
            (Some(recorded), Some(observed)) => recorded.matches(observed),
            (None, None) => true,
            _ => false,
        }
        || observed_secrets.mount_id != initial.root.mount_id
        || observed_operator
            .as_ref()
            .is_some_and(|observed| observed.mount_id != initial.root.mount_id)
    {
        return Err(());
    }
    let latest_secrets = child(root, "secrets", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let latest_operator = child(root, "operator-password", libc::O_PATH)?;
    let latest_record = child(&evidence, CREDENTIAL_RECEIPT, libc::O_PATH)?.ok_or(())?;
    let before = record.metadata().map_err(|_| ())?;
    let after = latest_record.metadata().map_err(|_| ())?;
    if observe(&latest_secrets).map_err(|_| ())? != observed_secrets
        || latest_operator
            .as_ref()
            .map(observe_operator)
            .transpose()
            .map_err(|_| ())?
            != observed_operator
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
#[derive(PartialEq, Eq)]
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBaoStateReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    openbao_state: RawDirectory,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerTransitionReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    engine_id: String,
    image: String,
    image_id: String,
    tls_init_container_id: String,
    initial_receipt_sha256: String,
    state_creation_receipt_sha256: String,
    tls_init_completion_sha256: String,
    root: ObservedDirectory,
    evidence: ObservedDirectory,
    openbao_state_before: ObservedDirectory,
    openbao_state_after: ObservedDirectory,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBaoCreated {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    image: String,
    image_id: String,
    network_id: String,
    container_ids: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsCompletion {
    role: String,
    container_id: String,
    exit_code: i32,
}
/// Local identity evidence for all seven storage boundaries (six directories
/// and the operator-password file). No descendants are read or authorized for
/// deletion. Foreign-owned OpenBao data may remain inaccessible to the caller.
#[derive(PartialEq, Eq)]
pub(crate) struct ObservedNormalCreation {
    pub application: ObservedApplicationCreation,
    pub openbao_state: ObservedDirectory,
    pub state_receipt_sha256: String,
    pub transition_receipt_sha256: String,
    pub created_record_sha256: String,
    pub completion_sha256: String,
    pub native_storage_roots: BTreeMap<String, ObservedDirectory>,
    pub native_receipts_sha256: BTreeMap<String, String>,
}
pub(crate) enum NormalInspectionOutcome {
    Missing,
    Unusable,
    MatchedLocalReceipt(Box<ObservedNormalCreation>),
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read_record(parent: &File, name: &str) -> Result<Option<(File, Vec<u8>)>> {
    child(parent, name, libc::O_PATH)?
        .map(|held| Ok((held.try_clone().map_err(|_| ())?, read_regular(&held)?)))
        .transpose()
}
fn unchanged_record(parent: &File, name: &str, held: &File, bytes: &[u8]) -> Result<()> {
    let current = child(parent, name, libc::O_PATH)?.ok_or(())?;
    let before = held.metadata().map_err(|_| ())?;
    let after = current.metadata().map_err(|_| ())?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || read_regular(&current)? != bytes
    {
        return Err(());
    }
    Ok(())
}
fn verify_normal_with_profile(
    locked: &LockedInspection,
    installation: &Path,
    native: bool,
) -> Result<Option<ObservedNormalCreation>> {
    let Some(application) = verify_application(locked, installation)? else {
        return Ok(None);
    };
    let root = locked.installation_directory();
    let evidence = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let Some((state_record, state_bytes)) = read_record(&evidence, OPENBAO_STATE_RECEIPT)? else {
        return Ok(None);
    };
    let Some((transition_record, transition_bytes)) =
        read_record(&evidence, OPENBAO_OWNER_TRANSITION_RECEIPT)?
    else {
        return Ok(None);
    };
    let created_parent = if native { &evidence } else { root };
    let created_name = if native {
        "compose-openbao-private-inputs.json"
    } else {
        "openbao-created.json"
    };
    let Some((created_record, created_bytes)) = read_record(created_parent, created_name)? else {
        return Ok(None);
    };
    let Some((completion_record, completion_bytes)) =
        read_record(root, "openbao-completed-openbao-tls-init.json")?
    else {
        return Ok(None);
    };
    let initial = &application.credentials.initial;
    let state: OpenBaoStateReceipt = serde_json::from_slice(&state_bytes).map_err(|_| ())?;
    let transition: OwnerTransitionReceipt =
        serde_json::from_slice(&transition_bytes).map_err(|_| ())?;
    let completion: TlsCompletion = serde_json::from_slice(&completion_bytes).map_err(|_| ())?;
    let binding = locked.journal().runtime().ok_or(())?;
    let uuid = locked.journal().installation_id();
    let source = &locked.journal().identity().source_sha;
    let roles = [
        "openbao-tls-init",
        "openbao",
        "openbao-unseal",
        "openbao-bootstrap",
    ];
    let after = &transition.openbao_state_after;
    let before = &transition.openbao_state_before;
    if serde_json::to_vec(&state).map_err(|_| ())? != state_bytes
        || serde_json::to_vec(&transition).map_err(|_| ())? != transition_bytes
        || state.schema != "elevenid.installer-created-openbao-state/v1"
        || transition.schema != "elevenid.installer-openbao-state-owner-transition/v1"
        || state.installation_id != uuid
        || transition.installation_id != uuid
        || state.source_sha != *source
        || transition.source_sha != *source
        || !state.local_historical_evidence
        || !transition.local_historical_evidence
        || state.deletion_authorized
        || transition.deletion_authorized
        || !state.openbao_state.matches(before)
        || before.mount_id != initial.root.mount_id
        || after.mount_id != before.mount_id
        || before.identity.dev != after.identity.dev
        || before.identity.ino != after.identity.ino
        || before.identity.kind != after.identity.kind
        || before.identity.mode != after.identity.mode
        || transition.root != initial.root
        || transition.evidence != initial.evidence
        || transition.initial_receipt_sha256 != initial.receipt_sha256
        || transition.state_creation_receipt_sha256 != digest(&state_bytes)
        || transition.tls_init_completion_sha256 != digest(&completion_bytes)
        || transition.engine_id != binding.engine_id
        || completion.role != "openbao-tls-init"
        || completion.exit_code != 0
        || completion.container_id != transition.tls_init_container_id
    {
        return Err(());
    }
    if native {
        verify_native_custody(locked, installation, &created_bytes, &transition)?;
    } else {
        let created: OpenBaoCreated = serde_json::from_slice(&created_bytes).map_err(|_| ())?;
        if created.schema != "elevenid.installer-openbao-created/v1"
            || created.installation_id != uuid.to_string()
            || created.engine_id != binding.engine_id
            || created.project != format!("{}-bao", locked.journal().compose_project())
            || !hex64(&created.network_id)
            || created.image != transition.image
            || created.image_id != transition.image_id
            || !created
                .image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:")
                .is_some_and(hex64)
            || !created.image_id.strip_prefix("sha256:").is_some_and(hex64)
            || created.container_ids.len() != roles.len()
            || !roles
                .iter()
                .all(|role| created.container_ids.get(*role).is_some_and(|id| hex64(id)))
            || created
                .container_ids
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != roles.len()
            || created.container_ids.get("openbao-tls-init")
                != Some(&transition.tls_init_container_id)
        {
            return Err(());
        }
    }
    // O_PATH works for metadata even after TLS init changes the owner of a
    // mode-0700 directory. Never open or enumerate its secret-bearing children.
    let held = child(root, "openbao-state", libc::O_PATH)?.ok_or(())?;
    let observed = observe(&held).map_err(|_| ())?;
    if observed != *after || observe(&evidence).map_err(|_| ())? != initial.evidence {
        return Err(());
    }
    for (parent, name, file, bytes) in [
        (
            &evidence,
            OPENBAO_STATE_RECEIPT,
            &state_record,
            &state_bytes,
        ),
        (
            &evidence,
            OPENBAO_OWNER_TRANSITION_RECEIPT,
            &transition_record,
            &transition_bytes,
        ),
        (
            created_parent,
            created_name,
            &created_record,
            &created_bytes,
        ),
        (
            root,
            "openbao-completed-openbao-tls-init.json",
            &completion_record,
            &completion_bytes,
        ),
    ] {
        unchanged_record(parent, name, file, bytes)?;
    }
    let latest = child(root, "openbao-state", libc::O_PATH)?.ok_or(())?;
    if observe(&held).map_err(|_| ())? != observed
        || observe(&latest).map_err(|_| ())? != observed
        || verify_application(locked, installation)?.ok_or(())? != application
    {
        return Err(());
    }
    let (native_storage_roots, native_receipts_sha256) = if native {
        verify_native_storage_roots(locked, installation, &application, &observed)?
    } else {
        (BTreeMap::new(), BTreeMap::new())
    };
    Ok(Some(ObservedNormalCreation {
        application,
        openbao_state: observed,
        state_receipt_sha256: digest(&state_bytes),
        transition_receipt_sha256: digest(&transition_bytes),
        created_record_sha256: digest(&created_bytes),
        completion_sha256: digest(&completion_bytes),
        native_storage_roots,
        native_receipts_sha256,
    }))
}
/// Native Compose custody is bound to the current initial-session owner and
/// the exact original state-root transition. No Docker mutation or key reads.
fn verify_native_custody(
    locked: &LockedInspection,
    installation: &Path,
    bytes: &[u8],
    transition: &OwnerTransitionReceipt,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Directory {
        dev: u64,
        ino: u64,
        uid: u32,
        gid: u32,
        mode: u32,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Custody {
        schema: String,
        project: String,
        engine_id: String,
        tls_container_id: String,
        tls_image: String,
        directory: Directory,
    }
    let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    if serde_json::to_vec(&raw).map_err(|_| ())? != bytes {
        return Err(());
    }
    let custody: Custody = serde_json::from_slice(bytes).map_err(|_| ())?;
    let saved =
        crate::installer_doctor::load_initial_session(locked, installation).map_err(|_| ())?;
    let tls = saved
        .receipt
        .resources
        .as_ref()
        .and_then(|r| r.containers.get("openbao-tls-init"))
        .ok_or(())?;
    let after = &transition.openbao_state_after.identity;
    if custody.schema != "elevenid.installer-openbao-private-inputs/v1"
        || custody.project != locked.journal().compose_project()
        || custody.engine_id != transition.engine_id
        || custody.tls_container_id != transition.tls_init_container_id
        || custody.tls_container_id != tls.id
        || custody.tls_image != tls.image
        || custody.tls_image != transition.image
        || !saved.inputs.approved_images.contains(&custody.tls_image)
        || !tls.setup
        || !tls
            .setup_execution
            .as_ref()
            .is_some_and(|e| e.completed_without_restart)
        || saved
            .receipt
            .input_files
            .get(&installation.join("evidence/compose-openbao-private-inputs.json"))
            != Some(&digest(bytes))
        || (
            custody.directory.dev,
            custody.directory.ino,
            custody.directory.uid,
            custody.directory.gid,
            custody.directory.mode,
        ) != (after.dev, after.ino, after.uid, after.gid, after.mode)
        || after.uid == unsafe { libc::geteuid() }
        || !transition
            .image_id
            .strip_prefix("sha256:")
            .is_some_and(hex64)
        || !transition
            .image
            .strip_prefix("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:")
            .is_some_and(hex64)
    {
        return Err(());
    }
    Ok(())
}

/// Metadata of the newly introduced control and seal roots. Existing owner
/// verifiers and receipt bindings remain required; current names alone cannot
/// become historical ownership. Secret-bearing child file contents are unread.
fn verify_native_storage_roots(
    locked: &LockedInspection,
    installation: &Path,
    application: &ObservedApplicationCreation,
    openbao_state: &ObservedDirectory,
) -> Result<(
    BTreeMap<String, ObservedDirectory>,
    BTreeMap<String, String>,
)> {
    use crate::installer_top_level_census::{current_native_profile, CensusProfile};
    let profile = current_native_profile(locked, installation).map_err(|_| ())?;
    let CensusProfile::NativeComposeV2 {
        local_operator_password,
    } = profile
    else {
        return Err(());
    };
    if local_operator_password != application.credentials.operator_password.is_some() {
        return Err(());
    }
    let root = locked.installation_directory();
    let evidence = child(root, "evidence", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
    let mut observations = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut held_records = Vec::new();
    let mut control_children = BTreeMap::new();
    let field_matches = |value: &serde_json::Value, directory: &ObservedDirectory| {
        value["device"] == directory.identity.dev
            && value["inode"] == directory.identity.ino
            && value["owner_uid"] == directory.identity.uid
            && value["owner_gid"] == directory.identity.gid
            && value["mode"] == directory.identity.mode
    };
    for (name, record) in [
        ("openbao-control", "openbao-control-created.json"),
        ("openbao-seal", crate::installer_openbao_seal::RECORD),
    ] {
        let held = child(root, name, libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
        let observed = observe(&held).map_err(|_| ())?;
        if observed.mount_id != application.credentials.initial.root.mount_id
            || observed.identity.dev != application.credentials.initial.root.identity.dev
            || observed.identity.uid != unsafe { libc::geteuid() }
            || observed.identity.mode != 0o700
        {
            return Err(());
        }
        let (file, bytes) = read_record(&evidence, record)?.ok_or(())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if serde_json::to_vec(&value).map_err(|_| ())? != bytes
            || value["installation_id"] != locked.journal().installation_id().to_string()
        {
            return Err(());
        }
        if name == "openbao-seal" {
            crate::installer_openbao_seal::verify(locked, installation).map_err(|_| ())?;
            if !field_matches(&value["outer"], &observed) {
                return Err(());
            }
        } else {
            if value["schema"] != "elevenid.installer-openbao-control-created/v1"
                || value["enrolled"] != false
                || !field_matches(&value, &observed)
                || value.as_object().is_none_or(|v| v.len() != 9)
                || value["children"].as_object().is_none_or(|v| v.len() != 2)
                || ["socket", "identity"].into_iter().any(|child| {
                    value["children"][child]
                        .as_object()
                        .is_none_or(|v| v.len() != 5)
                })
            {
                return Err(());
            }
            let identity =
                child(&held, "identity", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(())?;
            let identity_observed = observe(&identity).map_err(|_| ())?;
            let socket = child(&held, "socket", libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
            let socket_observed = observe(&socket).map_err(|_| ())?;
            let before = &value["children"]["socket"];
            if !field_matches(&value["children"]["identity"], &identity_observed)
                || identity_observed.mount_id != observed.mount_id
                || socket_observed.mount_id != observed.mount_id
                || before["device"] != socket_observed.identity.dev
                || before["inode"] != socket_observed.identity.ino
                || before["owner_uid"] != observed.identity.uid
                || before["owner_gid"] != observed.identity.gid
                || before["mode"] != 0o700
                || socket_observed.identity.mode != 0o700
                || socket_observed.identity.uid != openbao_state.identity.uid
                || socket_observed.identity.gid != openbao_state.identity.gid
            {
                return Err(());
            }
            control_children.insert("identity", identity_observed);
            control_children.insert("socket", socket_observed);
        }
        unchanged_record(&evidence, record, &file, &bytes)?;
        let latest = child(root, name, libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
        if observe(&latest).map_err(|_| ())? != observed {
            return Err(());
        }
        observations.insert(name.to_owned(), observed);
        records.insert(record.to_owned(), digest(&bytes));
        held_records.push((record, file, bytes));
    }
    for (name, file, bytes) in &held_records {
        unchanged_record(&evidence, name, file, bytes)?;
    }
    for (name, expected) in &observations {
        let current = child(root, name, libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
        if observe(&current).map_err(|_| ())? != *expected {
            return Err(());
        }
    }
    crate::installer_openbao_seal::verify(locked, installation).map_err(|_| ())?;
    if current_native_profile(locked, installation).map_err(|_| ())? != profile
        || verify_application(locked, installation)?.as_ref() != Some(application)
    {
        return Err(());
    }
    require_current_control_children(root, &observations["openbao-control"], &control_children)?;
    Ok((observations, records))
}

fn require_current_control_children(
    root: &File,
    expected_control: &ObservedDirectory,
    expected: &BTreeMap<&str, ObservedDirectory>,
) -> Result<()> {
    if expected.len() != 2
        || !["identity", "socket"]
            .iter()
            .all(|name| expected.contains_key(name))
    {
        return Err(());
    }
    let control = child(root, "openbao-control", libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
    if observe(&control).map_err(|_| ())? != *expected_control {
        return Err(());
    }
    for (name, snapshot) in expected {
        // O_PATH observes mapped socket metadata without opening its private
        // contents or changing ownership/permissions to make it readable.
        let current = child(&control, name, libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
        if observe(&current).map_err(|_| ())? != *snapshot {
            return Err(());
        }
    }
    let current_control =
        child(root, "openbao-control", libc::O_PATH | libc::O_DIRECTORY)?.ok_or(())?;
    if observe(&current_control).map_err(|_| ())? != *expected_control
        || observe(&control).map_err(|_| ())? != *expected_control
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn inspect_native_normal(
    locked: &LockedInspection,
    installation: &Path,
) -> NormalInspectionOutcome {
    let result = verify_normal_with_profile(locked, installation, true);
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return NormalInspectionOutcome::Unusable;
    }
    match result {
        Ok(Some(observed)) => NormalInspectionOutcome::MatchedLocalReceipt(Box::new(observed)),
        Ok(None) => NormalInspectionOutcome::Missing,
        Err(()) => NormalInspectionOutcome::Unusable,
    }
}

pub(crate) fn inspect_normal(
    locked: &LockedInspection,
    installation: &Path,
) -> NormalInspectionOutcome {
    let result = verify_normal_with_profile(locked, installation, false);
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return NormalInspectionOutcome::Unusable;
    }
    match result {
        Ok(Some(observed)) => NormalInspectionOutcome::MatchedLocalReceipt(Box::new(observed)),
        Ok(None) => NormalInspectionOutcome::Missing,
        Err(()) => NormalInspectionOutcome::Unusable,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };
    #[test]
    fn native_control_child_replacement_after_initial_observation_is_refused() {
        for replaced in ["identity", "socket"] {
            let temp = tempfile::tempdir().unwrap();
            let control = temp.path().join("openbao-control");
            fs::create_dir(&control).unwrap();
            fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
            let mut snapshots = BTreeMap::new();
            for name in ["identity", "socket"] {
                let path = control.join(name);
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                snapshots.insert(name, observe(&File::open(path).unwrap()).unwrap());
            }
            let root = File::open(temp.path()).unwrap();
            let outer = observe(&File::open(&control).unwrap()).unwrap();
            assert!(require_current_control_children(&root, &outer, &snapshots).is_ok());
            // Preserve the original inode, so the new directory cannot reuse it.
            fs::rename(control.join(replaced), temp.path().join("prior-child")).unwrap();
            fs::create_dir(control.join(replaced)).unwrap();
            fs::set_permissions(control.join(replaced), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                require_current_control_children(&root, &outer, &snapshots).is_err(),
                "{replaced}"
            );
        }
    }
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
                profile: crate::installer_state::RuntimeProfile::Rootful,
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
    pub(crate) fn normal_fixture() -> (tempfile::TempDir, PathBuf, InstallerState) {
        normal_fixture_with_chown(false, |_| {})
    }
    struct RestoreRootOnUnwind(bool);
    impl Drop for RestoreRootOnUnwind {
        fn drop(&mut self) {
            if self.0 && std::thread::panicking() {
                assert_eq!(unsafe { libc::seteuid(0) }, 0);
            }
        }
    }
    fn normal_fixture_with_chown(
        change_owner: bool,
        after_chown: impl FnOnce(&Path),
    ) -> (tempfile::TempDir, PathBuf, InstallerState) {
        let (parent, path, mut state) = application_fixture();
        // Declared after TempDir, so it regains root before the foreign-owned
        // fixture is dropped if a qualification assertion fails inside here.
        let _restore_before_cleanup = RestoreRootOnUnwind(change_owner);
        state.create_private_directory("openbao-state").unwrap();
        state.persist_openbao_state_creation_receipt(&path).unwrap();
        let ids: BTreeMap<_, _> = [
            "openbao-tls-init",
            "openbao",
            "openbao-unseal",
            "openbao-bootstrap",
        ]
        .into_iter()
        .enumerate()
        .map(|(i, role)| (role, format!("{:064x}", i + 1)))
        .collect();
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
            "b".repeat(64)
        );
        let image_id = format!("sha256:{}", "d".repeat(64));
        let completion = serde_json::to_vec(&serde_json::json!({"role":"openbao-tls-init", "container_id":ids["openbao-tls-init"], "exit_code":0})).unwrap();
        let created = serde_json::to_vec(&serde_json::json!({
            "schema":"elevenid.installer-openbao-created/v1", "installation_id":state.journal().installation_id().to_string(),
            "engine_id":"synthetic-engine", "project":format!("{}-bao", state.journal().compose_project()),
            "image":image,"image_id":image_id,"network_id":"e".repeat(64),"container_ids":ids
        })).unwrap();
        for (name, bytes) in [
            ("openbao-created.json", created),
            (
                "openbao-completed-openbao-tls-init.json",
                completion.clone(),
            ),
        ] {
            fs::write(path.join(name), bytes).unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        if change_owner {
            // Used only by the isolated, opt-in root qualification below.
            // Hold the fixture inode before changing its owner; no Docker or
            // installation outside this synthetic temp directory is touched.
            assert_eq!(unsafe { libc::getuid() }, 0);
            let held = File::open(path.join("openbao-state")).unwrap();
            assert_eq!(unsafe { libc::seteuid(0) }, 0);
            assert_eq!(unsafe { libc::fchown(held.as_raw_fd(), 100, 65534) }, 0);
            assert_eq!(unsafe { libc::seteuid(65534) }, 0);
        }
        after_chown(&path);
        state
            .persist_openbao_owner_transition_receipt(
                &path,
                "synthetic-engine",
                &image,
                &image_id,
                &ids["openbao-tls-init"],
                &completion,
            )
            .unwrap();
        (parent, path, state)
    }
    #[test]
    #[ignore = "requires isolated root runner with --exact --ignored --test-threads=1"]
    fn foreign_owned_private_openbao_metadata_qualification() {
        let args: Vec<_> = std::env::args().collect();
        assert!(
            ["--exact", "--ignored", "--test-threads=1", "installer_creation_receipt_validation::tests::foreign_owned_private_openbao_metadata_qualification"]
                .iter().all(|required| args.iter().any(|arg| arg.as_str() == *required)),
            "select only this qualification in a single-threaded test process"
        );
        assert_eq!(unsafe { libc::getuid() }, 0);
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run only in an isolated root test process"
        );
        struct RestoreIdentity(libc::gid_t);
        impl Drop for RestoreIdentity {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::seteuid(0) }, 0);
                assert_eq!(unsafe { libc::setegid(self.0) }, 0);
            }
        }
        let original_gid = unsafe { libc::getegid() };
        let restore = RestoreIdentity(original_gid);
        assert_eq!(unsafe { libc::setegid(65534) }, 0);
        assert_eq!(unsafe { libc::seteuid(65534) }, 0);
        let (parent, path, state) = normal_fixture_with_chown(true, |_| {});
        let _restore_before_cleanup = RestoreRootOnUnwind(true);
        assert!(File::open(path.join("openbao-state")).is_err());
        assert!(fs::read_dir(path.join("openbao-state")).is_err());
        let NormalInspectionOutcome::MatchedLocalReceipt(observed) =
            inspect_normal_state(&state, &path)
        else {
            panic!("O_PATH metadata evidence must match despite denied directory access");
        };
        assert_eq!(observed.openbao_state.identity.uid, 100);
        assert_eq!(observed.openbao_state.identity.mode, 0o700);
        assert_eq!(
            observed.application.credentials.initial.root.identity.uid,
            65534
        );
        drop(state);
        drop(restore); // Regain the test process identity before fixture cleanup.
        parent.close().unwrap();
        assert!(!path.exists());
        // Verify cleanup on both sides of the fixture return boundary, while
        // the failing process is still the ordinary fixture UID.
        for inside_fixture in [true, false] {
            let restore = RestoreIdentity(unsafe { libc::getegid() });
            assert_eq!(unsafe { libc::setegid(65534) }, 0);
            assert_eq!(unsafe { libc::seteuid(65534) }, 0);
            let mut failed_path = None;
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if inside_fixture {
                    normal_fixture_with_chown(true, |path| {
                        failed_path = Some(path.to_path_buf());
                        panic!("synthetic failure inside qualified fixture");
                    });
                } else {
                    let (_parent, path, _state) = normal_fixture_with_chown(true, |_| {});
                    let _restore_before_cleanup = RestoreRootOnUnwind(true);
                    failed_path = Some(path);
                    panic!("synthetic failure after qualified fixture");
                }
            }));
            assert!(failure.is_err());
            drop(restore);
            assert!(!failed_path.unwrap().exists());
        }
    }
    fn inspect_normal_state(state: &InstallerState, path: &Path) -> NormalInspectionOutcome {
        state
            .with_inspection(|locked| Ok(inspect_normal(locked, path)))
            .unwrap()
    }
    #[test]
    fn normal_boundary_evidence_matches_without_opening_openbao_children() {
        let (_parent, path, state) = normal_fixture();
        let fifo = CString::new(
            path.join("openbao-state/private-child")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let password = fs::read(path.join("operator-password")).unwrap();
        let receipt =
            fs::read(path.join("evidence").join(OPENBAO_OWNER_TRANSITION_RECEIPT)).unwrap();
        let NormalInspectionOutcome::MatchedLocalReceipt(observed) =
            inspect_normal_state(&state, &path)
        else {
            panic!("normal evidence expected");
        };
        assert_eq!(observed.application.roots.len(), 4);
        assert_eq!(observed.transition_receipt_sha256, digest(&receipt));
        assert_eq!(
            observed.openbao_state,
            observe(&File::open(path.join("openbao-state")).unwrap()).unwrap()
        );
        assert_eq!(fs::read(path.join("operator-password")).unwrap(), password);
        assert_eq!(
            fs::read(path.join("evidence").join(OPENBAO_OWNER_TRANSITION_RECEIPT)).unwrap(),
            receipt
        );
    }
    #[test]
    fn changed_transition_binding_is_unusable_and_preserved() {
        for field in [
            "engine",
            "inode",
            "owner",
            "mode",
            "source",
            "initial",
            "completion",
            "authorization",
        ] {
            let (_parent, path, state) = normal_fixture();
            let file = path.join("evidence").join(OPENBAO_OWNER_TRANSITION_RECEIPT);
            let mut receipt: OwnerTransitionReceipt =
                serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
            match field {
                "engine" => receipt.engine_id = "foreign-engine".into(),
                "inode" => receipt.openbao_state_after.identity.ino += 1,
                "owner" => {
                    receipt.openbao_state_after.identity.uid =
                        receipt.openbao_state_after.identity.uid.wrapping_add(1)
                }
                "mode" => receipt.openbao_state_after.identity.mode = 0o755,
                "source" => receipt.source_sha = "f".repeat(40),
                "initial" => receipt.initial_receipt_sha256 = "f".repeat(64),
                "completion" => receipt.tls_init_completion_sha256 = "f".repeat(64),
                "authorization" => receipt.deletion_authorized = true,
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&receipt).unwrap();
            fs::write(&file, &bytes).unwrap();
            assert!(
                matches!(
                    inspect_normal_state(&state, &path),
                    NormalInspectionOutcome::Unusable
                ),
                "{field}"
            );
            assert_eq!(fs::read(file).unwrap(), bytes);
        }
    }
    #[test]
    fn changed_openbao_runtime_records_or_root_are_unusable() {
        for record in [
            "openbao-created.json",
            "openbao-completed-openbao-tls-init.json",
            "root",
        ] {
            let (_parent, path, state) = normal_fixture();
            if record == "root" {
                fs::rename(path.join("openbao-state"), path.join("saved-openbao-state")).unwrap();
                fs::create_dir(path.join("openbao-state")).unwrap();
                fs::set_permissions(
                    path.join("openbao-state"),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            } else {
                let file = path.join(record);
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
                if record == "openbao-created.json" {
                    value["image_id"] = format!("sha256:{}", "f".repeat(64)).into();
                } else {
                    value["exit_code"] = 1.into();
                }
                fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            assert!(
                matches!(
                    inspect_normal_state(&state, &path),
                    NormalInspectionOutcome::Unusable
                ),
                "{record}"
            );
        }
    }
    #[test]
    fn missing_and_unsafe_transition_records_never_adopt_paths() {
        for kind in ["missing", "fifo", "symlink", "hardlink", "duplicate"] {
            let (_parent, path, state) = normal_fixture();
            let file = path.join("evidence").join(OPENBAO_OWNER_TRANSITION_RECEIPT);
            let original = fs::read(&file).unwrap();
            fs::remove_file(&file).unwrap();
            let outside = path.join("outside-canary");
            fs::write(&outside, b"private-canary").unwrap();
            match kind {
                "missing" => {}
                "fifo" => {
                    let c = CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
                "symlink" => symlink(&outside, &file).unwrap(),
                "hardlink" => fs::hard_link(&outside, &file).unwrap(),
                "duplicate" => {
                    let text = String::from_utf8(original).unwrap().replacen(
                        '{',
                        "{\"deletion_authorized\":false,",
                        1,
                    );
                    fs::write(&file, text).unwrap();
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => unreachable!(),
            }
            let result = inspect_normal_state(&state, &path);
            if kind == "missing" {
                assert!(matches!(result, NormalInspectionOutcome::Missing));
                assert!(!file.exists());
            } else {
                assert!(
                    matches!(result, NormalInspectionOutcome::Unusable),
                    "{kind}"
                );
            }
            assert_eq!(fs::read(outside).unwrap(), b"private-canary");
        }
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
    #[test]
    fn external_auth_v2_receipt_preserves_absence_and_rejects_later_operator_file() {
        // Synthetic reader fixture for current main's v2 external-auth shape;
        // this does not qualify the native credential writer or a live install.
        let (_parent, path, state) = credential_fixture();
        let record_path = path.join("evidence").join(CREDENTIAL_RECEIPT);
        let mut record: CredentialReceipt =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record.schema = "elevenid.installer-created-credentials/v2".into();
        record.operator_password = None;
        let receipt = serde_json::to_vec(&record).unwrap();
        fs::write(&record_path, &receipt).unwrap();
        fs::remove_file(path.join("operator-password")).unwrap();
        let CredentialInspectionOutcome::MatchedLocalReceipt(observed) =
            inspect_credential_state(&state, &path)
        else {
            panic!("v2 external authentication receipt must match without local credentials");
        };
        assert!(observed.operator_password.is_none());
        assert!(!path.join("operator-password").exists());
        fs::write(path.join("operator-password"), b"unexpected local operator").unwrap();
        fs::set_permissions(
            path.join("operator-password"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
        assert_eq!(fs::read(&record_path).unwrap(), receipt);
    }
    #[test]
    fn receipt_v1_cannot_omit_the_operator_identity() {
        let (_parent, path, state) = credential_fixture();
        let record_path = path.join("evidence").join(CREDENTIAL_RECEIPT);
        let mut record: CredentialReceipt =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record.operator_password = None;
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::remove_file(path.join("operator-password")).unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
    }
    #[test]
    fn receipt_v2_with_local_operator_retains_exact_identity_checks() {
        let (_parent, path, state) = credential_fixture();
        let record_path = path.join("evidence").join(CREDENTIAL_RECEIPT);
        let mut record: CredentialReceipt =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record.schema = "elevenid.installer-created-credentials/v2".into();
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::MatchedLocalReceipt(_)
        ));
        fs::rename(
            path.join("operator-password"),
            path.join("saved-operator-password"),
        )
        .unwrap();
        assert!(matches!(
            inspect_credential_state(&state, &path),
            CredentialInspectionOutcome::Unusable
        ));
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
        assert_eq!(
            observed.operator_password.as_ref().unwrap().identity.kind,
            Kind::File
        );
        assert_eq!(
            observed.initial.root.mount_id,
            observed.operator_password.as_ref().unwrap().mount_id
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
