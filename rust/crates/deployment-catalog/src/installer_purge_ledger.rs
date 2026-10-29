//! Dormant external write-ahead ledger for an explicitly confirmed purge.
//! The coordinator must authenticate the plan, installation parent and Docker
//! engine before calling this module. No resource removal occurs here.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};
use uuid::{Variant, Version};

use crate::installer_state::LockedDirectory;

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "purge ledger refused; retain installation and recovery evidence";
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_RECORD: usize = 4096;
const EXECUTION_Q_NAME: &str = ".marty-purge-quarantine";
const EXECUTION_Q_INTENT: &str = "execution-q-create-intent.json";
const EXECUTION_Q_CREATED: &str = "execution-q-created.json";
const CONFIRMATION: &str = "confirmation.json";

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn name(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| REFUSED.into())
}
fn procfs(path: &str) -> Result<File> {
    let directory = File::open(path).map_err(|_| REFUSED)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut info) } == 0
            && info.f_type as i64 == 0x9fa0,
    )?;
    Ok(directory)
}
fn mount_id(file: &File) -> Result<u64> {
    let proc = procfs("/proc/self/fdinfo")?;
    let entry = name(&file.as_raw_fd().to_string())?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            entry.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    require(fd >= 0)?;
    let mut bytes = Vec::new();
    unsafe { File::from_raw_fd(fd) }
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() <= 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let raw = ids.next().ok_or(REFUSED)?.trim_ascii();
    require(ids.next().is_none() && !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()))?;
    let id = raw.parse::<u64>().map_err(|_| REFUSED)?;
    require(id != 0)?;
    Ok(id)
}
fn open_at(parent: &File, entry: &str, flags: i32, mode: u32) -> Result<Option<File>> {
    let entry = name(entry)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(REFUSED.into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(
        m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
            && if directory {
                m.is_dir()
            } else {
                m.is_file() && m.nlink() == 1
            },
    )
}
fn mkdir_at(parent: &File, entry: &str) -> Result<bool> {
    let entry = name(entry)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), entry.as_ptr(), 0o700) } == 0 {
        parent.sync_all().map_err(|_| REFUSED)?;
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        Ok(false)
    } else {
        Err(REFUSED.into())
    }
}
fn read_record_once(parent: &File, entry: &str, limit: usize) -> Result<Option<(Vec<u8>, File)>> {
    let Some(held) = open_at(parent, entry, libc::O_PATH, 0)? else {
        return Ok(None);
    };
    private(&held, false)?;
    require(mount_id(parent)? == mount_id(&held)?)?;
    // Reopen the verified inode through its descriptor. Opening the directory
    // entry for reading first could itself operate on a substituted device.
    let proc = procfs("/proc/self/fd")?;
    let proc_path = name(&held.as_raw_fd().to_string())?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            proc_path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    require(fd >= 0)?;
    let file = unsafe { File::from_raw_fd(fd) };
    private(&file, false)?;
    let before = held.metadata().map_err(|_| REFUSED)?;
    let after = file.metadata().map_err(|_| REFUSED)?;
    require(before.dev() == after.dev() && before.ino() == after.ino())?;
    require(mount_id(&held)? == mount_id(&file)?)?;
    let mut bytes = Vec::new();
    (&file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(!bytes.is_empty() && bytes.len() <= limit)?;
    Ok(Some((bytes, file)))
}
// A name visible after rename is not necessarily durable. Stabilize the
// record inode and its containing directory, then reopen the exact name and
// require the same inode and bytes before allowing a retry to trust it.
fn read_record(parent: &File, entry: &str, limit: usize) -> Result<Option<Vec<u8>>> {
    let first = read_record_once(parent, entry, limit)?;
    if let Some((_, file)) = &first {
        file.sync_all().map_err(|_| REFUSED)?;
    }
    parent.sync_all().map_err(|_| REFUSED)?;
    let second = read_record_once(parent, entry, limit)?;
    match (first, second) {
        (None, None) => Ok(None),
        (Some((before, held)), Some((after, current))) => {
            let a = held.metadata().map_err(|_| REFUSED)?;
            let b = current.metadata().map_err(|_| REFUSED)?;
            require(
                before == after
                    && a.dev() == b.dev()
                    && a.ino() == b.ino()
                    && mount_id(&held)? == mount_id(&current)?,
            )?;
            Ok(Some(after))
        }
        _ => Err(REFUSED.into()),
    }
}
/// Return true if this call created the record. Existing bytes must match
/// exactly; a mismatch is never treated as a resumable transaction.
fn write_exact(parent: &File, entry: &str, bytes: &[u8], limit: usize) -> Result<bool> {
    require(!bytes.is_empty() && bytes.len() <= limit)?;
    let pending = format!(".tmp-{}", uuid::Uuid::new_v4().simple());
    let Some(mut file) = open_at(
        parent,
        &pending,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?
    else {
        return Err(REFUSED.into());
    };
    private(&file, false)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    let pending_name = name(&pending)?;
    let final_name = name(entry)?;
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            pending_name.as_ptr(),
            parent.as_raw_fd(),
            final_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    require(status == 0)?;
    parent.sync_all().map_err(|_| REFUSED)?;
    require(read_record(parent, entry, limit)?.as_deref() == Some(bytes))?;
    Ok(true)
}
fn write_or_verify(parent: &File, entry: &str, bytes: &[u8], limit: usize) -> Result<bool> {
    match read_record(parent, entry, limit)? {
        Some(existing) => {
            require(existing == bytes)?;
            Ok(false)
        }
        None => write_exact(parent, entry, bytes, limit),
    }
}
fn lock(directory: File) -> Result<LockedDirectory> {
    let result = crate::installer_state::lock(directory);
    #[cfg(test)]
    if result.is_err() {
        tests::record_lock_refusal(std::io::Error::last_os_error().raw_os_error());
    }
    result.map_err(|_| REFUSED.into())
}
fn directory_name(id: uuid::Uuid) -> String {
    format!("marty-purge-{}", id.simple())
}
fn valid_id(id: uuid::Uuid) -> bool {
    id.get_version() == Some(Version::Random) && id.get_variant() == Variant::RFC4122
}
fn entries(directory: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(|_| REFUSED)?
    {
        let item = item.map_err(|_| REFUSED)?;
        let name = item.file_name().into_string().map_err(|_| REFUSED)?;
        let allowed = name == "manifest.json"
            || name == CONFIRMATION
            || name == "custody.json"
            || name == "quarantine"
            || name == EXECUTION_Q_INTENT
            || name == EXECUTION_Q_CREATED
            || name
                .strip_prefix("intent-")
                .and_then(|v| v.strip_suffix(".json"))
                .is_some_and(hex_digest)
            || name
                .strip_prefix("result-")
                .and_then(|v| v.strip_suffix(".json"))
                .is_some_and(hex_digest)
            || name
                .strip_prefix(".tmp-")
                .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()));
        require(allowed && names.len() < 8192)?;
        let observed = open_at(directory, &name, libc::O_PATH, 0)?.ok_or(REFUSED)?;
        private(&observed, name == "quarantine")?;
        names.push(name);
    }
    Ok(names)
}

pub(crate) struct PurgeLedger {
    parent: File,
    directory: LockedDirectory,
    quarantine: File,
    installation_id: uuid::Uuid,
    plan_sha256: String,
}
/// Plain expected metadata supplied by the future receipt-authenticating
/// coordinator. Constructing this value does not grant deletion authority.
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryStamp {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mount_id: u64,
}
/// Exact local-custody assertion prepared by the coordinator after a separate
/// operator confirmation. It is not a cryptographic proof of who typed it.
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfirmationBinding {
    pub installation_id: uuid::Uuid,
    pub plan_sha256: String,
    pub engine_id: String,
    pub installation_path_sha256: String,
    pub installation_parent: DirectoryStamp,
    pub root: DirectoryStamp,
    pub operator_challenge_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationRecord {
    schema: String,
    action: String,
    binding: ConfirmationBinding,
    deletion_authorized: bool,
}
fn valid_confirmation_binding(binding: &ConfirmationBinding) -> bool {
    hex_digest(&binding.plan_sha256)
        && hex_digest(&binding.installation_path_sha256)
        && hex_digest(&binding.operator_challenge_sha256)
        && !binding.engine_id.is_empty()
        && binding.engine_id.len() <= 128
        && !binding
            .engine_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        && binding.root.mode == 0o700
        && binding.root.uid == unsafe { libc::geteuid() }
        && binding.root.ino != 0
        && binding.root.mount_id != 0
        && binding.installation_parent.ino != 0
        && binding.installation_parent.dev == binding.root.dev
        && binding.installation_parent.mount_id == binding.root.mount_id
}
pub(crate) fn directory_stamp(file: &File) -> Result<DirectoryStamp> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir())?;
    Ok(DirectoryStamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        mount_id: mount_id(file)?,
    })
}

/// One ordinary child name relative to a held installation parent. The future
/// coordinator must still authenticate that parent and this installation path.
pub(crate) struct InstallationLeaf(String);
impl InstallationLeaf {
    pub(crate) fn new(value: &str) -> Result<Self> {
        require(
            !value.is_empty()
                && value.len() <= 128
                && value != "."
                && value != ".."
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        )?;
        Ok(Self(value.into()))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionQCreateIntent {
    schema: String,
    installation_id: uuid::Uuid,
    plan_sha256: String,
    action: String,
    installation_leaf: String,
    parent: DirectoryStamp,
    root: DirectoryStamp,
    execution_q_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionQCreated {
    schema: String,
    installation_id: uuid::Uuid,
    plan_sha256: String,
    create_intent_sha256: String,
    status: String,
    execution_q: DirectoryStamp,
    deletion_authorized: bool,
}

/// Held q descriptor is returned only after the exact external creation pair
/// and current root/q custody have been verified. It is not a helper permit.
pub(crate) struct ExecutionQuarantineCustody {
    directory: File,
    pub stamp: DirectoryStamp,
}
impl ExecutionQuarantineCustody {
    pub(crate) fn directory(&self) -> &File {
        &self.directory
    }
}

fn checked_installation_root(
    parent: &File,
    leaf: &InstallationLeaf,
    held: &File,
    expected: &DirectoryStamp,
) -> Result<DirectoryStamp> {
    let parent_stamp = directory_stamp(parent)?;
    private(held, true)?;
    let held_stamp = directory_stamp(held)?;
    let current = open_at(parent, &leaf.0, libc::O_PATH | libc::O_DIRECTORY, 0)?.ok_or(REFUSED)?;
    private(&current, true)?;
    require(
        held_stamp == *expected
            && directory_stamp(&current)? == held_stamp
            && parent_stamp.mount_id == held_stamp.mount_id,
    )?;
    Ok(parent_stamp)
}

fn checked_execution_q(root: &File, expected: &DirectoryStamp) -> Result<File> {
    let q = open_at(root, EXECUTION_Q_NAME, libc::O_PATH | libc::O_DIRECTORY, 0)?.ok_or(REFUSED)?;
    private(&q, true)?;
    require(
        directory_stamp(&q)? == *expected
            && expected.mount_id == mount_id(root)?
            && expected.mode == 0o700,
    )?;
    Ok(q)
}
fn empty_directory(directory: &File) -> Result<()> {
    let mut observed =
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(|_| REFUSED)?;
    require(observed.next().is_none())
}
impl PurgeLedger {
    fn confirmation(&self) -> Result<Option<ConfirmationBinding>> {
        self.verify_manifest()?;
        require(
            !entries(&self.directory)?
                .iter()
                .any(|name| name.starts_with(".tmp-")),
        )?;
        let Some(bytes) = read_record(&self.directory, CONFIRMATION, MAX_RECORD)? else {
            return Ok(None);
        };
        let record: ConfirmationRecord = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        require(
            record.schema == "elevenid.installer-purge-confirmation/v1"
                && record.action == "confirm_exact_private_plan"
                && !record.deletion_authorized
                && record.binding.installation_id == self.installation_id
                && record.binding.plan_sha256 == self.plan_sha256
                && valid_confirmation_binding(&record.binding)
                && serde_json::to_vec(&record).map_err(|_| REFUSED)? == bytes,
        )?;
        self.verify_manifest()?;
        Ok(Some(record.binding))
    }
    fn require_confirmation(&self) -> Result<ConfirmationBinding> {
        self.confirmation()?.ok_or(REFUSED.into())
    }
    /// Publish exact confirmation after the original manifest is durable.
    /// Manifest-only interruption may be retried with this same binding, but
    /// any prior intent or execution-q record forbids retroactive confirmation.
    pub(crate) fn record_confirmation(&self, binding: &ConfirmationBinding) -> Result<()> {
        self.verify_manifest()?;
        require(
            binding.installation_id == self.installation_id
                && binding.plan_sha256 == self.plan_sha256
                && valid_confirmation_binding(binding),
        )?;
        if let Some(saved) = self.confirmation()? {
            return require(saved == *binding);
        }
        let names = entries(&self.directory)?;
        require(
            names.iter().all(|name| {
                !name.starts_with("intent-")
                    && !name.starts_with("result-")
                    && name != EXECUTION_Q_INTENT
                    && name != EXECUTION_Q_CREATED
                    && !name.starts_with(".tmp-")
            }) && entries(&self.quarantine)?.is_empty(),
        )?;
        let record = ConfirmationRecord {
            schema: "elevenid.installer-purge-confirmation/v1".into(),
            action: "confirm_exact_private_plan".into(),
            binding: binding.clone(),
            deletion_authorized: false,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        require(write_exact(
            &self.directory,
            CONFIRMATION,
            &bytes,
            MAX_RECORD,
        )?)?;
        require(self.require_confirmation()? == *binding)
    }
    pub(crate) fn confirmed_binding(&self) -> Result<Option<ConfirmationBinding>> {
        self.confirmation()
    }
    fn open_directory(
        parent: &File,
        id: uuid::Uuid,
        create: bool,
    ) -> Result<(LockedDirectory, bool)> {
        require(valid_id(id) && parent.metadata().map_err(|_| REFUSED)?.is_dir())?;
        let entry = directory_name(id);
        let created = create && mkdir_at(parent, &entry)?;
        let directory =
            open_at(parent, &entry, libc::O_RDONLY | libc::O_DIRECTORY, 0)?.ok_or(REFUSED)?;
        private(&directory, true)?;
        require(mount_id(parent)? == mount_id(&directory)?)?;
        let directory = lock(directory)?;
        Ok((directory, created))
    }
    fn open_quarantine(directory: &File, create: bool) -> Result<File> {
        if create {
            require(mkdir_at(directory, "quarantine")?)?;
        }
        let quarantine = open_at(
            directory,
            "quarantine",
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&quarantine, true)?;
        require(mount_id(directory)? == mount_id(&quarantine)?)?;
        Ok(quarantine)
    }
    fn custody_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Custody {
            schema: &'static str,
            installation_id: uuid::Uuid,
            plan_sha256: String,
            parent: DirectoryStamp,
            ledger: DirectoryStamp,
            quarantine: DirectoryStamp,
        }
        serde_json::to_vec(&Custody {
            schema: "elevenid.installer-purge-custody/v1",
            installation_id: self.installation_id,
            plan_sha256: self.plan_sha256.clone(),
            parent: directory_stamp(&self.parent)?,
            ledger: directory_stamp(&self.directory)?,
            quarantine: directory_stamp(&self.quarantine)?,
        })
        .map_err(|_| REFUSED.into())
    }
    fn verify_custody(&self) -> Result<()> {
        private(&self.directory, true)?;
        private(&self.quarantine, true)?;
        let current = open_at(
            &self.directory,
            "quarantine",
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&current, true)?;
        require(directory_stamp(&current)? == directory_stamp(&self.quarantine)?)?;
        require(
            read_record(&self.directory, "custody.json", MAX_RECORD)?.as_deref()
                == Some(self.custody_bytes()?.as_slice()),
        )
    }
    fn verify_manifest(&self) -> Result<Vec<u8>> {
        // Existing ledger and quarantine names, and any tombstones under the
        // latter, need durable publication before their absence or contents
        // can participate in crash recovery.
        self.parent.sync_all().map_err(|_| REFUSED)?;
        self.directory.sync_all().map_err(|_| REFUSED)?;
        self.quarantine.sync_all().map_err(|_| REFUSED)?;
        let current = open_at(
            &self.parent,
            &directory_name(self.installation_id),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&current, true)?;
        let held = self.directory.metadata().map_err(|_| REFUSED)?;
        let observed = current.metadata().map_err(|_| REFUSED)?;
        require(held.dev() == observed.dev() && held.ino() == observed.ino())?;
        require(mount_id(&self.parent)? == mount_id(&self.directory)?)?;
        require(mount_id(&self.directory)? == mount_id(&current)?)?;
        self.verify_custody()?;
        let bytes = read_record(&self.directory, "manifest.json", MAX_MANIFEST)?.ok_or(REFUSED)?;
        require(digest(&bytes) == self.plan_sha256)?;
        Ok(bytes)
    }

    /// Reject orphaned or incomplete auxiliary creation records on ledger
    /// reopen. Current installation/q path custody is checked separately when
    /// requesting the execution-q descriptor.
    fn execution_q_pair(&self) -> Result<Option<(ExecutionQCreateIntent, ExecutionQCreated)>> {
        let intent = read_record(&self.directory, EXECUTION_Q_INTENT, MAX_RECORD)?;
        let created = read_record(&self.directory, EXECUTION_Q_CREATED, MAX_RECORD)?;
        let (Some(intent), Some(created)) = (intent, created) else {
            require(
                read_record(&self.directory, EXECUTION_Q_INTENT, MAX_RECORD)?.is_none()
                    && read_record(&self.directory, EXECUTION_Q_CREATED, MAX_RECORD)?.is_none(),
            )?;
            return Ok(None);
        };
        let intent_record: ExecutionQCreateIntent =
            serde_json::from_slice(&intent).map_err(|_| REFUSED)?;
        let created_record: ExecutionQCreated =
            serde_json::from_slice(&created).map_err(|_| REFUSED)?;
        require(
            intent_record.schema == "elevenid.installer-execution-q-create-intent/v1"
                && intent_record.installation_id == self.installation_id
                && intent_record.plan_sha256 == self.plan_sha256
                && intent_record.action == "create_execution_quarantine"
                && intent_record.execution_q_name == EXECUTION_Q_NAME
                && InstallationLeaf::new(&intent_record.installation_leaf).is_ok()
                && intent_record.root.mode == 0o700
                && intent_record.root.uid == unsafe { libc::geteuid() }
                && intent_record.root.ino != 0
                && intent_record.root.mount_id != 0
                && intent_record.root.mount_id == intent_record.parent.mount_id
                && intent_record.root.dev == intent_record.parent.dev
                && created_record.schema == "elevenid.installer-execution-q-created/v1"
                && created_record.installation_id == self.installation_id
                && created_record.plan_sha256 == self.plan_sha256
                && created_record.create_intent_sha256 == digest(&intent)
                && created_record.status == "created"
                && !created_record.deletion_authorized
                && created_record.execution_q.mode == 0o700
                && created_record.execution_q.uid == unsafe { libc::geteuid() }
                && created_record.execution_q.ino != 0
                && created_record.execution_q.mount_id == intent_record.root.mount_id
                && created_record.execution_q.dev == intent_record.root.dev
                && serde_json::to_vec(&intent_record).map_err(|_| REFUSED)? == intent
                && serde_json::to_vec(&created_record).map_err(|_| REFUSED)? == created,
        )?;
        Ok(Some((intent_record, created_record)))
    }
    /// Create the private sibling ledger only after coordinator confirmation.
    /// The exact canonical plan bytes are durable before any intent is returned.
    pub(crate) fn create_or_resume(
        parent: &File,
        installation_id: uuid::Uuid,
        plan_bytes: &[u8],
        confirmed_sha256: &str,
    ) -> Result<Self> {
        require(hex_digest(confirmed_sha256) && digest(plan_bytes) == confirmed_sha256)?;
        let (directory, created) = Self::open_directory(parent, installation_id, true)?;
        // Existing ledgers must retain their original quarantine. Recreating
        // an empty replacement could hide data moved there before a crash.
        let quarantine = Self::open_quarantine(&directory, created)?;
        let names = entries(&directory)?;
        if !names.iter().any(|name| name == "manifest.json") {
            require(
                names.iter().all(|name| {
                    name == "quarantine" || name == "custody.json" || name.starts_with(".tmp-")
                }) && entries(&quarantine)?.is_empty(),
            )?;
        }
        let ledger = Self {
            parent: parent.try_clone().map_err(|_| REFUSED)?,
            directory,
            quarantine,
            installation_id,
            plan_sha256: confirmed_sha256.into(),
        };
        if created {
            write_exact(
                &ledger.directory,
                "custody.json",
                &ledger.custody_bytes()?,
                MAX_RECORD,
            )?;
        }
        ledger.verify_custody()?;
        write_or_verify(&ledger.directory, "manifest.json", plan_bytes, MAX_MANIFEST)?;
        ledger.verify_manifest()?;
        ledger.execution_q_pair()?;
        ledger.confirmation()?;
        Ok(ledger)
    }
    /// Resume after the installation root may be partly or fully gone. The
    /// coordinator must parse and authenticate the returned plan before use.
    pub(crate) fn open_existing(
        parent: &File,
        installation_id: uuid::Uuid,
        confirmed_sha256: &str,
    ) -> Result<(Self, Vec<u8>)> {
        require(hex_digest(confirmed_sha256))?;
        let (directory, _) = Self::open_directory(parent, installation_id, false)?;
        let quarantine = Self::open_quarantine(&directory, false)?;
        entries(&directory)?;
        let ledger = Self {
            parent: parent.try_clone().map_err(|_| REFUSED)?,
            directory,
            quarantine,
            installation_id,
            plan_sha256: confirmed_sha256.into(),
        };
        let plan = ledger.verify_manifest()?;
        ledger.execution_q_pair()?;
        ledger.require_confirmation()?;
        Ok((ledger, plan))
    }
    pub(crate) fn quarantine(&self) -> Result<&File> {
        self.require_confirmation()?;
        self.verify_manifest()?;
        private(&self.quarantine, true)?;
        let current = open_at(
            &self.directory,
            "quarantine",
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&current, true)?;
        let held = self.quarantine.metadata().map_err(|_| REFUSED)?;
        let observed = current.metadata().map_err(|_| REFUSED)?;
        require(held.dev() == observed.dev() && held.ino() == observed.ino())?;
        require(mount_id(&self.directory)? == mount_id(&self.quarantine)?)?;
        require(mount_id(&self.quarantine)? == mount_id(&current)?)?;
        Ok(&self.quarantine)
    }
    /// Create the fixed execution quarantine under the *installation* root,
    /// never under a separate Docker bind. The caller must authenticate the
    /// expected root and held installation parent against the confirmed plan.
    /// Intent-only crashes are intentionally manual-recovery cases in v1.
    pub(crate) fn create_execution_quarantine(
        &self,
        installation_parent: &File,
        installation_leaf: &InstallationLeaf,
        root: &File,
        expected_root: &DirectoryStamp,
    ) -> Result<ExecutionQuarantineCustody> {
        self.create_execution_quarantine_inner(
            installation_parent,
            installation_leaf,
            root,
            expected_root,
            || Ok(()),
        )
    }
    fn create_execution_quarantine_inner<F: FnOnce() -> Result<()>>(
        &self,
        installation_parent: &File,
        installation_leaf: &InstallationLeaf,
        root: &File,
        expected_root: &DirectoryStamp,
        after_intent: F,
    ) -> Result<ExecutionQuarantineCustody> {
        self.require_confirmation()?;
        let parent_stamp =
            checked_installation_root(installation_parent, installation_leaf, root, expected_root)?;
        // The held root may be O_PATH. Reopen only the already classified
        // directory for mkdir/fsync and bind that descriptor to its exact inode.
        let writable_root = open_at(
            installation_parent,
            &installation_leaf.0,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&writable_root, true)?;
        require(directory_stamp(&writable_root)? == *expected_root)?;
        require(
            read_record(&self.directory, EXECUTION_Q_INTENT, MAX_RECORD)?.is_none()
                && read_record(&self.directory, EXECUTION_Q_CREATED, MAX_RECORD)?.is_none()
                && open_at(&writable_root, EXECUTION_Q_NAME, libc::O_PATH, 0)?.is_none(),
        )?;
        let intent = ExecutionQCreateIntent {
            schema: "elevenid.installer-execution-q-create-intent/v1".into(),
            installation_id: self.installation_id,
            plan_sha256: self.plan_sha256.clone(),
            action: "create_execution_quarantine".into(),
            installation_leaf: installation_leaf.0.clone(),
            parent: parent_stamp.clone(),
            root: expected_root.clone(),
            execution_q_name: EXECUTION_Q_NAME.into(),
        };
        let intent_bytes = serde_json::to_vec(&intent).map_err(|_| REFUSED)?;
        require(write_exact(
            &self.directory,
            EXECUTION_Q_INTENT,
            &intent_bytes,
            MAX_RECORD,
        )?)?;
        self.verify_manifest()?;
        after_intent()?;
        require(
            checked_installation_root(installation_parent, installation_leaf, root, expected_root)?
                == parent_stamp,
        )?;
        require(mkdir_at(&writable_root, EXECUTION_Q_NAME)?)?;
        let q = open_at(
            &writable_root,
            EXECUTION_Q_NAME,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?
        .ok_or(REFUSED)?;
        private(&q, true)?;
        q.sync_all().map_err(|_| REFUSED)?;
        writable_root.sync_all().map_err(|_| REFUSED)?;
        empty_directory(&q)?;
        let stamp = directory_stamp(&q)?;
        checked_execution_q(&writable_root, &stamp)?;
        require(
            checked_installation_root(installation_parent, installation_leaf, root, expected_root)?
                == parent_stamp,
        )?;
        let created = ExecutionQCreated {
            schema: "elevenid.installer-execution-q-created/v1".into(),
            installation_id: self.installation_id,
            plan_sha256: self.plan_sha256.clone(),
            create_intent_sha256: digest(&intent_bytes),
            status: "created".into(),
            execution_q: stamp,
            deletion_authorized: false,
        };
        let created_bytes = serde_json::to_vec(&created).map_err(|_| REFUSED)?;
        require(write_exact(
            &self.directory,
            EXECUTION_Q_CREATED,
            &created_bytes,
            MAX_RECORD,
        )?)?;
        self.open_execution_quarantine(installation_parent, installation_leaf, root, expected_root)
    }
    /// Reopen only a complete, canonical creation pair with exact live root/q
    /// custody. The returned O_PATH descriptor is observational, not a permit
    /// to start a privileged helper or to remove any entry.
    pub(crate) fn open_execution_quarantine(
        &self,
        installation_parent: &File,
        installation_leaf: &InstallationLeaf,
        root: &File,
        expected_root: &DirectoryStamp,
    ) -> Result<ExecutionQuarantineCustody> {
        self.require_confirmation()?;
        let (intent, created) = self.execution_q_pair()?.ok_or(REFUSED)?;
        require(
            intent.installation_leaf == installation_leaf.0
                && intent.root == *expected_root
                && intent.parent
                    == checked_installation_root(
                        installation_parent,
                        installation_leaf,
                        root,
                        expected_root,
                    )?,
        )?;
        let q = checked_execution_q(root, &created.execution_q)?;
        require(
            intent.parent
                == checked_installation_root(
                    installation_parent,
                    installation_leaf,
                    root,
                    expected_root,
                )?,
        )?;
        self.verify_manifest()?;
        let (again_intent, again_created) = self.execution_q_pair()?.ok_or(REFUSED)?;
        require(
            serde_json::to_vec(&intent).map_err(|_| REFUSED)?
                == serde_json::to_vec(&again_intent).map_err(|_| REFUSED)?
                && serde_json::to_vec(&created).map_err(|_| REFUSED)?
                    == serde_json::to_vec(&again_created).map_err(|_| REFUSED)?
                && directory_stamp(&q)? == created.execution_q,
        )?;
        Ok(ExecutionQuarantineCustody {
            directory: q,
            stamp: created.execution_q,
        })
    }
    pub(crate) fn installation_id(&self) -> uuid::Uuid {
        self.installation_id
    }
    pub(crate) fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
    pub(crate) fn record_intent(
        &self,
        resource: ResourceKind,
        identity_sha256: &str,
    ) -> Result<PersistedIntent> {
        self.require_confirmation()?;
        require(hex_digest(identity_sha256))?;
        let record = IntentRecord {
            schema: "elevenid.installer-purge-intent/v1".into(),
            installation_id: self.installation_id,
            plan_sha256: self.plan_sha256.clone(),
            resource,
            identity_sha256: identity_sha256.into(),
            action: "remove".into(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        let key = digest(&bytes);
        let intent_entry = format!("intent-{key}.json");
        let result_entry = format!("result-{key}.json");
        if read_record(&self.directory, &intent_entry, MAX_RECORD)?.is_none() {
            // A surviving result with a missing intent is an inconsistent
            // ledger, not permission to recreate the earlier transaction.
            require(read_record(&self.directory, &result_entry, MAX_RECORD)?.is_none())?;
        }
        let created = write_or_verify(&self.directory, &intent_entry, &bytes, MAX_RECORD)?;
        if created {
            require(read_record(&self.directory, &result_entry, MAX_RECORD)?.is_none())?;
        }
        self.verify_manifest()?;
        require(
            read_record(&self.directory, &format!("intent-{key}.json"), MAX_RECORD)?.as_deref()
                == Some(bytes.as_slice()),
        )?;
        Ok(PersistedIntent { key, created })
    }
    fn verify_intent(&self, intent: &PersistedIntent) -> Result<()> {
        self.require_confirmation()?;
        require(hex_digest(&intent.key))?;
        let original = read_record(
            &self.directory,
            &format!("intent-{}.json", intent.key),
            MAX_RECORD,
        )?
        .ok_or(REFUSED)?;
        require(digest(&original) == intent.key)?;
        let record: IntentRecord = serde_json::from_slice(&original).map_err(|_| REFUSED)?;
        require(
            record.schema == "elevenid.installer-purge-intent/v1"
                && record.installation_id == self.installation_id
                && record.plan_sha256 == self.plan_sha256
                && record.action == "remove"
                && hex_digest(&record.identity_sha256)
                && serde_json::to_vec(&record).map_err(|_| REFUSED)? == original,
        )?;
        Ok(())
    }
    /// Inspect an exact durable result before reconciling a retry. The caller
    /// must still observe resource absence; this receipt alone never authorizes
    /// skipping a live resource or removing a replacement.
    pub(crate) fn recorded_result(&self, intent: &PersistedIntent) -> Result<Option<Outcome>> {
        self.verify_intent(intent)?;
        let entry = format!("result-{}.json", intent.key);
        let Some(bytes) = read_record(&self.directory, &entry, MAX_RECORD)? else {
            self.verify_manifest()?;
            return Ok(None);
        };
        let record: ResultRecord = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        require(
            record.schema == "elevenid.installer-purge-result/v1"
                && record.installation_id == self.installation_id
                && record.plan_sha256 == self.plan_sha256
                && record.intent_sha256 == intent.key
                && serde_json::to_vec(&record).map_err(|_| REFUSED)? == bytes,
        )?;
        self.verify_manifest()?;
        require(
            read_record(&self.directory, &entry, MAX_RECORD)?.as_deref() == Some(bytes.as_slice()),
        )?;
        Ok(Some(record.outcome))
    }
    pub(crate) fn record_result(&self, intent: &PersistedIntent, outcome: Outcome) -> Result<()> {
        self.verify_intent(intent)?;
        if outcome == Outcome::AlreadyAbsentAfterRetry {
            require(intent.is_retry())?;
        }
        let result = ResultRecord {
            schema: "elevenid.installer-purge-result/v1".into(),
            installation_id: self.installation_id,
            plan_sha256: self.plan_sha256.clone(),
            intent_sha256: intent.key.clone(),
            outcome,
        };
        let bytes = serde_json::to_vec(&result).map_err(|_| REFUSED)?;
        write_or_verify(
            &self.directory,
            &format!("result-{}.json", intent.key),
            &bytes,
            MAX_RECORD,
        )?;
        self.verify_manifest()?;
        require(
            read_record(
                &self.directory,
                &format!("result-{}.json", intent.key),
                MAX_RECORD,
            )?
            .as_deref()
                == Some(bytes.as_slice()),
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourceKind {
    HostEntry,
    DockerVolume,
    InstallationRoot,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Removed,
    AlreadyAbsentAfterRetry,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentRecord {
    schema: String,
    installation_id: uuid::Uuid,
    plan_sha256: String,
    resource: ResourceKind,
    identity_sha256: String,
    action: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultRecord {
    schema: String,
    installation_id: uuid::Uuid,
    plan_sha256: String,
    intent_sha256: String,
    outcome: Outcome,
}
pub(crate) struct PersistedIntent {
    key: String,
    created: bool,
}
impl PersistedIntent {
    /// A pre-existing exact intent can authorize retry-only absence after the
    /// coordinator independently verifies the expected resource is gone.
    pub(crate) fn is_retry(&self) -> bool {
        !self.created
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    std::thread_local! {
        static LAST_LOCK_ERRNO: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn record_lock_refusal(errno: Option<i32>) {
        LAST_LOCK_ERRNO.with(|value| value.set(errno));
    }

    fn observed_resume(
        parent: &File,
        installation_id: uuid::Uuid,
        confirmed_sha256: &str,
    ) -> Result<(PurgeLedger, Vec<u8>)> {
        LAST_LOCK_ERRNO.with(|value| value.set(None));
        let result = PurgeLedger::open_existing(parent, installation_id, confirmed_sha256);
        if result.is_err() {
            let errno = LAST_LOCK_ERRNO.with(|value| value.get());
            let stage = if errno.is_some() {
                "directory-flock"
            } else {
                "unclassified"
            };
            eprintln!("MARTY_LEDGER_RESUME_REFUSED stage={stage} errno={errno:?}");
        }
        result
    }

    use super::*;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    };

    fn fixture() -> (tempfile::TempDir, File, uuid::Uuid, Vec<u8>, String) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(root.path()).unwrap();
        let id = uuid::Uuid::new_v4();
        let plan = br#"{"schema":"synthetic-purge-plan","resources":1}"#.to_vec();
        let hash = digest(&plan);
        (root, parent, id, plan, hash)
    }
    fn synthetic_binding(
        id: uuid::Uuid,
        hash: &str,
        installation_parent: &File,
        root: &File,
    ) -> ConfirmationBinding {
        ConfirmationBinding {
            installation_id: id,
            plan_sha256: hash.into(),
            engine_id: "synthetic-engine".into(),
            installation_path_sha256: digest(b"/synthetic/installation"),
            installation_parent: directory_stamp(installation_parent).unwrap(),
            root: directory_stamp(root).unwrap(),
            operator_challenge_sha256: digest(format!("PURGE {id} {hash}").as_bytes()),
        }
    }
    fn create_confirmed(
        parent: &File,
        id: uuid::Uuid,
        plan: &[u8],
        hash: &str,
    ) -> Result<PurgeLedger> {
        let ledger = PurgeLedger::create_or_resume(parent, id, plan, hash)?;
        let binding = synthetic_binding(id, hash, parent, parent);
        ledger.record_confirmation(&binding)?;
        Ok(ledger)
    }
    #[test]
    fn manifest_without_confirmation_grants_no_intent_or_quarantine() {
        let (_root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        assert!(ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"synthetic-child"))
            .is_err());
        assert!(ledger.quarantine().is_err());
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert!(ledger.confirmed_binding().unwrap().is_none());
        let binding = synthetic_binding(id, &hash, &parent, &parent);
        ledger.record_confirmation(&binding).unwrap();
        assert!(ledger.confirmed_binding().unwrap() == Some(binding));
        assert!(ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"synthetic-child"))
            .is_ok());
    }
    #[test]
    fn confirmation_mismatch_and_corruption_refuse_without_adoption() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        let binding = synthetic_binding(id, &hash, &parent, &parent);
        ledger.record_confirmation(&binding).unwrap();
        let mut changed = binding.clone();
        changed.operator_challenge_sha256 = digest(b"wrong challenge");
        assert!(ledger.record_confirmation(&changed).is_err());
        let record = root.path().join(directory_name(id)).join(CONFIRMATION);
        let original = fs::read(&record).unwrap();
        let mut duplicate = original.clone();
        let needle = b"\"deletion_authorized\":false";
        let index = duplicate
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        duplicate.splice(
            index..index,
            b"\"deletion_authorized\":false,".iter().copied(),
        );
        fs::write(&record, &duplicate).unwrap();
        assert!(ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"synthetic-child"))
            .is_err());
        assert_eq!(fs::read(&record).unwrap(), duplicate);
    }
    #[test]
    fn unconfirmed_manifest_cannot_create_execution_quarantine() {
        let temp = tempfile::tempdir().unwrap();
        let external_path = temp.path().join("external");
        let installation_parent_path = temp.path().join("installation-parent");
        let installation_path = installation_parent_path.join("installation");
        fs::create_dir(&external_path).unwrap();
        fs::create_dir(&installation_parent_path).unwrap();
        fs::create_dir(&installation_path).unwrap();
        fs::set_permissions(&external_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&installation_path, fs::Permissions::from_mode(0o700)).unwrap();
        let external = File::open(&external_path).unwrap();
        let installation_parent = File::open(&installation_parent_path).unwrap();
        let root = File::open(&installation_path).unwrap();
        let expected = directory_stamp(&root).unwrap();
        let id = uuid::Uuid::new_v4();
        let plan = b"synthetic-unconfirmed-plan";
        let hash = digest(plan);
        let ledger = PurgeLedger::create_or_resume(&external, id, plan, &hash).unwrap();
        assert!(ledger
            .create_execution_quarantine(
                &installation_parent,
                &InstallationLeaf::new("installation").unwrap(),
                &root,
                &expected,
            )
            .is_err());
        assert!(!installation_path.join(EXECUTION_Q_NAME).exists());
        assert!(!external_path
            .join(directory_name(id))
            .join(EXECUTION_Q_INTENT)
            .exists());
    }
    #[test]
    fn recovered_rename_is_stabilized_before_record_is_trusted() {
        let (_root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let identity = digest(b"interrupted-intent-identity");
        let record = IntentRecord {
            schema: "elevenid.installer-purge-intent/v1".into(),
            installation_id: id,
            plan_sha256: hash,
            resource: ResourceKind::HostEntry,
            identity_sha256: identity.clone(),
            action: "remove".into(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let name = format!("intent-{}.json", digest(&bytes));
        let pending = format!(".tmp-{}", uuid::Uuid::new_v4().simple());
        let mut file = open_at(
            &ledger.directory,
            &pending,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .unwrap()
        .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let source = CString::new(pending).unwrap();
        let target = CString::new(name).unwrap();
        assert_eq!(
            unsafe {
                libc::renameat(
                    ledger.directory.as_raw_fd(),
                    source.as_ptr(),
                    ledger.directory.as_raw_fd(),
                    target.as_ptr(),
                )
            },
            0
        );
        // No directory sync followed rename. Recovery must supply that sync
        // and rebind the record name before this can become a retry.
        let retry = ledger
            .record_intent(ResourceKind::HostEntry, &identity)
            .unwrap();
        assert!(retry.is_retry());
    }
    #[test]
    fn recovered_record_refuses_when_containing_directory_cannot_sync() {
        let (root, _parent, _id, _plan, _hash) = fixture();
        let name = "intent-canary.json";
        let path = root.path().join(name);
        fs::write(&path, b"canary").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let held = open_at(&File::open(root.path()).unwrap(), ".", libc::O_PATH, 0)
            .unwrap()
            .unwrap();
        assert!(read_record(&held, name, MAX_RECORD).is_err());
    }
    #[test]
    fn existing_ledger_refuses_when_ancestor_cannot_sync() {
        let (root, parent, id, plan, hash) = fixture();
        drop(create_confirmed(&parent, id, &plan, &hash).unwrap());
        let held = open_at(&parent, ".", libc::O_PATH, 0).unwrap().unwrap();
        assert!(PurgeLedger::open_existing(&held, id, &hash).is_err());
        assert!(root.path().join(directory_name(id)).exists());
    }
    #[test]
    fn exact_manifest_intent_and_result_survive_resume() {
        let (_root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        assert_eq!(ledger.installation_id(), id);
        assert_eq!(ledger.plan_sha256(), hash);
        private(ledger.quarantine().unwrap(), true).unwrap();
        let resource = digest(b"synthetic-volume-identity");
        let first = ledger
            .record_intent(ResourceKind::DockerVolume, &resource)
            .unwrap();
        assert!(!first.is_retry());
        assert_eq!(ledger.recorded_result(&first).unwrap(), None);
        assert!(hex_digest(first.sha256()));
        assert!(ledger
            .record_result(&first, Outcome::AlreadyAbsentAfterRetry)
            .is_err());
        ledger.record_result(&first, Outcome::Removed).unwrap();
        assert_eq!(
            ledger.recorded_result(&first).unwrap(),
            Some(Outcome::Removed)
        );
        ledger.record_result(&first, Outcome::Removed).unwrap();
        let retry = ledger
            .record_intent(ResourceKind::DockerVolume, &resource)
            .unwrap();
        assert!(retry.is_retry());
        assert_eq!(
            ledger.recorded_result(&retry).unwrap(),
            Some(Outcome::Removed)
        );
        assert!(ledger
            .record_result(&retry, Outcome::AlreadyAbsentAfterRetry)
            .is_err());
        drop(ledger);
        let (resumed, stored) = PurgeLedger::open_existing(&parent, id, &hash).unwrap();
        assert_eq!(stored, plan);
        let retry = resumed
            .record_intent(ResourceKind::DockerVolume, &resource)
            .unwrap();
        assert_eq!(
            resumed.recorded_result(&retry).unwrap(),
            Some(Outcome::Removed)
        );
        assert!(resumed
            .record_intent(ResourceKind::DockerVolume, &resource)
            .unwrap()
            .is_retry());
        assert!(PurgeLedger::open_existing(&parent, id, &digest(b"wrong")).is_err());
        assert!(create_confirmed(&parent, id, b"different", &hash).is_err());
    }
    #[test]
    fn retained_duplicate_does_not_extend_or_release_owner_lock() {
        let (_root, parent, id, plan, hash) = fixture();
        let owner = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let inherited = owner.directory.try_clone().unwrap();
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        drop(owner);
        let (successor, stored) = PurgeLedger::open_existing(&parent, id, &hash).unwrap();
        assert_eq!(stored, plan);
        drop(inherited);
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        drop(successor);
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_ok());
    }
    #[test]
    fn recorded_result_rejects_mismatched_and_ambiguous_records() {
        for field in [
            "schema",
            "installation",
            "plan",
            "intent",
            "unknown",
            "duplicate",
        ] {
            let (root, parent, id, plan, hash) = fixture();
            let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
            let intent = ledger
                .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
                .unwrap();
            ledger.record_result(&intent, Outcome::Removed).unwrap();
            let path = root
                .path()
                .join(directory_name(id))
                .join(format!("result-{}.json", intent.sha256()));
            let original = fs::read(&path).unwrap();
            let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
            match field {
                "schema" => record["schema"] = "foreign".into(),
                "installation" => {
                    record["installation_id"] = uuid::Uuid::new_v4().to_string().into()
                }
                "plan" => record["plan_sha256"] = digest(b"other-plan").into(),
                "intent" => record["intent_sha256"] = digest(b"other-intent").into(),
                "unknown" => record["extra"] = true.into(),
                "duplicate" => {}
                _ => unreachable!(),
            }
            let bytes = if field == "duplicate" {
                String::from_utf8(original)
                    .unwrap()
                    .replacen('{', "{\"outcome\":\"removed\",", 1)
                    .into_bytes()
            } else {
                serde_json::to_vec(&record).unwrap()
            };
            fs::write(&path, &bytes).unwrap();
            assert!(ledger.recorded_result(&intent).is_err(), "{field}");
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }
    #[test]
    fn orphaned_or_special_result_never_grants_a_durable_outcome() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let intent = ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
            .unwrap();
        ledger.record_result(&intent, Outcome::Removed).unwrap();
        let directory = root.path().join(directory_name(id));
        let result = directory.join(format!("result-{}.json", intent.sha256()));
        fs::remove_file(&result).unwrap();
        let name = CString::new(result.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(ledger.recorded_result(&intent).is_err());
        fs::remove_file(&result).unwrap();
        ledger.record_result(&intent, Outcome::Removed).unwrap();
        fs::remove_file(directory.join(format!("intent-{}.json", intent.sha256()))).unwrap();
        assert!(ledger.recorded_result(&intent).is_err());
        assert!(ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
            .is_err());
        assert!(!directory
            .join(format!("intent-{}.json", intent.sha256()))
            .exists());
    }
    #[test]
    fn foreign_ledger_entry_and_replaced_manifest_refuse() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        drop(ledger);
        let path = root.path().join(directory_name(id));
        fs::write(path.join("foreign"), b"canary").unwrap();
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        fs::remove_file(path.join("foreign")).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside-canary").unwrap();
        fs::remove_file(path.join("manifest.json")).unwrap();
        symlink(&outside, path.join("manifest.json")).unwrap();
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside-canary");
    }
    #[test]
    fn fifo_manifest_is_refused_before_opening_for_read() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        drop(ledger);
        let path = root.path().join(directory_name(id)).join("manifest.json");
        fs::remove_file(&path).unwrap();
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
    }
    #[test]
    fn orphaned_temp_file_blocks_confirmed_resume_and_preserves_evidence() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        drop(ledger);
        let path = root.path().join(directory_name(id));
        let orphan = path.join(format!(".tmp-{}", uuid::Uuid::new_v4().simple()));
        fs::write(&orphan, b"incomplete intent").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert!(create_confirmed(&parent, id, &plan, &hash).is_err());
        assert_eq!(fs::read(&orphan).unwrap(), b"incomplete intent");
    }
    #[test]
    fn held_ledger_refuses_rebound_sibling_path() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let path = root.path().join(directory_name(id));
        fs::rename(&path, root.path().join("moved-ledger")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ledger.quarantine().is_err());
        assert!(ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
            .is_err());
        assert!(!path.join("manifest.json").exists());
    }
    #[test]
    fn held_quarantine_refuses_rebound_child_path() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let path = root.path().join(directory_name(id));
        fs::rename(path.join("quarantine"), path.join("moved-quarantine")).unwrap();
        fs::create_dir(path.join("quarantine")).unwrap();
        fs::set_permissions(path.join("quarantine"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ledger.quarantine().is_err());
    }
    #[test]
    fn resumed_ledger_refuses_replaced_quarantine_and_preserves_pending_data() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        ledger
            .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
            .unwrap();
        let path = root.path().join(directory_name(id));
        let pending = path.join("quarantine/pending-owned-data");
        fs::write(&pending, b"retained-pending-canary").unwrap();
        let old = root.path().join("saved-quarantine");
        fs::rename(path.join("quarantine"), &old).unwrap();
        fs::create_dir(path.join("quarantine")).unwrap();
        fs::set_permissions(path.join("quarantine"), fs::Permissions::from_mode(0o700)).unwrap();
        drop(ledger);
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert!(create_confirmed(&parent, id, &plan, &hash).is_err());
        assert_eq!(
            fs::read(old.join("pending-owned-data")).unwrap(),
            b"retained-pending-canary"
        );
        assert_eq!(fs::read_dir(path.join("quarantine")).unwrap().count(), 0);
    }
    #[test]
    fn missing_quarantine_is_not_recreated_on_resume() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
        let path = root.path().join(directory_name(id));
        drop(ledger);
        fs::remove_dir(path.join("quarantine")).unwrap();
        assert!(create_confirmed(&parent, id, &plan, &hash).is_err());
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert!(!path.join("quarantine").exists());
    }
    #[test]
    fn missing_or_changed_custody_record_is_never_adopted() {
        for missing in [true, false] {
            let (root, parent, id, plan, hash) = fixture();
            let ledger = create_confirmed(&parent, id, &plan, &hash).unwrap();
            let record = root.path().join(directory_name(id)).join("custody.json");
            drop(ledger);
            if missing {
                fs::remove_file(&record).unwrap();
            } else {
                fs::write(&record, b"foreign-custody-canary").unwrap();
            }
            assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
            assert!(create_confirmed(&parent, id, &plan, &hash).is_err());
            if missing {
                assert!(!record.exists());
            } else {
                assert_eq!(fs::read(&record).unwrap(), b"foreign-custody-canary");
            }
        }
    }
    #[test]
    fn durable_custody_allows_retry_before_manifest_publication() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        let directory = root.path().join(directory_name(id));
        let custody = fs::read(directory.join("custody.json")).unwrap();
        drop(ledger);
        fs::remove_file(directory.join("manifest.json")).unwrap();
        let resumed = create_confirmed(&parent, id, &plan, &hash).unwrap();
        assert!(resumed.quarantine().is_ok());
        assert_eq!(fs::read(directory.join("manifest.json")).unwrap(), plan);
        assert_eq!(fs::read(directory.join("custody.json")).unwrap(), custody);
    }

    fn execution_fixture() -> (
        tempfile::TempDir,
        File,
        File,
        File,
        PurgeLedger,
        InstallationLeaf,
        DirectoryStamp,
        uuid::Uuid,
        String,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let ledger_path = temp.path().join("external-ledger-parent");
        let installation_parent_path = temp.path().join("installation-parent");
        fs::create_dir(&ledger_path).unwrap();
        fs::create_dir(&installation_parent_path).unwrap();
        let installation_path = installation_parent_path.join("installation");
        fs::create_dir(&installation_path).unwrap();
        fs::set_permissions(&installation_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            installation_path.join("private-canary"),
            b"unread-synthetic-secret",
        )
        .unwrap();
        let ledger_parent = File::open(&ledger_path).unwrap();
        let installation_parent = File::open(&installation_parent_path).unwrap();
        let root = File::open(&installation_path).unwrap();
        let expected = directory_stamp(&root).unwrap();
        let id = uuid::Uuid::new_v4();
        let plan = br#"{"schema":"synthetic-execution-q-plan","reserved_q":true}"#;
        let hash = digest(plan);
        let ledger = PurgeLedger::create_or_resume(&ledger_parent, id, plan, &hash).unwrap();
        ledger
            .record_confirmation(&synthetic_binding(id, &hash, &installation_parent, &root))
            .unwrap();
        (
            temp,
            ledger_parent,
            installation_parent,
            root,
            ledger,
            InstallationLeaf::new("installation").unwrap(),
            expected,
            id,
            hash,
        )
    }

    #[test]
    fn execution_q_create_and_complete_pair_survive_separate_parent_resume() {
        // A concurrent test's fork can briefly inherit this locked open-file
        // description until exec closes CLOEXEC descriptors. Keep this positive
        // owner-release/resume fixture isolated; LOCK_NB still blocks contenders.
        const CHILD: &str = "MARTY_LEDGER_RESUME_TEST_CHILD";
        const MARKER: &str = "MARTY_LEDGER_RESUME_CHILD_OK";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "installer_purge_ledger::tests::execution_q_create_and_complete_pair_survive_separate_parent_resume",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated synthetic ledger resume failed: {}",
                String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(2048)])
            );
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            assert!(stdout.contains(MARKER));
            assert!(stdout.contains("MARTY_LEDGER_OWNER_RELEASED_WITH_RETAINED_DESCRIPTION"));
            assert!(stdout.contains("1 passed; 0 failed"));
            return;
        }
        let (temp, ledger_parent, installation_parent, root, ledger, leaf, expected, id, hash) =
            execution_fixture();
        let held_opath = open_at(
            &installation_parent,
            "installation",
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
        .unwrap()
        .unwrap();
        let q = ledger
            .create_execution_quarantine(&installation_parent, &leaf, &held_opath, &expected)
            .unwrap();
        assert_eq!(q.stamp.mount_id, expected.mount_id);
        assert_eq!(q.stamp.mode, 0o700);
        assert!(directory_stamp(q.directory()).unwrap() == q.stamp);
        let mut wrong_mount = q.stamp.clone();
        wrong_mount.mount_id += 1;
        assert!(checked_execution_q(&root, &wrong_mount).is_err());
        assert_eq!(
            fs::read(
                temp.path()
                    .join("installation-parent/installation/private-canary")
            )
            .unwrap(),
            b"unread-synthetic-secret"
        );
        let ledger_path = temp
            .path()
            .join("external-ledger-parent")
            .join(directory_name(id));
        let created: ExecutionQCreated =
            serde_json::from_slice(&fs::read(ledger_path.join(EXECUTION_Q_CREATED)).unwrap())
                .unwrap();
        assert!(!created.deletion_authorized);
        let retained_description = ledger.directory.try_clone().unwrap();
        drop(q);
        drop(ledger);
        let (resumed, _) = observed_resume(&ledger_parent, id, &hash).unwrap();
        assert_eq!(LAST_LOCK_ERRNO.with(|value| value.get()), None);
        drop(retained_description);
        assert!(observed_resume(&ledger_parent, id, &hash).is_err());
        assert_eq!(
            LAST_LOCK_ERRNO.with(|value| value.get()),
            Some(libc::EWOULDBLOCK)
        );
        println!("MARTY_LEDGER_OWNER_RELEASED_WITH_RETAINED_DESCRIPTION");
        assert!(
            resumed
                .open_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .unwrap()
                .stamp
                == created.execution_q
        );
        println!("{MARKER}");
    }

    #[test]
    fn execution_q_intent_only_crashes_refuse_manual_recovery_without_adoption() {
        for create_unknown_q in [false, true] {
            let (temp, ledger_parent, installation_parent, root, ledger, leaf, expected, id, hash) =
                execution_fixture();
            let q_path = temp
                .path()
                .join("installation-parent/installation")
                .join(EXECUTION_Q_NAME);
            assert!(ledger
                .create_execution_quarantine_inner(
                    &installation_parent,
                    &leaf,
                    &root,
                    &expected,
                    || {
                        if create_unknown_q {
                            fs::create_dir(&q_path).unwrap();
                            fs::set_permissions(&q_path, fs::Permissions::from_mode(0o700))
                                .unwrap();
                            fs::write(q_path.join("retained-canary"), b"preserve").unwrap();
                        }
                        Err("synthetic interruption".into())
                    },
                )
                .is_err());
            assert!(temp
                .path()
                .join("external-ledger-parent")
                .join(directory_name(id))
                .join(EXECUTION_Q_INTENT)
                .exists());
            assert!(!temp
                .path()
                .join("external-ledger-parent")
                .join(directory_name(id))
                .join(EXECUTION_Q_CREATED)
                .exists());
            assert_eq!(q_path.exists(), create_unknown_q);
            if create_unknown_q {
                assert_eq!(
                    fs::read(q_path.join("retained-canary")).unwrap(),
                    b"preserve"
                );
            }
            assert!(ledger
                .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .is_err());
            drop(ledger);
            assert!(PurgeLedger::open_existing(&ledger_parent, id, &hash).is_err());
            assert_eq!(q_path.exists(), create_unknown_q);
        }
    }

    #[test]
    fn execution_q_preexisting_entries_and_mount_mismatch_never_mint_intent() {
        for kind in ["directory", "symlink", "fifo"] {
            let (temp, _ledger_parent, installation_parent, root, ledger, leaf, expected, id, _) =
                execution_fixture();
            let q_path = temp
                .path()
                .join("installation-parent/installation")
                .join(EXECUTION_Q_NAME);
            match kind {
                "directory" => fs::create_dir(&q_path).unwrap(),
                "symlink" => symlink("private-canary", &q_path).unwrap(),
                "fifo" => {
                    let c = CString::new(q_path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(ledger
                .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .is_err());
            assert!(!temp
                .path()
                .join("external-ledger-parent")
                .join(directory_name(id))
                .join(EXECUTION_Q_INTENT)
                .exists());
        }
        let (temp, _, installation_parent, root, ledger, leaf, mut expected, id, _) =
            execution_fixture();
        expected.mount_id += 1;
        assert!(ledger
            .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
            .is_err());
        assert!(!temp
            .path()
            .join("external-ledger-parent")
            .join(directory_name(id))
            .join(EXECUTION_Q_INTENT)
            .exists());
        assert!(InstallationLeaf::new("../installation").is_err());
        assert!(InstallationLeaf::new("a/b").is_err());
    }

    #[test]
    fn execution_q_orphan_and_special_records_fail_closed() {
        for change in [
            "missing_intent",
            "missing_created",
            "hardlinked_created",
            "fifo_created",
            "symlink_created",
        ] {
            let (temp, ledger_parent, installation_parent, root, ledger, leaf, expected, id, hash) =
                execution_fixture();
            let q = ledger
                .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .unwrap();
            drop(q);
            drop(ledger);
            let ledger_path = temp
                .path()
                .join("external-ledger-parent")
                .join(directory_name(id));
            match change {
                "missing_intent" => fs::remove_file(ledger_path.join(EXECUTION_Q_INTENT)).unwrap(),
                "missing_created" => {
                    fs::remove_file(ledger_path.join(EXECUTION_Q_CREATED)).unwrap()
                }
                "hardlinked_created" => fs::hard_link(
                    ledger_path.join(EXECUTION_Q_CREATED),
                    temp.path().join("linked-record"),
                )
                .unwrap(),
                "fifo_created" => {
                    fs::remove_file(ledger_path.join(EXECUTION_Q_CREATED)).unwrap();
                    let path = ledger_path.join(EXECUTION_Q_CREATED);
                    let c = CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
                "symlink_created" => {
                    fs::remove_file(ledger_path.join(EXECUTION_Q_CREATED)).unwrap();
                    symlink(
                        temp.path()
                            .join("installation-parent/installation/private-canary"),
                        ledger_path.join(EXECUTION_Q_CREATED),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(PurgeLedger::open_existing(&ledger_parent, id, &hash).is_err());
            assert!(temp
                .path()
                .join("installation-parent/installation")
                .join(EXECUTION_Q_NAME)
                .exists());
        }
    }

    #[test]
    fn execution_q_pair_refuses_changed_schema_binding_and_digest() {
        for change in [
            "intent_schema",
            "created_uuid",
            "created_plan",
            "intent_digest",
        ] {
            let (temp, ledger_parent, installation_parent, root, ledger, leaf, expected, id, hash) =
                execution_fixture();
            ledger
                .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .unwrap();
            drop(ledger);
            let ledger_path = temp
                .path()
                .join("external-ledger-parent")
                .join(directory_name(id));
            let intent_path = ledger_path.join(EXECUTION_Q_INTENT);
            let created_path = ledger_path.join(EXECUTION_Q_CREATED);
            if change == "intent_schema" {
                let mut intent: ExecutionQCreateIntent =
                    serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();
                intent.schema = "foreign-schema".into();
                fs::write(&intent_path, serde_json::to_vec(&intent).unwrap()).unwrap();
            } else {
                let mut created: ExecutionQCreated =
                    serde_json::from_slice(&fs::read(&created_path).unwrap()).unwrap();
                match change {
                    "created_uuid" => created.installation_id = uuid::Uuid::new_v4(),
                    "created_plan" => created.plan_sha256 = digest(b"foreign-plan"),
                    "intent_digest" => created.create_intent_sha256 = digest(b"foreign-intent"),
                    _ => unreachable!(),
                }
                fs::write(&created_path, serde_json::to_vec(&created).unwrap()).unwrap();
            }
            assert!(PurgeLedger::open_existing(&ledger_parent, id, &hash).is_err());
            assert!(temp
                .path()
                .join("installation-parent/installation")
                .join(EXECUTION_Q_NAME)
                .exists());
        }
    }

    #[test]
    fn execution_q_replaced_child_or_root_refuses_exact_custody() {
        for replace_root in [false, true] {
            let (temp, _ledger_parent, installation_parent, root, ledger, leaf, expected, _, _) =
                execution_fixture();
            let q = ledger
                .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .unwrap();
            drop(q);
            let installation_path = temp.path().join("installation-parent/installation");
            let q_path = installation_path.join(EXECUTION_Q_NAME);
            if replace_root {
                fs::rename(
                    &installation_path,
                    temp.path().join("installation-parent/saved-root"),
                )
                .unwrap();
                fs::create_dir(&installation_path).unwrap();
                fs::set_permissions(&installation_path, fs::Permissions::from_mode(0o700)).unwrap();
            } else {
                fs::rename(&q_path, installation_path.join("saved-q")).unwrap();
                fs::create_dir(&q_path).unwrap();
                fs::set_permissions(&q_path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert!(ledger
                .open_execution_quarantine(&installation_parent, &leaf, &root, &expected)
                .is_err());
            assert!(if replace_root {
                temp.path()
                    .join("installation-parent/saved-root")
                    .join(EXECUTION_Q_NAME)
                    .exists()
            } else {
                installation_path.join("saved-q").exists()
            });
        }
    }

    #[test]
    fn execution_q_refuses_external_ledger_custody_drift_before_intent() {
        let (temp, _ledger_parent, installation_parent, root, ledger, leaf, expected, id, _) =
            execution_fixture();
        let ledger_path = temp
            .path()
            .join("external-ledger-parent")
            .join(directory_name(id));
        fs::rename(
            ledger_path.join("quarantine"),
            ledger_path.join("saved-external-q"),
        )
        .unwrap();
        fs::create_dir(ledger_path.join("quarantine")).unwrap();
        fs::set_permissions(
            ledger_path.join("quarantine"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(ledger
            .create_execution_quarantine(&installation_parent, &leaf, &root, &expected)
            .is_err());
        assert!(!ledger_path.join(EXECUTION_Q_INTENT).exists());
        assert!(ledger_path.join("saved-external-q").exists());
    }
}
