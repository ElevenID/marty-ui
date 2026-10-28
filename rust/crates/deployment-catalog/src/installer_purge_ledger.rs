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

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "purge ledger refused; retain installation and recovery evidence";
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_RECORD: usize = 4096;

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
fn read_record(parent: &File, entry: &str, limit: usize) -> Result<Option<Vec<u8>>> {
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
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(!bytes.is_empty() && bytes.len() <= limit)?;
    Ok(Some(bytes))
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
fn lock(directory: &File) -> Result<()> {
    require(unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)
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
            || name == "custody.json"
            || name == "quarantine"
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
    directory: File,
    quarantine: File,
    installation_id: uuid::Uuid,
    plan_sha256: String,
}
#[derive(PartialEq, Eq, Serialize)]
struct DirectoryStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mount_id: u64,
}
fn directory_stamp(file: &File) -> Result<DirectoryStamp> {
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
impl PurgeLedger {
    fn open_directory(parent: &File, id: uuid::Uuid, create: bool) -> Result<(File, bool)> {
        require(valid_id(id) && parent.metadata().map_err(|_| REFUSED)?.is_dir())?;
        let entry = directory_name(id);
        let created = create && mkdir_at(parent, &entry)?;
        let directory =
            open_at(parent, &entry, libc::O_RDONLY | libc::O_DIRECTORY, 0)?.ok_or(REFUSED)?;
        private(&directory, true)?;
        require(mount_id(parent)? == mount_id(&directory)?)?;
        lock(&directory)?;
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
        Ok((ledger, plan))
    }
    pub(crate) fn quarantine(&self) -> Result<&File> {
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
        self.verify_manifest()?;
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
        let created = write_or_verify(
            &self.directory,
            &format!("intent-{key}.json"),
            &bytes,
            MAX_RECORD,
        )?;
        self.verify_manifest()?;
        require(
            read_record(&self.directory, &format!("intent-{key}.json"), MAX_RECORD)?.as_deref()
                == Some(bytes.as_slice()),
        )?;
        Ok(PersistedIntent { key, created })
    }
    fn verify_intent(&self, intent: &PersistedIntent) -> Result<()> {
        self.verify_manifest()?;
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
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, File, uuid::Uuid, Vec<u8>, String) {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let id = uuid::Uuid::new_v4();
        let plan = br#"{"schema":"synthetic-purge-plan","resources":1}"#.to_vec();
        let hash = digest(&plan);
        (root, parent, id, plan, hash)
    }
    #[test]
    fn exact_manifest_intent_and_result_survive_resume() {
        let (_root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
        assert!(PurgeLedger::create_or_resume(&parent, id, b"different", &hash).is_err());
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
            let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
    }
    #[test]
    fn foreign_ledger_entry_and_replaced_manifest_refuse() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        drop(ledger);
        let path = root.path().join(directory_name(id)).join("manifest.json");
        fs::remove_file(&path).unwrap();
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
    }
    #[test]
    fn orphaned_temp_file_cannot_make_first_intent_a_retry() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        drop(ledger);
        let path = root.path().join(directory_name(id));
        let orphan = path.join(format!(".tmp-{}", uuid::Uuid::new_v4().simple()));
        fs::write(&orphan, b"incomplete intent").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
        let (resumed, _) = PurgeLedger::open_existing(&parent, id, &hash).unwrap();
        let first = resumed
            .record_intent(ResourceKind::HostEntry, &digest(b"owned-file"))
            .unwrap();
        assert!(!first.is_retry());
        assert_eq!(fs::read(&orphan).unwrap(), b"incomplete intent");
    }
    #[test]
    fn held_ledger_refuses_rebound_sibling_path() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        let path = root.path().join(directory_name(id));
        fs::rename(path.join("quarantine"), path.join("moved-quarantine")).unwrap();
        fs::create_dir(path.join("quarantine")).unwrap();
        fs::set_permissions(path.join("quarantine"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ledger.quarantine().is_err());
    }
    #[test]
    fn resumed_ledger_refuses_replaced_quarantine_and_preserves_pending_data() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
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
        assert!(PurgeLedger::create_or_resume(&parent, id, &plan, &hash).is_err());
        assert_eq!(
            fs::read(old.join("pending-owned-data")).unwrap(),
            b"retained-pending-canary"
        );
        assert_eq!(fs::read_dir(path.join("quarantine")).unwrap().count(), 0);
    }
    #[test]
    fn missing_quarantine_is_not_recreated_on_resume() {
        let (root, parent, id, plan, hash) = fixture();
        let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        let path = root.path().join(directory_name(id));
        drop(ledger);
        fs::remove_dir(path.join("quarantine")).unwrap();
        assert!(PurgeLedger::create_or_resume(&parent, id, &plan, &hash).is_err());
        assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
        assert!(!path.join("quarantine").exists());
    }
    #[test]
    fn missing_or_changed_custody_record_is_never_adopted() {
        for missing in [true, false] {
            let (root, parent, id, plan, hash) = fixture();
            let ledger = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
            let record = root.path().join(directory_name(id)).join("custody.json");
            drop(ledger);
            if missing {
                fs::remove_file(&record).unwrap();
            } else {
                fs::write(&record, b"foreign-custody-canary").unwrap();
            }
            assert!(PurgeLedger::open_existing(&parent, id, &hash).is_err());
            assert!(PurgeLedger::create_or_resume(&parent, id, &plan, &hash).is_err());
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
        let resumed = PurgeLedger::create_or_resume(&parent, id, &plan, &hash).unwrap();
        assert!(resumed.quarantine().is_ok());
        assert_eq!(fs::read(directory.join("manifest.json")).unwrap(), plan);
        assert_eq!(fs::read(directory.join("custody.json")).unwrap(), custody);
    }
}
