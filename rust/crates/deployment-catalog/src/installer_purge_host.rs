//! Dormant, descriptor-bound deletion of exact host entries. The caller must
//! authenticate the manifest and each permit, stop all writers, and keep the
//! separate quarantine directory under exclusive custody. This module neither
//! verifies receipts nor authorizes purge. It makes no sanitization claim.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // No production caller exists until the purge coordinator is reviewed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

pub(crate) type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "host purge refused; preserve all remaining and quarantined data";
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_PATH: usize = 1024;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct HostPurgeEntry {
    pub relative_path: String,
    pub parent: HostIdentity,
    pub target: HostIdentity,
}

#[derive(Clone, Debug)]
pub(crate) struct HostPurgeManifest {
    pub installation_id: uuid::Uuid,
    pub root: HostIdentity,
    /// A private directory outside the root slated for deletion, on its mount.
    pub quarantine: HostIdentity,
    /// Strict deepest-first order, then lexicographic path order at each depth.
    pub entries: Vec<HostPurgeEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservedState {
    Present,
    Quarantined,
    Absent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Removed,
    AlreadyAbsent,
}

/// The coordinator produces this only after checking its external receipt and
/// authorization. `acknowledge_absent` requires prior exact intent evidence.
#[derive(Clone, Debug)]
pub(crate) struct Permit {
    pub intent_sha256: String,
    pub acknowledge_absent: bool,
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && !path.starts_with('/')
        && path.split('/').count() <= MAX_DEPTH
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.bytes().any(|b| b == 0 || b.is_ascii_control())
        })
}
fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or(".", |(p, _)| p)
}
fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap()
}
fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| REFUSED.into())
}

fn validate(manifest: &HostPurgeManifest) -> Result<()> {
    if manifest.entries.is_empty()
        || manifest.entries.len() > MAX_ENTRIES
        || manifest.root.kind != Kind::Directory
        || manifest.quarantine.kind != Kind::Directory
        || manifest.root == manifest.quarantine
        || manifest.quarantine.mode != 0o700
    {
        return Err(REFUSED.into());
    }
    let mut paths = BTreeSet::new();
    let mut by_path = BTreeMap::new();
    let mut previous: Option<(usize, &str)> = None;
    for entry in &manifest.entries {
        let path = entry.relative_path.as_str();
        if !valid_path(path) || !paths.insert(path) {
            return Err(REFUSED.into());
        }
        let depth = path.split('/').count();
        if let Some((old_depth, old_path)) = previous {
            if depth > old_depth || (depth == old_depth && path <= old_path) {
                return Err(REFUSED.into());
            }
        }
        previous = Some((depth, path));
        by_path.insert(path, entry);
    }
    for entry in &manifest.entries {
        let parent = parent_path(&entry.relative_path);
        if parent == "." {
            if entry.parent != manifest.root {
                return Err(REFUSED.into());
            }
        } else {
            let listed = by_path.get(parent).ok_or(REFUSED)?;
            if listed.target.kind != Kind::Directory || listed.target != entry.parent {
                return Err(REFUSED.into());
            }
        }
    }
    Ok(())
}

fn openat2(parent: &File, path: &str, flags: i32) -> Result<Option<File>> {
    let name = cstr(path)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
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
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(REFUSED.into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd as i32) }))
}

fn mount_id(file: &File) -> Result<u64> {
    // Linux exposes the mount ID of this exact held descriptor in fdinfo.
    // Check the directory is genuine procfs before trusting its contents.
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let proc = File::open("/proc/self/fdinfo").map_err(|_| REFUSED)?;
    let mut fs_info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut fs_info) } != 0
        || fs_info.f_type as i64 != PROC_SUPER_MAGIC
    {
        return Err(REFUSED.into());
    }
    let name = cstr(&file.as_raw_fd().to_string())?;
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
    let fdinfo = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    fdinfo
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    if bytes.len() > 4096 {
        return Err(REFUSED.into());
    }
    parse_mount_id(&bytes)
}

fn parse_mount_id(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let raw = ids.next().ok_or(REFUSED)?.trim_ascii();
    if ids.next().is_some() || raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(REFUSED.into());
    }
    let value = raw.parse::<u64>().map_err(|_| REFUSED)?;
    if value == 0 {
        return Err(REFUSED.into());
    }
    Ok(value)
}

fn identity(meta: &Metadata) -> Result<HostIdentity> {
    let kind = if meta.is_dir() {
        Kind::Directory
    } else if meta.is_file() && meta.nlink() == 1 {
        Kind::File
    } else {
        return Err(REFUSED.into());
    };
    Ok(HostIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
        kind,
    })
}
fn verify(file: &File, expected: &HostIdentity) -> Result<()> {
    if identity(&file.metadata().map_err(|_| REFUSED)?)? != *expected {
        Err(REFUSED.into())
    } else {
        Ok(())
    }
}

fn require_empty_directory(file: &File, expected: &HostIdentity) -> Result<()> {
    if expected.kind != Kind::Directory {
        return Ok(());
    }
    let directory = openat2(file, ".", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(REFUSED)?;
    verify(&directory, expected)?;
    let mut items =
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(|_| REFUSED)?;
    if items.next().is_some() {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn tombstone(manifest: &HostPurgeManifest, entry: &HostPurgeEntry) -> Result<String> {
    let bytes = serde_json::to_vec(&(manifest.installation_id, entry)).map_err(|_| REFUSED)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("marty-purge-{:x}", digest))
}
pub(crate) fn intent_sha256(
    manifest: &HostPurgeManifest,
    entry: &HostPurgeEntry,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(manifest.installation_id, entry)).map_err(|_| REFUSED)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn inspect_quarantine(
    quarantine: &File,
    name: &str,
    expected: &HostIdentity,
) -> Result<Option<File>> {
    if let Some(file) = openat2(quarantine, name, libc::O_PATH)? {
        verify(&file, expected)?;
        require_empty_directory(&file, expected)?;
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

fn same_inode(left: &File, right: &File) -> Result<()> {
    let left = left.metadata().map_err(|_| REFUSED)?;
    let right = right.metadata().map_err(|_| REFUSED)?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn inspect_parent(
    root: &File,
    manifest: &HostPurgeManifest,
    entry: &HostPurgeEntry,
) -> Result<Option<File>> {
    let path = parent_path(&entry.relative_path);
    match openat2(root, path, libc::O_PATH | libc::O_DIRECTORY)? {
        Some(parent) => {
            verify(&parent, &entry.parent)?;
            Ok(Some(parent))
        }
        None if path != "." && manifest.entries.iter().any(|e| e.relative_path == path) => Ok(None),
        None => Err(REFUSED.into()),
    }
}

fn authorize<F>(
    manifest: &HostPurgeManifest,
    entry: &HostPurgeEntry,
    state: ObservedState,
    callback: &mut F,
) -> Result<()>
where
    F: FnMut(&HostPurgeEntry, ObservedState, &str) -> Result<Permit>,
{
    let digest = intent_sha256(manifest, entry)?;
    let permit = callback(entry, state, &digest)?;
    if permit.intent_sha256 != digest
        || permit.acknowledge_absent != (state == ObservedState::Absent)
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn move_to_quarantine(parent: &File, source: &str, quarantine: &File, name: &str) -> Result<()> {
    let source = cstr(source)?;
    let name = cstr(name)?;
    // The syscall is available on supported Linux kernels even when musl does
    // not export a renameat2 wrapper. ENOSYS fails closed on older kernels.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            source.as_ptr(),
            quarantine.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(REFUSED.into());
    }
    Ok(())
}
fn remove_quarantined(quarantine: &File, name: &str, kind: Kind) -> Result<()> {
    let name = cstr(name)?;
    let flags = if kind == Kind::Directory {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    if unsafe { libc::unlinkat(quarantine.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn sync_directories(parent: &File, expected: &HostIdentity, quarantine: &File) -> Result<()> {
    let held_parent = openat2(parent, ".", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(REFUSED)?;
    verify(&held_parent, expected)?;
    held_parent.sync_all().map_err(|_| REFUSED)?;
    quarantine.sync_all().map_err(|_| REFUSED)?;
    Ok(())
}

fn lock_quarantine(
    quarantine: &File,
    expected: &HostIdentity,
) -> Result<crate::installer_state::LockedDirectory> {
    // Use a fresh open description so another invocation cannot share this
    // lock. Explicit owner-PID unlock also releases it if a concurrent fork
    // retains a duplicate until exec, including on an interrupted move.
    let held = openat2(quarantine, ".", libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(REFUSED)?;
    verify(&held, expected)?;
    crate::installer_state::lock(held).map_err(|_| REFUSED.into())
}

fn apply_inner<F, H, C>(
    root: &File,
    quarantine: &File,
    manifest: &HostPurgeManifest,
    callback: &mut F,
    after_move: &mut H,
    completed: &mut C,
) -> Result<Vec<Outcome>>
where
    F: FnMut(&HostPurgeEntry, ObservedState, &str) -> Result<Permit>,
    H: FnMut(&HostPurgeEntry) -> Result<()>,
    C: FnMut(&HostPurgeEntry, Outcome, &str) -> Result<()>,
{
    validate(manifest)?;
    verify(root, &manifest.root)?;
    verify(quarantine, &manifest.quarantine)?;
    if mount_id(root)? != mount_id(quarantine)?
        || manifest.quarantine.uid != unsafe { libc::geteuid() }
    {
        return Err(REFUSED.into());
    }
    let held_quarantine = lock_quarantine(quarantine, &manifest.quarantine)?;
    let expected_names: BTreeSet<_> = manifest
        .entries
        .iter()
        .map(|e| tombstone(manifest, e))
        .collect::<Result<_>>()?;
    let mut observed_names = BTreeSet::new();
    for item in fs::read_dir(format!("/proc/self/fd/{}", held_quarantine.as_raw_fd()))
        .map_err(|_| REFUSED)?
    {
        let name = item.map_err(|_| REFUSED)?.file_name();
        let name = name.to_str().ok_or(REFUSED)?;
        if !expected_names.contains(name)
            || !observed_names.insert(name.to_owned())
            || observed_names.len() > MAX_ENTRIES
        {
            return Err(REFUSED.into());
        }
    }
    let mut outcomes = Vec::new();
    for entry in &manifest.entries {
        verify(root, &manifest.root)?;
        verify(&held_quarantine, &manifest.quarantine)?;
        let name = tombstone(manifest, entry)?;
        let pending = inspect_quarantine(&held_quarantine, &name, &entry.target)?;
        let parent = inspect_parent(root, manifest, entry)?;
        let present = if let Some(parent) = &parent {
            match openat2(parent, leaf(&entry.relative_path), libc::O_PATH)? {
                Some(file) => {
                    verify(&file, &entry.target)?;
                    require_empty_directory(&file, &entry.target)?;
                    Some(file)
                }
                None => None,
            }
        } else {
            None
        };
        if pending.is_some() && present.is_some() {
            return Err(REFUSED.into());
        }
        let state = if pending.is_some() {
            ObservedState::Quarantined
        } else if present.is_some() {
            ObservedState::Present
        } else {
            ObservedState::Absent
        };
        authorize(manifest, entry, state, callback)?;
        let outcome = match state {
            ObservedState::Absent => Outcome::AlreadyAbsent,
            ObservedState::Present => {
                let parent = parent.as_ref().ok_or(REFUSED)?;
                move_to_quarantine(parent, leaf(&entry.relative_path), &held_quarantine, &name)?;
                sync_directories(parent, &entry.parent, &held_quarantine)?;
                after_move(entry)?;
                let moved =
                    inspect_quarantine(&held_quarantine, &name, &entry.target)?.ok_or(REFUSED)?;
                same_inode(present.as_ref().ok_or(REFUSED)?, &moved)?;
                verify(root, &manifest.root)?;
                verify(&held_quarantine, &manifest.quarantine)?;
                remove_quarantined(&held_quarantine, &name, entry.target.kind)?;
                sync_directories(parent, &entry.parent, &held_quarantine)?;
                Outcome::Removed
            }
            ObservedState::Quarantined => {
                let parent = parent.as_ref().ok_or(REFUSED)?;
                let current =
                    inspect_quarantine(&held_quarantine, &name, &entry.target)?.ok_or(REFUSED)?;
                same_inode(pending.as_ref().ok_or(REFUSED)?, &current)?;
                verify(root, &manifest.root)?;
                verify(&held_quarantine, &manifest.quarantine)?;
                remove_quarantined(&held_quarantine, &name, entry.target.kind)?;
                sync_directories(parent, &entry.parent, &held_quarantine)?;
                Outcome::Removed
            }
        };
        // Stop on persistence failure, before authorizing or touching the next
        // entry. An interrupted result write leaves the prior exact intent as
        // the coordinator's only basis for acknowledging absence on retry.
        completed(entry, outcome, &intent_sha256(manifest, entry)?)?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Dormant host walker. External coordinator must verify the immutable receipt,
/// prove prior intent for absence, and guarantee exclusive quarantine custody.
/// A racing replacement can be moved into quarantine, but a mismatched inode is
/// never unlinked; its recovery requires a separate explicit decision.
pub(crate) fn apply<F>(
    root: &File,
    quarantine: &File,
    manifest: &HostPurgeManifest,
    mut authorize: F,
) -> Result<Vec<Outcome>>
where
    F: FnMut(&HostPurgeEntry, ObservedState, &str) -> Result<Permit>,
{
    apply_with_results(root, quarantine, manifest, &mut authorize, |_, _, _| Ok(()))
}

/// Persist each result after removal and directory fsync, before the next
/// authorization. The coordinator must durably bind it to the exact prior
/// intent, and preserve an existing result when retry observes absence. Both
/// callbacks may fail closed; this function cannot roll back a completed unlink.
pub(crate) fn apply_with_results<F, C>(
    root: &File,
    quarantine: &File,
    manifest: &HostPurgeManifest,
    mut authorize: F,
    mut completed: C,
) -> Result<Vec<Outcome>>
where
    F: FnMut(&HostPurgeEntry, ObservedState, &str) -> Result<Permit>,
    C: FnMut(&HostPurgeEntry, Outcome, &str) -> Result<()>,
{
    apply_inner(
        root,
        quarantine,
        manifest,
        &mut authorize,
        &mut |_| Ok(()),
        &mut completed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        },
        path::PathBuf,
        process::Command,
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        root_path: PathBuf,
        quarantine_path: PathBuf,
        root: File,
        quarantine: File,
        manifest: HostPurgeManifest,
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("owned");
        let quarantine_path = temp.path().join("quarantine");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(&quarantine_path).unwrap();
        fs::set_permissions(&quarantine_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root_path.join("payload"), b"synthetic").unwrap();
        let root = File::open(&root_path).unwrap();
        let quarantine = File::open(&quarantine_path).unwrap();
        let root_id = identity(&root.metadata().unwrap()).unwrap();
        let quarantine_id = identity(&quarantine.metadata().unwrap()).unwrap();
        let payload_id = identity(&fs::metadata(root_path.join("payload")).unwrap()).unwrap();
        let manifest = HostPurgeManifest {
            installation_id: uuid::Uuid::new_v4(),
            root: root_id.clone(),
            quarantine: quarantine_id,
            entries: vec![HostPurgeEntry {
                relative_path: "payload".into(),
                parent: root_id,
                target: payload_id,
            }],
        };
        Fixture {
            _temp: temp,
            root_path,
            quarantine_path,
            root,
            quarantine,
            manifest,
        }
    }

    #[test]
    fn mount_id_is_bound_to_fdinfo_and_parser_fails_closed() {
        let f = fixture();
        let root_mount = mount_id(&f.root).unwrap();
        assert_ne!(root_mount, 0);
        assert_eq!(root_mount, mount_id(&f.quarantine).unwrap());
        assert_eq!(parse_mount_id(b"pos:\t0\nmnt_id:\t123\n").unwrap(), 123);
        for invalid in [
            &b"pos:\t0\n"[..],
            &b"mnt_id:\t0\n"[..],
            &b"mnt_id:\t12x\n"[..],
            &b"mnt_id:\t12\nmnt_id:\t12\n"[..],
            &b"mnt_id:\t18446744073709551616\n"[..],
        ] {
            assert!(parse_mount_id(invalid).is_err());
        }
    }
    fn permitted(_: &HostPurgeEntry, state: ObservedState, digest: &str) -> Result<Permit> {
        Ok(Permit {
            intent_sha256: digest.into(),
            acknowledge_absent: state == ObservedState::Absent,
        })
    }

    // The parent invokes this exact ignored test in a separate process. It
    // checks the actual kernel lock while the parent retains its own guard or
    // a duplicate of the old open description.
    #[test]
    #[ignore = "subprocess probe invoked by quarantine lock regression"]
    fn quarantine_lock_child_probe() {
        let Some(path) = std::env::var_os("MARTY_PURGE_TEST_LOCK_DIR") else {
            return;
        };
        let parent_pid: u32 = std::env::var("MARTY_PURGE_TEST_PARENT_PID")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(std::process::id(), parent_pid);
        let directory = File::open(path).unwrap();
        let expected = identity(&directory.metadata().unwrap()).unwrap();
        let acquired = lock_quarantine(&directory, &expected);
        match std::env::var("MARTY_PURGE_TEST_EXPECT").unwrap().as_str() {
            "acquire" => assert!(acquired.is_ok()),
            "refuse" => assert!(acquired.is_err()),
            _ => panic!("unexpected synthetic probe expectation"),
        }
        println!("MARTY_PURGE_LOCK_CHILD_PROBE_OK");
    }

    fn assert_child_lock(f: &Fixture, expected: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "--nocapture",
                "installer_purge_host::tests::quarantine_lock_child_probe",
            ])
            .env("MARTY_PURGE_TEST_LOCK_DIR", &f.quarantine_path)
            .env(
                "MARTY_PURGE_TEST_PARENT_PID",
                std::process::id().to_string(),
            )
            .env("MARTY_PURGE_TEST_EXPECT", expected)
            .output()
            .unwrap();
        assert!(output.status.success(), "synthetic lock child failed");
        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        assert!(stdout.contains("MARTY_PURGE_LOCK_CHILD_PROBE_OK"));
        assert!(stdout.contains("1 passed; 0 failed"));
    }

    #[test]
    fn quarantine_lock_releases_retained_description_on_success_and_error() {
        for interrupted in [false, true] {
            let f = fixture();
            let mut inherited = None;
            let result: Result<()> = (|| {
                let guard = lock_quarantine(&f.quarantine, &f.manifest.quarantine)?;
                // A clone shares the open description, just as fork does.
                inherited = Some(guard.try_clone().unwrap());
                assert!(lock_quarantine(&f.quarantine, &f.manifest.quarantine).is_err());
                assert_child_lock(&f, "refuse");
                if interrupted {
                    return Err("synthetic interruption".into());
                }
                Ok(())
            })();
            assert_eq!(result.is_err(), interrupted);
            assert_child_lock(&f, "acquire");
            let successor = lock_quarantine(&f.quarantine, &f.manifest.quarantine).unwrap();
            // The old inherited description must not retain or release the
            // successor's lock when closed.
            drop(inherited.take().unwrap());
            assert!(lock_quarantine(&f.quarantine, &f.manifest.quarantine).is_err());
            assert_child_lock(&f, "refuse");
            drop(successor);
            assert!(lock_quarantine(&f.quarantine, &f.manifest.quarantine).is_ok());
            assert_child_lock(&f, "acquire");
            assert_eq!(fs::read(f.root_path.join("payload")).unwrap(), b"synthetic");
            assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 0);
        }
    }

    #[test]
    fn exact_file_removal_and_acknowledged_resume() {
        let f = fixture();
        assert_eq!(
            apply(&f.root, &f.quarantine, &f.manifest, permitted).unwrap(),
            [Outcome::Removed]
        );
        assert!(!f.root_path.join("payload").exists());
        assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 0);
        assert_eq!(
            apply(&f.root, &f.quarantine, &f.manifest, permitted).unwrap(),
            [Outcome::AlreadyAbsent]
        );
    }

    #[test]
    fn result_failure_stops_before_next_entry_and_retry_reports_absence() {
        let mut f = fixture();
        fs::write(f.root_path.join("z-canary"), b"later-customer-data").unwrap();
        f.manifest.entries.push(HostPurgeEntry {
            relative_path: "z-canary".into(),
            parent: f.manifest.root.clone(),
            target: identity(&fs::metadata(f.root_path.join("z-canary")).unwrap()).unwrap(),
        });
        let mut authorized = Vec::new();
        let mut reported = Vec::new();
        assert!(apply_with_results(
            &f.root,
            &f.quarantine,
            &f.manifest,
            |entry, state, digest| {
                authorized.push(entry.relative_path.clone());
                permitted(entry, state, digest)
            },
            |entry, outcome, digest| {
                assert!(!f.root_path.join(&entry.relative_path).exists());
                assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 0);
                assert_eq!(digest, intent_sha256(&f.manifest, entry).unwrap());
                reported.push((entry.relative_path.clone(), outcome));
                Err("synthetic durable-result failure".into())
            },
        )
        .is_err());
        assert_eq!(authorized, ["payload"]);
        assert_eq!(reported, [("payload".into(), Outcome::Removed)]);
        assert_eq!(
            fs::read(f.root_path.join("z-canary")).unwrap(),
            b"later-customer-data"
        );
        let mut retry_results = Vec::new();
        assert_eq!(
            apply_with_results(
                &f.root,
                &f.quarantine,
                &f.manifest,
                permitted,
                |entry, outcome, digest| {
                    assert_eq!(digest, intent_sha256(&f.manifest, entry).unwrap());
                    retry_results.push(outcome);
                    Ok(())
                },
            )
            .unwrap(),
            [Outcome::AlreadyAbsent, Outcome::Removed]
        );
        assert_eq!(retry_results, [Outcome::AlreadyAbsent, Outcome::Removed]);
    }

    #[test]
    fn no_result_is_reported_before_authorization_or_durable_removal() {
        let f = fixture();
        let mut reports = 0;
        assert!(apply_with_results(
            &f.root,
            &f.quarantine,
            &f.manifest,
            |_, _, _| Err("synthetic intent failure".into()),
            |_, _, _| {
                reports += 1;
                Ok(())
            },
        )
        .is_err());
        assert_eq!(reports, 0);
        assert_eq!(fs::read(f.root_path.join("payload")).unwrap(), b"synthetic");
        assert!(apply_inner(
            &f.root,
            &f.quarantine,
            &f.manifest,
            &mut permitted,
            &mut |_| Err("synthetic interruption after quarantine rename".into()),
            &mut |_, _, _| {
                reports += 1;
                Ok(())
            },
        )
        .is_err());
        assert_eq!(reports, 0);
        assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 1);
        assert_eq!(
            apply_with_results(
                &f.root,
                &f.quarantine,
                &f.manifest,
                permitted,
                |_, outcome, _| {
                    assert_eq!(outcome, Outcome::Removed);
                    reports += 1;
                    Ok(())
                },
            )
            .unwrap(),
            [Outcome::Removed]
        );
        assert_eq!(reports, 1);
    }

    #[test]
    fn unexplained_absence_and_wrong_permit_refuse() {
        let f = fixture();
        fs::remove_file(f.root_path.join("payload")).unwrap();
        assert!(
            apply(&f.root, &f.quarantine, &f.manifest, |_, _, digest| Ok(
                Permit {
                    intent_sha256: digest.into(),
                    acknowledge_absent: false,
                }
            ))
            .is_err()
        );
        assert!(
            apply(&f.root, &f.quarantine, &f.manifest, |_, _, _| Ok(Permit {
                intent_sha256: "wrong".into(),
                acknowledge_absent: true,
            }))
            .is_err()
        );
    }

    #[test]
    fn interrupted_move_resumes_only_the_matching_tombstone() {
        let f = fixture();
        let pending = tombstone(&f.manifest, &f.manifest.entries[0]).unwrap();
        assert!(apply_inner(
            &f.root,
            &f.quarantine,
            &f.manifest,
            &mut permitted,
            &mut |_| Err("synthetic interruption".into()),
            &mut |_, _, _| Ok(())
        )
        .is_err());
        assert!(!f.root_path.join("payload").exists());
        assert!(f.quarantine_path.join(&pending).exists());
        assert_eq!(
            apply(&f.root, &f.quarantine, &f.manifest, permitted).unwrap(),
            [Outcome::Removed]
        );
        assert!(!f.quarantine_path.join(&pending).exists());
    }

    #[test]
    fn racing_replacement_is_preserved_in_quarantine() {
        let f = fixture();
        let pending = tombstone(&f.manifest, &f.manifest.entries[0]).unwrap();
        assert!(apply(&f.root, &f.quarantine, &f.manifest, |_, _, digest| {
            fs::remove_file(f.root_path.join("payload")).unwrap();
            fs::write(f.root_path.join("payload"), b"foreign-canary").unwrap();
            Ok(Permit {
                intent_sha256: digest.into(),
                acknowledge_absent: false,
            })
        })
        .is_err());
        assert_eq!(
            fs::read(f.quarantine_path.join(&pending)).unwrap(),
            b"foreign-canary"
        );
        assert!(apply(&f.root, &f.quarantine, &f.manifest, permitted).is_err());
        assert_eq!(
            fs::read(f.quarantine_path.join(&pending)).unwrap(),
            b"foreign-canary"
        );
    }

    #[test]
    fn links_and_special_files_refuse_without_mutation() {
        for replacement in ["symlink", "hardlink", "fifo"] {
            let f = fixture();
            let path = f.root_path.join("payload");
            let outside = f._temp.path().join("outside");
            fs::write(&outside, b"outside-canary").unwrap();
            fs::remove_file(&path).unwrap();
            match replacement {
                "symlink" => symlink(&outside, &path).unwrap(),
                "hardlink" => fs::hard_link(&outside, &path).unwrap(),
                "fifo" => {
                    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(apply(&f.root, &f.quarantine, &f.manifest, permitted).is_err());
            assert_eq!(fs::read(&outside).unwrap(), b"outside-canary");
            assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 0);
        }
    }

    #[test]
    fn nested_directory_must_be_manifested_and_removed_last() {
        let mut f = fixture();
        fs::create_dir(f.root_path.join("subdir")).unwrap();
        fs::write(f.root_path.join("subdir/leaf"), b"leaf").unwrap();
        let dir_id = identity(&fs::metadata(f.root_path.join("subdir")).unwrap()).unwrap();
        let file_id = identity(&fs::metadata(f.root_path.join("subdir/leaf")).unwrap()).unwrap();
        f.manifest.entries = vec![
            HostPurgeEntry {
                relative_path: "subdir/leaf".into(),
                parent: dir_id.clone(),
                target: file_id,
            },
            HostPurgeEntry {
                relative_path: "payload".into(),
                parent: f.manifest.root.clone(),
                target: f.manifest.entries[0].target.clone(),
            },
            HostPurgeEntry {
                relative_path: "subdir".into(),
                parent: f.manifest.root.clone(),
                target: dir_id,
            },
        ];
        assert_eq!(
            apply(&f.root, &f.quarantine, &f.manifest, permitted).unwrap(),
            [Outcome::Removed, Outcome::Removed, Outcome::Removed]
        );
        assert_eq!(
            apply(&f.root, &f.quarantine, &f.manifest, permitted).unwrap(),
            [
                Outcome::AlreadyAbsent,
                Outcome::AlreadyAbsent,
                Outcome::AlreadyAbsent
            ]
        );
    }

    #[test]
    fn unlisted_directory_content_is_not_moved_or_removed() {
        let mut f = fixture();
        fs::create_dir(f.root_path.join("subdir")).unwrap();
        fs::write(f.root_path.join("subdir/unlisted"), b"customer-canary").unwrap();
        let dir_id = identity(&fs::metadata(f.root_path.join("subdir")).unwrap()).unwrap();
        f.manifest.entries = vec![HostPurgeEntry {
            relative_path: "subdir".into(),
            parent: f.manifest.root.clone(),
            target: dir_id,
        }];
        assert!(apply(&f.root, &f.quarantine, &f.manifest, permitted).is_err());
        assert_eq!(
            fs::read(f.root_path.join("subdir/unlisted")).unwrap(),
            b"customer-canary"
        );
        assert_eq!(fs::read_dir(&f.quarantine_path).unwrap().count(), 0);
    }
}
