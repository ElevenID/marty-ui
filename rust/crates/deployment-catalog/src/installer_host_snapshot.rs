//! Read-only, bounded candidate snapshot for the seven fixed host storage roots.
//! Complete means only that these seven roots match the supplied expectations;
//! other installation content remains outside this module's coverage.
//! A complete observation is not an ownership proof, atomic filesystem snapshot,
//! receipt, authorization, or deletion manifest. The coordinator must establish
//! all of those separately and must stop writers before any later purge.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until a reviewed receipt coordinator consumes it.

use crate::{
    installer_purge_host::{HostIdentity, HostPurgeEntry, Kind},
    installer_state::LockedInspection,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr},
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

const REFUSED: &str = "host snapshot incomplete; retain all data";
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_PATH: usize = 1024;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
type Result<T> = std::result::Result<T, String>;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RootName {
    OpenBaoState,
    State,
    Secrets,
    OperatorPassword,
    Backups,
    OpenBaoExports,
    OpenBaoSnapshotIdentity,
}
impl RootName {
    const ALL: [Self; 7] = [
        Self::OpenBaoState,
        Self::State,
        Self::Secrets,
        Self::OperatorPassword,
        Self::Backups,
        Self::OpenBaoExports,
        Self::OpenBaoSnapshotIdentity,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::OpenBaoState => "openbao-state",
            Self::State => "state",
            Self::Secrets => "secrets",
            Self::OperatorPassword => "operator-password",
            Self::Backups => "backups",
            Self::OpenBaoExports => "openbao-exports",
            Self::OpenBaoSnapshotIdentity => "openbao-snapshot-identity",
        }
    }
}

/// Expected identities come from an external authenticated receipt. Child
/// paths are private coordinator inputs and must never be emitted in diagnostics.
pub(crate) struct RootSpec {
    pub name: RootName,
    pub expected: Option<HostIdentity>,
    pub exact_children: BTreeMap<String, HostIdentity>,
}

/// Deliberately has no Serialize implementation: relative paths may contain
/// customer or secret filenames. Even Complete does not authorize deletion.
pub(crate) struct HostSnapshot {
    pub coverage: &'static str,
    pub installation_id: uuid::Uuid,
    pub root: HostIdentity,
    pub mount_id: u64,
    pub entries: Vec<HostPurgeEntry>,
    pub not_atomic_snapshot: bool,
    pub deletion_eligible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IncompleteReason {
    InvalidSpecification,
    MissingOrChangedEntry,
    UnknownChild,
    UnsafeEntry,
    BoundExceeded,
}
#[derive(Debug, Serialize)]
pub(crate) struct Incomplete {
    pub coverage: &'static str,
    pub reason: IncompleteReason,
    pub deletion_eligible: bool,
}
pub(crate) enum BuildOutcome {
    Complete(HostSnapshot),
    Incomplete(Incomplete),
}
fn incomplete(reason: IncompleteReason) -> BuildOutcome {
    BuildOutcome::Incomplete(Incomplete {
        coverage: "known_host_storage_roots_only",
        reason,
        deletion_eligible: false,
    })
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && path.split('/').count() <= MAX_DEPTH
        && path.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.bytes().any(|b| b == 0 || b.is_ascii_control())
        })
}
fn cstr(name: &OsStr) -> Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b".." || bytes.contains(&b'/') {
        return Err(REFUSED.into());
    }
    CString::new(bytes).map_err(|_| REFUSED.into())
}
fn open_child(parent: &File, name: &OsStr, flags: i32) -> Result<Option<File>> {
    let name = cstr(name)?;
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
    let mut ids = text.lines().filter_map(|s| s.strip_prefix("mnt_id:"));
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
fn identity(file: &File) -> Result<HostIdentity> {
    let meta = file.metadata().map_err(|_| REFUSED)?;
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
fn names(directory: &File) -> Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for item in
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(|_| REFUSED)?
    {
        names.push(item.map_err(|_| REFUSED)?.file_name());
        if names.len() > MAX_ENTRIES {
            return Err(REFUSED.into());
        }
    }
    names.sort();
    Ok(names)
}
fn directory(held: &File, expected: &HostIdentity, expected_mount: u64) -> Result<File> {
    let dir =
        open_child(held, OsStr::new("."), libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(REFUSED)?;
    if identity(&dir)? != *expected || mount_id(&dir)? != expected_mount {
        return Err(REFUSED.into());
    }
    Ok(dir)
}
fn walk(
    parent: &File,
    parent_identity: &HostIdentity,
    path: &str,
    expected_mount: u64,
    entries: &mut Vec<HostPurgeEntry>,
) -> Result<()> {
    if !valid_path(path) || entries.len() >= MAX_ENTRIES {
        return Err(REFUSED.into());
    }
    let leaf = path.rsplit('/').next().ok_or(REFUSED)?;
    let held = open_child(parent, OsStr::new(leaf), libc::O_PATH)?.ok_or(REFUSED)?;
    let current = identity(&held)?;
    if current.dev != parent_identity.dev || mount_id(&held)? != expected_mount {
        return Err(REFUSED.into());
    }
    entries.push(HostPurgeEntry {
        relative_path: path.to_owned(),
        parent: parent_identity.clone(),
        target: current.clone(),
    });
    if current.kind == Kind::Directory {
        let dir = directory(&held, &current, expected_mount)?;
        for name in names(&dir)? {
            let child = name.to_str().ok_or(REFUSED)?;
            let child_path = format!("{path}/{child}");
            walk(&dir, &current, &child_path, expected_mount, entries)?;
        }
        if identity(&held)? != current || identity(&dir)? != current {
            return Err(REFUSED.into());
        }
    }
    Ok(())
}

fn build_inner_with_hook<F: FnOnce()>(
    installation: &File,
    installation_id: uuid::Uuid,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[RootSpec],
    before_final_check: F,
) -> BuildOutcome {
    let mut by_name = BTreeMap::new();
    for spec in specs {
        if by_name.insert(spec.name, spec).is_some()
            || spec.exact_children.keys().any(|s| !valid_path(s))
            || (spec.expected.is_none() && !spec.exact_children.is_empty())
        {
            return incomplete(IncompleteReason::InvalidSpecification);
        }
    }
    if specs.len() != RootName::ALL.len()
        || RootName::ALL.iter().any(|name| !by_name.contains_key(name))
        || expected_root.kind != Kind::Directory
        || identity(installation).ok().as_ref() != Some(expected_root)
        || mount_id(installation).ok() != Some(expected_mount)
    {
        return incomplete(IncompleteReason::InvalidSpecification);
    }
    let mut entries = Vec::new();
    for root in RootName::ALL {
        let spec = by_name[&root];
        let present = match open_child(installation, OsStr::new(root.name()), libc::O_PATH) {
            Ok(file) => file,
            Err(_) => return incomplete(IncompleteReason::UnsafeEntry),
        };
        if present.is_some() != spec.expected.is_some() {
            return incomplete(IncompleteReason::MissingOrChangedEntry);
        }
        if let Some(expected) = &spec.expected {
            let held = present.unwrap();
            if identity(&held).ok().as_ref() != Some(expected)
                || mount_id(&held).ok() != Some(expected_mount)
            {
                return incomplete(IncompleteReason::MissingOrChangedEntry);
            }
            if walk(
                installation,
                expected_root,
                root.name(),
                expected_mount,
                &mut entries,
            )
            .is_err()
            {
                return incomplete(IncompleteReason::UnsafeEntry);
            }
            if entries
                .iter()
                .find(|entry| entry.relative_path == root.name())
                .map(|entry| &entry.target)
                != Some(expected)
            {
                return incomplete(IncompleteReason::MissingOrChangedEntry);
            }
            let actual: BTreeMap<_, _> = entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .relative_path
                        .strip_prefix(root.name())
                        .and_then(|p| p.strip_prefix('/'))
                        .map(|name| (name.to_owned(), entry.target.clone()))
                })
                .collect();
            if actual != spec.exact_children {
                return incomplete(IncompleteReason::UnknownChild);
            }
            if identity(&held).ok().as_ref() != Some(expected) {
                return incomplete(IncompleteReason::MissingOrChangedEntry);
            }
            let latest = open_child(installation, OsStr::new(root.name()), libc::O_PATH)
                .ok()
                .flatten();
            if latest
                .as_ref()
                .and_then(|file| identity(file).ok())
                .as_ref()
                != Some(expected)
                || latest.as_ref().and_then(|file| mount_id(file).ok()) != Some(expected_mount)
            {
                return incomplete(IncompleteReason::MissingOrChangedEntry);
            }
        }
    }
    before_final_check();
    for root in RootName::ALL {
        if by_name[&root].expected.is_none() {
            match open_child(installation, OsStr::new(root.name()), libc::O_PATH) {
                Ok(None) => {}
                _ => return incomplete(IncompleteReason::MissingOrChangedEntry),
            }
        }
    }
    if identity(installation).ok().as_ref() != Some(expected_root)
        || mount_id(installation).ok() != Some(expected_mount)
    {
        return incomplete(IncompleteReason::MissingOrChangedEntry);
    }
    entries.sort_by(|a, b| {
        b.relative_path
            .split('/')
            .count()
            .cmp(&a.relative_path.split('/').count())
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    BuildOutcome::Complete(HostSnapshot {
        coverage: "known_host_storage_roots_only",
        installation_id,
        root: expected_root.clone(),
        mount_id: expected_mount,
        entries,
        not_atomic_snapshot: true,
        deletion_eligible: false,
    })
}
fn build_inner(
    installation: &File,
    installation_id: uuid::Uuid,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[RootSpec],
) -> BuildOutcome {
    build_inner_with_hook(
        installation,
        installation_id,
        expected_root,
        expected_mount,
        specs,
        || {},
    )
}

/// Caller inputs are untrusted until the coordinator verifies its receipt.
/// No returned entry may be used for purge without a separate exact intent.
pub(crate) fn build(
    locked: &LockedInspection,
    installation: &Path,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[RootSpec],
) -> BuildOutcome {
    if locked.require_path_binding(installation).is_err() {
        return incomplete(IncompleteReason::MissingOrChangedEntry);
    }
    let result = build_inner(
        locked.installation_directory(),
        locked.journal().installation_id(),
        expected_root,
        expected_mount,
        specs,
    );
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return incomplete(IncompleteReason::MissingOrChangedEntry);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    fn fixture() -> (tempfile::TempDir, File, HostIdentity, u64, Vec<RootSpec>) {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("installation.json"), b"synthetic").unwrap();
        fs::create_dir(temp.path().join("backups")).unwrap();
        fs::write(temp.path().join("backups/known"), b"synthetic").unwrap();
        let dir = File::open(temp.path()).unwrap();
        let root_identity = identity(&dir).unwrap();
        let mount = mount_id(&dir).unwrap();
        let specs = RootName::ALL
            .iter()
            .map(|&name| RootSpec {
                name,
                expected: (name == RootName::Backups)
                    .then(|| identity(&File::open(temp.path().join("backups")).unwrap()).unwrap()),
                exact_children: if name == RootName::Backups {
                    BTreeMap::from([(
                        "known".to_owned(),
                        identity(&File::open(temp.path().join("backups/known")).unwrap()).unwrap(),
                    )])
                } else {
                    BTreeMap::new()
                },
            })
            .collect();
        (temp, dir, root_identity, mount, specs)
    }
    fn result(dir: &File, root: &HostIdentity, mount: u64, specs: &[RootSpec]) -> BuildOutcome {
        build_inner(dir, uuid::Uuid::nil(), root, mount, specs)
    }
    #[test]
    fn exact_synthetic_tree_is_complete_and_ordered() {
        let (_temp, dir, root, mount, specs) = fixture();
        let BuildOutcome::Complete(snapshot) = result(&dir, &root, mount, &specs) else {
            panic!("expected complete");
        };
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].relative_path, "backups/known");
        assert_eq!(snapshot.coverage, "known_host_storage_roots_only");
        assert!(snapshot.not_atomic_snapshot);
        assert!(!snapshot.deletion_eligible);
    }
    #[test]
    fn unknown_storage_child_is_incomplete_without_name_output() {
        let (temp, dir, root, mount, specs) = fixture();
        fs::write(temp.path().join("backups/customer-secret-name"), b"x").unwrap();
        let BuildOutcome::Incomplete(reason) = result(&dir, &root, mount, &specs) else {
            panic!("expected incomplete");
        };
        let json = serde_json::to_string(&reason).unwrap();
        assert!(!json.contains("customer-secret-name"));
    }
    #[test]
    fn links_hardlinks_and_specials_refuse() {
        let (temp, dir, root, mount, specs) = fixture();
        symlink("known", temp.path().join("backups/link")).unwrap();
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
        fs::remove_file(temp.path().join("backups/link")).unwrap();
        fs::hard_link(
            temp.path().join("backups/known"),
            temp.path().join("backups/link"),
        )
        .unwrap();
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
        fs::remove_file(temp.path().join("backups/link")).unwrap();
        let fifo = CString::new(temp.path().join("backups/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
    }
    #[test]
    fn wrong_mount_identity_and_missing_root_refuse() {
        let (temp, dir, root, mount, specs) = fixture();
        assert!(matches!(
            result(&dir, &root, mount + 1, &specs),
            BuildOutcome::Incomplete(_)
        ));
        fs::remove_file(temp.path().join("backups/known")).unwrap();
        fs::remove_dir(temp.path().join("backups")).unwrap();
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
    }
    #[test]
    fn same_name_replacement_does_not_match_receipt_identity() {
        let (temp, dir, root, mount, specs) = fixture();
        // Keep the old inode allocated while replacing its directory entry.
        let _old_inode = File::open(temp.path().join("backups/known")).unwrap();
        fs::remove_file(temp.path().join("backups/known")).unwrap();
        fs::write(temp.path().join("backups/known"), b"replacement").unwrap();
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
    }
    #[test]
    fn fixed_root_replacement_refuses() {
        let (temp, dir, root, mount, specs) = fixture();
        let retired = tempfile::tempdir_in(temp.path().parent().unwrap()).unwrap();
        fs::rename(temp.path().join("backups"), retired.path().join("old")).unwrap();
        fs::create_dir(temp.path().join("backups")).unwrap();
        fs::write(temp.path().join("backups/known"), b"replacement").unwrap();
        assert!(matches!(
            result(&dir, &root, mount, &specs),
            BuildOutcome::Incomplete(_)
        ));
    }
    #[test]
    fn ordinary_auxiliary_material_is_outside_storage_coverage() {
        let (temp, dir, root, mount, specs) = fixture();
        for name in ["downloads", "evidence", "keycloak-output", "tls-output"] {
            fs::create_dir(temp.path().join(name)).unwrap();
            fs::write(temp.path().join(name).join("synthetic"), b"retained").unwrap();
        }
        for name in ["marty-deploy", "openbao.env", "openbao-created.json"] {
            fs::write(temp.path().join(name), b"retained").unwrap();
        }
        let BuildOutcome::Complete(snapshot) = result(&dir, &root, mount, &specs) else {
            panic!("expected storage-only complete");
        };
        assert_eq!(snapshot.coverage, "known_host_storage_roots_only");
        assert_eq!(snapshot.entries.len(), 2);
        assert!(snapshot
            .entries
            .iter()
            .all(|entry| entry.relative_path.starts_with("backups")));
        assert!(temp.path().join("marty-deploy").exists());
    }
    #[test]
    fn expected_absent_storage_root_created_mid_scan_refuses() {
        let (temp, dir, root, mount, specs) = fixture();
        let outcome = build_inner_with_hook(&dir, uuid::Uuid::nil(), &root, mount, &specs, || {
            fs::create_dir(temp.path().join("evidence")).unwrap();
            fs::create_dir(temp.path().join("secrets")).unwrap();
        });
        assert!(matches!(outcome, BuildOutcome::Incomplete(_)));
    }
}
