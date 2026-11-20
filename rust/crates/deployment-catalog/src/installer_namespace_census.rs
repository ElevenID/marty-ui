//! Private, metadata-only native namespace walk. Raw namespace owners and mount
//! IDs are not host identities. The controller must authenticate container,
//! projection, receipts and stopped writers separately. No purge conversion.
//! A user-namespace projection cannot undo an unverified per-mount ID mapping;
//! the controller must prove an equivalent ownership view or refuse.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until the distinct private native protocol is integrated.

use crate::{
    installer_host_snapshot::{mount_id, names, open_child},
    installer_purge_host::Kind,
    installer_top_level_census::CensusProfile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    os::unix::fs::{FileTypeExt, MetadataExt},
};

const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_PATH: usize = 1024;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Incomplete {
    UnsupportedProfile,
    UnsafeEntry,
    Changed,
    BoundExceeded,
}
type Result<T> = std::result::Result<T, Incomplete>;

/// Deliberately distinct from the deletion module's file/directory kind.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ObservedKind {
    File,
    Directory,
    UnixSocket,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceIdentity {
    pub dev: u64,
    pub ino: u64,
    pub namespace_uid: u32,
    pub namespace_gid: u32,
    pub mode: u32,
    pub kind: ObservedKind,
    pub links: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceEntry {
    pub relative_path: String,
    pub parent: NamespaceIdentity,
    pub target: NamespaceIdentity,
}

/// Private untrusted observation bytes, not a receipt or deletion manifest.
/// Lexicographic order intentionally conveys no deletion execution order.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceTree {
    pub root: NamespaceIdentity,
    pub namespace_mount_id: u64,
    pub local_operator_password: bool,
    pub entries_lexicographic: Vec<NamespaceEntry>,
}
impl NamespaceTree {
    pub(crate) fn private_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| Incomplete::BoundExceeded)?;
        if bytes.is_empty() || bytes.len() > MAX_RESPONSE {
            return Err(Incomplete::BoundExceeded);
        }
        Ok(bytes)
    }
}
fn identity(file: &File) -> Result<NamespaceIdentity> {
    let meta = file.metadata().map_err(|_| Incomplete::UnsafeEntry)?;
    let kind = if meta.is_dir() && meta.nlink() > 0 {
        ObservedKind::Directory
    } else if meta.is_file() && meta.nlink() == 1 {
        ObservedKind::File
    } else if meta.file_type().is_socket() && meta.nlink() == 1 {
        ObservedKind::UnixSocket
    } else {
        return Err(Incomplete::UnsafeEntry);
    };
    if meta.dev() == 0 || meta.ino() == 0 {
        return Err(Incomplete::UnsafeEntry);
    }
    Ok(NamespaceIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        namespace_uid: meta.uid(),
        namespace_gid: meta.gid(),
        mode: meta.mode() & 0o7777,
        kind,
        links: meta.nlink(),
        size: meta.len(),
        mtime_seconds: meta.mtime(),
        mtime_nanoseconds: meta.mtime_nsec(),
        ctime_seconds: meta.ctime(),
        ctime_nanoseconds: meta.ctime_nsec(),
    })
}
fn component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control())
}
fn child(parent: &File, name: &str) -> Result<File> {
    if !component(name) {
        return Err(Incomplete::UnsafeEntry);
    }
    open_child(parent, OsStr::new(name), libc::O_PATH)
        .map_err(|_| Incomplete::UnsafeEntry)?
        .ok_or(Incomplete::Changed)
}
fn current(file: &File, expected: &NamespaceIdentity, mount: u64) -> Result<()> {
    if identity(file)? != *expected || mount_id(file).ok() != Some(mount) {
        return Err(Incomplete::Changed);
    }
    Ok(())
}
fn directory(held: &File, expected: &NamespaceIdentity, mount: u64) -> Result<File> {
    if expected.kind != ObservedKind::Directory {
        return Err(Incomplete::UnsafeEntry);
    }
    let dir = open_child(held, OsStr::new("."), libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| Incomplete::UnsafeEntry)?
        .ok_or(Incomplete::Changed)?;
    current(&dir, expected, mount)?;
    Ok(dir)
}
fn directory_names(file: &File) -> Result<Vec<String>> {
    names(file)
        .map_err(|_| Incomplete::BoundExceeded)?
        .into_iter()
        .map(|name| {
            let name = name.into_string().map_err(|_| Incomplete::UnsafeEntry)?;
            if !component(&name) || name.len() > MAX_PATH {
                return Err(Incomplete::UnsafeEntry);
            }
            Ok(name)
        })
        .collect()
}

struct Walk {
    mount: u64,
    device: u64,
    entries: Vec<NamespaceEntry>,
    directories: BTreeMap<String, (NamespaceIdentity, Vec<String>)>,
    inodes: BTreeSet<(u64, u64)>,
}
impl Walk {
    fn visit(
        &mut self,
        parent: &File,
        parent_identity: &NamespaceIdentity,
        name: &str,
        path: &str,
    ) -> Result<NamespaceIdentity> {
        if self.entries.len() >= MAX_ENTRIES
            || path.len() > MAX_PATH
            || path.split('/').count() > MAX_DEPTH
        {
            return Err(Incomplete::BoundExceeded);
        }
        current(parent, parent_identity, self.mount)?;
        let held = child(parent, name)?;
        let observed = identity(&held)?;
        if observed.dev != self.device
            || mount_id(&held).ok() != Some(self.mount)
            || !self.inodes.insert((observed.dev, observed.ino))
        {
            return Err(Incomplete::UnsafeEntry);
        }
        self.entries.push(NamespaceEntry {
            relative_path: path.to_owned(),
            parent: parent_identity.clone(),
            target: observed.clone(),
        });
        if observed.kind == ObservedKind::Directory {
            let dir = directory(&held, &observed, self.mount)?;
            let before = directory_names(&dir)?;
            self.directories
                .insert(path.to_owned(), (observed.clone(), before.clone()));
            for leaf in &before {
                self.visit(&dir, &observed, leaf, &format!("{path}/{leaf}"))?;
            }
            if directory_names(&dir)? != before {
                return Err(Incomplete::Changed);
            }
            current(&dir, &observed, self.mount)?;
        }
        current(&held, &observed, self.mount)?;
        current(&child(parent, name)?, &observed, self.mount)?;
        current(parent, parent_identity, self.mount)?;
        Ok(observed)
    }
}
fn reopen_directory(root: &File, relative: &str) -> Result<File> {
    let mut held = root.try_clone().map_err(|_| Incomplete::UnsafeEntry)?;
    for name in relative.split('/') {
        held = child(&held, name)?;
        if identity(&held)?.kind != ObservedKind::Directory {
            return Err(Incomplete::UnsafeEntry);
        }
    }
    Ok(held)
}
fn observe_with_hook(
    root: &File,
    profile: CensusProfile,
    after_walk: impl FnOnce(),
) -> Result<NamespaceTree> {
    let CensusProfile::NativeComposeV2 {
        local_operator_password,
    } = profile
    else {
        return Err(Incomplete::UnsupportedProfile);
    };
    let expected = profile
        .names()
        .into_iter()
        .map(|name| (name.name(), name.expected_kind()))
        .collect::<BTreeMap<_, _>>();
    let original = identity(root)?;
    if original.kind != ObservedKind::Directory || original.mode != 0o700 {
        return Err(Incomplete::UnsafeEntry);
    }
    let mount = mount_id(root).map_err(|_| Incomplete::UnsafeEntry)?;
    let dir = directory(root, &original, mount)?;
    let top = directory_names(&dir)?;
    if top.iter().cloned().collect::<BTreeSet<_>>() != expected.keys().cloned().collect() {
        return Err(Incomplete::Changed);
    }
    let mut walk = Walk {
        mount,
        device: original.dev,
        entries: Vec::new(),
        directories: BTreeMap::new(),
        inodes: BTreeSet::from([(original.dev, original.ino)]),
    };
    for name in &top {
        let actual = walk.visit(&dir, &original, name, name)?;
        if !matches!(
            (expected[name], actual.kind),
            (Kind::Directory, ObservedKind::Directory) | (Kind::File, ObservedKind::File)
        ) {
            return Err(Incomplete::UnsafeEntry);
        }
    }
    after_walk();
    if directory_names(&dir)? != top {
        return Err(Incomplete::Changed);
    }
    current(root, &original, mount)?;
    current(&dir, &original, mount)?;
    // Rebind all paths and every directory's names after the complete walk.
    for entry in &walk.entries {
        let (parent, leaf) = match entry.relative_path.rsplit_once('/') {
            Some((relative, leaf)) => (reopen_directory(root, relative)?, leaf),
            None => (
                root.try_clone().map_err(|_| Incomplete::UnsafeEntry)?,
                entry.relative_path.as_str(),
            ),
        };
        current(&parent, &entry.parent, mount)?;
        current(&child(&parent, leaf)?, &entry.target, mount)?;
    }
    for (relative, (observed, before)) in &walk.directories {
        let held = reopen_directory(root, relative)?;
        let directory = directory(&held, observed, mount)?;
        if directory_names(&directory)? != *before {
            return Err(Incomplete::Changed);
        }
        current(&held, observed, mount)?;
    }
    current(root, &original, mount)?;
    walk.entries
        .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    let tree = NamespaceTree {
        root: original,
        namespace_mount_id: mount,
        local_operator_password,
        entries_lexicographic: walk.entries,
    };
    tree.private_bytes()?;
    Ok(tree)
}

/// Read-only operations on a held root, not an assertion that its mount is RO.
/// The protocol owner must separately enforce the exact read-only bind, call
/// twice around receipt/projection revalidation, and authenticate the profile.
pub(crate) fn observe_held(root: &File, profile: CensusProfile) -> Result<NamespaceTree> {
    observe_with_hook(root, profile, || {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{
            fs::{symlink, PermissionsExt},
            net::UnixListener,
        },
        path::PathBuf,
    };

    fn fixture(local: bool) -> (tempfile::TempDir, PathBuf, File, UnixListener) {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().join("installation");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in (CensusProfile::NativeComposeV2 {
            local_operator_password: local,
        })
        .names()
        {
            let path = root.join(name.name());
            match name.expected_kind() {
                Kind::Directory => {
                    fs::create_dir(&path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                Kind::File => {
                    fs::write(&path, b"SYNTHETIC_FILE_BYTES_NOT_TO_READ").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
        }
        let socket = root.join("openbao-control/observer.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let held = File::open(&root).unwrap();
        (temporary, root, held, listener)
    }
    fn profile(local: bool) -> CensusProfile {
        CensusProfile::NativeComposeV2 {
            local_operator_password: local,
        }
    }
    #[test]
    fn exact_native_profiles_observe_socket_metadata_without_connecting_or_reading_contents() {
        for local in [true, false] {
            let (_temporary, _path, root, listener) = fixture(local);
            let first = observe_held(&root, profile(local)).unwrap();
            let second = observe_held(&root, profile(local)).unwrap();
            assert!(first == second);
            assert_eq!(
                first.entries_lexicographic.len(),
                if local { 25 } else { 24 }
            );
            assert!(first
                .entries_lexicographic
                .iter()
                .any(|entry| entry.target.kind == ObservedKind::UnixSocket));
            assert!(!String::from_utf8(first.private_bytes().unwrap())
                .unwrap()
                .contains("SYNTHETIC_FILE_BYTES_NOT_TO_READ"));
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(observe_held(&root, CensusProfile::LegacyNormal31).is_err());
        }
    }
    #[test]
    fn unknown_missing_symlink_hardlink_and_fifo_entries_are_refused() {
        for case in ["unknown", "missing", "symlink", "hardlink", "fifo"] {
            let (_temporary, path, root, _listener) = fixture(true);
            match case {
                "unknown" => {
                    fs::write(path.join("unknown"), b"x").unwrap();
                }
                "missing" => fs::remove_dir(path.join("downloads")).unwrap(),
                "symlink" => symlink(path.join("state"), path.join("evidence/alias")).unwrap(),
                "hardlink" => {
                    fs::hard_link(path.join("operator-password"), path.join("evidence/alias"))
                        .unwrap()
                }
                "fifo" => {
                    let path = std::ffi::CString::new(
                        path.join("evidence/fifo").as_os_str().as_encoded_bytes(),
                    )
                    .unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(observe_held(&root, profile(true)).is_err(), "{case}");
        }
    }
    #[test]
    fn replacement_after_walk_never_returns_the_old_inode_set() {
        let (temporary, path, root, _listener) = fixture(true);
        fs::write(path.join("backups/payload"), b"synthetic").unwrap();
        let outcome = observe_with_hook(&root, profile(true), || {
            fs::rename(
                path.join("backups/payload"),
                temporary.path().join("preserved-old-payload"),
            )
            .unwrap();
            fs::write(path.join("backups/payload"), b"synthetic").unwrap();
        });
        assert!(matches!(outcome, Err(Incomplete::Changed)));
    }
    #[test]
    fn excessive_depth_and_response_bytes_are_bounded() {
        let (_temporary, path, root, _listener) = fixture(true);
        let mut current = path.join("evidence");
        for _ in 0..MAX_DEPTH {
            current = current.join("nested");
            fs::create_dir(&current).unwrap();
        }
        assert!(matches!(
            observe_held(&root, profile(true)),
            Err(Incomplete::BoundExceeded)
        ));
        let (_temporary, _path, root, _listener) = fixture(false);
        let mut tree = observe_held(&root, profile(false)).unwrap();
        tree.entries_lexicographic[0].relative_path = "x".repeat(MAX_RESPONSE);
        assert!(matches!(
            tree.private_bytes(),
            Err(Incomplete::BoundExceeded)
        ));
    }
}
