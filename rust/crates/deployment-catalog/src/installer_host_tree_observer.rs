//! Read-only current tree census under the exact normal installer top level.
//! Local creation custody and stopped writers are external coordinator duties.
//! No file contents are read and this result never authorizes deletion.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until the full receipt coordinator is reviewed.

use crate::{
    installer_host_snapshot::{directory, identity, mount_id, names, open_child},
    installer_purge_host::{HostIdentity, HostPurgeEntry, Kind},
    installer_state::LockedInspection,
    installer_top_level_census::{
        self, CensusOutcome, ExpectedTopLevel, IncompleteReason as TopReason,
    },
};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};

const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_PATH: usize = 1024;

/// This is an observational set of exact current identities, not an immutable
/// deletion manifest. Removing the installation root requires separate proof.
pub(crate) struct TreeObservation {
    pub coverage: &'static str,
    pub installation_id: uuid::Uuid,
    pub root: HostIdentity,
    pub mount_id: u64,
    pub entries: Vec<HostPurgeEntry>,
    pub not_atomic_snapshot: bool,
    pub deletion_eligible: bool,
}
pub(crate) enum IncompleteReason {
    TopLevel(TopReason),
    ChangedTopLevel,
    UnsafeOrChangedEntry,
    BoundExceeded,
}
pub(crate) enum TreeOutcome {
    Observed(TreeObservation),
    Incomplete(IncompleteReason),
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control())
}
fn open_directory_path(root: &File, path: &str) -> Option<File> {
    let mut current = root.try_clone().ok()?;
    for component in path.split('/') {
        current = open_child(
            &current,
            OsStr::new(component),
            libc::O_PATH | libc::O_DIRECTORY,
        )
        .ok()??;
    }
    Some(current)
}
fn visit(
    parent: &File,
    parent_identity: &HostIdentity,
    name: &str,
    path: &str,
    mount: u64,
    entries: &mut Vec<HostPurgeEntry>,
    directory_names: &mut BTreeMap<String, (HostIdentity, Vec<std::ffi::OsString>)>,
) -> Result<HostIdentity, IncompleteReason> {
    let depth = path.split('/').count();
    if !valid_component(name)
        || path.len() > MAX_PATH
        || depth > MAX_DEPTH
        || entries.len() >= MAX_ENTRIES
    {
        return Err(IncompleteReason::BoundExceeded);
    }
    let held = open_child(parent, OsStr::new(name), libc::O_PATH)
        .ok()
        .flatten()
        .ok_or(IncompleteReason::UnsafeOrChangedEntry)?;
    let current = identity(&held).map_err(|_| IncompleteReason::UnsafeOrChangedEntry)?;
    if current.dev != parent_identity.dev || mount_id(&held).ok() != Some(mount) {
        return Err(IncompleteReason::UnsafeOrChangedEntry);
    }
    entries.push(HostPurgeEntry {
        relative_path: path.to_owned(),
        parent: parent_identity.clone(),
        target: current.clone(),
    });
    if current.kind == Kind::Directory {
        // Opening for enumeration happens only after O_PATH classified a
        // directory; an unreadable directory fails closed without escalation.
        let dir = directory(&held, &current, mount)
            .map_err(|_| IncompleteReason::UnsafeOrChangedEntry)?;
        let before = names(&dir).map_err(|_| IncompleteReason::BoundExceeded)?;
        directory_names.insert(path.to_owned(), (current.clone(), before.clone()));
        for child_name in &before {
            let child = child_name
                .to_str()
                .ok_or(IncompleteReason::UnsafeOrChangedEntry)?;
            let child_path = format!("{path}/{child}");
            visit(
                &dir,
                &current,
                child,
                &child_path,
                mount,
                entries,
                directory_names,
            )?;
        }
        if names(&dir).ok().as_ref() != Some(&before)
            || identity(&dir).ok().as_ref() != Some(&current)
            || identity(&held).ok().as_ref() != Some(&current)
        {
            return Err(IncompleteReason::UnsafeOrChangedEntry);
        }
    }
    // Rebind the current parent name, not only the old held descriptor.
    let latest = open_child(parent, OsStr::new(name), libc::O_PATH)
        .ok()
        .flatten()
        .ok_or(IncompleteReason::UnsafeOrChangedEntry)?;
    if identity(&latest).ok().as_ref() != Some(&current) || mount_id(&latest).ok() != Some(mount) {
        return Err(IncompleteReason::UnsafeOrChangedEntry);
    }
    Ok(current)
}

/// Shared held-FD walk. `inspect_top` enforces the exact fixed top level both
/// before and after the descendant walk; its caller owns authentication.
fn observe_core<I: FnMut() -> CensusOutcome, F: FnOnce()>(
    root: &File,
    expected_root: &HostIdentity,
    expected_mount: u64,
    mut inspect_top: I,
    after_walk: F,
) -> TreeOutcome {
    let first = match inspect_top() {
        CensusOutcome::ExactExpectedSetObserved(snapshot) => snapshot,
        CensusOutcome::Incomplete(reason) => {
            return TreeOutcome::Incomplete(IncompleteReason::TopLevel(reason));
        }
    };
    let mut entries = Vec::new();
    let mut directory_names = BTreeMap::new();
    for top in &first.entries {
        let observed = match visit(
            root,
            expected_root,
            &top.relative_path,
            &top.relative_path,
            expected_mount,
            &mut entries,
            &mut directory_names,
        ) {
            Ok(identity) => identity,
            Err(reason) => return TreeOutcome::Incomplete(reason),
        };
        if observed != top.target {
            return TreeOutcome::Incomplete(IncompleteReason::ChangedTopLevel);
        }
    }
    after_walk();
    let second = match inspect_top() {
        CensusOutcome::ExactExpectedSetObserved(snapshot) => snapshot,
        CensusOutcome::Incomplete(reason) => {
            return TreeOutcome::Incomplete(IncompleteReason::TopLevel(reason));
        }
    };
    if first.entries != second.entries
        || first.root != second.root
        || first.mount_id != second.mount_id
        || first.installation_id != second.installation_id
    {
        return TreeOutcome::Incomplete(IncompleteReason::ChangedTopLevel);
    }
    // The second census only freezes the top-level name set for an instant.
    // Reopen every observed descendant path once more before returning so a
    // late same-name replacement is noticed; writers must still be stopped.
    for entry in &entries {
        let parent_path = entry.relative_path.rsplit_once('/').map(|(p, _)| p);
        let parent = if let Some(path) = parent_path {
            open_directory_path(root, path)
        } else {
            root.try_clone().ok()
        };
        let Some(parent) = parent else {
            return TreeOutcome::Incomplete(IncompleteReason::UnsafeOrChangedEntry);
        };
        if identity(&parent).ok().as_ref() != Some(&entry.parent)
            || mount_id(&parent).ok() != Some(expected_mount)
        {
            return TreeOutcome::Incomplete(IncompleteReason::UnsafeOrChangedEntry);
        }
        let leaf = entry.relative_path.rsplit('/').next().unwrap();
        let latest = open_child(&parent, OsStr::new(leaf), libc::O_PATH)
            .ok()
            .flatten();
        if latest.as_ref().and_then(|f| identity(f).ok()).as_ref() != Some(&entry.target)
            || latest.as_ref().and_then(|f| mount_id(f).ok()) != Some(expected_mount)
        {
            return TreeOutcome::Incomplete(IncompleteReason::UnsafeOrChangedEntry);
        }
    }
    for (path, (expected_identity, expected_names)) in &directory_names {
        let Some(held) = open_directory_path(root, path) else {
            return TreeOutcome::Incomplete(IncompleteReason::UnsafeOrChangedEntry);
        };
        let dir = directory(&held, expected_identity, expected_mount);
        if dir.ok().and_then(|dir| names(&dir).ok()).as_ref() != Some(expected_names) {
            return TreeOutcome::Incomplete(IncompleteReason::UnsafeOrChangedEntry);
        }
    }
    if identity(root).ok().as_ref() != Some(expected_root)
        || mount_id(root).ok() != Some(expected_mount)
    {
        return TreeOutcome::Incomplete(IncompleteReason::ChangedTopLevel);
    }
    entries.sort_by(|a, b| {
        b.relative_path
            .split('/')
            .count()
            .cmp(&a.relative_path.split('/').count())
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    TreeOutcome::Observed(TreeObservation {
        coverage: "expected_normal_profile_current_tree",
        installation_id: first.installation_id,
        root: expected_root.clone(),
        mount_id: expected_mount,
        entries,
        not_atomic_snapshot: true,
        deletion_eligible: false,
    })
}

/// Descriptor-only full current tree observation. The caller must derive the
/// fixed 31-name specs inside the same namespace and authenticate any
/// receipt-bound roots separately. No journal or ownership assertion is made.
pub(crate) fn observe_held(
    root: &File,
    installation_id: uuid::Uuid,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
) -> TreeOutcome {
    observe_core(
        root,
        expected_root,
        expected_mount,
        || {
            installer_top_level_census::inspect_held(
                root,
                installation_id,
                expected_root,
                expected_mount,
                specs,
            )
        },
        || {},
    )
}

/// Host wrapper retains its original locked path/journal checks at both
/// top-level inspections. A held FD alone does not bind the installation path.
fn observe_with_hook<F: FnOnce()>(
    locked: &LockedInspection,
    installation: &Path,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
    after_walk: F,
) -> TreeOutcome {
    let result = observe_core(
        locked.installation_directory(),
        expected_root,
        expected_mount,
        || {
            installer_top_level_census::inspect(
                locked,
                installation,
                expected_root,
                expected_mount,
                specs,
            )
        },
        after_walk,
    );
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return TreeOutcome::Incomplete(IncompleteReason::ChangedTopLevel);
    }
    result
}
pub(crate) fn observe(
    locked: &LockedInspection,
    installation: &Path,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
) -> TreeOutcome {
    observe_with_hook(
        locked,
        installation,
        expected_root,
        expected_mount,
        specs,
        || {},
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installer_state::{Identity, InstallerState},
        installer_top_level_census::TopLevelName,
    };
    use std::{
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        },
        path::PathBuf,
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        path: PathBuf,
        locked: LockedInspection,
        root: HostIdentity,
        mount: u64,
        specs: Vec<ExpectedTopLevel>,
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("installation");
        let state = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        drop(state);
        let mut specs = Vec::new();
        for name in TopLevelName::REQUIRED {
            let target = path.join(name.name());
            if name != TopLevelName::Journal {
                match name.expected_kind() {
                    Kind::Directory => {
                        fs::create_dir(&target).unwrap();
                        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    Kind::File => {
                        fs::write(&target, b"synthetic fixture").unwrap();
                        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                }
            }
            specs.push(ExpectedTopLevel {
                name,
                identity: identity(&File::open(&target).unwrap()).unwrap(),
            });
        }
        let downloads = path.join("downloads");
        fs::create_dir(downloads.join("extracted")).unwrap();
        fs::create_dir(downloads.join("extracted/sub")).unwrap();
        fs::write(downloads.join("extracted/sub/payload"), b"synthetic").unwrap();
        fs::write(path.join("evidence/receipt.json"), b"synthetic").unwrap();
        let locked = LockedInspection::open(&path).unwrap();
        let root = identity(locked.installation_directory()).unwrap();
        let mount = mount_id(locked.installation_directory()).unwrap();
        Fixture {
            _temp: temp,
            path,
            locked,
            root,
            mount,
            specs,
        }
    }
    fn result(f: &Fixture) -> TreeOutcome {
        observe(&f.locked, &f.path, &f.root, f.mount, &f.specs)
    }
    #[test]
    fn exact_normal_profile_and_all_current_children_observed() {
        let f = fixture();
        let TreeOutcome::Observed(tree) = result(&f) else {
            panic!("expected observed tree")
        };
        assert_eq!(tree.coverage, "expected_normal_profile_current_tree");
        assert_eq!(tree.entries.len(), 35);
        assert_eq!(
            tree.entries[0].relative_path,
            "downloads/extracted/sub/payload"
        );
        assert_eq!(tree.root, f.root);
        assert_eq!(tree.mount_id, f.mount);
        assert_eq!(tree.installation_id, f.locked.journal().installation_id());
        assert!(tree.not_atomic_snapshot);
        assert!(!tree.deletion_eligible);
    }

    #[test]
    fn held_backend_matches_host_tree_but_host_wrapper_rejects_path_rebinding() {
        let f = fixture();
        let derived = installer_top_level_census::derive_current_fixed_specs_held(
            f.locked.installation_directory(),
            &f.root,
            f.mount,
        )
        .unwrap();
        let TreeOutcome::Observed(held) = observe_held(
            f.locked.installation_directory(),
            f.locked.journal().installation_id(),
            &f.root,
            f.mount,
            &derived,
        ) else {
            panic!("expected descriptor-only observation")
        };
        let TreeOutcome::Observed(host) = result(&f) else {
            panic!("expected host-bound observation")
        };
        assert_eq!(held.entries, host.entries);
        assert_eq!(held.root, host.root);
        assert_eq!(held.mount_id, host.mount_id);
        assert!(!held.deletion_eligible);
        assert!(held.not_atomic_snapshot);
        let mut wrong = f.root.clone();
        wrong.ino = wrong.ino.wrapping_add(1);
        assert!(matches!(
            observe_held(
                f.locked.installation_directory(),
                f.locked.journal().installation_id(),
                &wrong,
                f.mount,
                &derived,
            ),
            TreeOutcome::Incomplete(_)
        ));
        assert!(matches!(
            observe_held(
                f.locked.installation_directory(),
                f.locked.journal().installation_id(),
                &f.root,
                f.mount + 1,
                &derived,
            ),
            TreeOutcome::Incomplete(_)
        ));
        let moved = f.path.with_file_name("held-original");
        fs::rename(&f.path, &moved).unwrap();
        fs::create_dir(&f.path).unwrap();
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            observe_held(
                f.locked.installation_directory(),
                f.locked.journal().installation_id(),
                &f.root,
                f.mount,
                &derived,
            ),
            TreeOutcome::Observed(_)
        ));
        assert!(matches!(result(&f), TreeOutcome::Incomplete(_)));
    }
    #[test]
    fn unknown_top_level_link_hardlink_and_special_refuse() {
        let f = fixture();
        fs::write(f.path.join("customer-canary"), b"x").unwrap();
        assert!(matches!(result(&f), TreeOutcome::Incomplete(_)));
        fs::remove_file(f.path.join("customer-canary")).unwrap();
        symlink("receipt.json", f.path.join("evidence/link")).unwrap();
        assert!(matches!(result(&f), TreeOutcome::Incomplete(_)));
        fs::remove_file(f.path.join("evidence/link")).unwrap();
        fs::hard_link(
            f.path.join("evidence/receipt.json"),
            f.path.join("evidence/link"),
        )
        .unwrap();
        assert!(matches!(result(&f), TreeOutcome::Incomplete(_)));
        fs::remove_file(f.path.join("evidence/link")).unwrap();
        let fifo =
            std::ffi::CString::new(f.path.join("evidence/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(matches!(result(&f), TreeOutcome::Incomplete(_)));
    }
    #[test]
    fn wrong_mount_and_excess_depth_refuse() {
        let f = fixture();
        assert!(matches!(
            observe(&f.locked, &f.path, &f.root, f.mount + 1, &f.specs),
            TreeOutcome::Incomplete(_)
        ));
        let mut current = f.path.join("evidence");
        for i in 0..16 {
            current = current.join(format!("level{i}"));
            fs::create_dir(&current).unwrap();
        }
        assert!(matches!(
            result(&f),
            TreeOutcome::Incomplete(IncompleteReason::BoundExceeded)
        ));
    }
    #[test]
    fn child_created_after_walk_fails_final_name_recheck() {
        let f = fixture();
        let result = observe_with_hook(&f.locked, &f.path, &f.root, f.mount, &f.specs, || {
            fs::write(f.path.join("evidence/late"), b"synthetic").unwrap()
        });
        assert!(matches!(result, TreeOutcome::Incomplete(_)));
    }
}
