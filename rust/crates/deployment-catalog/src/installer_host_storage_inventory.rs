//! Read-only metadata inventory of known installation host storage roots.
//! This is not an ownership proof for Docker resources or a deletion manifest.
#![cfg(target_os = "linux")]

use crate::installer_state::LockedInspection;
use serde::Serialize;
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, Metadata},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

type Result<T> = std::result::Result<T, String>;
const MAX_ENTRIES: usize = 16_384;
const MAX_DEPTH: usize = 16;
const REFUSED: &str = "host storage inventory is incomplete or unsafe";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ApplicationData,
    OpenBaoData,
    Credential,
    Backup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Directory,
    File,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct HostEntry {
    /// A fixed, approved root name. Child filenames are never serialized.
    pub root: &'static str,
    pub category: Category,
    pub entry_type: EntryType,
    pub size_bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Serialize)]
pub struct HostStorageInventory {
    pub schema: &'static str,
    pub installation_id: String,
    pub coverage: &'static str,
    /// The journal lock does not freeze files created or changed by containers.
    pub not_atomic_snapshot: bool,
    /// Observed owner/mode metadata and device/inode never authorize deletion.
    pub deletion_eligible: bool,
    pub entries: Vec<HostEntry>,
}

fn component(name: &OsStr) -> Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(REFUSED.into());
    }
    CString::new(bytes).map_err(|_| REFUSED.into())
}

fn open_child(parent: &File, name: &OsStr) -> Result<Option<File>> {
    let name = component(name)?;
    // O_PATH obtains metadata without opening a FIFO/device for reading or
    // triggering its open-time behavior. O_NOFOLLOW prevents link traversal.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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

fn open_directory(held: &File, expected: &Metadata) -> Result<File> {
    let dot = CString::new(".").unwrap();
    let fd = unsafe {
        libc::openat(
            held.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(REFUSED.into());
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    let current = directory.metadata().map_err(|_| REFUSED)?;
    if !current.is_dir() || current.dev() != expected.dev() || current.ino() != expected.ino() {
        return Err(REFUSED.into());
    }
    Ok(directory)
}

fn metadata(file: &File, device: u64) -> Result<(Metadata, EntryType)> {
    let meta = file.metadata().map_err(|_| REFUSED)?;
    if meta.dev() != device {
        return Err(REFUSED.into());
    }
    let entry_type = if meta.is_dir() {
        EntryType::Directory
    } else if meta.is_file() && meta.nlink() == 1 {
        EntryType::File
    } else {
        return Err(REFUSED.into());
    };
    Ok((meta, entry_type))
}

fn add(
    entries: &mut Vec<HostEntry>,
    file: &File,
    root: &'static str,
    category: Category,
    device: u64,
    depth: usize,
) -> Result<()> {
    if entries.len() >= MAX_ENTRIES || depth > MAX_DEPTH {
        return Err(REFUSED.into());
    }
    let (meta, entry_type) = metadata(file, device)?;
    entries.push(HostEntry {
        root,
        category,
        entry_type,
        size_bytes: if entry_type == EntryType::File {
            meta.len()
        } else {
            0
        },
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
        device: meta.dev(),
        inode: meta.ino(),
    });
    if entry_type == EntryType::Directory {
        let directory = open_directory(file, &meta)?;
        // Enumerate the held descriptor, never a newly resolved path.
        let held_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let mut names = Vec::new();
        for item in fs::read_dir(held_path).map_err(|_| REFUSED)? {
            let item = item.map_err(|_| REFUSED)?;
            let name = item.file_name();
            component(&name)?;
            names.push(name);
            if entries.len() + names.len() > MAX_ENTRIES {
                return Err(REFUSED.into());
            }
        }
        names.sort();
        for name in names {
            let child = open_child(&directory, &name)?.ok_or(REFUSED)?;
            add(entries, &child, root, category, device, depth + 1)?;
        }
    }
    Ok(())
}

fn scan(installation: &File) -> Result<Vec<HostEntry>> {
    let device = installation.metadata().map_err(|_| REFUSED)?.dev();
    let mut entries = Vec::new();
    for (root, category) in [
        ("openbao-state", Category::OpenBaoData),
        ("state", Category::ApplicationData),
        ("secrets", Category::Credential),
        ("operator-password", Category::Credential),
        ("backups", Category::Backup),
        ("openbao-exports", Category::Backup),
        ("openbao-snapshot-identity", Category::Backup),
    ] {
        if let Some(file) = open_child(installation, OsStr::new(root))? {
            add(&mut entries, &file, root, category, device, 0)?;
        }
    }
    Ok(entries)
}

/// Inventory known host storage roots while the installation journal is locked.
/// Absent roots are omitted because provisioning may be incomplete. Callers must
/// not treat this as proof that Docker volumes or every host artifact is known.
/// UID/mode are observations, not verified ownership; a same-device bind mount
/// can still appear under a known root. This output cannot authorize purge.
fn inspect_held(locked: &LockedInspection, installation: &Path) -> Result<HostStorageInventory> {
    locked.require_path_binding(installation)?;
    let entries = scan(locked.installation_directory())?;
    locked.require_path_binding(installation)?;
    locked.require_unchanged()?;
    Ok(HostStorageInventory {
        schema: "elevenid.installer-host-storage-inventory/v1",
        installation_id: locked.journal().installation_id().to_string(),
        coverage: "known_host_storage_roots_only",
        not_atomic_snapshot: true,
        deletion_eligible: false,
        entries,
    })
}

pub fn inspect(installation: &Path) -> Result<HostStorageInventory> {
    let locked = LockedInspection::open(installation)?;
    inspect_held(&locked, installation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn metadata_only_inventory_is_sorted_and_scoped() {
        let root = tempfile::tempdir().unwrap();
        let owned = root.path();
        fs::create_dir(owned.join("state")).unwrap();
        fs::create_dir(owned.join("state/postgres")).unwrap();
        fs::write(owned.join("state/postgres/customer-secret-name"), b"17").unwrap();
        fs::create_dir(owned.join("backups")).unwrap();
        fs::write(owned.join("backups/snapshot"), b"synthetic canary").unwrap();
        fs::write(owned.join("operator-password"), b"synthetic secret").unwrap();
        let entries = scan(&File::open(owned).unwrap()).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.root).collect::<Vec<_>>(),
            [
                "state",
                "state",
                "state",
                "operator-password",
                "backups",
                "backups"
            ]
        );
        assert_eq!(entries[2].size_bytes, 2);
        assert_eq!(entries[3].category, Category::Credential);
        let serialized = serde_json::to_string(&entries).unwrap();
        assert!(!serialized.contains("synthetic"));
        assert!(!serialized.contains("customer-secret-name"));
    }

    #[test]
    fn rejects_links_hardlinks_and_special_files() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("customer"), b"data").unwrap();
        symlink(outside.path(), root.path().join("backups")).unwrap();
        assert!(scan(&File::open(root.path()).unwrap()).is_err());
        fs::remove_file(root.path().join("backups")).unwrap();
        fs::create_dir(root.path().join("backups")).unwrap();
        fs::hard_link(
            outside.path().join("customer"),
            root.path().join("backups/linked"),
        )
        .unwrap();
        assert!(scan(&File::open(root.path()).unwrap()).is_err());
        fs::remove_file(root.path().join("backups/linked")).unwrap();
        std::os::unix::net::UnixListener::bind(root.path().join("backups/socket")).unwrap();
        assert!(scan(&File::open(root.path()).unwrap()).is_err());
        fs::remove_file(root.path().join("backups/socket")).unwrap();
        let fifo = CString::new(root.path().join("backups/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(scan(&File::open(root.path()).unwrap()).is_err());
    }

    #[test]
    fn refuses_traversal_and_depth_overflow() {
        assert!(component(OsStr::new("..")).is_err());
        assert!(component(OsStr::new("a/b")).is_err());
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("backups")).unwrap();
        let mut path = root.path().join("backups");
        for _ in 0..=MAX_DEPTH {
            path = path.join("deeper");
            fs::create_dir(&path).unwrap();
        }
        assert!(scan(&File::open(root.path()).unwrap()).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn inspection_binds_entries_to_a_real_installation_journal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("install");
        let state = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        let id = state.journal().installation_id().to_string();
        drop(state);
        fs::create_dir(path.join("backups")).unwrap();
        let inventory = inspect(&path).unwrap();
        assert_eq!(inventory.installation_id, id);
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].root, "backups");
        assert_eq!(inventory.coverage, "known_host_storage_roots_only");
        assert!(inventory.not_atomic_snapshot);
        assert!(!inventory.deletion_eligible);
    }
}
