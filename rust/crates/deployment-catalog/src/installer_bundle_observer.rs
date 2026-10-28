//! Read-only, descriptor-bound observation of one previously validated bundle
//! subtree. This does not cover other downloads or authorize any deletion.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until the auxiliary receipt coordinator is reviewed.

use crate::{
    installer_bundle::ValidatedBundleInventory,
    installer_host_snapshot::{directory, identity, mount_id, names, open_child},
    installer_purge_host::{HostIdentity, HostPurgeEntry, Kind},
    installer_state::LockedInspection,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

const REFUSED: &str = "validated bundle subtree observation incomplete";
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_PATH: usize = 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const PREFIX: &str = "downloads/extracted/selfhost-prepared";
type Result<T> = std::result::Result<T, String>;

/// Internal identities for later receipt reconciliation. Its entries are not
/// a standalone HostPurgeManifest: `downloads` and `extracted` are ancestors,
/// and all other downloads remain outside this observation.
pub(crate) struct ObservedBundle {
    pub coverage: &'static str,
    pub installation_id: uuid::Uuid,
    pub installation: HostIdentity,
    pub downloads: HostIdentity,
    pub extracted: HostIdentity,
    pub mount_id: u64,
    pub inventory_sha256: String,
    pub archive_sha256: String,
    pub marker_sha256: String,
    pub entries: Vec<HostPurgeEntry>,
    pub not_atomic_snapshot: bool,
    pub deletion_eligible: bool,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_closure(closure: &ValidatedBundleInventory) -> Result<()> {
    if closure.coverage != "validated_bundle_subtree_only"
        || !closure.not_atomic_snapshot
        || closure.deletion_eligible
        || closure.files.is_empty()
        || closure.files.len() + closure.directories.len() > MAX_ENTRIES
        || !closure.directories.contains("")
        || !closure.inventory_sha256.starts_with("sha256:")
        || !digest(&closure.inventory_sha256[7..])
        || !digest(&closure.archive_sha256)
        || !digest(&closure.marker_sha256)
        || !digest(&closure.image_lock_sha256)
        || closure.files.values().any(|hash| !digest(hash))
        || closure.files.get(".marty-selfhost-bundle.json") != Some(&closure.marker_sha256)
        || closure.files.get(".marty-selfhost-images.json") != Some(&closure.image_lock_sha256)
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn reopen_held_regular(held: &File, expected: &HostIdentity, expected_mount: u64) -> Result<File> {
    // O_PATH classified a regular file first. Procfs reopens that held inode,
    // avoiding an O_RDONLY open side effect on a concurrently replaced name.
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let proc = File::open("/proc/self/fd").map_err(|_| REFUSED)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0
        || info.f_type as i64 != PROC_SUPER_MAGIC
    {
        return Err(REFUSED.into());
    }
    let fd_name = CString::new(held.as_raw_fd().to_string()).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            fd_name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(REFUSED.into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if identity(&file)? != *expected || mount_id(&file)? != expected_mount {
        return Err(REFUSED.into());
    }
    Ok(file)
}

struct Walk<'a> {
    closure: &'a ValidatedBundleInventory,
    mount: u64,
    files: BTreeMap<String, String>,
    directories: BTreeSet<String>,
    entries: Vec<HostPurgeEntry>,
    total_bytes: u64,
}
impl Walk<'_> {
    fn visit(
        &mut self,
        parent: &File,
        parent_identity: &HostIdentity,
        leaf: &str,
        relative: &str,
        depth: usize,
    ) -> Result<()> {
        let path = if relative.is_empty() {
            PREFIX.to_owned()
        } else {
            format!("{PREFIX}/{relative}")
        };
        if depth > MAX_DEPTH || path.len() > MAX_PATH || self.entries.len() >= MAX_ENTRIES {
            return Err(REFUSED.into());
        }
        let held = open_child(parent, OsStr::new(leaf), libc::O_PATH)?.ok_or(REFUSED)?;
        let current = identity(&held)?;
        if current.dev != parent_identity.dev || mount_id(&held)? != self.mount {
            return Err(REFUSED.into());
        }
        self.entries.push(HostPurgeEntry {
            relative_path: path,
            parent: parent_identity.clone(),
            target: current.clone(),
        });
        match current.kind {
            Kind::Directory => {
                if !self.closure.directories.contains(relative)
                    || current.uid != unsafe { libc::geteuid() }
                    || current.mode != 0o755
                    || !self.directories.insert(relative.to_owned())
                {
                    return Err(REFUSED.into());
                }
                let dir = directory(&held, &current, self.mount)?;
                let before = names(&dir)?;
                for name in &before {
                    let child = name.to_str().ok_or(REFUSED)?;
                    let child_relative = if relative.is_empty() {
                        child.to_owned()
                    } else {
                        format!("{relative}/{child}")
                    };
                    self.visit(&dir, &current, child, &child_relative, depth + 1)?;
                }
                let latest = open_child(parent, OsStr::new(leaf), libc::O_PATH)?.ok_or(REFUSED)?;
                if names(&dir)? != before
                    || identity(&dir)? != current
                    || identity(&held)? != current
                    || identity(&latest)? != current
                    || mount_id(&latest)? != self.mount
                {
                    return Err(REFUSED.into());
                }
            }
            Kind::File => {
                let expected_hash = self.closure.files.get(relative).ok_or(REFUSED)?;
                let mut file = reopen_held_regular(&held, &current, self.mount)?;
                let meta = file.metadata().map_err(|_| REFUSED)?;
                if current.uid != unsafe { libc::geteuid() }
                    || !matches!(current.mode, 0o644 | 0o755)
                    || meta.len() > MAX_FILE
                {
                    return Err(REFUSED.into());
                }
                self.total_bytes = self.total_bytes.checked_add(meta.len()).ok_or(REFUSED)?;
                if self.total_bytes > MAX_TOTAL {
                    return Err(REFUSED.into());
                }
                let mut hasher = Sha256::new();
                let mut count = 0u64;
                let mut buffer = [0u8; 65536];
                loop {
                    let n = file.read(&mut buffer).map_err(|_| REFUSED)?;
                    if n == 0 {
                        break;
                    }
                    count += n as u64;
                    if count > meta.len() || count > MAX_FILE {
                        return Err(REFUSED.into());
                    }
                    hasher.update(&buffer[..n]);
                }
                if count != meta.len()
                    || file.metadata().map_err(|_| REFUSED)?.len() != meta.len()
                    || identity(&file)? != current
                    || format!("{:x}", hasher.finalize()) != *expected_hash
                {
                    return Err(REFUSED.into());
                }
                let latest = open_child(parent, OsStr::new(leaf), libc::O_PATH)?.ok_or(REFUSED)?;
                if identity(&latest)? != current || mount_id(&latest)? != self.mount {
                    return Err(REFUSED.into());
                }
                self.files
                    .insert(relative.to_owned(), expected_hash.clone());
            }
        }
        Ok(())
    }
}

fn observe_inner_with_hook<F: FnOnce()>(
    installation: &File,
    installation_id: uuid::Uuid,
    expected_installation: &HostIdentity,
    expected_downloads: &HostIdentity,
    expected_mount: u64,
    closure: &ValidatedBundleInventory,
    after_walk: F,
) -> Result<ObservedBundle> {
    validate_closure(closure)?;
    if identity(installation)? != *expected_installation
        || mount_id(installation)? != expected_mount
    {
        return Err(REFUSED.into());
    }
    let downloads =
        open_child(installation, OsStr::new("downloads"), libc::O_PATH)?.ok_or(REFUSED)?;
    if identity(&downloads)? != *expected_downloads || mount_id(&downloads)? != expected_mount {
        return Err(REFUSED.into());
    }
    let downloads_dir = directory(&downloads, expected_downloads, expected_mount)?;
    let extracted =
        open_child(&downloads_dir, OsStr::new("extracted"), libc::O_PATH)?.ok_or(REFUSED)?;
    let extracted_identity = identity(&extracted)?;
    if extracted_identity.kind != Kind::Directory
        || extracted_identity.uid != unsafe { libc::geteuid() }
        || extracted_identity.mode != 0o700
        || mount_id(&extracted)? != expected_mount
    {
        return Err(REFUSED.into());
    }
    let extracted_dir = directory(&extracted, &extracted_identity, expected_mount)?;
    let expected_extracted = vec![std::ffi::OsString::from("selfhost-prepared")];
    if names(&extracted_dir)? != expected_extracted {
        return Err(REFUSED.into());
    }
    let mut walk = Walk {
        closure,
        mount: expected_mount,
        files: BTreeMap::new(),
        directories: BTreeSet::new(),
        entries: Vec::new(),
        total_bytes: 0,
    };
    walk.visit(
        &extracted_dir,
        &extracted_identity,
        "selfhost-prepared",
        "",
        0,
    )?;
    after_walk();
    if walk.files != closure.files
        || walk.directories != closure.directories
        || names(&extracted_dir)? != expected_extracted
        || identity(&extracted)? != extracted_identity
        || mount_id(&extracted)? != expected_mount
        || identity(&downloads)? != *expected_downloads
        || mount_id(&downloads)? != expected_mount
        || identity(installation)? != *expected_installation
        || mount_id(installation)? != expected_mount
    {
        return Err(REFUSED.into());
    }
    let latest_extracted =
        open_child(&downloads_dir, OsStr::new("extracted"), libc::O_PATH)?.ok_or(REFUSED)?;
    let latest_downloads =
        open_child(installation, OsStr::new("downloads"), libc::O_PATH)?.ok_or(REFUSED)?;
    let latest_bundle = open_child(
        &extracted_dir,
        OsStr::new("selfhost-prepared"),
        libc::O_PATH,
    )?
    .ok_or(REFUSED)?;
    let observed_bundle = walk
        .entries
        .iter()
        .find(|entry| entry.relative_path == PREFIX)
        .ok_or(REFUSED)?;
    if identity(&latest_extracted)? != extracted_identity
        || mount_id(&latest_extracted)? != expected_mount
        || identity(&latest_downloads)? != *expected_downloads
        || mount_id(&latest_downloads)? != expected_mount
        || identity(&latest_bundle)? != observed_bundle.target
        || mount_id(&latest_bundle)? != expected_mount
    {
        return Err(REFUSED.into());
    }
    walk.entries.sort_by(|a, b| {
        b.relative_path
            .split('/')
            .count()
            .cmp(&a.relative_path.split('/').count())
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    Ok(ObservedBundle {
        coverage: "validated_bundle_subtree_only",
        installation_id,
        installation: expected_installation.clone(),
        downloads: expected_downloads.clone(),
        extracted: extracted_identity,
        mount_id: expected_mount,
        inventory_sha256: closure.inventory_sha256.clone(),
        archive_sha256: closure.archive_sha256.clone(),
        marker_sha256: closure.marker_sha256.clone(),
        entries: walk.entries,
        not_atomic_snapshot: true,
        deletion_eligible: false,
    })
}
fn observe_inner(
    installation: &File,
    installation_id: uuid::Uuid,
    expected_installation: &HostIdentity,
    expected_downloads: &HostIdentity,
    expected_mount: u64,
    closure: &ValidatedBundleInventory,
) -> Result<ObservedBundle> {
    observe_inner_with_hook(
        installation,
        installation_id,
        expected_installation,
        expected_downloads,
        expected_mount,
        closure,
        || {},
    )
}

/// `expected_installation` and `expected_downloads` must come from a locally
/// validated creation receipt under exclusive installer custody. This merely
/// observes the marked bundle subtree; it never authenticates a receipt.
pub(crate) fn observe(
    locked: &LockedInspection,
    installation: &Path,
    expected_installation: &HostIdentity,
    expected_downloads: &HostIdentity,
    expected_mount: u64,
    closure: &ValidatedBundleInventory,
) -> Result<ObservedBundle> {
    locked
        .require_path_binding(installation)
        .map_err(|_| REFUSED)?;
    let observed = observe_inner(
        locked.installation_directory(),
        locked.journal().installation_id(),
        expected_installation,
        expected_downloads,
        expected_mount,
        closure,
    )?;
    locked
        .require_path_binding(installation)
        .map_err(|_| REFUSED)?;
    locked.require_unchanged().map_err(|_| REFUSED)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_bundle::validate_bundle_inventory;
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        install_path: PathBuf,
        bundle_path: PathBuf,
        install: File,
        root: HostIdentity,
        downloads: HostIdentity,
        mount: u64,
        closure: ValidatedBundleInventory,
    }
    fn write(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let install_path = temp.path().join("install");
        let downloads_path = install_path.join("downloads");
        let extracted_path = downloads_path.join("extracted");
        let bundle_path = extracted_path.join("selfhost-prepared");
        fs::create_dir(&install_path).unwrap();
        fs::create_dir(&downloads_path).unwrap();
        fs::create_dir(&extracted_path).unwrap();
        fs::create_dir(&bundle_path).unwrap();
        fs::create_dir(bundle_path.join("scripts")).unwrap();
        for path in [&install_path, &downloads_path, &extracted_path] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            bundle_path.join("scripts"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let lock = json!({"schema":"marty.selfhost-image-lock/v1","release":"marty-ui@1.2.3",
            "services":{"app":format!("ghcr.io/elevenid/app@sha256:{}","a".repeat(64))},
            "openbao_didcomm_image":format!("ghcr.io/elevenid/openbao@sha256:{}","b".repeat(64))});
        let lock_bytes = serde_json::to_vec(&lock).unwrap();
        write(
            &bundle_path.join(".marty-selfhost-images.json"),
            &lock_bytes,
            0o644,
        );
        write(
            &bundle_path.join("docker-compose.yml"),
            b"services: {}\n",
            0o644,
        );
        write(
            &bundle_path.join("scripts/start.sh"),
            b"#!/bin/sh\nexit 0\n",
            0o755,
        );
        let files: BTreeMap<_, _> = [
            ".marty-selfhost-images.json",
            "docker-compose.yml",
            "scripts/start.sh",
        ]
        .into_iter()
        .map(|name| {
            (
                name,
                format!(
                    "{:x}",
                    Sha256::digest(fs::read(bundle_path.join(name)).unwrap())
                ),
            )
        })
        .collect();
        let marker = json!({"schema":"marty.selfhost-bundle-files/v1","files":files,"directories":["","scripts"]});
        write(
            &bundle_path.join(".marty-selfhost-bundle.json"),
            &serde_json::to_vec(&marker).unwrap(),
            0o644,
        );
        let artifacts: Vec<_> = ["install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json"]
            .into_iter()
            .map(|name| if name == "prepared-selfhost-images.json" {
                json!({"name":name,"sha256":format!("{:x}",Sha256::digest(&lock_bytes)),"size":lock_bytes.len()})
            } else {
                json!({"name":name,"sha256":"a".repeat(64),"size":1})
            }).collect();
        let inventory = json!({"schema":"elevenid.installer-inventory/v1","repository":crate::installer_release::REPOSITORY,
            "source_sha":"a".repeat(40),"release_tag":"v1.2.3","platform":"linux/amd64","build_run_id":42,"build_run_attempt":1,
            "artifacts":artifacts,"images":{"app":lock["services"]["app"],"openbao_didcomm_image":lock["openbao_didcomm_image"]}});
        let bytes = serde_json::to_vec(&inventory).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let closure =
            validate_bundle_inventory(&bundle_path, &bytes, &digest, &lock_bytes).unwrap();
        let install = File::open(&install_path).unwrap();
        let root = identity(&install).unwrap();
        let downloads = identity(&File::open(&downloads_path).unwrap()).unwrap();
        let mount = mount_id(&install).unwrap();
        Fixture {
            _temp: temp,
            install_path,
            bundle_path,
            install,
            root,
            downloads,
            mount,
            closure,
        }
    }
    fn observe_fixture(f: &Fixture) -> Result<ObservedBundle> {
        observe_inner(
            &f.install,
            uuid::Uuid::nil(),
            &f.root,
            &f.downloads,
            f.mount,
            &f.closure,
        )
    }
    #[test]
    fn exact_closure_is_descriptor_observed_and_not_deletion_eligible() {
        let f = fixture();
        let observed = observe_fixture(&f).unwrap();
        assert_eq!(observed.entries.len(), 6);
        assert_eq!(observed.coverage, "validated_bundle_subtree_only");
        assert_eq!(observed.inventory_sha256, f.closure.inventory_sha256);
        assert_eq!(observed.marker_sha256, f.closure.marker_sha256);
        assert_eq!(observed.archive_sha256, f.closure.archive_sha256);
        assert_eq!(observed.downloads, f.downloads);
        assert_eq!(observed.installation, f.root);
        assert_eq!(observed.mount_id, f.mount);
        assert_eq!(observed.installation_id, uuid::Uuid::nil());
        assert_eq!(observed.extracted.mode, 0o700);
        assert!(observed.not_atomic_snapshot);
        assert!(!observed.deletion_eligible);
    }
    #[test]
    fn extra_changed_and_linked_bundle_entries_refuse() {
        for mutation in ["extra", "changed", "link", "fifo"] {
            let f = fixture();
            match mutation {
                "extra" => write(&f.bundle_path.join("customer-secret-name"), b"x", 0o644),
                "changed" => write(&f.bundle_path.join("docker-compose.yml"), b"changed", 0o644),
                "link" => symlink("docker-compose.yml", f.bundle_path.join("link")).unwrap(),
                _ => {
                    let name = CString::new(f.bundle_path.join("fifo").to_str().unwrap()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
            }
            assert!(observe_fixture(&f).is_err(), "accepted {mutation}");
        }
    }
    #[test]
    fn changed_downloads_identity_mount_or_extracted_contents_refuse() {
        let f = fixture();
        let mut wrong = f.downloads.clone();
        wrong.ino += 1;
        assert!(observe_inner(
            &f.install,
            uuid::Uuid::nil(),
            &f.root,
            &wrong,
            f.mount,
            &f.closure
        )
        .is_err());
        assert!(observe_inner(
            &f.install,
            uuid::Uuid::nil(),
            &f.root,
            &f.downloads,
            f.mount + 1,
            &f.closure
        )
        .is_err());
        fs::create_dir(f.install_path.join("downloads/extracted/foreign")).unwrap();
        assert!(observe_fixture(&f).is_err());
    }
    #[test]
    fn bundle_directory_replacement_after_walk_refuses() {
        let f = fixture();
        let retired = f.install_path.join("retired-bundle");
        let result = observe_inner_with_hook(
            &f.install,
            uuid::Uuid::nil(),
            &f.root,
            &f.downloads,
            f.mount,
            &f.closure,
            || {
                fs::rename(&f.bundle_path, &retired).unwrap();
                fs::create_dir(&f.bundle_path).unwrap();
                fs::set_permissions(&f.bundle_path, fs::Permissions::from_mode(0o755)).unwrap();
            },
        );
        assert!(result.is_err());
    }
}
