//! Linux installer filesystem invariants; callers retain stage-specific refusal messages.
#![cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
fn require(condition: bool, refusal: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refusal.into())
    }
}

pub(crate) fn directory(path: &Path, refusal: &str) -> Result<File> {
    require(path.canonicalize().map_err(|_| refusal)? == path, refusal)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| refusal)?;
    let metadata = file.metadata().map_err(|_| refusal)?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
        refusal,
    )?;
    Ok(file)
}

/// Mutable credential contents belong to an external identity producer. Bind
/// only the private parent and the single workload projection directory: token
/// bytes and their hashes must never enter installation receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialProjection {
    pub directory: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
    owner: u32,
}

impl CredentialProjection {
    pub const TOKEN_FILE: &'static str = "token";
    pub const TARGET: &'static str = "/run/aws-identity";

    pub(crate) fn observe(path: &Path, refusal: &str) -> Result<Self> {
        let parent_path = path.parent().ok_or(refusal)?;
        let parent = directory(parent_path, refusal)?;
        let name = path.file_name().and_then(|v| v.to_str()).ok_or(refusal)?;
        require(!name.is_empty() && name != "." && name != "..", refusal)?;
        let leaf = open_child(&parent, name, libc::O_RDONLY | libc::O_DIRECTORY, refusal)?;
        let metadata = leaf.metadata().map_err(|_| refusal)?;
        // Matches the existing private-parent/container-readable projection:
        // a 0700 parent is NEVER mounted, the unique leaf is read-only in one
        // runtime UID 10001 container. No credential chmod/chown occurs here.
        require(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o755,
            refusal,
        )?;
        require(path.canonicalize().map_err(|_| refusal)? == path, refusal)?;
        require(
            file_names(&leaf, refusal)? == BTreeSet::from([Self::TOKEN_FILE.into()]),
            refusal,
        )?;
        let token = open_child(
            &leaf,
            Self::TOKEN_FILE,
            libc::O_RDONLY | libc::O_NONBLOCK,
            refusal,
        )?;
        let token_metadata = token.metadata().map_err(|_| refusal)?;
        require(
            token_metadata.is_file()
                && token_metadata.nlink() == 1
                && token_metadata.uid() == metadata.uid()
                && token_metadata.mode() & 0o7777 == 0o444
                && (1..=65_536).contains(&token_metadata.len()),
            refusal,
        )?;
        // Do not read the credential. Replacing this regular token atomically
        // is permitted; replacing the mounted directory is not.
        require_directory_binding(parent_path, &parent, refusal)?;
        let current = std::fs::symlink_metadata(path).map_err(|_| refusal)?;
        require(
            current.is_dir()
                && current.dev() == metadata.dev()
                && current.ino() == metadata.ino()
                && current.uid() == metadata.uid()
                && current.mode() == metadata.mode(),
            refusal,
        )?;
        let parent_metadata = parent.metadata().map_err(|_| refusal)?;
        Ok(Self {
            directory: path.into(),
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    pub(crate) fn verify(&self, refusal: &str) -> Result<()> {
        require(Self::observe(&self.directory, refusal)? == *self, refusal)
    }
}

pub(crate) fn read_entry(
    dir: &File,
    name: &str,
    mode: u32,
    allow_root: bool,
    refusal: &str,
) -> Result<Vec<u8>> {
    require(
        !name.contains('/') && !name.contains('\\') && name != "." && name != "..",
        refusal,
    )?;
    let name = CString::new(name).map_err(|_| refusal)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, refusal)?;
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| refusal)?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.len() > 0
            && m.len() <= 65536
            && m.mode() & 0o7777 == mode
            && (m.uid() == unsafe { libc::geteuid() } || (allow_root && m.uid() == 0)),
        refusal,
    )?;
    let mut value = Vec::new();
    file.take(65537)
        .read_to_end(&mut value)
        .map_err(|_| refusal)?;
    require(
        value.len() as u64 == m.len()
            && value.is_ascii()
            && !value.contains(&0)
            && !value.windows(11).any(|v| v == b"PRIVATE KEY"),
        refusal,
    )?;
    Ok(value)
}

pub(crate) fn file_names(dir: &File, refusal: &str) -> Result<BTreeSet<String>> {
    std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| refusal)?
        .map(|entry| {
            entry
                .map_err(|_| refusal.to_string())
                .and_then(|e| e.file_name().into_string().map_err(|_| refusal.into()))
        })
        .collect()
}

pub(crate) fn open_child(parent: &File, name: &str, flags: i32, refusal: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| refusal)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, refusal)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn require_directory_binding(path: &Path, held: &File, refusal: &str) -> Result<()> {
    let observed = directory(path, refusal)?.metadata().map_err(|_| refusal)?;
    let original = held.metadata().map_err(|_| refusal)?;
    require(
        (
            observed.dev(),
            observed.ino(),
            observed.uid(),
            observed.gid(),
            observed.mode(),
        ) == (
            original.dev(),
            original.ino(),
            original.uid(),
            original.gid(),
            original.mode(),
        ),
        refusal,
    )
}

pub(crate) fn stage_inputs(
    secrets: &File,
    output: &File,
    read_inputs: impl Fn(&File) -> Result<BTreeMap<String, Vec<u8>>>,
    refusal: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    require(file_names(output, refusal)?.is_empty(), refusal)?;
    let values = read_inputs(secrets)?;
    for (name, value) in &values {
        let name = CString::new(name.as_str()).map_err(|_| refusal)?;
        let fd = unsafe {
            libc::openat(
                output.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0, refusal)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        output.sync_all().map_err(|_| refusal)?;
        file.write_all(value)
            .and_then(|_| file.sync_all())
            .map_err(|_| refusal)?;
        require(
            unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0,
            refusal,
        )?;
        file.sync_all()
            .and_then(|_| output.sync_all())
            .map_err(|_| refusal)?;
    }
    require(read_inputs(output)? == values, refusal)?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    const REFUSAL: &str = "test-stage refusal";

    fn private_dir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn token_projection(root: &Path) -> PathBuf {
        let leaf = root.join("gateway");
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(leaf.join("token"), b"never-persist-web-identity-token").unwrap();
        fs::set_permissions(leaf.join("token"), fs::Permissions::from_mode(0o444)).unwrap();
        leaf
    }

    #[test]
    fn external_identity_projection_allows_atomic_token_refresh_without_recording_token() {
        let root = private_dir();
        let leaf = token_projection(root.path());
        let projection = CredentialProjection::observe(&leaf, REFUSAL).unwrap();
        let receipt = serde_json::to_vec(&projection).unwrap();
        let text = std::str::from_utf8(&receipt).unwrap();
        assert!(
            !text.contains("never-persist") && !text.contains("sha256") && !text.contains("token")
        );
        let replacement = root.path().join("fresh");
        fs::write(&replacement, b"different-rotated-web-identity-token").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444)).unwrap();
        fs::rename(&replacement, leaf.join("token")).unwrap();
        projection.verify(REFUSAL).unwrap();
        assert_eq!(
            serde_json::to_vec(&CredentialProjection::observe(&leaf, REFUSAL).unwrap()).unwrap(),
            receipt
        );
        fs::rename(&leaf, root.path().join("preserved")).unwrap();
        token_projection(root.path());
        assert!(projection.verify(REFUSAL).is_err());
    }

    #[test]
    fn external_identity_projection_refuses_links_writable_inputs_and_exposed_parent() {
        let root = private_dir();
        let leaf = token_projection(root.path());
        fs::write(leaf.join("foreign-credential"), b"must-not-be-exposed").unwrap();
        assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
        fs::remove_file(leaf.join("foreign-credential")).unwrap();
        for mode in [0o600, 0o644, 0o666] {
            fs::set_permissions(leaf.join("token"), fs::Permissions::from_mode(mode)).unwrap();
            assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
        }
        fs::set_permissions(leaf.join("token"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::hard_link(leaf.join("token"), root.path().join("alias")).unwrap();
        assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
        fs::remove_file(root.path().join("alias")).unwrap();
        fs::rename(leaf.join("token"), root.path().join("original-token")).unwrap();
        symlink(root.path().join("original-token"), leaf.join("token")).unwrap();
        assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
        fs::remove_file(leaf.join("token")).unwrap();
        fs::rename(root.path().join("original-token"), leaf.join("token")).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(CredentialProjection::observe(&leaf, REFUSAL).is_err());
    }

    #[test]
    fn secure_reads_refuse_aliases_links_invalid_modes_and_unbounded_or_private_content() {
        let temp = private_dir();
        let dir = directory(temp.path(), REFUSAL).unwrap();
        let path = temp.path().join("value");
        fs::write(&path, b"public value").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(
            read_entry(&dir, "value", 0o444, true, REFUSAL).unwrap(),
            b"public value"
        );
        for name in ["../value", "a/b", "a\\b", ".", ".."] {
            assert_eq!(
                read_entry(&dir, name, 0o444, true, REFUSAL).unwrap_err(),
                REFUSAL
            );
        }
        symlink(&path, temp.path().join("symlink")).unwrap();
        assert!(read_entry(&dir, "symlink", 0o444, true, REFUSAL).is_err());
        fs::hard_link(&path, temp.path().join("hardlink")).unwrap();
        assert!(read_entry(&dir, "value", 0o444, true, REFUSAL).is_err());
        fs::remove_file(temp.path().join("hardlink")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_entry(&dir, "value", 0o444, true, REFUSAL).is_err());
        for bytes in [
            Vec::new(),
            vec![b'a'; 65537],
            b"PRIVATE KEY".to_vec(),
            b"nul\0".to_vec(),
            vec![0xff],
        ] {
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            assert_eq!(
                read_entry(&dir, "value", 0o444, true, REFUSAL).unwrap_err(),
                REFUSAL
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn staging_checks_empty_output_before_reading_secrets() {
        let input = private_dir();
        let output = private_dir();
        fs::write(output.path().join("existing"), b"keep").unwrap();
        let input = directory(input.path(), REFUSAL).unwrap();
        let output = directory(output.path(), REFUSAL).unwrap();
        let called = Cell::new(false);
        let result = stage_inputs(
            &input,
            &output,
            |_| {
                called.set(true);
                Ok(BTreeMap::new())
            },
            REFUSAL,
        );
        assert_eq!(result.unwrap_err(), REFUSAL);
        assert!(!called.get());
    }

    #[test]
    fn directory_binding_refuses_symlink_permissions_and_same_mode_replacement() {
        let temp = private_dir();
        let path = temp.path().join("held");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&path, REFUSAL).unwrap();
        symlink(&path, temp.path().join("alias")).unwrap();
        assert!(directory(&temp.path().join("alias"), REFUSAL).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(directory(&path, REFUSAL).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&path, temp.path().join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            require_directory_binding(&path, &held, REFUSAL).unwrap_err(),
            REFUSAL
        );
    }
}
