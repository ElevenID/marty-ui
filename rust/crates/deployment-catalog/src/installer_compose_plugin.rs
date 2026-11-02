//! Admit one user-owned Compose plugin into an otherwise empty Docker CLI config.
//! The account home comes from passwd, never from the invoking environment.
#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const MAX_PLUGIN_BYTES: u64 = 64 * 1024 * 1024;
const PLUGIN: &str = "docker-compose";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(file: &File) -> Result<Stamp> {
    let m = file
        .metadata()
        .map_err(|_| "Compose plugin metadata unavailable")?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.size(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
fn c_name(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| "invalid Compose plugin path".into())
}
fn openat_optional(parent: RawFd, name: &OsStr, flags: i32) -> Result<Option<File>> {
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("Compose plugin path unavailable or unsafe".into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn directory(parent: RawFd, name: &OsStr, uid: u32, user_plugin_dir: bool) -> Result<Option<File>> {
    let Some(file) = openat_optional(parent, name, libc::O_PATH | libc::O_DIRECTORY)? else {
        return Ok(None);
    };
    let s = stamp(&file)?;
    if s.mode & libc::S_IFMT != libc::S_IFDIR
        || (s.uid != 0 && s.uid != uid)
        || s.mode & 0o022 != 0
        || (user_plugin_dir && (s.uid != uid || s.mode & 0o100 == 0))
    {
        return Err("Compose plugin directory custody differs".into());
    }
    Ok(Some(file))
}
struct HeldSource {
    parents: Vec<(File, Stamp)>,
    plugin: File,
    plugin_stamp: Stamp,
}
fn source(home: &Path, uid: u32) -> Result<Option<HeldSource>> {
    if !home.is_absolute() || uid == 0 || home.as_os_str().as_bytes().len() > 4096 {
        return Err("invalid installer account home".into());
    }
    let mut parts = Vec::new();
    for c in home.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => parts.push(n.to_owned()),
            _ => return Err("invalid installer account home".into()),
        }
    }
    if parts.is_empty() || parts.len() > 32 {
        return Err("invalid installer account home".into());
    }
    parts.push(OsStr::new(".docker").to_owned());
    parts.push(OsStr::new("cli-plugins").to_owned());
    let root = File::open("/").map_err(|_| "Compose plugin root unavailable")?;
    let root_stamp = stamp(&root)?;
    if root_stamp.mode & libc::S_IFMT != libc::S_IFDIR
        || root_stamp.uid != 0
        || root_stamp.mode & 0o022 != 0
    {
        return Err("Compose plugin root custody differs".into());
    }
    let mut parents = vec![(root, root_stamp)];
    for (index, part) in parts.iter().enumerate() {
        let parent = parents
            .last()
            .ok_or("Compose plugin parent unavailable")?
            .0
            .as_raw_fd();
        let user_plugin_dir = index >= parts.len() - 2;
        let Some(file) = directory(parent, part, uid, user_plugin_dir)? else {
            if user_plugin_dir {
                return Ok(None);
            }
            return Err("installer account home unavailable".into());
        };
        if index == parts.len() - 3 && stamp(&file)?.uid != uid {
            return Err("installer account home owner differs".into());
        }
        let identity = stamp(&file)?;
        parents.push((file, identity));
    }
    let Some(plugin) = openat_optional(
        parents
            .last()
            .ok_or("Compose plugin parent unavailable")?
            .0
            .as_raw_fd(),
        OsStr::new(PLUGIN),
        libc::O_PATH,
    )?
    else {
        return Ok(None);
    };
    let p = stamp(&plugin)?;
    if p.mode & libc::S_IFMT != libc::S_IFREG
        || p.uid != uid
        || p.nlink != 1
        || p.mode & 0o100 == 0
        || p.mode & 0o022 != 0
        || p.mode & 0o6000 != 0
        || p.size == 0
        || p.size > MAX_PLUGIN_BYTES
    {
        return Err("Compose plugin is not a bounded owned ordinary executable".into());
    }
    Ok(Some(HeldSource {
        parents,
        plugin,
        plugin_stamp: p,
    }))
}
fn rebind(home: &Path, uid: u32, held: &HeldSource) -> Result<()> {
    let current = source(home, uid)?.ok_or("Compose plugin disappeared during admission")?;
    if current.parents.len() != held.parents.len()
        || current
            .parents
            .iter()
            .zip(held.parents.iter())
            .any(|(a, b)| {
                let a = a.1;
                let b = b.1;
                (a.dev, a.ino, a.uid, a.gid, a.mode) != (b.dev, b.ino, b.uid, b.gid, b.mode)
            })
        || current.plugin_stamp != held.plugin_stamp
        || stamp(&held.plugin)? != held.plugin_stamp
    {
        return Err("Compose plugin changed during admission".into());
    }
    Ok(())
}
fn no_file_capabilities(file: &File) -> Result<()> {
    let name = CString::new("security.capability").map_err(|_| "invalid capability name")?;
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Err("Compose plugin has file capabilities".into());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENODATA) {
        return Err("Compose plugin capability metadata unavailable".into());
    }
    Ok(())
}
fn reopen_held_regular(held: &File) -> Result<File> {
    let expected = stamp(held)?;
    if expected.mode & libc::S_IFMT != libc::S_IFREG {
        return Err("Compose plugin type changed".into());
    }
    // This procfs magic link names our held O_PATH inode, rather than a child
    // that could have been replaced with a device or FIFO in the parent.
    let path = CString::new(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .map_err(|_| "invalid held Compose descriptor")?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("held Compose plugin unavailable".into());
    }
    let reopened = unsafe { File::from_raw_fd(fd) };
    if stamp(&reopened)? != expected {
        return Err("held Compose plugin changed".into());
    }
    Ok(reopened)
}
fn destination_bound(
    directory: &Path,
    held_directory: &File,
    name: &Path,
    held_file: &File,
    uid: u32,
    size: u64,
) -> Result<()> {
    let named_directory =
        fs::symlink_metadata(directory).map_err(|_| "isolated Compose directory changed")?;
    let held_dir = stamp(held_directory)?;
    if !named_directory.is_dir()
        || named_directory.file_type().is_symlink()
        || (named_directory.dev(), named_directory.ino()) != (held_dir.dev, held_dir.ino)
        || held_dir.uid != uid
        || held_dir.mode & 0o7777 != 0o700
    {
        return Err("isolated Compose directory changed".into());
    }
    let named = fs::symlink_metadata(name).map_err(|_| "isolated Compose plugin changed")?;
    let held = stamp(held_file)?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (held.dev, held.ino)
        || held.uid != uid
        || held.nlink != 1
        || held.mode & 0o7777 != 0o500
        || held.size != size
    {
        return Err("isolated Compose plugin changed".into());
    }
    Ok(())
}
fn digest_exact(file: &mut File, size: u64, mut sink: Option<&mut File>) -> Result<[u8; 32]> {
    let mut remaining = size;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "Compose plugin size invalid")?;
        let count = file
            .read(&mut buffer[..want])
            .map_err(|_| "Compose plugin read failed")?;
        if count == 0 {
            return Err("Compose plugin shortened during admission".into());
        }
        hash.update(&buffer[..count]);
        if let Some(out) = sink.as_deref_mut() {
            out.write_all(&buffer[..count])
                .map_err(|_| "Compose plugin staging failed")?;
        }
        remaining -= count as u64;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| "Compose plugin read failed")?
        != 0
    {
        return Err("Compose plugin grew during admission".into());
    }
    Ok(hash.finalize().into())
}
fn account_home(uid: u32) -> Result<PathBuf> {
    let mut password = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    let result = unsafe {
        libc::getpwuid_r(
            uid,
            &mut password,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 || found.is_null() || password.pw_uid != uid || password.pw_dir.is_null() {
        return Err("installer account home unavailable".into());
    }
    let home = unsafe { CStr::from_ptr(password.pw_dir) };
    let path = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
    if !path.is_absolute() {
        return Err("installer account home invalid".into());
    }
    Ok(path)
}
pub(super) fn admit_current_user_compose(staging: &Path) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    admit_from_home(&account_home(uid)?, uid, staging)
}
fn admit_from_home(home: &Path, uid: u32, staging: &Path) -> Result<()> {
    let Some(held) = source(home, uid)? else {
        // An absent user plugin leaves the isolated config empty. Docker CLI
        // may still discover its trusted system plugin; preflight must prove it.
        return Ok(());
    };
    rebind(home, uid, &held)?;
    let mut input = reopen_held_regular(&held.plugin)?;
    if stamp(&input)? != held.plugin_stamp {
        return Err("Compose plugin changed during admission".into());
    }
    no_file_capabilities(&input)?;
    let destination_dir = staging.join("cli-plugins");
    fs::create_dir(&destination_dir)
        .map_err(|_| "isolated Compose plugin directory unavailable")?;
    let dir = File::open(&destination_dir).map_err(|_| "isolated Compose directory unavailable")?;
    dir.set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect isolated Compose plugin directory")?;
    let destination = destination_dir.join(PLUGIN);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&destination)
        .map_err(|_| "cannot create isolated Compose plugin")?;
    let first = digest_exact(&mut input, held.plugin_stamp.size, Some(&mut output))?;
    output
        .set_permissions(fs::Permissions::from_mode(0o500))
        .map_err(|_| "cannot protect isolated Compose plugin")?;
    output
        .sync_all()
        .map_err(|_| "cannot sync isolated Compose plugin")?;
    dir.sync_all()
        .map_err(|_| "cannot sync isolated Compose directory")?;
    rebind(home, uid, &held)?;
    let mut second_input = reopen_held_regular(&held.plugin)?;
    if stamp(&second_input)? != held.plugin_stamp
        || no_file_capabilities(&second_input).is_err()
        || digest_exact(&mut second_input, held.plugin_stamp.size, None)? != first
    {
        return Err("Compose plugin changed during admission".into());
    }
    destination_bound(
        &destination_dir,
        &dir,
        &destination,
        &output,
        uid,
        held.plugin_stamp.size,
    )?;
    let mut staged = reopen_held_regular(&output)?;
    if stamp(&staged)? != stamp(&output)? {
        return Err("isolated Compose plugin changed".into());
    }
    if digest_exact(&mut staged, held.plugin_stamp.size, None)? != first {
        return Err("isolated Compose plugin changed".into());
    }
    rebind(home, uid, &held)?;
    destination_bound(
        &destination_dir,
        &dir,
        &destination,
        &output,
        uid,
        held.plugin_stamp.size,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_runtime::private_parent;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, u32) {
        let uid = unsafe { libc::geteuid() };
        assert_ne!(uid, 0, "admission tests require an ordinary user");
        // The test seam builds an isolated home beneath the account's home; it
        // never opens or edits the account's actual Docker configuration.
        let base = account_home(uid).unwrap();
        let temp = tempfile::Builder::new()
            .prefix("marty-compose-fixture-")
            .tempdir_in(base)
            .unwrap();
        let home = temp.path().join("synthetic-home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let config = home.join(".docker");
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let plugins = config.join("cli-plugins");
        fs::create_dir(&plugins).unwrap();
        fs::set_permissions(&plugins, fs::Permissions::from_mode(0o700)).unwrap();
        let staging = temp.path().join("isolated-config");
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, home, staging, uid)
    }
    fn plugin(home: &Path) -> PathBuf {
        let path = home.join(".docker/cli-plugins/docker-compose");
        fs::write(&path, "#!/bin/sh\n[ \"$1\" != compose ] || shift\ncase \"$1\" in\n  docker-cli-plugin-metadata) printf '{\"SchemaVersion\":\"0.1.0\",\"Vendor\":\"Marty fixture\",\"Version\":\"v9.8.7\",\"ShortDescription\":\"Synthetic Compose plugin\"}\\n' ;;\n  version) printf '9.8.7\\n' ;;\n  *) exit 32 ;;\nesac\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn admits_only_exact_owned_plugin_and_preserves_bytes() {
        let (_temp, home, staging, uid) = fixture();
        let original = plugin(&home);
        let before = fs::read(&original).unwrap();
        admit_from_home(&home, uid, &staging).unwrap();
        let staged = staging.join("cli-plugins/docker-compose");
        assert_eq!(fs::read(staged).unwrap(), before);
        assert_eq!(fs::read(original).unwrap(), before);
        assert!(private_parent(&staging).is_ok());
    }
    #[test]
    fn accepts_standard_user_plugin_directories_and_refuses_group_write() {
        let (_temp, home, staging, uid) = fixture();
        plugin(&home);
        let config = home.join(".docker");
        let plugins = config.join("cli-plugins");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&plugins, fs::Permissions::from_mode(0o755)).unwrap();
        admit_from_home(&home, uid, &staging).unwrap();
        fs::set_permissions(&plugins, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(source(&home, uid).is_err());
    }
    #[test]
    fn absent_user_plugin_leaves_system_discovery_to_cli() {
        let docker = Path::new("/usr/bin/docker");
        let system_plugin = Path::new("/usr/libexec/docker/cli-plugins/docker-compose");
        let (_temp, home, staging, uid) = fixture();
        fs::remove_dir(home.join(".docker/cli-plugins")).unwrap();
        fs::remove_dir(home.join(".docker")).unwrap();
        admit_from_home(&home, uid, &staging).unwrap();
        assert!(!staging.join("cli-plugins").exists());
        if !docker.is_file() || !system_plugin.is_file() {
            return;
        }
        let output = std::process::Command::new(docker)
            .args(["compose", "version", "--short"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &staging)
            .env("DOCKER_CONFIG", &staging)
            .env(
                "DOCKER_HOST",
                "unix:///unreachable-owned-fixture/docker.sock",
            )
            .current_dir(&staging)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "system Compose plugin not discovered in isolated config"
        );
        assert!(!String::from_utf8(output.stdout).unwrap().trim().is_empty());
    }
    #[test]
    fn refuses_links_special_files_wrong_owner_and_writable_ancestors() {
        let (_temp, home, staging, uid) = fixture();
        let path = plugin(&home);
        assert!(admit_from_home(&home, uid + 1, &staging).is_err());
        let backup = path.with_extension("backup");
        fs::rename(&path, &backup).unwrap();
        symlink(&backup, &path).unwrap();
        assert!(admit_from_home(&home, uid, &staging).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&backup, &path).unwrap();
        assert!(admit_from_home(&home, uid, &staging).is_err());
        fs::remove_file(&path).unwrap();
        let c = c_name(path.file_name().unwrap()).unwrap();
        let parent = File::open(path.parent().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifoat(parent.as_raw_fd(), c.as_ptr(), 0o600) },
            0
        );
        assert!(admit_from_home(&home, uid, &staging).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&backup, &path).unwrap();
        fs::set_permissions(home.join(".docker"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(admit_from_home(&home, uid, &staging).is_err());
        fs::set_permissions(home.join(".docker"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4700)).unwrap();
        assert!(admit_from_home(&home, uid, &staging).is_err());
        for mode in [0o601, 0o610] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(admit_from_home(&home, uid, &staging).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_PLUGIN_BYTES + 1)
            .unwrap();
        assert!(admit_from_home(&home, uid, &staging).is_err());
    }
    #[test]
    fn refuses_rebound_plugin_name_after_held_observation() {
        let (_temp, home, _staging, uid) = fixture();
        let original = plugin(&home);
        let held = source(&home, uid).unwrap().unwrap();
        let old = original.with_extension("old");
        fs::rename(&original, &old).unwrap();
        plugin(&home);
        let mut old_inode = reopen_held_regular(&held.plugin).unwrap();
        assert!(digest_exact(&mut old_inode, held.plugin_stamp.size, None).is_ok());
        assert!(rebind(&home, uid, &held).is_err());
        assert!(old.exists());
    }
    #[test]
    fn refuses_replaced_staged_plugin_name() {
        let (_temp, home, staging, uid) = fixture();
        plugin(&home);
        admit_from_home(&home, uid, &staging).unwrap();
        let dir_path = staging.join("cli-plugins");
        let file_path = dir_path.join(PLUGIN);
        let dir = File::open(&dir_path).unwrap();
        let held = openat_optional(dir.as_raw_fd(), OsStr::new(PLUGIN), libc::O_PATH)
            .unwrap()
            .unwrap();
        fs::rename(&file_path, dir_path.join("old")).unwrap();
        fs::copy(dir_path.join("old"), &file_path).unwrap();
        assert!(destination_bound(
            &dir_path,
            &dir,
            &file_path,
            &held,
            uid,
            stamp(&held).unwrap().size
        )
        .is_err());
    }
    #[test]
    fn real_docker_cli_sees_only_staged_plugin_without_engine_access() {
        let docker = Path::new("/usr/bin/docker");
        if !docker.is_file() {
            return;
        }
        let (_temp, home, staging, uid) = fixture();
        plugin(&home);
        let ambient = home.join("ambient-canary");
        fs::write(&ambient, "never-read-by-isolated-cli").unwrap();
        admit_from_home(&home, uid, &staging).unwrap();
        let output = std::process::Command::new(docker)
            .args(["compose", "version", "--short"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &staging)
            .env("DOCKER_CONFIG", &staging)
            .env("XDG_CONFIG_HOME", &staging)
            .env(
                "DOCKER_HOST",
                "unix:///unreachable-owned-fixture/docker.sock",
            )
            .current_dir(&staging)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Docker CLI did not load staged plugin (status={:?}, stdout={}, stderr={})",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "9.8.7");
        assert_eq!(
            fs::read_to_string(ambient).unwrap(),
            "never-read-by-isolated-cli"
        );
        assert!(!staging.join("ambient-canary").exists());
    }
}
