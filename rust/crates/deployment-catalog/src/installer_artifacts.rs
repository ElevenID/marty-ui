//! Bounded extraction of an already authenticated production bundle.
//!
//! The caller authenticates expected_sha (bare lowercase SHA-256), binds it to
//! the admitted release, and owns all concurrent writers under the private parent.
//! This verifies bytes and archive safety, NOT signatures, image admission, or
//! marker semantics. Destination is a NEW container directory; the returned
//! path is destination/selfhost-prepared. Failed extraction is never deleted.
#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Cursor, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, String>;
const ROOT: &str = "selfhost-prepared";
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 16384;
const REQUIRED: [&str; 2] = [
    "selfhost-prepared/.marty-selfhost-bundle.json",
    "selfhost-prepared/.marty-selfhost-images.json",
];

struct Entry {
    index: usize,
    path: String,
    directory: bool,
    executable: bool,
    size: u64,
}
fn failure(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}
fn cname(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| "invalid path".into())
}
fn open_at(parent: &File, name: &CString, flags: i32, mode: u32) -> Result<File> {
    // SAFETY: name is terminated and parent is an owned live descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(failure("open bundle path"))
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn private_directory(directory: &File) -> Result<()> {
    let m = directory.metadata().map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
        return Err("bundle parent must be an owned 0700 directory".into());
    }
    Ok(())
}
fn destination_parent(destination: &Path) -> Result<(File, CString)> {
    if !destination.is_absolute() {
        return Err("bundle destination must be absolute".into());
    }
    let mut components = destination.components();
    if components.next() != Some(Component::RootDir) {
        return Err("invalid destination".into());
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(n) => {
                names.push(CString::new(n.as_bytes()).map_err(|_| "invalid destination")?)
            }
            _ => return Err("destination must not contain traversal".into()),
        }
    }
    let leaf = names.pop().ok_or("cannot extract over filesystem root")?;
    let mut parent = File::open("/").map_err(|e| e.to_string())?;
    for component in names {
        parent = open_at(&parent, &component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let m = parent.metadata().map_err(|e| e.to_string())?;
        let uid = unsafe { libc::geteuid() };
        if (m.uid() != 0 && m.uid() != uid)
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err("unsafe writable bundle ancestor".into());
        }
    }
    private_directory(&parent)?;
    Ok((parent, leaf))
}
fn path_name(raw: &[u8], directory: bool) -> Result<String> {
    if raw.is_empty() || raw.len() > 1024 || !raw.is_ascii() {
        return Err("invalid archive path".into());
    }
    let raw = std::str::from_utf8(raw).map_err(|_| "invalid archive path")?;
    let value = if directory {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    if value.split('/').count() > 32
        || !value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && !part.ends_with(['.', ' '])
                && part
                    .bytes()
                    .all(|b| (33..=126).contains(&b) && b != b'\\' && b != b':')
        })
        || !(value == ROOT && directory || value.starts_with(&format!("{ROOT}/")))
    {
        return Err("unsafe archive path or unexpected bundle root".into());
    }
    Ok(value.into())
}
// Bound the parser's central-directory allocation BEFORE constructing ZipArchive.
// Current production packager emits a single-disk classic ZIP with no comment;
// ZIP64 and other extensions require an explicit reviewed contract change.
fn central_directory_bound(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 22 {
        return Err("truncated archive".into());
    }
    let offset = bytes.len() - 22;
    let end = &bytes[offset..];
    let short = |at: usize| u16::from_le_bytes([end[at], end[at + 1]]);
    let long = |at: usize| u32::from_le_bytes(end[at..at + 4].try_into().unwrap()) as u64;
    let count = short(10) as usize;
    if &end[..4] != b"PK\x05\x06"
        || short(4) != 0
        || short(6) != 0
        || short(8) != short(10)
        || short(20) != 0
        || count == 0
        || count > MAX_ENTRIES
        || long(12) + long(16) != offset as u64
    {
        return Err("unsupported archive directory or entry count".into());
    }
    // Validate the complete raw directory: zip can stop at an underdeclared
    // count and silently omit trailing entries, or collapse duplicate names.
    let mut cursor = long(16) as usize;
    let mut names = BTreeSet::new();
    for _ in 0..count {
        if cursor.checked_add(46).is_none_or(|end| end > offset)
            || &bytes[cursor..cursor + 4] != b"PK\x01\x02"
        {
            return Err("invalid central directory entry".into());
        }
        let length =
            |at: usize| u16::from_le_bytes([bytes[cursor + at], bytes[cursor + at + 1]]) as usize;
        let name_length = length(28);
        let extra_length = length(30);
        let comment_length = length(32);
        let next = cursor + 46 + name_length + extra_length + comment_length;
        if next > offset
            || name_length == 0
            || extra_length != 0
            || comment_length != 0
            || length(34) != 0
        {
            return Err("unsupported central directory metadata".into());
        }
        if !names.insert(bytes[cursor + 46..cursor + 46 + name_length].to_vec()) {
            return Err("duplicate central directory name".into());
        }
        cursor = next;
    }
    if cursor != offset {
        return Err("central directory count or length differs".into());
    }
    Ok(count)
}
fn inspect(
    archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>,
    max_file: u64,
    max_total: u64,
) -> Result<Vec<Entry>> {
    if archive.len() == 0 || archive.len() > MAX_ENTRIES {
        return Err("archive entry count exceeds bounds".into());
    }
    let mut declared = BTreeSet::new();
    let mut paths: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut entries = Vec::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).map_err(|e| e.to_string())?;
        let directory = file.is_dir();
        let mode = file
            .unix_mode()
            .unwrap_or(if directory { 0o040755 } else { 0o100644 });
        let kind = mode & libc::S_IFMT;
        // No symlinks, devices, Unix hardlink extensions, ACLs, or permission
        // restoration. Our packager writes ordinary files/directories without
        // extra fields; reject extensions instead of interpreting link metadata.
        if file.encrypted()
            || (kind != 0
                && kind
                    != if directory {
                        libc::S_IFDIR
                    } else {
                        libc::S_IFREG
                    })
            || mode & 0o7000 != 0
            || file.extra_data().is_some()
        {
            return Err("unsupported archive entry type or metadata".into());
        }
        let path = path_name(file.name_raw(), directory)?;
        if !declared.insert(path.clone()) {
            return Err("duplicate archive entry".into());
        }
        let components: Vec<_> = path.split('/').collect();
        for count in 1..=components.len() {
            let prefix = components[..count].join("/");
            let is_directory = count < components.len() || directory;
            let folded = prefix.to_ascii_lowercase();
            if let Some((original, previous_directory)) = paths.get(&folded) {
                if original != &prefix || *previous_directory != is_directory {
                    return Err("archive path case or file/directory collision".into());
                }
            } else {
                paths.insert(folded, (prefix, is_directory));
            }
        }
        let size = file.size();
        total = total
            .checked_add(size)
            .ok_or("expanded archive size overflow")?;
        if size > max_file || total > max_total || (directory && size != 0) {
            return Err("expanded archive exceeds bounds".into());
        }
        // Read every entry before any mutation, both enforcing the actual size
        // and forcing zip's CRC verification. No unbounded decompressed buffer.
        let actual = std::io::copy(&mut file.by_ref().take(size + 1), &mut std::io::sink())
            .map_err(|e| e.to_string())?;
        if actual != size {
            return Err("archive entry length differs".into());
        }
        entries.push(Entry {
            index,
            path,
            directory,
            executable: mode & 0o111 != 0,
            size,
        });
    }
    for required in REQUIRED {
        if !entries
            .iter()
            .any(|e| e.path == required && !e.directory && e.size > 0)
        {
            return Err("required production bundle marker is absent".into());
        }
    }
    Ok(entries)
}
fn child_directory(parent: &File, component: &str) -> Result<File> {
    let name = cname(component)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(failure("create extracted directory"));
    }
    let directory = open_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || !matches!(metadata.mode() & 0o7777, 0o700 | 0o755)
    {
        return Err("extracted directory ownership or mode changed".into());
    }
    // Public bundle resources must remain readable when their subtree is bound
    // into a non-root container. The enclosing destination remains 0700.
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) } != 0 {
        return Err(failure("set extracted directory mode"));
    }
    directory.sync_all().map_err(|e| e.to_string())?;
    parent.sync_all().map_err(|e| e.to_string())?;
    Ok(directory)
}
/// Verify the complete immutable byte snapshot and all entries before creating
/// destination. Only executable bits are retained (files become 0644 or 0755,
/// subdirectories 0755, inside the exclusively created 0700 destination).
/// No existing destination is adopted; failures preserve partial output.
pub fn extract_bundle(archive: &Path, destination: &Path, expected_sha: &str) -> Result<PathBuf> {
    extract_with_limits(archive, destination, expected_sha, MAX_FILE, MAX_TOTAL)
}
fn extract_with_limits(
    archive: &Path,
    destination: &Path,
    expected_sha: &str,
    max_file: u64,
    max_total: u64,
) -> Result<PathBuf> {
    if expected_sha.len() != 64
        || !expected_sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid expected archive digest".into());
    }
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(archive)
        .map_err(|e| e.to_string())?;
    let metadata = source.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_ARCHIVE {
        return Err("invalid archive file".into());
    }
    let mut bytes = Vec::new();
    source
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_ARCHIVE || format!("{:x}", Sha256::digest(&bytes)) != expected_sha {
        return Err("archive digest differs".into());
    }
    let declared_count = central_directory_bound(&bytes)?;
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    // The ZIP reader indexes by name and can collapse duplicate central entries.
    // Reject that loss before relying on the reader's per-entry inspection.
    if zip.len() != declared_count {
        return Err("archive entry count differs or contains duplicate names".into());
    }
    let entries = inspect(&mut zip, max_file, max_total)?;
    let (parent, leaf) = destination_parent(destination)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
        return Err(failure("create new bundle destination"));
    }
    let root = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    private_directory(&root)?;
    parent.sync_all().map_err(|e| e.to_string())?;
    for entry in entries {
        let components: Vec<_> = entry.path.split('/').collect();
        let mut directory = root.try_clone().map_err(|e| e.to_string())?;
        let count = if entry.directory {
            components.len()
        } else {
            components.len() - 1
        };
        for component in &components[..count] {
            directory = child_directory(&directory, component)?;
        }
        if !entry.directory {
            let name = cname(components.last().unwrap())?;
            let mut output = open_at(
                &directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                if entry.executable { 0o700 } else { 0o600 },
            )?;
            let mut input = zip.by_index(entry.index).map_err(|e| e.to_string())?;
            let copied = std::io::copy(&mut input.by_ref().take(entry.size + 1), &mut output)
                .map_err(|e| e.to_string())?;
            if copied != entry.size {
                return Err("archive extraction length differs".into());
            }
            if unsafe {
                libc::fchmod(
                    output.as_raw_fd(),
                    if entry.executable { 0o755 } else { 0o644 },
                )
            } != 0
            {
                return Err(failure("set extracted file mode"));
            }
            output
                .flush()
                .and_then(|_| output.sync_all())
                .map_err(|e| e.to_string())?;
            directory.sync_all().map_err(|e| e.to_string())?;
        }
    }
    root.sync_all().map_err(|e| e.to_string())?;
    Ok(destination.join(ROOT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;
    fn private_temp() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn bundle(path: &Path, files: &[(&str, &[u8], u32)]) -> String {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, bytes, mode) in files {
            zip.start_file(
                *name,
                SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(*mode),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
        format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
    }
    fn entries() -> Vec<(&'static str, &'static [u8], u32)> {
        vec![
            (REQUIRED[0], b"{}", 0o644),
            (REQUIRED[1], b"{}", 0o644),
            ("selfhost-prepared/scripts/start.sh", b"#!/bin/sh\n", 0o755),
        ]
    }
    #[test]
    fn extracts_exact_bytes_and_never_overwrites() {
        let temp = private_temp();
        let archive = temp.path().join("bundle.zip");
        let destination = temp.path().join("install");
        let sha = bundle(&archive, &entries());
        let root = extract_bundle(&archive, &destination, &sha).unwrap();
        assert_eq!(
            std::fs::read(root.join("scripts/start.sh")).unwrap(),
            b"#!/bin/sh\n"
        );
        assert_eq!(
            std::fs::metadata(root.join("scripts/start.sh"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
    }
    #[test]
    fn wrong_digest_and_size_limits_do_not_create_output() {
        let temp = private_temp();
        let archive = temp.path().join("bundle.zip");
        let destination = temp.path().join("install");
        let sha = bundle(&archive, &entries());
        assert!(extract_bundle(&archive, &destination, &"0".repeat(64)).is_err());
        assert!(extract_with_limits(&archive, &destination, &sha, 1, 100).is_err());
        assert!(extract_with_limits(&archive, &destination, &sha, 100, 3).is_err());
        assert!(!destination.exists());
    }
    #[test]
    fn rejects_traversal_case_collision_and_missing_markers_before_writing() {
        let temp = private_temp();
        let archive = temp.path().join("bundle.zip");
        let destination = temp.path().join("install");
        for bad in [
            "selfhost-prepared/../outside",
            "selfhost-prepared/a\\b",
            "/selfhost-prepared/x",
            "wrong/x",
            "selfhost-prepared/SCRIPTS/start.sh",
            "selfhost-prepared/scripts",
        ] {
            let mut files = entries();
            files.push((bad, b"bad", 0o644));
            let sha = bundle(&archive, &files);
            assert!(
                extract_bundle(&archive, &destination, &sha).is_err(),
                "accepted {bad}"
            );
            assert!(!destination.exists());
        }
        let sha = bundle(&archive, &[("selfhost-prepared/other", b"x", 0o644)]);
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
    }
    #[test]
    fn rejects_symlink_entry_and_destination_symlink() {
        let temp = private_temp();
        let archive = temp.path().join("bundle.zip");
        let destination = temp.path().join("install");
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        zip.add_symlink(
            "selfhost-prepared/link",
            "../../outside",
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.finish().unwrap();
        let sha = format!("{:x}", Sha256::digest(std::fs::read(&archive).unwrap()));
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
        let sha = bundle(&archive, &entries());
        std::os::unix::fs::symlink(temp.path(), &destination).unwrap();
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
    }
    #[test]
    fn duplicate_names_and_crc_corruption_are_refused() {
        let temp = private_temp();
        let archive = temp.path().join("bundle.zip");
        let destination = temp.path().join("install");
        let files = [
            (REQUIRED[0], b"{}".as_slice(), 0o644),
            (REQUIRED[1], b"{}".as_slice(), 0o644),
            ("selfhost-prepared/one", b"payload".as_slice(), 0o644),
            ("selfhost-prepared/two", b"payload".as_slice(), 0o644),
        ];
        bundle(&archive, &files);
        let original = std::fs::read(&archive).unwrap();
        // Patch equal-length local and central names so the writer's own
        // duplicate-name refusal cannot hide the reader behavior being tested.
        let mut bytes = original.clone();
        for i in 0..bytes.len() - 3 {
            if &bytes[i..i + 3] == b"two" {
                bytes[i..i + 3].copy_from_slice(b"one");
            }
        }
        std::fs::write(&archive, &bytes).unwrap();
        let sha = format!("{:x}", Sha256::digest(&bytes));
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
        // A forged count must not make the reader silently skip the duplicate.
        let end = bytes.len() - 22;
        let reduced = (files.len() as u16 - 1).to_le_bytes();
        bytes[end + 8..end + 10].copy_from_slice(&reduced);
        bytes[end + 10..end + 12].copy_from_slice(&reduced);
        std::fs::write(&archive, &bytes).unwrap();
        let sha = format!("{:x}", Sha256::digest(&bytes));
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
        let mut bytes = original;
        let start = bytes.windows(7).position(|v| v == b"payload").unwrap();
        bytes[start] = b'P';
        std::fs::write(&archive, &bytes).unwrap();
        let sha = format!("{:x}", Sha256::digest(&bytes));
        assert!(extract_bundle(&archive, &destination, &sha).is_err());
        assert!(!destination.exists());
    }
}
