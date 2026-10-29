//! Fixed, metadata-only rootless bind ownership probe inside an admitted image.
//! The host controller supplies only a private fixed-layout bind and separately
//! authenticates the image, operator, containers, UID map and resulting inode.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "rootless canary helper refused";
const PARENT: &str = "/marty-canary";
const CHILD: &str = "child";
const REQUEST: &str = "request.json";
const MARKER: &str = "marker";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    installation_id: uuid::Uuid,
    canary_id: uuid::Uuid,
    host_uid: u32,
    host_gid: u32,
    marker_sha256: String,
}

#[derive(Serialize)]
struct Observation {
    schema: &'static str,
    installation_id: uuid::Uuid,
    canary_id: uuid::Uuid,
    phase: &'static str,
    host_uid_zero: u32,
    host_uid_hundred: u32,
    host_gid_zero: u32,
    host_gid_hundred: u32,
    marker_sha256: String,
    child_dev: u64,
    child_ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdMap {
    zero: u32,
    hundred: u32,
}

fn id_map_zero(bytes: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    let fields = text
        .lines()
        .next()
        .ok_or(REFUSED)?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != "0" || fields[2] != "1" {
        return Err(REFUSED.into());
    }
    let outside = fields[1].parse::<u32>().map_err(|_| REFUSED)?;
    if outside == 0 {
        return Err(REFUSED.into());
    }
    Ok(outside)
}

fn id_map(bytes: &[u8], expected_zero: u32) -> Result<IdMap> {
    if bytes.is_empty() || bytes.len() > 4096 || expected_zero == 0 {
        return Err(REFUSED.into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    let mut ranges = Vec::new();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || ranges.len() >= 16 {
            return Err(REFUSED.into());
        }
        let parse = |field: &str| -> Result<u64> {
            if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                return Err(REFUSED.into());
            }
            field.parse::<u64>().map_err(|_| REFUSED.into())
        };
        let start = parse(fields[0])?;
        let outside = parse(fields[1])?;
        let count = parse(fields[2])?;
        if count == 0
            || start
                .checked_add(count)
                .is_none_or(|end| end > u32::MAX as u64 + 1)
            || outside
                .checked_add(count)
                .is_none_or(|end| end > u32::MAX as u64 + 1)
            || ranges
                .iter()
                .any(|(s, _, c): &(u64, u64, u64)| start < *s + *c && *s < start + count)
        {
            return Err(REFUSED.into());
        }
        ranges.push((start, outside, count));
    }
    // A single host UID/GID maps container zero; the remaining range starts
    // at one. Refuse nested or partial layouts whose reported IDs cannot be
    // interpreted as host ownership without another namespace translation.
    if ranges.len() != 2
        || ranges[0] != (0, expected_zero as u64, 1)
        || ranges[1].0 != 1
        || ranges[1].2 < 100
        || ranges[1].1 == 0
        || (ranges[1].1..ranges[1].1 + ranges[1].2).contains(&(expected_zero as u64))
    {
        return Err(REFUSED.into());
    }
    let map = |id: u64| -> Result<u32> {
        let matching = ranges
            .iter()
            .filter(|(start, _, count)| *start <= id && id < *start + *count)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(REFUSED.into());
        }
        let (start, outside, _) = matching[0];
        u32::try_from(*outside + id - *start).map_err(|_| REFUSED.into())
    };
    let zero = map(0)?;
    let hundred = map(100)?;
    if zero != expected_zero || hundred == zero || hundred == 0 {
        return Err(REFUSED.into());
    }
    Ok(IdMap { zero, hundred })
}

fn bounded(path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| REFUSED)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}

fn process_gate() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(REFUSED.into());
    }
    let status = bounded("/proc/self/status", 16 * 1024)?;
    let status = std::str::from_utf8(&status).map_err(|_| REFUSED)?;
    let mut nnp = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| *name == "NoNewPrivs")
        .map(|(_, value)| value.trim());
    if nnp.next() != Some("1") || nnp.next().is_some() {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn open_at(parent: i32, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(REFUSED.into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn private_dir(file: &File, uid: u32) -> Result<()> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn read_entry(parent: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
    let path = open_at(parent.as_raw_fd(), name, libc::O_PATH, 0)?;
    let before = path.metadata().map_err(|_| REFUSED)?;
    if !before.is_file() || before.nlink() != 1 || before.mode() & 0o7777 != 0o600 {
        return Err(REFUSED.into());
    }
    let procfd = format!("/proc/self/fd/{}", path.as_raw_fd());
    let mut file = File::open(procfd).map_err(|_| REFUSED)?;
    let opened = file.metadata().map_err(|_| REFUSED)?;
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
        return Err(REFUSED.into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    let after = file.metadata().map_err(|_| REFUSED)?;
    if bytes.is_empty()
        || bytes.len() as u64 > limit
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.ctime(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.ctime(),
        )
    {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}

fn stabilize_existing_entry(parent: &File, name: &str, expected: &[u8]) -> Result<()> {
    let held = open_at(parent.as_raw_fd(), name, libc::O_PATH, 0)?;
    let before = held.metadata().map_err(|_| REFUSED)?;
    if !before.is_file() || before.nlink() != 1 || before.mode() & 0o7777 != 0o600 {
        return Err(REFUSED.into());
    }
    let file = File::open(format!("/proc/self/fd/{}", held.as_raw_fd())).map_err(|_| REFUSED)?;
    let opened = file.metadata().map_err(|_| REFUSED)?;
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || read_entry(parent, name, 4096)? != expected
    {
        return Err(REFUSED.into());
    }
    file.sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED)?;
    let current = open_at(parent.as_raw_fd(), name, libc::O_PATH, 0)?;
    let after = current.metadata().map_err(|_| REFUSED)?;
    if (
        after.dev(),
        after.ino(),
        after.uid(),
        after.gid(),
        after.mode(),
        after.nlink(),
        after.len(),
        after.mtime(),
        after.ctime(),
    ) != (
        before.dev(),
        before.ino(),
        before.uid(),
        before.gid(),
        before.mode(),
        before.nlink(),
        before.len(),
        before.mtime(),
        before.ctime(),
    ) || read_entry(parent, name, 4096)? != expected
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn write_entry(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(REFUSED.into());
    }
    let entry = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    let mut file = if fd >= 0 {
        unsafe { File::from_raw_fd(fd) }
    } else {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
            // A scoped restore retry may find the exact output fsynced before
            // its preceding helper was interrupted ahead of fchown.
            if stabilize_existing_entry(parent, name, bytes).is_ok() {
                return Ok(());
            }
        }
        return Err(REFUSED.into());
    };
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED.into())
}

/// This entry has no arbitrary path or command argument. The caller must bind
/// /marty-canary to one exact private parent, not to the child being chowned.
pub fn run(args: &[String]) -> Result<()> {
    let phase = match args {
        [phase] if phase == "transition" => "transition",
        [phase] if phase == "restore" => "restore",
        _ => return Err(REFUSED.into()),
    };
    process_gate()?;
    let raw_uid = bounded("/proc/self/uid_map", 4096)?;
    let raw_gid = bounded("/proc/self/gid_map", 4096)?;
    // This must precede even opening the fixed bind. A direct host-root
    // invocation has an initial-namespace UID0 mapping and stops here.
    let prelim_uid = id_map(&raw_uid, id_map_zero(&raw_uid)?)?;
    let prelim_gid = id_map(&raw_gid, id_map_zero(&raw_gid)?)?;
    let parent = open_at(
        libc::AT_FDCWD,
        PARENT,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    private_dir(&parent, 0)?;
    let request: Request =
        serde_json::from_slice(&read_entry(&parent, REQUEST, 4096)?).map_err(|_| REFUSED)?;
    if request.schema != "elevenid.rootless-storage-canary-request/v1"
        || request.host_uid == 0
        || request.host_gid == 0
        || request.marker_sha256.len() != 64
        || !request
            .marker_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(REFUSED.into());
    }
    let uid = id_map(&raw_uid, request.host_uid)?;
    let gid = id_map(&raw_gid, request.host_gid)?;
    if uid != prelim_uid || gid != prelim_gid {
        return Err(REFUSED.into());
    }
    let child = open_at(
        parent.as_raw_fd(),
        CHILD,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    private_dir(&child, if phase == "transition" { 0 } else { 100 })?;
    let marker = read_entry(&child, MARKER, 256)?;
    let marker_sha = format!("{:x}", Sha256::digest(&marker));
    if marker_sha != request.marker_sha256 {
        return Err(REFUSED.into());
    }
    let m = child.metadata().map_err(|_| REFUSED)?;
    let output = Observation {
        schema: "elevenid.rootless-storage-canary-helper/v1",
        installation_id: request.installation_id,
        canary_id: request.canary_id,
        phase,
        host_uid_zero: uid.zero,
        host_uid_hundred: uid.hundred,
        host_gid_zero: gid.zero,
        host_gid_hundred: gid.hundred,
        marker_sha256: marker_sha,
        child_dev: m.dev(),
        child_ino: m.ino(),
    };
    // Persist mapping/readback before changing ownership. The host requires a
    // separate observed inode/owner and exact container result after this write.
    write_entry(
        &parent,
        if phase == "transition" {
            "transition-output.json"
        } else {
            "restore-output.json"
        },
        &serde_json::to_vec(&output).map_err(|_| REFUSED)?,
    )?;
    let (new_uid, new_gid) = if phase == "transition" {
        (100, 100)
    } else {
        (0, 0)
    };
    if unsafe { libc::fchown(child.as_raw_fd(), new_uid, new_gid) } != 0 {
        return Err(REFUSED.into());
    }
    let after = child.metadata().map_err(|_| REFUSED)?;
    if after.uid() != new_uid || after.gid() != new_gid || after.mode() & 0o7777 != 0o700 {
        return Err(REFUSED.into());
    }
    child.sync_all().map_err(|_| REFUSED)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_prior_output_is_retryable_but_changed_output_refuses() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = File::open(parent.path()).unwrap();
        write_entry(&held, "restore-output.json", b"synthetic").unwrap();
        write_entry(&held, "restore-output.json", b"synthetic").unwrap();
        assert!(write_entry(&held, "restore-output.json", b"changed").is_err());
    }

    #[test]
    fn uid_map_requires_distinct_nonhost_zero_and_hundred() {
        assert_eq!(
            id_map(b"0 1000 1\n1 100000 65536\n", 1000).unwrap().hundred,
            100099
        );
        for map in [
            b"0 0 4294967295\n".as_slice(),
            b"0 1000 1\n".as_slice(),
            b"0 1000 200\n100 2000 1\n".as_slice(),
            b"0 1000 101\n".as_slice(),
            b"0 x 1\n1 100000 65536\n".as_slice(),
        ] {
            assert!(id_map(map, 1000).is_err());
        }
    }

    #[test]
    fn helper_refuses_host_namespace_before_fixed_path_access() {
        assert!(run(&["transition".into()]).is_err());
        assert!(run(&["restore".into()]).is_err());
        assert!(run(&["transition".into(), "/tmp/other".into()]).is_err());
    }
}
