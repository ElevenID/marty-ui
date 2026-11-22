//! Fixed, read-only root-container census primitive. The future host controller
//! must verify operator/image/Engine/container identity, authenticate creation
//! receipts, stop writers, and bind this output to a confirmed plan separately.
//! No Docker command, deletion, secret-content read, or purge authorization here.
#![cfg(target_os = "linux")]

use crate::{
    installer_host_snapshot::{identity, mount_id},
    installer_host_tree_observer::{self, TreeOutcome},
    installer_purge_host::{HostIdentity, HostPurgeEntry, Kind},
    installer_top_level_census,
};
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
use uuid::{Variant, Version};

const REFUSED: &str = "internal census refused";
const REQUEST_PATH: &str = "/input/request.json";
const ROOT_PATH: &str = "/installation";
const OUTPUT_PATH: &str = "/output/census.json";
const MAX_REQUEST: usize = 4096;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

type Result<T> = std::result::Result<T, String>;
fn fail<T>() -> Result<T> {
    Err(REFUSED.into())
}
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        fail()
    }
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    max_entries: usize,
    max_depth: usize,
    max_path_bytes: usize,
    max_response_bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    installation_id: uuid::Uuid,
    nonce: String,
    source_binding: String,
    normal_profile: String,
    expected_root: HostIdentity,
    expected_output: HostIdentity,
    bounds: Bounds,
}

fn decode_request(bytes: &[u8], build_identity: &str) -> Result<Request> {
    require(!bytes.is_empty() && bytes.len() <= MAX_REQUEST)?;
    let request: Request = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    require(
        serde_json::to_vec(&request).map_err(|_| REFUSED)? == bytes
            && request.schema == "elevenid.installer-root-census-request/v1"
            && request.installation_id.get_variant() == Variant::RFC4122
            && request.installation_id.get_version() == Some(Version::Random)
            && hex(&request.nonce, 64)
            && request.source_binding == build_identity
            && !build_identity.is_empty()
            && build_identity.len() <= 128
            && request.normal_profile == "normal_31_v1"
            && request.bounds.max_entries == 4096
            && request.bounds.max_depth == 16
            && request.bounds.max_path_bytes == 1024
            && request.bounds.max_response_bytes == MAX_RESPONSE
            && request.expected_root.kind == Kind::Directory
            && request.expected_root.mode == 0o700
            && request.expected_root.uid != 0
            && request.expected_root.ino != 0
            && request.expected_output.kind == Kind::File
            && request.expected_output.mode == 0o600
            && request.expected_output.ino != 0
            && request.expected_output.uid == request.expected_root.uid,
    )?;
    Ok(request)
}

fn open_path(path: &str) -> Result<File> {
    let path = CString::new(path).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        fail()
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn procfs(path: &str) -> Result<File> {
    let file = File::open(path).map_err(|_| REFUSED)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } == 0 && info.f_type as i64 == 0x9fa0,
    )?;
    Ok(file)
}
fn reopen(held: &File, flags: i32) -> Result<File> {
    let before = identity(held).map_err(|_| REFUSED)?;
    let before_mount = mount_id(held).map_err(|_| REFUSED)?;
    let proc = procfs("/proc/self/fd")?;
    let name = CString::new(held.as_raw_fd().to_string()).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return fail();
    }
    let file = unsafe { File::from_raw_fd(fd) };
    require(
        identity(&file).map_err(|_| REFUSED)? == before
            && mount_id(&file).map_err(|_| REFUSED)? == before_mount,
    )?;
    Ok(file)
}
fn readonly_mount(file: &File, readonly: bool) -> Result<()> {
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstatvfs(file.as_raw_fd(), &mut info) } == 0)?;
    require((info.f_flag & libc::ST_RDONLY != 0) == readonly)
}
fn same_binding(path: &str, held: &File) -> Result<()> {
    let current = open_path(path)?;
    require(
        identity(&current).map_err(|_| REFUSED)? == identity(held).map_err(|_| REFUSED)?
            && mount_id(&current).map_err(|_| REFUSED)? == mount_id(held).map_err(|_| REFUSED)?,
    )
}
fn identity_map(path: &str) -> Result<()> {
    let mut bytes = Vec::new();
    procfs(path)?
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() <= 256)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    parse_identity_map(text)
}
fn parse_identity_map(text: &str) -> Result<()> {
    let mut lines = text.lines();
    let line = lines.next().ok_or(REFUSED)?;
    require(lines.next().is_none())?;
    let parts: Vec<_> = line.split_whitespace().collect();
    require(parts.len() == 3)?;
    let inside = parts[0].parse::<u64>().map_err(|_| REFUSED)?;
    let outside = parts[1].parse::<u64>().map_err(|_| REFUSED)?;
    let count = parts[2].parse::<u64>().map_err(|_| REFUSED)?;
    // A partial map may present an unmapped descendant UID/GID as overflow
    // 65534, which cannot be distinguished from a genuine owner by stat.
    require(inside == 0 && outside == 0 && count == u64::from(u32::MAX))
}

#[derive(Serialize)]
struct PrivateResponse<'a> {
    schema: &'static str,
    installation_id: uuid::Uuid,
    nonce: &'a str,
    source_binding: &'a str,
    coverage: &'static str,
    root: &'a HostIdentity,
    helper_mount_id: u64,
    entries_deepest_first: &'a [HostPurgeEntry],
    not_atomic_snapshot: bool,
    deletion_eligible: bool,
    deletion_authorized: bool,
}

fn observe_bytes(root: &File, request: &Request) -> Result<Vec<u8>> {
    let expected_root = &request.expected_root;
    require(identity(root).map_err(|_| REFUSED)? == *expected_root)?;
    let mount = mount_id(root).map_err(|_| REFUSED)?;
    require(mount != 0)?;
    let specs =
        installer_top_level_census::derive_current_fixed_specs_held(root, expected_root, mount)
            .map_err(|_| REFUSED)?;
    let first = match installer_host_tree_observer::observe_held(
        root,
        request.installation_id,
        expected_root,
        mount,
        &specs,
    ) {
        TreeOutcome::Observed(value) => value,
        TreeOutcome::Incomplete(_) => return fail(),
    };
    let second = match installer_host_tree_observer::observe_held(
        root,
        request.installation_id,
        expected_root,
        mount,
        &specs,
    ) {
        TreeOutcome::Observed(value) => value,
        TreeOutcome::Incomplete(_) => return fail(),
    };
    require(
        first.entries.len() <= request.bounds.max_entries
            && first.entries == second.entries
            && first.root == second.root
            && first.mount_id == second.mount_id
            && first.installation_id == second.installation_id
            && first.coverage == second.coverage
            && !first.deletion_eligible
            && !second.deletion_eligible
            && first.not_atomic_snapshot
            && second.not_atomic_snapshot,
    )?;
    // A separate writable file bind can alias an inode under the read-only
    // installation bind. Never write the output if it is part of this census.
    let output = &request.expected_output;
    require(
        !(expected_root.dev == output.dev && expected_root.ino == output.ino)
            && first.entries.iter().all(|entry| {
                !(entry.target.dev == output.dev && entry.target.ino == output.ino
                    || entry.parent.dev == output.dev && entry.parent.ino == output.ino)
            }),
    )?;
    let response = PrivateResponse {
        schema: "elevenid.installer-private-root-census/v1",
        installation_id: request.installation_id,
        nonce: &request.nonce,
        source_binding: &request.source_binding,
        coverage: first.coverage,
        root: expected_root,
        helper_mount_id: mount,
        entries_deepest_first: &first.entries,
        not_atomic_snapshot: true,
        deletion_eligible: false,
        deletion_authorized: false,
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| REFUSED)?;
    require(!bytes.is_empty() && bytes.len() <= MAX_RESPONSE)?;
    Ok(bytes)
}

fn validate_bindings(
    input: &File,
    root: &File,
    output: &File,
) -> Result<(HostIdentity, HostIdentity)> {
    let input_identity = identity(input).map_err(|_| REFUSED)?;
    let root_identity = identity(root).map_err(|_| REFUSED)?;
    let output_identity = identity(output).map_err(|_| REFUSED)?;
    let input_meta = input.metadata().map_err(|_| REFUSED)?;
    let output_meta = output.metadata().map_err(|_| REFUSED)?;
    require(
        input_identity.kind == Kind::File
            && input_identity.mode == 0o600
            && input_meta.nlink() == 1
            && input_meta.len() > 0
            && input_meta.len() <= MAX_REQUEST as u64
            && root_identity.kind == Kind::Directory
            && root_identity.mode == 0o700
            && root_identity.uid != 0
            && output_identity.kind == Kind::File
            && output_identity.mode == 0o600
            && output_meta.nlink() == 1
            && output_meta.len() == 0
            && input_identity.uid == root_identity.uid
            && output_identity.uid == root_identity.uid,
    )?;
    Ok((root_identity, output_identity))
}

/// Exact internal dispatch only. All failure messages are fixed and reveal no
/// private names or identities. Output may be partial on failure and is never
/// an authenticated ownership or deletion receipt by itself.
pub fn run() -> Result<()> {
    require(unsafe { libc::geteuid() } == 0)?;
    let input = open_path(REQUEST_PATH)?;
    let root = open_path(ROOT_PATH)?;
    let output = open_path(OUTPUT_PATH)?;
    let (root_identity, output_identity) = validate_bindings(&input, &root, &output)?;
    let input_identity = identity(&input).map_err(|_| REFUSED)?;
    identity_map("/proc/self/uid_map")?;
    identity_map("/proc/self/gid_map")?;
    let readable_input = reopen(&input, libc::O_RDONLY)?;
    let readable_root = reopen(&root, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut writable_output = reopen(&output, libc::O_WRONLY)?;
    readonly_mount(&readable_input, true)?;
    readonly_mount(&readable_root, true)?;
    readonly_mount(&writable_output, false)?;
    same_binding(REQUEST_PATH, &input)?;
    same_binding(ROOT_PATH, &root)?;
    same_binding(OUTPUT_PATH, &output)?;
    let mut request_bytes = Vec::new();
    readable_input
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut request_bytes)
        .map_err(|_| REFUSED)?;
    let request = decode_request(&request_bytes, env!("MARTY_DEPLOY_BUILD_IDENTITY"))?;
    require(request.expected_root == root_identity && request.expected_output == output_identity)?;
    require(input.metadata().map_err(|_| REFUSED)?.len() == request_bytes.len() as u64)?;
    same_binding(REQUEST_PATH, &input)?;
    same_binding(ROOT_PATH, &root)?;
    same_binding(OUTPUT_PATH, &output)?;
    require(output.metadata().map_err(|_| REFUSED)?.len() == 0)?;
    let bytes = observe_bytes(&root, &request)?;
    let mut repeated_request = Vec::new();
    reopen(&input, libc::O_RDONLY)?
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut repeated_request)
        .map_err(|_| REFUSED)?;
    require(repeated_request == request_bytes)?;
    readonly_mount(&readable_root, true)?;
    same_binding(REQUEST_PATH, &input)?;
    same_binding(ROOT_PATH, &root)?;
    same_binding(OUTPUT_PATH, &output)?;
    require(
        identity(&input).map_err(|_| REFUSED)? == input_identity
            && identity(&root).map_err(|_| REFUSED)? == root_identity
            && identity(&output).map_err(|_| REFUSED)? == output_identity
            && output.metadata().map_err(|_| REFUSED)?.nlink() == 1,
    )?;
    require(output.metadata().map_err(|_| REFUSED)?.len() == 0)?;
    writable_output
        .write_all(&bytes)
        .and_then(|_| writable_output.sync_all())
        .map_err(|_| REFUSED)?;
    require(writable_output.metadata().map_err(|_| REFUSED)?.len() == bytes.len() as u64)?;
    same_binding(OUTPUT_PATH, &output)?;
    same_binding(ROOT_PATH, &root)?;
    require(
        identity(&output).map_err(|_| REFUSED)? == output_identity
            && output.metadata().map_err(|_| REFUSED)?.nlink() == 1
            && identity(&root).map_err(|_| REFUSED)? == root_identity,
    )?;
    println!(
        "{{\"status\":\"observed\",\"bytes\":{},\"sha256\":\"{}\",\"nonce\":\"{}\"}}",
        bytes.len(),
        digest(&bytes),
        request.nonce
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_top_level_census::TopLevelName;
    use std::{
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        },
    };

    fn request(root: HostIdentity, output: HostIdentity) -> Request {
        Request {
            schema: "elevenid.installer-root-census-request/v1".into(),
            installation_id: uuid::Uuid::new_v4(),
            nonce: "a".repeat(64),
            source_binding: "synthetic:fixture".into(),
            normal_profile: "normal_31_v1".into(),
            expected_root: root,
            expected_output: output,
            bounds: Bounds {
                max_entries: 4096,
                max_depth: 16,
                max_path_bytes: 1024,
                max_response_bytes: MAX_RESPONSE,
            },
        }
    }

    #[test]
    fn strict_canonical_request_rejects_missing_nonce_specs_and_bounds() {
        let root = HostIdentity {
            dev: 1,
            ino: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o700,
            kind: Kind::Directory,
        };
        let output = HostIdentity {
            dev: 1,
            ino: 3,
            uid: 1000,
            gid: 1000,
            mode: 0o600,
            kind: Kind::File,
        };
        let mut value = request(root, output);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(decode_request(&bytes, "synthetic:fixture").is_ok());
        assert!(decode_request(&bytes, "foreign:build").is_err());
        assert!(decode_request(&[bytes.as_slice(), b" "].concat(), "synthetic:fixture").is_err());
        value.nonce.clear();
        assert!(decode_request(&serde_json::to_vec(&value).unwrap(), "synthetic:fixture").is_err());
        value.nonce = "a".repeat(64);
        value.bounds.max_depth += 1;
        assert!(decode_request(&serde_json::to_vec(&value).unwrap(), "synthetic:fixture").is_err());
        let mut foreign: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        foreign["dynamic_paths"] = serde_json::json!(["secret"]);
        assert!(
            decode_request(&serde_json::to_vec(&foreign).unwrap(), "synthetic:fixture").is_err()
        );
        foreign.as_object_mut().unwrap().remove("dynamic_paths");
        foreign.as_object_mut().unwrap().remove("nonce");
        assert!(
            decode_request(&serde_json::to_vec(&foreign).unwrap(), "synthetic:fixture").is_err()
        );
    }

    #[test]
    fn fixed_held_bindings_refuse_partial_link_special_and_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let input_path = temp.path().join("input");
        let root_path = temp.path().join("installation");
        let output_path = temp.path().join("output");
        fs::write(&input_path, b"synthetic-request").unwrap();
        fs::create_dir(&root_path).unwrap();
        fs::write(&output_path, b"").unwrap();
        for path in [&input_path, &root_path, &output_path] {
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if path == &root_path { 0o700 } else { 0o600 }),
            )
            .unwrap();
        }
        let input = open_path(input_path.to_str().unwrap()).unwrap();
        let root = open_path(root_path.to_str().unwrap()).unwrap();
        let output = open_path(output_path.to_str().unwrap()).unwrap();
        assert!(validate_bindings(&input, &root, &output).is_ok());
        assert!(readonly_mount(&reopen(&input, libc::O_RDONLY).unwrap(), false).is_ok());
        assert!(readonly_mount(&reopen(&input, libc::O_RDONLY).unwrap(), true).is_err());
        fs::write(&output_path, b"partial").unwrap();
        assert!(validate_bindings(&input, &root, &output).is_err());
        fs::write(&output_path, b"").unwrap();
        fs::hard_link(&output_path, temp.path().join("linked")).unwrap();
        assert!(validate_bindings(&input, &root, &output).is_err());
        fs::remove_file(temp.path().join("linked")).unwrap();
        fs::rename(&output_path, temp.path().join("saved-output")).unwrap();
        fs::write(&output_path, b"").unwrap();
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(same_binding(output_path.to_str().unwrap(), &output).is_err());
        fs::remove_file(&output_path).unwrap();
        symlink(temp.path().join("saved-output"), &output_path).unwrap();
        assert!(identity(&open_path(output_path.to_str().unwrap()).unwrap()).is_err());
        fs::remove_file(&input_path).unwrap();
        let c = CString::new(input_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(identity(&open_path(input_path.to_str().unwrap()).unwrap()).is_err());
    }

    #[test]
    fn identity_mapping_refuses_shift_or_extra_range() {
        assert!(parse_identity_map("0 0 4294967295\n").is_ok());
        assert!(parse_identity_map("0 100000 65536\n").is_err());
        assert!(parse_identity_map("0 0 1000\n").is_err());
        assert!(parse_identity_map("0 0 65536\n").is_err());
        assert!(parse_identity_map("0 0 65536\n100000 100000 65536\n").is_err());
    }
    #[test]
    fn partial_uid_or_gid_map_refuses_before_observation() {
        let full = "0 0 4294967295\n";
        let partial = "0 0 65536\n";
        assert!(parse_identity_map(partial)
            .and_then(|_| parse_identity_map(full))
            .is_err());
        assert!(parse_identity_map(full)
            .and_then(|_| parse_identity_map(partial))
            .is_err());
    }

    #[test]
    fn two_current_tree_censuses_require_exact_normal_profile() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in TopLevelName::REQUIRED {
            let path = temp.path().join(name.name());
            if name.expected_kind() == Kind::Directory {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"unread-synthetic-value").unwrap();
            }
        }
        fs::create_dir(temp.path().join("openbao-state/tls")).unwrap();
        fs::write(
            temp.path().join("openbao-state/tls/ca.key"),
            b"unread-private-canary",
        )
        .unwrap();
        let root = File::open(temp.path()).unwrap();
        let expected = identity(&root).unwrap();
        let output = HostIdentity {
            dev: expected.dev,
            ino: expected.ino + 1000,
            uid: expected.uid,
            gid: expected.gid,
            mode: 0o600,
            kind: Kind::File,
        };
        let request = request(expected, output);
        let bytes = observe_bytes(&root, &request).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["deletion_authorized"], false);
        assert_eq!(response["coverage"], "expected_normal_profile_current_tree");
        fs::write(temp.path().join("unknown-canary"), b"unexpected").unwrap();
        assert!(observe_bytes(&root, &request).is_err());
    }
    #[test]
    fn writable_output_alias_inside_installation_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in TopLevelName::REQUIRED {
            let path = temp.path().join(name.name());
            if name.expected_kind() == Kind::Directory {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"synthetic").unwrap();
            }
        }
        let aliased_output = temp.path().join("backups/census-output");
        fs::write(&aliased_output, b"").unwrap();
        fs::set_permissions(&aliased_output, fs::Permissions::from_mode(0o600)).unwrap();
        let root = File::open(temp.path()).unwrap();
        let request = request(
            identity(&root).unwrap(),
            identity(&File::open(&aliased_output).unwrap()).unwrap(),
        );
        assert!(observe_bytes(&root, &request).is_err());
        assert_eq!(fs::read(&aliased_output).unwrap(), b"");
    }
}
