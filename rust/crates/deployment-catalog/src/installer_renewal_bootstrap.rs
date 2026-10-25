//! Internal fixed-path renewal authority bootstrap, not root retirement.
//! An external owned-container transaction must authenticate this executable,
//! bind the exact readonly inputs, record its ID before start, and retain the
//! durable pending receipt and surviving outputs after uncertainty. The shared
//! AppRole bootstrap may roll back some authority and identity files on failure;
//! that does not authorize replay. The owned installer renewal stage invokes it.
#![cfg(target_os = "linux")]

use crate::{activation_preflight, approle, operator_http};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::SELFHOST_ROLES;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Renewal bootstrap input refused";
const RECOVERY: &str =
    "Renewal bootstrap incomplete; preserve owned helper and private outputs for recovery";
const IDENTITY_FILES: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

/// Only the existing workload/Keycloak public certificates and scoped tokens.
/// No scalar application credentials, ingress token, root or unseal key.
pub fn current_inputs() -> BTreeSet<String> {
    let mut names = BTreeSet::from(["workload_identity_ca_cert".into()]);
    for role in SELFHOST_ROLES {
        names.insert(role.cert_file.into());
        names.insert(role.token_file.into());
    }
    names.extend(crate::installer_keycloak_bridge::OUTPUTS.map(String::from));
    names
}

fn readonly(file: &File) -> Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(unsafe { libc::fstatvfs(file.as_raw_fd(), info.as_mut_ptr()) } == 0)?;
    require(unsafe { info.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}

pub(crate) fn directory(path: &Path, root_owned: bool, read_only: bool) -> Result<File> {
    require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    let info = file.metadata().map_err(|_| REFUSED)?;
    require(info.is_dir() && info.mode() & 0o7777 == 0o700 && (!root_owned || info.uid() == 0))?;
    if read_only {
        readonly(&file)?;
    }
    Ok(file)
}

pub(crate) fn names(dir: &File) -> Result<BTreeSet<String>> {
    std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| REFUSED)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSED.to_owned())
                .and_then(|entry| entry.file_name().into_string().map_err(|_| REFUSED.into()))
        })
        .collect()
}

fn read_file(
    file: File,
    maximum: u64,
    owners: &[u32],
    modes: &[u32],
    read_only: bool,
) -> Result<Vec<u8>> {
    let info = file.metadata().map_err(|_| REFUSED)?;
    require(
        info.is_file()
            && info.nlink() == 1
            && info.len() > 0
            && info.len() <= maximum
            && owners.contains(&info.uid())
            && modes.contains(&(info.mode() & 0o7777)),
    )?;
    if read_only {
        readonly(&file)?;
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(
        bytes.len() as u64 == info.len()
            && bytes.is_ascii()
            && !bytes.contains(&0)
            && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
    )?;
    Ok(bytes)
}

const ROOT_OWNERS: &[u32] = &[0];
// The reviewed pinned OpenBao TLS producer owns its public CA as UID 100.
// Identity comes from the admitted container and exact read-only source mount,
// not from this UID alone. This exception never applies to the root token.
const CA_OWNERS: &[u32] = &[0, 100];
pub(crate) fn input(path: &Path, maximum: u64, owners: &[u32], modes: &[u32]) -> Result<Vec<u8>> {
    require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    read_file(file, maximum, owners, modes, true)
}

pub(crate) fn entry(
    dir: &File,
    name: &str,
    owners: &[u32],
    modes: &[u32],
    read_only: bool,
) -> Result<Vec<u8>> {
    require(!name.contains('/') && !name.contains('\\') && name != "." && name != "..")?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0)?;
    read_file(
        unsafe { File::from_raw_fd(fd) },
        65536,
        owners,
        modes,
        read_only,
    )
}

pub(crate) fn validate_current(values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    require(values.keys().cloned().collect::<BTreeSet<_>>() == current_inputs())?;
    let mut tokens = BTreeSet::new();
    for (name, value) in values {
        let value = std::str::from_utf8(value).map_err(|_| REFUSED)?;
        if name.ends_with("_token") {
            require(
                (20..=4096).contains(&value.len())
                    && value.bytes().all(|b| b.is_ascii_graphic())
                    && tokens.insert(value),
            )?;
        } else {
            require(
                value.starts_with("-----BEGIN CERTIFICATE-----\n")
                    && value.trim_end().ends_with("-----END CERTIFICATE-----"),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn current(dir: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(names(dir)? == current_inputs())?;
    let owner = dir.metadata().map_err(|_| REFUSED)?.uid();
    let values = current_inputs()
        .into_iter()
        .map(|name| {
            let value = entry(dir, &name, &[0, owner], &[0o444], true)?;
            Ok((name, value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_current(&values)?;
    Ok(values)
}

pub(crate) fn receipt(dir: &File, name: &str, value: &Value) -> Result<()> {
    let data = serde_json::to_vec(value).map_err(|_| RECOVERY)?;
    require(data.len() <= 8192)?;
    let name = CString::new(name).map_err(|_| RECOVERY)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(RECOVERY.into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    dir.sync_all().map_err(|_| RECOVERY)?;
    file.write_all(&data)
        .and_then(|_| file.sync_all())
        .and_then(|_| dir.sync_all())
        .map_err(|_| RECOVERY.into())
}

pub(crate) fn validate_id(id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| REFUSED)?;
    require(
        parsed.to_string() == id
            && parsed.get_version_num() == 4
            && parsed.get_variant() == uuid::Variant::RFC4122,
    )
}

/// Returns only the count of persisted private identity files. Root remains
/// active; ingress renewal, application activation and root retirement are NOT
/// performed. Failed login may have minted an unknown token: never auto-retry.
pub async fn bootstrap(installation_id: &str) -> Result<usize> {
    bootstrap_at(installation_id, Path::new("/output")).await
}

async fn bootstrap_at(installation_id: &str, output_path: &Path) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    validate_id(installation_id)?;
    let root_bytes = input(Path::new("/input/root.token"), 4096, ROOT_OWNERS, &[0o400])?;
    let root = std::str::from_utf8(&root_bytes)
        .map_err(|_| REFUSED)?
        .trim();
    require((20..=4096).contains(&root.len()) && root.bytes().all(|b| b.is_ascii_graphic()))?;
    let ca = input(
        Path::new("/input/ca.crt"),
        65536,
        CA_OWNERS,
        &[0o444, 0o644],
    )?;
    let inputs = directory(Path::new("/input/current"), false, true)?;
    let before = current(&inputs)?;
    require(
        before
            .values()
            .all(|v| !v.windows(root.len()).any(|w| w == root.as_bytes())),
    )?;
    let output = directory(output_path, true, false)?;
    require(names(&output)?.is_empty())?;
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new("/input/ca.crt")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSED)?;
    let lookup = operator_http::request(
        &bao,
        Method::GET,
        "auth/token/lookup-self",
        None,
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(lookup["data"]["policies"] == json!(["root"]))?;
    let policies = activation_preflight::renewal_inventory(
        &bao,
        &json!({"token":root,"current":"/input/current"}),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(
        current(&inputs)? == before
            && input(Path::new("/input/root.token"), 4096, ROOT_OWNERS, &[0o400])? == root_bytes
            && input(
                Path::new("/input/ca.crt"),
                65536,
                CA_OWNERS,
                &[0o444, 0o644],
            )? == ca,
    )?;
    receipt(
        &output,
        "pending.json",
        &json!({"schema":"elevenid.installer-renewal-bootstrap-intent/v1",
        "installation_id":installation_id,"root_retired":false,"ingress_renewal":false}),
    )?;
    let outcome: Result<usize> = async {
    let identity_name = CString::new("identity").unwrap();
    if unsafe { libc::mkdirat(output.as_raw_fd(), identity_name.as_ptr(), 0o700) } != 0 {
        return Err(RECOVERY.into());
    }
    output.sync_all().map_err(|_| RECOVERY)?;
        let identity_path = output_path.join("identity");
        let identity = directory(&identity_path, true, false)?;
    approle::bootstrap(
        &bao,
        approle::Role::Renewal,
            &identity_path,
        &json!({"root_token":root,"names":policies}),
    )
    .await
    .map_err(|_| RECOVERY)?;
    identity.sync_all().map_err(|_| RECOVERY)?;
    require(names(&identity)? == IDENTITY_FILES.map(String::from).into())?;
    for name in IDENTITY_FILES {
            let value = entry(&identity, name, &[0], &[0o600], false)?;
            require(!value.windows(root.len()).any(|v| v == root.as_bytes()))?;
    }
        let login = approle::login(&bao, approle::Role::Renewal, &identity_path, &json!({}))
        .await
        .map_err(|_| RECOVERY)?;
    let transient = login["token"].as_str().ok_or(RECOVERY)?;
    require(
        transient != root
            && (20..=4096).contains(&transient.len())
            && transient.bytes().all(|b| b.is_ascii_graphic()),
    )?;
        // Even a failed authority proof must retire the known verification
        // token. A failed login may instead hide a minted token; that remains
        // an uncertain pending transaction requiring separate recovery.
        let authority = activation_preflight::authority(&bao, transient, false).await;
    operator_http::request(
        &bao,
        Method::POST,
        "auth/token/revoke-self",
        None,
        Some(transient),
    )
    .await
    .map_err(|_| RECOVERY)?;
    let denial = operator_http::builder(
        &bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":transient})),
        Some(transient),
    )
    .send()
    .await
    .map_err(|_| RECOVERY)?;
    if denial.status() != StatusCode::FORBIDDEN {
        return Err(RECOVERY.into());
    }
        authority.map_err(|_| RECOVERY)?;
    require(current(&inputs)? == before)?;
    receipt(
        &output,
        "completed.json",
        &json!({"schema":"elevenid.installer-renewal-bootstrap-result/v1",
        "installation_id":installation_id,"identity_files":IDENTITY_FILES,"policy_count":21,
        "scoped_login_verified":true,"verification_token_revoked":true,"root_retired":false,"ingress_renewal":false}),
    )?;
    Ok(IDENTITY_FILES.len())
    }.await;
    outcome.map_err(|_| RECOVERY.into())
}

pub(crate) fn child(parent: &File, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| RECOVERY)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(RECOVERY.into());
    }
    parent.sync_all().map_err(|_| RECOVERY)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(RECOVERY.into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn deliver_file(directory: &File, name: &str, bytes: &[u8], uid: u32, gid: u32) -> Result<()> {
    let name = CString::new(name).map_err(|_| RECOVERY)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(RECOVERY.into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    directory.sync_all().map_err(|_| RECOVERY)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RECOVERY)?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(RECOVERY.into());
    }
    let metadata = file.metadata().map_err(|_| RECOVERY)?;
    require(
        metadata.uid() == uid
            && metadata.gid() == gid
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
    )?;
    file.sync_all()
        .and_then(|_| directory.sync_all())
        .map_err(|_| RECOVERY.into())
}

fn deliver_directory(directory: &File, parent: &File, uid: u32, gid: u32) -> Result<()> {
    if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0 {
        return Err(RECOVERY.into());
    }
    let metadata = directory.metadata().map_err(|_| RECOVERY)?;
    require(metadata.uid() == uid && metadata.gid() == gid && metadata.mode() & 0o7777 == 0o700)?;
    directory
        .sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| RECOVERY.into())
}

/// Fixed private transfer wrapper. CHOWN is needed only for freshly created
/// delivery file descriptors and their new directory. Original root-owned
/// identity and receipts remain private and untouched for recovery.
pub async fn bootstrap_transfer(installation_id: &str) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    validate_id(installation_id)?;
    let parent = directory(Path::new("/transfer"), false, false)?;
    let owner = parent.metadata().map_err(|_| REFUSED)?;
    require(names(&parent)?.is_empty())?;
    receipt(
        &parent,
        "transfer-pending.json",
        &json!({"schema":"elevenid.installer-renewal-transfer-intent/v1",
        "installation_id":installation_id,"root_retired":false}),
    )?;
    let result: Result<usize> = async {
        let output = child(&parent, "output")?;
        require(output.metadata().map_err(|_| RECOVERY)?.uid() == 0)?;
        bootstrap_at(installation_id, Path::new("/transfer/output")).await?;
        require(names(&output)? == BTreeSet::from(["pending.json".into(), "completed.json".into(), "identity".into()]))?;
        let identity = directory(Path::new("/transfer/output/identity"), true, false)?;
        require(names(&identity)? == IDENTITY_FILES.map(String::from).into())?;
        let mut values = BTreeMap::new();
        for name in IDENTITY_FILES {
            values.insert(name.to_owned(), entry(&identity, name, &[0], &[0o600], false)?);
        }
        for name in ["pending.json", "completed.json"] {
            values.insert(name.into(), entry(&output, name, &[0], &[0o600], false)?);
        }
        let completed: Value = serde_json::from_slice(&values["completed.json"]).map_err(|_| RECOVERY)?;
        require(completed == json!({"schema":"elevenid.installer-renewal-bootstrap-result/v1",
            "installation_id":installation_id,"identity_files":IDENTITY_FILES,"policy_count":21,
            "scoped_login_verified":true,"verification_token_revoked":true,"root_retired":false,"ingress_renewal":false}))?;
        let delivered = child(&parent, "delivered")?;
        for (name, bytes) in values { deliver_file(&delivered, &name, &bytes, owner.uid(), owner.gid())?; }
        let after = directory(Path::new("/transfer"), false, false)?.metadata().map_err(|_| RECOVERY)?;
        require((after.dev(),after.ino(),after.uid(),after.gid(),after.mode()) == (owner.dev(),owner.ino(),owner.uid(),owner.gid(),owner.mode()))?;
        deliver_directory(&delivered, &parent, owner.uid(), owner.gid())?;
        Ok(IDENTITY_FILES.len())
    }.await;
    result.map_err(|_| RECOVERY.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    #[ignore = "explicit root-only Linux ownership qualification; synthetic files only"]
    fn root_transfer_enforces_real_recipient_and_other_user_access() {
        use std::{
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        assert_eq!(unsafe { libc::geteuid() }, 0, "qualification requires root");
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let control = temp.path().join("control");
        std::fs::write(&control, b"public-control").unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o444)).unwrap();
        let outer = directory(temp.path(), false, true);
        // The production directory opener requires 0700, so hold the public
        // fixture ancestor directly; the actual transfer directory stays 0700.
        assert!(outer.is_err());
        let outer = File::open(temp.path()).unwrap();
        let parent = child(&outer, "transfer").unwrap();
        let uid = 65534;
        let gid = 65534;
        assert_eq!(unsafe { libc::fchown(parent.as_raw_fd(), uid, gid) }, 0);
        let original = child(&parent, "output").unwrap();
        receipt(
            &original,
            "pending.json",
            &json!({"synthetic":"root-original"}),
        )
        .unwrap();
        let delivered = child(&parent, "delivered").unwrap();
        deliver_file(
            &delivered,
            "renewal-secret-id",
            b"synthetic-private-credential",
            uid,
            gid,
        )
        .unwrap();
        deliver_directory(&delivered, &parent, uid, gid).unwrap();
        let script = r#"import errno, os, pathlib, sys
assert os.getuid() == os.geteuid() == int(sys.argv[2])
assert os.getgid() == os.getegid() == int(sys.argv[2])
assert os.getgroups() == []
base = pathlib.Path(sys.argv[1])
assert (base / 'control').read_bytes() == b'public-control'
delivered = base / 'transfer/delivered/renewal-secret-id'
denied = [base / 'transfer/output/pending.json']
if os.geteuid() == 65534:
    assert delivered.read_bytes() == b'synthetic-private-credential'
else:
    denied.append(delivered)
for path in denied:
    try:
        path.read_bytes()
    except OSError as error:
        assert error.errno == errno.EACCES
    else:
        raise AssertionError('private file was readable')
"#;
        for target in [uid, 65533] {
            let mut command = Command::new("/usr/bin/python3");
            command
                .args(["-I", "-c", script])
                .arg(temp.path())
                .arg(target.to_string())
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(target) != 0
                        || libc::setuid(target) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(
                command.status().unwrap().success(),
                "recipient permission qualification failed"
            );
        }
        assert_eq!(original.metadata().unwrap().uid(), 0);
        assert_eq!(original.metadata().unwrap().mode() & 0o7777, 0o700);
        assert!(entry(&original, "pending.json", &[0], &[0o600], false).is_ok());
        assert!(deliver_file(&delivered, "renewal-secret-id", b"overwrite", uid, gid).is_err());
        let ca_path = temp.path().join("synthetic-ca");
        std::fs::write(&ca_path, b"public fixture bytes").unwrap();
        let ca_file = File::open(&ca_path).unwrap();
        assert_eq!(unsafe { libc::fchown(ca_file.as_raw_fd(), 100, 1000) }, 0);
        for mode in [0o444, 0o644] {
            std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_file(
                File::open(&ca_path).unwrap(),
                65536,
                CA_OWNERS,
                &[0o444, 0o644],
                false
            )
            .is_ok());
            assert!(read_file(
                File::open(&ca_path).unwrap(),
                65536,
                ROOT_OWNERS,
                &[mode],
                false
            )
            .is_err());
        }
        std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_file(
            File::open(&ca_path).unwrap(),
            4096,
            ROOT_OWNERS,
            &[0o400],
            false
        )
        .is_err());
        std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_file(
            File::open(&ca_path).unwrap(),
            65536,
            CA_OWNERS,
            &[0o444, 0o644],
            false
        )
        .is_err());
        std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let linked = temp.path().join("linked-ca");
        std::fs::hard_link(&ca_path, &linked).unwrap();
        assert!(read_file(
            File::open(&ca_path).unwrap(),
            65536,
            CA_OWNERS,
            &[0o444, 0o644],
            false
        )
        .is_err());
        std::fs::remove_file(linked).unwrap();
        assert_eq!(unsafe { libc::fchown(ca_file.as_raw_fd(), 101, 1000) }, 0);
        assert!(read_file(
            File::open(&ca_path).unwrap(),
            65536,
            CA_OWNERS,
            &[0o444, 0o644],
            false
        )
        .is_err());
    }

    #[test]
    fn transfer_copies_are_private_exclusive_and_leave_originals() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = directory(temp.path(), false, false).unwrap();
        let original = child(&parent, "output").unwrap();
        receipt(&original, "pending.json", &json!({"root_retired":false})).unwrap();
        let delivered = child(&parent, "delivered").unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        deliver_file(
            &delivered,
            "renewal-secret-id",
            b"private-credential",
            uid,
            gid,
        )
        .unwrap();
        assert_eq!(
            entry(&delivered, "renewal-secret-id", &[uid], &[0o600], false).unwrap(),
            b"private-credential"
        );
        assert!(deliver_file(&delivered, "renewal-secret-id", b"overwrite", uid, gid).is_err());
        assert!(child(&parent, "delivered").is_err());
        assert_eq!(
            names(&original).unwrap(),
            BTreeSet::from(["pending.json".into()])
        );
        symlink(
            temp.path().join("output/pending.json"),
            temp.path().join("delivered/linked"),
        )
        .unwrap();
        assert!(deliver_file(&delivered, "linked", b"overwrite", uid, gid).is_err());
    }

    #[test]
    fn exact_input_inventory_refuses_scalar_ingress_duplicate_and_root_material() {
        let mut values = BTreeMap::new();
        for (index, name) in current_inputs().into_iter().enumerate() {
            let value = if name.ends_with("_token") {
                format!("token-{index:040}")
            } else {
                "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
            };
            values.insert(name, value.into_bytes());
        }
        assert_eq!(values.len(), 40);
        validate_current(&values).unwrap();
        for name in [
            "operator_bootstrap_password",
            "installer_ingress_kms_token",
            "root.token",
        ] {
            let mut changed = values.clone();
            changed.insert(name.into(), b"secret".to_vec());
            assert!(validate_current(&changed).is_err());
        }
        let tokens = values
            .keys()
            .filter(|n| n.ends_with("_token"))
            .cloned()
            .collect::<Vec<_>>();
        let mut duplicate = values.clone();
        duplicate.insert(tokens[0].clone(), values[&tokens[1]].clone());
        assert!(validate_current(&duplicate).is_err());
        values.remove(&tokens[0]);
        assert!(validate_current(&values).is_err());
    }

    #[test]
    fn canonical_installation_id_and_readonly_filesystem_are_required() {
        validate_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        for bad in [
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(validate_id(bad).is_err());
        }
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory(temp.path(), false, false).unwrap();
        assert!(readonly(&dir).is_err());
        receipt(&dir, "pending.json", &json!({"root_retired":false})).unwrap();
        assert!(receipt(&dir, "pending.json", &json!({})).is_err());
        assert_eq!(
            names(&dir).unwrap(),
            BTreeSet::from(["pending.json".into()])
        );
    }

    #[test]
    fn fd_relative_inputs_refuse_links_modes_and_private_keys() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory(temp.path(), false, false).unwrap();
        let owner = unsafe { libc::geteuid() };
        let path = temp.path().join("value");
        std::fs::write(&path, b"safe-input").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(
            entry(&dir, "value", &[owner], &[0o444], false).unwrap(),
            b"safe-input"
        );
        symlink(&path, temp.path().join("link")).unwrap();
        assert!(entry(&dir, "link", &[owner], &[0o444], false).is_err());
        std::fs::hard_link(&path, temp.path().join("hardlink")).unwrap();
        assert!(entry(&dir, "value", &[owner], &[0o444], false).is_err());
        std::fs::remove_file(temp.path().join("hardlink")).unwrap();
        assert!(entry(&dir, "value", &[owner], &[0o600], false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert!(entry(&dir, "value", &[owner], &[0o600], false).is_err());
        assert!(entry(&dir, "../value", &[owner], &[0o600], false).is_err());
    }
}
