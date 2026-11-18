//! Internal container-only bridge. Host orchestration must bind the authenticated
//! operator, CA and root token read-only, record the owned container before start,
//! and retain its output mount on failure. Never emits credential-bearing JSON.
//! Container root needs exactly DAC_OVERRIDE after dropping all capabilities to
//! access the installer-user-owned 0700 operator/output. The host must inspect
//! this capability, readonly rootfs, no-new-privileges, isolated network and exact
//! mounts before start. Never mount the Docker socket, whole state or secrets.
#![cfg(target_os = "linux")]

use marty_openbao_http::OpenBaoHttp;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
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
const REFUSED: &str = "Keycloak bridge input refused";
const RECOVERY: &str =
    "Keycloak bridge incomplete; preserve owned container and outputs for recovery";
pub const OUTPUTS: [&str; 7] = [
    "keycloak_signing_kms_token",
    "keycloak_master_rs256_cert",
    "keycloak_11id_rs256_cert",
    "keycloak_master_cookie_token",
    "keycloak_master_ciba_token",
    "keycloak_11id_cookie_token",
    "keycloak_11id_ciba_token",
];

fn read_input(path: &Path, maximum: u64, root_token: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| REFUSED)? != path {
        return Err(REFUSED.into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    let metadata = file.metadata().map_err(|_| REFUSED)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.mode() & 0o7022 != 0
        || (root_token && (metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o400))
    {
        return Err(REFUSED.into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}

fn output_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| REFUSED)? != path {
        return Err(REFUSED.into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    let metadata = directory.metadata().map_err(|_| REFUSED)?;
    if !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700 {
        return Err(REFUSED.into());
    }
    // Inspect the held directory inode, not a second lookup through the mount.
    let held = format!("/proc/self/fd/{}", directory.as_raw_fd());
    if std::fs::read_dir(held)
        .map_err(|_| REFUSED)?
        .next()
        .is_some()
    {
        return Err(REFUSED.into());
    }
    Ok(directory)
}

fn validate_outputs(outputs: &Value, root_token: &str) -> Result<()> {
    let object = outputs.as_object().ok_or(RECOVERY)?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(OUTPUTS) {
        return Err(RECOVERY.into());
    }
    let mut tokens = BTreeSet::new();
    for (name, value) in object {
        let value = value.as_str().ok_or(RECOVERY)?;
        if value.is_empty()
            || value.len() > 65536
            || !value.is_ascii()
            || value.contains("PRIVATE KEY")
            || value.contains(root_token)
        {
            return Err(RECOVERY.into());
        }
        if name.ends_with("_token") {
            if !(20..=2048).contains(&value.len())
                || value
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                || !tokens.insert(value)
            {
                return Err(RECOVERY.into());
            }
        } else if !value.starts_with("-----BEGIN CERTIFICATE-----")
            || !value.trim_end().ends_with("-----END CERTIFICATE-----")
        {
            return Err(RECOVERY.into());
        }
    }
    Ok(())
}

fn write_outputs(directory: &File, outputs: &Value, root_token: &str) -> Result<usize> {
    validate_outputs(outputs, root_token)?;
    for name in OUTPUTS {
        let entry = CString::new(name).unwrap();
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                entry.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(RECOVERY.into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        // Persist the partial name before writing; no automatic deletion/replay.
        directory.sync_all().map_err(|_| RECOVERY)?;
        file.write_all(outputs[name].as_str().ok_or(RECOVERY)?.as_bytes())
            .map_err(|_| RECOVERY)?;
        file.sync_all().map_err(|_| RECOVERY)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
            return Err(RECOVERY.into());
        }
        file.sync_all()
            .and_then(|_| directory.sync_all())
            .map_err(|_| RECOVERY)?;
    }
    Ok(OUTPUTS.len())
}

/// Only a future owned-container orchestration path may invoke this entry point.
/// All network/provisioning failures are conservatively recovery-required.
pub async fn provision(nonce: &str) -> Result<usize> {
    if unsafe { libc::geteuid() } != 0
        || nonce.len() != 12
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(REFUSED.into());
    }
    let token = read_input(Path::new("/input/root.token"), 4096, true)?;
    let token = std::str::from_utf8(&token).map_err(|_| REFUSED)?.trim();
    if !(20..=4096).contains(&token.len())
        || !token.is_ascii()
        || token
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(REFUSED.into());
    }
    let ca = Path::new("/input/ca.crt");
    read_input(ca, 65536, false)?;
    let output = output_directory(Path::new("/output"))?;
    let bao = OpenBaoHttp::connect("https://openbao:8200", Some(ca), Duration::from_secs(30))
        .map_err(|_| REFUSED)?;
    let values = crate::keycloak_provision::provision(
        &bao,
        &json!({"token":token,"renew":false,"pki_mount":"keycloak-pki","nonce":nonce}),
    )
    .await
    .map_err(|_| RECOVERY)?;
    write_outputs(&output, &values, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn private() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn outputs() -> Value {
        let mut values = serde_json::Map::new();
        for (index, name) in OUTPUTS.iter().enumerate() {
            values.insert(
                (*name).into(),
                json!(if name.ends_with("_token") {
                    format!("scoped-token-{index}-{}", "a".repeat(30))
                } else {
                    "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
                }),
            );
        }
        Value::Object(values)
    }
    #[test]
    fn validates_exact_outputs_and_never_exports_root_or_private_material() {
        let token = "root-token-not-for-export";
        validate_outputs(&outputs(), token).unwrap();
        for bad in [
            json!("PRIVATE KEY"),
            json!(token),
            json!("short"),
            json!("token with spaces exceeding twenty chars"),
            Value::Null,
        ] {
            let mut values = outputs();
            values[OUTPUTS[0]] = bad;
            assert!(validate_outputs(&values, token).is_err());
        }
        let mut values = outputs();
        values[OUTPUTS[3]] = values[OUTPUTS[0]].clone();
        assert!(validate_outputs(&values, token).is_err());
        values = outputs();
        values["unexpected"] = json!("extra");
        assert!(validate_outputs(&values, token).is_err());
    }
    #[test]
    fn writes_exclusive_readonly_outputs_and_preserves_on_repeat() {
        let root = private();
        let dir = output_directory(root.path()).unwrap();
        assert_eq!(
            write_outputs(&dir, &outputs(), "root-token-not-for-export").unwrap(),
            7
        );
        for name in OUTPUTS {
            assert_eq!(
                std::fs::metadata(root.path().join(name)).unwrap().mode() & 0o777,
                0o444
            );
        }
        assert!(write_outputs(&dir, &outputs(), "root-token-not-for-export").is_err());
        assert!(output_directory(root.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(root.path().join(OUTPUTS[0])).unwrap(),
            outputs()[OUTPUTS[0]].as_str().unwrap()
        );
    }
    #[test]
    fn refuses_linked_public_and_nonempty_output_directories() {
        let root = private();
        let link = root.path().join("linked");
        symlink(root.path(), &link).unwrap();
        assert!(output_directory(&link).is_err());
        assert!(output_directory(root.path()).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(output_directory(root.path()).is_err());
    }
    #[test]
    fn input_bounds_and_link_policy_are_enforced_without_network() {
        let root = private();
        let path = root.path().join("ca.crt");
        std::fs::write(&path, b"public certificate").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_input(&path, 65536, false).is_ok());
        assert!(read_input(&path, 4, false).is_err());
        assert!(read_input(&path, 65536, true).is_err());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_input(&link, 65536, false).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::hard_link(&path, root.path().join("hard")).unwrap();
        assert!(read_input(&path, 65536, false).is_err());
    }
}
