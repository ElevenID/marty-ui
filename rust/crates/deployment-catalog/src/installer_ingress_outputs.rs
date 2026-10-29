//! Accept outputs only after the caller authenticates and stops its owned helper.
//! Local validation does not replace the helper's remote custody and ACL proof.
#![cfg(target_os = "linux")]
use crate::installer_helper_output::HelperOutputOwner;
use crate::installer_ingress_provision::{certificate, check_certificates, resource_name, OUTPUTS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::der::{Encode, EncodePem};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::{SystemTime, UNIX_EPOCH},
};
pub type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Ingress output validation failed; preserve owned outputs for recovery";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngressMetadata {
    pub schema: String,
    pub installation_id: String,
    pub key_name: String,
    pub key_version: u64,
    pub pki_mount: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub ca_der_sha256: String,
    pub certificate_der_sha256: String,
    pub ca_pem_sha256: String,
    pub certificate_pem_sha256: String,
    pub ca_expires_at: u64,
    pub certificate_expires_at: u64,
    pub token_ttl_seconds: u64,
    pub token_observed_at: u64,
    pub trust_installed: bool,
    pub installation_ready: bool,
}
#[derive(Debug, Serialize)]
pub struct ValidatedIngressOutputs {
    pub metadata_bytes: Vec<u8>,
    pub metadata: IngressMetadata,
    pub outputnames: Vec<String>,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn directory(dir: &File) -> Result<()> {
    let m = dir.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)
}
fn absent(dir: &File, name: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    require(result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
}
/// Refuse existing or partial destinations before remote provisioning begins.
pub fn preflight(secrets: &File) -> Result<()> {
    directory(secrets)?;
    for name in &OUTPUTS[..3] {
        absent(secrets, name)?;
    }
    Ok(())
}
fn read(dir: &File, name: &str, owner: u32) -> Result<Vec<u8>> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0)?;
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(
        m.is_file()
            && m.uid() == owner
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o444
            && m.len() > 0
            && m.len() <= 65536,
    )?;
    let mut bytes = Vec::new();
    (&file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    let after = file.metadata().map_err(|_| REFUSED)?;
    require(
        bytes.len() as u64 == m.len()
            && after.len() == m.len()
            && after.nlink() == 1
            && after.mode() == m.mode()
            && after.mtime() == m.mtime()
            && after.mtime_nsec() == m.mtime_nsec(),
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    require(text.is_ascii() && !text.contains('\0') && !text.contains("PRIVATE KEY"))?;
    Ok(bytes)
}
fn write(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    dir.sync_all().map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    file.sync_all()
        .and_then(|_| dir.sync_all())
        .map_err(|_| REFUSED.to_owned())
}
fn metadata(bytes: &[u8], id: &str, now: u64) -> Result<IngressMetadata> {
    require(bytes.len() <= 8192)?;
    let m: IngressMetadata = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    let name = resource_name(id)?;
    require(
        m.schema == "elevenid.installer-ingress/v1"
            && m.installation_id == id
            && m.key_name == name
            && m.pki_mount == name
            && m.key_version == 1
            && m.dns_names == ["localhost"]
            && m.ip_addresses == ["127.0.0.1"]
            && !m.trust_installed
            && !m.installation_ready,
    )?;
    require(
        (3600..=28800).contains(&m.token_ttl_seconds)
            && m.token_observed_at <= now
            && now - m.token_observed_at <= 900
            && m.token_observed_at
                .checked_add(m.token_ttl_seconds)
                .is_some_and(|end| end >= now.saturating_add(3600)),
    )?;
    for hash in [
        &m.ca_der_sha256,
        &m.certificate_der_sha256,
        &m.ca_pem_sha256,
        &m.certificate_pem_sha256,
    ] {
        require(
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        )?;
    }
    Ok(m)
}
fn token(bytes: &[u8]) -> Result<()> {
    require(
        (20..=4096).contains(&bytes.len())
            && bytes
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c)),
    )
}
/// The caller holds the installation lock and proves the helper has stopped.
/// All validation precedes exclusive transfers; failures preserve partial files.
pub(crate) fn validate_and_transfer(
    output: &File,
    secrets: &File,
    installation_id: &str,
    expected_host_uid: HelperOutputOwner,
) -> Result<ValidatedIngressOutputs> {
    directory(output)?;
    preflight(secrets)?;
    let names: BTreeSet<String> =
        std::fs::read_dir(format!("/proc/self/fd/{}", output.as_raw_fd()))
            .map_err(|_| REFUSED)?
            .map(|e| {
                e.map_err(|_| REFUSED)?
                    .file_name()
                    .into_string()
                    .map_err(|_| REFUSED)
            })
            .collect::<std::result::Result<_, _>>()?;
    require(names == OUTPUTS.iter().map(|s| s.to_string()).collect())?;
    let bytes = OUTPUTS
        .iter()
        .map(|name| read(output, name, expected_host_uid.uid()))
        .collect::<Result<Vec<_>>>()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let m = metadata(&bytes[3], installation_id, now)?;
    token(&bytes[2])?;
    let ca = std::str::from_utf8(&bytes[0]).map_err(|_| REFUSED)?;
    let leaf = std::str::from_utf8(&bytes[1]).map_err(|_| REFUSED)?;
    let ca_cert = certificate(ca)?;
    let leaf_cert = certificate(leaf)?;
    let public = leaf_cert
        .tbs_certificate
        .subject_public_key_info
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let expiry = check_certificates(ca, leaf, &public, &m.key_name, now)?;
    require(expiry == (m.ca_expires_at, m.certificate_expires_at))?;
    for (expected, actual) in [
        (&m.ca_pem_sha256, bytes[0].clone()),
        (&m.certificate_pem_sha256, bytes[1].clone()),
        (&m.ca_der_sha256, ca_cert.to_der().map_err(|_| REFUSED)?),
        (
            &m.certificate_der_sha256,
            leaf_cert.to_der().map_err(|_| REFUSED)?,
        ),
    ] {
        require(*expected == format!("{:x}", Sha256::digest(actual)))?;
    }
    for (name, bytes) in OUTPUTS[..3].iter().zip(&bytes) {
        write(secrets, name, bytes)?;
    }
    Ok(ValidatedIngressOutputs {
        metadata_bytes: bytes[3].clone(),
        metadata: m,
        outputnames: OUTPUTS[..3].iter().map(|s| s.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const ID: &str = "12345678-1234-4234-8234-123456789abc";
    fn record() -> serde_json::Value {
        serde_json::json!({"schema":"elevenid.installer-ingress/v1","installation_id":ID,
            "key_name":resource_name(ID).unwrap(),"key_version":1,"pki_mount":resource_name(ID).unwrap(),
            "dns_names":["localhost"],"ip_addresses":["127.0.0.1"],
            "ca_der_sha256":"a".repeat(64),"certificate_der_sha256":"b".repeat(64),
            "ca_pem_sha256":"c".repeat(64),"certificate_pem_sha256":"d".repeat(64),
            "ca_expires_at":99999,"certificate_expires_at":28800,"token_ttl_seconds":7200,
            "token_observed_at":1000,"trust_installed":false,"installation_ready":false})
    }
    #[test]
    fn metadata_is_closed_bound_and_fresh() {
        let original = record();
        assert!(metadata(&serde_json::to_vec(&original).unwrap(), ID, 1100).is_ok());
        for (key, value) in [
            ("key_version", serde_json::json!(2)),
            ("installation_id", serde_json::json!("foreign")),
            ("pki_mount", serde_json::json!("transit")),
            ("dns_names", serde_json::json!(["example.com"])),
            ("ip_addresses", serde_json::json!(["0.0.0.0"])),
            ("token_observed_at", serde_json::json!(1101)),
            ("token_ttl_seconds", serde_json::json!(28801)),
            ("trust_installed", serde_json::json!(true)),
            ("installation_ready", serde_json::json!(true)),
            ("unknown", serde_json::json!(false)),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(
                metadata(&serde_json::to_vec(&changed).unwrap(), ID, 1100).is_err(),
                "{key}"
            );
        }
        assert!(metadata(&serde_json::to_vec(&original).unwrap(), ID, 2000).is_err());
        let encoded = serde_json::to_string(&original).unwrap();
        let duplicate = encoded.replacen('{', "{\"key_version\":1,", 1);
        assert!(metadata(duplicate.as_bytes(), ID, 1100).is_err());
    }
    fn private() -> (tempfile::TempDir, File) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(temp.path()).unwrap();
        (temp, file)
    }
    #[test]
    fn output_files_are_bounded_ordinary_and_exclusive() {
        let (temp, dir) = private();
        preflight(&dir).unwrap();
        write(&dir, OUTPUTS[0], b"public certificate bytes").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            read(&dir, OUTPUTS[0], uid).unwrap(),
            b"public certificate bytes"
        );
        assert!(read(&dir, OUTPUTS[0], uid.wrapping_add(1)).is_err());
        assert!(write(&dir, OUTPUTS[0], b"replacement").is_err());
        assert!(preflight(&dir).is_err());
        std::fs::hard_link(temp.path().join(OUTPUTS[0]), temp.path().join("linked")).unwrap();
        assert!(read(&dir, OUTPUTS[0], unsafe { libc::geteuid() }).is_err());
        symlink("missing", temp.path().join(OUTPUTS[1])).unwrap();
        assert!(read(&dir, OUTPUTS[1], unsafe { libc::geteuid() }).is_err());
        let fifo = CString::new(temp.path().join(OUTPUTS[2]).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o444) }, 0);
        assert!(read(&dir, OUTPUTS[2], unsafe { libc::geteuid() }).is_err());
    }
    #[test]
    fn token_and_inventory_refuse_private_or_partial_material() {
        assert!(token(b"hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").is_ok());
        for value in [
            b"short".as_slice(),
            b"hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ\n",
            b"-----BEGIN PRIVATE KEY-----",
        ] {
            assert!(token(value).is_err());
        }
        let (_out, output) = private();
        let (_sec, secrets) = private();
        let binding = crate::installer_state::RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "engine-identity-123".into(),
            openbao_port: 8200,
            profile: crate::installer_state::RuntimeProfile::Rootful,
        };
        assert!(validate_and_transfer(
            &output,
            &secrets,
            ID,
            crate::installer_helper_output::expected_host_uid(&binding).unwrap(),
        )
        .is_err());
        assert!(
            std::fs::read_dir(format!("/proc/self/fd/{}", secrets.as_raw_fd()))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
