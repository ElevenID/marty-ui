//! Accept public workload certificates and scoped KMS tokens from the admitted
//! bootstrap. Never creates private keys, retries remote mutations, or removes
//! partial output. The caller retains the installation lock and container proof.
#![cfg(target_os = "linux")]
use marty_selfhost_identity::SELFHOST_ROLES;
use serde::{Deserialize, Serialize};
use spki::der::DecodePem;
use std::{collections::{BTreeMap, BTreeSet}, ffi::CString, fs::{File, OpenOptions},
    io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::{MetadataExt, OpenOptionsExt}}, path::Path};
use x509_cert::Certificate;

pub type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "TLS output validation failed; preserve installation state for recovery";
pub const METADATA_FILE: &str = "selfhost-tls-kms-roles.json";
const CA: &str = "workload_identity_ca_cert";
// Prefixes are an independent wiring contract: they cannot be derived from the
// public role spelling (e.g. ORG, ES, RP and CT).
const PREFIX_ROLES: [(&str, &str); 16] = [
    ("SIGNING_KEYS", "signing-keys-server"), ("GATEWAY", "gateway-client"),
    ("AUTH", "auth-client"), ("AUTH_SERVER", "auth-server"),
    ("COMPLIANCE_PROFILE", "compliance-profile-client"), ("DEPLOYMENT_PROFILE", "deployment-profile-client"),
    ("ORG", "organization-server"), ("ES", "event-stream-server"),
    ("NOTIFICATION", "notification-server"), ("RP", "revocation-profile-server"),
    ("CT", "credential-template-server"), ("ISSUANCE", "issuance-server"),
    ("FLOW_CLIENT", "flow-client"), ("FLOW_SERVER", "flow-server"),
    ("PP", "pp-server"), ("VERIFICATION", "verification-client"),
];

#[derive(Debug, Serialize)]
pub struct ValidatedTlsOutputs {
    pub metadata_bytes: Vec<u8>,
    pub env_fragment: String,
    pub outputnames: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata { schema: String, roles: Vec<Role> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Role { role: String, key_name: String, version: u64 }
fn require(ok: bool) -> Result<()> { if ok { Ok(()) } else { Err(REFUSED.into()) } }
fn inventory() -> BTreeSet<String> {
    let mut names = BTreeSet::from([CA.to_owned()]);
    for role in SELFHOST_ROLES { names.insert(role.cert_file.into()); names.insert(role.token_file.into()); }
    names
}
fn metadata(bytes: &[u8]) -> Result<()> {
    require(bytes.len() <= 8192 && bytes.is_ascii())?;
    // Typed structs reject duplicate fields, including nested role fields.
    let value: Metadata = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    require(value.schema == "marty.selfhost-disposable-tls-keys/v1" && value.roles.len() == 16)?;
    let mut roles = BTreeSet::new();
    for role in value.roles {
        require(role.version == 1 && SELFHOST_ROLES.iter().any(|expected|
            expected.name == role.role && expected.key_name == role.key_name) && roles.insert(role.role))?;
    }
    require(roles == PREFIX_ROLES.iter().map(|(_, role)| role.to_string()).collect())
}
fn open_at(parent: &File, entry: &str, flags: i32, mode: u32) -> Result<File> {
    let entry = CString::new(entry).map_err(|_| REFUSED)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), entry.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, mode) };
    if fd < 0 { Err(REFUSED.into()) } else { Ok(unsafe { File::from_raw_fd(fd) }) }
}
fn private_directory(directory: &File, own: bool) -> Result<()> {
    let m = directory.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir() && m.mode() & 0o7777 == 0o700 && (!own || m.uid() == unsafe { libc::geteuid() }))
}
fn read_file(file: &File, maximum: u64, owner: u32, mode: u32) -> Result<Vec<u8>> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(m.is_file() && m.uid() == owner && m.nlink() == 1 && m.mode() & 0o7777 == mode && m.len() > 0 && m.len() <= maximum)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes).map_err(|_| REFUSED)?;
    require(bytes.len() as u64 == m.len())?;
    Ok(bytes)
}
fn bundle_text(bundle: &Path, name: &str, maximum: u64) -> Result<String> {
    let path = bundle.join(name);
    require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|_| REFUSED)?;
    let bytes = read_file(&file, maximum, unsafe { libc::geteuid() }, 0o644)?;
    require(bytes.is_ascii())?;
    String::from_utf8(bytes).map_err(|_| REFUSED.into())
}
fn render(bundle: &Path) -> Result<String> {
    render_text(&bundle_text(bundle, ".env.selfhost.production.example", 16384)?,
        &bundle_text(bundle, "docker-compose.yml", 131072)?)
}
fn render_text(example: &str, compose: &str) -> Result<String> {
    let assignment = regex::Regex::new(r"\A([A-Z][A-Z0-9_]*_TLS_KMS_KEY_(?:NAME|VERSION))=([^\r\n]*)\z").unwrap();
    let required = regex::Regex::new(r"\A\$\{([A-Z][A-Z0-9_]*_TLS_KMS_KEY_(?:NAME|VERSION)):\?[^}]*\}\z").unwrap();
    let variables = regex::Regex::new(r"\$\{[^}]*\}").unwrap();
    let mut values = BTreeMap::new();
    for line in example.lines().filter(|line| line.contains("_TLS_KMS_KEY_") && !line.trim_start().starts_with('#')) {
        let captures = assignment.captures(line).ok_or(REFUSED)?;
        require(values.insert(captures[1].to_owned(), captures[2].to_owned()).is_none())?;
    }
    let mut expected = BTreeMap::new();
    for (prefix, name) in PREFIX_ROLES {
        let role = SELFHOST_ROLES.iter().find(|r| r.name == name).ok_or(REFUSED)?;
        expected.insert(format!("{prefix}_TLS_KMS_KEY_NAME"), role.key_name.to_owned());
        expected.insert(format!("{prefix}_TLS_KMS_KEY_VERSION"), "1".into());
    }
    require(values == expected)?;
    let mut references = BTreeSet::new();
    for variable in variables.find_iter(compose).filter(|v| v.as_str().contains("_TLS_KMS_KEY_")) {
        let capture = required.captures(variable.as_str()).ok_or(REFUSED)?;
        require(references.insert(capture[1].to_owned()))?;
    }
    require(references == expected.keys().cloned().collect())?;
    Ok(expected.into_iter().map(|(key, value)| format!("{key}={value}\n")).collect())
}
fn absent_destinations(secrets: &File) -> Result<()> {
    private_directory(secrets, true)?;
    for name in inventory() {
        let name = CString::new(name).unwrap();
        let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstatat(secrets.as_raw_fd(), name.as_ptr(), m.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        require(result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))?;
    }
    Ok(())
}
/// Must run before remote mutations; refuses any previous/partial target set.
pub fn preflight(secrets: &File, bundle: &Path) -> Result<()> {
    absent_destinations(secrets)?;
    render(bundle)?;
    Ok(())
}
fn payloads(output: &File, owner: u32, mode: u32, root_token: Option<&str>) -> Result<BTreeMap<String, Vec<u8>>> {
    private_directory(output, false)?;
    let names = std::fs::read_dir(format!("/proc/self/fd/{}", output.as_raw_fd())).map_err(|_| REFUSED)?
        .map(|e| e.map_err(|_| REFUSED).and_then(|e| e.file_name().into_string().map_err(|_| REFUSED)))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let mut expected = inventory(); expected.insert(METADATA_FILE.into());
    require(names == expected)?;
    let mut result = BTreeMap::new(); let mut tokens = BTreeSet::new();
    for name in expected {
        let file = open_at(output, &name, libc::O_RDONLY, 0)?;
        let bytes = read_file(&file, if name == METADATA_FILE {8192} else {65536}, owner, mode)?;
        require(bytes.is_ascii())?;
        let value = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
        require(!value.contains("PRIVATE KEY") && !value.contains('\0')
            && root_token.is_none_or(|root| !value.contains(root)))?;
        if name == METADATA_FILE { metadata(&bytes)?; }
        else if name == CA || SELFHOST_ROLES.iter().any(|role| role.cert_file == name) {
            // Decode real X.509 DER rather than accepting only PEM delimiters.
            Certificate::from_pem(&bytes).map_err(|_| REFUSED)?;
        } else {
            require((20..=2048).contains(&value.len()) && !value.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                && root_token.is_none_or(|root| value != root) && tokens.insert(value.to_owned()))?;
        }
        result.insert(name, bytes);
    }
    Ok(result)
}
/// Host acceptance: only the stopped, inspected helper's public/scoped output.
/// Original output stays intact. A partial transfer requires recovery, not retry.
pub fn validate_and_transfer(output: &File, secrets: &File, bundle: &Path) -> Result<ValidatedTlsOutputs> {
    private_directory(output, true)?;
    preflight(secrets, bundle)?;
    let a = output.metadata().map_err(|_| REFUSED)?; let b = secrets.metadata().map_err(|_| REFUSED)?;
    require((a.dev(), a.ino()) != (b.dev(), b.ino()))?;
    let values = payloads(output, 0, 0o444, None)?;
    let env_fragment = render(bundle)?;
    transfer(secrets, &values)?;
    Ok(ValidatedTlsOutputs { metadata_bytes: values[METADATA_FILE].clone(), env_fragment, outputnames: inventory().into_iter().collect() })
}
fn transfer(secrets: &File, values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for name in inventory() {
        let mut file = open_at(secrets, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        secrets.sync_all().map_err(|_| REFUSED)?;
        file.write_all(&values[&name]).and_then(|_| file.sync_all()).map_err(|_| REFUSED)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
        file.sync_all().and_then(|_| secrets.sync_all()).map_err(|_| REFUSED)?;
    }
    Ok(())
}
/// Fixed container-only finalizer after successful producer exit. Production
/// bootstrap creates root0600 files; authenticate the complete set before making
/// public certificates and scoped tokens readable by the host installation owner.
pub fn finalize_container_outputs(output: &File, root_token: &str) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0 && root_token.len() >= 20 && root_token.is_ascii()
        && !root_token.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()))?;
    let values = payloads(output, 0, 0o600, Some(root_token))?;
    for (name, expected) in &values {
        let file = open_at(output, name, libc::O_RDONLY, 0)?;
        require(read_file(&file, 65536, 0, 0o600)? == *expected)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
        file.sync_all().and_then(|_| output.sync_all()).map_err(|_| REFUSED)?;
    }
    Ok(inventory().len())
}
/// Internal CLI entrypoint; accepts no caller-selected paths or secret arguments.
pub fn finalize() -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    let token_path = Path::new("/input/root.token");
    let output_path = Path::new("/output");
    require(token_path.canonicalize().map_err(|_| REFUSED)? == token_path
        && output_path.canonicalize().map_err(|_| REFUSED)? == output_path)?;
    let token = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(token_path).map_err(|_| REFUSED)?;
    let bytes = read_file(&token, 4096, 0, 0o400)?;
    let root_token = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?.trim();
    let output = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output_path).map_err(|_| REFUSED)?;
    finalize_container_outputs(&output, root_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn metadata_fixture() -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":"marty.selfhost-disposable-tls-keys/v1",
            "roles":SELFHOST_ROLES.iter().map(|r|json!({"role":r.name,"key_name":r.key_name,"version":1})).collect::<Vec<_>>() })).unwrap()
    }
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn fixture(path: &Path) {
        let cert = include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");
        for (index, name) in inventory().into_iter().enumerate() {
            let bytes = if name == CA || name.ends_with("_cert") { cert.to_vec() }
                else { format!("scoped-token-{index}-{}", "a".repeat(30)).into_bytes() };
            std::fs::write(path.join(&name), bytes).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(path.join(METADATA_FILE), metadata_fixture()).unwrap();
        std::fs::set_permissions(path.join(METADATA_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn metadata_refuses_duplicates_missing_roles_and_wrong_custody_version() {
        let bytes = metadata_fixture(); metadata(&bytes).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(metadata(text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1).as_bytes()).is_err());
        assert!(metadata(text.replacen("\"schema\":", "\"schema\":\"ignored\",\"schema\":", 1).as_bytes()).is_err());
        for mutation in ["missing", "duplicate-role", "version", "wrong-key", "extra"] {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            match mutation {
                "missing" => { value["roles"].as_array_mut().unwrap().pop(); }
                "duplicate-role" => value["roles"][1] = value["roles"][0].clone(),
                "version" => value["roles"][0]["version"] = json!(2),
                "wrong-key" => value["roles"][0]["key_name"] = json!("foreign-key"),
                _ => value["roles"][0]["private_key"] = json!("forbidden"),
            }
            assert!(metadata(&serde_json::to_vec(&value).unwrap()).is_err(), "accepted {mutation}");
        }
    }
    #[test]
    fn shipped_wiring_accepts_actual_files_and_refuses_swaps_and_weak_references() {
        let example = include_str!("../../../../.env.selfhost.production.example");
        // Source of the rendered bundle's docker-compose.yml; its KMS required
        // substitutions survive the packager's no-interpolate rendering.
        let compose = include_str!("../../../../docker-compose.selfhost.prod.yml");
        let fragment = render_text(example, compose).unwrap();
        assert_eq!(fragment.lines().count(), 32);
        assert!(fragment.contains("GATEWAY_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client\n"));
        assert!(render_text(&example.replace("GATEWAY_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client", "GATEWAY_TLS_KMS_KEY_NAME=workload-tls-auth-client"), compose).is_err());
        assert!(render_text(example, &compose.replace("GATEWAY_TLS_KMS_KEY_NAME:?", "GATEWAY_TLS_KMS_KEY_NAME:-")).is_err());
        assert!(render_text(&format!("{example}\nGATEWAY_TLS_KMS_KEY_VERSION=1\n"), compose).is_err());
    }
    #[test]
    fn output_acceptance_decodes_certificates_and_refuses_private_or_root_material() {
        let root = root(); fixture(root.path());
        let dir = File::open(root.path()).unwrap(); let owner = unsafe { libc::geteuid() };
        let root_token = "root-token-never-for-workloads";
        assert_eq!(payloads(&dir, owner, 0o600, Some(root_token)).unwrap().len(), 34);
        let target = root.path().join(SELFHOST_ROLES[0].token_file);
        let original = std::fs::read(&target).unwrap();
        for bad in [b"-----BEGIN PRIVATE KEY-----".as_slice(), root_token.as_bytes(), b"short", b"token with whitespace exceeding minimum"] {
            std::fs::write(&target, bad).unwrap();
            assert!(payloads(&dir, owner, 0o600, Some(root_token)).is_err());
        }
        std::fs::write(&target, original).unwrap();
        std::fs::write(root.path().join(CA), b"-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----").unwrap();
        assert!(payloads(&dir, owner, 0o600, Some(root_token)).is_err());
    }
    #[test]
    fn output_refuses_links_modes_extra_files_and_duplicate_tokens() {
        for mutation in ["symlink", "hardlink", "mode", "extra", "shared-token"] {
            let root = root(); fixture(root.path());
            let target = root.path().join(SELFHOST_ROLES[0].token_file);
            match mutation {
                "symlink" => { std::fs::remove_file(&target).unwrap(); symlink(root.path().join(SELFHOST_ROLES[1].token_file), &target).unwrap(); }
                "hardlink" => { std::fs::remove_file(&target).unwrap(); std::fs::hard_link(root.path().join(SELFHOST_ROLES[1].token_file), &target).unwrap(); }
                "mode" => std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap(),
                "extra" => std::fs::write(root.path().join("unexpected"), b"data").unwrap(),
                _ => std::fs::write(&target, std::fs::read(root.path().join(SELFHOST_ROLES[1].token_file)).unwrap()).unwrap(),
            }
            assert!(payloads(&File::open(root.path()).unwrap(), unsafe { libc::geteuid() }, 0o600, None).is_err(), "accepted {mutation}");
        }
    }
    #[test]
    fn transfer_is_exclusive_readonly_and_preserves_originals_and_partial_results() {
        let source = root(); fixture(source.path()); let target = root();
        let values = payloads(&File::open(source.path()).unwrap(), unsafe { libc::geteuid() }, 0o600, None).unwrap();
        let dir = File::open(target.path()).unwrap();
        absent_destinations(&dir).unwrap();
        transfer(&dir, &values).unwrap();
        for name in inventory() {
            assert_eq!(std::fs::read(target.path().join(&name)).unwrap(), values[&name]);
            assert_eq!(std::fs::metadata(target.path().join(&name)).unwrap().mode() & 0o7777, 0o444);
            assert!(source.path().join(name).exists());
        }
        assert!(transfer(&dir, &values).is_err()); assert!(absent_destinations(&dir).is_err());
        let partial = root(); let names: Vec<_> = inventory().into_iter().collect();
        std::fs::write(partial.path().join(&names[1]), b"existing").unwrap();
        assert!(transfer(&File::open(partial.path()).unwrap(), &values).is_err());
        assert_eq!(std::fs::read(partial.path().join(&names[0])).unwrap(), values[&names[0]]);
        assert_eq!(std::fs::read(partial.path().join(&names[1])).unwrap(), b"existing");
    }
}
