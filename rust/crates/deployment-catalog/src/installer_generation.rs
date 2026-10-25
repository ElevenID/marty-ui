//! Fixed-path orphan leaf generation; not activation, root retirement or readiness.
//! Caller must own/admit the container, image, executable and readonly mounts.
//! Pending precedes login: a lost login/mint response may leave unknown authority.
//! Known login tokens are self-revoked, but orphan leaves intentionally survive.
#![cfg(target_os = "linux")]
use crate::{
    activation_preflight, approle, generation, installer_renewal_bootstrap as fs,
    keycloak_provision, operator_http,
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Orphan generation input refused";
const RECOVERY: &str = "Orphan generation incomplete; retain owned helper and surviving outputs; unknown orphan leaves may remain";
const EXECUTABLE: &str = "/usr/local/bin/marty-passport-tls-bootstrap";
const IDENTITY: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialKeycloak {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    container_name: String,
    network_id: String,
    image: String,
    nonce: String,
    outputs: Vec<String>,
    container_removed: bool,
    installation_ready: bool,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
pub(crate) fn original_nonce(bytes: &[u8], owner: &str) -> Result<String> {
    let receipt: InitialKeycloak = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    require(
        receipt.schema == "elevenid.installer-keycloak/v1"
            && receipt.installation_id == owner
            && receipt.container_removed
            && !receipt.installation_ready
            && hex(&receipt.nonce, 12)
            && hex(&receipt.container_id, 64)
            && hex(&receipt.network_id, 64)
            && !receipt.engine_id.is_empty()
            && receipt.engine_id.len() <= 128
            && receipt.container_name
                == format!("marty-install-{}-keycloak-inputs", owner.replace('-', ""))
            && receipt
                .image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:")
                .is_some_and(|s| hex(s, 64))
            && receipt.outputs.len() == 7
            && receipt.outputs.into_iter().collect::<BTreeSet<_>>()
                == crate::installer_keycloak_bridge::OUTPUTS
                    .map(String::from)
                    .into(),
    )?;
    Ok(receipt.nonce)
}
fn identity_snapshot(dir: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(fs::names(dir)? == IDENTITY.map(String::from).into())?;
    let owner = dir.metadata().map_err(|_| REFUSED)?.uid();
    IDENTITY
        .into_iter()
        .map(|name| Ok((name.into(), fs::entry(dir, name, &[owner], &[0o600], true)?)))
        .collect()
}
fn binding(path: &Path, held: &File, root: bool, readonly: bool) -> Result<()> {
    let now = fs::directory(path, root, readonly)?
        .metadata()
        .map_err(|_| REFUSED)?;
    let old = held.metadata().map_err(|_| REFUSED)?;
    require(
        (now.dev(), now.ino(), now.uid(), now.gid(), now.mode())
            == (old.dev(), old.ino(), old.uid(), old.gid(), old.mode()),
    )
}
fn write(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
    write_open(dir, name, bytes).map(drop)
}
fn write_open(dir: &File, name: &str, bytes: &[u8]) -> Result<File> {
    require(
        !name.contains('/')
            && !name.contains('\\')
            && name != "."
            && name != ".."
            && !bytes.is_empty()
            && bytes.len() <= 65536
            && bytes.is_ascii()
            && !bytes.contains(&0)
            && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
    )?;
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
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| dir.sync_all())
        .map_err(|_| RECOVERY.to_string())?;
    Ok(file)
}
pub(crate) fn hashes(values: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(name, value)| (name.clone(), format!("{:x}", Sha256::digest(value))))
        .collect()
}

fn producer_outputs(tls: &File, keycloak: &File) -> Result<()> {
    let keycloak_names: BTreeSet<String> = crate::installer_keycloak_bridge::OUTPUTS
        .map(String::from)
        .into();
    let mut tls_names: BTreeSet<String> = fs::current_inputs()
        .difference(&keycloak_names)
        .cloned()
        .collect();
    tls_names.insert(crate::installer_tls_outputs::METADATA_FILE.into());
    for (dir, expected) in [(tls, tls_names), (keycloak, keycloak_names)] {
        require(fs::names(dir)? == expected)?;
        for name in expected {
            fs::entry(dir, &name, &[0], &[0o600], false)?;
        }
    }
    Ok(())
}

struct OwnedChild {
    child: Child,
    reaped: bool,
}
impl OwnedChild {
    fn kill(&self) {
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
    }
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        require(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
        )?;
        Ok(unsafe { info.si_pid() } != 0)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill();
            let _ = self.child.wait();
        }
    }
}
fn run_child(
    executable: &Path,
    env: &BTreeMap<String, String>,
    cwd: &Path,
    timeout: Duration,
) -> Result<()> {
    require(timeout > Duration::ZERO && timeout <= Duration::from_secs(600))?;
    let child = Command::new(executable)
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| RECOVERY)?;
    let mut owned = OwnedChild {
        child,
        reaped: false,
    };
    let deadline = Instant::now() + timeout;
    while !owned.exited()? {
        if Instant::now() >= deadline {
            return Err(RECOVERY.into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Reserve leader PID until all same-group descendants are killed, even on success.
    owned.kill();
    let status = owned.child.wait().map_err(|_| RECOVERY)?;
    owned.reaped = true;
    if status.success() {
        Ok(())
    } else {
        Err(RECOVERY.into())
    }
}
fn workload_environment(owner: &str, output: &Path) -> BTreeMap<String, String> {
    [
        ("PATH", "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME", output.to_string_lossy().into_owned()),
        ("LANG", "C".into()),
        ("BAO_ADDR", "https://openbao:8200".into()),
        ("BAO_CACERT", "/input/ca.crt".into()),
        (
            "BAO_RENEWAL_TOKEN_FILE",
            output
                .join("authority.token")
                .to_string_lossy()
                .into_owned(),
        ),
        ("MARTY_TLS_BOOTSTRAP_PROFILE", "selfhost-renew".into()),
        ("MARTY_SELFHOST_WORKLOAD_PKI_MOUNT", "workload-pki".into()),
        (
            "MARTY_SELFHOST_PROJECT",
            format!("marty-selfhost-disposable-{}", owner.replace('-', "")),
        ),
        (
            "SELFHOST_TLS_OUTPUT_DIR",
            output.join("tls").to_string_lossy().into_owned(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}
fn workload_executable() -> Result<()> {
    let path = Path::new(EXECUTABLE);
    require(path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| REFUSED)?;
    let metadata = file.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && metadata.len() > 0
            && metadata.len() <= 512 * 1024 * 1024,
    )?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(unsafe { libc::fstatvfs(file.as_raw_fd(), info.as_mut_ptr()) } == 0)?;
    require(unsafe { info.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}
async fn retire(bao: &OpenBaoHttp, token: &str) -> Result<()> {
    operator_http::request(
        bao,
        Method::POST,
        "auth/token/revoke-self",
        Some(&json!({})),
        Some(token),
    )
    .await
    .map_err(|_| RECOVERY)?;
    let response = operator_http::builder(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(token),
    )
    .send()
    .await
    .map_err(|_| RECOVERY)?;
    require(response.status() == StatusCode::FORBIDDEN)
}

/// Fixed mounts only; returns40 public certificate/scoped-token files staged in
/// /output/generation. No host delivery, activation, old-token revocation or root
/// retirement. Caller must preserve this entire directory on every failure.
pub async fn provision(owner: &str) -> Result<usize> {
    provision_at(owner, Path::new("/output")).await
}

async fn provision_at(owner: &str, output_path: &Path) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    fs::validate_id(owner)?;
    let current = fs::directory(Path::new("/input/current"), false, true)?;
    let before = fs::current(&current)?;
    let identity = fs::directory(Path::new("/input/identity"), false, true)?;
    let credentials = identity_snapshot(&identity)?;
    let input_owner = current.metadata().map_err(|_| REFUSED)?.uid();
    let identity_owner = identity.metadata().map_err(|_| REFUSED)?.uid();
    require(identity_owner == 0 || identity_owner == input_owner)?;
    let receipt = fs::input(
        Path::new("/input/keycloak-receipt.json"),
        8192,
        &[0, input_owner],
        &[0o600],
    )?;
    let nonce = original_nonce(&receipt, owner)?;
    let ca = fs::input(
        Path::new("/input/ca.crt"),
        65536,
        &[0, 100],
        &[0o444, 0o644],
    )?;
    let output = fs::directory(output_path, true, false)?;
    require(fs::names(&output)?.is_empty())?;
    workload_executable()?;
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new("/input/ca.crt")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSED)?;
    fs::receipt(
        &output,
        "pending.json",
        &json!({"schema":"elevenid.installer-generation-intent/v1",
        "installation_id":owner,"nonce":nonce,"input_sha256":hashes(&before),"identity_sha256":hashes(&credentials),
        "keycloak_receipt_sha256":format!("{:x}",Sha256::digest(&receipt)),"root_retired":false,"activated":false}),
    )?;
    let outcome: Result<usize> = async {
        // Login may mint before returning an error. No automatic retry is safe.
        let login = approle::login(&bao,approle::Role::Renewal,Path::new("/input/identity"),&json!({})).await.map_err(|_| RECOVERY)?;
        let token = login["token"].as_str().ok_or(RECOVERY)?;
        let produced: Result<()> = async {
            binding(Path::new("/input/current"),&current,false,true)?;
            binding(Path::new("/input/identity"),&identity,false,true)?;
            binding(output_path,&output,true,false)?;
            require(fs::current(&current)? == before && identity_snapshot(&identity)? == credentials)?;
            require((20..=256).contains(&token.len()) && token.bytes().all(|v|v.is_ascii_graphic()))?;
            activation_preflight::authority(&bao,token,false).await.map_err(|_| RECOVERY)?;
            write(&output,"authority.token",token.as_bytes())?;
            let tls = fs::child(&output,"tls")?;
            let keycloak = fs::child(&output,"keycloak")?;
            let candidate = fs::child(&output,"generation")?;
            run_child(Path::new(EXECUTABLE),&workload_environment(owner,output_path),output_path,Duration::from_secs(600))?;
            let values = keycloak_provision::provision(&bao,&json!({"token":token,"renew":true,"pki_mount":"keycloak-pki","nonce":nonce})).await.map_err(|_| RECOVERY)?;
            let values = values.as_object().ok_or(RECOVERY)?;
            require(values.keys().cloned().collect::<BTreeSet<_>>() == crate::installer_keycloak_bridge::OUTPUTS.map(String::from).into())?;
            for (name,value) in values { write(&keycloak,name,value.as_str().ok_or(RECOVERY)?.as_bytes())?; }
            binding(&output_path.join("tls"),&tls,true,false)?;
            binding(&output_path.join("keycloak"),&keycloak,true,false)?;
            binding(&output_path.join("generation"),&candidate,true,false)?;
            producer_outputs(&tls,&keycloak)?;
            require(generation::stage(Path::new("/input/current"),&output_path.join("tls"),&output_path.join("keycloak"),&output_path.join("generation"),false).map_err(|_| RECOVERY)? == 40)?;
            let mut next = BTreeMap::new();
            require(fs::names(&candidate)? == fs::current_inputs())?;
            for name in fs::current_inputs() {
                next.insert(name.clone(),fs::entry(&candidate,&name,&[0],&[0o444],false)?);
            }
            fs::validate_current(&next)?;
            require(!next.values().any(|value|value.windows(token.len()).any(|part|part == token.as_bytes())))?;
            let checks = json!({"token":token,"old":"/input/current","new":output_path.join("generation"),
                "minimum_ttl":3600,"require_orphan_new":true,"require_orphan_old":false,"replacement":null,"retiring":false});
            activation_preflight::tokens(&bao,&checks).await.map_err(|_| RECOVERY)?;
            activation_preflight::certificates(&bao,&checks).await.map_err(|_| RECOVERY)?;
            require(generation::verify(Path::new("/input/current"),&output_path.join("generation"),false,false).map_err(|_| RECOVERY)? == (40,39))?;
            tls.sync_all().and_then(|_|keycloak.sync_all()).and_then(|_|candidate.sync_all()).map_err(|_| RECOVERY)?;
            fs::receipt(&output,"validated.json",&json!({"schema":"elevenid.installer-generation-validation/v1","installation_id":owner,
                "output_sha256":hashes(&next),"orphan_tokens":21,"remote_key_version":1,"ca_changed":false}))?;
            Ok(())
        }.await;
        // Execute even when producer/validation fails. Revocation does not
        // revoke orphan leaves or recover tokens hidden by failed responses.
        retire(&bao,token).await?;
        produced?;
        binding(Path::new("/input/current"),&current,false,true)?;
        binding(Path::new("/input/identity"),&identity,false,true)?;
        binding(output_path,&output,true,false)?;
        require(fs::current(&current)? == before && identity_snapshot(&identity)? == credentials
            && fs::input(Path::new("/input/ca.crt"),65536,&[0,100],&[0o444,0o644])? == ca
            && fs::input(Path::new("/input/keycloak-receipt.json"),8192,&[0,input_owner],&[0o600])? == receipt)?;
        require(fs::names(&output)? == ["pending.json","authority.token","tls","keycloak","generation","validated.json"].map(String::from).into())?;
        fs::receipt(&output,"completed.json",&json!({"schema":"elevenid.installer-generation-result/v1","installation_id":owner,
            "files":40,"changed_files":39,"orphan_tokens":21,"transient_revoked":true,
            "activated":false,"root_retired":false,"ingress_renewal":false,"installation_ready":false}))?;
        Ok(40)
    }.await;
    outcome.map_err(|_| RECOVERY.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationPending {
    schema: String,
    installation_id: String,
    nonce: String,
    input_sha256: BTreeMap<String, String>,
    identity_sha256: BTreeMap<String, String>,
    keycloak_receipt_sha256: String,
    root_retired: bool,
    activated: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationValidated {
    schema: String,
    installation_id: String,
    output_sha256: BTreeMap<String, String>,
    orphan_tokens: u64,
    remote_key_version: u64,
    ca_changed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationCompleted {
    schema: String,
    installation_id: String,
    files: u64,
    changed_files: u64,
    orphan_tokens: u64,
    transient_revoked: bool,
    activated: bool,
    root_retired: bool,
    ingress_renewal: bool,
    installation_ready: bool,
}
pub(crate) struct GenerationProof<'a> {
    pub owner: &'a str,
    pub current: &'a BTreeMap<String, Vec<u8>>,
    pub identity: &'a BTreeMap<String, Vec<u8>>,
    pub keycloak_receipt: &'a [u8],
}
pub(crate) fn validate_records(
    records: &BTreeMap<String, Vec<u8>>,
    outputs: &BTreeMap<String, Vec<u8>>,
    proof: &GenerationProof<'_>,
) -> Result<BTreeMap<String, String>> {
    require(
        records.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == ["pending.json", "validated.json", "completed.json"].into(),
    )?;
    fs::validate_current(proof.current)?;
    fs::validate_current(outputs)?;
    let pending: GenerationPending =
        serde_json::from_slice(&records["pending.json"]).map_err(|_| REFUSED)?;
    let validated: GenerationValidated =
        serde_json::from_slice(&records["validated.json"]).map_err(|_| REFUSED)?;
    let completed: GenerationCompleted =
        serde_json::from_slice(&records["completed.json"]).map_err(|_| REFUSED)?;
    let digests = hashes(outputs);
    require(
        pending.schema == "elevenid.installer-generation-intent/v1"
            && pending.installation_id == proof.owner
            && pending.nonce == original_nonce(proof.keycloak_receipt, proof.owner)?
            && pending.input_sha256 == hashes(proof.current)
            && pending.identity_sha256 == hashes(proof.identity)
            && proof
                .identity
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == IDENTITY.into()
            && pending.keycloak_receipt_sha256
                == format!("{:x}", Sha256::digest(proof.keycloak_receipt))
            && !pending.root_retired
            && !pending.activated,
    )?;
    require(
        validated.schema == "elevenid.installer-generation-validation/v1"
            && validated.installation_id == proof.owner
            && validated.output_sha256 == digests
            && validated.orphan_tokens == 21
            && validated.remote_key_version == 1
            && !validated.ca_changed,
    )?;
    require(
        completed.schema == "elevenid.installer-generation-result/v1"
            && completed.installation_id == proof.owner
            && completed.files == 40
            && completed.changed_files == 39
            && completed.orphan_tokens == 21
            && completed.transient_revoked
            && !completed.activated
            && !completed.root_retired
            && !completed.ingress_renewal
            && !completed.installation_ready,
    )?;
    for (name, value) in outputs {
        require((value == &proof.current[name]) == (name == "workload_identity_ca_cert"))?;
    }
    Ok(digests)
}
fn deliver_copy(dir: &File, name: &str, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> Result<()> {
    require([0o444, 0o600].contains(&mode))?;
    let file = write_open(dir, name, bytes)?;
    let fd = file.as_raw_fd();
    require(unsafe { libc::fchmod(fd, mode) } == 0 && unsafe { libc::fchown(fd, uid, gid) } == 0)?;
    let info = file.metadata().map_err(|_| RECOVERY)?;
    require(
        info.is_file()
            && info.nlink() == 1
            && info.uid() == uid
            && info.gid() == gid
            && info.mode() & 0o7777 == mode,
    )?;
    file.sync_all()
        .and_then(|_| dir.sync_all())
        .map_err(|_| RECOVERY.into())
}
/// Single owned helper transaction, private originals retained under root700.
/// Recipient UID/GID come only from the held host-created /transfer directory.
pub async fn provision_transfer(owner: &str) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    fs::validate_id(owner)?;
    let parent = fs::directory(Path::new("/transfer"), false, false)?;
    let recipient = parent.metadata().map_err(|_| REFUSED)?;
    require(fs::names(&parent)?.is_empty())?;
    fs::receipt(
        &parent,
        "transfer-pending.json",
        &json!({"schema":"elevenid.installer-generation-transfer-intent/v1","installation_id":owner,"activated":false}),
    )?;
    let result: Result<usize> = async {
        let output = fs::child(&parent, "output")?;
        binding(Path::new("/transfer"), &parent, false, false)?;
        binding(Path::new("/transfer/output"), &output, true, false)?;
        provision_at(owner, Path::new("/transfer/output")).await?;
        binding(Path::new("/transfer/output"), &output, true, false)?;
        require(
            fs::names(&output)?
                == [
                    "pending.json",
                    "authority.token",
                    "tls",
                    "keycloak",
                    "generation",
                    "validated.json",
                    "completed.json",
                ]
                .map(String::from)
                .into(),
        )?;
        let current = fs::directory(Path::new("/input/current"), false, true)?;
        let identity = fs::directory(Path::new("/input/identity"), false, true)?;
        let before = fs::current(&current)?;
        let credentials = identity_snapshot(&identity)?;
        let input_owner = current.metadata().map_err(|_| RECOVERY)?.uid();
        let receipt = fs::input(
            Path::new("/input/keycloak-receipt.json"),
            8192,
            &[0, input_owner],
            &[0o600],
        )?;
        let candidate = fs::directory(Path::new("/transfer/output/generation"), true, false)?;
        require(fs::names(&candidate)? == fs::current_inputs())?;
        let mut values = BTreeMap::new();
        for name in fs::current_inputs() {
            values.insert(
                name.clone(),
                fs::entry(&candidate, &name, &[0], &[0o444], false)?,
            );
        }
        let mut records = BTreeMap::new();
        for name in ["pending.json", "validated.json", "completed.json"] {
            records.insert(
                name.into(),
                fs::entry(&output, name, &[0], &[0o600], false)?,
            );
        }
        validate_records(
            &records,
            &values,
            &GenerationProof {
                owner,
                current: &before,
                identity: &credentials,
                keycloak_receipt: &receipt,
            },
        )?;
        let delivered = fs::child(&parent, "delivered")?;
        for (name, value) in &values {
            deliver_copy(
                &delivered,
                name,
                value,
                0o444,
                recipient.uid(),
                recipient.gid(),
            )?;
        }
        for (name, value) in &records {
            deliver_copy(
                &delivered,
                name,
                value,
                0o600,
                recipient.uid(),
                recipient.gid(),
            )?;
        }
        binding(Path::new("/transfer"), &parent, false, false)?;
        fs::deliver_directory(&delivered, &parent, recipient.uid(), recipient.gid())?;
        binding(Path::new("/transfer"), &parent, false, false)?;
        Ok(40)
    }
    .await;
    result.map_err(|_| RECOVERY.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const OWNER: &str = "2e052c77-efe8-44c6-9421-9ef15fe8ee7c";
    fn private() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn receipt() -> Value {
        json!({"schema":"elevenid.installer-keycloak/v1","installation_id":OWNER,
        "engine_id":"engine","container_id":"a".repeat(64),"container_name":format!("marty-install-{}-keycloak-inputs",OWNER.replace('-',"")),
        "network_id":"b".repeat(64),"image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}","c".repeat(64)),
        "nonce":"0123456789ab","outputs":crate::installer_keycloak_bridge::OUTPUTS,"container_removed":true,"installation_ready":false})
    }
    #[test]
    fn nonce_requires_original_closed_owned_removed_receipt() {
        assert_eq!(
            original_nonce(&serde_json::to_vec(&receipt()).unwrap(), OWNER).unwrap(),
            "0123456789ab"
        );
        for (field, value) in [
            ("nonce", json!("new-nonce")),
            ("installation_id", json!(uuid::Uuid::new_v4().to_string())),
            ("container_removed", json!(false)),
            ("installation_ready", json!(true)),
            ("extra", json!(1)),
            ("outputs", json!([])),
        ] {
            let mut v = receipt();
            v[field] = value;
            assert!(original_nonce(&serde_json::to_vec(&v).unwrap(), OWNER).is_err());
        }
    }
    #[test]
    fn private_output_is_exclusive_and_no_link_or_key_material() {
        let temp = private();
        let dir = File::open(temp.path()).unwrap();
        write(&dir, "token", b"synthetic-token").unwrap();
        assert_eq!(
            std::fs::metadata(temp.path().join("token")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(write(&dir, "token", b"overwrite").is_err());
        symlink("token", temp.path().join("link")).unwrap();
        assert!(write(&dir, "link", b"overwrite").is_err());
        assert!(write(&dir, "../escape", b"x").is_err());
        assert!(write(&dir, "key", b"PRIVATE KEY").is_err());
        assert_eq!(
            std::fs::read(temp.path().join("token")).unwrap(),
            b"synthetic-token"
        );
    }
    #[test]
    fn environment_has_only_fixed_scoped_renewal_authority() {
        let env = workload_environment(OWNER, Path::new("/output"));
        assert_eq!(env["MARTY_TLS_BOOTSTRAP_PROFILE"], "selfhost-renew");
        assert_eq!(
            env["MARTY_SELFHOST_PROJECT"],
            "marty-selfhost-disposable-2e052c77efe844c694219ef15fe8ee7c"
        );
        assert!(!env
            .keys()
            .any(|k| k.contains("ROOT") || k.contains("PROXY")));
        assert!(env.values().all(|v| !v.contains("secret-token")));
    }
    fn script(root: &Path, body: &str) -> std::path::PathBuf {
        let path = root.join(format!("child-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn real_child_timeout_and_failure_are_redacted_and_success_cancels_descendants() {
        let temp = private();
        let env = BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]);
        let child = script(temp.path(), "printf secret >&2; sleep 30 & wait");
        let started = Instant::now();
        let error = run_child(&child, &env, temp.path(), Duration::from_millis(100)).unwrap_err();
        assert!(!error.contains("secret"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let child = script(temp.path(), "sleep 30 & echo $! > descendant; exit 0");
        run_child(&child, &env, temp.path(), Duration::from_secs(2)).unwrap();
        let pid = std::fs::read_to_string(temp.path().join("descendant")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()));
            if match &observed {
                Err(_) => true,
                Ok(stat) => stat.split_whitespace().nth(2) == Some("Z"),
            } {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned descendant survived cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn readonly_identity_and_input_paths_are_mandatory() {
        let temp = private();
        for name in IDENTITY {
            std::fs::write(temp.path().join(name), b"synthetic").unwrap();
            std::fs::set_permissions(
                temp.path().join(name),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(fs::directory(temp.path(), false, true).is_err());
        assert!(identity_snapshot(&File::open(temp.path()).unwrap()).is_err());
        let held = File::open(temp.path()).unwrap();
        assert!(binding(temp.path(), &held, false, false).is_ok());
        let other = private();
        assert!(binding(other.path(), &held, false, false).is_err());
    }
    #[test]
    fn delivery_keeps_exclusive_fd_private_and_refuses_existing_links() {
        let temp = private();
        let dir = File::open(temp.path()).unwrap();
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        for (name, mode) in [("candidate", 0o444), ("receipt", 0o600)] {
            deliver_copy(&dir, name, b"synthetic", mode, uid, gid).unwrap();
            let info = std::fs::metadata(temp.path().join(name)).unwrap();
            assert_eq!(
                (info.mode() & 0o7777, info.uid(), info.gid(), info.nlink()),
                (mode, uid, gid, 1)
            );
            assert!(deliver_copy(&dir, name, b"replacement", mode, uid, gid).is_err());
            assert_eq!(std::fs::read(temp.path().join(name)).unwrap(), b"synthetic");
        }
        symlink(temp.path().join("receipt"), temp.path().join("alias")).unwrap();
        assert!(deliver_copy(&dir, "alias", b"replacement", 0o444, uid, gid).is_err());
        assert_eq!(
            std::fs::metadata(temp.path().join("receipt"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(deliver_copy(&dir, "../escape", b"synthetic", 0o600, uid, gid).is_err());
    }
    #[test]
    fn delivered_proofs_bind_every_generation_and_reject_activation_claims() {
        let current: BTreeMap<String, Vec<u8>> = fs::current_inputs()
            .into_iter()
            .map(|name| {
                let bytes = if name.ends_with("_token") {
                    format!("old-synthetic-credential-{name}")
                } else {
                    format!("-----BEGIN CERTIFICATE-----\nold-{name}\n-----END CERTIFICATE-----")
                };
                (name, bytes.into_bytes())
            })
            .collect();
        let outputs: BTreeMap<String, Vec<u8>> = current
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    if name == "workload_identity_ca_cert" {
                        bytes.clone()
                    } else {
                        String::from_utf8(bytes.clone())
                            .unwrap()
                            .replace("old-", "new-")
                            .into_bytes()
                    },
                )
            })
            .collect();
        let identity = IDENTITY
            .into_iter()
            .map(|name| (name.into(), format!("identity-{name}").into_bytes()))
            .collect();
        let receipt = serde_json::to_vec(&receipt()).unwrap();
        let proof = GenerationProof {
            owner: OWNER,
            current: &current,
            identity: &identity,
            keycloak_receipt: &receipt,
        };
        let records: BTreeMap<String, Vec<u8>> = [
            ("pending.json", json!({"schema":"elevenid.installer-generation-intent/v1","installation_id":OWNER,"nonce":"0123456789ab","input_sha256":hashes(&current),"identity_sha256":hashes(&identity),"keycloak_receipt_sha256":format!("{:x}",Sha256::digest(&receipt)),"root_retired":false,"activated":false})),
            ("validated.json", json!({"schema":"elevenid.installer-generation-validation/v1","installation_id":OWNER,"output_sha256":hashes(&outputs),"orphan_tokens":21,"remote_key_version":1,"ca_changed":false})),
            ("completed.json", json!({"schema":"elevenid.installer-generation-result/v1","installation_id":OWNER,"files":40,"changed_files":39,"orphan_tokens":21,"transient_revoked":true,"activated":false,"root_retired":false,"ingress_renewal":false,"installation_ready":false}))
        ].into_iter().map(|(name, value)| (name.into(), serde_json::to_vec(&value).unwrap())).collect();
        assert_eq!(
            validate_records(&records, &outputs, &proof).unwrap(),
            hashes(&outputs)
        );
        for (record, field, value) in [
            ("pending.json", "identity_sha256", json!({})),
            ("pending.json", "input_sha256", json!({})),
            (
                "pending.json",
                "keycloak_receipt_sha256",
                json!("f".repeat(64)),
            ),
            ("validated.json", "output_sha256", json!({})),
            ("validated.json", "remote_key_version", json!(2)),
            ("completed.json", "transient_revoked", json!(false)),
            ("completed.json", "activated", json!(true)),
            ("completed.json", "unknown", json!(false)),
        ] {
            let mut altered = records.clone();
            let mut object: Value = serde_json::from_slice(&altered[record]).unwrap();
            object[field] = value;
            altered.insert(record.into(), serde_json::to_vec(&object).unwrap());
            assert!(
                validate_records(&altered, &outputs, &proof).is_err(),
                "accepted {record}/{field}"
            );
        }
        assert!(validate_records(&records, &current, &proof).is_err());
    }
}
