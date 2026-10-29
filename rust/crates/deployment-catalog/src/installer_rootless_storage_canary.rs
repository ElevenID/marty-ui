//! Candidate-only rootless storage probe. Every Docker object and host inode
//! belongs to this fresh installation. A refusal preserves evidence and leaves
//! provisioning stopped; no path is adopted or cleaned by name alone.
#![cfg(target_os = "linux")]

use crate::{
    installer_runtime::DockerRunner,
    installer_state::{ExecutionScope, InstallerState, LockedInspection, LockedMaintenance, Phase},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "rootless storage canary refused; preserve installation and probe evidence";
const INTENT: &str = "rootless-canary-intent.json";
const CREATED: &str = "rootless-canary-created.json";
const TRANSITION_CONTAINER: &str = "rootless-canary-transition-container.json";
const RESTORE_CONTAINER: &str = "rootless-canary-restore-container.json";
const START_INTENT: &str = "rootless-canary-start-intent.json";
const FOREIGN: &str = "rootless-canary-foreign-observed.json";
const RESTORE_INTENT: &str = "rootless-canary-restore-intent.json";
const RESULT: &str = "rootless-canary-result.json";
const REMOVE_INTENT: &str = "rootless-canary-remove-intent.json";
const COMPLETE: &str = "rootless-canary-complete.json";

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn path_text(path: &Path) -> Result<&str> {
    let value = path.to_str().ok_or(REFUSED)?;
    require(path.is_absolute() && !value.chars().any(|c| c.is_control() || c == ','))?;
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mount: u64,
}

fn mount_id(file: &File) -> Result<u64> {
    // fdinfo is used rather than st_dev: bind mounts can have the same device.
    let proc = File::open("/proc/self/fdinfo").map_err(|_| REFUSED)?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(proc.as_raw_fd(), &mut fs) } == 0 && fs.f_type as i64 == 0x9fa0,
    )?;
    let mut bytes = Vec::new();
    let held = open_at(
        proc.as_raw_fd(),
        &file.as_raw_fd().to_string(),
        libc::O_RDONLY,
        0,
    )?;
    held.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() <= 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let raw = ids.next().ok_or(REFUSED)?.trim();
    require(ids.next().is_none() && !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()))?;
    let value = raw.parse::<u64>().map_err(|_| REFUSED)?;
    require(value != 0)?;
    Ok(value)
}
fn stamp(file: &File) -> Result<Stamp> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir() && m.mode() & 0o7777 == 0o700)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        mount: mount_id(file)?,
    })
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
fn open_dir(parent: &File, name: &str) -> Result<File> {
    open_at(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
}
fn path_dir(parent: &File, name: &str) -> Result<File> {
    open_at(
        parent.as_raw_fd(),
        name,
        libc::O_PATH | libc::O_DIRECTORY,
        0,
    )
}
fn mkdir(parent: &File, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    require(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0)?;
    parent.sync_all().map_err(|_| REFUSED)?;
    let child = open_dir(parent, name.to_str().map_err(|_| REFUSED)?)?;
    require(stamp(&child)?.uid == unsafe { libc::geteuid() })?;
    child.sync_all().map_err(|_| REFUSED)?;
    Ok(child)
}
fn write_file(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    require(!bytes.is_empty() && bytes.len() <= 4096)?;
    let mut file = open_at(
        parent.as_raw_fd(),
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED.into())
}
fn read_file(parent: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
    let held = open_at(parent.as_raw_fd(), name, libc::O_PATH, 0)?;
    let before = held.metadata().map_err(|_| REFUSED)?;
    require(before.is_file() && before.nlink() == 1 && before.mode() & 0o7777 == 0o600)?;
    let mut file =
        File::open(format!("/proc/self/fd/{}", held.as_raw_fd())).map_err(|_| REFUSED)?;
    let opened = file.metadata().map_err(|_| REFUSED)?;
    require((opened.dev(), opened.ino()) == (before.dev(), before.ino()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    let after = file.metadata().map_err(|_| REFUSED)?;
    require(
        !bytes.is_empty()
            && bytes.len() as u64 <= limit
            && (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.ctime(),
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.ctime(),
            ),
    )?;
    Ok(bytes)
}
fn exact_children(parent: &File, expected: &[&str]) -> Result<()> {
    let mut names = BTreeSet::new();
    for child in
        fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd())).map_err(|_| REFUSED)?
    {
        let child = child.map_err(|_| REFUSED)?;
        let name = child.file_name().into_string().map_err(|_| REFUSED)?;
        require(names.insert(name))?;
    }
    require(names == expected.iter().map(|s| (*s).to_owned()).collect())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: uuid::Uuid,
    canary_id: uuid::Uuid,
    source_sha: String,
    inventory_sha256: String,
    engine_id: String,
    image: String,
    image_id: String,
    operator_sha256: String,
    root: Stamp,
    evidence: Stamp,
    parent_name: String,
    marker_sha256: String,
    host_uid: u32,
    host_gid: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    schema: String,
    intent_sha256: String,
    parent: Stamp,
    child: Stamp,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerReceipt {
    schema: String,
    intent_sha256: String,
    role: String,
    name: String,
    id: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperOutput {
    schema: String,
    installation_id: uuid::Uuid,
    canary_id: uuid::Uuid,
    phase: String,
    host_uid_zero: u32,
    host_uid_hundred: u32,
    host_gid_zero: u32,
    host_gid_hundred: u32,
    marker_sha256: String,
    child_dev: u64,
    child_ino: u64,
}

fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn read_evidence(state: &InstallerState, name: &str, expected: &[u8]) -> Result<()> {
    let observed = state.with_inspection(|view| view.diagnostic_record(name, true))?;
    require(observed.as_deref() == Some(expected))
}

fn host_parent(
    view: &LockedInspection,
    installation: &Path,
    name: &str,
) -> Result<(File, File, File)> {
    view.require_path_binding(installation)?;
    let root = view
        .installation_directory()
        .try_clone()
        .map_err(|_| REFUSED)?;
    let evidence = open_dir(&root, "evidence")?;
    let parent = open_dir(&evidence, name)?;
    view.require_path_binding(installation)?;
    Ok((root, evidence, parent))
}

struct Contract {
    role: &'static str,
    name: String,
    owner: String,
    canary_id: uuid::Uuid,
    image: String,
    image_id: String,
    environment: BTreeMap<String, String>,
    parent: PathBuf,
    operator: PathBuf,
}
fn image(
    docker: &DockerRunner,
    reference: &str,
    pull: bool,
) -> Result<(String, BTreeMap<String, String>)> {
    require(
        regex::Regex::new(r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z")
            .unwrap()
            .is_match(reference),
    )?;
    if pull {
        docker.run_checked_with_timeout(&["pull", reference], Duration::from_secs(600))?;
    }
    let value: Value = serde_json::from_str(&docker.run_checked(&["image", "inspect", reference])?)
        .map_err(|_| REFUSED)?;
    let images = value.as_array().ok_or(REFUSED)?;
    require(images.len() == 1)?;
    let observed = &images[0];
    require(
        crate::installer_container::empty_or_null(&observed["Config"]["Volumes"])
            && observed["RepoDigests"]
                .as_array()
                .is_some_and(|values| values.contains(&json!(reference))),
    )?;
    let image_id = observed["Id"].as_str().ok_or(REFUSED)?;
    require(image_id.strip_prefix("sha256:").is_some_and(id))?;
    let environment =
        crate::installer_container::bootstrap_environment(&observed["Config"]["Env"], REFUSED)?;
    Ok((image_id.to_owned(), environment))
}
fn container_name(owner: uuid::Uuid, role: &str) -> Result<String> {
    require(matches!(role, "transition" | "restore"))?;
    Ok(format!("marty-canary-{}-{role}", owner.simple()))
}
fn command(contract: &Contract) -> Result<Vec<String>> {
    let mut args = vec![
        "create".into(),
        "--name".into(),
        contract.name.clone(),
        "--pull=never".into(),
        "--network".into(),
        "none".into(),
        "--user".into(),
        "0:0".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "DAC_OVERRIDE".into(),
        "--cap-add".into(),
        "CHOWN".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--restart=no".into(),
        "--label".into(),
        format!("com.elevenid.installer.id={}", contract.owner),
        "--label".into(),
        "com.elevenid.installer.stage=rootless-canary".into(),
        "--label".into(),
        format!("com.elevenid.installer.canary={}", contract.canary_id),
        "--label".into(),
        format!("com.elevenid.installer.canary-role={}", contract.role),
        "--entrypoint".into(),
        "/input/marty-deploy".into(),
    ];
    for (target, source, readonly) in [
        ("/input/marty-deploy", &contract.operator, true),
        ("/marty-canary", &contract.parent, false),
    ] {
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={target}{}",
                path_text(source)?,
                if readonly { ",readonly" } else { "" }
            ),
        ]);
    }
    for (key, value) in &contract.environment {
        args.extend(["--env".into(), format!("{key}={value}")]);
    }
    args.extend([
        contract.image.clone(),
        "installer-rootless-canary-helper".into(),
        contract.role.into(),
    ]);
    Ok(args)
}
fn run(docker: &DockerRunner, args: &[String]) -> Result<String> {
    docker.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn inspect(docker: &DockerRunner, id: &str) -> Result<Value> {
    crate::installer_container::inspect(docker, id, REFUSED)
}
fn capabilities(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.len() == 2
            && items
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["CHOWN", "DAC_OVERRIDE"])
    })
}
fn container_config(docker: &DockerRunner, id: &str, c: &Contract) -> Result<Value> {
    let value = inspect(docker, id)?;
    validate_container_value(&value, id, c)?;
    Ok(value)
}
fn validate_container_value(value: &Value, id: &str, c: &Contract) -> Result<()> {
    crate::installer_container::validate_identity_and_security(
        value,
        &crate::installer_container::ExpectedContainer {
            id,
            name: &c.name,
            owner: &c.owner,
            image: &c.image,
            image_id: &c.image_id,
            network_id: "none",
            stage: "rootless-canary",
            entrypoint: json!(["/input/marty-deploy"]),
            command: json!(["installer-rootless-canary-helper", c.role]),
        },
        REFUSED,
    )?;
    require(
        value["Config"]["Labels"]["com.elevenid.installer.canary"] == c.canary_id.to_string()
            && value["Config"]["Labels"]["com.elevenid.installer.canary-role"] == c.role
            && capabilities(&value["HostConfig"]["CapAdd"])
            && crate::installer_container::empty_or_null(&value["HostConfig"]["Tmpfs"])
            && crate::installer_container::environment_map(&value["Config"]["Env"], REFUSED)?
                == c.environment,
    )?;
    let mut mounts = BTreeMap::new();
    for mount in value["Mounts"].as_array().ok_or(REFUSED)? {
        require(mount["Type"] == "bind")?;
        let destination = mount["Destination"].as_str().ok_or(REFUSED)?;
        let source = mount["Source"].as_str().ok_or(REFUSED)?;
        let writable = mount["RW"].as_bool().ok_or(REFUSED)?;
        require(
            mounts
                .insert(destination.to_owned(), (PathBuf::from(source), !writable))
                .is_none(),
        )?;
    }
    require(
        mounts
            == BTreeMap::from([
                ("/input/marty-deploy".into(), (c.operator.clone(), true)),
                ("/marty-canary".into(), (c.parent.clone(), false)),
            ]),
    )?;
    // The none network has no application endpoint and no published ports.
    require(
        value["NetworkSettings"]["Networks"]
            .as_object()
            .is_some_and(|networks| {
                networks.is_empty() || (networks.len() == 1 && networks.contains_key("none"))
            }),
    )?;
    Ok(())
}
fn validate_container(docker: &DockerRunner, id: &str, c: &Contract, terminal: bool) -> Result<()> {
    let value = container_config(docker, id, c)?;
    crate::installer_container::validate_stopped_state(&value, terminal, REFUSED)
}
fn create_container(docker: &DockerRunner, c: &Contract) -> Result<String> {
    require(
        docker
            .run_checked(&[
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                &format!("name=^/{}$", c.name),
            ])?
            .trim()
            .is_empty(),
    )?;
    let id_value = run(docker, &command(c)?)?;
    let id_value = id_value.trim();
    require(id(id_value))?;
    validate_container(docker, id_value, c, false)?;
    Ok(id_value.into())
}
fn start_and_wait(docker: &DockerRunner, id: &str, contract: &Contract) -> Result<()> {
    docker.preflight()?;
    validate_container(docker, id, contract, false)?;
    let started = docker.run_checked(&["start", id])?;
    require(started.trim() == id || started.trim() == contract.name)?;
    let waited = docker.run_checked_with_timeout(&["wait", id], Duration::from_secs(120))?;
    require(waited.trim() == "0")?;
    validate_container(docker, id, contract, true)
}

fn create_layout(
    view: &LockedInspection,
    installation: &Path,
    intent: &Intent,
    request: &[u8],
    marker: &[u8],
) -> Result<Created> {
    view.require_path_binding(installation)?;
    let root = view.installation_directory();
    require(stamp(root)? == intent.root)?;
    let evidence = open_dir(root, "evidence")?;
    require(stamp(&evidence)? == intent.evidence)?;
    let parent = mkdir(&evidence, &intent.parent_name)?;
    let child = mkdir(&parent, "child")?;
    write_file(&parent, "request.json", request)?;
    write_file(&child, "marker", marker)?;
    exact_children(&parent, &["child", "request.json"])?;
    exact_children(&child, &["marker"])?;
    require(stamp(root)? == intent.root && stamp(&evidence)? == intent.evidence)?;
    view.require_path_binding(installation)?;
    Ok(Created {
        schema: "elevenid.rootless-storage-canary-created/v1".into(),
        intent_sha256: sha(&encoded(intent)?),
        parent: stamp(&parent)?,
        child: stamp(&child)?,
    })
}

fn bound_layout(
    view: &LockedInspection,
    installation: &Path,
    intent: &Intent,
    created: &Created,
) -> Result<(File, File)> {
    let (root, evidence, parent) = host_parent(view, installation, &intent.parent_name)?;
    require(
        stamp(&root)? == intent.root
            && stamp(&evidence)? == intent.evidence
            && stamp(&parent)? == created.parent
            && created.intent_sha256 == sha(&encoded(intent)?)
            && created.schema == "elevenid.rootless-storage-canary-created/v1",
    )?;
    let child = path_dir(&parent, "child")?;
    let observed = stamp(&child)?;
    require(
        (observed.dev, observed.ino, observed.mount, observed.mode)
            == (
                created.child.dev,
                created.child.ino,
                created.child.mount,
                created.child.mode,
            ),
    )?;
    Ok((parent, child))
}
fn helper_output(
    parent: &File,
    intent: &Intent,
    created: &Created,
    phase: &str,
) -> Result<HelperOutput> {
    require(matches!(phase, "transition" | "restore"))?;
    let output: HelperOutput = serde_json::from_slice(&read_file(
        parent,
        if phase == "transition" {
            "transition-output.json"
        } else {
            "restore-output.json"
        },
        4096,
    )?)
    .map_err(|_| REFUSED)?;
    require(
        output.schema == "elevenid.rootless-storage-canary-helper/v1"
            && output.installation_id == intent.installation_id
            && output.canary_id == intent.canary_id
            && output.phase == phase
            && output.host_uid_zero == intent.host_uid
            && output.host_gid_zero == intent.host_gid
            && output.host_uid_hundred != intent.host_uid
            && output.host_uid_hundred != 0
            && output.host_gid_hundred != intent.host_gid
            && output.host_gid_hundred != 0
            && output.marker_sha256 == intent.marker_sha256
            && (output.child_dev, output.child_ino) == (created.child.dev, created.child.ino),
    )?;
    Ok(output)
}
fn foreign_child(parent: &File, created: &Created, output: &HelperOutput) -> Result<Stamp> {
    let child = path_dir(parent, "child")?;
    let observed = stamp(&child)?;
    require(
        (observed.dev, observed.ino, observed.mount, observed.mode)
            == (
                created.child.dev,
                created.child.ino,
                created.child.mount,
                0o700,
            )
            && observed.uid == output.host_uid_hundred
            && observed.gid == output.host_gid_hundred,
    )?;
    let name = CString::new("child").map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        return Err(REFUSED.into());
    }
    require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES))?;
    exact_children(parent, &["child", "request.json", "transition-output.json"])?;
    Ok(observed)
}
fn restored_child(
    parent: &File,
    intent: &Intent,
    created: &Created,
    marker: &[u8],
) -> Result<Stamp> {
    let child = open_dir(parent, "child")?;
    let observed = stamp(&child)?;
    require(
        (observed.dev, observed.ino, observed.mount, observed.mode)
            == (
                created.child.dev,
                created.child.ino,
                created.child.mount,
                0o700,
            )
            && observed.uid == intent.host_uid
            && observed.gid == intent.host_gid
            && read_file(&child, "marker", 256)? == marker,
    )?;
    exact_children(
        parent,
        &[
            "child",
            "request.json",
            "transition-output.json",
            "restore-output.json",
        ],
    )?;
    exact_children(&child, &["marker"])?;
    Ok(observed)
}

fn persist(state: &mut InstallerState, name: &str, bytes: &[u8]) -> Result<()> {
    state.write_evidence(name, bytes)?;
    read_evidence(state, name, bytes)
}
fn receipt(intent: &Intent, role: &str, name: String, id: String) -> ContainerReceipt {
    ContainerReceipt {
        schema: "elevenid.rootless-storage-canary-container/v1".into(),
        intent_sha256: sha(&encoded(intent).expect("intent is serializable")),
        role: role.into(),
        name,
        id,
    }
}
fn remove_exact(docker: &DockerRunner, id: &str, contract: &Contract) -> Result<()> {
    docker.preflight()?;
    validate_container(docker, id, contract, true)?;
    let result = docker.run_checked(&["rm", id])?;
    require(result.trim() == id || result.trim() == contract.name)?;
    require(
        docker
            .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &format!("id={id}")])?
            .trim()
            .is_empty(),
    )
}

fn maintenance_record(maintenance: &mut LockedMaintenance, name: &str, bytes: &[u8]) -> Result<()> {
    match maintenance.read_evidence(name)? {
        Some(existing) => require(existing == bytes),
        None => {
            maintenance.write_evidence_exclusive(name, bytes)?;
            require(maintenance.read_evidence(name)?.as_deref() == Some(bytes))
        }
    }
}

fn verified_records(
    intent: &Intent,
    intent_bytes: &[u8],
    created_bytes: &[u8],
    transition_bytes: &[u8],
    restore_bytes: &[u8],
    start_bytes: &[u8],
) -> Result<(Created, ContainerReceipt, ContainerReceipt)> {
    let created: Created = serde_json::from_slice(created_bytes).map_err(|_| REFUSED)?;
    require(
        encoded(&created)? == created_bytes
            && created.schema == "elevenid.rootless-storage-canary-created/v1"
            && created.intent_sha256 == sha(intent_bytes)
            && created.parent.mode == 0o700
            && created.child.mode == 0o700
            && created.parent.mount != 0
            && created.child.mount != 0,
    )?;
    let transition: ContainerReceipt =
        serde_json::from_slice(transition_bytes).map_err(|_| REFUSED)?;
    let restore: ContainerReceipt = serde_json::from_slice(restore_bytes).map_err(|_| REFUSED)?;
    for (record, role, bytes) in [
        (&transition, "transition", transition_bytes),
        (&restore, "restore", restore_bytes),
    ] {
        require(
            encoded(record)? == bytes
                && record.schema == "elevenid.rootless-storage-canary-container/v1"
                && record.intent_sha256 == sha(intent_bytes)
                && record.role == role
                && record.name == container_name(intent.canary_id, role)?
                && id(&record.id),
        )?;
    }
    require(transition.id != restore.id)?;
    let expected_start = encoded(&json!({
        "schema":"elevenid.rootless-storage-canary-start-intent/v1",
        "intent_sha256":sha(intent_bytes),"transition_id":transition.id,"restore_id":restore.id,
        "parent":created.parent,"child":created.child
    }))?;
    require(start_bytes == expected_start)?;
    Ok((created, transition, restore))
}

/// Restore only an interrupted, exact candidate canary. This cannot resume
/// provisioning or mark an installation ready. It never adopts an unknown
/// container, and it leaves stopped helper containers for separate review.
pub fn restore_interrupted(installation: &Path, dockerpath: &Path) -> Result<()> {
    crate::installer_command::require_rootless_process()?;
    let mut maintenance = LockedMaintenance::open(installation)?;
    let journal = maintenance.journal();
    require(
        matches!(journal.execution_scope(), ExecutionScope::CandidateTest(_))
            && journal.phase() == Phase::Verified,
    )?;
    let binding = journal.runtime().ok_or(REFUSED)?.clone();
    require(binding.profile == crate::installer_state::RuntimeProfile::Rootless)?;
    let intent_bytes = maintenance.read_evidence(INTENT)?.ok_or(REFUSED)?;
    let intent: Intent = serde_json::from_slice(&intent_bytes).map_err(|_| REFUSED)?;
    require(
        encoded(&intent)? == intent_bytes
            && intent.schema == "elevenid.rootless-storage-canary-intent/v1"
            && intent.installation_id == journal.installation_id()
            && intent.source_sha == journal.identity().source_sha
            && intent.inventory_sha256 == journal.identity().inventory_sha256
            && intent.engine_id == binding.engine_id
            && intent.host_uid == unsafe { libc::geteuid() }
            && intent.host_gid == unsafe { libc::getegid() }
            && intent.host_uid != 0
            && intent.host_gid != 0
            && intent.parent_name == format!("rootless-canary-{}", intent.canary_id.simple()),
    )?;
    let (created, transition, restore) = verified_records(
        &intent,
        &intent_bytes,
        &maintenance.read_evidence(CREATED)?.ok_or(REFUSED)?,
        &maintenance
            .read_evidence(TRANSITION_CONTAINER)?
            .ok_or(REFUSED)?,
        &maintenance
            .read_evidence(RESTORE_CONTAINER)?
            .ok_or(REFUSED)?,
        &maintenance.read_evidence(START_INTENT)?.ok_or(REFUSED)?,
    )?;
    let inventory = maintenance
        .read_evidence("candidate-test-inventory.json")?
        .ok_or(REFUSED)?;
    require(format!("sha256:{}", sha(&inventory)) == intent.inventory_sha256)?;
    let operator = installation.join("marty-deploy");
    require(
        crate::installer_verify::current_operator_digest()? == intent.operator_sha256
            && crate::installer_verify::operator_digest(&operator)? == intent.operator_sha256,
    )?;
    maintenance
        .inspection()
        .require_path_binding(installation)?;
    let docker = DockerRunner::from_binding(dockerpath, &binding, installation)?;
    docker.preflight()?;
    let (current_image, environment) = image(&docker, &intent.image, false)?;
    require(current_image == intent.image_id)?;
    let parent_path = installation.join("evidence").join(&intent.parent_name);
    let contract = |role: &'static str, record: &ContainerReceipt| Contract {
        role,
        name: record.name.clone(),
        owner: intent.installation_id.to_string(),
        canary_id: intent.canary_id,
        image: intent.image.clone(),
        image_id: intent.image_id.clone(),
        environment: environment.clone(),
        parent: parent_path.clone(),
        operator: operator.clone(),
    };
    let transition_contract = contract("transition", &transition);
    let restore_contract = contract("restore", &restore);
    let transition_inspect = container_config(&docker, &transition.id, &transition_contract)?;
    require(transition_inspect["State"]["Status"] != "created")?;
    if transition_inspect["State"]["Running"] == true {
        let _ =
            docker.run_checked_with_timeout(&["wait", &transition.id], Duration::from_secs(120))?;
    }
    let transition_inspect = container_config(&docker, &transition.id, &transition_contract)?;
    require(
        transition_inspect["State"]["Running"] == false
            && transition_inspect["State"]["Status"] == "exited",
    )?;
    let (parent, child) = bound_layout(maintenance.inspection(), installation, &intent, &created)?;
    require(stamp(&parent)? == created.parent)?;
    let transition_output = helper_output(&parent, &intent, &created, "transition")?;
    let current = stamp(&child)?;
    let foreign = current.uid == transition_output.host_uid_hundred
        && current.gid == transition_output.host_gid_hundred;
    let expected_foreign = encoded(&json!({
        "schema":"elevenid.rootless-storage-canary-foreign/v1",
        "intent_sha256":sha(&intent_bytes),"child":current,
        "host_uid_hundred":transition_output.host_uid_hundred,
        "host_gid_hundred":transition_output.host_gid_hundred
    }))?;
    if foreign {
        foreign_child(&parent, &created, &transition_output)?;
        maintenance_record(&mut maintenance, FOREIGN, &expected_foreign)?;
    } else {
        require(
            current.uid == intent.host_uid
                && current.gid == intent.host_gid
                && maintenance.read_evidence(FOREIGN)?.is_some(),
        )?;
    }
    let expected_restore = encoded(&json!({
        "schema":"elevenid.rootless-storage-canary-restore-intent/v1",
        "intent_sha256":sha(&intent_bytes),"restore_id":restore.id,
        "foreign_child": if foreign { current.clone() } else {
            let evidence = maintenance.read_evidence(FOREIGN)?.ok_or(REFUSED)?;
            let value: Value = serde_json::from_slice(&evidence).map_err(|_| REFUSED)?;
            serde_json::from_value::<Stamp>(value["child"].clone()).map_err(|_| REFUSED)?
        }
    }))?;
    if foreign {
        let state = container_config(&docker, &restore.id, &restore_contract)?;
        if state["State"]["Status"] == "created" {
            maintenance_record(&mut maintenance, RESTORE_INTENT, &expected_restore)?;
            start_and_wait(&docker, &restore.id, &restore_contract)?;
        } else if state["State"]["Running"] == true {
            require(
                maintenance.read_evidence(RESTORE_INTENT)?.as_deref() == Some(&expected_restore),
            )?;
            let _ = docker
                .run_checked_with_timeout(&["wait", &restore.id], Duration::from_secs(120))?;
        } else {
            require(
                maintenance.read_evidence(RESTORE_INTENT)?.as_deref() == Some(&expected_restore),
            )?;
        }
    } else {
        require(maintenance.read_evidence(RESTORE_INTENT)?.as_deref() == Some(&expected_restore))?;
    }
    let restore_inspect = container_config(&docker, &restore.id, &restore_contract)?;
    require(
        restore_inspect["State"]["Running"] == false
            && restore_inspect["State"]["Status"] == "exited",
    )?;
    let (parent, _) = bound_layout(maintenance.inspection(), installation, &intent, &created)?;
    let restore_output = helper_output(&parent, &intent, &created, "restore")?;
    require(
        restore_output.host_uid_hundred == transition_output.host_uid_hundred
            && restore_output.host_gid_hundred == transition_output.host_gid_hundred,
    )?;
    let marker = format!("marty-rootless-canary/v1:{}\n", intent.canary_id).into_bytes();
    require(sha(&marker) == intent.marker_sha256)?;
    let restored = restored_child(&parent, &intent, &created, &marker)?;
    maintenance_record(
        &mut maintenance,
        "rootless-canary-recovery-result.json",
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-recovery/v1",
            "intent_sha256":sha(&intent_bytes),"restored_child":restored,
            "host_traversal_restored":true,"containers_retained":true,
            "provisioning_resumed":false,"installation_ready":false,
        }))?,
    )?;
    Ok(())
}

/// The caller has authenticated the exact candidate inventory and complete
/// bundle, received user confirmation, and has not generated runtime secrets.
/// This function requires a fresh CandidateTest journal and never grants Ready.
pub(crate) fn qualify_candidate(
    dockerpath: &Path,
    installation: &Path,
    state: &mut InstallerState,
    inventory: &crate::installer_release::Inventory,
    operator_sha: &str,
) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    require(matches!(
        state.journal().execution_scope(),
        ExecutionScope::CandidateTest(_)
    ))?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    require(binding.profile == crate::installer_state::RuntimeProfile::Rootless)?;
    let docker = DockerRunner::from_binding(dockerpath, &binding, installation)?;
    docker.preflight()?;
    let reference = inventory.images.get("gateway").ok_or(REFUSED)?;
    require(inventory.images.get("signing-keys") == Some(reference))?;
    let operator = installation.join("marty-deploy");
    require(
        crate::installer_verify::operator_digest(&operator)? == operator_sha && id(operator_sha),
    )?;
    let (image_id, environment) = image(&docker, reference, true)?;
    let canary_id = uuid::Uuid::new_v4();
    let parent_name = format!("rootless-canary-{}", canary_id.simple());
    let marker = format!("marty-rootless-canary/v1:{canary_id}\n").into_bytes();
    let (root, evidence) = state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        let root = view.installation_directory();
        let evidence = open_dir(root, "evidence")?;
        Ok((stamp(root)?, stamp(&evidence)?))
    })?;
    let journal = state.journal();
    let intent = Intent {
        schema: "elevenid.rootless-storage-canary-intent/v1".into(),
        installation_id: journal.installation_id(),
        canary_id,
        source_sha: journal.identity().source_sha.clone(),
        inventory_sha256: journal.identity().inventory_sha256.clone(),
        engine_id: binding.engine_id.clone(),
        image: reference.clone(),
        image_id,
        operator_sha256: operator_sha.into(),
        root,
        evidence,
        parent_name,
        marker_sha256: sha(&marker),
        host_uid: unsafe { libc::geteuid() },
        host_gid: unsafe { libc::getegid() },
    };
    require(intent.host_uid != 0 && intent.host_gid != 0 && intent.root.uid == intent.host_uid)?;
    let intent_bytes = encoded(&intent)?;
    persist(state, INTENT, &intent_bytes)?;
    let request = encoded(&json!({
        "schema":"elevenid.rootless-storage-canary-request/v1",
        "installation_id":intent.installation_id,
        "canary_id":canary_id,
        "host_uid":intent.host_uid,
        "host_gid":intent.host_gid,
        "marker_sha256":intent.marker_sha256,
    }))?;
    let created = state
        .with_inspection(|view| create_layout(view, installation, &intent, &request, &marker))?;
    persist(state, CREATED, &encoded(&created)?)?;
    let parent_path = installation.join("evidence").join(&intent.parent_name);
    let mut records = Vec::new();
    for role in ["transition", "restore"] {
        state.with_inspection(|view| {
            let (parent, child) = bound_layout(view, installation, &intent, &created)?;
            require(stamp(&parent)? == created.parent && stamp(&child)? == created.child)?;
            exact_children(&parent, &["child", "request.json"])
        })?;
        docker.preflight()?;
        let contract = Contract {
            role,
            name: container_name(canary_id, role)?,
            owner: intent.installation_id.to_string(),
            canary_id,
            image: intent.image.clone(),
            image_id: intent.image_id.clone(),
            environment: environment.clone(),
            parent: parent_path.clone(),
            operator: operator.clone(),
        };
        let id = create_container(&docker, &contract)?;
        let record = receipt(&intent, role, contract.name, id);
        let bytes = encoded(&record)?;
        persist(
            state,
            if role == "transition" {
                TRANSITION_CONTAINER
            } else {
                RESTORE_CONTAINER
            },
            &bytes,
        )?;
        records.push(record);
    }
    let restore = records.pop().ok_or(REFUSED)?;
    let transition = records.pop().ok_or(REFUSED)?;
    read_evidence(state, TRANSITION_CONTAINER, &encoded(&transition)?)?;
    read_evidence(state, RESTORE_CONTAINER, &encoded(&restore)?)?;
    require(
        transition.id != restore.id && transition.role == "transition" && restore.role == "restore",
    )?;
    let contract = |role: &'static str, record: &ContainerReceipt| Contract {
        role,
        name: record.name.clone(),
        owner: intent.installation_id.to_string(),
        canary_id,
        image: intent.image.clone(),
        image_id: intent.image_id.clone(),
        environment: environment.clone(),
        parent: parent_path.clone(),
        operator: operator.clone(),
    };
    let transition_contract = contract("transition", &transition);
    let restore_contract = contract("restore", &restore);
    validate_container(&docker, &transition.id, &transition_contract, false)?;
    validate_container(&docker, &restore.id, &restore_contract, false)?;
    persist(
        state,
        START_INTENT,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-start-intent/v1",
            "intent_sha256":sha(&intent_bytes),"transition_id":transition.id,"restore_id":restore.id,
            "parent":created.parent,"child":created.child
        }))?,
    )?;
    state.with_inspection(|view| {
        let (parent, child) = bound_layout(view, installation, &intent, &created)?;
        require(stamp(&parent)? == created.parent && stamp(&child)? == created.child)?;
        exact_children(&parent, &["child", "request.json"])
    })?;
    require(crate::installer_verify::operator_digest(&operator)? == intent.operator_sha256)?;
    read_evidence(state, TRANSITION_CONTAINER, &encoded(&transition)?)?;
    read_evidence(state, RESTORE_CONTAINER, &encoded(&restore)?)?;
    start_and_wait(&docker, &transition.id, &transition_contract)?;
    let (foreign_stamp, transition_output) = state.with_inspection(|view| {
        let (parent, _) = bound_layout(view, installation, &intent, &created)?;
        require(stamp(&parent)? == created.parent)?;
        let output = helper_output(&parent, &intent, &created, "transition")?;
        let foreign = foreign_child(&parent, &created, &output)?;
        Ok((foreign, output))
    })?;
    persist(
        state,
        FOREIGN,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-foreign/v1",
            "intent_sha256":sha(&intent_bytes),"child":foreign_stamp,
            "host_uid_hundred":transition_output.host_uid_hundred,
            "host_gid_hundred":transition_output.host_gid_hundred
        }))?,
    )?;
    validate_container(&docker, &restore.id, &restore_contract, false)?;
    persist(
        state,
        RESTORE_INTENT,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-restore-intent/v1",
            "intent_sha256":sha(&intent_bytes),"restore_id":restore.id,
            "foreign_child":foreign_stamp
        }))?,
    )?;
    state.with_inspection(|view| {
        let (parent, _) = bound_layout(view, installation, &intent, &created)?;
        require(stamp(&parent)? == created.parent)?;
        foreign_child(&parent, &created, &transition_output).map(|_| ())
    })?;
    require(crate::installer_verify::operator_digest(&operator)? == intent.operator_sha256)?;
    start_and_wait(&docker, &restore.id, &restore_contract)?;
    let restored = state.with_inspection(|view| {
        let (parent, _) = bound_layout(view, installation, &intent, &created)?;
        require(stamp(&parent)? == created.parent)?;
        let output = helper_output(&parent, &intent, &created, "restore")?;
        require(
            output.host_uid_hundred == transition_output.host_uid_hundred
                && output.host_gid_hundred == transition_output.host_gid_hundred,
        )?;
        restored_child(&parent, &intent, &created, &marker)
    })?;
    persist(
        state,
        RESULT,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-result/v1",
            "intent_sha256":sha(&intent_bytes),"restored_child":restored,
            "host_traversal_restored":true,"deletion_authorized":false,
            "installation_ready":false
        }))?,
    )?;
    persist(
        state,
        REMOVE_INTENT,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-remove-intent/v1",
            "intent_sha256":sha(&intent_bytes),"transition_id":transition.id,"restore_id":restore.id
        }))?,
    )?;
    remove_exact(&docker, &transition.id, &transition_contract)?;
    remove_exact(&docker, &restore.id, &restore_contract)?;
    persist(
        state,
        COMPLETE,
        &encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-complete/v1",
            "intent_sha256":sha(&intent_bytes),"containers_removed":true,
            "host_traversal_restored":true,"installation_ready":false
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn canary_id_and_name_bounds() {
        assert!(id(&"a".repeat(64)));
        assert!(!id("not-a-container-id"));
        assert!(path_text(Path::new("/tmp/owned")).is_ok());
        assert!(path_text(Path::new("relative")).is_err());
        assert!(path_text(Path::new("/tmp/with,comma")).is_err());
    }

    #[test]
    fn recovery_refuses_partial_or_replaced_durable_chain() {
        let installation_id = uuid::Uuid::new_v4();
        let canary_id = uuid::Uuid::new_v4();
        let stamp = Stamp {
            dev: 1,
            ino: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o700,
            mount: 3,
        };
        let intent = Intent {
            schema: "elevenid.rootless-storage-canary-intent/v1".into(),
            installation_id,
            canary_id,
            source_sha: "a".repeat(40),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            engine_id: uuid::Uuid::new_v4().to_string(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
                "c".repeat(64)
            ),
            image_id: format!("sha256:{}", "d".repeat(64)),
            operator_sha256: "e".repeat(64),
            root: stamp.clone(),
            evidence: stamp.clone(),
            parent_name: format!("rootless-canary-{}", canary_id.simple()),
            marker_sha256: "f".repeat(64),
            host_uid: 1000,
            host_gid: 1000,
        };
        let intent_bytes = encoded(&intent).unwrap();
        let created = Created {
            schema: "elevenid.rootless-storage-canary-created/v1".into(),
            intent_sha256: sha(&intent_bytes),
            parent: stamp.clone(),
            child: stamp,
        };
        let transition = receipt(
            &intent,
            "transition",
            container_name(canary_id, "transition").unwrap(),
            "1".repeat(64),
        );
        let restore = receipt(
            &intent,
            "restore",
            container_name(canary_id, "restore").unwrap(),
            "2".repeat(64),
        );
        let created_bytes = encoded(&created).unwrap();
        let transition_bytes = encoded(&transition).unwrap();
        let restore_bytes = encoded(&restore).unwrap();
        let start = encoded(&json!({
            "schema":"elevenid.rootless-storage-canary-start-intent/v1",
            "intent_sha256":sha(&intent_bytes),"transition_id":transition.id,"restore_id":restore.id,
            "parent":created.parent,"child":created.child
        })).unwrap();
        let check = |created: &[u8], transition: &[u8], restore: &[u8], start: &[u8]| {
            verified_records(&intent, &intent_bytes, created, transition, restore, start)
        };
        check(&created_bytes, &transition_bytes, &restore_bytes, &start).unwrap();
        assert!(check(&created_bytes, &transition_bytes, &restore_bytes, b"").is_err());
        let mut changed = created.clone();
        changed.child.ino += 1;
        assert!(check(
            &encoded(&changed).unwrap(),
            &transition_bytes,
            &restore_bytes,
            &start
        )
        .is_err());
        let mut changed = restore.clone();
        changed.id = transition.id.clone();
        assert!(check(
            &created_bytes,
            &transition_bytes,
            &encoded(&changed).unwrap(),
            &start
        )
        .is_err());
        let mut changed = transition.clone();
        changed.role = "restore".into();
        assert!(check(
            &created_bytes,
            &encoded(&changed).unwrap(),
            &restore_bytes,
            &start
        )
        .is_err());
    }

    #[test]
    fn fixed_layout_refuses_replaced_or_special_entries() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = File::open(temp.path()).unwrap();
        let parent = mkdir(&root, "owned").unwrap();
        let child = mkdir(&parent, "child").unwrap();
        write_file(&parent, "request.json", b"request").unwrap();
        write_file(&child, "marker", b"synthetic").unwrap();
        assert_eq!(read_file(&child, "marker", 256).unwrap(), b"synthetic");
        exact_children(&parent, &["child", "request.json"]).unwrap();
        let original = stamp(&child).unwrap();
        fs::rename(
            temp.path().join("owned/child"),
            temp.path().join("owned/old"),
        )
        .unwrap();
        let replacement = mkdir(&parent, "child").unwrap();
        assert_ne!(stamp(&replacement).unwrap(), original);
        assert!(exact_children(&parent, &["child", "request.json"]).is_err());
        symlink("request.json", temp.path().join("owned/link")).unwrap();
        assert!(read_file(&parent, "link", 256).is_err());
        let fifo = CString::new("pipe").unwrap();
        assert_eq!(
            unsafe { libc::mkfifoat(parent.as_raw_fd(), fifo.as_ptr(), 0o600) },
            0
        );
        assert!(read_file(&parent, "pipe", 256).is_err());
        fs::set_permissions(
            temp.path().join("owned/request.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read_file(&parent, "request.json", 256).is_err());
    }

    fn fixture_container(c: &Contract, id: &str) -> Value {
        json!({
            "Id":id,"Image":c.image_id,"Name":format!("/{}",c.name),
            "Config":{
                "Image":c.image,"User":"0:0","Entrypoint":["/input/marty-deploy"],
                "Cmd":["installer-rootless-canary-helper",c.role],"Env":[],
                "Labels":{
                    "com.elevenid.installer.id":c.owner,
                    "com.elevenid.installer.stage":"rootless-canary",
                    "com.elevenid.installer.canary":c.canary_id,
                    "com.elevenid.installer.canary-role":c.role
                }
            },
            "HostConfig":{
                "ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],
                "CapAdd":["DAC_OVERRIDE","CHOWN"],"SecurityOpt":["no-new-privileges"],
                "NetworkMode":"none","AutoRemove":false,"RestartPolicy":{"Name":"no"},
                "PidMode":"","UsernsMode":"","IpcMode":"private","PortBindings":{},
                "Devices":[],"DeviceRequests":null,"Binds":null,"Tmpfs":null
            },
            "Mounts":[
                {"Type":"bind","Destination":"/input/marty-deploy","Source":c.operator,"RW":false},
                {"Type":"bind","Destination":"/marty-canary","Source":c.parent,"RW":true}
            ],
            "NetworkSettings":{"Networks":{}},
            "State":{"Running":false,"Status":"created","ExitCode":0,"OOMKilled":false}
        })
    }

    #[test]
    fn container_contract_rejects_extra_mount_cap_network_and_identity_drift() {
        let c = Contract {
            role: "transition",
            name: "marty-canary-test-transition".into(),
            owner: uuid::Uuid::new_v4().to_string(),
            canary_id: uuid::Uuid::new_v4(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
                "a".repeat(64)
            ),
            image_id: format!("sha256:{}", "b".repeat(64)),
            environment: BTreeMap::new(),
            parent: PathBuf::from("/owned/parent"),
            operator: PathBuf::from("/owned/marty-deploy"),
        };
        let id = "c".repeat(64);
        let baseline = fixture_container(&c, &id);
        validate_container_value(&baseline, &id, &c).unwrap();
        for (pointer, wrong) in [
            (
                "/Config/Labels/com.elevenid.installer.canary",
                json!(uuid::Uuid::new_v4()),
            ),
            ("/HostConfig/CapAdd", json!(["SYS_ADMIN"])),
            ("/HostConfig/NetworkMode", json!("bridge")),
            ("/HostConfig/UsernsMode", json!("host")),
            ("/HostConfig/AutoRemove", json!(true)),
            ("/Mounts/0/Source", json!("/other/operator")),
            ("/Mounts/1/RW", json!(false)),
            ("/State/Status", json!("exited")),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong;
            if pointer == "/State/Status" {
                // State is separately checked after static configuration.
                assert!(crate::installer_container::validate_stopped_state(
                    &changed, false, REFUSED
                )
                .is_err());
            } else {
                assert!(
                    validate_container_value(&changed, &id, &c).is_err(),
                    "{pointer}"
                );
            }
        }
        let mut extra = baseline;
        extra["Mounts"].as_array_mut().unwrap().push(json!({
            "Type":"volume","Destination":"/unowned","Source":"anonymous","RW":true
        }));
        assert!(validate_container_value(&extra, &id, &c).is_err());
    }
}
