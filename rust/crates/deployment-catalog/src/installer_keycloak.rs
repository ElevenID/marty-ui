//! Owned one-shot Keycloak provisioning. Never retries a mutation or removes an
//! uncertain container. Durable intent, ID and outputs survive every failure.
#![cfg(target_os = "linux")]
use crate::{
    installer_helper_output,
    installer_keycloak_bridge::OUTPUTS,
    installer_openbao::{self, OpenBaoInventory},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_verify,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Keycloak provisioning refused; preserve installation state for recovery";
const SCRATCH_OPTIONS: &str = "rw,noexec,nosuid,nodev,size=1048576,mode=0700";
const SCRATCH_PATHS: [&str; 2] = ["/openbao/file", "/openbao/logs"];

fn scratch_configuration() -> Value {
    json!({"/openbao/file":SCRATCH_OPTIONS,"/openbao/logs":SCRATCH_OPTIONS})
}

// Cover the admitted image's exact inherited volumes BEFORE Docker create;
// unknown declarations must never allocate unrecorded anonymous volumes.
fn image_volumes(image: &Value) -> Result<()> {
    require(image["Config"]["Volumes"] == json!({"/openbao/file":{},"/openbao/logs":{}}))
}
#[derive(Serialize)]
pub struct KeycloakReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub nonce: String,
    pub outputs: Vec<String>,
    pub container_removed: bool,
    pub installation_ready: bool,
}
struct Contract {
    name: String,
    owner: String,
    image: String,
    image_id: String,
    network_id: String,
    network_name: String,
    nonce: String,
    mounts: BTreeMap<String, (PathBuf, bool)>,
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn path_text(path: &Path) -> Result<&str> {
    let value = path.to_str().ok_or(REFUSAL)?;
    require(path.is_absolute() && !value.chars().any(|c| c.is_control() || c == ','))?;
    Ok(value)
}
fn command(contract: &Contract) -> Result<Vec<String>> {
    let mut args = vec![
        "create".into(),
        "--name".into(),
        contract.name.clone(),
        "--pull=never".into(),
        "--network".into(),
        contract.network_id.clone(),
        "--user".into(),
        "0:0".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "DAC_OVERRIDE".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--restart=no".into(),
        "--label".into(),
        format!("com.elevenid.installer.id={}", contract.owner),
        "--label".into(),
        "com.elevenid.installer.stage=keycloak".into(),
        "--entrypoint".into(),
        "/input/marty-deploy".into(),
    ];
    for target in SCRATCH_PATHS {
        args.extend(["--tmpfs".into(), format!("{target}:{SCRATCH_OPTIONS}")]);
    }
    for (target, (source, readonly)) in &contract.mounts {
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={target}{}",
                path_text(source)?,
                if *readonly { ",readonly" } else { "" }
            ),
        ]);
    }
    args.extend([
        contract.image.clone(),
        "installer-keycloak-bridge".into(),
        "--nonce".into(),
        contract.nonce.clone(),
    ]);
    Ok(args)
}
fn run(docker: &DockerRunner, args: &[String]) -> Result<String> {
    docker.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn inspect(docker: &DockerRunner, container: &str) -> Result<Value> {
    crate::installer_container::inspect(docker, container, REFUSAL)
}
fn validate_observation(
    c: &Value,
    container: &str,
    contract: &Contract,
    terminal: bool,
) -> Result<()> {
    let host = &c["HostConfig"];
    crate::installer_container::validate_identity_and_security(
        c,
        &crate::installer_container::ExpectedContainer {
            id: container,
            name: &contract.name,
            owner: &contract.owner,
            image: &contract.image,
            image_id: &contract.image_id,
            network_id: &contract.network_id,
            stage: "keycloak",
            entrypoint: json!(["/input/marty-deploy"]),
            command: json!(["installer-keycloak-bridge", "--nonce", contract.nonce]),
        },
        REFUSAL,
    )?;
    require(
        (host["CapAdd"] == json!(["DAC_OVERRIDE"])
            || host["CapAdd"] == json!(["CAP_DAC_OVERRIDE"]))
            && host["Tmpfs"] == scratch_configuration(),
    )?;
    crate::installer_container::validate_network(
        c,
        &contract.network_name,
        &contract.network_id,
        terminal,
        REFUSAL,
    )?;
    let mut mounts = BTreeMap::new();
    for mount in c["Mounts"].as_array().ok_or(REFUSAL)? {
        require(mount["Type"] == "bind")?;
        let target = mount["Destination"].as_str().ok_or(REFUSAL)?;
        let source = mount["Source"].as_str().ok_or(REFUSAL)?;
        let writable = mount["RW"].as_bool().ok_or(REFUSAL)?;
        require(
            mounts
                .insert(target.to_owned(), (PathBuf::from(source), !writable))
                .is_none(),
        )?;
    }
    require(mounts == contract.mounts)?;
    crate::installer_container::validate_stopped_state(c, terminal, REFUSAL)?;
    Ok(())
}
fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}
fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name).map_err(|_| REFUSAL)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(REFUSAL.into())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn read_outputs(directory: &File, owner: u32) -> Result<BTreeMap<String, Vec<u8>>> {
    let held = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let names = std::fs::read_dir(held)
        .map_err(|_| REFUSAL)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSAL)
                .and_then(|e| e.file_name().into_string().map_err(|_| REFUSAL))
        })
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    require(names == OUTPUTS.into_iter().map(str::to_owned).collect())?;
    let mut result = BTreeMap::new();
    let mut tokens = BTreeSet::new();
    for name in OUTPUTS {
        let file = open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let m = file.metadata().map_err(|_| REFUSAL)?;
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
            .map_err(|_| REFUSAL)?;
        require(bytes.len() as u64 == m.len())?;
        let after = file.metadata().map_err(|_| REFUSAL)?;
        require(
            after.dev() == m.dev()
                && after.ino() == m.ino()
                && after.uid() == owner
                && after.nlink() == m.nlink()
                && after.mode() == m.mode()
                && after.len() == m.len()
                && after.mtime() == m.mtime()
                && after.mtime_nsec() == m.mtime_nsec(),
        )?;
        let value = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
        require(value.is_ascii() && !value.contains("PRIVATE KEY"))?;
        if name.ends_with("_token") {
            require(
                (20..=2048).contains(&value.len())
                    && !value
                        .bytes()
                        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                    && tokens.insert(value.to_owned()),
            )?;
        } else {
            require(
                value.starts_with("-----BEGIN CERTIFICATE-----")
                    && value.trim_end().ends_with("-----END CERTIFICATE-----"),
            )?;
        }
        result.insert(name.to_owned(), bytes);
    }
    Ok(result)
}
fn transfer(secrets: &File, outputs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for name in OUTPUTS {
        let mut file = open_at(
            secrets,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        secrets.sync_all().map_err(|_| REFUSAL)?;
        file.write_all(outputs.get(name).ok_or(REFUSAL)?)
            .map_err(|_| REFUSAL)?;
        file.sync_all().map_err(|_| REFUSAL)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
        file.sync_all()
            .and_then(|_| secrets.sync_all())
            .map_err(|_| REFUSAL)?;
    }
    Ok(())
}
pub fn provision(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    expected_operator_sha: &str,
) -> Result<KeycloakReceipt> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let docker = DockerRunner::from_binding(dockerpath, &binding, installation)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let operator = installation.join("marty-deploy");
    require(installer_verify::operator_digest(&operator)? == expected_operator_sha)?;
    let nonce = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
    let owner = state.journal().installation_id().to_string();
    let name = format!("{}-keycloak-inputs", state.journal().compose_project());
    let output = installation.join("keycloak-output");
    let local_image: Value =
        serde_json::from_str(&docker.run_checked(&["image", "inspect", &bao.image])?)
            .map_err(|_| REFUSAL)?;
    let images = local_image.as_array().ok_or(REFUSAL)?;
    require(
        images.len() == 1
            && images[0]["RepoDigests"]
                .as_array()
                .is_some_and(|digests| digests.contains(&json!(bao.image))),
    )?;
    image_volumes(&images[0])?;
    let image_id = images[0]["Id"].as_str().ok_or(REFUSAL)?.to_owned();
    require(image_id.strip_prefix("sha256:").is_some_and(id))?;
    let contract = Contract {
        name,
        owner,
        image: bao.image.clone(),
        image_id,
        network_id: bao.network_id.clone(),
        network_name: bao.network_name.clone(),
        nonce,
        mounts: BTreeMap::from([
            ("/input/marty-deploy".into(), (operator, true)),
            (
                "/input/root.token".into(),
                (installation.join("openbao-state/root.token"), true),
            ),
            (
                "/input/ca.crt".into(),
                (installation.join("openbao-state/tls/ca.crt"), true),
            ),
            ("/output".into(), (output.clone(), false)),
        ]),
    };
    let args = command(&contract)?;
    let name_filter = format!("name=^/{}$", contract.name);
    let owner_filter = format!("label=com.elevenid.installer.id={}", contract.owner);
    for filters in [
        vec!["ps", "-aq", "--filter", &name_filter],
        vec![
            "ps",
            "-aq",
            "--filter",
            &owner_filter,
            "--filter",
            "label=com.elevenid.installer.stage=keycloak",
        ],
    ] {
        require(docker.run_checked(&filters)?.trim().is_empty())?;
    }
    let secrets = directory(&installation.join("secrets"))?;
    for name in OUTPUTS {
        let name = CString::new(name).unwrap();
        let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                secrets.as_raw_fd(),
                name.as_ptr(),
                m.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        require(
            result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        )?;
    }
    state.create_private_directory("keycloak-output")?;
    let output_directory = directory(&output)?;
    let intent = json!({"schema":"elevenid.installer-keycloak-intent/v1","installation_id":contract.owner,"container_name":contract.name,"image":contract.image,"network_id":contract.network_id,"engine_id":binding.engine_id,"nonce":contract.nonce,"operator_sha256":expected_operator_sha,"mounts":contract.mounts});
    state.write_evidence(
        "keycloak-pending.json",
        &serde_json::to_vec(&intent).map_err(|_| REFUSAL)?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let created = run(&docker, &args)?;
    let container = created.trim();
    require(id(container))?;
    state.write_evidence("keycloak-container.json",&serde_json::to_vec(&json!({"container_id":container,"container_name":contract.name,"engine_id":binding.engine_id})).map_err(|_|REFUSAL)?)?;
    validate_observation(&inspect(&docker, container)?, container, &contract, false)?;
    require(
        installer_verify::operator_digest(&installation.join("marty-deploy"))?
            == expected_operator_sha,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    docker.run_checked(&["start", container])?;
    require(
        docker
            .run_checked_with_timeout(&["wait", container], Duration::from_secs(600))?
            .trim()
            == "0",
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let outputs = read_outputs(
        &output_directory,
        installer_helper_output::expected_host_uid(&binding)?.uid(),
    )?;
    transfer(&secrets, &outputs)?;
    let mut receipt = KeycloakReceipt {
        schema: "elevenid.installer-keycloak/v1",
        installation_id: contract.owner.clone(),
        engine_id: binding.engine_id,
        container_id: container.to_owned(),
        container_name: contract.name.clone(),
        network_id: contract.network_id.clone(),
        image: contract.image.clone(),
        nonce: contract.nonce.clone(),
        outputs: OUTPUTS.into_iter().map(str::to_owned).collect(),
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "keycloak-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
    docker.run_checked(&["rm", container])?;
    let filter = format!("id={container}");
    require(
        docker
            .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &filter])?
            .trim()
            .is_empty(),
    )?;
    receipt.container_removed = true;
    state.write_evidence(
        "keycloak-container-removed.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn contract() -> Contract {
        Contract {
            name: "marty-install-owned-keycloak-inputs".into(),
            owner: "installation-uuid".into(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
                "a".repeat(64)
            ),
            image_id: format!("sha256:{}", "b".repeat(64)),
            network_id: "c".repeat(64),
            network_name: "owned-bao_default".into(),
            nonce: "0123456789ab".into(),
            mounts: BTreeMap::from([
                (
                    "/input/marty-deploy".into(),
                    (PathBuf::from("/owned/marty-deploy"), true),
                ),
                (
                    "/input/root.token".into(),
                    (PathBuf::from("/owned/openbao-state/root.token"), true),
                ),
                (
                    "/input/ca.crt".into(),
                    (PathBuf::from("/owned/openbao-state/tls/ca.crt"), true),
                ),
                (
                    "/output".into(),
                    (PathBuf::from("/owned/keycloak-output"), false),
                ),
            ]),
        }
    }
    fn observed(contract: &Contract, terminal: bool) -> Value {
        let mounts:Vec<_>=contract.mounts.iter().map(|(target,(source,readonly))|json!({"Type":"bind","Source":source,"Destination":target,"RW":!readonly})).collect();
        let mut networks = serde_json::Map::new();
        networks.insert(
            contract.network_name.clone(),
            json!({"NetworkID":if terminal {contract.network_id.clone()} else {String::new()}}),
        );
        json!({"Id":"d".repeat(64),"Image":contract.image_id,"Name":format!("/{}",contract.name),
            "Config":{"Image":contract.image,"User":"0:0","Entrypoint":["/input/marty-deploy"],"Cmd":["installer-keycloak-bridge","--nonce",contract.nonce],"Labels":{"com.elevenid.installer.id":contract.owner,"com.elevenid.installer.stage":"keycloak"}},
            "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":["DAC_OVERRIDE"],"SecurityOpt":["no-new-privileges"],"NetworkMode":contract.network_id,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"PidMode":"","UsernsMode":"","IpcMode":"private","Binds":null,"PortBindings":{},"Devices":[],"DeviceRequests":null,"Tmpfs":scratch_configuration()},
            "NetworkSettings":{"Networks":networks},"Mounts":mounts,"State":{"Running":false,"Status":if terminal {"exited"} else {"created"},"ExitCode":0,"OOMKilled":false}})
    }
    #[test]
    fn create_has_only_narrow_mounts_and_no_automatic_removal() {
        let mut c = contract();
        let args = command(&c).unwrap();
        assert_eq!(args[0], "create");
        assert!(!args
            .iter()
            .any(|v| v == "--rm" || v == "--force" || v == "--privileged"));
        assert_eq!(args.iter().filter(|v| v.as_str() == "--mount").count(), 4);
        assert_eq!(args.iter().filter(|v| v.as_str() == "--tmpfs").count(), 2);
        for path in SCRATCH_PATHS {
            assert!(args
                .windows(2)
                .any(|v| v == ["--tmpfs", &format!("{path}:{SCRATCH_OPTIONS}")]));
        }
        assert!(args.contains(&"DAC_OVERRIDE".into()));
        c.mounts.get_mut("/output").unwrap().0 = PathBuf::from("/owned/comma,path");
        assert!(command(&c).is_err());
    }
    #[test]
    fn inherited_image_volumes_require_exact_bounded_scratch_closure() {
        image_volumes(&json!({"Config":{"Volumes":{"/openbao/file":{},"/openbao/logs":{}}}}))
            .unwrap();
        for volumes in [
            Value::Null,
            json!({}),
            json!({"/openbao/file":{}}),
            json!({"/openbao/file":{},"/openbao/logs":{},"/foreign":{}}),
            json!({"/openbao/file":{"size":1},"/openbao/logs":{}}),
        ] {
            assert!(image_volumes(&json!({"Config":{"Volumes":volumes}})).is_err());
        }
        let contract = contract();
        let container = "d".repeat(64);
        for tmpfs in [
            Value::Null,
            json!({}),
            json!({"/openbao/file":SCRATCH_OPTIONS}),
            json!({"/openbao/file":"rw,size=1048576","/openbao/logs":SCRATCH_OPTIONS}),
            json!({"/openbao/file":SCRATCH_OPTIONS,"/openbao/logs":SCRATCH_OPTIONS,"/tmp":SCRATCH_OPTIONS}),
        ] {
            let mut observed = observed(&contract, false);
            observed["HostConfig"]["Tmpfs"] = tmpfs;
            assert!(validate_observation(&observed, &container, &contract, false).is_err());
        }
        let mut anonymous = observed(&contract, true);
        anonymous["Mounts"].as_array_mut().unwrap().push(
            json!({"Type":"volume","Source":"/foreign","Destination":"/openbao/file","RW":true}),
        );
        assert!(validate_observation(&anonymous, &container, &contract, true).is_err());
    }
    #[test]
    fn exact_created_and_exited_contracts_refuse_mutations() {
        let c = contract();
        let container = "d".repeat(64);
        validate_observation(&observed(&c, false), &container, &c, false).unwrap();
        validate_observation(&observed(&c, true), &container, &c, true).unwrap();
        assert!(validate_observation(&observed(&c, false), &container, &c, true).is_err());
        for mutation in [
            "network",
            "image",
            "image-id",
            "cap",
            "mount-source",
            "mount-access",
            "command",
            "owner",
            "running",
            "exit",
            "restart",
            "socket",
        ] {
            let mut v = observed(&c, true);
            match mutation {
                "network"=>v["NetworkSettings"]["Networks"][&c.network_name]["NetworkID"]=json!("wrong"),
                "image"=>v["Config"]["Image"]=json!("other"),
                "image-id"=>v["Image"]=json!("sha256:wrong"),
                "cap"=>v["HostConfig"]["CapAdd"]=json!(["SYS_ADMIN"]),
                "mount-source"=>v["Mounts"][0]["Source"]=json!("/foreign"),
                "mount-access"=>v["Mounts"][0]["RW"]=json!(true),
                "command"=>v["Config"]["Cmd"]=json!(["operator"]),
                "owner"=>v["Config"]["Labels"]["com.elevenid.installer.id"]=json!("other"),
                "running"=>v["State"]["Running"]=json!(true),
                "exit"=>v["State"]["ExitCode"]=json!(1),
                "restart"=>v["HostConfig"]["RestartPolicy"]["Name"]=json!("always"),
                _=>v["Mounts"].as_array_mut().unwrap().push(json!({"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true})),
            }
            assert!(
                validate_observation(&v, &container, &c, true).is_err(),
                "accepted {mutation}"
            );
        }
    }
    fn private() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn write_outputs(path: &Path) {
        for (index, name) in OUTPUTS.iter().enumerate() {
            let content = if name.ends_with("_token") {
                format!("leaf-{index}-{}", "a".repeat(30))
            } else {
                "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
            };
            let file = path.join(name);
            std::fs::write(&file, content).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
    }
    #[test]
    fn output_transfer_is_exclusive_and_retains_originals() {
        let source = private();
        let destination = private();
        write_outputs(source.path());
        let outputs = read_outputs(&directory(source.path()).unwrap(), unsafe {
            libc::geteuid()
        })
        .unwrap();
        let target = directory(destination.path()).unwrap();
        transfer(&target, &outputs).unwrap();
        assert!(transfer(&target, &outputs).is_err());
        for name in OUTPUTS {
            assert_eq!(
                std::fs::read(source.path().join(name)).unwrap(),
                std::fs::read(destination.path().join(name)).unwrap()
            );
            assert_eq!(
                std::fs::metadata(destination.path().join(name))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o444
            );
        }
    }
    #[test]
    fn rootless_profile_accepts_only_its_expected_host_owner() {
        let uid = unsafe { libc::geteuid() };
        let binding = crate::installer_state::RuntimeBinding {
            docker_host: format!("unix:///run/user/{uid}/docker.sock"),
            engine_id: "engine-identity-123".into(),
            openbao_port: 8200,
            profile: crate::installer_state::RuntimeProfile::Rootless,
        };
        if uid == 0 {
            assert!(installer_helper_output::expected_host_uid(&binding).is_err());
            return;
        }
        let source = private();
        write_outputs(source.path());
        let owner = installer_helper_output::expected_host_uid(&binding)
            .unwrap()
            .uid();
        assert!(read_outputs(&directory(source.path()).unwrap(), owner).is_ok());
        assert!(read_outputs(&directory(source.path()).unwrap(), owner.wrapping_add(1)).is_err());
    }
    #[test]
    fn output_inventory_refuses_links_wrong_owner_modes_and_extra_files() {
        for mutation in [
            "link", "hardlink", "owner", "mode", "extra", "size", "private",
        ] {
            let source = private();
            write_outputs(source.path());
            let path = source.path().join(OUTPUTS[0]);
            let owner = if mutation == "owner" {
                unsafe { libc::geteuid() }.wrapping_add(1)
            } else {
                unsafe { libc::geteuid() }
            };
            match mutation {
                "link" => {
                    std::fs::remove_file(&path).unwrap();
                    symlink(source.path().join(OUTPUTS[3]), &path).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&path, source.path().join("extra-link")).unwrap();
                }
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "extra" => std::fs::write(source.path().join("extra"), b"x").unwrap(),
                "size" | "private" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::write(
                        &path,
                        if mutation == "size" {
                            vec![b'a'; 65537]
                        } else {
                            b"PRIVATE KEY forbidden content".to_vec()
                        },
                    )
                    .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
                        .unwrap();
                }
                _ => (),
            }
            assert!(
                read_outputs(&directory(source.path()).unwrap(), owner).is_err(),
                "accepted {mutation}"
            );
        }
    }
}
