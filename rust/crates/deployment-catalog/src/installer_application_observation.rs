//! Admission of stopped application containers before any workload starts.
//! The caller owns Docker observation, immutable intent/IDs and the installation
//! lock. These predicates never create resources or infer ownership from names.
#![cfg(target_os = "linux")]
use crate::installer_application_model::ApplicationModelPlan;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
pub type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Application observation differs from authenticated owned resources";
#[derive(Clone, Copy)]
pub enum ContainerPhase {
    Created,
    Running,
    ExitedSuccessfully,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| REFUSED.into())
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn empty(v: &Value) -> bool {
    v.is_null()
        || v.as_array().is_some_and(Vec::is_empty)
        || v.as_object().is_some_and(serde_json::Map::is_empty)
}
fn list(v: &Value) -> Result<Vec<String>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    v.as_array()
        .ok_or(REFUSED)?
        .iter()
        .map(|v| text(v).map(str::to_owned))
        .collect()
}
/// Decode only Compose's literal-dollar encoding; reject unresolved variables.
fn literal(s: &str) -> Result<String> {
    let mut chars = s.chars();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        if c == '$' {
            require(chars.next() == Some('$'))?;
        }
        out.push(c);
    }
    Ok(out)
}
fn model_list(v: &Value) -> Result<Vec<String>> {
    list(v)?.iter().map(|s| literal(s)).collect()
}
fn env(v: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for value in list(v)? {
        let (key, value) = value.split_once('=').ok_or(REFUSED)?;
        require(!key.is_empty() && result.insert(key.into(), value.into()).is_none())?;
    }
    Ok(result)
}
fn service<'a>(plan: &'a ApplicationModelPlan, role: &str) -> Result<&'a Value> {
    require(
        !plan.installation_ready
            && (plan.selected_services.iter().any(|s| s == role) || role == "kms-initialize")
            && id(&plan.expected_network_id),
    )?;
    if role == "kms-initialize" {
        let s = &plan.model["services"][role];
        require(
            s["profiles"] == json!(["kms-init"])
                && s["restart"] == "no"
                && s["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] == "true"
                && s["environment"]["BAO_TOKEN_FILE"] == "/run/secrets/openbao_bootstrap_token",
        )?;
    }
    plan.model["services"]
        .get(role)
        .ok_or_else(|| REFUSED.into())
}
fn project(plan: &ApplicationModelPlan) -> Result<&str> {
    text(&plan.model["name"])
}
fn network_name(plan: &ApplicationModelPlan) -> Result<&str> {
    text(&plan.model["networks"]["default"]["name"])
}
fn duration(s: &str) -> Result<u64> {
    let mut remaining = s;
    let mut total = 0u64;
    while !remaining.is_empty() {
        let length = remaining.bytes().take_while(u8::is_ascii_digit).count();
        require(length > 0)?;
        let number: u64 = remaining[..length].parse().map_err(|_| REFUSED)?;
        remaining = &remaining[length..];
        let (unit, multiplier) = [
            ("ns", 1u64),
            ("us", 1000),
            ("µs", 1000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| remaining.starts_with(unit))
        .ok_or(REFUSED)?;
        total = total
            .checked_add(number.checked_mul(multiplier).ok_or(REFUSED)?)
            .ok_or(REFUSED)?;
        remaining = &remaining[unit.len()..];
    }
    Ok(total)
}
fn healthcheck(actual: &Value, service: &Value, base: &Value) -> Result<()> {
    if service.is_null() {
        return require(actual == base || (empty(actual) && empty(base)));
    }
    let expected_test = if service["disable"] == true {
        vec!["NONE".into()]
    } else if service.get("test").is_some() {
        model_list(&service["test"])?
    } else {
        list(&base["Test"])?
    };
    require(list(&actual["Test"])? == expected_test)?;
    for (model, field) in [
        ("interval", "Interval"),
        ("timeout", "Timeout"),
        ("start_period", "StartPeriod"),
        ("start_interval", "StartInterval"),
    ] {
        let expected = if let Some(value) = service.get(model) {
            duration(text(value)?)?
        } else {
            base[field].as_u64().unwrap_or(0)
        };
        require(actual[field].as_u64().unwrap_or(0) == expected)?;
    }
    require(
        actual["Retries"].as_u64().unwrap_or(0)
            == service
                .get("retries")
                .or_else(|| base.get("Retries"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
    )
}
#[derive(Debug, PartialEq, Eq)]
struct Mount {
    source: String,
    kind: String,
    readonly: bool,
}
fn expected_mounts(plan: &ApplicationModelPlan, role: &str) -> Result<BTreeMap<String, Mount>> {
    let s = service(plan, role)?;
    let mut mounts = BTreeMap::new();
    for v in s["volumes"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let kind = text(&v["type"])?;
        require(kind == "bind" || kind == "volume")?;
        let source = if kind == "volume" {
            text(&plan.model["volumes"][text(&v["source"])?]["name"])?.into()
        } else {
            literal(text(&v["source"])?)?
        };
        require(
            mounts
                .insert(
                    text(&v["target"])?.into(),
                    Mount {
                        source,
                        kind: kind.into(),
                        readonly: v["read_only"].as_bool().unwrap_or(false),
                    },
                )
                .is_none(),
        )?;
    }
    for reference in s["secrets"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let source = text(&reference["source"])?;
        let declaration = &plan.model["secrets"][source];
        require(declaration.get("external").is_none())?;
        let target = text(&reference["target"])?;
        let target = if target.starts_with('/') {
            target.into()
        } else {
            format!("/run/secrets/{target}")
        };
        require(
            mounts
                .insert(
                    target,
                    Mount {
                        source: literal(text(&declaration["file"])?)?,
                        kind: "bind".into(),
                        readonly: true,
                    },
                )
                .is_none(),
        )?;
    }
    Ok(mounts)
}
/// Validate fresh source metadata before create and again immediately before start.
/// Root-owned public outputs are accepted only under the exact secrets subtree.
pub fn validate_inputs(
    plan: &ApplicationModelPlan,
    installation: &Path,
    bundle: &Path,
) -> Result<()> {
    crate::installer_runtime::private_parent(installation)?;
    require(bundle.starts_with(installation) && bundle != installation)?;
    let mut paths = BTreeMap::<String, bool>::new();
    for role in plan
        .selected_services
        .iter()
        .map(String::as_str)
        .chain(["kms-initialize"])
    {
        for (_, m) in expected_mounts(plan, role)? {
            if m.kind == "bind" {
                let readonly = paths.entry(m.source).or_insert(true);
                *readonly &= m.readonly;
            }
        }
    }
    for (source, readonly) in paths {
        let path = Path::new(&source);
        require(
            path.is_absolute()
                && path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                && path.starts_with(installation)
                && path != installation,
        )?;
        // Walk each component with held directory fds so no ancestor symlink is followed.
        let relative = path.strip_prefix(installation).map_err(|_| REFUSED)?;
        let components: Vec<_> = relative.components().collect();
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(installation)
            .map_err(|_| REFUSED)?;
        for (index, component) in components.iter().enumerate() {
            let name = std::ffi::CString::new(component.as_os_str().as_encoded_bytes())
                .map_err(|_| REFUSED)?;
            let last = index + 1 == components.len();
            let fd = unsafe {
                libc::openat(
                    std::os::fd::AsRawFd::as_raw_fd(&parent),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_CLOEXEC
                        | if last { 0 } else { libc::O_DIRECTORY },
                )
            };
            require(fd >= 0)?;
            let file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
            let m = file.metadata().map_err(|_| REFUSED)?;
            require(m.uid() == unsafe { libc::geteuid() } || m.uid() == 0)?;
            require(m.mode() & 0o7022 == 0)?;
            if last {
                require(m.is_file() || m.is_dir())?;
                if m.is_file() {
                    require(m.nlink() == 1 && readonly)?;
                }
                if path.starts_with(installation.join("secrets")) {
                    require(m.is_file() && matches!(m.mode() & 0o7777, 0o444 | 0o644))?;
                } else if path.starts_with(bundle) {
                    require(readonly && m.uid() == unsafe { libc::geteuid() })?;
                } else if path.starts_with(installation.join("state")) {
                    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() })?;
                } else {
                    require(
                        path == installation.join("evidence/installer-nginx.conf")
                            && readonly
                            && m.is_file()
                            && m.uid() == unsafe { libc::geteuid() }
                            && m.mode() & 0o7777 == 0o600,
                    )?;
                }
            } else {
                require(m.is_dir())?;
            }
            parent = file;
        }
    }
    Ok(())
}
/// `image` is the one authoritative image-inspect object, not a caller digest hint.
pub fn validate_container(
    c: &Value,
    container_id: &str,
    role: &str,
    plan: &ApplicationModelPlan,
    image: &Value,
    phase: ContainerPhase,
) -> Result<()> {
    validate_container_inner(
        c,
        container_id,
        role,
        plan,
        image,
        phase,
        ObservationKind::Application,
    )
}

/// Diagnostics validate ownership/configuration even for failed workloads.
/// This deliberately makes no running, successful exit, or readiness assertion.
pub(crate) fn validate_container_for_logs(
    c: &Value,
    container_id: &str,
    role: &str,
    plan: &ApplicationModelPlan,
    image: &Value,
) -> Result<()> {
    validate_container_inner(
        c,
        container_id,
        role,
        plan,
        image,
        ContainerPhase::Created,
        ObservationKind::Diagnostic,
    )
}

enum ObservationKind {
    Application,
    OpenBao,
    Diagnostic,
    OpenBaoDiagnostic,
}

/// Cleanup may inspect failed Bao workloads; ownership/configuration admission
/// remains identical. This predicate does not itself authorize any removal.
pub(crate) fn validate_openbao_container_for_cleanup(
    c: &Value,
    container_id: &str,
    role: &str,
    plan: &ApplicationModelPlan,
    image: &Value,
) -> Result<()> {
    require(
        [
            "openbao",
            "openbao-tls-init",
            "openbao-bootstrap",
            "openbao-unseal",
        ]
        .contains(&role)
            && project(plan)?.ends_with("-bao"),
    )?;
    validate_container_inner(
        c,
        container_id,
        role,
        plan,
        image,
        ContainerPhase::Created,
        ObservationKind::OpenBaoDiagnostic,
    )
}

/// Same identity and execution admission for the separately owned Bao project.
/// Its sole permitted publication is the server's fixed 8200 loopback mapping.
pub(crate) fn validate_openbao_container(
    c: &Value,
    container_id: &str,
    role: &str,
    plan: &ApplicationModelPlan,
    image: &Value,
    phase: ContainerPhase,
) -> Result<()> {
    require(
        [
            "openbao",
            "openbao-tls-init",
            "openbao-bootstrap",
            "openbao-unseal",
        ]
        .contains(&role)
            && project(plan)?.ends_with("-bao"),
    )?;
    validate_container_inner(
        c,
        container_id,
        role,
        plan,
        image,
        phase,
        ObservationKind::OpenBao,
    )
}

fn validate_container_inner(
    c: &Value,
    container_id: &str,
    role: &str,
    plan: &ApplicationModelPlan,
    image: &Value,
    phase: ContainerPhase,
    kind: ObservationKind,
) -> Result<()> {
    let bao = matches!(
        kind,
        ObservationKind::OpenBao | ObservationKind::OpenBaoDiagnostic
    );
    let diagnostic = matches!(
        kind,
        ObservationKind::Diagnostic | ObservationKind::OpenBaoDiagnostic
    );
    let s = service(plan, role)?;
    let p = project(plan)?;
    let config = &c["Config"];
    let host = &c["HostConfig"];
    let image_ref = text(&s["image"])?;
    let image_id = text(&image["Id"])?;
    require(
        id(container_id)
            && image_id.strip_prefix("sha256:").is_some_and(id)
            && image["RepoDigests"]
                .as_array()
                .is_some_and(|v| v.contains(&json!(image_ref))),
    )?;
    require(
        c["Id"] == container_id
            && c["Image"] == image_id
            && config["Image"] == image_ref
            && c["Name"] == format!("/{p}-{role}-1"),
    )?;
    let labels = config["Labels"].as_object().ok_or(REFUSED)?;
    require(
        labels.get("com.docker.compose.project") == Some(&json!(p))
            && labels.get("com.docker.compose.service") == Some(&json!(role))
            && labels.get("com.docker.compose.container-number") == Some(&json!("1"))
            && labels.get("com.docker.compose.oneoff") == Some(&json!("False")),
    )?;
    let mut expected_labels = serde_json::Map::new();
    for source in [&image["Config"]["Labels"], &s["labels"]] {
        if let Some(expected) = source.as_object() {
            expected_labels.extend(expected.clone());
        }
    }
    for (key, value) in expected_labels {
        require(labels.get(&key) == Some(&value))?;
    }
    let base = &image["Config"];
    let entry = if s.get("entrypoint").is_some_and(|v| !v.is_null()) {
        model_list(&s["entrypoint"])?
    } else {
        list(&base["Entrypoint"])?
    };
    let command = if s.get("command").is_some_and(|v| !v.is_null()) {
        model_list(&s["command"])?
    } else if s.get("entrypoint").is_some_and(|v| !v.is_null()) {
        vec![]
    } else {
        list(&base["Cmd"])?
    };
    require(list(&config["Entrypoint"])? == entry && list(&config["Cmd"])? == command)?;
    let mut environment = env(&base["Env"])?;
    if let Some(values) = s["environment"].as_object() {
        for (key, value) in values {
            environment.insert(key.clone(), literal(text(value)?)?);
        }
    }
    require(env(&config["Env"])? == environment)?;
    healthcheck(
        &config["Healthcheck"],
        &s["healthcheck"],
        &base["Healthcheck"],
    )?;
    for (field, model) in [("User", "user"), ("WorkingDir", "working_dir")] {
        let expected = if let Some(v) = s.get(model) {
            literal(text(v)?)?
        } else {
            base[field].as_str().unwrap_or("").into()
        };
        require(config[field].as_str().unwrap_or("") == expected)?;
    }
    require(
        host["Privileged"] == false
            && host["ReadonlyRootfs"].as_bool() == Some(s["read_only"].as_bool().unwrap_or(false))
            && host["AutoRemove"] == false
            && host["RestartPolicy"]["Name"] == s["restart"],
    )?;
    require(
        empty(&host["CapAdd"])
            && list(&host["CapDrop"])? == list(&s["cap_drop"])?
            && list(&host["SecurityOpt"])? == list(&s["security_opt"])?
            && empty(&host["Devices"])
            && empty(&host["DeviceRequests"])
            && empty(&host["VolumesFrom"]),
    )?;
    if bao {
        require(
            host["Tmpfs"]
                == json!({
                    "/openbao/file": "rw,noexec,nosuid,nodev,size=1048576,mode=0700",
                    "/openbao/logs": "rw,noexec,nosuid,nodev,size=1048576,mode=0700"
                }),
        )?;
    } else {
        require(empty(&host["Tmpfs"]))?;
    }
    for field in ["PidMode", "UsernsMode", "UTSMode"] {
        require(host[field].as_str().unwrap_or("").is_empty())?;
    }
    require(
        matches!(host["IpcMode"].as_str(), Some("private" | ""))
            && host["NetworkMode"] == network_name(plan)?,
    )?;
    let networks = c["NetworkSettings"]["Networks"]
        .as_object()
        .ok_or(REFUSED)?;
    require(networks.len() == 1 && networks.contains_key(network_name(plan)?))?;
    let attached = &networks[network_name(plan)?];
    // Compose's default network aliases are the generated container name and
    // service name. Refuse added aliases such as another service or "openbao".
    let aliases = list(&attached["Aliases"])?;
    require(
        aliases.len() == 2
            && aliases.into_iter().collect::<BTreeSet<_>>()
                == BTreeSet::from([format!("{p}-{role}-1"), role.to_owned()]),
    )?;
    require(empty(&attached["Links"]))?;
    for field in ["ExtraHosts", "Dns", "DnsSearch", "DnsOptions", "Links"] {
        require(empty(&host[field]))?;
    }
    let netid = &networks[network_name(plan)?]["NetworkID"];
    let detached = if diagnostic {
        matches!(
            c["State"]["Status"].as_str(),
            Some("created" | "exited" | "dead")
        )
    } else {
        matches!(phase, ContainerPhase::Created)
    };
    require(netid == &json!(plan.expected_network_id) || (detached && netid == ""))?;
    let mut actual = BTreeMap::new();
    for m in c["Mounts"].as_array().ok_or(REFUSED)? {
        let kind = text(&m["Type"])?;
        require(kind == "bind" || kind == "volume")?;
        let source = if kind == "volume" {
            require(m["Driver"] == "local")?;
            text(&m["Name"])?
        } else {
            require(m["Propagation"] == "rprivate")?;
            text(&m["Source"])?
        };
        require(
            actual
                .insert(
                    text(&m["Destination"])?.into(),
                    Mount {
                        source: source.into(),
                        kind: kind.into(),
                        readonly: !m["RW"].as_bool().ok_or(REFUSED)?,
                    },
                )
                .is_none(),
        )?;
    }
    require(actual == expected_mounts(plan, role)?)?;
    let mut ports = serde_json::Map::new();
    let (published_role, published_target) = if bao {
        ("openbao", 8200)
    } else {
        ("installer-ingress", 8443)
    };
    for port in s["ports"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        require(
            role == published_role
                && port["host_ip"] == "127.0.0.1"
                && port["target"] == published_target
                && port["protocol"] == "tcp",
        )?;
        let published = text(&port["published"])?;
        let n: u16 = published.parse().map_err(|_| REFUSED)?;
        require(n >= 1024 && n.to_string() == published)?;
        require(
            ports
                .insert(
                    format!("{published_target}/tcp"),
                    json!([{"HostIp":"127.0.0.1","HostPort":published}]),
                )
                .is_none(),
        )?;
    }
    require(
        (ports.is_empty() && empty(&host["PortBindings"]))
            || host["PortBindings"] == Value::Object(ports.clone()),
    )?;
    if let Some(observed) = c["NetworkSettings"]["Ports"].as_object() {
        for (port, bindings) in observed {
            require(bindings.is_null() || ports.get(port) == Some(bindings))?;
        }
    }
    if matches!(phase, ContainerPhase::Running) {
        for (port, bindings) in &ports {
            require(c["NetworkSettings"]["Ports"].get(port) == Some(bindings))?;
        }
    }
    if diagnostic {
        return require(matches!(
            c["State"]["Status"].as_str(),
            Some("created" | "running" | "exited" | "paused" | "restarting" | "dead")
        ));
    }
    require(
        c["State"]["OOMKilled"] == false
            && c["State"]["Paused"] == false
            && c["State"]["Restarting"] == false,
    )?;
    match phase {
        ContainerPhase::Created => {
            require(c["State"]["Status"] == "created" && c["State"]["Running"] == false)
        }
        ContainerPhase::Running => {
            require(c["State"]["Status"] == "running" && c["State"]["Running"] == true)
        }
        ContainerPhase::ExitedSuccessfully => require(
            c["State"]["Status"] == "exited"
                && c["State"]["Running"] == false
                && c["State"]["ExitCode"] == 0,
        ),
    }
}
pub fn validate_volume(v: &Value, plan: &ApplicationModelPlan) -> Result<()> {
    require(
        v["Name"] == plan.model["volumes"]["redis-socket"]["name"]
            && v["Driver"] == "local"
            && v["Scope"] == "local"
            && empty(&v["Options"])
            && v["Labels"]["com.docker.compose.project"] == project(plan)?
            && v["Labels"]["com.docker.compose.volume"] == "redis-socket",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> (ApplicationModelPlan, Value, Value) {
        let digest = format!("ghcr.io/elevenid/services@sha256:{}", "a".repeat(64));
        let image_id = format!("sha256:{}", "b".repeat(64));
        let plan = ApplicationModelPlan {
            model: json!({"name":"owned","networks":{"default":{"name":"owned-bao_default","external":true}},
                "volumes":{"redis-socket":{"name":"owned_redis-socket"}},
                "secrets":{"token":{"file":"/private/install $$literal/secrets/token"}},
                "services":{"app":{"image":digest,"restart":"no","command":["serve","$$VALUE"],
                    "environment":{"SETTING":"$$literal"},"secrets":[{"source":"token","target":"/run/secrets/token"}],
                    "healthcheck":{"test":["CMD","true"],"interval":"1m30s","timeout":"5s","retries":3}}}}),
            selected_services: vec!["app".into()],
            expected_network_id: "c".repeat(64),
            installation_ready: false,
        };
        let image = json!({"Id":image_id,"RepoDigests":[digest],"Config":{"Env":["BASE=base"],"Entrypoint":["/entry"],"Cmd":["old"],"User":"","WorkingDir":"/app"}});
        let observed = json!({"Id":"d".repeat(64),"Image":image_id,"Name":"/owned-app-1",
            "Config":{"Image":digest,"Labels":{"com.docker.compose.project":"owned","com.docker.compose.service":"app","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False"},
            "Env":["BASE=base","SETTING=$literal"],"Entrypoint":["/entry"],"Cmd":["serve","$VALUE"],"User":"","WorkingDir":"/app",
            "Healthcheck":{"Test":["CMD","true"],"Interval":90_000_000_000u64,"Timeout":5_000_000_000u64,"Retries":3}},
            "HostConfig":{"Privileged":false,"ReadonlyRootfs":false,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"IpcMode":"private","NetworkMode":"owned-bao_default"},
            "NetworkSettings":{"Networks":{"owned-bao_default":{"NetworkID":"","Aliases":["owned-app-1","app"]}},"Ports":{"80/tcp":null}},
            "Mounts":[{"Type":"bind","Source":"/private/install $literal/secrets/token","Destination":"/run/secrets/token","RW":false,"Propagation":"rprivate"}],
            "State":{"Status":"created","Running":false,"Paused":false,"Restarting":false,"OOMKilled":false}});
        (plan, image, observed)
    }
    #[test]
    fn binds_actual_identity_mounts_execution_and_phase() {
        let (plan, image, c) = fixture();
        let id = "d".repeat(64);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
        for (pointer, value) in [
            ("/Image", json!(format!("sha256:{}", "e".repeat(64)))),
            (
                "/Config/Labels/com.docker.compose.project",
                json!("foreign"),
            ),
            ("/Config/Cmd", json!(["sh"])),
            ("/Config/Env", json!(["BASE=base", "SETTING=interpolated"])),
            ("/Config/Healthcheck/Test", json!(["CMD", "false"])),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/IpcMode", json!("host")),
            ("/Mounts/0/Source", json!("/etc/shadow")),
            ("/Mounts/0/RW", json!(true)),
            ("/Mounts/0/Propagation", json!("rshared")),
            (
                "/NetworkSettings/Networks/owned-bao_default/NetworkID",
                json!("e".repeat(64)),
            ),
            (
                "/NetworkSettings/Networks/owned-bao_default/Aliases",
                json!(["owned-app-1", "openbao"]),
            ),
        ] {
            let mut changed = c.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_container(&changed, &id, "app", &plan, &image, ContainerPhase::Created)
                    .is_err(),
                "{pointer}"
            );
        }
        let mut running = c;
        running["State"]["Status"] = json!("running");
        running["State"]["Running"] = json!(true);
        assert!(
            validate_container(&running, &id, "app", &plan, &image, ContainerPhase::Running)
                .is_err()
        );
        running["NetworkSettings"]["Networks"]["owned-bao_default"]["NetworkID"] =
            json!(plan.expected_network_id);
        validate_container(&running, &id, "app", &plan, &image, ContainerPhase::Running).unwrap();
    }
    #[test]
    fn diagnostics_admit_failed_states_without_weakening_resource_identity() {
        let (plan, image, mut c) = fixture();
        let id = "d".repeat(64);
        c["State"]["Status"] = json!("exited");
        c["State"]["ExitCode"] = json!(137);
        c["State"]["OOMKilled"] = json!(true);
        validate_container_for_logs(&c, &id, "app", &plan, &image).unwrap();
        c["State"]["Status"] = json!("running");
        assert!(validate_container_for_logs(&c, &id, "app", &plan, &image).is_err());
        c["NetworkSettings"]["Networks"]["owned-bao_default"]["NetworkID"] =
            json!(plan.expected_network_id);
        validate_container_for_logs(&c, &id, "app", &plan, &image).unwrap();
        c["State"]["Status"] = json!("exited");
        assert!(validate_container(
            &c,
            &id,
            "app",
            &plan,
            &image,
            ContainerPhase::ExitedSuccessfully
        )
        .is_err());
        c["HostConfig"]["Privileged"] = json!(true);
        assert!(validate_container_for_logs(&c, &id, "app", &plan, &image).is_err());
        c["HostConfig"]["Privileged"] = json!(false);
        c["State"]["Status"] = json!("removing");
        assert!(validate_container_for_logs(&c, &id, "app", &plan, &image).is_err());
    }
    #[test]
    fn bao_port_exception_is_scoped_to_the_server_and_owned_project() {
        let (mut plan, image, mut c) = fixture();
        plan.model["name"] = json!("owned-bao");
        let service = plan.model["services"]
            .as_object_mut()
            .unwrap()
            .remove("app")
            .unwrap();
        plan.model["services"]["openbao"] = service;
        plan.model["services"]["openbao"]["ports"] =
            json!([{"host_ip":"127.0.0.1","target":8200,"published":"18200","protocol":"tcp"}]);
        plan.selected_services = vec!["openbao".into()];
        c["Name"] = json!("/owned-bao-openbao-1");
        c["Config"]["Labels"]["com.docker.compose.project"] = json!("owned-bao");
        c["Config"]["Labels"]["com.docker.compose.service"] = json!("openbao");
        c["NetworkSettings"]["Networks"]["owned-bao_default"]["Aliases"] =
            json!(["owned-bao-openbao-1", "openbao"]);
        c["HostConfig"]["PortBindings"] =
            json!({"8200/tcp":[{"HostIp":"127.0.0.1","HostPort":"18200"}]});
        c["HostConfig"]["Tmpfs"] = json!({
            "/openbao/file":"rw,noexec,nosuid,nodev,size=1048576,mode=0700",
            "/openbao/logs":"rw,noexec,nosuid,nodev,size=1048576,mode=0700"
        });
        let cid = "d".repeat(64);
        validate_openbao_container(&c, &cid, "openbao", &plan, &image, ContainerPhase::Created)
            .unwrap();
        for tmpfs in [
            json!({}),
            json!({"/openbao/file":"rw"}),
            json!({"/foreign":"rw"}),
        ] {
            let mut changed = c.clone();
            changed["HostConfig"]["Tmpfs"] = tmpfs;
            assert!(validate_openbao_container(
                &changed,
                &cid,
                "openbao",
                &plan,
                &image,
                ContainerPhase::Created
            )
            .is_err());
        }
        assert!(
            validate_container(&c, &cid, "openbao", &plan, &image, ContainerPhase::Created)
                .is_err()
        );
        for (field, value) in [
            ("host_ip", json!("0.0.0.0")),
            ("target", json!(8443)),
            ("protocol", json!("udp")),
        ] {
            let original = plan.model["services"]["openbao"]["ports"][0][field].clone();
            plan.model["services"]["openbao"]["ports"][0][field] = value;
            assert!(validate_openbao_container(
                &c,
                &cid,
                "openbao",
                &plan,
                &image,
                ContainerPhase::Created
            )
            .is_err());
            plan.model["services"]["openbao"]["ports"][0][field] = original;
        }
        plan.model["name"] = json!("other");
        assert!(validate_openbao_container(
            &c,
            &cid,
            "openbao",
            &plan,
            &image,
            ContainerPhase::Created
        )
        .is_err());
    }
    #[test]
    fn rejects_extra_mounts_ports_capabilities_and_unselected_roles() {
        let (plan, image, c) = fixture();
        let id = "d".repeat(64);
        for (key, value) in [
            ("CapAdd", json!(["SYS_ADMIN"])),
            ("ExtraHosts", json!(["openbao:127.0.0.1"])),
            ("Dns", json!(["127.0.0.1"])),
            ("PidMode", json!("host")),
            ("DeviceRequests", json!([{}])),
            (
                "PortBindings",
                json!({"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}),
            ),
        ] {
            let mut changed = c.clone();
            changed["HostConfig"][key] = value;
            assert!(validate_container(
                &changed,
                &id,
                "app",
                &plan,
                &image,
                ContainerPhase::Created
            )
            .is_err());
        }
        let mut changed = c.clone();
        changed["Mounts"].as_array_mut().unwrap().push(json!({"Type":"bind","Source":"/var/run/docker.sock","Destination":"/docker.sock","RW":false,"Propagation":"rprivate"}));
        assert!(
            validate_container(&changed, &id, "app", &plan, &image, ContainerPhase::Created)
                .is_err()
        );
        assert!(validate_container(
            &c,
            &id,
            "cloudflared",
            &plan,
            &image,
            ContainerPhase::Created
        )
        .is_err());
        assert!(validate_container(
            &c,
            &id,
            "kms-initialize",
            &plan,
            &image,
            ContainerPhase::Created
        )
        .is_err());
    }
    #[test]
    fn volume_requires_exact_local_owned_identity_without_driver_options() {
        let (plan, _, _) = fixture();
        let v = json!({"Name":"owned_redis-socket","Driver":"local","Scope":"local","Options":null,"Labels":{"com.docker.compose.project":"owned","com.docker.compose.volume":"redis-socket"}});
        validate_volume(&v, &plan).unwrap();
        for (key, value) in [
            ("Name", json!("foreign")),
            ("Driver", json!("nfs")),
            ("Options", json!({"device":"/etc","o":"bind"})),
        ] {
            let mut changed = v.clone();
            changed[key] = value;
            assert!(validate_volume(&changed, &plan).is_err());
        }
    }
    #[test]
    fn literal_encoding_and_duration_are_closed() {
        assert_eq!(literal("/owned/$$HOME/$$$$").unwrap(), "/owned/$HOME/$$");
        for value in ["$HOME", "${HOME}", "$$$"] {
            assert!(literal(value).is_err());
        }
        assert_eq!(duration("1m30s").unwrap(), 90_000_000_000);
        assert!(duration("10fortnights").is_err());
        assert!(duration("18446744073709551615h").is_err());
    }
    #[test]
    fn filesystem_preflight_refuses_links_and_unreadable_public_output() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["bundle", "secrets"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
            std::fs::set_permissions(
                root.path().join(name),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let path = root.path().join("secrets/token");
        std::fs::write(&path, b"scoped-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let (mut plan, _, _) = fixture();
        plan.model["secrets"]["token"]["file"] = json!(path.to_str().unwrap().replace('$', "$$"));
        plan.model["services"]["kms-initialize"] = json!({"profiles":["kms-init"],"restart":"no","environment":{"MARTY_KMS_BOOTSTRAP_ENABLED":"true","BAO_TOKEN_FILE":"/run/secrets/openbao_bootstrap_token"}});
        validate_inputs(&plan, root.path(), &root.path().join("bundle")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_inputs(&plan, root.path(), &root.path().join("bundle")).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(validate_inputs(&plan, root.path(), &root.path().join("bundle")).is_err());
    }
}
