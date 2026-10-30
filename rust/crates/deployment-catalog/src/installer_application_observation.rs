//! Admission of stopped application containers before any workload starts.
//! The caller owns Docker observation, immutable intent/IDs and the installation
//! lock. These predicates never create resources or infer ownership from names.
#![cfg(target_os = "linux")]
use crate::installer_application_model::ApplicationModelPlan;
use crate::installer_state::ApplicantContainerGroup;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
pub type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Application observation differs from authenticated owned resources";

// Docker may print a Hub RepoDigest without docker.io and the official-image
// library namespace. Normalize those defaults only, never a foreign registry,
// digest, tag, or the container's recorded Config.Image.
// Default naming: https://docs.docker.com/reference/cli/docker/image/tag/
fn canonical_repo_digest(reference: &str) -> Option<String> {
    if reference.len() > 512 {
        return None;
    }
    let (repository, digest) = reference.split_once("@sha256:")?;
    if !id(digest) {
        return None;
    }
    let (first, rest) = repository.split_once('/').unwrap_or((repository, ""));
    let explicit_registry = first.contains('.') || first.contains(':') || first == "localhost";
    let (registry, path) = if explicit_registry {
        (first, rest)
    } else {
        ("docker.io", repository)
    };
    if registry.is_empty()
        || !registry
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
    {
        return None;
    }
    static COMPONENT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let component = COMPONENT
        .get_or_init(|| regex::Regex::new(r"\A[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\z").unwrap());
    if !path.split('/').all(|part| component.is_match(part)) {
        return None;
    }
    let path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path.into()
    };
    Some(format!("{registry}/{path}@sha256:{digest}"))
}

/// Bind inspected image identity and repository digest, accounting only for
/// Docker Hub's omitted default registry/namespace in RepoDigests output.
pub(crate) fn validate_image_digest(image: &Value, reference: &str) -> Result<()> {
    let expected = canonical_repo_digest(reference).ok_or(REFUSED)?;
    require(
        image["Id"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .is_some_and(id)
            && image["RepoDigests"].as_array().is_some_and(|entries| {
                entries.iter().any(|value| {
                    value.as_str().and_then(canonical_repo_digest).as_ref() == Some(&expected)
                })
            }),
    )
}
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
    applicant_group: ApplicantContainerGroup,
) -> Result<()> {
    validate_inputs_with_generation(plan, installation, bundle, applicant_group, None)
}

pub fn validate_inputs_with_generation(
    plan: &ApplicationModelPlan,
    installation: &Path,
    bundle: &Path,
    applicant_group: ApplicantContainerGroup,
    generation: Option<&crate::installer_generation_binding::GenerationBinding>,
) -> Result<()> {
    let generation_dir = if let Some(binding) = generation {
        crate::installer_generation_binding::verify_model(installation, binding, plan)?;
        Some(binding.secret_dir(installation)?)
    } else {
        None
    };
    crate::installer_runtime::private_parent(installation)?;
    require(bundle.starts_with(installation) && bundle != installation)?;
    let mut paths = BTreeMap::<String, bool>::new();
    for role in plan
        .selected_services
        .iter()
        .map(String::as_str)
        .chain(["kms-initialize"])
    {
        for (target, m) in expected_mounts(plan, role)? {
            if m.kind == "bind" {
                if Path::new(&m.source) == installation.join("state/applicant") {
                    require(role == "applicant" && target == "/app/data" && !m.readonly)?;
                }
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
            if last && path == installation.join("state/applicant") {
                // Only this reviewed writable leaf uses the setgid/shared-group
                // contract established by prepare_application_storage. Bind it
                // to the authenticated applicant mount and exact host-group
                // policy; all other inodes retain the generic permission check.
                let gid = applicant_group.host_gid();
                require(
                    gid == crate::installer_state::applicant_state_gid()?
                        && !readonly
                        && plan.model["services"]["applicant"].get("user").is_none()
                        && plan.model["services"]["applicant"]["group_add"]
                            == json!([applicant_group.container_gid().to_string()])
                        && expected_mounts(plan, "applicant")?.get("/app/data")
                            == Some(&Mount {
                                source: source.clone(),
                                kind: "bind".into(),
                                readonly: false,
                            }),
                )?;
                crate::installer_state::require_applicant_storage(&file, gid)?;
            } else {
                require(m.mode() & 0o7022 == 0)?;
            }
            if last {
                require(m.is_file() || m.is_dir())?;
                if m.is_file() {
                    require(m.nlink() == 1 && readonly)?;
                }
                if path.starts_with(installation.join("secrets")) {
                    require(m.is_file() && matches!(m.mode() & 0o7777, 0o444 | 0o644))?;
                } else if generation_dir
                    .as_ref()
                    .is_some_and(|dir| path.parent() == Some(dir.as_path()))
                {
                    require(
                        m.is_file()
                            && readonly
                            && m.uid() == unsafe { libc::geteuid() }
                            && m.mode() & 0o7777 == 0o444,
                    )?;
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
    // New ingress models explicitly require Docker's init process. Compare
    // boolean declarations exactly; a daemon default must not replace them.
    // Historical models omitted init and remain observable only with Docker's
    // unset or false representation, never an unrecorded init process.
    if let Some(expected) = s.get("init") {
        require(expected.is_boolean() && host.get("Init") == Some(expected))?;
    } else {
        require(host["Init"].is_null() || host["Init"] == false)?;
    }
    // Historical cleanup observations may have no declared cap. New source
    // models require it at admission, and each observed container must match.
    if let Some(limit) = s.get("mem_limit") {
        require(
            host["Memory"].as_u64()
                == Some(crate::installer_application_model::memory_limit(limit)?),
        )?;
    }
    let image_ref = text(&s["image"])?;
    let image_id = text(&image["Id"])?;
    require(id(container_id))?;
    validate_image_digest(image, image_ref)?;
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
    fn rootful_applicant_group() -> crate::installer_state::ApplicantContainerGroup {
        use crate::installer_state::{applicant_container_group, RuntimeBinding, RuntimeProfile};
        applicant_container_group(&RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        })
        .unwrap()
    }
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn retained_postgres_digest_accepts_only_hub_default_aliases() {
        // Exact nonsecret Id/RepoDigests projection from the failed engineering
        // trial (Engine29.1.3, Compose2.40.3). This is not a whole-image fixture.
        let actual: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/installer-postgres-image-inspect-projection.json"
        ))
        .unwrap();
        let digest = "a8e042598834300dfaa17a54f695b87b7f25d3490433bbbe2ef3bffbb9747f24";
        let requested = format!("docker.io/library/postgres@sha256:{digest}");
        validate_image_digest(&actual, &requested).unwrap();
        for repository in [
            "postgres",
            "library/postgres",
            "docker.io/postgres",
            "docker.io/library/postgres",
        ] {
            let mut image = actual.clone();
            image["RepoDigests"] = json!([format!("{repository}@sha256:{digest}")]);
            validate_image_digest(&image, &requested).unwrap();
        }
        for bad in [
            format!("evil.example/library/postgres@sha256:{digest}"),
            format!("ghcr.io/library/postgres@sha256:{digest}"),
            format!("registry-1.docker.io/library/postgres@sha256:{digest}"),
            format!("index.docker.io/library/postgres@sha256:{digest}"),
            format!("docker.io:443/library/postgres@sha256:{digest}"),
            format!("team/postgres@sha256:{digest}"),
            format!("postgres/extra@sha256:{digest}"),
            format!("redis@sha256:{digest}"),
            format!("postgres@sha256:{}", "f".repeat(64)),
            format!("postgres:16@sha256:{digest}"),
            format!("docker.io//postgres@sha256:{digest}"),
            format!("docker.io/library/../postgres@sha256:{digest}"),
            format!("Postgres@sha256:{digest}"),
            format!("postgres@sha256:{digest}\n"),
            "postgres:16".into(),
        ] {
            let mut image = actual.clone();
            image["RepoDigests"] = json!([bad]);
            assert!(
                validate_image_digest(&image, &requested).is_err(),
                "accepted {bad}"
            );
        }
        for bad in [Value::Null, json!([]), json!([null]), json!([actual["Id"]])] {
            let mut image = actual.clone();
            image["RepoDigests"] = bad;
            assert!(validate_image_digest(&image, &requested).is_err());
        }
        let mut bad_id = actual;
        bad_id["Id"] = json!("sha256:short");
        assert!(validate_image_digest(&bad_id, &requested).is_err());
    }
    #[test]
    fn hub_digest_alias_does_not_relax_container_config_or_image_identity() {
        let (mut plan, mut image, mut observed) = fixture();
        let requested = format!("docker.io/library/postgres@sha256:{}", "a".repeat(64));
        plan.model["services"]["app"]["image"] = json!(requested);
        observed["Config"]["Image"] = json!(requested);
        image["RepoDigests"] = json!([format!("postgres@sha256:{}", "a".repeat(64))]);
        let id = "d".repeat(64);
        validate_container(
            &observed,
            &id,
            "app",
            &plan,
            &image,
            ContainerPhase::Created,
        )
        .unwrap();
        validate_container_for_logs(&observed, &id, "app", &plan, &image).unwrap();
        let mut changed = observed.clone();
        changed["Config"]["Image"] = image["RepoDigests"][0].clone();
        assert!(validate_container_for_logs(&changed, &id, "app", &plan, &image).is_err());
        changed = observed;
        changed["Image"] = json!(format!("sha256:{}", "e".repeat(64)));
        assert!(validate_container_for_logs(&changed, &id, "app", &plan, &image).is_err());
        let private = format!("ghcr.io/team/postgres@sha256:{}", "a".repeat(64));
        assert!(validate_image_digest(&image, &private).is_err());
        image["RepoDigests"] = json!([private]);
        validate_image_digest(&image, &private).unwrap();
    }
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
    fn observed_init_requires_the_declared_boolean_in_every_phase() {
        let (mut plan, image, mut c) = fixture();
        let id = "d".repeat(64);
        plan.model["services"]["app"]["init"] = json!(true);
        c["HostConfig"]["Init"] = json!(true);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
        validate_container_for_logs(&c, &id, "app", &plan, &image).unwrap();
        for actual in [
            Value::Null,
            json!(false),
            json!(0),
            json!("true"),
            json!([]),
        ] {
            let mut changed = c.clone();
            changed["HostConfig"]["Init"] = actual;
            assert!(validate_container(
                &changed,
                &id,
                "app",
                &plan,
                &image,
                ContainerPhase::Created
            )
            .is_err());
            assert!(validate_container_for_logs(&changed, &id, "app", &plan, &image).is_err());
        }
        let mut missing = c.clone();
        missing["HostConfig"]
            .as_object_mut()
            .unwrap()
            .remove("Init");
        assert!(
            validate_container(&missing, &id, "app", &plan, &image, ContainerPhase::Created)
                .is_err()
        );
        c["State"]["Status"] = json!("running");
        c["State"]["Running"] = json!(true);
        c["NetworkSettings"]["Networks"]["owned-bao_default"]["NetworkID"] =
            json!(plan.expected_network_id);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Running).unwrap();
        c["HostConfig"]["Init"] = json!(false);
        assert!(
            validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Running).is_err()
        );
        c["State"]["Status"] = json!("exited");
        c["State"]["Running"] = json!(false);
        c["State"]["ExitCode"] = json!(0);
        assert!(validate_container(
            &c,
            &id,
            "app",
            &plan,
            &image,
            ContainerPhase::ExitedSuccessfully
        )
        .is_err());
        c["HostConfig"]["Init"] = json!(true);
        validate_container(
            &c,
            &id,
            "app",
            &plan,
            &image,
            ContainerPhase::ExitedSuccessfully,
        )
        .unwrap();
    }
    #[test]
    fn observed_init_rejects_malformed_policy_and_preserves_legacy_defaults() {
        let (mut plan, image, mut c) = fixture();
        let id = "d".repeat(64);
        // No new init authority is inferred from an old journal without a field.
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
        for actual in [Value::Null, json!(false)] {
            c["HostConfig"]["Init"] = actual;
            validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
            validate_container_for_logs(&c, &id, "app", &plan, &image).unwrap();
        }
        for actual in [json!(true), json!(0), json!("false"), json!({})] {
            c["HostConfig"]["Init"] = actual;
            assert!(validate_container_for_logs(&c, &id, "app", &plan, &image).is_err());
        }
        plan.model["services"]["app"]["init"] = json!(false);
        c["HostConfig"]["Init"] = json!(false);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
        c["HostConfig"]["Init"] = Value::Null;
        assert!(
            validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).is_err()
        );
        for malformed in [Value::Null, json!(0), json!("true"), json!([]), json!({})] {
            plan.model["services"]["app"]["init"] = malformed.clone();
            c["HostConfig"]["Init"] = malformed;
            assert!(
                validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).is_err()
            );
            assert!(validate_container_for_logs(&c, &id, "app", &plan, &image).is_err());
        }
    }
    #[test]
    fn observed_init_does_not_replace_existing_identity_and_security_checks() {
        let (mut plan, image, mut c) = fixture();
        let id = "d".repeat(64);
        plan.model["services"]["app"]["init"] = json!(true);
        c["HostConfig"]["Init"] = json!(true);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
        for (pointer, value) in [
            ("/Image", json!(format!("sha256:{}", "e".repeat(64)))),
            (
                "/Config/Labels/com.docker.compose.project",
                json!("foreign"),
            ),
            ("/Config/Entrypoint", json!(["/unreviewed"])),
            ("/Config/User", json!("0:0")),
            ("/HostConfig/Privileged", json!(true)),
            ("/Mounts/0/RW", json!(true)),
        ] {
            let mut changed = c.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_container(
                &changed,
                &id,
                "app",
                &plan,
                &image,
                ContainerPhase::Created
            )
            .is_err());
            assert!(validate_container_for_logs(&changed, &id, "app", &plan, &image).is_err());
        }
    }
    #[test]
    fn observed_ram_cap_must_match_declared_finite_limit() {
        let (mut plan, image, mut c) = fixture();
        let id = "d".repeat(64);
        plan.model["services"]["app"]["mem_limit"] = json!("536870912");
        for actual in [Value::Null, json!(0), json!(1073741824)] {
            c["HostConfig"]["Memory"] = actual;
            assert!(
                validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).is_err()
            );
        }
        c["HostConfig"]["Memory"] = json!(536870912);
        validate_container(&c, &id, "app", &plan, &image, ContainerPhase::Created).unwrap();
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
        validate_inputs(
            &plan,
            root.path(),
            &root.path().join("bundle"),
            rootful_applicant_group(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_inputs(
            &plan,
            root.path(),
            &root.path().join("bundle"),
            rootful_applicant_group()
        )
        .is_err());
        std::fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(validate_inputs(
            &plan,
            root.path(),
            &root.path().join("bundle"),
            rootful_applicant_group()
        )
        .is_err());
    }

    fn applicant_input_fixture() -> (tempfile::TempDir, ApplicationModelPlan) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["bundle", "state", "state/applicant"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = root.path().join("state/applicant");
        let gid = crate::installer_state::applicant_state_gid().unwrap();
        set_applicant_fixture_metadata(&path, gid);
        let plan = ApplicationModelPlan {
            model: json!({"services":{
                "applicant":{"group_add":[gid.to_string()],"volumes":[{
                    "type":"bind","source":path.to_str().unwrap().replace('$',"$$"),
                    "target":"/app/data","read_only":false}]},
                "kms-initialize":{"profiles":["kms-init"],"restart":"no","environment":{
                    "MARTY_KMS_BOOTSTRAP_ENABLED":"true",
                    "BAO_TOKEN_FILE":"/run/secrets/openbao_bootstrap_token"}}
            }}),
            selected_services: vec!["applicant".into()],
            expected_network_id: "c".repeat(64),
            installation_ready: false,
        };
        (root, plan)
    }

    fn set_applicant_fixture_metadata(path: &Path, gid: u32) {
        use std::os::fd::AsRawFd;
        let held = std::fs::File::open(path).unwrap();
        if held.metadata().unwrap().gid() != gid {
            assert_eq!(unsafe { libc::fchown(held.as_raw_fd(), !0, gid) }, 0);
        }
        held.set_permissions(std::fs::Permissions::from_mode(0o2770))
            .unwrap();
    }

    fn copy_applicant_input_plan(plan: &ApplicationModelPlan) -> ApplicationModelPlan {
        ApplicationModelPlan {
            model: plan.model.clone(),
            selected_services: plan.selected_services.clone(),
            expected_network_id: plan.expected_network_id.clone(),
            installation_ready: plan.installation_ready,
        }
    }

    #[test]
    fn applicant_input_accepts_only_the_exact_owned_directory_and_model() {
        let (root, plan) = applicant_input_fixture();
        let path = root.path().join("state/applicant");
        let bundle = root.path().join("bundle");
        let sentinel = path.join("retained-test-data");
        std::fs::write(&sentinel, b"disposable applicant fixture").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode()
            ),
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode()
            )
        );
        assert_eq!(
            std::fs::read(sentinel).unwrap(),
            b"disposable applicant fixture"
        );

        // An ordinary user cannot chown a fixture to an arbitrary group. Check
        // the same real held inode against a different required GID instead.
        let held = std::fs::File::open(&path).unwrap();
        let gid = crate::installer_state::applicant_state_gid().unwrap();
        let wrong_gid = if gid == 1 { 2 } else { 1 };
        assert!(crate::installer_state::require_applicant_storage(&held, wrong_gid).is_err());
        for group in [
            Value::Null,
            json!([]),
            json!(["0"]),
            json!([wrong_gid.to_string()]),
            json!([format!("0{gid}")]),
            json!([gid]),
            json!([gid.to_string(), gid.to_string()]),
        ] {
            let mut changed = copy_applicant_input_plan(&plan);
            changed.model["services"]["applicant"]["group_add"] = group;
            assert!(
                validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group()).is_err()
            );
        }
        for field in ["user", "read_only", "target", "selected_role"] {
            let mut changed = copy_applicant_input_plan(&plan);
            match field {
                "user" => changed.model["services"]["applicant"]["user"] = json!("0:0"),
                "read_only" => {
                    changed.model["services"]["applicant"]["volumes"][0]["read_only"] = json!(true);
                }
                "target" => {
                    changed.model["services"]["applicant"]["volumes"][0]["target"] =
                        json!("/other");
                }
                "selected_role" => {
                    let service = changed.model["services"]["applicant"].clone();
                    changed.model["services"]["other"] = service;
                    changed.selected_services = vec!["other".into()];
                }
                _ => unreachable!(),
            }
            assert!(
                validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group()).is_err(),
                "{field}"
            );
        }
        for readonly in [false, true] {
            let mut changed = copy_applicant_input_plan(&plan);
            changed.model["services"]["other"] = json!({"volumes":[{
                "type":"bind","source":path.to_str().unwrap().replace('$',"$$"),
                "target":"/foreign","read_only":readonly}]});
            changed.selected_services.push("other".into());
            assert!(
                validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group()).is_err()
            );
        }
        validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).unwrap();
    }

    #[test]
    fn applicant_input_exception_does_not_relax_modes_ancestors_or_other_inputs() {
        let (root, plan) = applicant_input_fixture();
        let applicant = root.path().join("state/applicant");
        let bundle = root.path().join("bundle");
        for mode in [0o700, 0o770, 0o2777, 0o4770, 0o6770] {
            std::fs::set_permissions(&applicant, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err(),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&applicant, std::fs::Permissions::from_mode(0o2770)).unwrap();
        let state = root.path().join("state");
        for mode in [0o770, 0o2770] {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err()
            );
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, readonly) in [("state/other", false), ("bundle/other", true)] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            let mut changed = copy_applicant_input_plan(&plan);
            changed.model["services"]["other"] = json!({"volumes":[{
                "type":"bind","source":path.to_str().unwrap().replace('$',"$$"),
                "target":"/other","read_only":readonly}]});
            changed.selected_services.push("other".into());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group()).unwrap();
            for mode in [0o770, 0o2770] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert!(
                    validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group())
                        .is_err()
                );
            }
        }
        // The applicant directory is exempt only as a leaf, never as an ancestor.
        let child = applicant.join("child");
        std::fs::create_dir(&child).unwrap();
        let mut changed = copy_applicant_input_plan(&plan);
        changed.model["services"]["other"] = json!({"volumes":[{
            "type":"bind","source":child.to_str().unwrap().replace('$',"$$"),
            "target":"/other","read_only":false}]});
        changed.selected_services.push("other".into());
        assert!(
            validate_inputs(&changed, root.path(), &bundle, rootful_applicant_group()).is_err()
        );
        validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).unwrap();
    }

    #[test]
    fn applicant_input_keeps_host_ownership_for_the_rootless_container_group() {
        use crate::installer_state::{applicant_container_group, RuntimeBinding, RuntimeProfile};
        let binding = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootless,
        };
        if unsafe { libc::geteuid() } == 0 {
            assert!(applicant_container_group(&binding).is_err());
            return;
        }
        let group = applicant_container_group(&binding).unwrap();
        let (root, mut plan) = applicant_input_fixture();
        let path = root.path().join("state/applicant");
        let bundle = root.path().join("bundle");
        let before = std::fs::metadata(&path).unwrap();
        assert_eq!(before.gid(), group.host_gid());
        assert_ne!(group.host_gid(), group.container_gid());
        plan.model["services"]["applicant"]["group_add"] = json!(["0"]);
        validate_inputs(&plan, root.path(), &bundle, group).unwrap();
        assert!(validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err());
        plan.model["services"]["applicant"]["group_add"] = json!([group.host_gid().to_string()]);
        assert!(validate_inputs(&plan, root.path(), &bundle, group).is_err());
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode()),
            (after.uid(), after.gid(), after.mode())
        );
    }

    #[test]
    fn applicant_input_refuses_files_and_links_at_the_leaf_or_an_ancestor() {
        let (root, plan) = applicant_input_fixture();
        let path = root.path().join("state/applicant");
        let retained = root.path().join("state/retained-applicant");
        let bundle = root.path().join("bundle");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"not a directory").unwrap();
        set_applicant_fixture_metadata(
            &path,
            crate::installer_state::applicant_state_gid().unwrap(),
        );
        assert!(validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(&retained, &path).unwrap();
        assert!(validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&retained, &path).unwrap();
        let state = root.path().join("state");
        let retained_state = root.path().join("retained-state");
        std::fs::rename(&state, &retained_state).unwrap();
        symlink(&retained_state, &state).unwrap();
        assert!(validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).is_err());
        std::fs::remove_file(&state).unwrap();
        std::fs::rename(&retained_state, &state).unwrap();
        validate_inputs(&plan, root.path(), &bundle, rootful_applicant_group()).unwrap();
    }
}
