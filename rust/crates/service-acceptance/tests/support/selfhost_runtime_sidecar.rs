//! Stage B: only Compose creates the real public-image service environment.
//! The host owns Docker; the service receives no socket or replacement loader.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use uuid::Uuid;

use super::{
    bounded_fixture_command,
    canvas_published_database::{docker, inspect, PublishedDatabase},
    selfhost_prepared::PreparedCompose,
};

const ERROR: &str = "Owned selfhost service boundary refused";
const SOCKET: &str = "unix:///var/run/docker.sock";
pub(super) const PENDING_OPERATION: &str = ".pending-operation-v1";

#[derive(Clone, Copy)]
pub(super) enum PendingKind {
    Database,
    Packager,
    NativeCreate,
    NativeStart,
    NativeCleanup,
}
impl PendingKind {
    fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Packager => "packager",
            Self::NativeCreate => "native-create",
            Self::NativeStart => "native-start",
            Self::NativeCleanup => "native-cleanup",
        }
    }

    fn valid(name: &str) -> bool {
        matches!(
            name,
            "database" | "packager" | "native-create" | "native-start" | "native-cleanup"
        )
    }
}

pub(super) struct PendingOperation {
    path: PathBuf,
    scope: Uuid,
}
impl PendingOperation {
    pub(super) fn begin(kind: PendingKind) -> Result<Self, String> {
        Self::begin_at(parent_scope()?, &parent_scratch()?, kind)
    }

    pub(super) fn begin_at(scope: Uuid, scratch: &Path, kind: PendingKind) -> Result<Self, String> {
        require(scope.get_version_num() == 4 && scope.get_variant() == uuid::Variant::RFC4122)?;
        require(
            scratch.is_absolute()
                && scratch.is_dir()
                && scratch.canonicalize().map_err(|_| ERROR)? == scratch,
        )?;
        let path = scratch.join(PENDING_OPERATION);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|_| ERROR)?;
        let record = format!("v1\n{scope}\n{}\n", kind.name());
        file.write_all(record.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ERROR)?;
        validate_pending_operation(&path, scope)?;
        #[cfg(unix)]
        std::fs::File::open(scratch)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ERROR)?;
        Ok(Self { path, scope })
    }

    pub(super) fn complete(self) -> Result<(), String> {
        validate_pending_operation(&self.path, self.scope)?;
        std::fs::remove_file(&self.path).map_err(|_| ERROR)?;
        match self.path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(ERROR.into()),
        }
        #[cfg(unix)]
        std::fs::File::open(self.path.parent().ok_or(ERROR)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ERROR)?;
        Ok(())
    }
}

fn validate_pending_operation(path: &Path, scope: Uuid) -> Result<PendingKind, String> {
    let metadata = path.symlink_metadata().map_err(|_| ERROR)?;
    require(metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 128)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(metadata.nlink() == 1 && metadata.mode() & 0o077 == 0)?;
    }
    let value = std::fs::read_to_string(path).map_err(|_| ERROR)?;
    let rows = value.lines().collect::<Vec<_>>();
    require(
        rows.len() == 3
            && rows[0] == "v1"
            && rows[1] == scope.to_string()
            && PendingKind::valid(rows[2]),
    )?;
    Ok(match rows[2] {
        "database" => PendingKind::Database,
        "packager" => PendingKind::Packager,
        "native-create" => PendingKind::NativeCreate,
        "native-start" => PendingKind::NativeStart,
        "native-cleanup" => PendingKind::NativeCleanup,
        _ => unreachable!("validated pending operation kind"),
    })
}

pub(super) fn require_no_pending_operation(scope: Uuid, scratch: &Path) -> Result<(), String> {
    let path = scratch.join(PENDING_OPERATION);
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => {
            let kind = validate_pending_operation(&path, scope)?;
            Err(format!(
                "Selfhost child has an incomplete {} operation; recovery withheld",
                kind.name()
            ))
        }
        Err(_) => Err(ERROR.into()),
    }
}

pub(super) fn parent_scope() -> Result<Uuid, String> {
    let value = std::env::var("MARTY_SELFHOST_PARENT_SCOPE").map_err(|_| ERROR)?;
    let scope = Uuid::parse_str(&value).map_err(|_| ERROR)?;
    require(scope.get_version_num() == 4 && scope.to_string() == value)?;
    Ok(scope)
}
pub(super) fn parent_scratch() -> Result<PathBuf, String> {
    let path = PathBuf::from(std::env::var_os("TMPDIR").ok_or(ERROR)?);
    require(
        path.is_absolute() && path.is_dir() && path.canonicalize().map_err(|_| ERROR)? == path,
    )?;
    Ok(path)
}
pub(super) fn require_closed_child() -> Result<(), String> {
    require(std::env::var("MARTY_SELFHOST_LOADER_CHILD").as_deref() == Ok("1"))?;
    require(std::env::var("DOCKER_HOST").as_deref() == Ok(SOCKET))?;
    require(
        ["DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]
            .iter()
            .all(|key| std::env::var_os(key).is_none()),
    )?;
    let config = PathBuf::from(std::env::var_os("DOCKER_CONFIG").ok_or(ERROR)?);
    let parent = parent_scratch()?;
    parent_scope()?;
    require(config == parent.join("docker-config") && config.is_dir())
}
const LABEL: &str = "com.elevenid.test.selfhost-loader";
const RUN_LABEL: &str = "com.elevenid.test.selfhost-loader-run";
const OWNER: &str = "issuance-native";
const ENTRYPOINT: &str = "/app/services/entrypoint.sh";
pub(super) const TRANSACTION_ID: &str = "selfhost-loader-persisted-transaction";
pub(super) const ORGANIZATION: &str = "synthetic-selfhost-loader-org";
pub(super) const MANAGEMENT_KEY: &str = "synthetic-selfhost-loader-management-key";

fn require(condition: bool) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(ERROR.into())
    }
}
fn exact_id(id: &str) -> Result<(), String> {
    require(id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
}
fn image_id(id: &str) -> Result<(), String> {
    exact_id(id.strip_prefix("sha256:").ok_or(ERROR)?)
}
fn environment(value: &Value) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for entry in value.as_array().ok_or(ERROR)? {
        let (key, value) = entry.as_str().ok_or(ERROR)?.split_once('=').ok_or(ERROR)?;
        require(!key.is_empty() && result.insert(key.to_owned(), value.to_owned()).is_none())?;
    }
    Ok(result)
}

/// No arbitrary raw environment, command, host path or Docker argument variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SecretCase {
    Correct,
    CrLf,
    WrongPassword,
    MissingMount,
    Directory,
    Unreadable,
    Empty,
    Placeholder,
    RawAndFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LogExpectation<'a> {
    Contains(&'a str),
    Structured {
        message: &'a str,
        field: &'a str,
        value: &'a str,
    },
}

pub(super) fn log_satisfies_boundary(
    log: &str,
    secrets: &[&str],
    expected: Option<LogExpectation<'_>>,
) -> bool {
    let secrets_absent = secrets
        .iter()
        .all(|value| !value.is_empty() && !log.contains(value));
    let expected_present = match expected {
        None => true,
        Some(LogExpectation::Contains(value)) => log.contains(value),
        Some(LogExpectation::Structured {
            message,
            field,
            value,
        }) => log.lines().any(|line| {
            serde_json::from_str::<Value>(line).is_ok_and(|event| {
                event["fields"]["message"] == message && event["fields"][field] == value
            })
        }),
    };
    secrets_absent && expected_present
}

pub(super) struct PublicImage {
    id: String,
    environment: BTreeMap<String, String>,
}
impl PublicImage {
    pub(super) fn inspect(id: String, revision: &str) -> Result<Self, String> {
        image_id(&id)?;
        require(revision.len() == 40 && revision.bytes().all(|v| v.is_ascii_hexdigit()))?;
        let rows: Value =
            serde_json::from_str(&docker(&["image", "inspect", &id])?).map_err(|_| ERROR)?;
        require(rows.as_array().is_some_and(|rows| rows.len() == 1))?;
        let image = &rows[0];
        require(image["Id"] == id && image["Os"] == "linux")?;
        require(image["Config"]["User"] == "10001:10001")?;
        require(image["Config"]["Cmd"] == json!([ENTRYPOINT]))?;
        require(image["Config"]["Entrypoint"].is_null())?;
        require(image["Config"]["Labels"]["org.opencontainers.image.revision"] == revision)?;
        // This is source-build identity checking, never release provenance.
        Ok(Self {
            id,
            environment: environment(&image["Config"]["Env"])?,
        })
    }
}

fn checked_recovery_native(
    info: &Value,
    id: &str,
    scope: Uuid,
    image: &str,
    postgres: &str,
    scratch: &Path,
) -> Result<(), String> {
    exact_id(id)?;
    exact_id(postgres)?;
    image_id(image)?;
    let labels = &info["Config"]["Labels"];
    let project = labels[LABEL].as_str().ok_or(ERROR)?;
    let project_uuid =
        Uuid::parse_str(project.strip_prefix("selfhost-").ok_or(ERROR)?).map_err(|_| ERROR)?;
    require(
        project == format!("selfhost-{}", project_uuid.simple())
            && project_uuid.get_version_num() == 4,
    )?;
    require(info["Id"] == id && info["Image"] == image && labels[RUN_LABEL] == scope.to_string())?;
    require(
        labels["com.docker.compose.project"] == project
            && labels["com.docker.compose.service"] == OWNER,
    )?;
    require(
        info["Config"]["User"] == "10001:10001"
            && info["Config"]["Entrypoint"] == json!([ENTRYPOINT]),
    )?;
    require(info["Config"]["Cmd"].is_null() || info["Config"]["Cmd"] == json!([]))?;
    require(info["HostConfig"]["NetworkMode"] == format!("container:{postgres}"))?;
    require(
        info["HostConfig"]["ReadonlyRootfs"] == true && info["HostConfig"]["Privileged"] == false,
    )?;
    require(info["HostConfig"]["CapDrop"] == json!(["ALL"]))?;
    for key in ["CapAdd", "Devices"] {
        require(info["HostConfig"][key].is_null() || info["HostConfig"][key] == json!([]))?;
    }
    require(info["HostConfig"]["PidMode"] == "")?;
    require(info["HostConfig"]["IpcMode"] == "private" || info["HostConfig"]["IpcMode"] == "")?;
    require(
        info["HostConfig"]["PortBindings"].is_null()
            || info["HostConfig"]["PortBindings"] == json!({}),
    )?;
    require(info["HostConfig"]["Tmpfs"] == json!({"/tmp":"rw,noexec,nosuid,size=33554432"}))?;
    let security = &info["HostConfig"]["SecurityOpt"];
    require(
        *security == json!(["no-new-privileges:true"]) || *security == json!(["no-new-privileges"]),
    )?;
    let mut names = std::collections::BTreeSet::new();
    let mut tmpfs = false;
    for mount in info["Mounts"].as_array().ok_or(ERROR)? {
        if mount["Type"] == "tmpfs" {
            require(!tmpfs && mount["Destination"] == "/tmp" && mount["RW"] == true)?;
            require(mount["Source"].is_null() || mount["Source"] == "")?;
            tmpfs = true;
            continue;
        }
        require(mount["Type"] == "bind" && mount["RW"] == false)?;
        let destination = mount["Destination"].as_str().ok_or(ERROR)?;
        let name = destination.strip_prefix("/run/secrets/").ok_or(ERROR)?;
        require(
            [
                "marty_db_password",
                "issuance_api_key",
                "integration_secret_master_key",
                "token_hmac_key",
                "canvas_credentials_shared_secret",
                "grpc_service_token",
            ]
            .contains(&name),
        )?;
        require(names.insert(name.to_owned()))?;
        let source = Path::new(mount["Source"].as_str().ok_or(ERROR)?);
        require(source.is_absolute() && source.starts_with(scratch))?;
        require(
            source
                .components()
                .all(|part| !matches!(part, std::path::Component::ParentDir)),
        )?;
        require(source.file_name().and_then(|v| v.to_str()) == Some(name))?;
        let metadata = std::fs::symlink_metadata(source).map_err(|_| ERROR)?;
        require(!metadata.file_type().is_symlink())?;
        require(source.canonicalize().map_err(|_| ERROR)? == source)?;
    }
    require(names.len() == 6 || (names.len() == 5 && !names.contains("grpc_service_token")))
}

/// Only exact parent-run labels are discoverable. No project-prefix cleanup;
/// every candidate is fully identity/topology checked before the first removal.
pub(super) fn recover_parent_scope(
    scope: Uuid,
    image: &str,
    postgres: Option<&str>,
    scratch: &Path,
    execute: &impl Fn(&[&str]) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    let filter = format!("label={RUN_LABEL}={scope}");
    let discover = || execute(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter]);
    let ids = discover()?.lines().map(str::to_owned).collect::<Vec<_>>();
    require(ids.len() <= 1)?; // cases are deliberately serial
    for id in &ids {
        exact_id(id)?;
        let info = serde_json::from_str(&execute(&["inspect", "--format", "{{json .}}", id])?)
            .map_err(|_| ERROR)?;
        checked_recovery_native(&info, id, scope, image, postgres.ok_or(ERROR)?, scratch)?;
    }
    for id in &ids {
        execute(&["rm", "--force", id])?;
        let exact = format!("id={id}");
        require(
            execute(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &exact])?.is_empty(),
        )?;
    }
    require(discover()?.is_empty())?;
    // No networks are authorized for a container-namespace service.
    require(
        execute(&[
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            &filter,
        ])?
        .is_empty(),
    )?;
    Ok(ids)
}

pub(super) struct OwnedNative<'a> {
    prepared: &'a PreparedCompose,
    scope: String,
    database: &'a PublishedDatabase,
    network: String,
    image: String,
    directory: Option<tempfile::TempDir>,
    config: PathBuf,
    model: Value,
    secrets: BTreeMap<String, PathBuf>,
    environment: BTreeMap<String, String>,
    id: Option<String>,
    creation_attempted: bool,
    cleanup_attempted: bool,
}

impl<'a> OwnedNative<'a> {
    pub(super) fn prepare(
        prepared: &'a PreparedCompose,
        database: &'a PublishedDatabase,
        image: &PublicImage,
        case: SecretCase,
    ) -> Result<Self, String> {
        require_closed_child()?;
        let descriptor: Value =
            serde_json::from_str(&database.borrow_descriptor()?).map_err(|_| ERROR)?;
        let postgres = descriptor["postgres_id"].as_str().ok_or(ERROR)?;
        exact_id(postgres)?;
        let postgres_info = inspect(postgres)?;
        let networks = postgres_info["NetworkSettings"]["Networks"]
            .as_object()
            .ok_or(ERROR)?;
        require(networks.len() == 1)?;
        let database_host = networks
            .values()
            .next()
            .and_then(|network| network["IPAddress"].as_str())
            .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
            .filter(|value| value.is_private() && !value.is_loopback() && !value.is_unspecified())
            .ok_or(ERROR)?;
        let network = format!("container:{postgres}");
        let scope = format!("selfhost-{}", Uuid::new_v4().simple());
        let mut directory = tempfile::tempdir().map_err(|_| ERROR)?;
        require(directory.path().starts_with(parent_scratch()?))?;
        // Parent recovers exact labels even if this child is killed; retain
        // configuration on unwinding as well as explicit cleanup errors.
        directory.disable_cleanup(true);
        let config = directory.path().join("compose.json");
        let mut model = prepared.raw_model().clone();
        let mut secrets = BTreeMap::new();
        for value in model["services"][OWNER]["secrets"]
            .as_array()
            .ok_or(ERROR)?
        {
            let name = value["source"].as_str().ok_or(ERROR)?;
            let path = PathBuf::from(model["secrets"][name]["file"].as_str().ok_or(ERROR)?);
            require(path == prepared.secret_directory.join(name))?;
            secrets.insert(name.to_owned(), path);
        }
        let service = model["services"][OWNER].as_object_mut().ok_or(ERROR)?;
        require(service.get("entrypoint") == Some(&json!([ENTRYPOINT])))?;
        require(service.get("command") == Some(&json!([])))?;
        require(!service.contains_key("user") && !service.contains_key("build"))?;
        require(
            service
                .get("volumes")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        )?;
        // Compose v5.4 removed `create --no-deps`. Remove dependencies only
        // from this isolated test copy so create cannot materialize siblings.
        require(
            service
                .remove("depends_on")
                .is_some_and(|v| v.as_object().is_some_and(|v| !v.is_empty())),
        )?;
        // Explicit deployment-only isolation delta. All sibling fields remain.
        service.insert("image".into(), json!(image.id));
        service.remove("networks");
        service.insert("network_mode".into(), json!(network));
        service.insert("ports".into(), json!([]));
        service.insert("restart".into(), json!("no"));
        service.insert("read_only".into(), json!(true));
        service.insert("cap_drop".into(), json!(["ALL"]));
        service.insert("security_opt".into(), json!(["no-new-privileges:true"]));
        service.insert(
            "tmpfs".into(),
            json!(["/tmp:rw,noexec,nosuid,size=33554432"]),
        );
        service.insert(
            "labels".into(),
            json!({LABEL:scope, RUN_LABEL:parent_scope()?.to_string()}),
        );
        let environment = service
            .get_mut("environment")
            .ok_or(ERROR)?
            .as_object_mut()
            .ok_or(ERROR)?;
        let template = environment["DATABASE_URL_TEMPLATE"].as_str().ok_or(ERROR)?;
        let prefix = template.strip_suffix("@postgres:5432/marty").ok_or(ERROR)?;
        require(prefix == "postgresql+asyncpg://marty:$${MARTY_DB_PASSWORD}")?;
        environment.insert(
            "DATABASE_URL_TEMPLATE".into(),
            json!(format!("{prefix}@{database_host}:5432/marty")),
        );
        if case == SecretCase::RawAndFile {
            environment.insert(
                "GRPC_SERVICE_TOKEN".into(),
                json!("synthetic-conflicting-raw-service-token"),
            );
        }
        if case == SecretCase::MissingMount {
            service
                .get_mut("secrets")
                .ok_or(ERROR)?
                .as_array_mut()
                .ok_or(ERROR)?
                .retain(|v| v["source"] != "grpc_service_token");
            secrets.remove("grpc_service_token");
        }
        let mut expected_environment = image.environment.clone();
        for (key, value) in model["services"][OWNER]["environment"]
            .as_object()
            .ok_or(ERROR)?
        {
            expected_environment.insert(key.clone(), value.as_str().ok_or(ERROR)?.to_owned());
        }
        expected_environment.insert(
            "DATABASE_URL_TEMPLATE".into(),
            format!("postgresql+asyncpg://marty:${{MARTY_DB_PASSWORD}}@{database_host}:5432/marty"),
        );
        std::fs::write(&config, serde_json::to_vec(&model).map_err(|_| ERROR)?)
            .map_err(|_| ERROR)?;
        Ok(Self {
            prepared,
            scope,
            database,
            network,
            image: image.id.clone(),
            directory: Some(directory),
            config,
            model,
            secrets,
            environment: expected_environment,
            id: None,
            creation_attempted: false,
            cleanup_attempted: false,
        })
    }

    fn compose(&self, arguments: &[&str]) -> Result<(), String> {
        self.prepared.verify_sources();
        require(
            serde_json::from_slice::<Value>(&std::fs::read(&self.config).map_err(|_| ERROR)?)
                .map_err(|_| ERROR)?
                == self.model,
        )?;
        let executable = std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE").ok_or(ERROR)?;
        let mut command = Command::new(executable);
        command
            .env_clear()
            .current_dir(self.directory.as_ref().ok_or(ERROR)?.path())
            .env("DOCKER_HOST", "unix:///var/run/docker.sock")
            .env(
                "DOCKER_CONFIG",
                std::env::var_os("DOCKER_CONFIG").ok_or(ERROR)?,
            )
            .args(["--project-name", &self.scope, "-f"])
            .arg(&self.config)
            .args(arguments);
        let output =
            bounded_fixture_command::run(&mut command, None, Duration::from_secs(60), 1024 * 1024)
                .map_err(|_| ERROR)?;
        require(output.status.success())
    }

    fn checked(&self, info: &Value, id: &str) -> Result<(), String> {
        exact_id(id)?;
        require(info["Id"] == id && info["Image"] == self.image)?;
        require(info["Config"]["Labels"][LABEL] == self.scope)?;
        require(info["Config"]["Labels"][RUN_LABEL] == parent_scope()?.to_string())?;
        require(info["Config"]["Labels"]["com.docker.compose.project"] == self.scope)?;
        require(info["Config"]["Labels"]["com.docker.compose.service"] == OWNER)?;
        require(info["Config"]["User"] == "10001:10001")?;
        require(info["Config"]["Entrypoint"] == json!([ENTRYPOINT]))?;
        require(info["Config"]["Cmd"].is_null() || info["Config"]["Cmd"] == json!([]))?;
        require(info["HostConfig"]["NetworkMode"] == self.network)?;
        require(
            info["HostConfig"]["PortBindings"].is_null()
                || info["HostConfig"]["PortBindings"] == json!({}),
        )?;
        require(info["HostConfig"]["ReadonlyRootfs"] == true)?;
        require(info["HostConfig"]["Privileged"] == false)?;
        require(info["HostConfig"]["CapDrop"] == json!(["ALL"]))?;
        require(
            info["HostConfig"]["CapAdd"].is_null() || info["HostConfig"]["CapAdd"] == json!([]),
        )?;
        require(info["HostConfig"]["PidMode"] == "")?;
        require(info["HostConfig"]["IpcMode"] == "private" || info["HostConfig"]["IpcMode"] == "")?;
        require(
            info["HostConfig"]["Devices"].is_null() || info["HostConfig"]["Devices"] == json!([]),
        )?;
        require(
            info["HostConfig"]["SecurityOpt"] == json!(["no-new-privileges:true"])
                || info["HostConfig"]["SecurityOpt"] == json!(["no-new-privileges"]),
        )?;
        require(info["HostConfig"]["Tmpfs"] == json!({"/tmp":"rw,noexec,nosuid,size=33554432"}))?;
        let mounts = info["Mounts"].as_array().ok_or(ERROR)?;
        let temporary: Vec<_> = mounts
            .iter()
            .filter(|m| m["Destination"] == "/tmp")
            .collect();
        require(temporary.len() <= 1)?;
        for mount in &temporary {
            require(
                mount["Type"] == "tmpfs"
                    && mount["RW"] == true
                    && mount["Source"].as_str().is_none_or(str::is_empty),
            )?;
        }
        require(mounts.len() == self.secrets.len() + temporary.len())?;
        for (name, path) in &self.secrets {
            let matching: Vec<_> = mounts
                .iter()
                .filter(|m| m["Destination"] == format!("/run/secrets/{name}"))
                .collect();
            require(matching.len() == 1)?;
            let mount = matching[0];
            require(mount["Type"] == "bind" && mount["RW"] == false)?;
            require(mount["Source"].as_str() == path.to_str())?;
        }
        let environment = info["Config"]["Env"].as_array().ok_or(ERROR)?;
        require(self.environment == self::environment(&info["Config"]["Env"])?)?;
        let templates: Vec<_> = environment
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|s| s.strip_prefix("DATABASE_URL_TEMPLATE="))
            .collect();
        require(
            templates
                == [self
                    .environment
                    .get("DATABASE_URL_TEMPLATE")
                    .map(String::as_str)
                    .ok_or(ERROR)?],
        )?;
        require(
            !environment
                .iter()
                .filter_map(Value::as_str)
                .any(|v| v.starts_with("DATABASE_URL=")),
        )?;
        Ok(())
    }

    pub(super) fn create(&mut self) -> Result<(), String> {
        require_closed_child()?;
        self.database.borrow_descriptor()?;
        let pending = PendingOperation::begin(PendingKind::NativeCreate)?;
        self.creation_attempted = true;
        self.compose(&["create", "--no-build", "--pull", "never", OWNER])?;
        let ids = self.discover()?;
        require(ids.len() == 1)?;
        self.checked(&inspect(&ids[0])?, &ids[0])?;
        self.id = Some(ids[0].clone());
        pending.complete()
    }
    fn discover(&self) -> Result<Vec<String>, String> {
        let filter = format!("label=com.docker.compose.project={}", self.scope);
        let ids = docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?;
        Ok(ids.lines().map(str::to_owned).collect())
    }
    pub(super) fn start(&self) -> Result<(), String> {
        let id = self.id.as_deref().ok_or(ERROR)?;
        let pending = PendingOperation::begin(PendingKind::NativeStart)?;
        self.checked(&inspect(id)?, id)?;
        docker(&["start", id])?;
        self.checked(&inspect(id)?, id)?;
        pending.complete()
    }
    fn exec(&self, arguments: &[&str]) -> Result<String, String> {
        let id = self.id.as_deref().ok_or(ERROR)?;
        self.checked(&inspect(id)?, id)?;
        let mut args = vec!["exec", id];
        args.extend_from_slice(arguments);
        docker(&args)
    }
    pub(super) fn verify_baked_files(&self, repo: &Path) -> Result<(), String> {
        let id = self.id.as_deref().ok_or(ERROR)?;
        self.checked(&inspect(id)?, id)?;
        for (index, (baked, source)) in [
            (ENTRYPOINT, "services/entrypoint.sh"),
            ("/app/load-secrets-env.sh", "scripts/load-secrets-env.sh"),
        ]
        .iter()
        .enumerate()
        {
            let path = self
                .directory
                .as_ref()
                .ok_or(ERROR)?
                .path()
                .join(format!("baked-{index}"));
            require(!path.exists())?;
            docker(&["cp", &format!("{id}:{baked}"), path.to_str().ok_or(ERROR)?])?;
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ERROR)?;
            require(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() < 128 * 1024,
            )?;
            let actual = std::fs::read(&path).map_err(|_| ERROR)?;
            let expected = std::fs::read(repo.join(source)).map_err(|_| ERROR)?;
            require(Sha256::digest(actual) == Sha256::digest(expected))?;
        }
        Ok(())
    }
    pub(super) fn verify_running_identity(&self) -> Result<(), String> {
        require(self.exec(&["id", "-u"])? == "10001")?;
        require(self.exec(&["id", "-g"])? == "10001")?;
        let status = self.exec(&["cat", "/proc/1/status"])?;
        for key in ["Uid:", "Gid:"] {
            let rows: Vec<_> = status.lines().filter_map(|v| v.strip_prefix(key)).collect();
            require(
                rows.len() == 1 && rows[0].split_whitespace().collect::<Vec<_>>() == ["10001"; 4],
            )?;
        }
        require(self.exec(&["readlink", "/proc/1/exe"])? == "/usr/local/bin/marty-issuance-service")
    }
    fn http(&self, path: &str, key: Option<&str>) -> Result<(u16, Value), String> {
        let origin = format!("http://127.0.0.1:8005{path}");
        let auth = format!("X-API-Key: {}", key.unwrap_or_default());
        let tenant = format!("X-Organization-ID: {ORGANIZATION}");
        let mut arguments = vec![
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "45",
            "--write-out",
            "\n%{http_code}",
            "--header",
            &tenant,
        ];
        if key.is_some() {
            arguments.extend(["--header", &auth]);
        }
        arguments.push(&origin);
        let response = self.exec(&arguments)?;
        let (body, status) = response.rsplit_once('\n').ok_or(ERROR)?;
        Ok((
            status.parse().map_err(|_| ERROR)?,
            serde_json::from_str(body).map_err(|_| ERROR)?,
        ))
    }
    pub(super) fn health(&self) -> Result<(), String> {
        let (status, body) = self.http("/health", None)?;
        require(status == 200 && body == json!({"status":"healthy","service":"issuance-service"}))
    }
    pub(super) fn transaction(&self, valid_key: bool) -> Result<(u16, Value), String> {
        self.http(
            &format!("/v1/issuance/transactions/{TRANSACTION_ID}"),
            Some(if valid_key {
                MANAGEMENT_KEY
            } else {
                "synthetic-invalid-key"
            }),
        )
    }
    pub(super) fn verify_log_boundary(
        &self,
        secrets: &[&str],
        expected: Option<LogExpectation<'_>>,
    ) -> Result<(), String> {
        let id = self.id.as_deref().ok_or(ERROR)?;
        self.checked(&inspect(id)?, id)?;
        let output = super::canvas_published_database::docker_output_with_timeout(
            &["logs", id],
            Duration::from_secs(10),
            1024 * 1024,
        )?;
        let mut bytes = output.stdout;
        bytes.extend(output.stderr);
        let log = String::from_utf8(bytes).map_err(|_| ERROR)?;
        require(log_satisfies_boundary(&log, secrets, expected))
    }
    pub(super) fn state(&self) -> Result<Value, String> {
        let id = self.id.as_deref().ok_or(ERROR)?;
        let info = inspect(id)?;
        self.checked(&info, id)?;
        Ok(info["State"].clone())
    }
    pub(super) fn close_verified(&mut self) -> Result<(), String> {
        if !self.creation_attempted {
            return Ok(());
        }
        require(!self.cleanup_attempted)?;
        let pending = PendingOperation::begin(PendingKind::NativeCleanup)?;
        self.cleanup_attempted = true;
        let ids = self.discover()?;
        require(ids.len() <= 1 && self.id.as_ref().is_none_or(|id| ids == [id.clone()]))?;
        for id in ids {
            self.checked(&inspect(&id)?, &id)?;
            docker(&["rm", "--force", &id])?;
            require(
                docker(&[
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    &format!("id={id}"),
                ])?
                .is_empty(),
            )?;
        }
        require(
            docker(&[
                "network",
                "ls",
                "--quiet",
                "--filter",
                &format!("label=com.docker.compose.project={}", self.scope),
            ])?
            .is_empty(),
        )?;
        require_closed_child()?;
        self.database.borrow_descriptor()?;
        self.prepared.verify_sources();
        self.id = None;
        self.creation_attempted = false;
        pending.complete()
    }
}
impl Drop for OwnedNative<'_> {
    fn drop(&mut self) {
        if self.close_verified().is_err() {
            if let Some(directory) = self.directory.take() {
                let retained = directory.keep();
                eprintln!(
                    "Owned selfhost cleanup requires inspection; retained synthetic config at {}",
                    retained.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn pending_operation_record_is_exclusive_validated_and_explicitly_completed() {
        let owned = tempfile::tempdir().unwrap();
        let scratch = owned.path().canonicalize().unwrap();
        let scope = Uuid::new_v4();
        assert!(require_no_pending_operation(scope, &scratch).is_ok());

        let pending = PendingOperation::begin_at(scope, &scratch, PendingKind::Packager).unwrap();
        assert!(PendingOperation::begin_at(scope, &scratch, PendingKind::Database).is_err());
        assert!(require_no_pending_operation(scope, &scratch)
            .unwrap_err()
            .contains("incomplete packager operation"));
        pending.complete().unwrap();
        assert!(require_no_pending_operation(scope, &scratch).is_ok());

        let path = scratch.join(PENDING_OPERATION);
        std::fs::write(&path, format!("v1\n{}\nunknown\n", scope)).unwrap();
        assert_eq!(
            require_no_pending_operation(scope, &scratch),
            Err(ERROR.into())
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            require_no_pending_operation(scope, &scratch),
            Err(ERROR.into())
        );
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn exact_parent_native_recovery_refuses_foreign_identity_and_mounts() {
        let owned = tempfile::tempdir().unwrap();
        let scratch = owned.path().canonicalize().unwrap();
        let secrets = scratch.join("synthetic-secrets");
        std::fs::create_dir(&secrets).unwrap();
        let names = [
            "marty_db_password",
            "issuance_api_key",
            "integration_secret_master_key",
            "token_hmac_key",
            "canvas_credentials_shared_secret",
            "grpc_service_token",
        ];
        let mut mounts = Vec::new();
        for name in names {
            let source = secrets.join(name);
            std::fs::write(&source, "synthetic").unwrap();
            mounts.push(json!({"Type":"bind","RW":false,"Source":source,"Destination":format!("/run/secrets/{name}")}));
        }
        let id = "a".repeat(64);
        let pg = "b".repeat(64);
        let image = format!("sha256:{}", "c".repeat(64));
        let scope = Uuid::new_v4();
        let project = format!("selfhost-{}", Uuid::new_v4().simple());
        let info = json!({
            "Id":id,"Image":image,
            "Config":{"User":"10001:10001","Entrypoint":[ENTRYPOINT],"Cmd":[],"Labels":{LABEL:project,RUN_LABEL:scope.to_string(),"com.docker.compose.project":project,"com.docker.compose.service":OWNER}},
            "HostConfig":{"NetworkMode":format!("container:{pg}"),"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"PidMode":"","IpcMode":"private","PortBindings":{},"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=33554432"},"SecurityOpt":["no-new-privileges"]},
            "Mounts":mounts,
        });
        checked_recovery_native(&info, &id, scope, &image, &pg, &scratch).unwrap();
        let mut with_tmpfs = info.clone();
        with_tmpfs["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true}));
        checked_recovery_native(&with_tmpfs, &id, scope, &image, &pg, &scratch).unwrap();
        for (pointer, value) in [
            ("/Image", json!(format!("sha256:{}", "d".repeat(64)))),
            (
                "/Config/Labels/com.elevenid.test.selfhost-loader-run",
                json!(Uuid::new_v4().to_string()),
            ),
            (
                "/Config/Labels/com.docker.compose.service",
                json!("gateway"),
            ),
            ("/Config/User", json!("0")),
            ("/Config/Cmd", json!(["sh"])),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/SecurityOpt", json!([])),
            ("/HostConfig/Tmpfs", json!({"/tmp":"rw,exec"})),
            ("/HostConfig/PidMode", json!("host")),
            (
                "/HostConfig/PortBindings",
                json!({"8005/tcp":[{"HostIp":"0.0.0.0","HostPort":"8005"}]}),
            ),
            ("/Mounts/0/RW", json!(true)),
            ("/Mounts/0/Destination", json!("/var/run/docker.sock")),
            ("/Mounts/0/Source", json!("/operator/marty_db_password")),
        ] {
            let mut changed = info.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let writes = std::cell::Cell::new(0);
            let invoke = |args: &[&str]| -> Result<String, String> {
                match args[0] {
                    "ps" => Ok(id.clone()),
                    "inspect" => Ok(changed.to_string()),
                    _ => {
                        writes.set(writes.get() + 1);
                        Err("unexpected write".into())
                    }
                }
            };
            assert!(recover_parent_scope(scope, &image, Some(&pg), &scratch, &invoke).is_err());
            assert_eq!(writes.get(), 0);
        }
        let mut extra = info.clone();
        extra["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(info["Mounts"][0].clone());
        assert!(checked_recovery_native(&extra, &id, scope, &image, &pg, &scratch).is_err());
    }
}
