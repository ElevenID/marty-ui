// Exact-owned platform acceptance database. Current native schema owners only.
// No historical provider image, oracle overlay or deployment URL is accepted.
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.platform-schema";
const DATABASE: &str = "platform_schema_test";
const POSTGRES_IMAGE: &str =
    "postgres@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c";

fn ci_postgres_image() -> Result<String, String> {
    let mirrored = format!("mirror.gcr.io/library/{POSTGRES_IMAGE}");
    match std::env::var("MARTY_PLATFORM_TEST_POSTGRES_IMAGE") {
        Ok(value) if value == POSTGRES_IMAGE || value == mirrored => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(POSTGRES_IMAGE.into()),
        _ => Err("Platform PostgreSQL image differs from its fixed pin".into()),
    }
}

pub(super) struct PhaseTimer {
    phase: &'static str,
    name: String,
    started: Instant,
    succeeded: bool,
}

impl PhaseTimer {
    fn start(phase: &'static str, name: impl Into<String>) -> Self {
        Self {
            phase,
            name: name.into(),
            started: Instant::now(),
            succeeded: false,
        }
    }

    pub(super) fn success(mut self) {
        self.succeeded = true;
    }
}

// These are exact test-owned identities, never an oracle value or payload.
// Time the whole repository matrix, including its template and owned cleanup,

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        eprintln!(
            "\nMARTY_CI_PHASE_V1 {{\"phase\":\"{}\",\"name\":\"{}\",\"duration_ms\":{},\"status\":\"{}\"}}",
            self.phase,
            self.name,
            self.started.elapsed().as_millis(),
            if self.succeeded { "ok" } else { "failed" },
        );
    }
}

pub(super) fn repository_root_from(start: &Path) -> Option<&Path> {
    // The packaged child mounts only reviewed inputs, not the entire checkout.
    // Cargo's compile-time manifest path still has a fixed package suffix.
    if !start.is_absolute()
        || !(start.ends_with("rust/services/issuance")
            || start.ends_with("rust/crates/flow-acceptance")
            || start.ends_with("rust/crates/selfhost-acceptance"))
    {
        return None;
    }
    start.ancestors().nth(3)
}

pub(super) fn repository_root() -> PathBuf {
    repository_root_from(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("Platform contract manifest directory has an unexpected package layout")
        .to_path_buf()
}

pub(super) fn docker(arguments: &[&str]) -> Result<String, String> {
    docker_with_timeout(arguments, Duration::from_secs(120))
}

pub(super) fn docker_with_timeout(arguments: &[&str], timeout: Duration) -> Result<String, String> {
    let limit = if arguments.first() == Some(&"logs") {
        64 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    };
    let output = docker_output_with_timeout(arguments, timeout, limit)?;
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "Docker returned invalid UTF-8".to_owned())
}

pub(super) fn docker_output_with_timeout(
    arguments: &[&str],
    timeout: Duration,
    limit: u64,
) -> Result<Output, String> {
    use super::bounded_fixture_command::{run, CommandFailure};
    let output =
        run(Command::new("docker").args(arguments), None, timeout, limit).map_err(|error| {
            match error {
                CommandFailure::Io(_) => "Docker execution unavailable".to_owned(),
                CommandFailure::TimedOut => "Docker command exceeded deadline".to_owned(),
                CommandFailure::OutputTooLarge => "Docker command output exceeded limit".to_owned(),
                CommandFailure::TerminationFailed => "Docker command cleanup failed".to_owned(),
            }
        })?;
    if !output.status.success() {
        if arguments.first() == Some(&"create") {
            return Err(format!(
                "Docker create failed ({})",
                docker_create_failure_category(&output.stderr)
            ));
        }
        return Err(format!(
            "Docker {} failed",
            arguments.first().copied().unwrap_or("command")
        ));
    }
    Ok(output)
}

fn docker_create_failure_category(stderr: &[u8]) -> &'static str {
    let detail = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if detail.contains("no such image") || detail.contains("image not found") {
        "image_unavailable"
    } else if detail.contains("cannot connect to the docker daemon")
        || detail.contains("is the docker daemon running")
    {
        "daemon_unavailable"
    } else if detail.contains("no space left on device") {
        "storage_exhausted"
    } else if detail.contains("cannot allocate memory")
        || detail.contains("resource temporarily unavailable")
    {
        "runtime_capacity"
    } else if detail.contains("port is already allocated")
        || detail.contains("address already in use")
    {
        "port_conflict"
    } else if detail.contains("permission denied") {
        "permission_denied"
    } else {
        "unknown"
    }
}

pub(super) fn inspect(id: &str) -> Result<Value, String> {
    inspect_with_timeout(id, Duration::from_secs(120))
}

pub(super) fn inspect_with_timeout(id: &str, timeout: Duration) -> Result<Value, String> {
    serde_json::from_str(&docker_with_timeout(
        &["inspect", "--format", "{{json .}}", id],
        timeout,
    )?)
    .map_err(|_| "Invalid container inspection".into())
}

fn checked_database_storage(info: &Value, id: &str, scope: &str) -> Result<(), String> {
    if info["Id"] != id
        || info["Config"]["Labels"][LABEL] != scope
        || info["Mounts"]
            .as_array()
            .is_none_or(|mounts| !mounts.is_empty())
        || info["HostConfig"]["Tmpfs"]["/var/lib/postgresql/data"] != "rw"
        || info["HostConfig"]["Tmpfs"]["/var/run/postgresql"] != "rw"
    {
        return Err("Refusing database access: identity/storage mismatch".into());
    }
    Ok(())
}

fn checked_borrow_descriptor(descriptor: &str) -> Result<(String, String), String> {
    // No database URL, credentials, arbitrary Docker arguments or host path can
    // be supplied across this boundary. Errors never echo descriptor contents.
    if descriptor.len() > 256 {
        return Err("Invalid owned database descriptor".into());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Descriptor {
        postgres_id: String,
        scope: String,
    }
    let value: Descriptor =
        serde_json::from_str(descriptor).map_err(|_| "Invalid owned database descriptor")?;
    let id = &value.postgres_id;
    let scope = &value.scope;
    PublishedDatabase::accept_id(id)?;
    let parsed = Uuid::parse_str(scope).map_err(|_| "Invalid owned database scope")?;
    if parsed.get_version_num() != 4
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.to_string() != *scope
    {
        return Err("Invalid owned database scope".into());
    }
    Ok((id.to_owned(), scope.to_owned()))
}

fn checked_borrowed_url(info: &Value, id: &str, scope: &str) -> Result<String, String> {
    checked_database_configuration(info, id, scope)?;
    if info["HostConfig"]["Tmpfs"]
        .as_object()
        .is_none_or(|entries| entries.len() != 2)
    {
        return Err("Owned database requires its exact temporary storage topology".into());
    }
    let postgres_image = ci_postgres_image()?;
    if info["State"]["Running"] != true
        || info["Config"]["Image"].as_str() != Some(postgres_image.as_str())
    {
        return Err("Owned database must retain its running pinned image".into());
    }
    let environment = info["Config"]["Env"]
        .as_array()
        .ok_or("Missing owned database configuration")?;
    for (key, expected) in [
        ("POSTGRES_USER", "oracle"),
        ("POSTGRES_PASSWORD", "synthetic-local-only"),
        ("POSTGRES_DB", "platform_schema_test"),
    ] {
        let prefix = format!("{key}=");
        let actual: Vec<_> = environment
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| value.starts_with(&prefix))
            .collect();
        if actual != [format!("{prefix}{expected}")] {
            return Err("Owned database synthetic configuration mismatch".into());
        }
    }
    let ports = info["NetworkSettings"]["Ports"]
        .as_object()
        .ok_or("Missing owned database ports")?;
    let bindings = ports
        .get("5432/tcp")
        .and_then(Value::as_array)
        .ok_or("Missing owned database binding")?;
    if ports.len() != 1 || bindings.len() != 1 || bindings[0]["HostIp"] != "127.0.0.1" {
        return Err("Owned database requires exactly one loopback binding".into());
    }
    let port = bindings[0]["HostPort"]
        .as_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("Invalid owned database port")?;
    Ok(format!(
        "postgresql://oracle:synthetic-local-only@127.0.0.1:{port}/platform_schema_test"
    ))
}

fn checked_recovery_scope(scope: Uuid) -> Result<(), String> {
    if scope.get_version_num() != 4 || scope.get_variant() != uuid::Variant::RFC4122 {
        return Err("Invalid caller-owned database scope".into());
    }
    Ok(())
}

fn scope_ids(
    scope: Uuid,
    execute: &impl Fn(&[&str]) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    checked_recovery_scope(scope)?;
    let filter = format!("label={LABEL}={scope}");
    let output = execute(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?;
    let ids = output.lines().map(str::to_owned).collect::<Vec<_>>();
    if ids.len() > 1 {
        return Err("Unexpected resources in caller-owned database scope".into());
    }
    for id in &ids {
        PublishedDatabase::accept_id(id)?;
    }
    Ok(ids)
}

fn checked_database_configuration(info: &Value, id: &str, scope: &str) -> Result<(), String> {
    checked_database_storage(info, id, scope)?;
    let error = "Refusing platform database access: exact configuration/topology mismatch";
    if info["Config"]["Image"].as_str() != Some(ci_postgres_image()?.as_str())
        || info["HostConfig"]["Tmpfs"]
            .as_object()
            .is_none_or(|v| v.len() != 2)
        || info["HostConfig"]["Privileged"] != false
        || info["HostConfig"]["PortBindings"]
            != serde_json::json!({"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]})
    {
        return Err(error.into());
    }
    let values = info["Config"]["Env"].as_array().ok_or(error)?;
    for expected in [
        "POSTGRES_USER=oracle",
        "POSTGRES_PASSWORD=synthetic-local-only",
        "POSTGRES_DB=platform_schema_test",
    ] {
        let key = expected.split_once('=').unwrap().0;
        if values
            .iter()
            .filter_map(Value::as_str)
            .filter(|v| v.starts_with(&format!("{key}=")))
            .collect::<Vec<_>>()
            != [expected]
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn checked_recovery_rows(scope: Uuid, rows: &[(String, Value)]) -> Result<Vec<String>, String> {
    checked_recovery_scope(scope)?;
    if rows.len() > 1 {
        return Err("Unexpected resources in platform database scope".into());
    }
    for (id, info) in rows {
        PublishedDatabase::accept_id(id)?;
        checked_database_configuration(info, id, &scope.to_string())?;
    }
    Ok(rows.iter().map(|(id, _)| id.clone()).collect())
}

pub struct PublishedDatabase {
    scope: String,
    postgres: Option<String>,
    pub url: String,
}

impl PublishedDatabase {
    pub fn borrow_descriptor(&self) -> Result<String, String> {
        let id = self.postgres.as_deref().ok_or("Missing owned database")?;
        let descriptor = serde_json::json!({"postgres_id": id, "scope": self.scope}).to_string();
        if Self::borrowed_url(&descriptor)? != self.url {
            return Err("Owned database binding changed before handoff".into());
        }
        Ok(descriptor)
    }

    pub fn borrowed_url(descriptor: &str) -> Result<String, String> {
        let (id, scope) = checked_borrow_descriptor(descriptor)?;
        checked_borrowed_url(&inspect(&id)?, &id, &scope)
    }

    fn accept_id(id: &str) -> Result<(), String> {
        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err("Docker did not return an exact container ID".into())
        }
    }

    pub async fn start_for_current_issuance() -> Result<Self, String> {
        Self::start_with_scope(Uuid::new_v4()).await
    }

    pub(super) async fn start_with_scope(scope: Uuid) -> Result<Self, String> {
        checked_recovery_scope(scope)?;
        if !scope_ids(scope, &docker)?.is_empty() {
            return Err("Caller-owned platform database scope already exists".into());
        }
        let owned = Self::start_empty_postgres(scope).await?;
        let result = async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(5))
                .connect(&owned.url)
                .await
                .map_err(|_| "Platform fixture database is unavailable".to_owned())?;
            let migration = async {
                marty_organization::migration::migrate_organization_schema(&pool)
                    .await
                    .map_err(|_| "Organization fixture migration failed".to_owned())?;
                marty_credential_template::migration::migrate_credential_template_schema(&pool)
                    .await
                    .map_err(|_| "Credential template fixture migration failed".to_owned())?;
                marty_issuance_service::migration::migrate_owned_schema(&pool, Uuid::from_u128(1))
                    .await
                    .map_err(|_| "Issuance fixture migration failed".to_owned())?;
                marty_issuance_service::migration::verify_owned_schema(&pool)
                    .await
                    .map_err(|_| "Issuance fixture schema validation failed".to_owned())
            }
            .await;
            pool.close().await;
            migration
        }
        .await;
        if let Err(error) = result {
            return match owned.close_verified() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; owned cleanup failed: {cleanup}")),
            };
        }
        Ok(owned)
    }

    pub(super) fn recover_scope(
        scope: Uuid,
        execute: &impl Fn(&[&str]) -> Result<String, String>,
    ) -> Result<Vec<String>, String> {
        let ordered = Self::inspect_recovery_scope(scope, execute)?;
        for id in &ordered {
            execute(&["rm", "--force", id])?;
            let filter = format!("id={id}");
            if !execute(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty()
            {
                return Err("Exact recovered database resource remained".into());
            }
        }
        if !scope_ids(scope, execute)?.is_empty() {
            return Err("Owned recovery scope remained".into());
        }
        Ok(ordered)
    }

    pub(super) fn inspect_recovery_scope(
        scope: Uuid,
        execute: &impl Fn(&[&str]) -> Result<String, String>,
    ) -> Result<Vec<String>, String> {
        let ids = scope_ids(scope, execute)?;
        let rows = ids
            .iter()
            .map(|id| {
                let info =
                    serde_json::from_str(&execute(&["inspect", "--format", "{{json .}}", id])?)
                        .map_err(|_| "Invalid owned recovery inspection")?;
                Ok((id.clone(), info))
            })
            .collect::<Result<Vec<_>, String>>()?;
        // Validate the complete set before removing any resource.
        checked_recovery_rows(scope, &rows)
    }

    async fn start_empty_postgres(scope: Uuid) -> Result<Self, String> {
        let postgres_image = ci_postgres_image()?;
        let mut owned = Self {
            scope: scope.to_string(),
            postgres: None,
            url: String::new(),
        };
        let label = format!("{LABEL}={}", owned.scope);
        let create_timing = PhaseTimer::start("container_startup", "postgres_create");
        let postgres = docker(&[
            "create",
            "--pull=never",
            "--label",
            &label,
            "--tmpfs",
            "/var/lib/postgresql/data:rw",
            "--tmpfs",
            "/var/run/postgresql:rw",
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_USER=oracle",
            "--env",
            "POSTGRES_PASSWORD=synthetic-local-only",
            "--env",
            "POSTGRES_DB=platform_schema_test",
            &postgres_image,
        ])?;
        Self::accept_id(&postgres)?;
        owned.postgres = Some(postgres.clone());
        create_timing.success();
        eprintln!("Owned published-schema PostgreSQL: {postgres}");
        let readiness_timing = PhaseTimer::start("database_readiness", "postgres_ready");
        docker(&["start", &postgres])?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if docker(&[
                "exec",
                &postgres,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "oracle",
                "-d",
                "platform_schema_test",
            ])
            .is_ok()
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("Owned PostgreSQL readiness exceeded deadline".into());
            }
            if inspect(&postgres)?["State"]["Running"] != true {
                return Err("Owned PostgreSQL exited before readiness".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let info = inspect(&postgres)?;
        let port = info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
            .as_str()
            .ok_or("Missing owned port")?;
        port.parse::<u16>().map_err(|_| "Invalid owned port")?;
        if info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] != "127.0.0.1" {
            return Err("Non-loopback test port".into());
        }
        readiness_timing.success();
        owned.url = format!(
            "postgresql://oracle:synthetic-local-only@127.0.0.1:{port}/platform_schema_test"
        );
        Ok(owned)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if let Some(id) = self.postgres.as_ref() {
            let info = inspect(id)?;
            checked_database_configuration(&info, id, &self.scope)?;
            docker(&["rm", "--force", id])?;
            self.postgres = None;
        }
        Ok(())
    }

    pub fn close_verified(mut self) -> Result<(), String> {
        let ids: Vec<_> = self.postgres.iter().cloned().collect();
        self.cleanup()?;
        for id in ids {
            let filter = format!("id={id}");
            if !docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty() {
                return Err("Exact owned platform database remained after cleanup".into());
            }
        }
        Ok(())
    }
}
impl Drop for PublishedDatabase {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Owned platform-schema cleanup requires inspection: {error}");
        }
    }
}

#[cfg(test)]
pub(super) fn assert_recovery_mutations_never_remove_a_foreign_database() {
    use std::cell::Cell;
    let scope = Uuid::from_u128(0x123456781234412381231234567890ab);
    let id = "a".repeat(64);
    let pristine = serde_json::json!({
        "Id":id, "Config":{"Image":ci_postgres_image().unwrap(), "Labels":{LABEL:scope.to_string()},
        "Env":["POSTGRES_USER=oracle","POSTGRES_PASSWORD=synthetic-local-only","POSTGRES_DB=platform_schema_test"]},
        "Mounts":[], "HostConfig":{"Tmpfs":{"/var/lib/postgresql/data":"rw","/var/run/postgresql":"rw"},
        "Privileged":false,"PortBindings":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]}},
        "State":{"Running":false}
    });
    for fault in [
        "valid",
        "extra-tmpfs",
        "privileged",
        "public-port",
        "fixed-port",
        "extra-port",
        "foreign-db",
        "duplicate-env",
        "foreign-mount",
        "foreign-label",
        "foreign-image",
        "foreign-id",
    ] {
        let mut info = pristine.clone();
        match fault {
            "valid" => {}
            "extra-tmpfs" => info["HostConfig"]["Tmpfs"]["/foreign"] = serde_json::json!("rw"),
            "privileged" => info["HostConfig"]["Privileged"] = serde_json::json!(true),
            "public-port" => {
                info["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"] =
                    serde_json::json!("0.0.0.0")
            }
            "fixed-port" => {
                info["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostPort"] =
                    serde_json::json!("5432")
            }
            "extra-port" => info["HostConfig"]["PortBindings"]["1234/tcp"] = serde_json::json!([]),
            "foreign-db" => info["Config"]["Env"][2] = serde_json::json!("POSTGRES_DB=production"),
            "duplicate-env" => info["Config"]["Env"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("POSTGRES_USER=other")),
            "foreign-mount" => {
                info["Mounts"] = serde_json::json!([{"Type":"bind","Source":"/foreign"}])
            }
            "foreign-label" => {
                info["Config"]["Labels"][LABEL] = serde_json::json!(Uuid::new_v4().to_string())
            }
            "foreign-image" => info["Config"]["Image"] = serde_json::json!("postgres:latest"),
            "foreign-id" => info["Id"] = serde_json::json!("b".repeat(64)),
            _ => unreachable!(),
        }
        let removals = Cell::new(0);
        let result = PublishedDatabase::recover_scope(scope, &|args| match args[0] {
            "ps" => Ok(if removals.get() == 0 {
                id.clone()
            } else {
                String::new()
            }),
            "inspect" => Ok(info.to_string()),
            "rm" => {
                removals.set(removals.get() + 1);
                Ok(String::new())
            }
            _ => panic!("Unexpected recovery command"),
        });
        assert_eq!(result.is_ok(), fault == "valid", "{fault}");
        assert_eq!(removals.get(), usize::from(fault == "valid"), "{fault}");
    }
}
