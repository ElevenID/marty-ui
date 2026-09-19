//! Real public-image loader/PG gate. Gateway and Flow TLS are later gates.
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use super::{
    canvas_published_database::PublishedDatabase,
    selfhost_runtime_sidecar::{
        OwnedNative, PendingKind, PendingOperation, PublicImage, SecretCase, MANAGEMENT_KEY,
        ORGANIZATION, TRANSACTION_ID,
    },
};

const ERROR: &str = "Packaged selfhost qualification failed";
const PASSWORD: &str = "SyntheticSelfhostDatabasePassword5837";
const WRONG_PASSWORD: &str = "SyntheticDifferentDatabasePassword9014";
const SERVICE_TOKEN: &str = "synthetic-selfhost-production-grpc-service-token";
const HMAC: &str = "synthetic-selfhost-native-token-hmac-key";
pub(super) const CHILD_TEST: &str = "selfhost_public_image_loader_child";

#[derive(Clone, Copy)]
enum ChildCase {
    Workload,
    TimeoutAfterDatabase,
    ExitAfterDatabase,
}
impl ChildCase {
    fn key(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::TimeoutAfterDatabase => "timeout-after-database",
            Self::ExitAfterDatabase => "exit-after-database",
        }
    }
}

pub(super) fn after_database_checkpoint() -> Result<(), String> {
    let scope = super::selfhost_runtime_sidecar::parent_scope()?;
    let scratch = super::selfhost_runtime_sidecar::parent_scratch()?;
    match std::env::var("MARTY_SELFHOST_CHILD_CASE").as_deref() {
        Ok("workload") => Ok(()),
        Ok("timeout-after-database") => {
            std::fs::write(scratch.join("database-ready"), scope.to_string()).map_err(|_| ERROR)?;
            std::thread::sleep(Duration::from_secs(300));
            Err("Controlled timeout child unexpectedly resumed".into())
        }
        Ok("exit-after-database") => {
            std::fs::write(scratch.join("database-ready"), scope.to_string()).map_err(|_| ERROR)?;
            std::process::exit(39);
        }
        _ => Err(ERROR.into()),
    }
}

/// Host child, not a container: the existing Docker owners inherit one closed
/// endpoint without mutating the caller's global environment or Docker context.
pub(super) fn run_isolated_child() -> Result<(), String> {
    for case in [
        ChildCase::ExitAfterDatabase,
        ChildCase::TimeoutAfterDatabase,
        ChildCase::Workload,
    ] {
        run_isolated_case(case)?;
    }
    Ok(())
}

fn run_isolated_case(case: ChildCase) -> Result<(), String> {
    require(std::env::consts::OS == "linux")?;
    let mut owned = tempfile::tempdir().map_err(|_| ERROR)?;
    let scratch = owned.path().canonicalize().map_err(|_| ERROR)?;
    let config = owned.path().join("docker-config");
    std::fs::create_dir(&config).map_err(|_| ERROR)?;
    let scope = uuid::Uuid::new_v4();
    let sentinel = scope.to_string();
    let path = std::env::var_os("PATH").ok_or(ERROR)?;
    let image = std::env::var("MARTY_SELFHOST_TEST_IMAGE").map_err(|_| ERROR)?;
    let executable = std::env::current_exe().map_err(|_| ERROR)?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::null())
        .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env("DOCKER_HOST", "unix:///var/run/docker.sock")
        .env("DOCKER_CONFIG", &config)
        .env("TMPDIR", &scratch)
        .env("MARTY_SELFHOST_PARENT_SCOPE", &sentinel)
        .env("MARTY_SELFHOST_CHILD_CASE", case.key())
        .env("MARTY_SELFHOST_LOADER_CHILD", "1")
        .env("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
        .env("MARTY_SELFHOST_CHILD_SENTINEL", &sentinel);
    for key in [
        "PATH",
        "MARTY_SELFHOST_TEST_PACKAGER_BINARY",
        "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE",
        "MARTY_SELFHOST_TEST_IMAGE",
        "MARTY_SELFHOST_TEST_REVISION",
    ] {
        command.env(key, std::env::var_os(key).ok_or(ERROR)?);
    }
    // Disable automatic parent cleanup before the child can create anything.
    // Only verified resource absence restores automatic scratch removal.
    owned.disable_cleanup(true);
    let output = super::bounded_fixture_command::run(
        &mut command,
        None,
        Duration::from_secs(if matches!(case, ChildCase::TimeoutAfterDatabase) {
            60
        } else {
            900
        }),
        4 * 1024 * 1024,
    );
    let terminated = !matches!(
        &output,
        Err(super::bounded_fixture_command::CommandFailure::TerminationFailed)
    );
    let operation = match case {
        ChildCase::Workload => child_result(output, &sentinel),
        ChildCase::TimeoutAfterDatabase | ChildCase::ExitAfterDatabase => {
            let expected = match (&output, case) {
                (
                    Err(super::bounded_fixture_command::CommandFailure::TimedOut),
                    ChildCase::TimeoutAfterDatabase,
                ) => true,
                (Ok(output), ChildCase::ExitAfterDatabase) => output.status.code() == Some(39),
                _ => false,
            };
            // The fault must occur after actual PG/probe creation, not during
            // unrelated setup. No output/secret parsing substitutes for this.
            require(
                expected
                    && std::fs::read(scratch.join("database-ready"))
                        .ok()
                        .as_deref()
                        == Some(sentinel.as_bytes()),
            )
        }
    };
    let execute = |arguments: &[&str]| closed_docker(&config, &path, arguments);
    finish_parent_scope(operation, terminated, scope, &mut owned, || {
        recover(scope, &image, &scratch, &execute)
    })
}

fn finish_parent_scope(
    operation: Result<(), String>,
    terminated: bool,
    scope: uuid::Uuid,
    owned: &mut tempfile::TempDir,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let cleanup = if terminated {
        super::selfhost_runtime_sidecar::require_no_pending_operation(scope, owned.path())
            .and_then(|()| cleanup())
    } else {
        Err("Selfhost child was not verifiably reaped; recovery withheld".into())
    };
    if cleanup.is_ok() {
        owned.disable_cleanup(false);
    } else {
        eprintln!(
            "Retained synthetic selfhost scratch after unverified resource cleanup at {}",
            owned.path().display()
        );
    }
    super::base_runtime_container::retain_failure(operation, cleanup)
}

fn child_result(
    output: Result<std::process::Output, super::bounded_fixture_command::CommandFailure>,
    sentinel: &str,
) -> Result<(), String> {
    use super::bounded_fixture_command::CommandFailure;
    let output = output.map_err(|error| match error {
        CommandFailure::TimedOut => "Selfhost child deadline exceeded",
        CommandFailure::TerminationFailed => "Selfhost child termination failed",
        CommandFailure::OutputTooLarge => "Selfhost child output exceeded limit",
        CommandFailure::Io(_) => "Selfhost child execution failed",
    })?;
    let stdout = String::from_utf8(output.stdout).map_err(|_| ERROR)?;
    let complete = format!("SELFHOST_PUBLIC_LOADER_COMPLETE:{sentinel}");
    require(output.status.success() && stdout.lines().filter(|line| *line == complete).count() == 1)
}

fn closed_docker(
    config: &Path,
    path: &std::ffi::OsStr,
    arguments: &[&str],
) -> Result<String, String> {
    let mut command = Command::new("docker");
    command
        .env_clear()
        .stdin(Stdio::null())
        .env("PATH", path)
        .env("DOCKER_HOST", "unix:///var/run/docker.sock")
        .env("DOCKER_CONFIG", config)
        .args(arguments);
    let output = super::bounded_fixture_command::run(
        &mut command,
        None,
        Duration::from_secs(120),
        1024 * 1024,
    )
    .map_err(|_| "Closed selfhost recovery command failed")?;
    require(output.status.success())?;
    String::from_utf8(output.stdout)
        .map(|v| v.trim().to_owned())
        .map_err(|_| ERROR.into())
}

fn recover(
    scope: uuid::Uuid,
    image: &str,
    scratch: &Path,
    execute: &impl Fn(&[&str]) -> Result<String, String>,
) -> Result<(), String> {
    let ids = PublishedDatabase::inspect_recovery_scope(scope, execute)?;
    let postgres = ids.last().map(String::as_str);
    let native = super::selfhost_runtime_sidecar::recover_parent_scope(
        scope, image, postgres, scratch, execute,
    )?;
    let database = PublishedDatabase::recover_scope(scope, execute)?;
    for id in native.iter().chain(database.iter()) {
        eprintln!("Verified recovered selfhost resource absent: {id}");
    }
    Ok(())
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(ERROR.into())
    }
}

fn packager(repo: &Path) -> Result<Command, String> {
    let path = PathBuf::from(std::env::var_os("MARTY_SELFHOST_TEST_PACKAGER_BINARY").ok_or(ERROR)?);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| ERROR)?;
    require(metadata.is_file() && !metadata.file_type().is_symlink())?;
    let mut command = Command::new(path);
    command.env_clear().stdin(Stdio::null()).current_dir(repo);
    for key in ["PATH", "TMPDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .arg("--compose-executable")
        .arg(std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE").ok_or(ERROR)?);
    Ok(command)
}

async fn provision(database: &PublishedDatabase) -> Result<sqlx::PgPool, String> {
    let mut url = url::Url::parse(&database.url).map_err(|_| ERROR)?;
    url.set_path("/postgres");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url.as_str())
        .await
        .map_err(|_| ERROR)?;
    // This exact new role/database lives only in the freshly verified PG owner.
    sqlx::query("CREATE ROLE marty LOGIN PASSWORD 'SyntheticSelfhostDatabasePassword5837'")
        .execute(&admin)
        .await
        .map_err(|_| ERROR)?;
    sqlx::query("CREATE DATABASE marty WITH TEMPLATE canvas_published_schema_test OWNER marty")
        .execute(&admin)
        .await
        .map_err(|_| ERROR)?;
    admin.close().await;
    url.set_path("/marty");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url.as_str())
        .await
        .map_err(|_| ERROR)?;
    for statement in [
        "GRANT USAGE ON SCHEMA issuance_service TO marty",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA issuance_service TO marty",
        "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA issuance_service TO marty",
    ] {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .map_err(|_| ERROR)?;
    }
    let mut authenticated = url.clone();
    authenticated.set_username("marty").map_err(|_| ERROR)?;
    authenticated
        .set_password(Some(PASSWORD))
        .map_err(|_| ERROR)?;
    let check = sqlx::PgPool::connect(authenticated.as_str())
        .await
        .map_err(|_| ERROR)?;
    let identity: (String, String) =
        sqlx::query_as("SELECT current_user::text,current_database()::text")
            .fetch_one(&check)
            .await
            .map_err(|_| ERROR)?;
    require(identity == ("marty".into(), "marty".into()))?;
    check.close().await;
    seed(&pool).await?;
    Ok(pool)
}

async fn seed(pool: &sqlx::PgPool) -> Result<(), String> {
    use super::renewal_reference_fixture as reference;
    use marty_issuance_service::{
        credential::CredentialTransactionStatus, credential_postgres::PostgresCredentialRepository,
        initiation::InitiationRepository,
    };
    let corpus = reference::corpus();
    let snapshot = reference::snapshot(&corpus, reference::case(&corpus, "missing-key"), "before");
    let source = reference::source(snapshot).ok_or(ERROR)?;
    let row = snapshot["transactions"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .find(|row| row["id"] == source.transaction_id)
        .ok_or(ERROR)?;
    let mut transaction = reference::transaction(row);
    transaction.id = TRANSACTION_ID.into();
    transaction.organization_id = ORGANIZATION.into();
    transaction.credential_template_id = "synthetic-loader-template".into();
    transaction.applicant_id = None;
    transaction.application_id = None;
    transaction.subject_did = Some("did:web:holder.example".into());
    transaction.status = CredentialTransactionStatus::Pending;
    transaction.created_at = "2026-01-02T03:04:05Z".parse().map_err(|_| ERROR)?;
    transaction.expires_at = "2030-01-02T03:04:05Z".parse().map_err(|_| ERROR)?;
    transaction.pre_authorized_code = "synthetic-loader-pre-auth-code".into();
    transaction.idempotency_key_hash = None;
    transaction.idempotency_request_hash = None;
    let repository = PostgresCredentialRepository::new(pool.clone(), HMAC.as_bytes());
    require(
        repository
            .reserve_idempotently(&transaction)
            .await
            .map_err(|_| ERROR)?
            .created,
    )
}

async fn snapshot(pool: &sqlx::PgPool) -> Result<Value, String> {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'transactions',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM issuance_service.issuance_transactions t),
      'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c),
      'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d),
      'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM issuance_service.issuance_events e))")
        .fetch_one(pool).await.map_err(|_| ERROR.to_owned())
}

fn write_synthetic_secrets(directory: &Path, case: SecretCase) -> Result<Vec<String>, String> {
    require(
        std::fs::read_dir(directory)
            .map_err(|_| ERROR)?
            .next()
            .is_none(),
    )?;
    let mut values = vec![
        (
            "marty_db_password",
            if case == SecretCase::WrongPassword {
                WRONG_PASSWORD
            } else {
                PASSWORD
            },
        ),
        ("issuance_api_key", MANAGEMENT_KEY),
        (
            "integration_secret_master_key",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        ("token_hmac_key", HMAC),
        (
            "canvas_credentials_shared_secret",
            "synthetic-selfhost-canvas-shared-secret",
        ),
        ("grpc_service_token", SERVICE_TOKEN),
    ];
    if case == SecretCase::Empty {
        values[5].1 = "";
    }
    if case == SecretCase::Placeholder {
        values[5].1 = "change-me-synthetic-placeholder-service-token";
    }
    for (name, value) in &values {
        let path = directory.join(name);
        if case == SecretCase::Directory && *name == "grpc_service_token" {
            std::fs::create_dir(&path).map_err(|_| ERROR)?;
            continue;
        }
        let contents = if case == SecretCase::CrLf {
            format!("{value}\r\n")
        } else {
            value.to_string()
        };
        std::fs::write(&path, contents).map_err(|_| ERROR)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if case == SecretCase::Unreadable && *name == "grpc_service_token" {
                0
            } else {
                0o444
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .map_err(|_| ERROR)?;
        }
    }
    Ok(values
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(_, value)| value.to_owned())
        .collect())
}

fn run_service(
    service: &mut OwnedNative<'_>,
    repo: &Path,
    case: SecretCase,
    secrets: &[String],
) -> Result<(), String> {
    service.create()?;
    service.verify_baked_files(repo)?;
    service.start()?;
    let healthy = matches!(
        case,
        SecretCase::Correct | SecretCase::CrLf | SecretCase::WrongPassword
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let state = service.state()?;
        if state["Running"] == false {
            require(!healthy && state["ExitCode"].as_i64().is_some_and(|code| code != 0))?;
            break;
        }
        if healthy && service.health().is_ok() {
            break;
        }
        require(Instant::now() < deadline)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    if healthy {
        service.verify_running_identity()?;
        let invalid = service.transaction(false)?;
        require(invalid == (401, json!({"detail":"Invalid API Key"})))?;
        let response = service.transaction(true)?;
        if case == SecretCase::WrongPassword {
            require(
                response
                    == (
                        500,
                        json!({"detail":"Issuance transaction data is temporarily unavailable"}),
                    ),
            )?;
        } else {
            require(
                response
                    == (
                        200,
                        json!({"id":TRANSACTION_ID,"organization_id":ORGANIZATION,"credential_template_id":"synthetic-loader-template","applicant_id":null,"application_id":null,"subject_did":"did:web:holder.example","status":"pending","created_at":"2026-01-02T03:04:05+00:00","expires_at":"2030-01-02T03:04:05+00:00","issued_at":null,"revoked_at":null,"revocation_reason":null}),
                    ),
            )?;
        }
    }
    let expected = match case {
        SecretCase::MissingMount | SecretCase::Directory => {
            Some("Secret file for GRPC_SERVICE_TOKEN is not a regular file")
        }
        SecretCase::Unreadable => Some("Secret file for GRPC_SERVICE_TOKEN is not readable"),
        SecretCase::RawAndFile => {
            Some("Both GRPC_SERVICE_TOKEN and GRPC_SERVICE_TOKEN_FILE are set")
        }
        SecretCase::Empty | SecretCase::Placeholder => Some("GRPC_SERVICE_TOKEN"),
        _ => None,
    };
    service.verify_log_boundary(
        &secrets.iter().map(String::as_str).collect::<Vec<_>>(),
        expected,
    )
}

pub(super) struct Preflight {
    repo: PathBuf,
    image: PublicImage,
    extracted: super::selfhost_extracted::ExtractedBundle,
}
pub(super) fn preflight() -> Result<Preflight, String> {
    require(std::env::consts::OS == "linux")?;
    super::selfhost_runtime_sidecar::require_closed_child()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or(ERROR)?;
    let image = PublicImage::inspect(
        std::env::var("MARTY_SELFHOST_TEST_IMAGE").map_err(|_| ERROR)?,
        &std::env::var("MARTY_SELFHOST_TEST_REVISION").map_err(|_| ERROR)?,
    )?;
    let pending = PendingOperation::begin(PendingKind::Packager)?;
    let mut extracted =
        super::selfhost_extracted::ExtractedBundle::create_with(repo, packager(repo)?, |command| {
            super::bounded_fixture_command::run(command, None, Duration::from_secs(60), 1024 * 1024)
                .expect("Bounded actual packager invocation")
        });
    extracted.retain_for_parent(&super::selfhost_runtime_sidecar::parent_scratch()?);
    super::selfhost_prepared::qualify(repo, &extracted.extracted);
    require(extracted.directory().is_dir())?;
    pending.complete()?;
    Ok(Preflight {
        repo: repo.to_owned(),
        image,
        extracted,
    })
}
pub(super) async fn run(database: &PublishedDatabase, fixture: Preflight) -> Result<(), String> {
    database.borrow_descriptor()?;
    let Preflight {
        repo,
        image,
        extracted,
    } = fixture;
    let repo = repo.as_path();
    let pool = provision(database).await?;
    let result = async {
        for case in [
            SecretCase::Correct,
            SecretCase::CrLf,
            SecretCase::WrongPassword,
            SecretCase::MissingMount,
            SecretCase::Directory,
            SecretCase::Unreadable,
            SecretCase::Empty,
            SecretCase::Placeholder,
            SecretCase::RawAndFile,
        ] {
            let mut prepared = super::selfhost_prepared::prepare(repo, &extracted.extracted);
            prepared.retain_for_parent(&super::selfhost_runtime_sidecar::parent_scratch()?);
            let secrets = write_synthetic_secrets(&prepared.secret_directory, case)?;
            let before = snapshot(&pool).await?;
            extracted.verify_unchanged();
            prepared.verify_sources();
            let mut service = OwnedNative::prepare(&prepared, database, &image, case)?;
            let operation = run_service(&mut service, repo, case, &secrets);
            let cleanup = service.close_verified();
            let cleanup_failed = cleanup.is_err();
            let combined = super::base_runtime_container::retain_failure(operation, cleanup);
            drop(service);
            if cleanup_failed {
                if let Some(path) = prepared.finish(true) {
                    eprintln!(
                        "Retained synthetic selfhost secret inputs for cleanup inspection at {}",
                        path.display()
                    );
                }
                return combined;
            }
            let unchanged = snapshot(&pool).await? == before;
            extracted.verify_unchanged();
            prepared.verify_sources();
            combined?;
            require(unchanged)?;
            require(prepared.finish(false).is_none())?;
        }
        Ok(())
    }
    .await;
    pool.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_control_child() {
        let Ok(mode) = std::env::var("MARTY_SELFHOST_PROCESS_CONTROL") else {
            return;
        };
        let scratch = PathBuf::from(std::env::var_os("MARTY_SELFHOST_CONTROL_SCRATCH").unwrap());
        std::fs::write(scratch.join("owned-resource"), "synthetic-control").unwrap();
        match mode.as_str() {
            "exit" => std::process::exit(39),
            "timeout" => std::thread::sleep(Duration::from_secs(30)),
            _ => panic!("closed process control mode"),
        }
    }

    #[test]
    fn host_timeout_and_abrupt_exit_preserve_inputs_until_verified_recovery() {
        for mode in ["exit", "timeout"] {
            let mut owned = tempfile::tempdir().unwrap();
            owned.disable_cleanup(true);
            let root = owned.path().to_owned();
            let scope = uuid::Uuid::new_v4();
            std::fs::write(root.join("mounted-input"), "retained").unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .env_clear()
                .args([
                    "selfhost_packaged_runtime::tests::process_control_child",
                    "--exact",
                    "--nocapture",
                ])
                .env("MARTY_SELFHOST_PROCESS_CONTROL", mode)
                .env("MARTY_SELFHOST_CONTROL_SCRATCH", &root);
            let output = super::super::bounded_fixture_command::run(
                &mut child,
                None,
                Duration::from_secs(2),
                65536,
            );
            if mode == "exit" {
                assert_eq!(output.as_ref().unwrap().status.code(), Some(39));
            } else {
                assert!(matches!(
                    &output,
                    Err(super::super::bounded_fixture_command::CommandFailure::TimedOut)
                ));
            }
            assert!(
                root.join("owned-resource").is_file(),
                "control reached the owned-resource checkpoint"
            );
            let called = std::cell::Cell::new(false);
            let result = finish_parent_scope(
                child_result(output, "unused"),
                true,
                scope,
                &mut owned,
                || {
                    called.set(true);
                    assert_eq!(
                        std::fs::read(root.join("mounted-input")).unwrap(),
                        b"retained"
                    );
                    std::fs::remove_file(root.join("owned-resource")).unwrap();
                    assert!(!root.join("owned-resource").exists());
                    Ok(())
                },
            );
            assert!(result.is_err() && called.get());
            drop(owned);
            assert!(!root.exists());
        }
    }

    #[test]
    fn cleanup_failure_retains_scratch_and_original_failure() {
        for terminated in [false, true] {
            let mut owned = tempfile::tempdir().unwrap();
            owned.disable_cleanup(true);
            let root = owned.path().to_owned();
            let scope = uuid::Uuid::new_v4();
            let called = std::cell::Cell::new(false);
            let error = finish_parent_scope(
                Err("original-child-failure".into()),
                terminated,
                scope,
                &mut owned,
                || {
                    called.set(true);
                    Err("exact-cleanup-failure".into())
                },
            )
            .unwrap_err();
            assert!(error.contains("original-child-failure"));
            assert!(error.contains(if terminated {
                "exact-cleanup-failure"
            } else {
                "not verifiably reaped"
            }));
            assert_eq!(called.get(), terminated);
            drop(owned);
            assert!(root.is_dir());
            // Exact test-created empty directory, after proving retention.
            std::fs::remove_dir(&root).unwrap();
        }
    }

    #[test]
    fn held_pending_operation_withholds_recovery_and_retains_scratch() {
        let mut owned = tempfile::tempdir().unwrap();
        owned.disable_cleanup(true);
        let root = owned.path().canonicalize().unwrap();
        let scope = uuid::Uuid::new_v4();
        let pending = super::super::selfhost_runtime_sidecar::PendingOperation::begin_at(
            scope,
            &root,
            super::super::selfhost_runtime_sidecar::PendingKind::NativeCreate,
        )
        .unwrap();
        let called = std::cell::Cell::new(false);
        let error =
            finish_parent_scope(Err("child-failed".into()), true, scope, &mut owned, || {
                called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("child-failed"));
        assert!(error.contains("incomplete nested operation"));
        assert!(!called.get());
        drop(pending);
        drop(owned);
        assert!(root.is_dir());
        std::fs::remove_file(root.join(super::super::selfhost_runtime_sidecar::PENDING_OPERATION))
            .unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
