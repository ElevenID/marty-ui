//! Source-built native acceptance, not released-image or installed-stack qualification.
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[expect(dead_code, reason = "shared bounded fixture command has other owners")]
#[path = "../../../services/issuance/tests/support/bounded_fixture_command.rs"]
mod bounded_fixture_command;

const POSTGRES: &str = "docker.io/library/postgres@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229";
const SCHEMA_SCAN: &str = include_str!("../../../../scripts/sql/kms-private-key-schema.sql");
const CONTENT_SCAN: &str = include_str!("../../../../scripts/sql/kms-private-key-content.sql");

fn run(command: &mut Command, seconds: u64) -> String {
    let label = PathBuf::from(command.get_program())
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let operation = command
        .get_args()
        .next()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let result =
        bounded_fixture_command::run(command, None, Duration::from_secs(seconds), 2 * 1024 * 1024)
            .expect("owned acceptance command did not finish");
    assert!(
        result.status.success(),
        "owned acceptance command failed: {label} {operation} (output withheld)"
    );
    String::from_utf8(result.stdout).expect("command output must be UTF-8")
}
fn executable(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name).expect("compiled acceptance executable path is required"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "compiled executable must be an absolute regular file"
    );
    path
}
struct Database {
    id: String,
    password: String,
    port: u16,
}
impl Database {
    fn start() -> Self {
        let password = Uuid::new_v4().simple().to_string();
        let id = run(
            Command::new("docker").args([
                "create",
                "--label",
                "com.elevenid.test.native-kms-schema=true",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--env",
                &format!("POSTGRES_PASSWORD={password}"),
                "--publish",
                "127.0.0.1::5432",
                POSTGRES,
            ]),
            180,
        )
        .trim()
        .to_owned();
        assert!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid owned container ID"
        );
        let mut owned = Self {
            id,
            password,
            port: 0,
        };
        run(Command::new("docker").args(["start", &owned.id]), 60);
        let port = run(
            Command::new("docker").args(["port", &owned.id, "5432/tcp"]),
            30,
        );
        owned.port = port
            .trim()
            .strip_prefix("127.0.0.1:")
            .expect("database must bind loopback only")
            .parse()
            .unwrap();
        owned
    }
    fn remove(&mut self) {
        run(Command::new("docker").args(["rm", "--force", &self.id]), 30);
        self.id.clear();
    }
    fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.password, self.port
        )
    }
    async fn admin(&self) -> PgPool {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(pool) = PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(2))
                .connect(&self.url("postgres"))
                .await
            {
                return pool;
            }
            assert!(
                Instant::now() < deadline,
                "owned PostgreSQL did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    async fn fresh(&self, admin: &PgPool, name: &str) -> PgPool {
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        // The database identifier above permits only ASCII lowercase letters and underscores.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(admin)
            .await
            .unwrap();
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&self.url(name))
            .await
            .unwrap()
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        if self.id.is_empty() {
            return;
        }
        let result = bounded_fixture_command::run(
            Command::new("docker").args(["rm", "--force", &self.id]),
            None,
            Duration::from_secs(30),
            1024 * 1024,
        );
        if !result.is_ok_and(|r| r.status.success()) {
            eprintln!("Owned native KMS database cleanup requires inspection");
        }
    }
}
async fn custody(pool: &PgPool, schema: &str) {
    let count: (i64,i64) = sqlx::query_as("SELECT count(DISTINCT c.oid),count(a.attnum) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid WHERE n.nspname=$1 AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped")
        .bind(schema).fetch_one(pool).await.unwrap();
    assert!(
        count.0 > 0 && count.1 > 0,
        "native owner must actually create tables and columns"
    );
    let findings: Vec<(String,)> = sqlx::query_as(SCHEMA_SCAN).fetch_all(pool).await.unwrap();
    assert!(
        findings.is_empty(),
        "native schema contains private-key storage"
    );
    assert!(
        sqlx::raw_sql(CONTENT_SCAN).execute(pool).await.is_ok(),
        "native database contains private-key content"
    );
}
struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        bounded_fixture_command::stop_owned_child(&mut self.0)
            .expect("owned service cleanup failed");
    }
}
fn start_profile(binary: &PathBuf, prefix: &str, backend: &str, database: &str) {
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let log = tempfile::tempfile().unwrap();
    let mut child = Service(
        Command::new(binary)
            .env("DATABASE_URL", database)
            .env("ENVIRONMENT", "test")
            .env("GRPC_INSECURE_ALLOWED", "true")
            .env(format!("{prefix}_HTTP_ADDR"), address.to_string())
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "native profile exited before readiness"
        );
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if stream
                .write_all(b"GET /health/native-backend HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .is_ok()
            {
                let mut reply = Vec::new();
                if stream.take(64 * 1024).read_to_end(&mut reply).is_ok() {
                    if let Some(body) = reply.windows(4).position(|b| b == b"\r\n\r\n") {
                        if let Ok(health) = serde_json::from_slice::<Value>(&reply[body + 4..]) {
                            assert_eq!(health["status"], "ready");
                            assert_eq!(health["backend"], backend);
                            return;
                        }
                    }
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "native profile readiness timed out"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[tokio::test]
#[ignore = "requires disposable Docker and explicit compiled native executable paths; mandatory in contracts CI"]
async fn native_owners_preserve_kms_only_custody() {
    let owners = [
        (
            "auth",
            "AUTH_POSTGRES_TEST_URL",
            "postgres_audit_behavior_matches_contract_when_configured",
            "auth_service",
        ),
        (
            "organization",
            "ORGANIZATION_POSTGRES_TEST_URL",
            "complete_repository_round_trip_is_tenant_bound_when_configured",
            "organization_service",
        ),
        (
            "credential_template",
            "CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL",
            "complete_repository_round_trip_is_tenant_bound_when_configured",
            "credential_template_service",
        ),
        (
            "presentation_policy",
            "PRESENTATION_POLICY_POSTGRES_TEST_URL",
            "migration_and_complete_repository_round_trip_when_configured",
            "presentation_policy_service",
        ),
        (
            "flow",
            "FLOW_MIGRATION_AUDIT_URL",
            "fresh_postgres_migration_is_idempotent_when_configured",
            "flow_service",
        ),
    ];
    // Resolve every input before starting Docker; a missing executable cannot silently skip coverage.
    let contracts: Vec<_> = owners
        .iter()
        .map(|(name, _, _, _)| executable(&format!("MARTY_KMS_{}_CONTRACT", name.to_uppercase())))
        .collect();
    let verification = executable("MARTY_KMS_VERIFICATION_BINARY");
    let deployment = executable("MARTY_KMS_DEPLOYMENT_BINARY");
    let compliance = executable("MARTY_KMS_COMPLIANCE_BINARY");
    let mut database = Database::start();
    let admin = database.admin().await;
    for ((name, variable, test, schema), binary) in owners.iter().zip(contracts) {
        println!("Native KMS custody owner: {name}");
        let db = format!("marty_kms_{name}");
        let pool = database.fresh(&admin, &db).await;
        let output = run(
            Command::new(binary)
                .args([*test, "--exact", "--test-threads=1"])
                .env(variable, database.url(&db)),
            120,
        );
        let summaries: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with("test result:"))
            .collect();
        assert_eq!(summaries.len(), 1, "one native test summary is required");
        assert!(
            summaries[0].starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"),
            "the exact native owner contract must execute once"
        );
        assert!(
            output
                .lines()
                .any(|line| line == format!("test {test} ... ok")),
            "the named native contract must report success"
        );
        custody(&pool, schema).await;
        pool.close().await;
    }
    println!("Native KMS custody owner: verification");
    let pool = database.fresh(&admin, "marty_kms_verification").await;
    for _ in 0..2 {
        run(
            Command::new(&verification)
                .arg("migrate")
                .env("DATABASE_URL", database.url("marty_kms_verification")),
            120,
        );
    }
    custody(&pool, "verification_service").await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid='public.verification_sessions'::regclass AND attnum>0 AND NOT attisdropped").fetch_one(&pool).await.unwrap();
    assert!(count > 0);
    pool.close().await;
    println!("Native KMS custody owners: deployment and compliance profiles");
    let pool = database.fresh(&admin, "marty_kms_profiles").await;
    for _ in 0..2 {
        start_profile(
            &deployment,
            "DEPLOYMENT_PROFILE",
            "marty-deployment-profile-rust",
            &database.url("marty_kms_profiles"),
        );
        start_profile(
            &compliance,
            "COMPLIANCE_PROFILE",
            "marty-compliance-profile-rust",
            &database.url("marty_kms_profiles"),
        );
    }
    let counts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM deployment_profile_service.deployment_profiles),(SELECT count(*) FROM compliance_profile_service.profiles),(SELECT count(*) FROM deployment_profile_service.native_migrations),(SELECT count(*) FROM compliance_profile_service.native_migrations)").fetch_one(&pool).await.unwrap();
    assert!(counts.0 > 0 && counts.1 > 0);
    assert_eq!((counts.2, counts.3), (1, 1));
    custody(&pool, "deployment_profile_service").await;
    custody(&pool, "compliance_profile_service").await;
    // Exercise the shared SQL on actual PostgreSQL, including nested JWK and PEM content.
    sqlx::raw_sql("CREATE TABLE public.custody_probe(payload jsonb, note text)")
        .execute(&pool)
        .await
        .unwrap();
    for payload in [
        r#"{"private_key":"rejected"}"#,
        r#"{"nested":{"kty":"EC","d":"rejected"}}"#,
        r#"{"pem":"-----BEGIN PRIVATE KEY-----"}"#,
    ] {
        sqlx::query("INSERT INTO public.custody_probe(payload) VALUES($1::jsonb)")
            .bind(payload)
            .execute(&pool)
            .await
            .unwrap();
        assert!(sqlx::raw_sql(CONTENT_SCAN).execute(&pool).await.is_err());
        sqlx::query("TRUNCATE public.custody_probe")
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO public.custody_probe(note) VALUES('-----BEGIN RSA PRIVATE KEY-----')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::raw_sql(CONTENT_SCAN).execute(&pool).await.is_err());
    sqlx::query("DROP TABLE public.custody_probe")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE public.private_key_probe(value text)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!sqlx::query_as::<_, (String,)>(SCHEMA_SCAN)
        .fetch_all(&pool)
        .await
        .unwrap()
        .is_empty());
    pool.close().await;
    admin.close().await;
    database.remove();
}
