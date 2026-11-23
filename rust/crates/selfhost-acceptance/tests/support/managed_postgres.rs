//! Owned local PostgreSQL process; never accepts a database URL or provider account.
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use sqlx::{postgres::PgConnectOptions, ConnectOptions};
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;

#[expect(
    dead_code,
    reason = "shared fixture command supports other test owners"
)]
#[path = "../../../../services/issuance/tests/support/bounded_fixture_command.rs"]
mod bounded_fixture_command;

// Supavisor's user.PROJECT_REF transport name resolves to the ordinary app
// role; a direct local PostgreSQL test must not invent that pooler mapping.
pub const APP_ROLE: &str = "elevenid";
pub const APP_PASSWORD: &str = "synthetic:p@ss/?#%$&=+[]";
pub const DATABASE: &str = "managed_service_test";

pub fn run(command: &mut Command, seconds: u64) -> std::process::Output {
    bounded_fixture_command::run(command, None, Duration::from_secs(seconds), 2 * 1024 * 1024)
        .expect("bounded owned fixture command must finish")
}

pub struct Database {
    pub directory: TempDir,
    bin: PathBuf,
    process: Option<Child>,
    port: u16,
    admin_password: String,
}

impl Database {
    pub fn start() -> Self {
        let bin = PathBuf::from(
            std::env::var_os("MARTY_TEST_POSTGRES_BIN_DIR")
                .expect("set the absolute local PostgreSQL bin directory"),
        );
        assert!(bin.is_absolute());
        for name in ["initdb", "postgres", "pg_ctl"] {
            assert!(
                bin.join(name).is_file(),
                "local PostgreSQL {name} is required"
            );
        }
        let directory = tempfile::Builder::new()
            .prefix("marty-managed-postgres-")
            .tempdir()
            .unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let admin_password = uuid::Uuid::new_v4().simple().to_string();
        private_file(&directory.path().join("admin-password"), &admin_password);
        let data = directory.path().join("data");
        let initialized = run(
            Command::new(bin.join("initdb"))
                .args(["--no-locale", "--encoding=UTF8", "--username=fixture_admin"])
                .args(["--auth-local=trust", "--auth-host=scram-sha-256"])
                .arg("--pwfile")
                .arg(directory.path().join("admin-password"))
                .arg("--pgdata")
                .arg(&data),
            45,
        );
        assert!(
            initialized.status.success(),
            "owned initdb failed: {}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        private_file(
            &directory.path().join("ca.pem"),
            &ca.self_signed(&ca_key).unwrap().pem(),
        );
        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&server_key, &Issuer::from_params(&ca, &ca_key))
            .unwrap();
        private_file(&data.join("server.pem"), &server.pem());
        private_file(&data.join("server.key"), &server_key.serialize_pem());
        fs::write(
            data.join("postgresql.auto.conf"),
            format!(
                "listen_addresses='127.0.0.1'\nport={port}\nunix_socket_directories=''\n\
                 ssl=on\nssl_cert_file='server.pem'\nssl_key_file='server.key'\n\
                 max_connections=36\nshared_buffers='16MB'\nstatement_timeout='30s'\n"
            ),
        )
        .unwrap();
        // Refuse plaintext on the owned TCP listener, including the admin connection.
        fs::write(
            data.join("pg_hba.conf"),
            "hostssl all all 127.0.0.1/32 scram-sha-256\n",
        )
        .unwrap();
        let log = fs::File::create(directory.path().join("postgres.log")).unwrap();
        drop(reservation);
        let process = Command::new(bin.join("postgres"))
            .arg("-D")
            .arg(data)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("owned postgres must start");
        Self {
            directory,
            bin,
            process: Some(process),
            port,
            admin_password,
        }
    }

    pub fn admin_options(&self, database: &str) -> PgConnectOptions {
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(self.port)
            .username("fixture_admin")
            .password(&self.admin_password)
            .database(database)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(self.ca())
            .disable_statement_logging()
    }

    pub fn ca(&self) -> PathBuf {
        self.directory.path().join("ca.pem")
    }

    pub fn app_url_from_secret_loader(&self) -> String {
        let password = self.directory.path().join("external_postgres_password");
        private_file(&password, APP_PASSWORD);
        let loader =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/load-secrets-env.sh");
        let template = format!(
            "postgresql://{APP_ROLE}:${{MARTY_DB_PASSWORD}}@127.0.0.1:{}/{DATABASE}?sslmode=verify-full",
            self.port
        );
        let output = run(
            Command::new("sh")
                .args([
                    "-c",
                    ". \"$MARTY_TEST_SECRET_LOADER\"; printf '%s' \"$DATABASE_URL\"",
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("MARTY_TEST_SECRET_LOADER", loader)
                .env("MARTY_DB_PASSWORD_FILE", password)
                .env("DATABASE_URL_TEMPLATE", template),
            10,
        );
        assert!(
            output.status.success(),
            "production database secret loader must succeed"
        );
        String::from_utf8(output.stdout).unwrap()
    }

    pub fn assert_running(&mut self) {
        assert!(
            self.process.as_mut().unwrap().try_wait().unwrap().is_none(),
            "owned PostgreSQL exited: {}",
            fs::read_to_string(self.directory.path().join("postgres.log")).unwrap_or_default()
        );
    }

    pub fn stop(&mut self) {
        let Some(mut process) = self.process.take() else {
            return;
        };
        let stopped = run(
            Command::new(self.bin.join("pg_ctl"))
                .arg("--pgdata")
                .arg(self.directory.path().join("data"))
                .args(["stop", "--mode=fast", "--wait", "--timeout=15"]),
            20,
        );
        if !stopped.status.success() {
            bounded_fixture_command::stop_owned_child(&mut process)
                .expect("owned PostgreSQL must be reaped");
        } else {
            process.wait().unwrap();
        }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.stop();
    }
}

fn private_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
