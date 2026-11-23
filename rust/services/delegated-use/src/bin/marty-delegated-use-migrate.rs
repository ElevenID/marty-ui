//! Owner-only migration entry point. The serving binary only verifies schema.

use std::{env, fs, process::ExitCode, time::Duration};

use marty_delegated_authority::PgDelegationGrantRepository;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

#[derive(Clone, Copy)]
enum Schema {
    DelegatedAuthority,
    MachineCredentialSource,
}

async fn run() -> Result<(), &'static str> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let schema = match arguments.as_slice() {
        [name] if name == "delegated-authority" => Schema::DelegatedAuthority,
        [name] if name == "machine-credential-source" => Schema::MachineCredentialSource,
        _ => return Err("select delegated-authority or machine-credential-source"),
    };

    let url_file = env::var_os("DELEGATED_USE_MIGRATION_DATABASE_URL_FILE")
        .ok_or("DELEGATED_USE_MIGRATION_DATABASE_URL_FILE is required")?;
    let ca_file = env::var_os("DELEGATED_USE_MIGRATION_DATABASE_CA_FILE")
        .ok_or("DELEGATED_USE_MIGRATION_DATABASE_CA_FILE is required")?;
    let url =
        fs::read_to_string(url_file).map_err(|_| "migration database URL file unavailable")?;
    let connect_options: PgConnectOptions = url
        .trim_end_matches(['\r', '\n'])
        .parse()
        .map_err(|_| "migration database URL is invalid")?;
    let connect_options = connect_options
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file);

    marty_service_runtime::install_tls_crypto_provider();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET lock_timeout = '5s'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(connect_options)
        .await
        .map_err(|_| "verified TLS migration database connection failed")?;
    let result = match schema {
        Schema::DelegatedAuthority => PgDelegationGrantRepository::new(pool.clone())
            .migrate()
            .await
            .map_err(|_| "delegated authority migration failed"),
        Schema::MachineCredentialSource => marty_machine_credential_source::run_migrations(&pool)
            .await
            .map_err(|_| "machine credential source migration failed"),
    };
    pool.close().await;
    result
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
