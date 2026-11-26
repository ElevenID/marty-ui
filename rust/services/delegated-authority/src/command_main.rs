//! Optional lifecycle-command host. Holds no approval producer write credential.
use std::{error::Error, io, sync::Arc, time::Duration};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use marty_delegated_authority::{
    command_host_config::CommandHostConfig,
    command_http::{organization_command_router, CommandHttpState},
    command_postgres::PgOrganizationCommandService,
    PgDelegationGrantRepository, SystemDelegationClock,
};
use marty_organization::postgres::PostgresOrganizationStore;
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}
async fn connect(url: &str, maximum: u32) -> Result<PgPool, io::Error> {
    tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new()
            .max_connections(maximum)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::raw_sql("SET statement_timeout='5s'; SET lock_timeout='3s';")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(url),
    )
    .await
    .map_err(|_| failure("command database connection timed out"))?
    .map_err(|_| failure("command database connection failed"))
}
fn database_secret(name: &str) -> Result<String, io::Error> {
    match (
        std::env::var(name).ok(),
        std::env::var(format!("{name}_FILE")).ok(),
    ) {
        (Some(value), None) if !value.is_empty() => Ok(value),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
            .map_err(|_| failure("command database secret file could not be read")),
        _ => Err(failure(
            "command requires exactly one database URL or secret file",
        )),
    }
}
async fn ready(State(service): State<Arc<PgOrganizationCommandService>>) -> StatusCode {
    if service.readiness().await.is_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    marty_service_runtime::install_tls_crypto_provider();
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let [command] = arguments.as_slice() {
        if command == "migrate" || command == "verify-owned-schema" {
            let name = if command == "migrate" {
                "DELEGATION_MIGRATION_DATABASE_URL"
            } else {
                "DELEGATION_COMMAND_RUNTIME_DATABASE_URL"
            };
            let pool = connect(&database_secret(name)?, 1).await?;
            let repository = PgDelegationGrantRepository::new(pool.clone());
            if command == "migrate" {
                repository.migrate().await?;
            } else {
                repository.readiness().await?;
            }
            pool.close().await;
            return Ok(());
        }
    }
    if !arguments.is_empty() {
        return Err(failure("unsupported delegation command host argument").into());
    }
    let host = CommandHostConfig::from_env()?;
    let writer = connect(
        &host.command_database_url,
        host.command_pool_max_connections,
    )
    .await?;
    let reader = connect(
        &host.runtime_database_url,
        host.runtime_pool_max_connections,
    )
    .await?;
    let organization = connect(
        &host.organization_database_url,
        host.organization_pool_max_connections,
    )
    .await?;
    let application = Arc::new(PgOrganizationCommandService::new(
        writer,
        reader,
        PostgresOrganizationStore::new(organization),
        host.configuration.clone(),
        host.authority,
        Arc::new(SystemDelegationClock),
    )?);
    // Startup only verifies migrations, actual role identities and capabilities.
    // Owner migrations and role grants remain explicit external operations.
    application.readiness().await?;
    let state = CommandHttpState::new(
        application.clone(),
        host.service_token,
        host.configuration.organization_id(),
    )?;
    let router = Router::new()
        .route("/health", get(|| async { Json(json!({"status":"up"})) }))
        .route("/ready", get(ready))
        .with_state(application)
        .merge(organization_command_router(state));
    let listener = TcpListener::bind(host.http_addr).await?;
    eprintln!(
        "organization delegation commands listening on {}",
        host.http_addr
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(marty_service_runtime::shutdown_signal())
        .await?;
    Ok(())
}
