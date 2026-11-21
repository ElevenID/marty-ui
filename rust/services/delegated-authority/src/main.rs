//! Optional, explicitly configured organization approval producer.
//! No lifecycle command, final-use endpoint or receipt signer is hosted here.

use std::{error::Error, io, sync::Arc, time::Duration};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use marty_delegated_authority::{
    approval::OrganizationApprovalConfiguration,
    approval_host_config::ApprovalHostConfig,
    approval_http::{organization_approval_router, ApprovalHttpState},
    approval_postgres::PgOrganizationApprovalService,
    organization_authority::PgOrganizationAuthorityProducer,
    PgDelegationGrantRepository, SystemDelegationClock,
};
use marty_organization::postgres::PostgresOrganizationStore;
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::{net::TcpListener, sync::watch};

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

async fn connect(url: &str) -> Result<PgPool, io::Error> {
    tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // A statement failure rolls back its transaction. Original results
                    // remain the only recovery path if a response is lost after commit.
                    sqlx::raw_sql("SET statement_timeout='5s'; SET lock_timeout='3s';")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(url),
    )
    .await
    .map_err(|_| failure("approval database connection timed out"))?
    .map_err(|_| failure("approval database connection failed"))
}

fn command_database(name: &str) -> Result<String, io::Error> {
    let inline = std::env::var(name).ok();
    let file = std::env::var(format!("{name}_FILE")).ok();
    match (inline, file) {
        (Some(value), None) if !value.is_empty() => Ok(value),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
            .map_err(|_| failure("approval command database secret could not be read")),
        _ => Err(failure(
            "approval command requires exactly one database URL or secret file",
        )),
    }
}

#[derive(Clone)]
struct Readiness {
    service: Arc<PgOrganizationApprovalService>,
    repository: PgDelegationGrantRepository,
}

async fn ready(State(state): State<Readiness>) -> StatusCode {
    if state.repository.readiness().await.is_ok() && state.service.readiness().await.is_ok() {
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
                "DELEGATION_APPROVAL_RUNTIME_DATABASE_URL"
            };
            let pool = connect(&command_database(name)?).await?;
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
        return Err(failure("unsupported approval service command").into());
    }

    let host = ApprovalHostConfig::from_env()?;
    let configuration = OrganizationApprovalConfiguration::new(
        host.organization_id,
        host.issuer.clone(),
        host.pin.clone(),
        host.review_ttl_seconds,
        host.confirmation_max_age_seconds,
        host.authority_validity_seconds,
    )?;
    let runtime_pool = connect(&host.runtime_database_url).await?;
    let consent_pool = connect(&host.consent_database_url).await?;
    let authority_pool = connect(&host.authority_database_url).await?;
    let organization_pool = connect(&host.organization_database_url).await?;
    let repository = PgDelegationGrantRepository::new(runtime_pool.clone());
    repository.readiness().await?;
    let clock = Arc::new(SystemDelegationClock);
    let authority = Arc::new(PgOrganizationAuthorityProducer::new(
        PostgresOrganizationStore::new(organization_pool),
        authority_pool,
        configuration.clone(),
        clock.clone(),
    ));
    let application = Arc::new(PgOrganizationApprovalService::new(
        runtime_pool,
        consent_pool,
        authority.clone(),
        configuration,
        clock,
    )?);
    // This checks actual connected identities/privileges, not merely different
    // URL strings. Neither startup nor readiness applies migrations or grants.
    application.readiness().await?;
    authority.readiness().await?;
    let state = ApprovalHttpState::new(
        application.clone(),
        host.service_token,
        host.organization_id,
    )?;
    let router = Router::new()
        .route("/health", get(|| async { Json(json!({"status":"up"})) }))
        .route("/ready", get(ready))
        .with_state(Readiness {
            service: application,
            repository,
        })
        .merge(organization_approval_router(state));
    let listener = TcpListener::bind(host.http_addr).await?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let refresh_seconds = host.authority_refresh_seconds;
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(u64::from(refresh_seconds)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() { break; }
                }
                _ = interval.tick() => {
                    if authority.refresh_due_authorities(128).await.is_err() {
                        // Do not renew timestamps on failure. Every verification
                        // independently checks live membership and the stored TTL.
                        eprintln!("organization authority refresh unavailable; stale authority remains denied");
                    }
                }
            }
        }
    });
    eprintln!(
        "organization approval candidate listening on {}",
        host.http_addr
    );
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            marty_service_runtime::shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        })
        .await;
    // A listener error must not strand the independently owned worker.
    worker.abort();
    let _ = worker.await;
    result?;
    Ok(())
}
