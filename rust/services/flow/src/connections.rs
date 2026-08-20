use std::{sync::Arc, time::Duration};

use redis::aio::ConnectionManager;
use sqlx::{postgres::PgPoolOptions, PgPool};
use thiserror::Error;
use url::Url;

use crate::{
    migrate_flow_schema, FlowDependency, FlowGrpcChannelFactories, FlowMigrationError,
    FlowProviderError, FlowProviderRegistry, FlowRuntime, FlowServiceConfig,
    HttpPhysicalDocumentProvider, HttpSigningProvider, PostgresFlowRepository,
};

pub struct FlowBackendConnections {
    pub repository: PostgresFlowRepository,
    pub nonce_store: ConnectionManager,
    pub providers: Arc<FlowProviderRegistry>,
}

#[derive(Debug, Error)]
pub enum FlowConnectionError {
    #[error("FLOW.DEPENDENCY_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("FLOW.DEPENDENCY_SCHEMA: {0}")]
    Migration(#[from] FlowMigrationError),
    #[error("FLOW.DEPENDENCY_NONCE_STORE: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("FLOW.DEPENDENCY_GRPC: {0}")]
    Grpc(#[from] mmf_platform::PlatformError),
    #[error("FLOW.DEPENDENCY_HTTP: {0}")]
    Http(#[from] FlowProviderError),
    #[error("FLOW.DEPENDENCY_RUNTIME: {0}")]
    Runtime(#[from] mmf_core::MmfError),
    #[error("FLOW.CONFIGURATION: {0}")]
    Configuration(String),
}

impl FlowBackendConnections {
    pub async fn connect(
        config: &FlowServiceConfig,
        runtime: &FlowRuntime,
    ) -> Result<Self, FlowConnectionError> {
        let pool = connect_database(config, runtime).await?;
        let nonce_store = connect_nonce_store(config, runtime).await?;
        let providers = connect_providers(config, runtime).await?;
        providers.require_complete()?;
        Ok(Self {
            repository: PostgresFlowRepository::new(pool),
            nonce_store,
            providers: Arc::new(providers),
        })
    }
}

async fn connect_database(
    config: &FlowServiceConfig,
    runtime: &FlowRuntime,
) -> Result<PgPool, FlowConnectionError> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    migrate_flow_schema(&pool).await?;
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await?;
    runtime.mark_healthy(FlowDependency::Database)?;
    Ok(pool)
}

async fn connect_nonce_store(
    config: &FlowServiceConfig,
    runtime: &FlowRuntime,
) -> Result<ConnectionManager, FlowConnectionError> {
    let redis_url = redis_database_url(&config.redis_url, config.redis_database)?;
    let client = redis::Client::open(redis_url)?;
    let mut connection = client.get_connection_manager().await?;
    let response: String = redis::cmd("PING").query_async(&mut connection).await?;
    if response != "PONG" {
        return Err(FlowConnectionError::Configuration(
            "nonce store returned an invalid health response".into(),
        ));
    }
    runtime.mark_healthy(FlowDependency::NonceStore)?;
    Ok(connection)
}

async fn connect_providers(
    config: &FlowServiceConfig,
    runtime: &FlowRuntime,
) -> Result<FlowProviderRegistry, FlowConnectionError> {
    let clients = FlowGrpcChannelFactories::from_config(config)?
        .connect()
        .await?;
    runtime.mark_healthy(FlowDependency::Organization)?;
    runtime.mark_healthy(FlowDependency::CredentialTemplate)?;
    runtime.mark_healthy(FlowDependency::PresentationPolicy)?;
    runtime.mark_healthy(FlowDependency::IssuanceGrpc)?;
    let grpc = clients.providers(config.service_token.as_deref())?;

    let signing = Arc::new(HttpSigningProvider::new(
        &config.signing_keys_url,
        required_secret(&config.signing_keys_api_key, "signing keys API key")?,
    )?);
    signing.health_check().await?;
    runtime.mark_healthy(FlowDependency::SigningKeys)?;

    let physical = Arc::new(HttpPhysicalDocumentProvider::new(
        &config.issuance_url,
        required_secret(&config.issuance_api_key, "issuance API key")?,
    )?);
    physical.health_check().await?;
    runtime.mark_healthy(FlowDependency::PhysicalIssuance)?;

    Ok(FlowProviderRegistry {
        tenant_membership: Some(Arc::new(grpc.tenant_membership)),
        credential_template: Some(Arc::new(grpc.credential_template)),
        presentation_policy: Some(Arc::new(grpc.presentation_policy)),
        issuance: Some(Arc::new(grpc.issuance)),
        signing_identity: Some(signing.clone()),
        flow_key_envelope: Some(signing),
        physical_document: Some(physical),
    })
}

fn redis_database_url(value: &str, database: u8) -> Result<String, FlowConnectionError> {
    let mut url = Url::parse(value)
        .map_err(|_| FlowConnectionError::Configuration("Redis URL is invalid".into()))?;
    url.set_path(&format!("/{database}"));
    Ok(url.into())
}

fn required_secret<'a>(
    value: &'a Option<String>,
    name: &str,
) -> Result<&'a str, FlowConnectionError> {
    value
        .as_deref()
        .ok_or_else(|| FlowConnectionError::Configuration(format!("{name} is missing")))
}

#[cfg(test)]
mod tests {
    use super::redis_database_url;

    #[test]
    fn redis_database_selection_is_canonical_and_secret_safe() {
        assert_eq!(
            redis_database_url("redis://user:secret@redis:6379/9", 3).unwrap(),
            "redis://user:secret@redis:6379/3"
        );
        assert!(redis_database_url("not a URL", 3).is_err());
    }
}
