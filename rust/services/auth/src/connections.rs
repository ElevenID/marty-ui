use std::{collections::BTreeMap, sync::Arc, time::Duration};

use mmf_data::{CacheBackend, CacheConfig, CacheStore, RedisCache};
use mmf_messaging::{MessageTransport, PostgresOutboxStore};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    KeylessGrpcTlsAcceptor, KeylessGrpcTransportOptions, OpenBaoTlsIdentityFiles,
    OutboundHttpClient, OutboundHttpMethod, OutboundHttpRequest, ReqwestOutboundHttpClient,
};
use mmf_security::RedisRateLimiter;
use sqlx::{postgres::PgPoolOptions, PgPool};
use thiserror::Error;

use crate::{
    event_stream_proto::event_stream_service_client::EventStreamServiceClient, migrate_auth_schema,
    validate_auth_schema, AuthDependency, AuthGrpcClients, AuthRuntime, AuthServiceConfig,
    GrpcEventStreamTransport, KeycloakOidcProvider,
};

const HEALTH_RESPONSE_LIMIT: usize = 64 * 1024;
const OUTBOX_PARTITIONS: u32 = 32;

#[derive(Debug, Error)]
pub enum AuthConnectionError {
    #[error("AUTH.STARTUP_DATABASE: {0}")]
    Database(String),
    #[error("AUTH.STARTUP_CACHE: {0}")]
    Cache(String),
    #[error("AUTH.STARTUP_OIDC: {0}")]
    Oidc(String),
    #[error("AUTH.STARTUP_GRPC: {0}")]
    Grpc(String),
    #[error("AUTH.STARTUP_HTTP: {0}")]
    Http(String),
    #[error("AUTH.STARTUP_OUTBOX: {0}")]
    Outbox(String),
    #[error("AUTH.STARTUP_RUNTIME: {0}")]
    Runtime(String),
}

pub struct AuthConnections {
    pub pool: PgPool,
    pub cache: Arc<dyn CacheStore>,
    pub rate_limiter: Arc<RedisRateLimiter>,
    pub oidc: Arc<KeycloakOidcProvider>,
    pub grpc_clients: crate::AuthGrpcClients,
    pub outbound_http: Arc<dyn OutboundHttpClient>,
    pub outbox: Arc<PostgresOutboxStore>,
    pub event_transport: Arc<GrpcEventStreamTransport>,
}

impl AuthConnections {
    pub async fn connect(
        config: &AuthServiceConfig,
        runtime: &AuthRuntime,
    ) -> Result<Self, AuthConnectionError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .connect(&config.database_url)
            .await
            .map_err(|error| AuthConnectionError::Database(error.to_string()))?;
        migrate_auth_schema(&pool)
            .await
            .map_err(|error| AuthConnectionError::Database(error.to_string()))?;
        validate_auth_schema(&pool)
            .await
            .map_err(|error| AuthConnectionError::Database(error.to_string()))?;
        runtime_health(runtime, AuthDependency::Database)?;

        let cache: Arc<dyn CacheStore> = Arc::new(
            RedisCache::connect(
                CacheConfig {
                    backend: CacheBackend::Redis,
                    url: Some(config.redis_url.clone()),
                    database: config.redis_database,
                    namespace: "auth".into(),
                    ..CacheConfig::default()
                },
                config.environment == "production",
            )
            .await
            .map_err(|error| AuthConnectionError::Cache(error.to_string()))?,
        );
        runtime_health(runtime, AuthDependency::SessionCache)?;
        let rate_limiter = Arc::new(
            RedisRateLimiter::connect(&config.redis_url, "auth:rate_limit")
                .await
                .map_err(|error| AuthConnectionError::Cache(error.to_string()))?,
        );
        rate_limiter
            .health_check()
            .await
            .map_err(|error| AuthConnectionError::Cache(error.to_string()))?;
        runtime_health(runtime, AuthDependency::RateLimit)?;

        let oidc = Arc::new(
            KeycloakOidcProvider::with_reqwest(config.oidc.clone())
                .map_err(|error| AuthConnectionError::Oidc(error.to_string()))?,
        );
        oidc.health_check()
            .await
            .map_err(|error| AuthConnectionError::Oidc(error.to_string()))?;
        runtime_health(runtime, AuthDependency::Oidc)?;

        let flow_channel = if let Some(tls) = &config.workload_client_tls {
            let target = config.flow_grpc_target.replacen("http://", "https://", 1);
            openbao_identity(tls)
                .grpc_channel_connected(
                    &target,
                    &tls.ca_certificate,
                    KeylessGrpcTransportOptions::default(),
                )
                .await
                .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        } else {
            workload_channel_factory(&config.flow_grpc_target)?
                .connect()
                .await
                .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        };
        let organization_channel = if let Some(tls) = &config.workload_client_tls {
            GrpcChannelFactory::new(
                GrpcChannelConfig {
                    target: config.organization_grpc_target.clone(),
                    security: GrpcTransportSecurity::ServerTls,
                    trust: GrpcTrustMode::CustomCa,
                    ..GrpcChannelConfig::default()
                },
                GrpcTlsMaterial::from_ca_pem_file(Some(&tls.ca_certificate))
                    .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?,
            )
            .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
            .connect()
            .await
            .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        } else {
            workload_channel_factory(&config.organization_grpc_target)?
                .connect()
                .await
                .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        };
        let grpc_clients = AuthGrpcClients::new(
            flow_channel,
            organization_channel,
            config.grpc_service_token.clone(),
        );
        runtime_health(runtime, AuthDependency::Flow)?;
        runtime_health(runtime, AuthDependency::Organization)?;

        let outbound_http: Arc<dyn OutboundHttpClient> = Arc::new(
            ReqwestOutboundHttpClient::new(Duration::from_secs(
                config.outbound_http_timeout_seconds,
            ))
            .map_err(|error| AuthConnectionError::Http(error.to_string()))?,
        );
        let (applicant_health, canvas_health) = tokio::join!(
            probe_http_health(outbound_http.as_ref(), &config.applicant_service_url),
            probe_http_health(outbound_http.as_ref(), &config.issuance_native_service_url),
        );
        applicant_health?;
        runtime_health(runtime, AuthDependency::Applicant)?;
        canvas_health?;
        runtime_health(runtime, AuthDependency::CanvasLti)?;

        let outbox = Arc::new(
            PostgresOutboxStore::new(pool.clone(), "auth", OUTBOX_PARTITIONS)
                .map_err(|error| AuthConnectionError::Outbox(error.to_string()))?,
        );
        outbox
            .migrate()
            .await
            .map_err(|error| AuthConnectionError::Outbox(error.to_string()))?;
        outbox
            .health()
            .await
            .map_err(|error| AuthConnectionError::Outbox(error.to_string()))?;
        runtime_health(runtime, AuthDependency::EventOutbox)?;

        let event_channel = if let Some(tls) = &config.workload_client_tls {
            GrpcChannelFactory::new(
                GrpcChannelConfig {
                    target: config.event_stream_grpc_target.clone(),
                    security: GrpcTransportSecurity::ServerTls,
                    trust: GrpcTrustMode::CustomCa,
                    ..GrpcChannelConfig::default()
                },
                GrpcTlsMaterial::from_ca_pem_file(Some(&tls.ca_certificate))
                    .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?,
            )
            .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
            .connect()
            .await
            .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        } else {
            workload_channel_factory(&config.event_stream_grpc_target)?
                .connect()
                .await
                .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?
        };
        let event_transport = Arc::new(GrpcEventStreamTransport::new(
            EventStreamServiceClient::new(event_channel),
            config.grpc_service_token.clone(),
        ));
        event_transport
            .connect()
            .await
            .map_err(|error| AuthConnectionError::Grpc(error.to_string()))?;
        runtime_health(runtime, AuthDependency::EventStream)?;

        Ok(Self {
            pool,
            cache,
            rate_limiter,
            oidc,
            grpc_clients,
            outbound_http,
            outbox,
            event_transport,
        })
    }
}

pub fn workload_channel_factory(target: &str) -> Result<GrpcChannelFactory, AuthConnectionError> {
    let (security, trust, material) = if target.starts_with("https://") {
        (
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        )
    } else {
        (
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        )
    };
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target: target.to_owned(),
            security,
            trust,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .map_err(|error| AuthConnectionError::Grpc(error.to_string()))
}

pub async fn workload_server_tls(
    config: &AuthServiceConfig,
) -> Result<Option<KeylessGrpcTlsAcceptor>, AuthConnectionError> {
    let Some(tls) = &config.workload_server_tls else {
        return Ok(None);
    };
    openbao_identity(tls)
        .grpc_acceptor(&tls.ca_certificate, 64, Duration::from_secs(15))
        .await
        .map(Some)
        .map_err(|error| AuthConnectionError::Grpc(error.to_string()))
}

fn openbao_identity(tls: &crate::AuthWorkloadClientTlsFiles) -> OpenBaoTlsIdentityFiles {
    OpenBaoTlsIdentityFiles {
        certificate_chain_file: tls.certificate.clone(),
        kms_ca_cert_file: tls.kms_ca_certificate.clone(),
        kms_endpoint: tls.kms_endpoint.clone(),
        kms_token_file: tls.kms_token_file.clone(),
        kms_key_name: tls.kms_key_name.clone(),
        kms_key_version: tls.kms_key_version,
        request_timeout: Duration::from_secs(10),
        max_concurrent_signs: 64,
    }
}

async fn probe_http_health(
    client: &dyn OutboundHttpClient,
    base_url: &str,
) -> Result<(), AuthConnectionError> {
    let response = client
        .execute(OutboundHttpRequest {
            method: OutboundHttpMethod::Get,
            url: format!("{}/health", base_url.trim_end_matches('/')),
            headers: BTreeMap::from([("accept".into(), "application/json".into())]),
            body: None,
            maximum_response_bytes: HEALTH_RESPONSE_LIMIT,
        })
        .await
        .map_err(|error| AuthConnectionError::Http(error.to_string()))?;
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(AuthConnectionError::Http(format!(
            "{base_url} health returned HTTP {}",
            response.status
        )))
    }
}

fn runtime_health(
    runtime: &AuthRuntime,
    dependency: AuthDependency,
) -> Result<(), AuthConnectionError> {
    runtime
        .mark_healthy(dependency)
        .map_err(|error| AuthConnectionError::Runtime(error.to_string()))
}
