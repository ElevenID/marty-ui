use marty_revocation_profile::{
    migrate_and_seed, migration_only_from_env, operational_router,
    proto::revocation_profile_service_server::RevocationProfileServiceServer, BackendReadiness,
    Config, MigrationConfig, NativeDiagnostics, OperationalState, OrganizationAuthorization,
    PgProfileRepository, PgRevocationOperationRepository, RedisStatusRepository,
    RevocationProfileGrpc, RevocationProfileHttp, RevocationProfileService,
};
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::broadcast};
use tonic::{service::Interceptor, transport::Server, Request, Status};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if migration_only_from_env()? {
        let config = MigrationConfig::from_env()?;
        let pool = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await?;
        migrate_and_seed(&pool, &config.organization_id, &config.status_list_base_url).await?;
        info!("Rust revocation-profile schema migration completed");
        return Ok(());
    }

    let config = Config::from_env().map_err(|error| {
        error!(%error, "invalid revocation-profile configuration");
        error
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    migrate_and_seed(&pool, &config.organization_id, &config.status_list_base_url).await?;
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis_connection = redis_client.get_connection_manager().await?;
    let authorization = OrganizationAuthorization::connect_lazy(
        config.organization_grpc_target.clone(),
        config.service_token.clone(),
    )?;

    let profiles = Arc::new(PgProfileRepository::from_pool(pool.clone()));
    let statuses = Arc::new(RedisStatusRepository::from_connection(
        redis_connection.clone(),
    ));
    let operations = Arc::new(PgRevocationOperationRepository::from_pool(pool.clone()));
    let service =
        RevocationProfileService::new(profiles, statuses, config.status_list_base_url.clone())?;
    let http_api = RevocationProfileHttp::new(service.clone(), Arc::new(authorization.clone()))
        .with_internal_service_token(config.service_token.clone())?
        .with_operation_repository(operations)
        .router();
    let readiness = BackendReadiness::new(pool, redis_connection, authorization);
    let diagnostics = NativeDiagnostics::new(
        config.release_version.clone(),
        config.build_revision.clone(),
    );
    let http_app = http_api
        .merge(operational_router(OperationalState::new(
            Arc::new(readiness),
            diagnostics,
        )))
        .layer(TraceLayer::new_for_http());
    let http_listener = TcpListener::bind(config.http_addr).await?;

    let grpc_service = RevocationProfileGrpc::new(service);
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<RevocationProfileServiceServer<RevocationProfileGrpc>>()
        .await;

    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        grpc_enabled = config.grpc_enabled,
        environment = %config.environment,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "starting Rust revocation-profile service"
    );

    let (shutdown_sender, _) = broadcast::channel::<()>(1);
    let shutdown_trigger = shutdown_sender.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_trigger.send(());
    });

    let mut http_shutdown = shutdown_sender.subscribe();
    let http_server = axum::serve(http_listener, http_app).with_graceful_shutdown(async move {
        let _ = http_shutdown.recv().await;
    });

    if config.grpc_enabled {
        let mut grpc_shutdown = shutdown_sender.subscribe();
        let grpc_server = Server::builder()
            .add_service(health_service)
            .add_service(RevocationProfileServiceServer::with_interceptor(
                grpc_service,
                ServiceTokenInterceptor::new(config.service_token),
            ))
            .serve_with_shutdown(config.grpc_addr, async move {
                let _ = grpc_shutdown.recv().await;
            });
        tokio::try_join!(
            async {
                http_server
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            },
            async {
                grpc_server
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            }
        )?;
    } else {
        info!("gRPC listener disabled by RP_GRPC_ENABLED=false");
        http_server.await?;
    }
    Ok(())
}

#[derive(Clone)]
struct ServiceTokenInterceptor {
    expected: Option<Arc<str>>,
}

impl ServiceTokenInterceptor {
    fn new(expected: Option<String>) -> Self {
        Self {
            expected: expected.map(Arc::<str>::from),
        }
    }
}

impl Interceptor for ServiceTokenInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let Some(expected) = &self.expected else {
            return Ok(request);
        };
        let supplied = request
            .metadata()
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let valid = supplied.len() == expected.len()
            && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()));
        if valid {
            Ok(request)
        } else {
            Err(Status::unauthenticated(
                "missing or invalid internal service token",
            ))
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_service_token_check_fails_closed() {
        let mut interceptor = ServiceTokenInterceptor::new(Some("secret".into()));
        assert!(interceptor.call(Request::new(())).is_err());

        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("x-service-token", "secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }
}
