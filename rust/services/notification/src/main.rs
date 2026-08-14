use marty_notification::{
    delivery::{
        outbox_batch_size, outbox_lease_seconds, outbox_poll_milliseconds,
        outbox_retention_seconds, run_worker,
    },
    domain::default_templates,
    grpc::NotificationGrpc,
    http::{router_with_service, validate_internal_auth_config},
    migration,
    postgres::PgNotificationRepository,
    proto::notification_service_server::NotificationServiceServer,
    repository::NotificationRepository,
    service::NotificationService,
    webhook::WebhookSecretEnvelope,
};
use sqlx::postgres::PgPoolOptions;
use std::{env, error::Error, fs, io, net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use tonic::{
    metadata::MetadataMap,
    service::Interceptor,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Status,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct GrpcAuth {
    token: Option<String>,
}

impl Interceptor for GrpcAuth {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let Some(expected) = &self.token else {
            return Ok(request);
        };
        let supplied = service_token(request.metadata());
        if supplied.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1 {
            Ok(request)
        } else {
            Err(Status::unauthenticated("Missing or invalid service token"))
        }
    }
}

fn service_token(metadata: &MetadataMap) -> &str {
    metadata
        .get("x-service-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}
fn io_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn is_development() -> bool {
    matches!(
        env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".into())
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev" | "local" | "test"
    )
}

fn read_secret(name: &str) -> Result<String, io::Error> {
    let direct = env::var(name).unwrap_or_default().trim().to_owned();
    let file = env::var(format!("{name}_FILE"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !direct.is_empty() && !file.is_empty() {
        return Err(io_error(format!(
            "Both {name} and {name}_FILE are configured"
        )));
    }
    if file.is_empty() {
        Ok(direct)
    } else {
        fs::read_to_string(file)
            .map(|value| value.trim().to_owned())
            .map_err(|_| io_error(format!("Unable to read {name}_FILE")))
    }
}

fn grpc_token() -> Result<Option<String>, io::Error> {
    let token = read_secret("GRPC_SERVICE_TOKEN")?;
    if token.is_empty() && is_development() {
        return Ok(None);
    }
    if token.len() < 32
        || [
            "change-me",
            "change_me",
            "changeme",
            "replace-me",
            "replace_me",
        ]
        .iter()
        .any(|prefix| token.to_ascii_lowercase().starts_with(prefix))
    {
        return Err(io_error("GRPC_SERVICE_TOKEN is not production-safe"));
    }
    Ok(Some(token))
}

fn grpc_tls() -> Result<Option<ServerTlsConfig>, io::Error> {
    let cert = env::var("GRPC_TLS_CERT").unwrap_or_default();
    let key = env::var("GRPC_TLS_KEY").unwrap_or_default();
    if cert.is_empty() != key.is_empty() {
        return Err(io_error("Incomplete gRPC TLS configuration"));
    }
    if cert.is_empty() {
        if is_development() {
            return Ok(None);
        }
        return Err(io_error(
            "gRPC TLS is required outside development environments",
        ));
    }
    let mut config =
        ServerTlsConfig::new().identity(Identity::from_pem(fs::read(cert)?, fs::read(key)?));
    let require_client = matches!(
        env::var("GRPC_TLS_REQUIRE_CLIENT_AUTH")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    );
    if require_client {
        let ca = env::var("GRPC_TLS_CA_CERT")
            .map_err(|_| io_error("GRPC_TLS_CA_CERT is required for client authentication"))?;
        config = config.client_ca_root(Certificate::from_pem(fs::read(ca)?));
    }
    Ok(Some(config))
}

fn database_url() -> String {
    env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://marty:marty_dev@localhost:5432/marty_credentials".into())
        .replace("postgresql+asyncpg://", "postgresql://")
}
fn address(port_name: &str, default: u16) -> Result<SocketAddr, io::Error> {
    let port = env::var(port_name).ok().map_or(Ok(default), |value| {
        value
            .parse::<u16>()
            .map_err(|_| io_error(format!("{port_name} must be a port")))
    })?;
    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let pool = PgPoolOptions::new()
        .max_connections(30)
        .connect(&database_url())
        .await?;
    let envelope = Arc::new(WebhookSecretEnvelope::from_environment()?);
    envelope.check_ready().await?;
    if env::args().any(|argument| argument == "--migrate") {
        migration::migrate(&pool, &envelope).await?;
        info!("notification schema migrated");
        return Ok(());
    }
    migration::validate(&pool).await?;
    validate_internal_auth_config().map_err(io_error)?;
    outbox_retention_seconds().map_err(io_error)?;
    outbox_lease_seconds().map_err(io_error)?;
    outbox_poll_milliseconds().map_err(io_error)?;
    outbox_batch_size().map_err(io_error)?;
    let repository: Arc<dyn NotificationRepository> = Arc::new(PgNotificationRepository::new(pool));
    for template in default_templates(chrono::Utc::now()) {
        if repository.get_template(&template.id).await?.is_none() {
            repository.save_template(template).await?
        }
    }
    let service = NotificationService::with_envelope(repository.clone(), envelope.clone());
    let http_address = address("NOTIFICATION_SERVICE_PORT", 8007)?;
    let listener = tokio::net::TcpListener::bind(http_address).await?;
    let http = axum::serve(listener, router_with_service(service.clone()));
    info!(address=%http_address,"notification HTTP listening");
    let worker = tokio::spawn(run_worker(repository.clone(), envelope));
    let grpc_enabled = env::var("NOTIF_GRPC_ENABLED")
        .unwrap_or_else(|_| "true".into())
        .eq_ignore_ascii_case("true");
    if grpc_enabled {
        let grpc_address = address("NOTIF_GRPC_PORT", 9007)?;
        let auth = GrpcAuth {
            token: grpc_token()?,
        };
        let notification = NotificationServiceServer::with_interceptor(
            NotificationGrpc::with_service(service),
            auth,
        );
        let (reporter, health) = tonic_health::server::health_reporter();
        reporter
            .set_serving::<NotificationServiceServer<NotificationGrpc>>()
            .await;
        let mut server = Server::builder();
        if let Some(tls) = grpc_tls()? {
            server = server.tls_config(tls)?
        }
        let grpc = server
            .add_service(health)
            .add_service(notification)
            .serve(grpc_address);
        info!(address=%grpc_address,"notification gRPC listening");
        tokio::select! {result=http=>{result?},result=grpc=>{result?},_ = shutdown()=>{info!("notification shutdown requested")}}
    } else {
        tokio::select! {result=http=>{result?},_ = shutdown()=>{info!("notification shutdown requested")}}
    }
    worker.abort();
    if let Err(join_error) = worker.await {
        if !join_error.is_cancelled() {
            error!(error=%join_error,"notification worker stopped unexpectedly")
        }
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal registration");
        tokio::select! {_ = ctrl_c=>{},_ = terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
