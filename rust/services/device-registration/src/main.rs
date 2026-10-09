use marty_device_registration::{
    control_plane::{MembershipAuthorizer, OrganizationMembershipClient},
    holder_key_cleanup::HolderKeyCleanup,
    holder_key_client::HolderKeyClient,
    holder_key_repository::PostgresHolderKeyRepository,
    http::{router, HttpState},
    migration::{migrate, validate},
    postgres::PostgresDeviceRepository,
    DeviceRepository, DeviceService,
};
use sqlx::postgres::PgPoolOptions;
use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let arguments: Vec<String> = env::args().skip(1).collect();
    if let [command] = arguments.as_slice() {
        if command == "migrate" || command == "verify-owned-schema" {
            let database_url =
                required("DATABASE_URL")?.replacen("postgresql+asyncpg://", "postgresql://", 1);
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&database_url)
                .await?;
            if command == "migrate" {
                migrate(&pool).await?;
            } else {
                validate(&pool).await?;
            }
            pool.close().await;
            return Ok(());
        }
    }
    if !arguments.is_empty() {
        return Err("unsupported Device Registration command".into());
    }
    let environment = env_value("ENVIRONMENT", "development").to_ascii_lowercase();
    let deployed = !matches!(
        environment.as_str(),
        "development" | "dev" | "local" | "test"
    );
    let database_url =
        required("DATABASE_URL")?.replacen("postgresql+asyncpg://", "postgresql://", 1);
    let pool = PgPoolOptions::new()
        .max_connections(env_value("DATABASE_MAX_CONNECTIONS", "10").parse()?)
        .connect(&database_url)
        .await?;
    migrate(&pool).await?;
    let repository: Arc<dyn DeviceRepository> =
        Arc::new(PostgresDeviceRepository::new(pool.clone()));
    let service = Arc::new(DeviceService::new(repository));
    let token = optional_secret("GRPC_SERVICE_TOKEN")?;
    if deployed && token.is_none() {
        return Err("GRPC_SERVICE_TOKEN is required in deployed environments".into());
    }
    let gateway_key = optional_secret("DEVICE_REGISTRATION_GATEWAY_KEY")?
        .or_else(|| (!deployed).then(|| "dev-device-registration-gateway-key-change-me".into()))
        .ok_or("DEVICE_REGISTRATION_GATEWAY_KEY is required in deployed environments")?;
    if gateway_key.len() < 32 {
        return Err("DEVICE_REGISTRATION_GATEWAY_KEY must contain at least 32 bytes".into());
    }
    if token.as_deref() == Some(gateway_key.as_str()) {
        return Err("DEVICE_REGISTRATION_GATEWAY_KEY must differ from GRPC_SERVICE_TOKEN".into());
    }
    let holder_service_key = optional_secret("DEVICE_REGISTRATION_SIGNING_KEYS_KEY")?;
    let holder_origin = env::var("SIGNING_KEYS_HOLDER_ORIGIN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if holder_service_key.is_some() != holder_origin.is_some() {
        return Err(
            "holder Signing Keys origin and service credential must be configured together".into(),
        );
    }
    if let (Some(origin), Some(key)) = (holder_origin, holder_service_key) {
        if key == gateway_key || token.as_deref() == Some(key.as_str()) {
            return Err("holder Signing Keys credential must be dedicated".into());
        }
        let client = HolderKeyClient::new(&origin, key)?;
        let cleanup = HolderKeyCleanup::new(PostgresHolderKeyRepository::new(pool), client);
        tokio::spawn(cleanup.run_forever());
    }
    let target = env_value("ORG_GRPC_TARGET", "organization:9002");
    let target = if target.contains("://") {
        target
    } else {
        format!("http://{target}")
    };
    let memberships: Arc<dyn MembershipAuthorizer> =
        Arc::new(OrganizationMembershipClient::connect_lazy(
            &target,
            token.as_deref(),
            Duration::from_secs(env_value("ORG_GRPC_TIMEOUT_SECONDS", "5").parse()?),
        )?);
    let port = env_value("DEVICE_REGISTRATION_SERVICE_PORT", "8014").parse()?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(address).await?;
    let release_version = env_value("MARTY_RELEASE_VERSION", env!("CARGO_PKG_VERSION"));
    let build_revision = env_value("MARTY_UI_SHA", "unknown");
    info!(backend="rust", native_kernel="marty-device-registration::repository", version=%release_version, revision=%build_revision, %address, "device registration native backend ready");
    axum::serve(
        listener,
        router(HttpState {
            service,
            memberships,
            release_version,
            build_revision,
            gateway_key,
        }),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

fn env_value(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.into())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

fn optional_secret(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let direct = env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let file = env::var(format!("{name}_FILE"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if direct.is_some() && file.is_some() {
        return Err(format!("both {name} and {name}_FILE are configured").into());
    }
    if let Some(path) = file {
        let value = fs::read_to_string(path)?.trim().to_owned();
        return Ok((!value.is_empty()).then_some(value));
    }
    Ok(direct)
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
