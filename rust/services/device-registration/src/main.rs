use marty_device_registration::{
    challenge::{ChallengeRepository, MemoryChallengeRepository, RedisChallengeRepository},
    control_plane::{MembershipAuthorizer, OrganizationMembershipClient},
    http::{router, HttpState},
    migration::migrate,
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
    let repository: Arc<dyn DeviceRepository> = Arc::new(PostgresDeviceRepository::new(pool));
    let challenge_ttl: u64 = env_value("DEVICE_CHALLENGE_TTL", "300").parse()?;
    if challenge_ttl == 0 || challenge_ttl > 3600 {
        return Err("DEVICE_CHALLENGE_TTL must be between 1 and 3600".into());
    }
    let challenges: Arc<dyn ChallengeRepository> = match env::var("REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(url) => Arc::new(RedisChallengeRepository::connect(&url, challenge_ttl).await?),
        None if deployed => {
            return Err(
                "REDIS_URL is required for atomic device challenges in deployed environments"
                    .into(),
            )
        }
        None => Arc::new(MemoryChallengeRepository::new(challenge_ttl)),
    };
    let rotation_grace = env_value("DEVICE_KEY_ROTATION_GRACE_SECONDS", "300").parse()?;
    let service = Arc::new(DeviceService::new(repository, challenges, rotation_grace)?);
    let token = optional_secret("GRPC_SERVICE_TOKEN")?;
    if deployed && token.is_none() {
        return Err("GRPC_SERVICE_TOKEN is required in deployed environments".into());
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
    info!(backend="rust", native_kernel="marty-verification::device_auth", version=%release_version, revision=%build_revision, %address, "device registration native backend ready");
    axum::serve(
        listener,
        router(HttpState {
            service,
            memberships,
            release_version,
            build_revision,
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
