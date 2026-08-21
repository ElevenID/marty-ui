use marty_applicant::{
    http::{router, HttpState},
    migration::migrate_file,
    providers::{GrpcEventPublisher, HttpFlowProvider, HttpTemplateProvider},
    service::{ApplicantService, FilePersistence, MmfApprovalAuthorizer},
};
use mmf_security::ApplicationEventAuthenticator;
use reqwest::Client;
use std::{
    collections::BTreeMap,
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{net::TcpListener, sync::RwLock};
use tonic::transport::Endpoint;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let store_path = PathBuf::from(env_value(
        "APPLICANT_DATA_FILE",
        "/app/data/applicant_store.json",
    ));
    let migration_map = migration_map()?;
    let migrated = migrate_file(&store_path, &migration_map)?;
    let store = FilePersistence::load(&store_path)?;

    let application_secret = required_secret("FLOW_APPLICATION_EVENT_HMAC_KEY")?;
    let max_age = env_value("FLOW_APPLICATION_EVENT_MAX_AGE_SECONDS", "60").parse()?;
    let replay_ttl = env_value("FLOW_APPLICATION_EVENT_REPLAY_TTL_SECONDS", "300").parse()?;
    let application_auth =
        ApplicationEventAuthenticator::new(application_secret, max_age, replay_ttl)?;

    let issuance_url = env_value("ISSUANCE_SERVICE_URL", "http://issuance:8005");
    let flow_url = env_value("FLOW_SERVICE_URL", "http://flow:8011");
    let issuance_api_key = optional_secret("ISSUANCE_API_KEY")?;
    let event_stream_target = env_value("ES_GRPC_TARGET", "event-stream:9015");
    let event_stream_uri = if event_stream_target.contains("://") {
        event_stream_target
    } else {
        format!("http://{event_stream_target}")
    };
    let event_channel = Endpoint::from_shared(event_stream_uri)?.connect_lazy();
    let notification_url = env::var("NOTIFICATION_EVENT_INGEST_URL").ok().or_else(|| {
        env::var("NOTIFICATION_SERVICE_URL")
            .ok()
            .map(|url| format!("{}/internal/events", url.trim_end_matches('/')))
    });
    let notification_token = optional_secret("NOTIFICATION_APPLICANT_EVENT_TOKEN")?;

    let persistence = Arc::new(FilePersistence::new(&store_path));
    let service = Arc::new(ApplicantService::with_persistence(
        Arc::new(RwLock::new(store)),
        Arc::new(HttpTemplateProvider::new(
            issuance_url.clone(),
            issuance_api_key.clone(),
        )),
        Arc::new(HttpFlowProvider::new(flow_url, application_auth)),
        Arc::new(MmfApprovalAuthorizer::new()?),
        Arc::new(GrpcEventPublisher::new(
            event_channel,
            notification_url,
            notification_token,
        )),
        persistence,
    ));
    let port = env_value("APPLICANT_SERVICE_PORT", "8006").parse()?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(address).await?;
    info!(
        backend = "rust",
        version = env!("CARGO_PKG_VERSION"),
        migration_applied = migrated,
        store = %store_path.display(),
        address = %address,
        "applicant native backend ready"
    );
    axum::serve(
        listener,
        router(HttpState {
            service,
            issuance_url,
            issuance_api_key,
            client: Client::new(),
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

fn required_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    optional_secret(name)?.ok_or_else(|| format!("{name} is required").into())
}

fn optional_secret(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let direct = env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let file_name = env::var(format!("{name}_FILE"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if direct.is_some() && file_name.is_some() {
        return Err(format!("both {name} and {name}_FILE are configured").into());
    }
    if let Some(file_name) = file_name {
        let value = fs::read_to_string(file_name)?.trim().to_owned();
        return Ok((!value.is_empty()).then_some(value));
    }
    Ok(direct)
}

fn migration_map() -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let raw = env_value("APPLICATION_TEMPLATE_MIGRATION_MAP", "{}");
    let value = serde_json::from_str::<BTreeMap<String, String>>(&raw)?;
    Ok(value
        .into_iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .collect())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
