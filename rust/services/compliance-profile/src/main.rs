use marty_compliance_profile::{
    compliance_router, run_migrations, tenant_membership_provider, ComplianceDependency,
    ComplianceHttpState, ComplianceRepository, ComplianceRuntime, ComplianceService,
    ComplianceServiceConfig, PostgresComplianceRepository,
};
use sqlx::postgres::PgPoolOptions;
use std::{error::Error, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::watch};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let c = ComplianceServiceConfig::from_env()?;
    let runtime = ComplianceRuntime::new(&c)?;
    let pool = PgPoolOptions::new()
        .max_connections(c.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&c.database_url)
        .await?;
    runtime.mark_healthy(ComplianceDependency::Database)?;
    run_migrations(&pool).await?;
    runtime.mark_healthy(ComplianceDependency::Schema)?;
    runtime.mark_healthy(ComplianceDependency::SystemCatalog)?;
    let membership = tenant_membership_provider(&c)?;
    runtime.mark_healthy(ComplianceDependency::Organization)?;
    let repo: Arc<dyn ComplianceRepository> = Arc::new(PostgresComplianceRepository::new(pool));
    let service = Arc::new(ComplianceService::new(repo, membership));
    runtime.mark_healthy(ComplianceDependency::NativeKernel)?;
    let listener = TcpListener::bind(c.http_addr).await?;
    runtime.mark_healthy(ComplianceDependency::HttpListener)?;
    let app = runtime
        .router()
        .merge(compliance_router(ComplianceHttpState { service }))
        .layer(TraceLayer::new_for_http());
    let (tx, mut rx) = watch::channel(false);
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        while !*rx.borrow() && rx.changed().await.is_ok() {}
    });
    runtime.activate()?;
    info!(http_address=%c.http_addr,"native Rust Compliance Profile service active");
    tokio::select! {r=server=>r?,()=shutdown()=>{runtime.drain()?;let _=tx.send(true);}}
    let _ = tx.send(true);
    runtime.stop()?;
    Ok(())
}
async fn shutdown() {
    let c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let t = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let t = std::future::pending::<()>();
    tokio::select! {()=c=>{},()=t=>{}}
}
