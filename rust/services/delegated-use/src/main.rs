//! Default-off internal use host. Startup verifies; it never migrates or grants.
use std::{process::ExitCode, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chrono::Utc;
use marty_delegated_authority::{
    use_http::DelegationUseHttpAuthenticator, use_mtls::BoundDelegatedUseMtlsServer,
};
use marty_delegated_use::{config::DelegatedUseHostConfig, runtime::DelegatedUseRuntime};

#[derive(Clone)]
struct ProbeState {
    runtime: Arc<DelegatedUseRuntime>,
    authenticator: Arc<DelegationUseHttpAuthenticator>,
    organization: String,
}

fn response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn health(State(state): State<ProbeState>, request: Request) -> Response {
    probe(state, request, false).await
}
async fn ready(State(state): State<ProbeState>, request: Request) -> Response {
    probe(state, request, true).await
}
async fn probe(state: ProbeState, request: Request, readiness: bool) -> Response {
    let context = match state
        .authenticator
        .authenticate(&state.organization, &request)
    {
        Ok(context) => context,
        Err(error) => return error.into_response(),
    };
    if request.uri().query().is_some()
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value != "0")
    {
        return response(StatusCode::BAD_REQUEST);
    }
    let available = !readiness || state.runtime.readiness().await.is_ok();
    if let Err(error) = context.check(Utc::now()) {
        return error.into_response();
    }
    response(if available {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    })
}

async fn run() -> Result<(), String> {
    if std::env::args_os().nth(1).is_some() {
        return Err("delegated use accepts no command-line arguments".into());
    }
    // Configuration checks the opt-in before reading any credential or CA file.
    let config = DelegatedUseHostConfig::from_env().map_err(|error| error.to_string())?;
    marty_service_runtime::install_tls_crypto_provider();
    let runtime = Arc::new(
        DelegatedUseRuntime::connect(&config)
            .await
            .map_err(|_| "delegated use runtime qualification failed before listening")?,
    );
    // `connect` completed the actual source/role/remote readiness checks. Reuse
    // the exact authenticated identity selection for both probes and commands.
    let authenticator = runtime.authenticator();
    let probes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(ProbeState {
            runtime: runtime.clone(),
            authenticator,
            organization: config.organization_id.to_string(),
        });
    let router = runtime.router().merge(probes);
    let server = match BoundDelegatedUseMtlsServer::bind(
        config.listen_addr,
        &config.tls_identity,
        config.client_ca_der.clone(),
        router,
    )
    .await
    {
        Ok(server) => server,
        Err(_) => {
            runtime.close().await;
            return Err("delegated use mutual-TLS listener failed before serving".into());
        }
    };
    let address = server
        .local_addr()
        .map_err(|_| "delegated use listener address unavailable")?;
    eprintln!("internal delegated use listening on {address}");
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        marty_service_runtime::shutdown_signal().await;
        let _ = shutdown.send(true);
    });
    let result = server.serve(receiver).await;
    signal.abort();
    runtime.close().await;
    result.map_err(|_| "delegated use listener stopped with an error".into())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
