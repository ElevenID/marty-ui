use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use marty_signing_keys::{
    config::Config, csca_lifecycle::CscaLifecycleStore, documents::DocumentStore,
    flow_envelope::OpenBaoEnvelopeProvider, http, managed_holder_http,
    managed_holder_key::OpenBaoManagedHolderKeys, profiles::ProfileStore, registry::RegistryStore,
    vc_api_holder_proof::OpenBaoHolderProofProvider,
};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env().map_err(|error| {
        error!(%error, "invalid signing-keys configuration");
        error
    })?;
    let managed_openbao_endpoint = config.bao_addr.clone();
    let holder_api = match (
        config.holder_device_key.as_ref(),
        config.bao_addr.as_ref(),
        config.bao_token.as_ref(),
    ) {
        (Some(key), Some(endpoint), Some(token)) => Some((
            key.clone(),
            OpenBaoManagedHolderKeys::new(endpoint.clone(), token.clone())?,
        )),
        _ => None,
    };
    let registry_store = RegistryStore::connect(&config.registry_redis_url)
        .await?
        .with_managed_openbao(managed_openbao_endpoint);
    let document_store = DocumentStore::from_connection(registry_store.connection());
    let csca_lifecycle_store = CscaLifecycleStore::from_connection(registry_store.connection());
    let profile_store = ProfileStore::from_connection(registry_store.connection());
    // A configured KMS must also be able to reconcile ephemeral holder keys
    // after an interrupted request. Do not silently disable that cleanup.
    let holder_proofs = if config.bao_addr.is_some() {
        Some(OpenBaoHolderProofProvider::from_environment()?)
    } else {
        None
    };
    let flow_envelopes = match (config.bao_addr, config.bao_token) {
        (Some(address), Some(token)) => Some(OpenBaoEnvelopeProvider::new(address, token)?),
        (None, None) => None,
        _ => unreachable!("configuration validates paired OpenBao values"),
    };
    let flow_envelopes = match (flow_envelopes, config.haip_kms_token_file) {
        (Some(provider), Some(path)) => Some(provider.with_haip_token_file(path)?),
        (provider, None) => provider,
        (None, Some(_)) => unreachable!("configuration requires BAO_ADDR for HAIP token"),
    };
    if let Some(holder_proofs) = holder_proofs {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                match holder_proofs.reap_stale_keys().await {
                    Ok(deleted) if deleted > 0 => {
                        info!(deleted, "reaped stale VC-API holder proof keys");
                    }
                    Err(error) => {
                        error!(%error, "VC-API holder proof key reconciliation failed");
                    }
                    Ok(_) => {}
                }
            }
        });
    }
    let listener = TcpListener::bind(config.http_addr).await?;
    let integration_secret_tls = config.integration_secret_tls.clone();
    info!(
        address = %config.http_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "starting Rust signing-keys service"
    );
    let app = http::router_with_all_keys(
        config.internal_api_key,
        Some(config.service_sign_gateway_key),
        Some(config.issuer_sign_key),
        config.dsc_issue_gateway_key,
        config.csca_issue_gateway_key,
        config.beta_csca_issuance_enabled,
        Some(registry_store),
        Some(document_store),
        Some(csca_lifecycle_store),
        Some(profile_store),
        flow_envelopes,
        config.public_domain,
    );
    let app = match holder_api {
        Some((device_key, provider)) => {
            app.merge(managed_holder_http::router(device_key, provider))
        }
        None => app,
    };
    // The existing HTTP listener serves non-secret signing routes. Plaintext
    // integration-secret requests are accepted only by the separate TLS port.
    let http_app = app
        .clone()
        .layer(axum::middleware::from_fn(reject_integration_secret_http));
    if let Some(tls) = integration_secret_tls {
        let tls_config = RustlsConfig::from_pem_file(&tls.cert_file, &tls.key_file).await?;
        let handle = Handle::new();
        let shutdown_handle = handle.clone();
        let http_server = axum::serve(listener, http_app).with_graceful_shutdown(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
        info!(address = %tls.addr, "starting integration-secret TLS listener");
        let tls_server = axum_server::bind_rustls(tls.addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service());
        tokio::try_join!(http_server, tls_server)?;
    } else {
        axum::serve(listener, http_app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

async fn reject_integration_secret_http(request: Request, next: Next) -> Response {
    if request
        .uri()
        .path()
        .starts_with("/internal/integration-secrets/")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
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
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn plaintext_listener_refuses_both_integration_secret_operations() {
        let app = Router::new()
            .route(
                "/internal/integration-secrets/encrypt",
                post(|| async { StatusCode::OK }),
            )
            .route(
                "/internal/integration-secrets/decrypt",
                post(|| async { StatusCode::OK }),
            )
            .route("/other", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(reject_integration_secret_http));

        for (path, expected) in [
            (
                "/internal/integration-secrets/encrypt",
                StatusCode::NOT_FOUND,
            ),
            (
                "/internal/integration-secrets/decrypt",
                StatusCode::NOT_FOUND,
            ),
            ("/other", StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
    }
}
