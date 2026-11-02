use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use marty_signing_grant::replay::RedisGrantReplayStore;
use marty_signing_keys::{
    config::Config, csca_lifecycle::CscaLifecycleStore, documents::DocumentStore,
    flow_envelope::OpenBaoEnvelopeProvider, http,
    integration_secret_envelope::IntegrationSecretProvider, managed_holder_http,
    managed_holder_key::OpenBaoManagedHolderKeys, profiles::ProfileStore, registry::RegistryStore,
    vc_api_holder_proof::OpenBaoHolderProofProvider,
};
use mmf_platform::keyless_https_server_config;
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
    let holder_api = if let Some(key) = config.holder_device_key.as_ref() {
        let provider = config
            .bao_addr
            .as_ref()
            .map(|endpoint| OpenBaoManagedHolderKeys::new(endpoint.clone()))
            .transpose()?;
        Some((key.clone(), provider))
    } else {
        None
    };
    let registry_store = RegistryStore::connect(&config.registry_redis_url)
        .await?
        .with_managed_openbao(managed_openbao_endpoint.clone());
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
    let integration_secret_envelopes =
        IntegrationSecretProvider::from_environment(flow_envelopes.clone()).await?;
    let registry_store =
        registry_store.with_auth_envelope_provider(integration_secret_envelopes.clone());
    let grant_verifier = marty_signing_grant::configuration::GrantAuthority::from_environment()?
        .verifier(
            managed_openbao_endpoint.as_deref(),
            config.sign_grant_verify_token_file.clone(),
            RedisGrantReplayStore::new(registry_store.connection()),
        )?;
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
    let app = http::router_with_runtime_kms(
        config.internal_api_key,
        Some(config.service_sign_gateway_key),
        Some(config.issuer_sign_key),
        config.integration_secret_key,
        config.dsc_issue_gateway_key,
        config.csca_issue_gateway_key,
        config.beta_csca_issuance_enabled,
        Some(registry_store),
        Some(document_store),
        Some(csca_lifecycle_store),
        Some(profile_store),
        http::RuntimeKmsProviders {
            flow_envelopes,
            integration_secret_envelopes,
        },
        config.public_domain,
        Some(grant_verifier),
        config.mdoc_certificates,
    );
    let app = match holder_api {
        Some((device_key, provider)) => app.merge(
            managed_holder_http::router_with_optional_provider(device_key, provider),
        ),
        None => app,
    };
    // The existing HTTP listener serves non-secret signing routes. Plaintext
    // integration-secret requests are accepted only by the separate TLS port.
    let http_app = app
        .clone()
        .layer(axum::middleware::from_fn(reject_integration_secret_http));
    if let Some(tls) = integration_secret_tls {
        let identity = tls.identity.connect().await?;
        let tls_config = RustlsConfig::from_config(keyless_https_server_config(&identity)?);
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
        || request
            .uri()
            .path()
            .starts_with("/internal/compat/issuer-dids/didcomm/")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

async fn shutdown_signal() {
    mmf_runtime::shutdown_signal().await;
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
            .route(
                marty_signing_grant::didcomm::PACK_ROUTE,
                post(|| async { StatusCode::OK }),
            )
            .route(
                marty_signing_grant::didcomm::RESOLVE_ROUTE,
                post(|| async { StatusCode::OK }),
            )
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
            (
                marty_signing_grant::didcomm::PACK_ROUTE,
                StatusCode::NOT_FOUND,
            ),
            (
                marty_signing_grant::didcomm::RESOLVE_ROUTE,
                StatusCode::NOT_FOUND,
            ),
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
