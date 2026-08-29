use axum::{
    extract::{Path, State},
    middleware,
    routing::get,
    Json, Router,
};
use marty_oid4vci::discovery::{
    AuthorizationServerMetadata, CredentialIssuerMetadata, CredentialTypeMetadata, IssuerVariant,
    StaticDiscoveryDocuments,
};
use mmf_core::HealthReport;
use mmf_runtime::{system_router_with_options, RuntimeState, SystemRouteOptions};
use serde_json::{json, Value};

use crate::transport::{legacy_transport, TransportPolicy};

fn legacy_health(_report: &HealthReport) -> Value {
    json!({"status": "healthy", "service": "issuance-service"})
}

pub fn router(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
) -> Router {
    let system = system_router_with_options(
        runtime,
        SystemRouteOptions::default().with_health_projector(legacy_health),
    );
    let discovery = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(root_issuer_metadata),
        )
        .route(
            "/credentials/{*credential_type}",
            get(credential_type_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(root_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}",
            get(organization_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}/credential-manager",
            get(credential_manager_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}/apple-wallet",
            get(apple_wallet_authorization_server_metadata),
        )
        .with_state(discovery);
    system
        .merge(discovery)
        .layer(middleware::from_fn_with_state(transport, legacy_transport))
}

async fn root_issuer_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
) -> Json<CredentialIssuerMetadata> {
    Json(documents.root_issuer_metadata())
}

async fn credential_type_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
    Path(credential_type): Path<String>,
) -> Json<CredentialTypeMetadata> {
    Json(documents.credential_type_metadata(&credential_type))
}

async fn root_authorization_server_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
) -> Json<AuthorizationServerMetadata> {
    Json(documents.root_authorization_server_metadata())
}

async fn organization_authorization_server_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(
        documents
            .organization_authorization_server_metadata(&organization_id, IssuerVariant::Default),
    )
}

async fn credential_manager_authorization_server_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(documents.organization_authorization_server_metadata(
        &organization_id,
        IssuerVariant::CredentialManager,
    ))
}

async fn apple_wallet_authorization_server_metadata(
    State(documents): State<StaticDiscoveryDocuments>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(
        documents.organization_authorization_server_metadata(
            &organization_id,
            IssuerVariant::AppleWallet,
        ),
    )
}
