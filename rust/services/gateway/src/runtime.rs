//! Executable Marty tenant-authorization boundary for the Axum gateway.
//!
//! Generic policy engines and HTTP decisions stay in MMF. This module only
//! adapts Marty request context to the frozen route classifier and membership
//! provider contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::Utc;
use futures_core::Stream;
use marty_passport_auth::PassportTenantCredentialSource;
#[cfg(test)]
use marty_passport_auth::PassportTenantKeyring;
#[cfg(test)]
use marty_signing_grant::SigningOrigin;
use marty_signing_grant::{
    ceremony::{IssuerCsrIntent, ServiceCsrIntent},
    minter::{GrantMinter, GrantMinting},
};
#[path = "runtime_organization_defaults.rs"]
mod organization_defaults;
#[path = "runtime_signing_ceremony.rs"]
mod signing_ceremony;
#[path = "runtime_signing_compatibility.rs"]
mod signing_compatibility;
use signing_compatibility::*;
#[path = "runtime_console_cors.rs"]
mod console_cors;
#[path = "runtime_profile_operations.rs"]
mod profile_operations;
use mmf_platform::{
    ContentTypeDecision, EntityTagDecision, EntityTagPolicy, GatewayProxy, GatewayRequest,
    GatewayResponse, HttpMethod, IdempotencyBegin, IdempotencyRequest, IdempotencyResponse,
    IdempotencyStore, ProtocolVersionDecision, ProxyOverrides, RouteTable, TrustedIdentityContext,
};
use mmf_security::SecurityError;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use profile_operations::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use signing_ceremony::{
    mint_public_issuer_csr_grant, mint_public_service_csr_grant, mint_public_service_sign_grant,
};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use crate::{
    authorization::{
        authorize_api_key, authorize_membership, extract_org_id, resolve_action,
        resolve_resource_lookup, skips_tenant_authorization, OrganizationMembership,
        OrganizationMembershipProvider, RequiredPermission, TenantAuthorizationFailure,
    },
    contract::{
        mdoc_crl_operator_path, requires_issuance_service_auth, route_ownership, GatewayContract,
    },
    credential_metadata, credential_template_contract, deployment_contract, did_web,
    didcomm_contract,
    discovery::{self, ReleaseIdentity},
    flow_contract,
    issuance_create::IssuanceCreate,
    issuance_lifecycle_contract, issuance_native,
    middleware::{
        authenticate, permits_pairing_ticket, AuthenticationInput, AuthenticationOutcome,
        AuthenticationSource, GatewayHttpPolicies, GatewayIdentity, GatewayIdentityProvider,
        GatewayRateLimiter, MipError, MIP_VERSION,
    },
    organization_composition, organization_contract,
    passport_gateway::{passport_upstream_auth, PassportUpstreamAuth},
    presentation_policy_contract, response_projection,
    signing_compat::{self, SigningCompatibilityOperation},
    trust_contract,
    vc_api::{
        adapt_evaluation, adapt_verifiable, credential_issuer_id, evaluation_request,
        issued_data_integrity_credential, parse_inline_credential_offer, VerifiableField,
    },
    verification_flow_contract,
};

const DEFAULT_MAXIMUM_BODY_BYTES: usize = 10 * 1024 * 1024;
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

pub struct GatewayRuntimeState {
    pub routes: Arc<RouteTable>,
    pub proxy: Arc<GatewayProxy>,
    pub identities: Arc<dyn GatewayIdentityProvider>,
    pub memberships: Arc<dyn OrganizationMembershipProvider>,
    pub owners: Arc<dyn ResourceOwnerProvider>,
    pub readiness: Arc<dyn ReadinessProvider>,
    pub event_streams: Arc<dyn EventStreamProvider>,
    pub required_ready_services: Vec<String>,
    pub rate_limiter: Arc<GatewayRateLimiter>,
    pub observe_client_ip: bool,
    pub idempotency: Arc<dyn IdempotencyStore>,
    pub policies: GatewayHttpPolicies,
    pub cors_origins: BTreeSet<String>,
    pub issuer_base_url: String,
    pub public_api_url: String,
    pub did_web_authority: String,
    pub default_organization_id: Option<String>,
    pub signing_service_api_key: String,
    pub service_sign_gateway_key: Option<String>,
    pub service_sign_grant_minter: Option<Arc<dyn GrantMinting>>,
    pub issuer_csr_grant_minter: Option<Arc<dyn GrantMinting>>,
    pub issuer_sign_key: Option<String>,
    pub dsc_issue_gateway_key: Option<String>,
    pub csca_issue_gateway_key: Option<String>,
    pub mdoc_iaca_issue_gateway_key: Option<String>,
    pub mdoc_dsc_issue_gateway_key: Option<String>,
    pub issuance_service_api_key: String,
    pub passport_native_gateway_enabled: bool,
    pub agent_admin_enabled: bool,
    pub delegation_approval_enabled: bool,
    pub delegation_commands_enabled: bool,
    pub agent_enrollment_enabled: bool,
    pub passport_tenant_keys: Option<PassportTenantCredentialSource>,
    pub service_token: Option<String>,
    pub device_registration_gateway_key: Option<String>,
    pub release_identity: ReleaseIdentity,
    pub maximum_body_bytes: usize,
}

impl GatewayRuntimeState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        routes: RouteTable,
        proxy: GatewayProxy,
        identities: Arc<dyn GatewayIdentityProvider>,
        memberships: Arc<dyn OrganizationMembershipProvider>,
        owners: Arc<dyn ResourceOwnerProvider>,
        readiness: Arc<dyn ReadinessProvider>,
        event_streams: Arc<dyn EventStreamProvider>,
        required_ready_services: Vec<String>,
        rate_limiter: GatewayRateLimiter,
        idempotency: Arc<dyn IdempotencyStore>,
        cors_origins: impl IntoIterator<Item = String>,
        issuer_base_url: impl Into<String>,
        public_api_url: impl Into<String>,
        public_domain: impl Into<String>,
        default_organization_id: Option<String>,
        signing_service_api_key: impl Into<String>,
        issuance_service_api_key: impl Into<String>,
        release_identity: ReleaseIdentity,
    ) -> Result<Self, mmf_platform::PlatformError> {
        let cors_origins = cors_origins
            .into_iter()
            .map(|origin| origin.trim().to_owned())
            .filter(|origin| !origin.is_empty())
            .collect::<BTreeSet<_>>();
        if cors_origins.is_empty() || cors_origins.contains("*") {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "credentialed gateway CORS requires explicit origins".into(),
            ));
        }
        let issuer_base_url = issuer_base_url.into().trim_end_matches('/').to_owned();
        let issuer_url = url::Url::parse(&issuer_base_url).map_err(|error| {
            mmf_platform::PlatformError::InvalidConfiguration(error.to_string())
        })?;
        if !matches!(issuer_url.scheme(), "http" | "https")
            || issuer_url.host_str().is_none()
            || !issuer_url.username().is_empty()
            || issuer_url.password().is_some()
            || issuer_url.query().is_some()
            || issuer_url.fragment().is_some()
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "issuer base URL must be an HTTP(S) origin without credentials, query, or fragment"
                    .into(),
            ));
        }
        let public_domain = public_domain.into();
        let public_api_url = public_api_url.into().trim_end_matches('/').to_owned();
        let public_api = url::Url::parse(&public_api_url).map_err(|error| {
            mmf_platform::PlatformError::InvalidConfiguration(error.to_string())
        })?;
        if !matches!(public_api.scheme(), "http" | "https")
            || public_api.host_str().is_none()
            || !public_api.username().is_empty()
            || public_api.password().is_some()
            || public_api.query().is_some()
            || public_api.fragment().is_some()
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "public API URL must be credential-free HTTP(S) without query or fragment".into(),
            ));
        }
        let did_web_authority = did_web::public_authority(&public_domain).ok_or_else(|| {
            mmf_platform::PlatformError::InvalidConfiguration(
                "public domain must be a valid did:web authority".into(),
            )
        })?;
        let signing_service_api_key = signing_service_api_key.into();
        if signing_service_api_key.trim().is_empty() {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "signing service API key is required".into(),
            ));
        }
        let issuance_service_api_key = issuance_service_api_key.into();
        if issuance_service_api_key.trim().is_empty() {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "issuance service API key is required".into(),
            ));
        }
        Ok(Self {
            routes: Arc::new(routes),
            proxy: Arc::new(proxy),
            identities,
            memberships,
            owners,
            readiness,
            event_streams,
            required_ready_services,
            rate_limiter: Arc::new(rate_limiter),
            observe_client_ip: true,
            idempotency,
            policies: GatewayHttpPolicies::new()?,
            cors_origins,
            issuer_base_url,
            public_api_url,
            did_web_authority,
            default_organization_id: default_organization_id
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            signing_service_api_key,
            service_sign_gateway_key: None,
            service_sign_grant_minter: None,
            issuer_csr_grant_minter: None,
            issuer_sign_key: None,
            dsc_issue_gateway_key: None,
            csca_issue_gateway_key: None,
            mdoc_iaca_issue_gateway_key: None,
            mdoc_dsc_issue_gateway_key: None,
            issuance_service_api_key,
            passport_native_gateway_enabled: false,
            agent_admin_enabled: false,
            delegation_approval_enabled: false,
            delegation_commands_enabled: false,
            agent_enrollment_enabled: false,
            passport_tenant_keys: None,
            service_token: None,
            device_registration_gateway_key: None,
            release_identity,
            maximum_body_bytes: DEFAULT_MAXIMUM_BODY_BYTES,
        })
    }

    /// Use unknown client addresses when a hosting path does not preserve an
    /// authenticated source address. Session and unknown-client rate limits
    /// remain active; an internal proxy's socket address is not a client claim.
    pub fn with_client_ip_observation(mut self, enabled: bool) -> Self {
        self.observe_client_ip = enabled;
        self
    }

    pub fn with_agent_administration(
        mut self,
        directory: bool,
        approval: bool,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if (directory || approval)
            && self
                .service_token
                .as_ref()
                .is_none_or(|token| token.len() < 32)
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "candidate agent administration requires a service token".into(),
            ));
        }
        self.agent_admin_enabled = directory;
        self.delegation_approval_enabled = approval;
        Ok(self)
    }

    pub fn with_delegation_commands(
        mut self,
        enabled: bool,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if enabled
            && self
                .service_token
                .as_ref()
                .is_none_or(|token| token.len() < 32)
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "candidate delegation commands require a service token".into(),
            ));
        }
        self.delegation_commands_enabled = enabled;
        Ok(self)
    }

    pub fn with_agent_enrollment(
        mut self,
        enabled: bool,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if enabled
            && (!self.agent_admin_enabled
                || self
                    .service_token
                    .as_ref()
                    .is_none_or(|token| token.len() < 32))
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "candidate enrollment requires agent administration and a service token".into(),
            ));
        }
        self.agent_enrollment_enabled = enabled;
        Ok(self)
    }

    pub fn with_service_token(
        mut self,
        service_token: Option<String>,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if service_token.as_ref().is_some_and(|token| token.len() < 32) {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "gateway service token must contain at least 32 bytes".into(),
            ));
        }
        self.service_token = service_token;
        Ok(self)
    }

    pub fn with_device_registration_gateway_key(
        mut self,
        key: String,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if key.len() < 32 {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "device registration gateway key must contain at least 32 bytes".into(),
            ));
        }
        self.device_registration_gateway_key = Some(key);
        Ok(self)
    }

    pub fn with_dsc_issue_gateway_key(
        mut self,
        key: Option<String>,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if let Some(key) = &key {
            if key.len() < 32
                || key == &self.signing_service_api_key
                || self.service_sign_gateway_key.as_ref() == Some(key)
            {
                return Err(mmf_platform::PlatformError::InvalidConfiguration(
                    "DSC issuance credential must be distinct and at least 32 bytes".into(),
                ));
            }
        }
        self.dsc_issue_gateway_key = key;
        Ok(self)
    }

    pub fn with_service_sign_gateway_key(
        mut self,
        key: String,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if key.len() < 32
            || key == self.signing_service_api_key
            || key == self.issuance_service_api_key
            || self.service_token.as_ref() == Some(&key)
            || self.device_registration_gateway_key.as_ref() == Some(&key)
            || self.dsc_issue_gateway_key.as_ref() == Some(&key)
            || self.csca_issue_gateway_key.as_ref() == Some(&key)
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "service signing Gateway credential must be distinct and at least 32 bytes".into(),
            ));
        }
        self.service_sign_gateway_key = Some(key);
        Ok(self)
    }

    pub fn with_service_sign_grant_minter(mut self, minter: GrantMinter) -> Self {
        self.service_sign_grant_minter = Some(Arc::new(minter));
        self
    }

    pub fn with_issuer_csr_grant_minter(mut self, minter: GrantMinter) -> Self {
        self.issuer_csr_grant_minter = Some(Arc::new(minter));
        self
    }

    pub fn with_issuer_sign_key(
        mut self,
        key: String,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if key.len() < 32
            || key == self.signing_service_api_key
            || key == self.issuance_service_api_key
            || self.service_sign_gateway_key.as_ref() == Some(&key)
            || self.service_token.as_ref() == Some(&key)
            || self.device_registration_gateway_key.as_ref() == Some(&key)
            || self.dsc_issue_gateway_key.as_ref() == Some(&key)
            || self.csca_issue_gateway_key.as_ref() == Some(&key)
        {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "issuer signing credential must be distinct and at least 32 bytes".into(),
            ));
        }
        self.issuer_sign_key = Some(key);
        Ok(self)
    }

    pub fn with_csca_issue_gateway_key(
        mut self,
        key: Option<String>,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if let Some(key) = &key {
            if key.len() < 32
                || key == &self.signing_service_api_key
                || self.service_sign_gateway_key.as_ref() == Some(key)
                || self.dsc_issue_gateway_key.as_ref() == Some(key)
            {
                return Err(mmf_platform::PlatformError::InvalidConfiguration(
                    "CSCA issuance credential must be distinct and at least 32 bytes".into(),
                ));
            }
        }
        self.csca_issue_gateway_key = key;
        Ok(self)
    }

    pub fn with_mdoc_certificate_keys(
        mut self,
        iaca: Option<String>,
        dsc: Option<String>,
    ) -> Result<Self, mmf_platform::PlatformError> {
        for (key, other) in [(iaca.as_ref(), dsc.as_ref()), (dsc.as_ref(), iaca.as_ref())] {
            if let Some(key) = key {
                if key.len() < 32
                    || [
                        Some(&self.signing_service_api_key),
                        Some(&self.issuance_service_api_key),
                        self.service_sign_gateway_key.as_ref(),
                        self.issuer_sign_key.as_ref(),
                        self.service_token.as_ref(),
                        self.device_registration_gateway_key.as_ref(),
                        self.dsc_issue_gateway_key.as_ref(),
                        self.csca_issue_gateway_key.as_ref(),
                        other,
                    ]
                    .contains(&Some(key))
                {
                    return Err(mmf_platform::PlatformError::InvalidConfiguration(
                        "MDOC operator credentials must be distinct and at least 32 bytes".into(),
                    ));
                }
            }
        }
        self.mdoc_iaca_issue_gateway_key = iaca;
        self.mdoc_dsc_issue_gateway_key = dsc;
        Ok(self)
    }

    pub fn with_passport_native_gateway(
        mut self,
        enabled: bool,
        tenant_keys: Option<PassportTenantCredentialSource>,
    ) -> Result<Self, mmf_platform::PlatformError> {
        if enabled && tenant_keys.is_none() {
            return Err(mmf_platform::PlatformError::InvalidConfiguration(
                "native passport gateway requires tenant keys".into(),
            ));
        }
        self.passport_native_gateway_enabled = enabled;
        self.passport_tenant_keys = tenant_keys;
        Ok(self)
    }
}

/// Build the frozen eight-stage gateway middleware chain.
pub fn gateway_router(state: Arc<GatewayRuntimeState>) -> Router {
    Router::new()
        .fallback(any(proxy_handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            cors_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            idempotency_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            tenant_authorization_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            entity_tag_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            content_type_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observation_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authentication_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            mip_version_middleware,
        ))
        // Preserve the decision-stage order while making early Auth/learner
        // errors readable by the one configured browser Origin.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            console_cors::error_headers,
        ))
        .layer(middleware::from_fn(crate::public_verification::no_store))
        .with_state(state)
}

async fn mip_version_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let advertised = request
        .headers()
        .get("x-mip-version")
        .and_then(|value| value.to_str().ok());
    if let ProtocolVersionDecision::Unsupported {
        advertised,
        supported,
    } = state.policies.negotiate_version(advertised)
    {
        let mut error = MipError::new(
            "UNSUPPORTED_VERSION",
            format!("MIP version {advertised:?} is not supported. Supported: {supported:?}"),
        );
        error.extra.insert(
            "supported_versions".into(),
            serde_json::to_value(supported).expect("versions serialize"),
        );
        return error_response(400, error);
    }
    let mut response = next.run(request).await;
    insert_header(&mut response, "x-mip-version", MIP_VERSION);
    response
}

struct ClientIpObservation<'a> {
    forwarded_for: Option<&'a str>,
    peer_ip: Option<String>,
}

const CLIENT_ADDRESS_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "x-envoy-external-address",
];

fn client_ip_observation<'a>(
    enabled: bool,
    headers: &'a axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
) -> ClientIpObservation<'a> {
    if !enabled {
        return ClientIpObservation {
            forwarded_for: None,
            peer_ip: None,
        };
    }
    ClientIpObservation {
        forwarded_for: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        peer_ip: extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|value| value.0.ip().to_string()),
    }
}

async fn rate_limit_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if !state.observe_client_ip {
        // Enforce unknown attribution before authentication, owner lookups,
        // and every upstream path. Canonical public host/proto/port remain.
        for name in CLIENT_ADDRESS_HEADERS {
            request.headers_mut().remove(*name);
        }
    }
    let cookies = cookies(request.headers());
    let session_id = cookies.get("sessionId").map(String::as_str);
    let client_ip = client_ip_observation(
        state.observe_client_ip,
        request.headers(),
        request.extensions(),
    );
    let result = match state
        .rate_limiter
        .check(
            session_id,
            client_ip.forwarded_for,
            client_ip.peer_ip.as_deref(),
            request.uri().path(),
            now_ms(),
        )
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                503,
                MipError::new("service_unavailable", "Rate limit provider unavailable"),
            );
        }
    };
    let Some(result) = result else {
        return next.run(request).await;
    };
    if !result.allowed {
        let mut error = MipError::new(
            "rate_limit_exceeded",
            "Too many requests. Please retry after the rate limit window resets.",
        );
        error.extra.insert(
            "retry_after_seconds".into(),
            Value::from(result.retry_after_ms.div_ceil(1_000)),
        );
        return error_response(429, error);
    }
    let mut response = next.run(request).await;
    insert_header(
        &mut response,
        "x-ratelimit-limit",
        &result.limit.to_string(),
    );
    insert_header(
        &mut response,
        "x-ratelimit-remaining",
        &result.remaining.to_string(),
    );
    response
}

async fn authentication_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Only gateway-authenticated identity may supply downstream actor attribution.
    // Some upstreams prefer this legacy alias over the trusted X-User-ID header.
    request.headers_mut().remove("x-authenticated-user-id");
    if request.method() == "OPTIONS"
        && crate::delegation_commands::is_namespace(request.uri().path())
    {
        return crate::delegation_commands::preflight(
            &state,
            request.uri().path(),
            request.headers(),
        );
    }
    if request.method() == "OPTIONS"
        && crate::agent_administration::is_namespace(request.uri().path())
    {
        return crate::agent_administration::preflight(
            &state,
            request.uri().path(),
            request.headers(),
        );
    }
    if request.method() == "OPTIONS" && console_cors::is_namespace(request.uri().path()) {
        // Preflight carries no application identity and must never reach an
        // upstream. The subsequent operation still traverses every guard.
        return console_cors::preflight(&state, request.uri().path(), request.headers());
    }
    let Some(method) = http_method(request.method().as_str()) else {
        return error_response(
            405,
            MipError::new("method_not_allowed", "Method not allowed"),
        );
    };
    // The public catalog has explicit GET/POST routes, so a browser preflight
    // otherwise fails lookup before the existing innermost CORS stage. Resolve
    // only its declared target; retain OPTIONS through the middleware chain.
    let lookup_method = if method == HttpMethod::Options
        && request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| state.cors_origins.contains(origin))
    {
        crate::public_verification::preflight_method(request.uri().path(), request.headers())
            .filter(|target| {
                state
                    .routes
                    .find(&GatewayRequest::new(
                        *target,
                        request.uri().path(),
                        now_ms(),
                    ))
                    .is_ok_and(|found| !found.route.auth_required)
            })
            .unwrap_or(method)
    } else {
        method
    };
    let route_request = GatewayRequest::new(lookup_method, request.uri().path(), now_ms());
    let required = match state.routes.find(&route_request) {
        Ok(found) => found.route.auth_required,
        Err(_) => {
            return error_response(404, MipError::new("not_found", "Route not found"));
        }
    };
    let input = AuthenticationInput {
        required,
        headers: request_headers(request.headers()),
        cookies: cookies(request.headers()),
    };
    match authenticate(&input, state.identities.as_ref()).await {
        AuthenticationOutcome::Bypass => {}
        AuthenticationOutcome::Authenticated(identity) => {
            request
                .extensions_mut()
                .insert(base_trusted_identity(&identity));
            request.extensions_mut().insert(identity);
        }
        AuthenticationOutcome::Failed(failure) => {
            return error_response(
                failure.status,
                MipError::new(failure.error, failure.description),
            );
        }
    }
    next.run(request).await
}

async fn observation_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    if crate::external_association::is_namespace(request.uri().path()) {
        let Some(identity) = request.extensions().get::<GatewayIdentity>().cloned() else {
            return detail_response(401, "association_authentication_required");
        };
        let permission = crate::external_association::required_permission(request.uri().path());
        let producer = crate::external_association::is_producer_namespace(request.uri().path());
        let authentication = if identity.source == AuthenticationSource::ApiKey {
            crate::external_association::Identity::Producer {
                key_id: identity.api_key_id.as_deref(),
                organization_id: identity.session_organization_id.as_deref(),
                scopes: &identity.api_key_scopes,
            }
        } else if identity.source == AuthenticationSource::Session && identity.api_key_id.is_none()
        {
            if crate::external_association::requires_own_session(request.uri().path())
                && identity.non_impersonated_session != Some(true)
            {
                return detail_response(403, "learner_own_session_required");
            }
            let mut origins = request.headers().get_all(header::ORIGIN).iter();
            let origin = origins.next().and_then(|v| v.to_str().ok());
            let allowed =
                origins.next().is_none() && origin.is_some_and(|v| state.cors_origins.contains(v));
            crate::external_association::Identity::Session {
                organization_id: identity.session_organization_id.as_deref(),
                user_id: &identity.user_id,
                allowed_origin: allowed,
            }
        } else {
            return detail_response(401, "association_authentication_required");
        };
        return match crate::external_association::admit(request, authentication).await {
            Ok(mut request) => {
                let mut trusted = base_trusted_identity(&identity);
                trusted.required_permission = permission.map(str::to_owned);
                if producer {
                    trusted.user_id = None;
                    trusted.user_email = None;
                    trusted.user_domain = None;
                }
                request.extensions_mut().insert(trusted);
                next.run(request).await
            }
            Err((status, code)) => detail_response(status.as_u16(), code),
        };
    }
    let producer = request.uri().path() == crate::external_observation::PATH;
    let admin = crate::external_observation::is_admin_namespace(request.uri().path());
    let ownership = request.uri().path().split('/').nth(4) == Some("application-ownerships");
    let ownership_admin = ownership
        && matches!(
            request.uri().path().rsplit('/').next(),
            Some("propose" | "revoke")
        );
    if !producer && !admin {
        return next.run(request).await;
    }
    let Some(identity) = request.extensions().get::<GatewayIdentity>().cloned() else {
        return detail_response(401, "observation_authentication_required");
    };
    if ownership
        && request.uri().path().rsplit('/').next() == Some("confirm")
        && identity.non_impersonated_session != Some(true)
    {
        return detail_response(403, "learner_own_session_required");
    }
    let result = if producer {
        crate::external_observation::admit(
            request,
            identity.source == AuthenticationSource::ApiKey,
            identity.api_key_id.as_deref(),
            identity.session_organization_id.as_deref(),
            &identity.api_key_scopes,
        )
        .await
    } else {
        let mut origins = request.headers().get_all(header::ORIGIN).iter();
        let origin = origins.next().and_then(|h| h.to_str().ok());
        let allowed =
            origins.next().is_none() && origin.is_some_and(|v| state.cors_origins.contains(v));
        crate::external_observation::admit_admin(
            request,
            identity.source == AuthenticationSource::Session && identity.api_key_id.is_none(),
            identity.session_organization_id.as_deref(),
            &identity.user_id,
            allowed,
        )
        .await
    };
    match result {
        Ok(mut request) => {
            let mut trusted = base_trusted_identity(&identity);
            trusted.required_permission = if producer {
                Some("evidence:submit".into())
            } else if ownership_admin {
                Some("application:manage-ownership".into())
            } else if ownership {
                // Core verifies the session user's proposed/current relationship.
                // Learner confirmation is never an administrative permission.
                None
            } else {
                Some("external-observation:manage".into())
            };
            request.extensions_mut().insert(trusted);
            next.run(request).await
        }
        Err((status, code)) => detail_response(status.as_u16(), code),
    }
}

async fn content_type_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    match state.policies.content_types.evaluate(
        request.method().as_str(),
        request.uri().path(),
        content_type,
    ) {
        ContentTypeDecision::Accepted => next.run(request).await,
        ContentTypeDecision::Unsupported { media_type } => error_response(
            415,
            MipError::new(
                "unsupported_media_type",
                format!("Content-Type '{media_type}' is not supported. Use application/json."),
            ),
        ),
    }
}

async fn entity_tag_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/v1/notifications/events/push"
        || crate::public_verification::is_public_path(request.uri().path())
        || crate::agent_administration::is_namespace(request.uri().path())
        || crate::delegation_commands::is_namespace(request.uri().path())
    {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_owned();
    let authenticated = request.extensions().get::<GatewayIdentity>().is_some();
    let if_none_match = request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (parts, body) = response.into_parts();
    let body = match to_bytes(body, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                502,
                MipError::new("invalid_response", "Unable to buffer upstream response"),
            );
        }
    };
    let decision = EntityTagPolicy::evaluate(
        &method,
        authenticated,
        status,
        cache_control.as_deref(),
        if_none_match.as_deref(),
        &body,
    );
    let mut response = Response::from_parts(parts, Body::from(body));
    match decision {
        EntityTagDecision::Bypass => response,
        EntityTagDecision::Attach { entity_tag } => {
            insert_header(&mut response, "etag", &entity_tag);
            response
        }
        EntityTagDecision::NotModified { entity_tag } => {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.body_mut() = Body::empty();
            response.headers_mut().remove(header::CONTENT_LENGTH);
            insert_header(&mut response, "etag", &entity_tag);
            response
        }
    }
}

async fn tenant_authorization_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    if crate::delegation_commands::is_namespace(request.uri().path()) {
        return match crate::delegation_commands::admit(&state, request).await {
            Ok(request) => next.run(request).await,
            Err(response) => response,
        };
    }
    if crate::agent_administration::is_namespace(request.uri().path()) {
        return match crate::agent_administration::admit(&state, request).await {
            Ok(request) => next.run(request).await,
            Err(response) => response,
        };
    }
    // Original observation bytes and retries belong to the canonical journal.
    if request.uri().path() == crate::external_observation::PATH
        || crate::external_association::is_namespace(request.uri().path())
        || crate::external_observation::is_admin_namespace(request.uri().path())
    {
        return next.run(request).await;
    }

    let (parts, body) = request.into_parts();
    let maximum_body_bytes = if crate::public_verification::is_public_path(parts.uri.path()) {
        4_096.min(state.maximum_body_bytes)
    } else {
        state.maximum_body_bytes
    };
    let body = match to_bytes(body, maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                413,
                MipError::new("payload_too_large", "Request body too large"),
            );
        }
    };
    // Generic internal service routes authenticate with service credentials and
    // are never part of the public gateway surface. The signing-key prefix is
    // the sole explicit gateway-owned compatibility API; its dedicated handler
    // replaces tenant scope and never enters the generic proxy. Falling through
    // for any other internal path could inject a privileged upstream key after
    // bypassing public route authorization.
    if (parts.uri.path() == "/internal" || parts.uri.path().starts_with("/internal/"))
        && !parts.uri.path().starts_with("/internal/signing-keys/")
    {
        return detail_response(404, "Route not found");
    }
    // Public wallet protocol routes are deliberately tenant-authorization
    // skips.  Bypass owner resolution as well: resolving an instance owner
    // requires an authenticated service call and must never make a public
    // request-object endpoint depend on browser session context.
    if skips_tenant_authorization(parts.uri.path()) {
        return next.run(Request::from_parts(parts, Body::from(body))).await;
    }
    let identity = parts.extensions.get::<GatewayIdentity>().cloned();
    if let Some(method) = http_method(parts.method.as_str()).filter(|method| {
        state.passport_native_gateway_enabled
            && issuance_native::is_passport_public_http(*method, parts.uri.path())
    }) {
        let outcome = authorize_native_passport_tenant(
            method,
            parts.uri.path(),
            identity.as_ref(),
            state.memberships.as_ref(),
        )
        .await;
        let TenantAuthorizationOutcome::Authorized(context) = outcome else {
            return match outcome {
                TenantAuthorizationOutcome::Denied(error) => {
                    detail_response(error.status, &error.detail)
                }
                _ => detail_response(403, "Passport tenant authorization is required"),
            };
        };
        let header_organizations = parts
            .headers
            .get_all("x-organization-id")
            .iter()
            .collect::<Vec<_>>();
        if header_organizations.len() > 1 {
            return detail_response(403, "Passport organization context is invalid");
        }
        let header_organization = header_organizations
            .first()
            .map(|value| value.to_str())
            .transpose();
        let Ok(header_organization) = header_organization else {
            return detail_response(403, "Passport organization context is invalid");
        };
        let query = query_pairs(parts.uri.query());
        let query_organizations = query.get("organization_id");
        if query_organizations.is_some_and(|values| values.len() != 1) {
            return detail_response(403, "Passport organization context is invalid");
        }
        let body_organization = body_organization_id(parts.method.as_str(), &body);
        let Some(keyring) = state.passport_tenant_keys.as_ref() else {
            return detail_response(503, "Passport tenant keys are unavailable");
        };
        let passport_auth = match passport_upstream_auth(
            keyring,
            &context,
            method,
            parts.uri.path(),
            header_organization,
            body_organization.as_deref(),
            query_organizations.and_then(|values| values.first().map(String::as_str)),
        ) {
            Ok(auth) => auth,
            Err(_) => return detail_response(403, "Passport organization is not authorized"),
        };
        let mut request = Request::from_parts(parts, Body::from(body));
        request.extensions_mut().insert(*context);
        request.extensions_mut().insert(passport_auth);
        return next.run(request).await;
    }
    let query_organization_id = query_pairs(parts.uri.query())
        .remove("organization_id")
        .and_then(|values| values.into_iter().next());
    let resolved = match resolve_organization(
        &OrganizationResolutionInput {
            method: parts.method.as_str().into(),
            path: parts.uri.path().into(),
            query_organization_id,
            body_organization_id: body_organization_id(parts.method.as_str(), &body),
            authenticated_organization_id: identity
                .as_ref()
                .and_then(|value| value.session_organization_id.clone()),
            owner_context: resource_owner_context(identity.as_ref(), &parts.headers),
        },
        state.owners.as_ref(),
    )
    .await
    {
        Ok(value) => value,
        Err(SecurityError::Authorization(_)) => {
            return detail_response(403, "Forbidden");
        }
        Err(_) => {
            return detail_response(500, "Authorization service unavailable");
        }
    };
    let outcome = authorize_tenant_request(
        parts.method.as_str(),
        parts.uri.path(),
        resolved
            .as_ref()
            .map(|value| value.organization_id.as_str()),
        identity.as_ref(),
        state.memberships.as_ref(),
    )
    .await;
    let mut request = Request::from_parts(parts, Body::from(body));
    match outcome {
        TenantAuthorizationOutcome::Bypass => next.run(request).await,
        TenantAuthorizationOutcome::Authorized(context) => {
            request.extensions_mut().insert(*context);
            next.run(request).await
        }
        TenantAuthorizationOutcome::Denied(error) => detail_response(error.status, &error.detail),
    }
}

fn resource_owner_context(
    identity: Option<&GatewayIdentity>,
    headers: &axum::http::HeaderMap,
) -> ResourceOwnerContext {
    let mut forwarded = BTreeMap::new();
    if let Some(identity) = identity {
        forwarded.insert("x-user-id".into(), identity.user_id.clone());
        if let Some(value) = &identity.user_email {
            forwarded.insert("x-user-email".into(), value.clone());
        }
        if let Some(value) = &identity.user_domain {
            forwarded.insert("x-user-domain".into(), value.clone());
        }
        if let Some(value) = &identity.session_organization_id {
            forwarded.insert("x-organization-id".into(), value.clone());
        }
        if let Some(value) = &identity.api_key_id {
            forwarded.insert("x-api-key-id".into(), value.clone());
        }
        if !identity.api_key_scopes.is_empty() {
            forwarded.insert("x-api-key-scopes".into(), identity.api_key_scopes.join(","));
        }
    }
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        forwarded.insert("authorization".into(), value.to_owned());
    }
    ResourceOwnerContext { headers: forwarded }
}

fn invalid_passport_cancellation_key(
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    native_passport_enabled: bool,
) -> bool {
    if !native_passport_enabled
        || method != "POST"
        || !issuance_native::is_passport_administrative_cancel(HttpMethod::Post, path)
    {
        return false;
    }
    let mut values = headers.get_all("idempotency-key").iter();
    let first = values.next().and_then(|value| value.to_str().ok());
    values.next().is_some()
        || !first.is_some_and(marty_passport_auth::valid_operation_idempotency_key)
}

fn duplicate_start_idempotency_header(
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    native_passport_enabled: bool,
) -> bool {
    method == "POST"
        && (path == "/v1/flows/instances"
            || (native_passport_enabled && path == "/v1/passport/applications"))
        && headers.get_all("idempotency-key").iter().nth(1).is_some()
}

fn issuance_idempotency_key(
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, &'static str> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("Idempotency-Key must occur once");
    }
    let value = value.to_str().map_err(|_| {
        "Idempotency-Key must contain 1 to 128 ASCII letters, digits, '.', '_', ':', or '-'"
    })?;
    // Admit the exact durable issuance grammar from issuance-initiation.json.
    // Trimming here would alias an invalid request to an existing cached key.
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(
            "Idempotency-Key must contain 1 to 128 ASCII letters, digits, '.', '_', ':', or '-'",
        );
    }
    Ok(Some(value.to_owned()))
}

async fn idempotency_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    if crate::agent_administration::is_namespace(request.uri().path())
        || crate::delegation_commands::is_namespace(request.uri().path())
    {
        return next.run(request).await;
    }
    // Original observation bytes and retries belong to the canonical journal.
    if request.uri().path() == crate::external_observation::PATH
        || crate::external_association::is_namespace(request.uri().path())
        || crate::external_observation::is_admin_namespace(request.uri().path())
    {
        return next.run(request).await;
    }

    // The capability, admitted selection and stored nonce form the public
    // launch identity. A general body/Idempotency-Key cache cannot replace it.
    if crate::public_verification::is_public_path(request.uri().path()) {
        return next.run(request).await;
    }
    // Validate before IdempotencyBegin::Replay, not just before proxying.
    if request.method() == "POST" && request.uri().path() == "/v1/issuance" {
        if let Err(detail) = issuance_idempotency_key(request.headers()) {
            return detail_response(422, detail);
        }
    }
    if invalid_passport_cancellation_key(
        request.method().as_str(),
        request.uri().path(),
        request.headers(),
        state.passport_native_gateway_enabled,
    ) {
        return detail_response(
            422,
            "Administrative cancellation requires one valid Idempotency-Key",
        );
    }
    if duplicate_start_idempotency_header(
        request.method().as_str(),
        request.uri().path(),
        request.headers(),
        state.passport_native_gateway_enabled,
    ) {
        return detail_response(422, "Idempotency-Key must occur once");
    }
    let key = request
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if key.is_none() || !matches!(request.method().as_str(), "POST" | "PUT" | "PATCH") {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                413,
                MipError::new("payload_too_large", "Request body too large"),
            );
        }
    };
    let principal_id = parts
        .extensions
        .get::<TrustedIdentityContext>()
        .and_then(|identity| identity.user_id.clone())
        .unwrap_or_else(|| "anonymous".into());
    let operation = IdempotencyRequest {
        principal_id,
        key: key.expect("checked above"),
        method: parts.method.as_str().into(),
        path: parts.uri.path().into(),
        query: parts.uri.query().unwrap_or_default().into(),
        body: body.to_vec(),
    };
    let started = match state.idempotency.begin(&operation, now_ms()).await {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                503,
                MipError::new("service_unavailable", "Idempotency provider unavailable"),
            );
        }
    };
    match started {
        IdempotencyBegin::Replay(cached) => cached_response(cached),
        IdempotencyBegin::Conflict => error_response(
            409,
            MipError::new(
                "idempotency_conflict",
                "Idempotency key was reused for another request",
            ),
        ),
        IdempotencyBegin::InProgress => error_response(
            409,
            MipError::new(
                "idempotency_in_progress",
                "A request with this idempotency key is in progress",
            ),
        ),
        IdempotencyBegin::Started(lease) => {
            let response = next.run(Request::from_parts(parts, Body::from(body))).await;
            let (response_parts, response_body) = response.into_parts();
            let response_body = match to_bytes(response_body, state.maximum_body_bytes).await {
                Ok(body) => body,
                Err(_) => {
                    let _ = state.idempotency.abort(&lease).await;
                    return error_response(
                        502,
                        MipError::new("invalid_response", "Unable to buffer upstream response"),
                    );
                }
            };
            let mut response =
                Response::from_parts(response_parts, Body::from(response_body.clone()));
            if !response.status().is_success() {
                let _ = state.idempotency.abort(&lease).await;
                return response;
            }
            let cached = response_snapshot(&response, response_body.to_vec());
            if state
                .idempotency
                .complete(&lease, cached, now_ms())
                .await
                .is_err()
            {
                return error_response(
                    503,
                    MipError::new("service_unavailable", "Idempotency provider unavailable"),
                );
            }
            insert_header(&mut response, "idempotency-replayed", "false");
            response
        }
    }
}

async fn cors_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let allowed = origin
        .as_ref()
        .is_some_and(|origin| state.cors_origins.contains(origin));
    let preflight = request.method() == axum::http::Method::OPTIONS
        && request
            .headers()
            .contains_key("access-control-request-method");
    let mut response = if preflight && allowed {
        StatusCode::OK.into_response()
    } else {
        next.run(request).await
    };
    if allowed {
        insert_header(
            &mut response,
            "access-control-allow-origin",
            origin.as_deref().expect("allowed origin"),
        );
        insert_header(&mut response, "access-control-allow-credentials", "true");
        insert_header(&mut response, "access-control-allow-methods", "*");
        insert_header(&mut response, "access-control-allow-headers", "*");
        insert_header(&mut response, "access-control-expose-headers", "*");
        insert_header(&mut response, "vary", "Origin");
    }
    response
}

async fn proxy_handler(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
) -> Response {
    if crate::delegation_commands::is_namespace(request.uri().path()) {
        return crate::delegation_commands::dispatch(state, request).await;
    }
    if crate::agent_administration::is_namespace(request.uri().path()) {
        return crate::agent_administration::dispatch(state, request).await;
    }
    match request.uri().path() {
        "/health" => {
            return (
                StatusCode::OK,
                Json(json!({"status": "healthy", "service": "api-gateway"})),
            )
                .into_response();
        }
        "/openapi.json" => {
            let mut document = GatewayContract::load()
                .expect("validated embedded gateway contract")
                .openapi_document(&state.release_identity.release_version);
            crate::agent_administration::extend_openapi(
                &mut document,
                state.agent_admin_enabled,
                state.delegation_approval_enabled,
            );
            crate::agent_administration::extend_enrollment_openapi(
                &mut document,
                state.agent_enrollment_enabled,
            );
            crate::delegation_commands::extend_openapi(
                &mut document,
                state.delegation_commands_enabled,
            );
            return Json(document).into_response();
        }
        "/v1/protocol-support" => {
            return Json(discovery::protocol_support_catalog()).into_response();
        }
        "/docs" | "/redoc" => return api_documentation_handler(),
        "/ready" | "/health/ready" => return readiness_handler(state).await,
        "/health/services" => return services_health_handler(state).await,
        "/.well-known/openid-configuration" => {
            return Json(discovery::openid_configuration(&state.issuer_base_url)).into_response();
        }
        "/.well-known/marty-release" => {
            return Json(discovery::release_document(&state.release_identity)).into_response();
        }
        "/.well-known/mip-configuration" => {
            return mip_configuration_handler(state).await;
        }
        _ => {}
    }
    if request.uri().path() == "/.well-known/did.json" {
        return did_web_root_handler(state).await;
    }
    if let Some(slug) = request
        .uri()
        .path()
        .strip_prefix("/orgs/")
        .and_then(|value| value.strip_suffix("/did.json"))
    {
        return did_web_slug_handler(state, slug).await;
    }
    if let Some(metadata) =
        credential_metadata::response(request.uri().path(), &state.issuer_base_url)
    {
        let mut response = Response::new(Body::from(metadata.body));
        insert_header(&mut response, "content-type", metadata.content_type);
        insert_header(&mut response, "cache-control", metadata.cache_control);
        return response;
    }
    if let Some(plan) = discovery::well_known_proxy_plan(request.uri().path()) {
        return well_known_proxy_handler(state, plan).await;
    }
    if matches!(
        request.uri().path(),
        "/v1/vc-api/credentials/verify" | "/v1/vc-api/presentations/verify"
    ) {
        return vc_api_verify_handler(state, request).await;
    }
    if request.uri().path() == "/v1/vc-api/credentials/issue" {
        return vc_api_issue_handler(state, request).await;
    }
    if request.uri().path().starts_with("/internal/signing-keys") {
        return internal_signing_compatibility_handler(state, request).await;
    }
    if request.uri().path() == "/v1/notifications/events/push" {
        return sse_events_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/issuance" {
        return issuance_create_handler(state, request).await;
    }
    if request.method() == "POST"
        && request.uri().path() == "/v1/credential-templates/issuer-options"
    {
        return template_issuer_options_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/credential-templates" {
        return credential_template_create_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/devices/pairing-tickets" {
        return pairing_ticket_issue_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/deployment-profiles" {
        return deployment_profile_create_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/flows/verify" {
        return verification_flow_start_handler(state, request).await;
    }
    if (request.method() == "POST" && request.uri().path() == "/v1/presentation-policies")
        || (request.method() == "PATCH"
            && request
                .uri()
                .path()
                .strip_prefix("/v1/presentation-policies/")
                .is_some_and(|tail| !tail.is_empty() && !tail.contains('/')))
    {
        return presentation_policy_write_handler(state, request).await;
    }
    if (request.method() == "POST" && request.uri().path() == "/v1/flows/definitions")
        || (request.method() == "PATCH"
            && request
                .uri()
                .path()
                .strip_prefix("/v1/flows/definitions/")
                .is_some_and(|tail| !tail.is_empty() && !tail.contains('/')))
    {
        return flow_definition_write_handler(state, request).await;
    }
    if organization_defaults::organization_id(request.uri().path()).is_some() {
        return organization_defaults::handler(state, request).await;
    }
    if organization_composition_route(request.uri().path()).is_some() {
        return organization_composition_handler(state, request).await;
    }
    if request.method() == "GET" && applicant_evidence_summary_route(request.uri().path()).is_some()
    {
        return applicant_evidence_summary_handler(state, request).await;
    }
    if route_ownership(request.uri().path()).gateway_owned {
        return error_response(
            501,
            MipError::new(
                "not_implemented",
                "Gateway-owned route has not completed Rust migration",
            ),
        );
    }
    let Some(method) = http_method(request.method().as_str()) else {
        return error_response(
            405,
            MipError::new("method_not_allowed", "Method not allowed"),
        );
    };
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let session_organization_id = request
        .extensions()
        .get::<GatewayIdentity>()
        .and_then(|identity| identity.session_organization_id.clone());
    let api_key_organization_id =
        api_key_organization_id(&identity, session_organization_id.as_deref());
    let peer_ip = client_ip_observation(
        state.observe_client_ip,
        request.headers(),
        request.extensions(),
    )
    .peer_ip;
    let passport_auth = request.extensions().get::<PassportUpstreamAuth>().cloned();
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                413,
                MipError::new("payload_too_large", "Request body too large"),
            );
        }
    };
    let public_path = parts.uri.path().to_owned();
    if crate::public_verification::is_public_path(&public_path)
        && !crate::public_verification::unambiguous_headers(&parts.headers)
    {
        return detail_response(
            400,
            "Origin and verification session capability must occur once",
        );
    }
    if invalid_passport_cancellation_key(
        parts.method.as_str(),
        &public_path,
        &parts.headers,
        state.passport_native_gateway_enabled,
    ) {
        return detail_response(
            422,
            "Administrative cancellation requires one valid Idempotency-Key",
        );
    }
    if duplicate_start_idempotency_header(
        parts.method.as_str(),
        &public_path,
        &parts.headers,
        state.passport_native_gateway_enabled,
    ) {
        return detail_response(422, "Idempotency-Key must occur once");
    }
    let native_passport_public = state.passport_native_gateway_enabled
        && issuance_native::is_passport_public_http(method, &public_path);
    if native_passport_public && passport_auth.is_none() {
        return detail_response(403, "Passport tenant authorization is required");
    }
    let upstream_path =
        match compatibility_upstream_path(&public_path, api_key_organization_id.as_deref()) {
            Ok(path) => path,
            Err((status, detail)) => return detail_response(status, detail),
        };
    // The generic proxy stores headers in a map. Reject ambiguity before it
    // could collapse two preconditions into one at the signing service.
    if ambiguous_config_precondition(&parts.method, &public_path, &parts.headers) {
        return detail_response(400, "Exactly one If-Match revision is allowed");
    }
    if public_path == "/v1/signing-keys/issuer-identities/dsc-certificate"
        && state.dsc_issue_gateway_key.is_none()
    {
        return detail_response(503, "DSC issuance authority is unavailable");
    }
    if public_path == "/v1/signing-keys/issuer-identities/csca-self-signed-certificate"
        && (!state.passport_native_gateway_enabled || state.csca_issue_gateway_key.is_none())
    {
        return detail_response(503, "Beta CSCA issuance authority is unavailable");
    }
    if (public_path == "/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate"
        && state.mdoc_iaca_issue_gateway_key.is_none())
        || (mdoc_crl_operator_path(&public_path) && state.mdoc_iaca_issue_gateway_key.is_none())
        || (public_path == "/v1/signing-keys/issuer-identities/mdoc-dsc-certificate"
            && state.mdoc_dsc_issue_gateway_key.is_none())
    {
        return detail_response(503, "MDOC certificate authority is unavailable");
    }
    let mut gateway_request = GatewayRequest::new(method, &upstream_path, now_ms());
    gateway_request.query = query_pairs(parts.uri.query());
    gateway_request.headers = request_headers(&parts.headers);
    if crate::public_verification::is_public_path(&public_path) {
        crate::public_verification::restrict_headers(&mut gateway_request.headers);
    }
    // Only the authorized Gateway producer may attach this proof. A public
    // caller's header must never be forwarded to Signing Keys.
    gateway_request
        .headers
        .remove(marty_signing_grant::HEADER_NAME);
    if native_passport_public {
        gateway_request.headers.remove("x-api-key");
        gateway_request.headers.remove("x-organization-id");
        gateway_request.headers.remove("x-user-id");
        gateway_request.headers.remove("x-api-key-id");
        gateway_request.headers.remove("x-authenticated-user-id");
    }
    let mut canonical_body = match organization_contract::canonicalize_request(
        parts.method.as_str(),
        &public_path,
        &body,
    ) {
        Ok(value) => value,
        Err(_) => {
            return detail_response(422, "Organization request is outside the public contract")
        }
    };
    if canonical_body.is_none()
        && parts.method == "PATCH"
        && public_path
            .strip_prefix("/v1/credential-templates/")
            .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'))
    {
        canonical_body = match credential_template_contract::canonicalize_update(&body) {
            Ok(body) => Some(body),
            Err(_) => {
                return detail_response(
                    422,
                    "Credential-template request is outside the public contract",
                )
            }
        };
    }
    if canonical_body.is_none() {
        canonical_body = match trust_contract::canonicalize_request(
            parts.method.as_str(),
            &public_path,
            &body,
        ) {
            Ok(body) => body,
            Err(_) => return detail_response(422, "Trust request is outside the public contract"),
        };
    }
    if canonical_body.is_none() {
        canonical_body = match deployment_contract::canonicalize_request(
            parts.method.as_str(),
            &public_path,
            &body,
        ) {
            Ok(body) => body,
            Err(_) => {
                return detail_response(422, "Deployment request is outside the public contract")
            }
        };
    }
    if canonical_body.is_none() {
        canonical_body = match issuance_lifecycle_contract::canonicalize_request(
            parts.method.as_str(),
            &public_path,
            &body,
        ) {
            Ok(body) => body,
            Err(_) => {
                return detail_response(
                    422,
                    "Issued-credential lifecycle request is outside the public contract",
                )
            }
        };
    }
    if canonical_body.is_none() {
        canonical_body = match didcomm_contract::canonicalize_request(
            parts.method.as_str(),
            &public_path,
            &body,
        ) {
            Ok(body) => body,
            Err(_) => {
                return detail_response(
                    422,
                    "DIDComm delivery request is outside the public contract",
                )
            }
        };
        if let Some(canonical) = canonical_body.as_deref() {
            // Membership authorization has already bound the selected tenant;
            // a principal may belong to a different tenant than its session default.
            if didcomm_contract::request_organization(canonical).as_deref()
                != identity.organization_id.as_deref()
            {
                return detail_response(403, "Request is not authorized for this organization");
            }
        }
    }
    if canonical_body.is_none() && parts.method == "POST" && public_path == "/v1/flows/instances" {
        canonical_body = match flow_contract::canonicalize_instance(&body) {
            Ok(body) => Some(serde_json::to_vec(&body).expect("canonical flow instance")),
            Err(_) => {
                return detail_response(422, "Flow instance request is outside the public contract")
            }
        };
    }
    gateway_request.body = (!body.is_empty()).then(|| body.to_vec());
    gateway_request.client_ip = peer_ip;
    // The public correlation ID is gateway-issued evidence. Never allow a
    // caller-supplied identifier to become authoritative merely because it is
    // syntactically a UUID.
    let request_id = gateway_request.request_id.clone();
    gateway_request
        .headers
        .retain(|name, _| !name.eq_ignore_ascii_case("x-request-id"));
    gateway_request
        .headers
        .insert("x-request-id".into(), request_id.clone());
    // Authentication and tenant scope belong to the public contract. Some
    // compatibility paths are rewritten for an upstream service, so deriving
    // overrides from the upstream path can lose the authenticated tenant or
    // misread a compatibility segment (for example `organizations/audit`).
    let mut overrides = proxy_overrides(&state, &public_path, &identity);
    if let Some(passport_auth) = passport_auth.filter(|_| native_passport_public) {
        overrides
            .headers
            .insert("x-api-key".into(), passport_auth.api_key().into());
        overrides.headers.insert(
            "x-organization-id".into(),
            passport_auth.organization_id().into(),
        );
        if let Some(user_id) = &identity.user_id {
            overrides
                .headers
                .insert("x-user-id".into(), user_id.clone());
        }
        if let Some(api_key_id) = &identity.api_key_id {
            overrides
                .headers
                .insert("x-api-key-id".into(), api_key_id.clone());
        }
    }
    overrides.body = canonical_body;
    if is_public_service_sign_path(&public_path)
        || is_public_service_csr_path(&public_path)
        || is_public_issuer_csr_path(&public_path)
    {
        let body = overrides
            .body
            .as_deref()
            .or(gateway_request.body.as_deref());
        let grant_result = if is_public_issuer_csr_path(&public_path) {
            mint_public_issuer_csr_grant(
                &state,
                &identity,
                &public_path,
                &request_id,
                body,
                &overrides,
            )
            .await
        } else if is_public_service_csr_path(&public_path) {
            mint_public_service_csr_grant(
                &state,
                &identity,
                &public_path,
                &request_id,
                body,
                &overrides,
            )
            .await
        } else {
            mint_public_service_sign_grant(
                &state,
                &identity,
                &public_path,
                &request_id,
                body,
                &overrides,
            )
            .await
        };
        let grant = match grant_result {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        overrides
            .headers
            .insert(marty_signing_grant::HEADER_NAME.into(), grant);
    }
    match state
        .proxy
        .execute(gateway_request, &identity, &overrides)
        .await
    {
        Ok(mut response) => {
            response
                .headers
                .insert("x-request-id".into(), request_id.clone());
            if response.status_code < 400 {
                if credential_template_contract::response_route(method_name(method), &public_path) {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| {
                            credential_template_contract::public_response(value).ok()
                        });
                    let Some(projected) = projected else {
                        return detail_response(
                            502,
                            "Credential-template service returned an invalid public response",
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if let Some(many) =
                    organization_contract::response_shape(method_name(method), &public_path)
                {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| {
                            organization_contract::project_response(value, many).ok()
                        });
                    let Some(projected) = projected else {
                        return error_response(
                            502,
                            MipError::new(
                                "invalid_service_response",
                                "Organization service returned an invalid public response",
                            ),
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if let Some((kind, many)) =
                    trust_contract::response_shape(method_name(method), &public_path)
                {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| trust_contract::project_response(value, kind, many).ok());
                    let Some(projected) = projected else {
                        return error_response(
                            502,
                            MipError::new(
                                "invalid_service_response",
                                "Trust service returned an invalid public response",
                            ),
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if presentation_policy_contract::response_route(method_name(method), &public_path) {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| {
                            presentation_policy_contract::project_response(value).ok()
                        });
                    let Some(projected) = projected else {
                        return detail_response(
                            502,
                            "Presentation policy service response violates the public contract",
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if let Some(kind) = flow_contract::response_route(method_name(method), &public_path)
                {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| flow_contract::project_response(value, kind).ok());
                    let Some(projected) = projected else {
                        return detail_response(
                            502,
                            "Flow service returned a response outside the public contract",
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if let Some(kind) =
                    deployment_contract::response_shape(method_name(method), &public_path)
                {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| deployment_contract::project_response(value, kind).ok());
                    let Some(projected) = projected else {
                        return detail_response(
                            502,
                            "Deployment service returned a response outside the public contract",
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
                if method == HttpMethod::Post && public_path == "/v1/issuance/didcomm/deliver" {
                    let projected = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_slice(body).ok())
                        .and_then(|value| didcomm_contract::project_response(value).ok());
                    let Some(projected) = projected else {
                        return detail_response(
                            502,
                            "DIDComm delivery service returned an invalid public response",
                        );
                    };
                    response.body = serde_json::to_vec(&projected).ok();
                    response.headers.remove("content-length");
                    response.headers.remove("content-encoding");
                    response.headers.remove("transfer-encoding");
                    response
                        .headers
                        .insert("content-type".into(), "application/json".into());
                }
            }
            match response_projection::project(method, &public_path, response) {
                Ok(response) => upstream_response(response),
                Err(_) => {
                    detail_response(502, "Issuance service returned an invalid public response.")
                }
            }
        }
        Err(_) => {
            let mut response = error_response(
                502,
                MipError::new("bad_gateway", "Unable to execute upstream request"),
            );
            insert_header(&mut response, "x-request-id", &request_id);
            response
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingTicketIssueRequest {
    organization_id: String,
    trust_profile_id: String,
    verifier_trust_profile_id: Option<String>,
}

async fn pairing_ticket_issue_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let Some(actor) = request.extensions().get::<GatewayIdentity>().cloned() else {
        return detail_response(401, "Authentication is required");
    };
    if !permits_pairing_ticket(&actor, Utc::now().timestamp()) {
        return detail_response(403, "Recent user authentication is required");
    }
    let user_id = actor.user_id.clone();
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let Ok(input) = serde_json::from_slice::<PairingTicketIssueRequest>(&body) else {
        return detail_response(422, "Pairing ticket request is invalid");
    };
    let organization_id = input.organization_id.trim();
    if organization_id.is_empty() {
        return detail_response(422, "organization_id is required");
    }
    let Ok(issuer_profile) = uuid::Uuid::parse_str(&input.trust_profile_id) else {
        return detail_response(422, "trust_profile_id is required");
    };
    let mut payload =
        json!({"organization_id": organization_id, "trust_profile_id": input.trust_profile_id});
    if let Some(verifier) = input.verifier_trust_profile_id {
        let Ok(id) = uuid::Uuid::parse_str(&verifier) else {
            return detail_response(422, "verifier_trust_profile_id is invalid");
        };
        if id.is_nil() || id == issuer_profile || id.to_string() != verifier {
            return detail_response(
                422,
                "A distinct canonical verifier trust profile is required",
            );
        }
        payload["verifier_trust_profile_id"] = Value::String(verifier);
    }
    let membership = match state
        .memberships
        .get_membership(&user_id, organization_id)
        .await
    {
        Ok(Some(value))
            if value.user_id == user_id
                && value.organization_id == organization_id
                && value.is_active() =>
        {
            value
        }
        Ok(_) => return detail_response(403, "Active organization membership is required"),
        Err(_) => return detail_response(503, "Organization authorization is unavailable"),
    };
    let mut trusted = base_trusted_identity(&actor);
    trusted.organization_id = Some(membership.organization_id);
    let response = execute_json_proxy(
        &state,
        &trusted,
        HttpMethod::Post,
        "/v1/devices/pairing-tickets",
        payload,
        BTreeMap::new(),
    )
    .await;
    let mut response = match response {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    };
    insert_header(&mut response, "cache-control", "no-store");
    response
}

fn api_documentation_handler() -> Response {
    const DOCUMENT: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Marty API Gateway documentation</title>
<style>body{font:15px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#172033}input{width:100%;padding:.7rem;box-sizing:border-box}li{margin:.45rem 0}code{background:#eef1f6;padding:.15rem .3rem;border-radius:.2rem}.method{display:inline-block;width:4rem;font-weight:700}</style></head>
<body><h1>Marty API Gateway</h1><p>This self-contained browser renders the canonical <a href="/openapi.json">OpenAPI 3.1 document</a>.</p>
<input id="filter" aria-label="Filter API operations" placeholder="Filter methods or paths"><ol id="operations"></ol>
<script>const list=document.querySelector('#operations'),filter=document.querySelector('#filter');let rows=[];fetch('/openapi.json').then(r=>r.json()).then(spec=>{for(const [path,item] of Object.entries(spec.paths))for(const [method,op] of Object.entries(item))rows.push({method:method.toUpperCase(),path,tag:(op.tags||[]).join(', ')});rows.sort((a,b)=>a.path.localeCompare(b.path)||a.method.localeCompare(b.method));render()});function render(){const q=filter.value.toLowerCase();list.replaceChildren(...rows.filter(r=>(r.method+' '+r.path+' '+r.tag).toLowerCase().includes(q)).map(r=>{const li=document.createElement('li'),method=document.createElement('span'),path=document.createElement('code'),tag=document.createElement('small');method.className='method';method.textContent=r.method;path.textContent=r.path;tag.textContent=r.tag;li.append(method,' ',path,' ',tag);return li}))}filter.addEventListener('input',render)</script></body></html>"#;
    let mut response = Response::new(Body::from(DOCUMENT));
    insert_header(&mut response, "content-type", "text/html; charset=utf-8");
    response
}

#[derive(Clone, Copy)]
enum OrganizationCompositionRoute {
    Lifecycle,
    Purge,
    RuntimeStatus,
    ApplicantStats,
    IntegrationInfo,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HostedPilotPurgeSweepStats {
    pub organizations_scanned: u64,
    pub hosted_pilot_orgs: u64,
    pub purge_requests: u64,
    pub purged_records: u64,
}

fn organization_composition_route(path: &str) -> Option<(&str, OrganizationCompositionRoute)> {
    let tail = path.strip_prefix("/v1/organizations/")?;
    let (org_id, suffix) = tail.split_once('/')?;
    if org_id.is_empty() {
        return None;
    }
    let route = match suffix {
        "lifecycle" => OrganizationCompositionRoute::Lifecycle,
        "lifecycle/purge" => OrganizationCompositionRoute::Purge,
        "runtime/status" => OrganizationCompositionRoute::RuntimeStatus,
        "dashboard/applicant-stats" => OrganizationCompositionRoute::ApplicantStats,
        "integration-info" => OrganizationCompositionRoute::IntegrationInfo,
        _ => return None,
    };
    Some((org_id, route))
}

fn applicant_evidence_summary_route(path: &str) -> Option<(&str, &str)> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        ["v1", "organizations", organization_id, "applicants", application_id, "evidence-summary"]
            if !organization_id.is_empty() && !application_id.is_empty() =>
        {
            Some((organization_id, application_id))
        }
        _ => None,
    }
}

fn applicant_evidence_fact(value: &Value) -> Value {
    let field = |name: &str| value.get(name).cloned().unwrap_or(Value::Null);
    let observed_at = value
        .get("captured_at")
        .filter(|item| !item.is_null())
        .cloned()
        .unwrap_or_else(|| field("created_at"));
    json!({
        "id": field("id"),
        "organization_id": field("organization_id"),
        "application_id": field("application_id"),
        "subject_id": field("submitted_by"),
        "provider": field("source"),
        "fact_type": field("evidence_type"),
        "scope": {
            "evidence_requirement_id": field("evidence_requirement_id")
        },
        "assertion": {
            "filename": field("filename"),
            "media_type": field("media_type"),
            "size_bytes": field("size_bytes"),
            "sha256": field("sha256")
        },
        "verification": {
            "status": field("status"),
            "method": "sha-256"
        },
        "source": {
            "kind": field("source"),
            "content_url": field("content_url")
        },
        "requirement_id": field("evidence_requirement_id"),
        "logical_key": field("id"),
        "source_revision": field("updated_at"),
        "payload_hash": field("sha256"),
        "observed_at": observed_at,
        "effective_at": field("captured_at"),
        "superseded_fact_id": Value::Null,
        "created_at": field("created_at")
    })
}

fn applicant_evidence_identity_matches(
    value: &Value,
    organization_id: &str,
    application_id: &str,
) -> bool {
    value.get("organization_id").and_then(Value::as_str) == Some(organization_id)
        && value.get("application_id").and_then(Value::as_str) == Some(application_id)
}

async fn applicant_evidence_summary_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let Some((organization_id, application_id)) =
        applicant_evidence_summary_route(request.uri().path())
    else {
        return detail_response(404, "Application evidence summary route not found");
    };
    let organization_id = organization_id.to_owned();
    let application_id = application_id.to_owned();
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    if identity.organization_id.as_deref() != Some(organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let headers = request_headers(request.headers());
    let issuance_path = format!("/internal/applications/{application_id}/evidence-summary");
    let issuance_service = issuance_native::upstream_service(HttpMethod::Get, &issuance_path);
    match composition_proxy_json(
        &state,
        &identity,
        issuance_service,
        HttpMethod::Get,
        &issuance_path,
        BTreeMap::new(),
        None,
        headers.clone(),
    )
    .await
    {
        Ok(summary)
            if applicant_evidence_identity_matches(&summary, &organization_id, &application_id) =>
        {
            return (StatusCode::OK, Json(summary)).into_response();
        }
        Ok(_) => {
            return detail_response(
                502,
                "Issuance service returned a cross-tenant evidence summary",
            );
        }
        Err(response) if response.status() != StatusCode::NOT_FOUND => return response,
        Err(_) => {}
    }

    let application_path =
        format!("/v1/organizations/{organization_id}/applicants/{application_id}");
    let application = match composition_proxy_json(
        &state,
        &identity,
        "applicant",
        HttpMethod::Get,
        &application_path,
        BTreeMap::new(),
        None,
        headers.clone(),
    )
    .await
    {
        Ok(application) => application,
        Err(response) => return response,
    };
    if application.get("organization_id").and_then(Value::as_str) != Some(organization_id.as_str())
    {
        return detail_response(502, "Applicant service returned a cross-tenant application");
    }
    let evidence_path = format!("{application_path}/evidence");
    let evidence = match composition_proxy_json(
        &state,
        &identity,
        "applicant",
        HttpMethod::Get,
        &evidence_path,
        BTreeMap::new(),
        None,
        headers,
    )
    .await
    {
        Ok(Value::Array(evidence)) => evidence,
        Ok(_) => return detail_response(502, "Applicant evidence response is malformed"),
        Err(response) => return response,
    };
    if evidence
        .iter()
        .any(|item| !applicant_evidence_identity_matches(item, &organization_id, &application_id))
    {
        return detail_response(502, "Applicant service returned cross-tenant evidence");
    }
    (
        StatusCode::OK,
        Json(json!({
            "application_id": application_id,
            "organization_id": organization_id,
            "status": application.get("status").cloned().unwrap_or(Value::Null),
            "evidence_facts": evidence.iter().map(applicant_evidence_fact).collect::<Vec<_>>(),
            "policy_decision": Value::Null,
            "policy_source": Value::Null,
            "policy_set_id": Value::Null,
            "issuance_transaction_id": Value::Null,
            "available_api_checks": []
        })),
    )
        .into_response()
}

async fn organization_composition_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let Some((org_id, route)) = organization_composition_route(request.uri().path()) else {
        return detail_response(404, "Organization composition route not found");
    };
    let org_id = org_id.to_owned();
    let expected_method = matches!(route, OrganizationCompositionRoute::Purge)
        .then_some("POST")
        .unwrap_or("GET");
    if request.method().as_str() != expected_method {
        return detail_response(405, "Method not allowed");
    }
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    if identity.organization_id.as_deref() != Some(org_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let headers = request_headers(request.headers());
    let result = match route {
        OrganizationCompositionRoute::IntegrationInfo => Ok(
            organization_composition::integration_info(&org_id, &state.public_api_url),
        ),
        OrganizationCompositionRoute::ApplicantStats => {
            let path = format!(
                "/v1/organizations/{}/applicants",
                utf8_percent_encode(&org_id, NON_ALPHANUMERIC)
            );
            composition_proxy_json(
                &state,
                &identity,
                "applicant",
                HttpMethod::Get,
                &path,
                BTreeMap::from([("limit".into(), vec!["500".into()])]),
                None,
                headers,
            )
            .await
            .map(|payload| organization_composition::applicant_stats(&payload))
        }
        OrganizationCompositionRoute::RuntimeStatus => {
            load_runtime_status(&state, &identity, &org_id, headers).await
        }
        OrganizationCompositionRoute::Lifecycle => {
            load_organization_lifecycle(&state, &identity, &org_id, false, headers).await
        }
        OrganizationCompositionRoute::Purge => {
            run_hosted_pilot_purge(&state, &identity, &org_id, None, headers).await
        }
    };
    match result {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn sse_events_handler(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    if request.method() != "GET" {
        return detail_response(405, "Method not allowed");
    }
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let Some(authorized_org) = identity
        .organization_id
        .as_deref()
        .or_else(|| {
            request
                .extensions()
                .get::<GatewayIdentity>()
                .and_then(|identity| identity.session_organization_id.as_deref())
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return detail_response(403, "Organization authorization context is required");
    };
    let query = query_pairs(request.uri().query());
    let requested_orgs = ["organization_id", "tenant_id"]
        .into_iter()
        .flat_map(|key| query.get(key).into_iter().flatten())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if requested_orgs.len() > 1
        || requested_orgs
            .iter()
            .next()
            .is_some_and(|requested| *requested != authorized_org)
    {
        return detail_response(
            403,
            "Organization scope does not match authorized organization",
        );
    }
    if query
        .get("user_id")
        .into_iter()
        .flatten()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .any(|requested| identity.user_id.as_deref() != Some(requested))
    {
        return detail_response(403, "User scope does not match authenticated user");
    }
    let event_types = first_query(&query, "subscriptions")
        .map(|subscriptions| {
            subscriptions
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if event_types
        .iter()
        .any(|event_type| event_type.contains(['\r', '\n']))
    {
        return detail_response(422, "Event subscription contains an invalid event type");
    }

    let subscription = EventStreamSubscription {
        event_types,
        organization_id: authorized_org.clone(),
    };
    let provider = Arc::clone(&state.event_streams);
    let (sender, receiver) = mpsc::channel::<Result<String, Infallible>>(16);
    let (cancel_sender, mut cancel_receiver) = watch::channel(false);
    tokio::spawn(async move {
        if sender
            .send(Ok("data: {\"type\": \"connected\"}\n\n".into()))
            .await
            .is_err()
        {
            return;
        }
        let mut stream = match provider.subscribe(subscription).await {
            Ok(stream) => stream,
            Err(_) => {
                let _ = sender
                    .send(Ok("data: {\"error\": \"stream_error\"}\n\n".into()))
                    .await;
                return;
            }
        };
        loop {
            tokio::select! {
                changed = cancel_receiver.changed() => {
                    if changed.is_err() || *cancel_receiver.borrow() {
                        return;
                    }
                }
                event = stream.next() => {
                    let Some(event) = event else { return; };
                    let event = match event {
                        Ok(event) => event,
                        Err(_) => {
                            let _ = sender.send(Ok("data: {\"error\": \"stream_error\"}\n\n".into())).await;
                            return;
                        }
                    };
                    if event.organization_id != authorized_org {
                        continue;
                    }
                    let Some(frame) = sse_event_frame(&event) else {
                        continue;
                    };
                    if sender.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    let body = Body::from_stream(DisconnectStream::new(receiver, cancel_sender));
    let mut response = Response::new(body);
    insert_header(
        &mut response,
        "content-type",
        "text/event-stream; charset=utf-8",
    );
    insert_header(&mut response, "cache-control", "no-cache");
    insert_header(&mut response, "x-accel-buffering", "no");
    insert_header(&mut response, "connection", "keep-alive");
    response
}

fn sse_event_frame(event: &GatewayDomainEvent) -> Option<String> {
    if event.event_type.is_empty() || event.event_type.contains(['\r', '\n']) {
        return None;
    }
    let quoted = |value: &str| serde_json::to_string(value).ok();
    let data = event
        .data
        .iter()
        .map(|(key, value)| Some(format!("{}: {}", quoted(key)?, quoted(value)?)))
        .collect::<Option<Vec<_>>>()?
        .join(", ");
    let data = format!("{{{data}}}");
    Some(format!(
        "event: {}\ndata: {{\"event_id\": {}, \"aggregate_id\": {}, \"aggregate_type\": {}, \"organization_id\": {}, \"data\": {}, \"timestamp\": {}}}\n\n",
        event.event_type,
        quoted(&event.event_id)?,
        quoted(&event.aggregate_id)?,
        quoted(&event.aggregate_type)?,
        quoted(&event.organization_id)?,
        data,
        quoted(&event.timestamp)?,
    ))
}

struct DisconnectStream {
    inner: ReceiverStream<Result<String, Infallible>>,
    cancellation: watch::Sender<bool>,
    heartbeat: Pin<Box<tokio::time::Sleep>>,
}

impl DisconnectStream {
    fn new(
        receiver: mpsc::Receiver<Result<String, Infallible>>,
        cancellation: watch::Sender<bool>,
    ) -> Self {
        Self {
            inner: ReceiverStream::new(receiver),
            cancellation,
            heartbeat: Box::pin(tokio::time::sleep(SSE_HEARTBEAT_INTERVAL)),
        }
    }
}

impl Stream for DisconnectStream {
    type Item = Result<String, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Real frames and EOF take precedence. The response owns this timer,
        // so an unread body cannot accumulate comments in the producer queue.
        let result = match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(frame)) => Poll::Ready(Some(frame)),
            Poll::Pending => {
                if self.heartbeat.as_mut().poll(context).is_pending() {
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(": keep-alive\n\n".into())))
            }
        };
        self.heartbeat
            .as_mut()
            .reset(tokio::time::Instant::now() + SSE_HEARTBEAT_INTERVAL);
        result
    }
}

impl Drop for DisconnectStream {
    fn drop(&mut self) {
        let _ = self.cancellation.send(true);
    }
}

async fn load_runtime_status(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    org_id: &str,
    headers: BTreeMap<String, String>,
) -> Result<Value, Response> {
    let query = BTreeMap::from([("organization_id".into(), vec![org_id.into()])]);
    let mut payloads = Vec::new();
    for (service, path) in [
        ("credential-templates", "/v1/credential-templates"),
        ("presentation-policies", "/v1/presentation-policies"),
        ("deployment-profiles", "/v1/deployment-profiles"),
        ("flows", "/v1/flows/definitions"),
    ] {
        payloads.push(
            composition_proxy_json(
                state,
                identity,
                service,
                HttpMethod::Get,
                path,
                query.clone(),
                None,
                headers.clone(),
            )
            .await?,
        );
    }
    Ok(organization_composition::runtime_status(
        &payloads[0],
        &payloads[1],
        &payloads[2],
        &payloads[3],
    ))
}

async fn load_organization_lifecycle(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    org_id: &str,
    internal: bool,
    headers: BTreeMap<String, String>,
) -> Result<Value, Response> {
    let escaped = utf8_percent_encode(org_id, NON_ALPHANUMERIC);
    let path = if internal {
        format!("/internal/v1/organizations/{escaped}/lifecycle")
    } else {
        format!("/v1/organizations/{escaped}/lifecycle")
    };
    let query = if internal {
        BTreeMap::new()
    } else {
        BTreeMap::from([("organization_id".into(), vec![org_id.into()])])
    };
    let lifecycle = composition_proxy_json(
        state,
        identity,
        "organizations",
        HttpMethod::Get,
        &path,
        query,
        None,
        headers.clone(),
    )
    .await?;
    let summary = if organization_composition::pilot_retention_enabled(&lifecycle) {
        let retention_days = organization_composition::retention_window_days(&lifecycle);
        Some(
            composition_proxy_json(
                state,
                identity,
                "issuance",
                HttpMethod::Get,
                &format!("/v1/issuance/organizations/{escaped}/retention"),
                BTreeMap::from([("retention_days".into(), vec![retention_days.to_string()])]),
                None,
                headers,
            )
            .await?,
        )
    } else {
        None
    };
    organization_composition::compose_lifecycle(lifecycle, summary.as_ref()).map_err(|_| {
        detail_response(
            502,
            "Organization lifecycle service returned an invalid public response",
        )
    })
}

async fn run_hosted_pilot_purge(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    org_id: &str,
    lifecycle: Option<Value>,
    headers: BTreeMap<String, String>,
) -> Result<Value, Response> {
    let lifecycle = match lifecycle {
        Some(lifecycle) => lifecycle,
        None => {
            load_organization_lifecycle(state, identity, org_id, false, headers.clone()).await?
        }
    };
    if !organization_composition::pilot_retention_enabled(&lifecycle) {
        return Err(error_response(
            400,
            MipError::new(
                "retention_not_enabled",
                "Hosted Pilot retention is not enabled for this organization",
            ),
        ));
    }
    let retention_days = organization_composition::retention_window_days(&lifecycle);
    let escaped = utf8_percent_encode(org_id, NON_ALPHANUMERIC);
    let purge = composition_proxy_json(
        state,
        identity,
        "issuance",
        HttpMethod::Post,
        &format!("/v1/issuance/organizations/{escaped}/retention/purge"),
        BTreeMap::from([("retention_days".into(), vec![retention_days.to_string()])]),
        None,
        headers.clone(),
    )
    .await?;
    if let Some(patch) = organization_composition::purge_metadata_patch(&purge) {
        let _ = composition_proxy_json(
            state,
            identity,
            "organizations",
            HttpMethod::Patch,
            &format!("/internal/v1/organizations/{escaped}/settings"),
            BTreeMap::new(),
            Some(patch),
            headers,
        )
        .await;
    }
    organization_composition::project_purge(purge).map_err(|_| {
        detail_response(
            502,
            "Issuance retention service returned an invalid purge response",
        )
    })
}

pub async fn run_hosted_pilot_auto_purge_sweep(
    state: &GatewayRuntimeState,
    batch_size: usize,
) -> HostedPilotPurgeSweepStats {
    let page_size = batch_size.max(1);
    let mut stats = HostedPilotPurgeSweepStats::default();
    let mut offset = 0_usize;
    loop {
        let identity = TrustedIdentityContext::default();
        let organizations = match composition_proxy_json(
            state,
            &identity,
            "organizations",
            HttpMethod::Get,
            "/v1/organizations",
            BTreeMap::from([
                ("limit".into(), vec![page_size.to_string()]),
                ("offset".into(), vec![offset.to_string()]),
            ]),
            None,
            BTreeMap::new(),
        )
        .await
        {
            Ok(Value::Array(organizations)) => organizations,
            _ => return stats,
        };
        if organizations.is_empty() {
            return stats;
        }
        stats.organizations_scanned += organizations.len() as u64;
        for organization in &organizations {
            let Some(org_id) = organization
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let identity = TrustedIdentityContext {
                organization_id: Some(org_id.into()),
                ..TrustedIdentityContext::default()
            };
            let lifecycle =
                match load_organization_lifecycle(state, &identity, org_id, true, BTreeMap::new())
                    .await
                {
                    Ok(lifecycle) => lifecycle,
                    Err(_) => continue,
                };
            if !organization_composition::pilot_retention_enabled(&lifecycle) {
                continue;
            }
            stats.hosted_pilot_orgs += 1;
            if !organization_composition::purge_due(&lifecycle, Utc::now()) {
                continue;
            }
            let purge = match run_hosted_pilot_purge(
                state,
                &identity,
                org_id,
                Some(lifecycle),
                BTreeMap::new(),
            )
            .await
            {
                Ok(purge) => purge,
                Err(_) => continue,
            };
            stats.purge_requests += 1;
            stats.purged_records += organization_composition::purged_total(&purge);
        }
        if organizations.len() < page_size {
            return stats;
        }
        offset += organizations.len();
    }
}

fn internal_issuance_proxy_path(method: HttpMethod, upstream_path: &str) -> String {
    let service = issuance_native::upstream_service(method, upstream_path);
    format!("/__gateway/{service}{upstream_path}")
}

#[allow(clippy::too_many_arguments)]
async fn composition_proxy_json(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    service: &str,
    method: HttpMethod,
    upstream_path: &str,
    query: BTreeMap<String, Vec<String>>,
    body: Option<Value>,
    mut headers: BTreeMap<String, String>,
) -> Result<Value, Response> {
    let is_issuance = matches!(
        service,
        issuance_native::LEGACY_SERVICE | issuance_native::NATIVE_SERVICE
    );
    if is_issuance {
        headers.insert("x-api-key".into(), state.issuance_service_api_key.clone());
    }
    if body.is_some() {
        headers.insert("content-type".into(), "application/json".into());
    }
    let internal_path = if is_issuance {
        format!("/__gateway/{service}{upstream_path}")
    } else {
        format!("/__gateway/composition/{service}{upstream_path}")
    };
    let mut request = GatewayRequest::new(method, &internal_path, now_ms());
    request.query = query;
    request.headers = headers;
    request.body = body
        .map(|body| serde_json::to_vec(&body))
        .transpose()
        .map_err(|_| detail_response(422, "Composition request could not be serialized"))?;
    let mut overrides = proxy_overrides(state, &internal_path, identity);
    if is_issuance {
        overrides
            .headers
            .insert("x-api-key".into(), state.issuance_service_api_key.clone());
    }
    if requires_gateway_service_token(service) {
        if let Some(service_token) = &state.service_token {
            overrides
                .headers
                .insert("x-service-token".into(), service_token.clone());
        }
    }
    let response = state
        .proxy
        .execute(request, identity, &overrides)
        .await
        .map_err(|_| detail_response(502, "Gateway composition dependency unavailable"))?;
    if response.status_code >= 400 {
        return Err(upstream_response(response));
    }
    response_json(&response)
        .ok_or_else(|| detail_response(502, "Gateway composition dependency returned invalid JSON"))
}

async fn deployment_profile_create_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let owner_context = resource_owner_context(
        request.extensions().get::<GatewayIdentity>(),
        request.headers(),
    );
    let headers = request_headers(request.headers());
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let canonical =
        match deployment_contract::canonicalize_request("POST", "/v1/deployment-profiles", &body) {
            Ok(Some(body)) => body,
            _ => return detail_response(422, "Deployment request is outside the public contract"),
        };
    let value: Value = serde_json::from_slice(&canonical).expect("canonical deployment JSON");
    let dependencies = deployment_contract::create_dependencies(&value)
        .expect("canonical deployment dependencies");
    if identity.organization_id.as_deref() != Some(dependencies.organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let Some(trust_profile_id) = dependencies
        .trust_profile_id
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return detail_response(422, "trust_profile_id is required");
    };
    let trust_path = format!(
        "/v1/trust-profiles/{}",
        utf8_percent_encode(trust_profile_id, NON_ALPHANUMERIC)
    );
    if execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Get,
        &trust_path,
        Vec::new(),
        BTreeMap::new(),
    )
    .await
    .is_err()
    {
        return detail_response(422, &format!("Trust profile not found: {trust_profile_id}"));
    }
    let effective_policies = if dependencies.presentation_policy_ids.is_empty() {
        dependencies
            .default_policy_id
            .as_ref()
            .map(|id| vec![id.clone()])
            .unwrap_or_default()
    } else {
        dependencies.presentation_policy_ids.clone()
    };
    if effective_policies.is_empty() {
        return detail_response(
            422,
            "presentation_policy_ids must contain at least one policy",
        );
    }
    if dependencies
        .default_policy_id
        .as_ref()
        .is_some_and(|id| !effective_policies.contains(id))
    {
        return detail_response(
            422,
            "default_policy_id must be included in presentation_policy_ids",
        );
    }
    for (service, ids, label) in [
        (
            "presentation-policies",
            effective_policies,
            "presentation policy",
        ),
        (
            "credential-templates",
            dependencies.credential_template_ids,
            "credential template",
        ),
    ] {
        for resource_id in ids {
            let path = format!(
                "/v1/{service}/{}",
                utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
            );
            let owner = match state
                .owners
                .resolve_organization(service, &path, &owner_context)
                .await
            {
                Ok(owner) => owner,
                Err(_) => return detail_response(502, "Unable to resolve deployment dependency"),
            };
            let Some(owner) = owner.filter(|value| !value.trim().is_empty()) else {
                return detail_response(422, &format!("{label} not found: {resource_id}"));
            };
            if owner != dependencies.organization_id {
                return detail_response(
                    403,
                    &format!("Access denied: {label} belongs to another organization"),
                );
            }
        }
    }
    let response = match execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/deployment-profiles",
        canonical,
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response).and_then(|value| {
        deployment_contract::project_response(
            value,
            deployment_contract::DeploymentResponseKind::Profile,
        )
        .ok()
    });
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Deployment service returned a response outside the public contract",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    response.headers.remove("content-encoding");
    response.headers.remove("transfer-encoding");
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    upstream_response(response)
}

fn proxy_overrides(
    state: &GatewayRuntimeState,
    path: &str,
    identity: &TrustedIdentityContext,
) -> ProxyOverrides {
    let mut overrides = ProxyOverrides::default();
    if route_ownership(path).service == "device-registration" {
        if let Some(key) = &state.device_registration_gateway_key {
            overrides
                .headers
                .insert("x-service-token".into(), key.clone());
        }
    }
    if requires_issuance_service_auth(path) {
        overrides
            .headers
            .insert("x-api-key".into(), state.issuance_service_api_key.clone());
    }
    if (is_public_service_sign_path(path)
        || is_public_service_csr_path(path)
        || path == "/v1/signing-keys/config/validate-current")
        && identity.required_permission.as_deref() == Some("signing-key:create")
        && identity.organization_id.is_some()
    {
        if let Some(key) = &state.service_sign_gateway_key {
            overrides.headers.insert("x-api-key".into(), key.clone());
        }
    }
    if is_public_issuer_csr_path(path)
        && identity.required_permission.as_deref() == Some("signing-key:create")
        && identity.organization_id.is_some()
    {
        if let Some(key) = &state.issuer_sign_key {
            overrides.headers.insert("x-api-key".into(), key.clone());
        }
    }
    // GatewayProxy strips caller identity and credential headers before
    // applying these trusted action-specific Signing Keys credentials.
    if path == "/v1/signing-keys/issuer-identities/dsc-certificate"
        && identity.required_permission.as_deref() == Some("passport-certificate:issue")
        && identity.organization_id.is_some()
        && identity.user_id.is_some()
        && identity.api_key_id.is_none()
    {
        if let Some(key) = &state.dsc_issue_gateway_key {
            overrides.headers.insert("x-api-key".into(), key.clone());
        }
    }
    if path == "/v1/signing-keys/issuer-identities/csca-self-signed-certificate"
        && state.passport_native_gateway_enabled
        && identity.required_permission.as_deref() == Some("passport-certificate:issue-csca")
        && identity.organization_id.is_some()
        && identity.user_id.is_some()
        && identity.api_key_id.is_none()
    {
        if let Some(key) = &state.csca_issue_gateway_key {
            overrides.headers.insert("x-api-key".into(), key.clone());
        }
    }
    let mdoc_authority = match (path, identity.required_permission.as_deref()) {
        (
            "/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate",
            Some("mdoc-certificate:issue-iaca"),
        ) => state.mdoc_iaca_issue_gateway_key.as_ref(),
        (
            "/v1/signing-keys/issuer-identities/mdoc-dsc-certificate",
            Some("mdoc-certificate:issue"),
        ) => state.mdoc_dsc_issue_gateway_key.as_ref(),
        (path, Some("mdoc-certificate:issue-iaca")) if mdoc_crl_operator_path(path) => {
            state.mdoc_iaca_issue_gateway_key.as_ref()
        }
        _ => None,
    };
    if identity.organization_id.is_some()
        && identity.user_id.is_some()
        && identity.api_key_id.is_none()
    {
        if let Some(key) = mdoc_authority {
            overrides.headers.insert("x-api-key".into(), key.clone());
        }
    }
    let owner = route_ownership(path);
    if requires_gateway_service_token(owner.service) {
        if let Some(service_token) = &state.service_token {
            overrides
                .headers
                .insert("x-service-token".into(), service_token.clone());
        }
    }
    let trusted_organization = if owner.service == "organizations" {
        extract_org_id(path).map(str::to_owned).or_else(|| {
            path.starts_with("/v1/policy-sets")
                .then(|| identity.organization_id.clone())
                .flatten()
        })
    } else if matches!(owner.service, "notifications" | "signing-keys") {
        identity.organization_id.clone()
    } else {
        None
    };
    if let Some(organization_id) = trusted_organization {
        overrides
            .trusted_query
            .insert("organization_id".into(), vec![organization_id]);
    }
    overrides
}

fn is_public_service_sign_path(path: &str) -> bool {
    path.strip_prefix("/v1/signing-keys/services/")
        .and_then(|tail| tail.strip_suffix("/sign"))
        .is_some_and(|service_id| !service_id.is_empty() && !service_id.contains('/'))
}

fn is_public_service_csr_path(path: &str) -> bool {
    path.strip_prefix("/v1/signing-keys/services/")
        .and_then(|tail| tail.strip_suffix("/certificate-csr"))
        .is_some_and(|service_id| !service_id.is_empty() && !service_id.contains('/'))
}

fn is_public_issuer_csr_path(path: &str) -> bool {
    path == "/v1/signing-keys/issuer-identities/certificate-csr"
}

fn compatibility_upstream_path(
    public_path: &str,
    organization_id: Option<&str>,
) -> Result<String, (u16, &'static str)> {
    let organization_id = organization_id
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(relative) = public_path.strip_prefix("/v1/api-keys") {
        if !relative.is_empty()
            && (!relative.starts_with('/')
                || relative[1..].is_empty()
                || relative[1..].contains('/'))
        {
            return Err((404, "API key route not found"));
        }
        let Some(organization_id) = organization_id else {
            return Err((
                422,
                "An active organization is required before managing API keys",
            ));
        };
        return Ok(format!(
            "/v1/organizations/{}/api-keys{relative}",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ));
    }

    if let Some(relative) = public_path.strip_prefix("/v1/policy-sets") {
        if !relative.is_empty() && !relative.starts_with('/') {
            return Err((404, "Policy set route not found"));
        }
        let Some(organization_id) = organization_id else {
            return Err((
                422,
                "An active organization is required before managing policy sets",
            ));
        };
        return Ok(format!(
            "/__gateway/composition/organizations/v1/organizations/{}/policy-sets{relative}",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ));
    }

    if let Some(tail) = public_path.strip_prefix("/v1/organizations/") {
        if let Some((path_organization_id, audit_path)) = tail.split_once("/audit-events") {
            let valid_suffix = audit_path.is_empty()
                || audit_path == "/export"
                || audit_path
                    .strip_prefix('/')
                    .is_some_and(|event_id| !event_id.is_empty() && !event_id.contains('/'));
            if !valid_suffix {
                return Err((404, "Audit event route not found"));
            }
            let Some(organization_id) = organization_id else {
                return Err((
                    422,
                    "An active organization is required before viewing audit events",
                ));
            };
            if path_organization_id != organization_id {
                return Err((403, "Request is not authorized for this organization"));
            }
            return Ok(format!(
                "/__gateway/composition/organizations/v1/organizations/audit/events{audit_path}"
            ));
        }
    }

    Ok(public_path.to_owned())
}

fn requires_gateway_service_token(service: &str) -> bool {
    matches!(
        service,
        "organizations"
            | "credential-templates"
            | "trust-profiles"
            | "presentation-policies"
            | "compliance-profiles"
            | "deployment-profiles"
            | "revocation-profiles"
            | "flows"
    )
}

async fn readiness_handler(state: Arc<GatewayRuntimeState>) -> Response {
    let services = state
        .readiness
        .check_services(&state.required_ready_services)
        .await;
    let ready = services.values().all(|details| details.status == "healthy");
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "service": "api-gateway",
            "services": services,
        })),
    )
        .into_response()
}

async fn services_health_handler(state: Arc<GatewayRuntimeState>) -> Response {
    let services = state.readiness.all_services();
    Json(json!({
        "services": state.readiness.check_services(&services).await,
    }))
    .into_response()
}

fn constant_time_header_matches(value: Option<&HeaderValue>, expected: &str) -> bool {
    let supplied = value
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    supplied.len() == expected.len()
        && supplied.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
}

async fn did_web_slug_handler(state: Arc<GatewayRuntimeState>, raw_slug: &str) -> Response {
    let Some(slug) = did_web::organization_slug(raw_slug) else {
        return detail_response(400, "Invalid organization slug.");
    };
    let response = match signing_service_request(
        &state,
        HttpMethod::Get,
        &format!(
            "/internal/documents/did-web/{}",
            utf8_percent_encode(&slug, NON_ALPHANUMERIC)
        ),
        None,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    if response.status_code != 200 {
        return upstream_response(response);
    }
    let Some(organization_id) = response_json(&response)
        .and_then(|value| value.get("organization_id").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
    else {
        if response_json(&response).is_some_and(|value| value["organization_id"].is_null()) {
            return detail_response(404, "Organization DID not found.");
        }
        return detail_response(503, "DID document registry is unavailable.");
    };
    let did = format!("did:web:{}:orgs:{slug}", state.did_web_authority);
    public_did_document(&state, &organization_id, &did).await
}

async fn did_web_root_handler(state: Arc<GatewayRuntimeState>) -> Response {
    let Some(organization_id) = state.default_organization_id.as_deref() else {
        return detail_response(404, "Root DID document not configured.");
    };
    let did = format!("did:web:{}", state.did_web_authority);
    public_did_document(&state, organization_id, &did).await
}

async fn public_did_document(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    did: &str,
) -> Response {
    let scoped = match load_did_document(state, organization_id, Some(did), did).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let document = if scoped.1 {
        if scoped.0.get("id").and_then(Value::as_str) != Some(did) {
            return detail_response(
                503,
                "Scoped DID document identity does not match its registry key.",
            );
        }
        scoped.0
    } else {
        match load_did_document(state, organization_id, None, did).await {
            Ok((legacy, true)) => did_web::retarget_document(&legacy, did),
            Ok((_, false)) => did_web::empty_document(did),
            Err(response) => return response,
        }
    };
    let mut response = Json(did_web::retarget_document(&document, did)).into_response();
    insert_header(&mut response, "content-type", "application/did+json");
    insert_header(&mut response, "cache-control", "public, max-age=300");
    response
}

async fn load_did_document(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    did_id: Option<&str>,
    fallback_did: &str,
) -> Result<(Value, bool), Response> {
    let body = serde_json::to_vec(&json!({
        "did_id": did_id,
        "fallback_did": fallback_did
    }))
    .expect("DID load request serializes");
    let response = signing_service_request(
        state,
        HttpMethod::Post,
        &format!(
            "/internal/documents/{}/did/load",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ),
        Some(body),
    )
    .await?;
    if response.status_code != 200 {
        return Err(upstream_response(response));
    }
    let Some(body) = response_json(&response) else {
        return Err(detail_response(
            503,
            "DID document registry is unavailable.",
        ));
    };
    let Some(document) = body
        .get("document")
        .filter(|value| value.is_object())
        .cloned()
    else {
        return Err(detail_response(
            503,
            "DID document registry is unavailable.",
        ));
    };
    let Some(found) = body.get("found").and_then(Value::as_bool) else {
        return Err(detail_response(
            503,
            "DID document registry is unavailable.",
        ));
    };
    if document.get("id").and_then(Value::as_str).is_none() {
        return Err(detail_response(
            503,
            "DID document registry is unavailable.",
        ));
    }
    Ok((document, found))
}

async fn signing_service_request(
    state: &Arc<GatewayRuntimeState>,
    method: HttpMethod,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<GatewayResponse, Response> {
    signing_service_request_with_grant(state, method, path, body, None).await
}

async fn signing_service_request_with_grant(
    state: &Arc<GatewayRuntimeState>,
    method: HttpMethod,
    path: &str,
    body: Option<Vec<u8>>,
    grant_header: Option<&str>,
) -> Result<GatewayResponse, Response> {
    let mut request =
        GatewayRequest::new(method, format!("/__gateway/signing-keys{path}"), now_ms());
    request
        .headers
        .insert("accept".into(), "application/json".into());
    if body.is_some() {
        request
            .headers
            .insert("content-type".into(), "application/json".into());
    }
    request.body = body;
    let api_key = if path == "/internal/compat/issuer-dids/sign" {
        state
            .issuer_sign_key
            .as_ref()
            .ok_or_else(|| detail_response(503, "Issuer signing credential is unavailable."))?
    } else {
        &state.signing_service_api_key
    };
    let mut headers = BTreeMap::from([("x-api-key".into(), api_key.clone())]);
    if let Some(grant_header) = grant_header {
        headers.insert(marty_signing_grant::HEADER_NAME.into(), grant_header.into());
    }
    let overrides = ProxyOverrides {
        headers,
        ..ProxyOverrides::default()
    };
    state
        .proxy
        .execute(request, &TrustedIdentityContext::default(), &overrides)
        .await
        .map_err(|_| detail_response(503, "DID document registry is unavailable."))
}

async fn mip_configuration_handler(state: Arc<GatewayRuntimeState>) -> Response {
    let mut request = GatewayRequest::new(
        HttpMethod::Get,
        "/v1/compliance-profiles/system/discoverable",
        now_ms(),
    );
    request
        .headers
        .insert("accept".into(), "application/json".into());
    let profiles = match state
        .proxy
        .execute(
            request,
            &TrustedIdentityContext::default(),
            &ProxyOverrides::default(),
        )
        .await
    {
        Ok(response) if response.status_code == 200 => response_json(&response)
            .and_then(|value| match value {
                Value::Array(values) => Some(values),
                Value::Object(mut object) => object
                    .remove("items")
                    .and_then(|items| items.as_array().cloned()),
                _ => None,
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Json(discovery::mip_configuration(
        &state.issuer_base_url,
        &profiles,
    ))
    .into_response()
}

async fn well_known_proxy_handler(
    state: Arc<GatewayRuntimeState>,
    plan: discovery::WellKnownProxyPlan,
) -> Response {
    let service = issuance_native::upstream_service(HttpMethod::Get, &plan.upstream_path);
    let mut request = GatewayRequest::new(
        HttpMethod::Get,
        format!("/__gateway/{service}{}", plan.upstream_path),
        now_ms(),
    );
    request
        .headers
        .insert("accept".into(), "application/json".into());
    let mut response = match state
        .proxy
        .execute(
            request,
            &TrustedIdentityContext::default(),
            &ProxyOverrides::default(),
        )
        .await
    {
        Ok(response) => response,
        Err(_) => return detail_response(502, "Issuance service error"),
    };
    if plan.normalize_issuer
        && response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .is_some_and(|(_, value)| value.to_ascii_lowercase().contains("json"))
    {
        if let Some(body) = response_json(&response) {
            let normalized = discovery::normalize_issuer_metadata(&body, plan.variant.as_deref());
            if normalized != body {
                response.body = serde_json::to_vec(&normalized).ok();
                response.headers.remove("content-length");
            }
        }
    }
    upstream_response(response)
}

async fn vc_api_verify_handler(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let field = if request.uri().path().ends_with("credentials/verify") {
        ("verifiableCredential", VerifiableField::Credential)
    } else {
        ("verifiablePresentation", VerifiableField::Presentation)
    };
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let query = query_pairs(request.uri().query());
    let organization_id = first_query(&query, "organization_id");
    let policy_id = first_query(&query, "presentation_policy_id");
    let (Some(organization_id), Some(policy_id)) = (organization_id, policy_id) else {
        return detail_response(
            422,
            "organization_id and presentation_policy_id are required",
        );
    };
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                413,
                MipError::new("payload_too_large", "Request body too large"),
            );
        }
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(value)) => Value::Object(value),
        _ => return detail_response(422, "VC-API request body must be a JSON object"),
    };
    let Some(value) = payload.get(field.0) else {
        return detail_response(422, &format!("{} is required", field.0));
    };
    let token = match adapt_verifiable(value, field.1) {
        Ok(value) => value,
        Err(error) => return json_detail_response(422, json!({"error": error.code()})),
    };
    let options = payload
        .get("options")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let upstream_body = match serde_json::to_vec(&evaluation_request(token, &options)) {
        Ok(body) => body,
        Err(_) => return detail_response(422, "VC-API request could not be adapted"),
    };
    let mut upstream_request = GatewayRequest::new(
        HttpMethod::Post,
        format!("/v1/presentation-policies/{policy_id}/evaluate"),
        now_ms(),
    );
    upstream_request
        .headers
        .insert("content-type".into(), "application/json".into());
    upstream_request.body = Some(upstream_body);
    upstream_request.client_ip =
        client_ip_observation(state.observe_client_ip, &parts.headers, &parts.extensions).peer_ip;
    let overrides = proxy_overrides(
        &state,
        &format!("/v1/presentation-policies/{policy_id}/evaluate"),
        &identity,
    );
    let upstream = match state
        .proxy
        .execute(upstream_request, &identity, &overrides)
        .await
    {
        Ok(response) => response,
        Err(_) => return detail_response(502, "Presentation policy service unavailable"),
    };
    if upstream.status_code >= 400 {
        return upstream_response(upstream);
    }
    let evaluation = match upstream
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok())
    {
        Some(value) => value,
        None => return detail_response(502, "Presentation policy returned an invalid response"),
    };
    match adapt_evaluation(&evaluation) {
        Ok(adapted) => (
            StatusCode::from_u16(adapted.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(adapted.body),
        )
            .into_response(),
        Err(_) => detail_response(502, "Presentation policy returned an invalid response"),
    }
}

async fn vc_api_issue_handler(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let query = query_pairs(request.uri().query());
    let organization_id = first_query(&query, "organization_id");
    let template_id = first_query(&query, "credential_template_id");
    let issuer_did = first_query(&query, "issuer_did");
    let (Some(organization_id), Some(template_id), Some(issuer_did)) =
        (organization_id, template_id, issuer_did)
    else {
        return detail_response(
            422,
            "organization_id, credential_template_id, and issuer_did are required",
        );
    };
    if !issuer_did.starts_with("did:") {
        return detail_response(422, "issuer_did must be a DID");
    }
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let (_, body) = request.into_parts();
    let body = match to_bytes(body, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                413,
                MipError::new("payload_too_large", "Request body too large"),
            );
        }
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(value)) => Value::Object(value),
        _ => return detail_response(422, "VC-API request body must be a JSON object"),
    };
    let Some(credential) = payload.get("credential").filter(|value| value.is_object()) else {
        return detail_response(422, "credential is required");
    };
    if credential_issuer_id(credential).is_some_and(|issuer| issuer != issuer_did) {
        return json_detail_response(
            422,
            json!({
                "error": "issuer_mismatch",
                "error_description": "credential issuer must match the issuer_did selected for signing"
            }),
        );
    }
    let issuer_url = format!("{}/org/{organization_id}", state.issuer_base_url);
    let initiate = json!({
        "organization_id": organization_id,
        "credential_template_id": template_id,
        "issuer_did": issuer_did,
        "credential_document": credential,
    });
    let initiated = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance",
        initiate,
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let transaction = match response_json(&initiated) {
        Some(Value::Object(value)) => Value::Object(value),
        _ => {
            return detail_response(
                502,
                "Marty general issuance API returned an invalid response",
            )
        }
    };
    let offer_uri = transaction
        .get("credential_offer_uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let offer = match parse_inline_credential_offer(offer_uri, &issuer_url) {
        Ok(offer) => offer,
        Err(error) => {
            return detail_response(
                502,
                &format!("Marty issuance returned an invalid credential offer: {error}"),
            );
        }
    };

    let token_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        )
        .append_pair("pre-authorized_code", &offer.pre_authorized_code)
        .finish();
    let token_response = match execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance/token",
        token_form.into_bytes(),
        BTreeMap::from([(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        )]),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(access_token) = response_json(&token_response)
        .as_ref()
        .and_then(|value| value.get("access_token"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return detail_response(502, "Marty issuance did not return an access token");
    };

    let nonce_response = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance/nonce",
        json!({}),
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(nonce) = response_json(&nonce_response)
        .as_ref()
        .and_then(|value| value.get("c_nonce"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return detail_response(502, "Marty issuance did not return a proof nonce");
    };
    let proof_request = json!({
        "organization_id": organization_id,
        "issuer_url": issuer_url,
        "nonce": nonce,
    });
    let proof_body = match serde_json::to_vec(&proof_request) {
        Ok(body) => body,
        Err(_) => return detail_response(503, "could not generate OID4VCI holder proof"),
    };
    let proof_response = match signing_service_request(
        &state,
        HttpMethod::Post,
        "/internal/vc-api/holder-proof",
        Some(proof_body),
    )
    .await
    {
        Ok(response) if response.status_code == 200 => response,
        _ => return detail_response(503, "could not generate OID4VCI holder proof"),
    };
    let Some(proof) = response_json(&proof_response)
        .as_ref()
        .and_then(|value| value.get("proof_jwt"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return detail_response(503, "could not generate OID4VCI holder proof");
    };
    let issued = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance/credential",
        json!({
            "credential_configuration_id": offer.credential_configuration_id,
            "proofs": {"jwt": [proof]},
        }),
        BTreeMap::from([("authorization".into(), format!("Bearer {access_token}"))]),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(issued_json) = response_json(&issued) else {
        return detail_response(
            502,
            "Marty issuance did not return a native Data Integrity credential",
        );
    };
    let credential = match issued_data_integrity_credential(&issued_json, issuer_did) {
        Ok(credential) => credential.clone(),
        Err(_) => {
            return detail_response(
                502,
                "Marty issuance did not return a native Data Integrity credential",
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({"verifiableCredential": credential})),
    )
        .into_response()
}

async fn execute_json_proxy(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    method: HttpMethod,
    path: &str,
    body: Value,
    mut headers: BTreeMap<String, String>,
) -> Result<GatewayResponse, Response> {
    headers.insert("content-type".into(), "application/json".into());
    let body = serde_json::to_vec(&body)
        .map_err(|_| detail_response(422, "Gateway request could not be serialized"))?;
    execute_proxy_request(state, identity, method, path, body, headers).await
}

async fn execute_proxy_request(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    method: HttpMethod,
    path: &str,
    body: Vec<u8>,
    headers: BTreeMap<String, String>,
) -> Result<GatewayResponse, Response> {
    let mut request = GatewayRequest::new(method, path, now_ms());
    request.headers = headers;
    request.body = Some(body);
    let response = state
        .proxy
        .execute(request, identity, &proxy_overrides(state, path, identity))
        .await
        .map_err(|_| detail_response(502, "Gateway dependency unavailable"))?;
    if response.status_code >= 400 {
        Err(upstream_response(response))
    } else {
        Ok(response)
    }
}

/// Shared bounded object admission; callers retain tenant and grant binding.
async fn request_json_object(request: Request, maximum_bytes: usize) -> Result<Value, Response> {
    let body = to_bytes(request.into_body(), maximum_bytes)
        .await
        .map_err(|_| detail_response(413, "Request body too large"))?;
    match serde_json::from_slice(&body) {
        Ok(Value::Object(body)) => Ok(Value::Object(body)),
        _ => Err(detail_response(422, "Request body must be a JSON object.")),
    }
}

fn response_json(response: &GatewayResponse) -> Option<Value> {
    response
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok())
}

fn base_trusted_identity(identity: &GatewayIdentity) -> TrustedIdentityContext {
    TrustedIdentityContext {
        user_id: Some(identity.user_id.clone()),
        user_email: identity.user_email.clone(),
        user_domain: identity.user_domain.clone(),
        organization_id: identity.session_organization_id.clone(),
        api_key_id: identity.api_key_id.clone(),
        api_key_scopes: identity.api_key_scopes.clone(),
        ..TrustedIdentityContext::default()
    }
}

fn api_key_organization_id(
    trusted_identity: &TrustedIdentityContext,
    session_organization_id: Option<&str>,
) -> Option<String> {
    trusted_identity
        .organization_id
        .clone()
        .or_else(|| session_organization_id.map(str::to_owned))
}

fn request_headers(headers: &axum::http::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn ambiguous_config_precondition(
    method: &axum::http::Method,
    path: &str,
    headers: &axum::http::HeaderMap,
) -> bool {
    ((*method == axum::http::Method::PATCH && path == "/v1/signing-keys/config")
        || ((*method == axum::http::Method::POST || *method == axum::http::Method::PATCH)
            && path == "/v1/signing-keys/issuer-identities"))
        && headers.get_all(header::IF_MATCH).iter().count() > 1
}

fn cookies(headers: &axum::http::HeaderMap) -> BTreeMap<String, String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn query_pairs(query: Option<&str>) -> BTreeMap<String, Vec<String>> {
    let mut pairs = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        pairs
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    pairs
}

fn first_query<'a>(query: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    query
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn http_method(method: &str) -> Option<HttpMethod> {
    match method {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "DELETE" => Some(HttpMethod::Delete),
        "PATCH" => Some(HttpMethod::Patch),
        "HEAD" => Some(HttpMethod::Head),
        "OPTIONS" => Some(HttpMethod::Options),
        "TRACE" => Some(HttpMethod::Trace),
        "CONNECT" => Some(HttpMethod::Connect),
        _ => None,
    }
}

const fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
    }
}

fn response_snapshot(response: &Response, body: Vec<u8>) -> IdempotencyResponse {
    IdempotencyResponse {
        status: response.status().as_u16(),
        body,
        content_type: response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        headers: request_headers(response.headers()),
    }
}

fn cached_response(cached: IdempotencyResponse) -> Response {
    let mut response = Response::new(Body::from(cached.body));
    *response.status_mut() = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in cached.headers {
        insert_header(&mut response, &name, &value);
    }
    if let Some(content_type) = cached.content_type {
        insert_header(&mut response, "content-type", &content_type);
    }
    insert_header(&mut response, "idempotency-replayed", "true");
    response
}

fn upstream_response(upstream: GatewayResponse) -> Response {
    let mut response = Response::new(upstream.body.map_or_else(Body::empty, Body::from));
    *response.status_mut() =
        StatusCode::from_u16(upstream.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in upstream.headers {
        insert_header(&mut response, &name, &value);
    }
    for cookie in upstream.set_cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn error_response(status: u16, error: MipError) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(error),
    )
        .into_response()
}

fn detail_response(status: u16, detail: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(serde_json::json!({"detail": detail})),
    )
        .into_response()
}

fn json_detail_response(status: u16, detail: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(json!({"detail": detail})),
    )
        .into_response()
}

fn insert_header(response: &mut Response, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(value) = HeaderValue::from_str(value) else {
        return;
    };
    response.headers_mut().insert(name, value);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[async_trait]
pub trait ResourceOwnerProvider: Send + Sync {
    async fn resolve_organization(
        &self,
        service: &str,
        path: &str,
        context: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventStreamSubscription {
    pub event_types: Vec<String>,
    pub organization_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDomainEvent {
    pub event_id: String,
    pub event_type: String,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub organization_id: String,
    pub data: BTreeMap<String, String>,
    pub timestamp: String,
}

pub type GatewayDomainEventStream =
    Pin<Box<dyn Stream<Item = Result<GatewayDomainEvent, SecurityError>> + Send>>;

#[async_trait]
pub trait EventStreamProvider: Send + Sync {
    async fn subscribe(
        &self,
        subscription: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceOwnerContext {
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessServiceStatus {
    pub status: String,
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[async_trait]
pub trait ReadinessProvider: Send + Sync {
    async fn check_services(&self, services: &[String])
        -> BTreeMap<String, ReadinessServiceStatus>;

    fn all_services(&self) -> Vec<String>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrganizationResolutionInput {
    pub method: String,
    pub path: String,
    pub query_organization_id: Option<String>,
    pub body_organization_id: Option<String>,
    pub authenticated_organization_id: Option<String>,
    pub owner_context: ResourceOwnerContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganizationSource {
    Path,
    ResourceOwner,
    Query,
    Body,
    AuthenticatedState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedOrganization {
    pub organization_id: String,
    pub source: OrganizationSource,
}

pub async fn resolve_organization(
    input: &OrganizationResolutionInput,
    owners: &dyn ResourceOwnerProvider,
) -> Result<Option<ResolvedOrganization>, SecurityError> {
    if let Some(value) = extract_org_id(&input.path).and_then(normalize_id) {
        return Ok(Some(ResolvedOrganization {
            organization_id: value.to_owned(),
            source: OrganizationSource::Path,
        }));
    }
    if let Some(lookup) = resolve_resource_lookup(&input.path) {
        if let Some(value) = owners
            .resolve_organization(lookup.service, &lookup.path, &input.owner_context)
            .await?
            .as_deref()
            .and_then(normalize_id)
        {
            return Ok(Some(ResolvedOrganization {
                organization_id: value.to_owned(),
                source: OrganizationSource::ResourceOwner,
            }));
        }
    }
    for (value, source) in [
        (
            input.query_organization_id.as_deref(),
            OrganizationSource::Query,
        ),
        (
            input.body_organization_id.as_deref(),
            OrganizationSource::Body,
        ),
        (
            input.authenticated_organization_id.as_deref(),
            OrganizationSource::AuthenticatedState,
        ),
    ] {
        if let Some(value) = value.and_then(normalize_id) {
            return Ok(Some(ResolvedOrganization {
                organization_id: value.to_owned(),
                source,
            }));
        }
    }
    Ok(None)
}

fn normalize_id(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[must_use]
pub fn body_organization_id(method: &str, body: &[u8]) -> Option<String> {
    if !matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        return None;
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("organization_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|value| normalize_id(&value).map(str::to_owned))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantAuthorizationOutcome {
    Bypass,
    Authorized(Box<TrustedIdentityContext>),
    Denied(TenantAuthorizationError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantAuthorizationError {
    pub status: u16,
    pub detail: String,
}

impl TenantAuthorizationError {
    fn provider_unavailable() -> Self {
        Self {
            status: 500,
            detail: "Authorization service unavailable".into(),
        }
    }
}

pub async fn authorize_tenant_request(
    method: &str,
    path: &str,
    organization_id: Option<&str>,
    identity: Option<&GatewayIdentity>,
    memberships: &dyn OrganizationMembershipProvider,
) -> TenantAuthorizationOutcome {
    if skips_tenant_authorization(path) {
        return TenantAuthorizationOutcome::Bypass;
    }
    let Some(required) = resolve_action(method, path) else {
        return TenantAuthorizationOutcome::Bypass;
    };
    let Some(organization_id) = organization_id.and_then(normalize_id) else {
        return if matches!(
            required.permission,
            "passport-certificate:issue"
                | "passport-certificate:issue-csca"
                | "mdoc-certificate:issue"
                | "mdoc-certificate:issue-iaca"
        ) {
            TenantAuthorizationOutcome::Denied(TenantAuthorizationError {
                status: 403,
                detail: "Authenticated organization context is required".into(),
            })
        } else {
            TenantAuthorizationOutcome::Bypass
        };
    };
    if matches!(
        required.permission,
        "passport-certificate:issue"
            | "passport-certificate:issue-csca"
            | "mdoc-certificate:issue"
            | "mdoc-certificate:issue-iaca"
    ) && identity
        .filter(|identity| identity.source == AuthenticationSource::Session)
        .and_then(|identity| identity.session_organization_id.as_deref())
        .and_then(normalize_id)
        != Some(organization_id)
    {
        return TenantAuthorizationOutcome::Denied(TenantAuthorizationError {
            status: 403,
            detail: "Authenticated organization context is required".into(),
        });
    }
    let outcome = authorize_required_tenant(required, organization_id, identity, memberships).await;
    // VC-API verification evaluates an existing presentation policy. Check the
    // machine actor's second permission before idempotency can replay a result;
    // the policy service retains its own tenant and permission enforcement.
    if matches!(&outcome, TenantAuthorizationOutcome::Authorized(_))
        && method == "POST"
        && matches!(
            path,
            "/v1/vc-api/credentials/verify" | "/v1/vc-api/presentations/verify"
        )
    {
        if let Some(identity) =
            identity.filter(|actor| actor.source == AuthenticationSource::ApiKey)
        {
            if let Err(failure) = authorize_api_key(
                "presentation-policy:view",
                organization_id,
                identity.session_organization_id.as_deref(),
                &identity.api_key_scopes,
            ) {
                let mut error = map_failure(failure, "presentation-policy:view");
                if failure == TenantAuthorizationFailure::ApiKeyPermissionMissing {
                    error.detail = "VC-API verification also requires presentation-policy:view (trust:read or trust:write scope); credentials:read plus trust:read is the least-privilege scope pair".into();
                }
                return TenantAuthorizationOutcome::Denied(error);
            }
        }
    }
    outcome
}

async fn authorize_required_tenant(
    required: RequiredPermission,
    organization_id: &str,
    identity: Option<&GatewayIdentity>,
    memberships: &dyn OrganizationMembershipProvider,
) -> TenantAuthorizationOutcome {
    let Some(identity) = identity else {
        return TenantAuthorizationOutcome::Denied(map_failure(
            TenantAuthorizationFailure::AuthenticationRequired,
            required.permission,
        ));
    };

    let membership = match identity.source {
        AuthenticationSource::ApiKey => {
            let result = authorize_api_key(
                required.permission,
                organization_id,
                identity.session_organization_id.as_deref(),
                &identity.api_key_scopes,
            );
            if let Err(failure) = result {
                return TenantAuthorizationOutcome::Denied(map_failure(
                    failure,
                    required.permission,
                ));
            }
            None
        }
        AuthenticationSource::Session => {
            let membership = match memberships
                .get_membership(&identity.user_id, organization_id)
                .await
            {
                Ok(value) => value,
                Err(_) => {
                    return TenantAuthorizationOutcome::Denied(
                        TenantAuthorizationError::provider_unavailable(),
                    );
                }
            };
            if let Err(failure) = authorize_membership(
                required.permission,
                &identity.user_id,
                organization_id,
                membership.as_ref(),
            ) {
                return TenantAuthorizationOutcome::Denied(map_failure(
                    failure,
                    required.permission,
                ));
            }
            membership
        }
    };

    TenantAuthorizationOutcome::Authorized(Box::new(trusted_identity(
        identity,
        organization_id,
        required.permission,
        membership.as_ref(),
    )))
}

async fn authorize_native_passport_tenant(
    method: HttpMethod,
    path: &str,
    identity: Option<&GatewayIdentity>,
    memberships: &dyn OrganizationMembershipProvider,
) -> TenantAuthorizationOutcome {
    let Some(permission) = issuance_native::passport_required_permission(method, path) else {
        return TenantAuthorizationOutcome::Denied(TenantAuthorizationError {
            status: 404,
            detail: "Passport route not found".into(),
        });
    };
    let Some(organization_id) = identity
        .and_then(|value| value.session_organization_id.as_deref())
        .and_then(normalize_id)
    else {
        return TenantAuthorizationOutcome::Denied(TenantAuthorizationError {
            status: 403,
            detail: "Authenticated organization context is required".into(),
        });
    };
    authorize_required_tenant(
        RequiredPermission {
            permission,
            resource: "issuance",
        },
        organization_id,
        identity,
        memberships,
    )
    .await
}

fn trusted_identity(
    identity: &GatewayIdentity,
    organization_id: &str,
    required_permission: &str,
    membership: Option<&OrganizationMembership>,
) -> TrustedIdentityContext {
    TrustedIdentityContext {
        user_id: Some(identity.user_id.clone()),
        user_email: identity.user_email.clone(),
        user_domain: identity.user_domain.clone(),
        organization_id: Some(organization_id.to_owned()),
        api_key_id: identity.api_key_id.clone(),
        api_key_scopes: identity.api_key_scopes.clone(),
        organization_permissions: membership
            .map(|item| item.permissions.iter().cloned().collect())
            .unwrap_or_else(|| {
                if identity.source == AuthenticationSource::ApiKey {
                    vec![required_permission.to_owned()]
                } else {
                    Vec::new()
                }
            }),
        organization_roles: membership
            .map(|item| item.role_names.iter().cloned().collect())
            .unwrap_or_default(),
        required_permission: Some(required_permission.to_owned()),
        ..TrustedIdentityContext::default()
    }
}

fn map_failure(
    failure: TenantAuthorizationFailure,
    required_permission: &str,
) -> TenantAuthorizationError {
    let detail = match failure {
        TenantAuthorizationFailure::ApiKeyOrganizationMismatch => {
            "API key does not have access to this organization".into()
        }
        TenantAuthorizationFailure::ApiKeyPermissionMissing => {
            format!("API key missing required permission: {required_permission}")
        }
        TenantAuthorizationFailure::AuthenticationRequired => "Authentication required".into(),
        TenantAuthorizationFailure::MembershipMissing => "Not a member of this organization".into(),
        TenantAuthorizationFailure::MembershipInactive => {
            "Organization membership is inactive".into()
        }
        TenantAuthorizationFailure::ActionNotAuthorized => {
            format!("Missing required permission: {required_permission}")
        }
    };
    TenantAuthorizationError {
        status: if failure == TenantAuthorizationFailure::AuthenticationRequired {
            401
        } else {
            403
        },
        detail,
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
