//! Executable Marty tenant-authorization boundary for the Axum gateway.
//!
//! Generic policy engines and HTTP decisions stay in MMF. This module only
//! adapts Marty request context to the frozen route classifier and membership
//! provider contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
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
use chrono::Utc;
use futures_core::Stream;
use mmf_platform::{
    ContentTypeDecision, EntityTagDecision, EntityTagPolicy, GatewayProxy, GatewayRequest,
    GatewayResponse, HttpMethod, IdempotencyBegin, IdempotencyRequest, IdempotencyResponse,
    IdempotencyStore, ProtocolVersionDecision, ProxyOverrides, RouteTable, TrustedIdentityContext,
};
use mmf_security::SecurityError;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use crate::{
    authorization::{
        authorize_api_key, authorize_membership, extract_org_id, resolve_action,
        resolve_resource_lookup, skips_tenant_authorization, OrganizationMembership,
        OrganizationMembershipProvider, TenantAuthorizationFailure,
    },
    contract::{requires_issuance_service_auth, retired_canvas_state_route, route_ownership},
    credential_metadata, credential_template_contract, deployment_contract, did_web,
    didcomm_contract,
    discovery::{self, ReleaseIdentity},
    flow_contract,
    issuance_create::IssuanceCreate,
    issuance_lifecycle_contract,
    middleware::{
        authenticate, AuthenticationInput, AuthenticationOutcome, AuthenticationSource,
        GatewayHttpPolicies, GatewayIdentity, GatewayIdentityProvider, GatewayRateLimiter,
        MipError, MIP_VERSION,
    },
    organization_composition, organization_contract, presentation_policy_contract,
    response_projection,
    signing_compat::{self, SigningCompatibilityOperation},
    trust_contract,
    vc_api::{
        adapt_evaluation, adapt_verifiable, credential_issuer_id, evaluation_request,
        issued_data_integrity_credential, parse_inline_credential_offer, VerifiableField,
    },
    verification_flow_contract,
};

const DEFAULT_MAXIMUM_BODY_BYTES: usize = 10 * 1024 * 1024;

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
    pub idempotency: Arc<dyn IdempotencyStore>,
    pub policies: GatewayHttpPolicies,
    pub cors_origins: BTreeSet<String>,
    pub issuer_base_url: String,
    pub public_api_url: String,
    pub did_web_authority: String,
    pub default_organization_id: Option<String>,
    pub signing_service_api_key: String,
    pub issuance_service_api_key: String,
    pub service_token: Option<String>,
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
            issuance_service_api_key,
            service_token: None,
            release_identity,
            maximum_body_bytes: DEFAULT_MAXIMUM_BODY_BYTES,
        })
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

async fn rate_limit_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let cookies = cookies(request.headers());
    let session_id = cookies.get("sessionId").map(String::as_str);
    let forwarded = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip().to_string());
    let result = match state
        .rate_limiter
        .check(
            session_id,
            forwarded,
            peer_ip.as_deref(),
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
    let Some(method) = http_method(request.method().as_str()) else {
        return error_response(
            405,
            MipError::new("method_not_allowed", "Method not allowed"),
        );
    };
    let route_request = GatewayRequest::new(method, request.uri().path(), now_ms());
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
    if request.uri().path() == "/v1/notifications/events/push" {
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
    let identity = parts.extensions.get::<GatewayIdentity>().cloned();
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

async fn idempotency_middleware(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
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
    match request.uri().path() {
        "/health" => {
            return (
                StatusCode::OK,
                Json(json!({"status": "healthy", "service": "gateway"})),
            )
                .into_response();
        }
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
    if retired_canvas_state_route(request.uri().path()) {
        return detail_response(
            410,
            "State-addressed Canvas sessions are no longer supported",
        );
    }
    if request.method() == "POST" && request.uri().path() == "/v1/issuance" {
        return issuance_create_handler(state, request).await;
    }
    if request.method() == "POST" && request.uri().path() == "/v1/credential-templates" {
        return credential_template_create_handler(state, request).await;
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
    if organization_composition_route(request.uri().path()).is_some() {
        return organization_composition_handler(state, request).await;
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
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip().to_string());
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
    let upstream_path =
        match compatibility_upstream_path(&public_path, api_key_organization_id.as_deref()) {
            Ok(path) => path,
            Err((status, detail)) => return detail_response(status, detail),
        };
    let mut gateway_request = GatewayRequest::new(method, &upstream_path, now_ms());
    gateway_request.query = query_pairs(parts.uri.query());
    gateway_request.headers = request_headers(&parts.headers);
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
            if didcomm_contract::request_organization(canonical).as_deref()
                != session_organization_id.as_deref()
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
    if let Some(request_id) = gateway_request.header("x-request-id") {
        gateway_request.request_id = request_id.to_owned();
    }
    // Authentication and tenant scope belong to the public contract. Some
    // compatibility paths are rewritten for an upstream service, so deriving
    // overrides from the upstream path can lose the authenticated tenant or
    // misread a compatibility segment (for example `organizations/audit`).
    let mut overrides = proxy_overrides(&state, &public_path, &identity);
    overrides.body = canonical_body;
    match state
        .proxy
        .execute(gateway_request, &identity, &overrides)
        .await
    {
        Ok(mut response) => {
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
        Err(_) => error_response(
            502,
            MipError::new("bad_gateway", "Unable to execute upstream request"),
        ),
    }
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
    let Some(authorized_org) = request
        .extensions()
        .get::<GatewayIdentity>()
        .and_then(|identity| identity.session_organization_id.as_deref())
        .or(identity.organization_id.as_deref())
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
    let body = Body::from_stream(DisconnectStream {
        inner: ReceiverStream::new(receiver),
        cancellation: cancel_sender,
    });
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
}

impl Stream for DisconnectStream {
    type Item = Result<String, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
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
    if service == "issuance" {
        headers.insert("x-api-key".into(), state.issuance_service_api_key.clone());
    }
    if body.is_some() {
        headers.insert("content-type".into(), "application/json".into());
    }
    let internal_path = if service == "issuance" {
        format!("/__gateway/issuance{upstream_path}")
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
    if service == "issuance" {
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

async fn credential_template_create_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let mut body = match credential_template_contract::canonicalize_create(&body) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Credential-template request is outside the public contract",
            )
        }
    };
    let organization_id = body["organization_id"]
        .as_str()
        .expect("validated organization")
        .to_owned();
    if identity.organization_id.as_deref() != Some(organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    if let Some(trust_profile_id) = body.get("trust_profile_id").and_then(Value::as_str) {
        let path = format!(
            "/v1/trust-profiles/{}",
            utf8_percent_encode(trust_profile_id, NON_ALPHANUMERIC)
        );
        if let Err(response) = execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            return response;
        }
    }
    let compliance_profile_id = body["compliance_profile_id"]
        .as_str()
        .expect("validated compliance profile");
    let compliance_path = format!(
        "/v1/compliance-profiles/{}",
        utf8_percent_encode(compliance_profile_id, NON_ALPHANUMERIC)
    );
    let compliance = match execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Get,
        &compliance_path,
        Vec::new(),
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(compliance) = response_json(&compliance) else {
        return detail_response(502, "Compliance profile service returned invalid data");
    };
    if compliance
        .get("organization_id")
        .and_then(Value::as_str)
        .is_some_and(|owner| owner != organization_id)
    {
        return detail_response(
            403,
            "Access denied: compliance profile belongs to another organization",
        );
    }
    let issuer_did = body["issuer_did"]
        .as_str()
        .expect("validated DID")
        .to_owned();
    let credential_format = body
        .get("credential_payload_format")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("supported_formats")
                .and_then(Value::as_array)
                .and_then(|values| (values.len() == 1).then(|| values[0].as_str()).flatten())
        });
    let key_purpose = if credential_format.is_some_and(|format| {
        matches!(
            format.to_ascii_lowercase().replace('-', "_").as_str(),
            "mdoc" | "mso_mdoc" | "zk_mdoc"
        )
    }) {
        "mdoc_dsc"
    } else {
        "vc_jwt_issuer"
    };
    let resolved = match signing_service_request(
        &state,
        HttpMethod::Post,
        "/internal/compat/resolve-issuer-did",
        Some(
            serde_json::to_vec(&json!({
                "organization_id": organization_id, "issuer_did": issuer_did,
                "credential_format": credential_format, "key_purpose": key_purpose
            }))
            .expect("resolution request"),
        ),
    )
    .await
    {
        Ok(response) if response.status_code < 400 => response,
        Ok(response) => return upstream_response(response),
        Err(response) => return response,
    };
    let valid_identity = response_json(&resolved).is_some_and(|resolved| {
        resolved.get("ok") == Some(&Value::Bool(true))
            && resolved.get("organization_id").and_then(Value::as_str)
                == Some(organization_id.as_str())
            && resolved.get("issuer_did").and_then(Value::as_str) == Some(issuer_did.as_str())
            && resolved.get("key_purpose").and_then(Value::as_str) == Some(key_purpose)
            && resolved
                .get("public_jwk")
                .and_then(Value::as_object)
                .is_some_and(|jwk| {
                    !["d", "p", "q", "k"]
                        .iter()
                        .any(|field| jwk.contains_key(*field))
                })
    });
    if !valid_identity {
        return detail_response(422, "issuer_did must resolve to exactly one active organization-owned signing identity for this template.");
    }
    body["issuer_did"] = Value::String(issuer_did);
    let response = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/credential-templates",
        body,
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok())
        .and_then(|value| credential_template_contract::public_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Credential-template service returned an invalid public response",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    upstream_response(response)
}

async fn flow_definition_write_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let update = request.method() == "PATCH";
    let public_path = request.uri().path().to_owned();
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let headers = request_headers(request.headers());
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let canonical = match flow_contract::canonicalize_definition(&body, update) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Flow definition request is outside the public contract",
            )
        }
    };
    let organization_id = canonical["organization_id"]
        .as_str()
        .expect("canonical flow organization");
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    for (kind, resource_id) in flow_contract::definition_references(&canonical) {
        let (path, not_found_status) = match kind {
            "credential-templates" => (
                format!(
                    "/v1/credential-templates/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                404,
            ),
            "application-templates" => (
                format!(
                    "/v1/application-templates/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                404,
            ),
            "presentation-policies" => (
                format!(
                    "/v1/presentation-policies/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            "delivery-destinations" => (
                format!(
                    "/v1/delivery-destinations/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            "trust-profiles" => (
                format!(
                    "/v1/trust-profiles/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            _ => unreachable!("known flow reference"),
        };
        if execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        .is_err()
        {
            return detail_response(
                not_found_status,
                &format!("Flow dependency not found: {resource_id}"),
            );
        }
    }
    let method = if update {
        HttpMethod::Patch
    } else {
        HttpMethod::Post
    };
    let response = match execute_proxy_request(
        &state,
        &identity,
        method,
        &public_path,
        serde_json::to_vec(&canonical).expect("canonical flow definition"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response).and_then(|value| {
        flow_contract::project_response(value, flow_contract::FlowResponseKind::Definition).ok()
    });
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Flow service returned a response outside the public contract",
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

async fn presentation_policy_write_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let update = request.method() == "PATCH";
    let public_path = request.uri().path().to_owned();
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
    let mut canonical =
        match presentation_policy_contract::canonicalize_request(&body, update, true) {
            Ok(body) => body,
            Err(_) => {
                return detail_response(
                    422,
                    "Presentation policy request is outside the public contract",
                )
            }
        };
    let organization_id = canonical["organization_id"]
        .as_str()
        .expect("canonical policy organization")
        .to_owned();
    if identity.organization_id.as_deref() != Some(organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    if update {
        let owner = match state
            .owners
            .resolve_organization("presentation-policies", &public_path, &owner_context)
            .await
        {
            Ok(owner) => owner,
            Err(_) => return detail_response(502, "Unable to resolve presentation policy owner"),
        };
        if owner.as_deref() != Some(organization_id.as_str()) {
            return detail_response(404, "Presentation Policy not found");
        }
    }
    let template_ids = presentation_policy_contract::credential_template_ids(&canonical)
        .into_iter()
        .collect::<BTreeSet<_>>();
    for template_id in template_ids {
        let template_path = format!(
            "/v1/credential-templates/{}",
            utf8_percent_encode(&template_id, NON_ALPHANUMERIC)
        );
        let template = match execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &template_path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                return detail_response(
                    422,
                    &format!("Credential template not found: {template_id}"),
                )
            }
        };
        let Some(template) = response_json(&template) else {
            return detail_response(502, "Credential template service returned invalid JSON");
        };
        if template.get("organization_id").and_then(Value::as_str) != Some(organization_id.as_str())
        {
            return detail_response(
                422,
                &format!(
                    "Credential template must belong to the presentation policy organization: {template_id}"
                ),
            );
        }
        let Some(format) = template
            .get("credential_payload_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|format| !format.is_empty())
        else {
            return detail_response(
                502,
                &format!(
                    "Credential template has no canonical credential payload format: {template_id}"
                ),
            );
        };
        presentation_policy_contract::apply_authoritative_format(
            &mut canonical,
            &template_id,
            format,
        );
    }
    if update {
        canonical
            .as_object_mut()
            .expect("canonical policy object")
            .remove("organization_id");
    }
    let method = if update {
        HttpMethod::Patch
    } else {
        HttpMethod::Post
    };
    let response = match execute_proxy_request(
        &state,
        &identity,
        method,
        &public_path,
        serde_json::to_vec(&canonical).expect("canonical policy request"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response)
        .and_then(|value| presentation_policy_contract::project_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Presentation policy service response violates the public contract",
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

async fn verification_flow_start_handler(
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
    let canonical = match verification_flow_contract::canonicalize_request(&body) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Verification flow request is outside the public contract",
            )
        }
    };
    let organization_id = verification_flow_contract::organization_id(&canonical);
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    for (field, service, label) in [
        (
            "presentation_policy_id",
            "presentation-policies",
            "Presentation policy",
        ),
        ("trust_profile_id", "trust-profiles", "Trust profile"),
    ] {
        let Some(resource_id) = verification_flow_contract::reference(&canonical, field) else {
            continue;
        };
        let path = format!("/v1/{service}/{resource_id}");
        let owner = match state
            .owners
            .resolve_organization(service, &path, &owner_context)
            .await
        {
            Ok(owner) => owner,
            Err(_) => return detail_response(502, "Unable to resolve verification dependency"),
        };
        let Some(owner) = owner.filter(|owner| !owner.trim().is_empty()) else {
            return detail_response(422, &format!("{label} not found: {resource_id}"));
        };
        if owner.trim() != organization_id {
            return detail_response(403, &format!("{label} belongs to another organization."));
        }
    }
    let response = match execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/flows/verify",
        serde_json::to_vec(&canonical).expect("canonical verification request"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response)
        .and_then(|value| verification_flow_contract::project_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Flow service returned an invalid public verification response",
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

async fn issuance_create_handler(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let input = match serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| IssuanceCreate::parse(value).ok())
    {
        Some(input) => input,
        None => return detail_response(422, "Issuance request is outside the public contract"),
    };
    if identity.organization_id.as_deref() != Some(input.organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }

    let template = if let Some(template_id) = input.credential_template_id.as_deref() {
        let path = format!(
            "/v1/credential-templates/{}",
            utf8_percent_encode(template_id, NON_ALPHANUMERIC)
        );
        let response = match execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(response) => return response,
        };
        let Some(template) = response_json(&response) else {
            return detail_response(502, "Credential template service returned invalid data");
        };
        if template.get("organization_id").and_then(Value::as_str)
            != Some(input.organization_id.as_str())
        {
            return detail_response(
                403,
                "Access denied: credential template belongs to another organization",
            );
        }
        template
    } else {
        json!({})
    };
    let issuer_did = match input.select_issuer_did(&template) {
        Ok(value) => value,
        Err(error) => return detail_response(422, error.0),
    };
    let credential_format = input.credential_format(&template);
    let key_purpose = match credential_format.as_deref() {
        Some("mso_mdoc") => "mdoc_dsc",
        Some("vds_nc" | "vdsnc") => "vdsnc_signing",
        _ => "vc_jwt_issuer",
    };
    let resolution = match signing_service_request(
        &state,
        HttpMethod::Post,
        "/internal/compat/resolve-issuer-did",
        Some(
            serde_json::to_vec(&json!({
                "organization_id": input.organization_id,
                "issuer_did": issuer_did,
                "credential_format": credential_format,
                "key_purpose": key_purpose
            }))
            .expect("issuer resolution request serializes"),
        ),
    )
    .await
    {
        Ok(response) if response.status_code < 400 => response,
        Ok(response) => return upstream_response(response),
        Err(response) => return response,
    };
    let Some(resolved) = response_json(&resolution) else {
        return detail_response(
            503,
            "Signing-keys issuer DID resolver returned invalid data",
        );
    };
    let public_jwk = resolved.get("public_jwk").and_then(Value::as_object);
    let private_jwk = public_jwk.is_some_and(|jwk| {
        ["d", "p", "q", "k"]
            .iter()
            .any(|field| jwk.contains_key(*field))
    });
    if resolved.get("ok") != Some(&Value::Bool(true))
        || resolved.get("organization_id").and_then(Value::as_str)
            != Some(input.organization_id.as_str())
        || resolved.get("issuer_did").and_then(Value::as_str) != Some(issuer_did.as_str())
        || resolved.get("key_purpose").and_then(Value::as_str) != Some(key_purpose)
        || resolved
            .get("verification_method_id")
            .and_then(Value::as_str)
            .is_none_or(|method| !method.starts_with(&format!("{issuer_did}#")))
        || public_jwk.is_none()
        || private_jwk
    {
        return detail_response(
            422,
            "issuer_did must resolve to exactly one active organization-owned signing identity.",
        );
    }

    if let Some(registration) = input.registration() {
        if let Err(response) = execute_json_proxy(
            &state,
            &identity,
            HttpMethod::Put,
            "/__gateway/issuance/v1/issuance/oid4vci-clients",
            registration,
            BTreeMap::from([("x-api-key".into(), state.issuance_service_api_key.clone())]),
        )
        .await
        {
            return response;
        }
    }
    let downstream = match input.downstream(issuer_did) {
        Ok(value) => value,
        Err(error) => return detail_response(422, error.0),
    };
    let response = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance",
        downstream,
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    match response_projection::project(HttpMethod::Post, "/v1/issuance", response) {
        Ok(response) => upstream_response(response),
        Err(_) => detail_response(502, "Issuance service returned an invalid public response."),
    }
}

fn proxy_overrides(
    state: &GatewayRuntimeState,
    path: &str,
    identity: &TrustedIdentityContext,
) -> ProxyOverrides {
    let mut overrides = ProxyOverrides::default();
    if requires_issuance_service_auth(path) {
        overrides
            .headers
            .insert("x-api-key".into(), state.issuance_service_api_key.clone());
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
        "organizations" | "credential-templates" | "trust-profiles" | "presentation-policies"
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

async fn internal_signing_compatibility_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    if !constant_time_header_matches(
        request.headers().get("x-api-key"),
        &state.signing_service_api_key,
    ) {
        return detail_response(401, "Invalid internal API key");
    }
    let Some(method) = http_method(request.method().as_str()) else {
        return detail_response(405, "Method not allowed");
    };
    let Some(operation) = signing_compat::operation(method, request.uri().path()) else {
        return detail_response(404, "Not found");
    };
    let query = query_pairs(request.uri().query());
    let Some(organization_id) = first_query(&query, "organization_id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return detail_response(422, "organization_id is required.");
    };
    if matches!(
        &operation,
        SigningCompatibilityOperation::FlowEnvelopeWrap
            | SigningCompatibilityOperation::FlowEnvelopeUnwrap
    ) {
        return forward_flow_envelope(&state, &operation, &organization_id, request).await;
    }
    if operation == SigningCompatibilityOperation::IssuerContext {
        return forward_issuer_context(&state, &organization_id, &query).await;
    }
    if operation == SigningCompatibilityOperation::ResolveIssuerDid {
        return forward_resolve_issuer_did(&state, &organization_id, &query).await;
    }
    if let SigningCompatibilityOperation::ProfileIdentity { profile_id } = &operation {
        return forward_profile_identity(&state, &organization_id, profile_id, false).await;
    }
    if let SigningCompatibilityOperation::ProfilePublicIdentity { profile_id } = &operation {
        return forward_profile_identity(&state, &organization_id, profile_id, true).await;
    }
    if operation == SigningCompatibilityOperation::IssuerDidSign {
        return forward_signing_body(
            &state,
            &organization_id,
            "/internal/compat/issuer-dids/sign",
            request,
        )
        .await;
    }
    if let SigningCompatibilityOperation::ServiceSign { service_id } = &operation {
        let path = format!(
            "/internal/compat/services/{}/sign",
            utf8_percent_encode(service_id, NON_ALPHANUMERIC)
        );
        return forward_signing_body(&state, &organization_id, &path, request).await;
    }
    if operation == SigningCompatibilityOperation::CreateProfile {
        return forward_profile_write(
            &state,
            &organization_id,
            "/internal/compat/issuer-profiles",
            request,
        )
        .await;
    }
    if let SigningCompatibilityOperation::UpdateProfile { profile_id } = &operation {
        let path = format!(
            "/internal/compat/issuer-profiles/{}",
            utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
        );
        return forward_profile_write(&state, &organization_id, &path, request).await;
    }
    if let SigningCompatibilityOperation::ProfileCertificate { profile_id } = &operation {
        let path = format!(
            "/internal/compat/issuer-profiles/{}/certificate",
            utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
        );
        return forward_profile_write(&state, &organization_id, &path, request).await;
    }
    let organization_id = utf8_percent_encode(&organization_id, NON_ALPHANUMERIC);
    let (method, path, transform_delete) = match operation {
        SigningCompatibilityOperation::ListProfiles => (
            HttpMethod::Get,
            format!("/internal/profiles/{organization_id}"),
            false,
        ),
        SigningCompatibilityOperation::GetProfile { profile_id } => (
            HttpMethod::Get,
            format!(
                "/internal/profiles/{organization_id}/{}",
                utf8_percent_encode(&profile_id, NON_ALPHANUMERIC)
            ),
            false,
        ),
        SigningCompatibilityOperation::DeleteProfile { profile_id } => (
            HttpMethod::Delete,
            format!(
                "/internal/profiles/{organization_id}/{}",
                utf8_percent_encode(&profile_id, NON_ALPHANUMERIC)
            ),
            true,
        ),
        _ => {
            return error_response(
                501,
                MipError::new(
                    "not_implemented",
                    "Internal signing compatibility operation has not completed Rust migration",
                ),
            );
        }
    };
    let response = match signing_service_request(&state, method, &path, None).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    if !transform_delete || response.status_code != 200 {
        return upstream_response(response);
    }
    let Some(deleted) = response_json(&response)
        .and_then(|body| body.get("deleted").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
    else {
        return detail_response(503, "Native issuer-profile backend is unavailable.");
    };
    Json(json!({"ok": true, "deleted": deleted})).into_response()
}

async fn forward_resolve_issuer_did(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Response {
    if query.contains_key("issuer_profile_id") {
        return detail_response(
            422,
            "issuer_profile_id is not accepted; resolve the issuer by issuer_did.",
        );
    }
    let Some(issuer_did) = first_query(query, "issuer_did") else {
        return detail_response(422, "issuer_did is required.");
    };
    let body = json!({
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "verification_method_id": first_query(query, "verification_method_id"),
        "credential_format": first_query(query, "credential_format"),
        "key_purpose": first_query(query, "key_purpose"),
        "algorithm": first_query(query, "algorithm")
    });
    forward_signing_compatibility_json(state, "/internal/compat/resolve-issuer-did", body).await
}

async fn forward_profile_identity(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    profile_id: &str,
    public_projection: bool,
) -> Response {
    let suffix = if public_projection {
        "public-identity"
    } else {
        "identity"
    };
    let path = format!(
        "/internal/compat/issuer-profiles/{}/{suffix}",
        utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
    );
    forward_signing_compatibility_json(state, &path, json!({"organization_id": organization_id}))
        .await
}

async fn forward_signing_compatibility_json(
    state: &Arc<GatewayRuntimeState>,
    path: &str,
    body: Value,
) -> Response {
    match signing_service_request(
        state,
        HttpMethod::Post,
        path,
        Some(serde_json::to_vec(&body).expect("compatibility request serializes")),
    )
    .await
    {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
}

async fn forward_signing_body(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    path: &str,
    request: Request,
) -> Response {
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let mut body: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(body)) => Value::Object(body),
        _ => return detail_response(422, "Request body must be a JSON object."),
    };
    body["organization_id"] = Value::String(organization_id.into());
    forward_signing_compatibility_json(state, path, body).await
}

async fn forward_profile_write(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    path: &str,
    request: Request,
) -> Response {
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let body: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(body)) => Value::Object(body),
        _ => return detail_response(422, "Request body must be a JSON object."),
    };
    forward_signing_compatibility_json(
        state,
        path,
        json!({"organization_id": organization_id, "body": body}),
    )
    .await
}

async fn forward_issuer_context(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Response {
    if query.contains_key("issuer_profile_id") {
        return detail_response(
            422,
            "issuer_profile_id is not accepted; resolve the issuer by issuer_did.",
        );
    }
    let body = json!({
        "organization_id": organization_id,
        "issuer_did": first_query(query, "issuer_did")
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        "issuer_mode": first_query(query, "issuer_mode")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("org_managed"),
        "credential_format": first_query(query, "credential_format"),
        "key_purpose": first_query(query, "key_purpose"),
        "algorithm": first_query(query, "algorithm")
    });
    let response = signing_service_request(
        state,
        HttpMethod::Post,
        "/internal/compat/issuer-context",
        Some(serde_json::to_vec(&body).expect("issuer context request serializes")),
    )
    .await;
    match response {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
}

async fn forward_flow_envelope(
    state: &Arc<GatewayRuntimeState>,
    operation: &SigningCompatibilityOperation,
    organization_id: &str,
    request: Request,
) -> Response {
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let mut body: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(body)) => Value::Object(body),
        _ => return detail_response(422, "Request body must be a JSON object."),
    };
    body["organization_id"] = Value::String(organization_id.into());
    let path = match operation {
        SigningCompatibilityOperation::FlowEnvelopeWrap => "/internal/flow-key-envelopes/wrap",
        SigningCompatibilityOperation::FlowEnvelopeUnwrap => "/internal/flow-key-envelopes/unwrap",
        _ => unreachable!("caller restricts flow-envelope operations"),
    };
    let response = signing_service_request(
        state,
        HttpMethod::Post,
        path,
        Some(serde_json::to_vec(&body).expect("flow envelope request serializes")),
    )
    .await;
    match response {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
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
    let overrides = ProxyOverrides {
        headers: BTreeMap::from([("x-api-key".into(), state.signing_service_api_key.clone())]),
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
    let mut request = GatewayRequest::new(
        HttpMethod::Get,
        format!("/__gateway/issuance{}", plan.upstream_path),
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
    upstream_request.client_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip().to_string());
    let upstream = match state
        .proxy
        .execute(upstream_request, &identity, &ProxyOverrides::default())
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
    let proof = match marty_oid4vci::proof::create_proof_jwt(&issuer_url, &nonce) {
        Ok(proof) => proof,
        Err(_) => return detail_response(503, "could not generate OID4VCI holder proof"),
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
        return TenantAuthorizationOutcome::Bypass;
    };
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
            .unwrap_or_default(),
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
mod tests {
    use super::*;
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicBool, Ordering},
    };

    use mmf_platform::{
        GatewayResponse, InMemoryIdempotencyStore, PlatformError, ProxyConfig, ServiceInstance,
        UpstreamClient,
    };
    use mmf_security::InMemoryRateLimiter;
    use tower::ServiceExt;

    use crate::{
        contract::GatewayContract,
        middleware::{ApiKeyIdentity, SessionIdentity},
        registry::StaticServiceRegistry,
    };

    struct ScriptedOwner(Option<String>);

    #[async_trait]
    impl ResourceOwnerProvider for ScriptedOwner {
        async fn resolve_organization(
            &self,
            _: &str,
            _: &str,
            _: &ResourceOwnerContext,
        ) -> Result<Option<String>, SecurityError> {
            Ok(self.0.clone())
        }
    }

    struct ScriptedMembership(&'static str);

    #[async_trait]
    impl OrganizationMembershipProvider for ScriptedMembership {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            match self.0 {
                "allowed" => Ok(Some(OrganizationMembership {
                    user_id: user_id.into(),
                    organization_id: organization_id.into(),
                    status: "active".into(),
                    role_names: BTreeSet::from(["key-manager".into()]),
                    permissions: BTreeSet::from(["signing-key:view".into()]),
                    is_owner: false,
                })),
                "inactive" => Ok(Some(OrganizationMembership {
                    user_id: user_id.into(),
                    organization_id: organization_id.into(),
                    status: "inactive".into(),
                    role_names: BTreeSet::new(),
                    permissions: BTreeSet::new(),
                    is_owner: false,
                })),
                "error" => Err(SecurityError::ProviderUnavailable("fixture".into())),
                _ => Ok(None),
            }
        }
    }

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        organization_resolution: Vec<ResolutionCase>,
        authorization: Vec<AuthorizationCase>,
    }

    #[derive(Deserialize)]
    struct ResolutionCase {
        path: String,
        owner: Option<String>,
        query: Option<String>,
        body: Option<String>,
        state: Option<String>,
        expected: Option<String>,
    }

    #[derive(Deserialize)]
    struct AuthorizationCase {
        method: String,
        path: String,
        identity: String,
        organization: Option<String>,
        membership: String,
        outcome: String,
        status: Option<u16>,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/gateway-runtime-authorization.json"
        ))
        .expect("valid runtime authorization contract")
    }

    fn identity(kind: &str) -> Option<GatewayIdentity> {
        let (source, organization, scopes) = match kind {
            "session" => (AuthenticationSource::Session, Some("org-1"), vec![]),
            "api_key_wrong_org" => (
                AuthenticationSource::ApiKey,
                Some("org-other"),
                vec!["keys:read".into()],
            ),
            "api_key_read" => (
                AuthenticationSource::ApiKey,
                Some("org-1"),
                vec!["keys:read".into()],
            ),
            _ => return None,
        };
        let is_api_key = source == AuthenticationSource::ApiKey;
        Some(GatewayIdentity {
            source,
            user_id: if kind == "session" {
                "user-1".into()
            } else {
                "api_key:key-1".into()
            },
            user_email: None,
            user_domain: None,
            session_organization_id: organization.map(str::to_owned),
            api_key_id: is_api_key.then(|| "key-1".into()),
            api_key_prefix: None,
            api_key_scopes: scopes,
        })
    }

    #[tokio::test]
    async fn language_neutral_runtime_authorization_contract() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        for case in contract.organization_resolution {
            let resolved = resolve_organization(
                &OrganizationResolutionInput {
                    method: "GET".into(),
                    path: case.path,
                    query_organization_id: case.query,
                    body_organization_id: case.body,
                    authenticated_organization_id: case.state,
                    owner_context: ResourceOwnerContext::default(),
                },
                &ScriptedOwner(case.owner),
            )
            .await
            .expect("organization resolution");
            assert_eq!(
                resolved
                    .as_ref()
                    .map(|value| value.organization_id.as_str()),
                case.expected.as_deref()
            );
        }
        for case in contract.authorization {
            let identity = identity(&case.identity);
            let outcome = authorize_tenant_request(
                &case.method,
                &case.path,
                case.organization.as_deref(),
                identity.as_ref(),
                &ScriptedMembership(Box::leak(case.membership.into_boxed_str())),
            )
            .await;
            let (name, status) = match outcome {
                TenantAuthorizationOutcome::Bypass => ("bypass", None),
                TenantAuthorizationOutcome::Authorized(_) => ("authorized", None),
                TenantAuthorizationOutcome::Denied(error) => ("denied", Some(error.status)),
            };
            assert_eq!(name, case.outcome);
            assert_eq!(status, case.status);
        }
    }

    #[test]
    fn body_tenant_is_only_read_for_mutating_json_requests() {
        let body = br#"{"organization_id":" org-1 "}"#;
        assert_eq!(body_organization_id("POST", body).as_deref(), Some("org-1"));
        assert_eq!(body_organization_id("GET", body), None);
        assert_eq!(body_organization_id("PATCH", b"not-json"), None);
    }

    struct RuntimeProvider;

    #[async_trait]
    impl GatewayIdentityProvider for RuntimeProvider {
        async fn validate_session(
            &self,
            session_id: &str,
        ) -> Result<Option<SessionIdentity>, SecurityError> {
            let organization_id = match session_id {
                "valid" => Some("org-1"),
                "valid-uuid" => Some("11111111-1111-1111-1111-111111111111"),
                "valid-no-org" => None,
                _ => return Ok(None),
            };
            Ok(Some(SessionIdentity {
                user_id: "user-1".into(),
                organization_id: organization_id.map(str::to_owned),
                ..SessionIdentity::default()
            }))
        }

        async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl OrganizationMembershipProvider for RuntimeProvider {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            Ok(Some(OrganizationMembership {
                user_id: user_id.into(),
                organization_id: organization_id.into(),
                status: "active".into(),
                role_names: BTreeSet::from(["key-manager".into()]),
                permissions: BTreeSet::from([
                    "signing-key:view".into(),
                    "signing-key:create".into(),
                    "verification:execute".into(),
                    "issuance:initiate".into(),
                    "issuance:view".into(),
                    "application:review".into(),
                    "integration-connector:view".into(),
                    "role:view".into(),
                    "credential-template:edit".into(),
                    "credential-template:create".into(),
                    "trusted-issuer:view".into(),
                    "trusted-issuer:create".into(),
                    "trusted-issuer:edit".into(),
                    "trust-profile:view".into(),
                    "trust-profile:create".into(),
                    "trust-profile:edit".into(),
                    "presentation-policy:view".into(),
                    "presentation-policy:create".into(),
                    "presentation-policy:edit".into(),
                    "flow-definition:view".into(),
                    "flow-definition:create".into(),
                    "flow-definition:edit".into(),
                    "flow-instance:view".into(),
                    "flow-instance:start".into(),
                    "deployment-profile:view".into(),
                    "deployment-profile:create".into(),
                    "deployment-profile:edit".into(),
                    "api-key:view".into(),
                    "api-key:create".into(),
                    "api-key:revoke".into(),
                    "organization:view".into(),
                    "audit:view".into(),
                    "policy-set:view".into(),
                    "notification:view".into(),
                ]),
                is_owner: false,
            }))
        }
    }

    struct NoOwner;

    #[async_trait]
    impl ResourceOwnerProvider for NoOwner {
        async fn resolve_organization(
            &self,
            _: &str,
            path: &str,
            _: &ResourceOwnerContext,
        ) -> Result<Option<String>, SecurityError> {
            Ok((path.starts_with("/v1/presentation-policies/")
                || path.starts_with("/v1/credential-templates/"))
            .then(|| "org-1".into()))
        }
    }

    #[async_trait]
    impl ReadinessProvider for NoOwner {
        async fn check_services(
            &self,
            services: &[String],
        ) -> BTreeMap<String, ReadinessServiceStatus> {
            services
                .iter()
                .map(|service| {
                    (
                        service.clone(),
                        ReadinessServiceStatus {
                            status: "healthy".into(),
                            url: Some(format!("http://{service}")),
                            status_code: Some(200),
                            error: None,
                        },
                    )
                })
                .collect()
        }

        fn all_services(&self) -> Vec<String> {
            vec!["auth".into()]
        }
    }

    #[async_trait]
    impl EventStreamProvider for NoOwner {
        async fn subscribe(
            &self,
            subscription: EventStreamSubscription,
        ) -> Result<GatewayDomainEventStream, SecurityError> {
            assert_eq!(subscription.organization_id, "org-1");
            assert_eq!(subscription.event_types, vec!["application.approved"]);
            Ok(Box::pin(tokio_stream::iter([
                Ok(GatewayDomainEvent {
                    event_id: "event-other".into(),
                    event_type: "application.approved".into(),
                    aggregate_id: "application-other".into(),
                    aggregate_type: "application".into(),
                    organization_id: "org-other".into(),
                    data: BTreeMap::from([("application_id".into(), "application-other".into())]),
                    timestamp: "2026-08-06T11:59:00Z".into(),
                }),
                Ok(GatewayDomainEvent {
                    event_id: "event-1".into(),
                    event_type: "application.approved".into(),
                    aggregate_id: "application-1".into(),
                    aggregate_type: "application".into(),
                    organization_id: "org-1".into(),
                    data: BTreeMap::from([("application_id".into(), "application-1".into())]),
                    timestamp: "2026-08-06T12:00:00Z".into(),
                }),
            ])))
        }
    }

    struct SuccessfulUpstream;

    #[async_trait]
    impl UpstreamClient for SuccessfulUpstream {
        async fn send(
            &self,
            instance: &ServiceInstance,
            request: GatewayRequest,
        ) -> Result<GatewayResponse, PlatformError> {
            if request.path.starts_with("/internal/") {
                let expected = match instance.service_name.as_str() {
                    "signing-keys" => Some("internal-signing-key"),
                    "issuance" => Some("issuance-service-key"),
                    "organizations" => None,
                    service => panic!("unexpected internal request to {service}"),
                };
                if let Some(expected) = expected {
                    assert_eq!(request.header("x-api-key"), Some(expected));
                }
            }
            if request.path == "/v1/issuance/token" {
                assert_eq!(instance.service_name, "issuance");
                assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
            }
            if matches!(
                request.path.as_str(),
                "/v1/issuance/transactions" | "/v1/issued-credentials/credential-1"
            ) {
                assert_eq!(instance.service_name, "issuance");
                assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
            }
            if request.path == "/v1/issuance/didcomm/deliver" {
                assert_eq!(instance.service_name, "issuance");
                assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                let body: Value =
                    serde_json::from_slice(request.body.as_deref().expect("DIDComm delivery body"))
                        .expect("DIDComm delivery JSON");
                assert_eq!(body["organization_id"], "org-1");
                assert!(body.get("universal_resolver_url").is_none());
            }
            if request.path == "/v1/integrations/canvas/lti/jwks" {
                assert_eq!(instance.service_name, "issuance");
                assert_eq!(request.header("x-api-key"), None);
            }
            if request.path == "/v1/organizations/11111111-1111-1111-1111-111111111111/roles" {
                assert_eq!(instance.service_name, "organizations");
                assert_eq!(
                    request.query.get("organization_id"),
                    Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
                );
            }
            if request.path == "/v1/organizations/org%2D1/api-keys" {
                assert_eq!(instance.service_name, "organizations");
                assert_eq!(request.header("x-user-id"), Some("user-1"));
                assert_eq!(request.header("x-organization-id"), Some("org-1"));
            }
            let body = match request.path.as_str() {
                path if path.contains("presentation-policies") && path.ends_with("/evaluate") => {
                    br#"{"decision":"allow","result":"passed"}"#.to_vec()
                }
                "/v1/compliance-profiles/system/discoverable" => serde_json::to_vec(&json!({
                    "items": [{
                        "compliance_code": "OPEN_BADGES_3",
                        "credential_format": "VC_JWT",
                        "api_surface": []
                    }]
                }))
                .expect("profiles"),
                "/v1/compliance-profiles/profile%2D1" => {
                    br#"{"id":"profile-1","organization_id":"org-1"}"#.to_vec()
                }
                path if path.starts_with("/.well-known/openid-credential-issuer") => {
                    serde_json::to_vec(&json!({
                        "credential_issuer": "https://issuer.example/org/org-1",
                        "issuer_display_name": "Example University",
                        "credential_configurations_supported": {
                            "EmployeeCredential": {
                                "format": "jwt_vc_json",
                                "credential_definition": {
                                    "type": ["VerifiableCredential", "EmployeeCredential"],
                                    "credentialSubject": {"email": {"mandatory": true}}
                                },
                                "credential_signing_alg_values_supported": ["ES256"]
                            }
                        }
                    }))
                    .expect("issuer metadata")
                }
                "/credentials/default" => serde_json::to_vec(&json!({
                    "vct": "https://issuer.example/credentials/default"
                }))
                .expect("type metadata"),
                "/internal/documents/did-web/acme" => br#"{"organization_id":"org-acme"}"#.to_vec(),
                "/internal/documents/org%2Dacme/did/load" => {
                    let request: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID load body"))
                            .expect("DID load request");
                    let did = request["fallback_did"].as_str().expect("fallback DID");
                    serde_json::to_vec(&json!({
                        "document": {
                            "id": did,
                            "controller": did,
                            "verificationMethod": [{
                                "id": format!("{did}#key-1"),
                                "controller": did,
                                "type": "JsonWebKey2020"
                            }],
                            "assertionMethod": [format!("{did}#key-1")]
                        },
                        "found": true
                    }))
                    .expect("DID document")
                }
                "/internal/documents/org%2Droot/did/load" => {
                    let request: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID load body"))
                            .expect("DID load request");
                    let did = request["fallback_did"].as_str().expect("fallback DID");
                    serde_json::to_vec(&json!({
                        "document": {
                            "id": did,
                            "controller": did,
                            "verificationMethod": [],
                            "assertionMethod": []
                        },
                        "found": true
                    }))
                    .expect("root DID document")
                }
                "/internal/profiles/org%2D1" => serde_json::to_vec(&json!({
                    "profiles": [{"id": "profile-1", "organization_id": "org-1"}]
                }))
                .expect("profiles"),
                "/internal/profiles/org%2D1/profile%2D1" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({
                        "profile": {"id": "profile-1", "organization_id": "org-1"}
                    }))
                    .expect("profile")
                }
                "/internal/profiles/org%2D1/profile%2D1"
                    if request.method == HttpMethod::Delete =>
                {
                    br#"{"deleted":"profile-1"}"#.to_vec()
                }
                "/internal/flow-key-envelopes/wrap" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow envelope body"),
                    )
                    .expect("flow envelope JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    br#"{"schema":"marty.flow-key-envelope/v1","flow_instance_id":"flow-1","ciphertext":"vault:v1:test"}"#.to_vec()
                }
                "/internal/flow-key-envelopes/unwrap" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow envelope body"),
                    )
                    .expect("flow envelope JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    br#"{"schema":"marty.flow-key-envelope/v1","flow_instance_id":"flow-1","plaintext_b64":"cHJpdmF0ZS1qd2s"}"#.to_vec()
                }
                "/internal/compat/issuer-context" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("issuer context body"),
                    )
                    .expect("issuer context JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "organization_id": "org-1",
                        "issuer_profile_id": "profile-1",
                        "issuer_mode": "org_managed",
                        "issuer_did": "did:web:issuer.example",
                        "signing_service_id": "service-1",
                        "signing_key_reference": "issuer-key",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "key_purpose": "vc_jwt_issuer",
                        "issuer_x5c": [],
                        "issuer_profile": {"id": "profile-1"},
                        "service": {"id": "service-1"}
                    }))
                    .expect("issuer context response")
                }
                "/internal/compat/resolve-issuer-did" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("issuer DID body"))
                            .expect("issuer DID JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    assert_eq!(body["key_purpose"], "vc_jwt_issuer");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "organization_id": "org-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "key_purpose": "vc_jwt_issuer",
                        "algorithm": "ES256",
                        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
                    }))
                    .expect("issuer DID response")
                }
                "/internal/compat/issuer-profiles/profile%2D1/identity" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("profile identity body"),
                    )
                    .expect("profile identity JSON");
                    assert_eq!(body, json!({"organization_id": "org-1"}));
                    serde_json::to_vec(&json!({
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"},
                        "did_document": {"id": "did:web:issuer.example"},
                        "key_purpose": "vc_jwt_issuer",
                        "algorithm": "ES256"
                    }))
                    .expect("profile identity response")
                }
                "/internal/compat/issuer-profiles/profile%2D1/public-identity" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("public identity body"),
                    )
                    .expect("public identity JSON");
                    assert_eq!(body, json!({"organization_id": "org-1"}));
                    serde_json::to_vec(&json!({
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"},
                        "algorithm": "ES256",
                        "x5c": ["leaf", "root"],
                        "certificate_expires_at": "2027-01-01T00:00:00Z"
                    }))
                    .expect("public identity response")
                }
                "/internal/compat/services/service%2D1/sign" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("service sign body"))
                            .expect("service sign JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["payload_b64"], "cGF5bG9hZA");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "service_id": "service-1",
                        "algorithm": "ES256",
                        "payload_length": 7,
                        "signature_encoding": "der",
                        "signature_b64": "c2lnbmF0dXJl",
                        "signature_hex": "7369676e6174757265",
                        "signed_at": "2026-08-20T00:00:00+00:00"
                    }))
                    .expect("service sign response")
                }
                "/internal/compat/issuer-dids/sign" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID sign body"))
                            .expect("DID sign JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "algorithm": "ES256",
                        "payload_length": 7,
                        "signature_encoding": "der",
                        "signature_b64": "c2lnbmF0dXJl",
                        "signature_hex": "7369676e6174757265",
                        "signed_at": "2026-08-20T00:00:00+00:00",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"}
                    }))
                    .expect("DID sign response")
                }
                "/internal/compat/issuer-profiles" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("create profile body"),
                    )
                    .expect("create profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "profile": {"id": "profile-1", "issuer_did": "did:web:issuer.example"},
                        "created": true
                    }))
                    .expect("create profile response")
                }
                "/internal/compat/issuer-profiles/profile%2D1" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("update profile body"),
                    )
                    .expect("update profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["status"], "active");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "profile": {"id": "profile-1", "status": "active"}
                    }))
                    .expect("update profile response")
                }
                "/internal/compat/issuer-profiles/profile%2D1/certificate" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("certificate body"))
                            .expect("certificate JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["cert_pem"], "certificate");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "certificate_chain_length": 2,
                        "certificate_expires_at": "2027-01-01T00:00:00Z"
                    }))
                    .expect("certificate response")
                }
                "/v1/credential-templates/template%2D1" => {
                    if request.method == HttpMethod::Patch {
                        let body: Value =
                            serde_json::from_slice(request.body.as_deref().expect("template body"))
                                .expect("template JSON");
                        assert_eq!(body["claims"][0]["mdoc_namespace"], "org.iso.18013.5.1");
                        assert_eq!(body["claims"][0]["mdoc_element_identifier"], "birth_date");
                    }
                    serde_json::to_vec(&json!({
                        "id": "template-1", "organization_id": "org-1", "name": "employee",
                        "description": null, "status": "draft", "credential_type": "EmployeeCredential",
                        "compliance_profile_id": "profile-1", "vct": "EmployeeCredential", "doctype": null,
                        "claims": [{"name":"birth_date","claim_type":"date","display_name":"Date of birth","mdoc_namespace":"org.iso.18013.5.1","mdoc_element_identifier":"birth_date","derivable":true}],
                        "validity_rules": {}, "issuer_did": "did:web:issuer.example",
                        "credential_payload_format": "w3c_vcdm_v2_di", "privacy_posture": null,
                        "created_at": "2026-08-01T00:00:00Z", "updated_at": null,
                        "issuer_profile_id": "must-not-leak"
                    })).expect("credential template")
                }
                "/v1/credential-templates/template%2Ddtc" => serde_json::to_vec(&json!({
                    "id":"template-dtc", "organization_id":"org-1",
                    "credential_payload_format":"MDOC"
                }))
                .expect("authoritative template"),
                "/v1/credential-templates" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("template create body"),
                    )
                    .expect("template create JSON");
                    assert_eq!(body["claims"][0]["mdoc_namespace"], "org.iso.18013.5.1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "id":"template-1","organization_id":"org-1","name":"employee",
                        "description":null,"status":"draft","credential_type":"EmployeeCredential",
                        "compliance_profile_id":"profile-1","vct":"EmployeeCredential","doctype":null,
                        "claims":body["claims"],"validity_rules":{},"issuer_did":"did:web:issuer.example",
                        "privacy_posture":null,"created_at":"2026-08-01T00:00:00Z","updated_at":null,
                        "issuer_profile_id":"must-not-leak"
                    })).expect("template create response")
                }
                "/v1/credential-templates" if request.method == HttpMethod::Get => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["org-1".into()])
                    );
                    serde_json::to_vec(&json!([{
                        "id":"template-1", "status":"ACTIVE",
                        "issuer_did":"did:web:issuer.example:orgs:org-1"
                    }]))
                    .expect("template list")
                }
                "/v1/organizations/org%2D1/api-keys" => b"[]".to_vec(),
                "/v1/organizations/11111111%2D1111%2D1111%2D1111%2D111111111111/policy-sets" => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
                    );
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    b"[]".to_vec()
                }
                "/v1/organizations/audit/events" => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
                    );
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    br#"{"events":[],"total":0,"page":1,"per_page":5}"#.to_vec()
                }
                "/v1/organizations" => {
                    if request.method == HttpMethod::Get && request.query.contains_key("limit") {
                        return Ok(GatewayResponse {
                            status_code: 200,
                            headers: BTreeMap::from([(
                                "content-type".into(),
                                "application/json".into(),
                            )]),
                            body: Some(br#"[{"id":"org-1"}]"#.to_vec()),
                            response_time_ms: None,
                            upstream_service: None,
                        });
                    }
                    if request.method == HttpMethod::Post {
                        let body: Value = serde_json::from_slice(
                            request.body.as_deref().expect("organization body"),
                        )
                        .expect("organization JSON");
                        assert_eq!(body["org_type"], "healthcare");
                        assert_eq!(body["description"], Value::Null);
                        assert!(body.get("settings").is_none());
                    }
                    let organization = json!({
                        "id":"20000000-0000-4000-8000-000000000001",
                        "name":"example-issuer", "display_name":"Example Issuer",
                        "description":"Example tenant", "join_code":null,
                        "visibility":"PUBLIC", "owner_id":"owner-subject",
                        "status":"active", "org_type":"healthcare",
                        "join_mechanism":"open", "requires_approval":true,
                        "is_discoverable":true, "contact_email":"operator@example.com",
                        "contact_phone":null, "website":"https://example.com",
                        "membership":null, "created_at":"2026-07-31T00:00:00Z",
                        "updated_at":"2026-07-31T00:00:00Z"
                    });
                    let output = if request.method == HttpMethod::Get {
                        json!([organization])
                    } else {
                        organization
                    };
                    serde_json::to_vec(&output).expect("organization response")
                }
                "/v1/issuer-entities" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("issuer entity body"),
                    )
                    .expect("issuer entity JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_type"], "ORGANIZATION");
                    assert_eq!(body["accreditations"], json!(["ISO27001"]));
                    assert_eq!(body["metadata"], json!({}));
                    serde_json::to_vec(&json!({
                        "id":"10000000-0000-4000-8000-000000000001",
                        "organization_id":"org-1", "issuer_id":"did:web:issuer.example",
                        "issuer_type":"ORGANIZATION", "display_name":"Example Issuer",
                        "description":null, "is_system_issuer":false,
                        "compliance_status":"COMPLIANT", "accreditation_body":null,
                        "accreditations":["ISO27001"], "accreditation_date":null,
                        "valid_from":"2026-08-01T00:00:00Z", "valid_until":null,
                        "trust_anchor_id":null, "revoked_at":null, "revocation_reason":null,
                        "revoked_by":null, "metadata":{"jurisdiction":"US"},
                        "created_at":"2026-08-01T00:00:00Z",
                        "updated_at":"2026-08-01T00:00:00Z"
                    }))
                    .expect("issuer entity response")
                }
                "/v1/trust-profiles" if request.method == HttpMethod::Post => {
                    assert_eq!(request.header("content-length"), None);
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("trust profile body"),
                    )
                    .expect("trust profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["profile_type"], "CUSTOM");
                    assert_eq!(body["trust_sources"][0]["source_type"], "TRUST_LIST");
                    assert_eq!(body["revocation_policy"]["check_mode"], "HARD_FAIL");
                    serde_json::to_vec(&json!({
                        "id":"40000000-0000-4000-8000-000000000001",
                        "organization_id":"org-1", "name":"Registry profile",
                        "description":null, "status":"draft", "profile_type":"CUSTOM",
                        "compliance_status":"SETUP_REQUIRED", "trust_sources":body["trust_sources"],
                        "allowed_algorithms":["ES256"], "revocation_policy":null,
                        "revocation_services":null, "revocation_profile_id":null,
                        "time_policy":body["time_policy"], "supported_formats":["SD_JWT_VC","MDOC"],
                        "allowed_issuers":null, "denied_issuers":null,
                        "verification_policy_set_id":null, "created_at":"2026-08-07T00:00:00Z",
                        "updated_at":null
                    }))
                    .expect("trust profile response")
                }
                "/v1/trust-profiles/trust%2D1" => {
                    br#"{"id":"trust-1","organization_id":"org-1"}"#.to_vec()
                }
                "/v1/presentation-policies" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({"policies":[{"id":"policy-1","status":"active"}]}))
                        .expect("policy list")
                }
                "/v1/deployment-profiles" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(
                        &json!({"deployment_profiles":[{"id":"deployment-1","status":"ready"}]}),
                    )
                    .expect("deployment list")
                }
                "/v1/deployment-profiles" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("deployment profile body"),
                    )
                    .expect("deployment profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["environment"], "development");
                    assert_eq!(body["network_mode"], "ONLINE");
                    assert!(body.get("private_runtime_config").is_none());
                    serde_json::to_vec(&json!({
                        "id":"deployment-1", "organization_id":"org-1",
                        "name":"Campus runtime", "status":"active",
                        "default_policy_id":"policy-1",
                        "presentation_policy_ids":[],
                        "credential_template_ids":["template-1"],
                        "created_at":"2026-08-01T00:00:00Z",
                        "updated_at":"2026-08-01T00:00:00Z",
                        "api_key":"must-not-leak"
                    }))
                    .expect("deployment profile response")
                }
                "/v1/flows/definitions" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({"definitions":[{
                        "id":"flow-1", "status":"ACTIVE",
                        "credential_template_id":"template-1"
                    }]}))
                    .expect("flow list")
                }
                "/v1/organizations/org%2D1/applicants" => {
                    assert_eq!(request.query.get("limit"), Some(&vec!["500".into()]));
                    serde_json::to_vec(&json!({"items":[
                        {"status":"SUBMITTED"}, {"status":"APPROVED"},
                        {"status":"OFFERED"}
                    ]}))
                    .expect("applicant list")
                }
                "/v1/organizations/org%2D1/lifecycle"
                | "/internal/v1/organizations/org%2D1/lifecycle" => {
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    serde_json::to_vec(&json!({
                        "created_at":"2026-04-01T00:00:00Z",
                        "audit_retention_days":30,
                        "pilot_retention":{"enabled":true,"window_days":30}
                    }))
                    .expect("lifecycle")
                }
                "/v1/issuance/organizations/org%2D1/retention" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    assert_eq!(
                        request.query.get("retention_days"),
                        Some(&vec!["30".into()])
                    );
                    serde_json::to_vec(&json!({
                        "cutoff_at":"2026-03-01T00:00:00Z",
                        "next_expiry_at":"2026-04-01T00:00:00Z",
                        "oldest_retained_record_at":"2026-03-02T00:00:00Z",
                        "eligible_for_purge":{"total":2},
                        "tracked_scope":["applications"]
                    }))
                    .expect("retention summary")
                }
                "/v1/issuance/organizations/org%2D1/retention/purge" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    serde_json::to_vec(&json!({
                        "organization_id":"org-1", "retention_days":30,
                        "cutoff_at":"2026-03-01T00:00:00Z",
                        "purged_at":"2026-04-13T12:00:00Z",
                        "purged_records":{"total":2},
                        "tracked_scope":["applications"],
                        "deletion_token":"must-not-leak"
                    }))
                    .expect("purge")
                }
                "/internal/v1/organizations/org%2D1/settings" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("settings patch body"),
                    )
                    .expect("settings patch JSON");
                    assert_eq!(
                        body["settings_patch"]["pilot_retention_last_purged_at"],
                        "2026-04-13T12:00:00Z"
                    );
                    br#"{"ok":true}"#.to_vec()
                }
                "/v1/flows/verify" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("verification flow body"),
                    )
                    .expect("verification flow JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:verifier.example");
                    assert_eq!(body["response_type"], "vp_token");
                    assert_eq!(body["expiry_minutes"], 15);
                    serde_json::to_vec(&json!({
                        "instance_id":"instance-1", "flow_definition_id":"internal-definition",
                        "request_uri":"openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
                        "qr_code_data":"openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
                        "presentation_policy_id":"policy-1", "nonce":"nonce-value",
                        "expires_at":"2026-07-30T20:00:00Z", "status":"AWAITING_WALLET",
                        "issuer_profile_id":"must-not-leak"
                    }))
                    .expect("verification flow response")
                }
                "/v1/flows/definitions" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow definition body"),
                    )
                    .expect("flow definition JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["credential_template_id"], "template-1");
                    assert_eq!(body["approval_strategy"], "AUTO");
                    serde_json::to_vec(&json!({
                        "id":"flow-1","organization_id":"org-1","name":"Issue employee",
                        "description":null,"status":"DRAFT","flow_type":"oid4vci_pre_authorized",
                        "flow_category":"ISSUANCE","resolved_steps":["prepare","issue"],
                        "extension":null,"trust_profile_id":null,
                        "credential_template_id":"template-1","application_template_id":null,
                        "presentation_policy_id":null,"delivery_destination_profile_id":null,
                        "approval_strategy":"AUTO","hooks":{},"trigger":null,
                        "deployment_profile_ids":[],"version":1,
                        "created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-01T00:00:00Z",
                        "private_execution_plan":{"key_reference":"private"}
                    }))
                    .expect("flow definition response")
                }
                "/v1/flows/instances" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow instance body"),
                    )
                    .expect("flow instance JSON");
                    assert_eq!(body["subject_type"], "applicant");
                    assert!(body["initial_context"].get("access_token").is_none());
                    serde_json::to_vec(&json!({
                        "id":"instance-1","flow_id":"flow-1",
                        "flow_type":"oid4vci_pre_authorized","organization_id":"org-1",
                        "status":"PENDING","current_step":null,"current_step_index":null,
                        "context_data":body["initial_context"],"step_results":{},
                        "issued_credential_id":null,"started_at":null,"completed_at":null,
                        "expires_at":null,"error_code":null,"metadata":{},"state_history":[],
                        "created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-01T00:00:00Z",
                        "private_runtime":"must-not-leak"
                    }))
                    .expect("flow instance response")
                }
                "/v1/presentation-policies" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("presentation policy body"),
                    )
                    .expect("presentation policy JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(
                        body["credential_requirements"][0]["credential_payload_format"],
                        "MDOC"
                    );
                    serde_json::to_vec(&json!({
                        "id":"policy-1", "organization_id":"org-1", "name":"Verify DTC",
                        "status":"draft", "description":null, "purpose":null,
                        "required_claims":[], "accepted_credential_types":[],
                        "trust_profile_id":null, "display_metadata":null,
                        "credential_requirements":body["credential_requirements"],
                        "alternative_requirements":[], "compliance_profile_id":null,
                        "holder_binding":{"required":false}, "issuer_constraints":null,
                        "freshness":null, "prefer_predicates":false, "fallback_policy":null,
                        "supported_circuits":[], "credential_ranking_strategy":"FRESHEST_FIRST",
                        "credential_ranking_weights":null, "version":1,
                        "created_at":"2026-07-30T00:00:00Z",
                        "updated_at":"2026-07-30T00:00:00Z",
                        "issuer_profile_id":"must-not-leak"
                    }))
                    .expect("presentation policy response")
                }
                "/v1/issuance/initiate" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("issuance body"))
                            .expect("issuance JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    assert!(body.get("issuer_profile_id").is_none());
                    let offer = json!({
                        "credential_issuer": "https://issuer.example/org/org-1",
                        "credential_configuration_ids": ["EmployeeCredential#ldp-vc"],
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": "pre-auth-1"
                            }
                        }
                    });
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("credential_offer", &offer.to_string())
                        .finish();
                    serde_json::to_vec(&json!({
                        "id": "iss-1",
                        "organization_id": "org-1",
                        "credential_template_id": "template-1",
                        "status": "pending",
                        "credential_offer_uri": format!("openid-credential-offer://?{query}")
                        ,"credential_offer_uris": {},
                        "credential_offer_labels": {},
                        "expires_at": "2026-09-01T00:00:00Z",
                        "pre_auth_code": "must-not-leak"
                    }))
                    .expect("offer")
                }
                "/v1/issuance/token" => br#"{"access_token":"access-token"}"#.to_vec(),
                "/v1/issuance/didcomm/deliver" => serde_json::to_vec(&json!({
                    "transaction_id":"tx-123", "credential_id":"credential-123",
                    "holder_did":"did:peer:2.EzExample",
                    "service_endpoint":"https://holder.example/didcomm",
                    "didcomm_message_id":"message-123", "status":"delivered",
                    "error":null, "provider_delivery_receipt":"must-not-leak"
                }))
                .expect("DIDComm delivery response"),
                "/v1/issuance/transactions" => serde_json::to_vec(&json!([{
                    "id": "iss-1",
                    "organization_id": "org-1",
                    "credential_template_id": "template-1",
                    "status": "issued",
                    "created_at": "2026-08-01T00:00:00Z",
                    "pre_auth_code": "must-not-leak"
                }]))
                .expect("issuance transactions"),
                "/v1/issued-credentials/credential-1" => serde_json::to_vec(&json!({
                    "id": "credential-1",
                    "organization_id": "org-1",
                    "credential_id": "credential-1",
                    "credential_type": "EmployeeCredential",
                    "credential_format": "SD_JWT_VC",
                    "flow_execution_id": "iss-1",
                    "credential_template_id": "template-1",
                    "subject_id": "did:example:holder",
                    "issued_at": "2026-08-01T00:00:00Z",
                    "status": "ACTIVE",
                    "status_list_entries": [],
                    "created_at": "2026-08-01T00:00:00Z",
                    "deliveries": [{"external_credential_id": "must-not-leak"}]
                }))
                .expect("issued credential"),
                "/v1/issuance/nonce" => br#"{"c_nonce":"nonce-1"}"#.to_vec(),
                "/v1/issuance/credential" => serde_json::to_vec(&json!({
                    "credentials": [{
                        "format": "ldp_vc",
                        "credential": {
                            "@context": ["https://www.w3.org/ns/credentials/v2"],
                            "type": ["VerifiableCredential"],
                            "issuer": "did:web:issuer.example",
                            "credentialSubject": {"id": "did:example:subject"},
                            "proof": {
                                "type": "DataIntegrityProof",
                                "cryptosuite": "eddsa-rdfc-2022"
                            }
                        }
                    }]
                }))
                .expect("credential"),
                _ => br#"{"ok":true}"#.to_vec(),
            };
            Ok(GatewayResponse {
                status_code: 200,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body: Some(body),
                response_time_ms: None,
                upstream_service: None,
            })
        }
    }

    fn runtime_router() -> Router {
        gateway_router(runtime_state())
    }

    fn runtime_state() -> Arc<GatewayRuntimeState> {
        runtime_state_with_events(Arc::new(NoOwner))
    }

    fn runtime_state_with_events(
        event_streams: Arc<dyn EventStreamProvider>,
    ) -> Arc<GatewayRuntimeState> {
        let routes = GatewayContract::load()
            .expect("contract")
            .route_table()
            .expect("routes");
        let proxy_routes = GatewayContract::load()
            .expect("contract")
            .proxy_route_table()
            .expect("proxy routes");
        let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
            ("auth".into(), "http://auth:8001".into()),
            ("applicant".into(), "http://applicant:8000".into()),
            (
                "compliance-profiles".into(),
                "http://compliance-profiles:8080".into(),
            ),
            (
                "credential-templates".into(),
                "http://credential-templates:8000".into(),
            ),
            ("flows".into(), "http://flows:8000".into()),
            (
                "deployment-profiles".into(),
                "http://deployment-profiles:8000".into(),
            ),
            ("issuance".into(), "http://issuance:8000".into()),
            ("organizations".into(), "http://organizations:8000".into()),
            (
                "presentation-policies".into(),
                "http://presentation-policies:8080".into(),
            ),
            ("signing-keys".into(), "http://signing-keys:8080".into()),
            ("trust-profiles".into(), "http://trust-profiles:8000".into()),
            (
                "revocation-profiles".into(),
                "http://revocation-profiles:8000".into(),
            ),
        ]))
        .expect("registry");
        let proxy = GatewayProxy::new(
            proxy_routes,
            Arc::new(registry),
            Arc::new(SuccessfulUpstream),
            ProxyConfig::default(),
        )
        .expect("proxy");
        let state = GatewayRuntimeState::new(
            routes,
            proxy,
            Arc::new(RuntimeProvider),
            Arc::new(RuntimeProvider),
            Arc::new(NoOwner),
            Arc::new(NoOwner),
            event_streams,
            vec!["auth".into()],
            GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120)
                .expect("rate limiter"),
            Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).expect("idempotency")),
            ["https://beta.elevenidllc.com".into()],
            "https://issuer.example",
            "https://issuer.example",
            "issuer.example:8443",
            Some("org-root".into()),
            "internal-signing-key",
            "issuance-service-key",
            ReleaseIdentity::default(),
        )
        .expect("runtime state")
        .with_service_token(Some("s".repeat(32)))
        .expect("service token");
        Arc::new(state)
    }

    #[test]
    fn service_authenticated_proxies_receive_only_gateway_configured_credentials() {
        let state = runtime_state();
        let identity = TrustedIdentityContext::default();
        for path in [
            "/v1/organizations/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "/v1/credential-templates",
            "/v1/trust-profiles",
            "/v1/presentation-policies",
        ] {
            let overrides = proxy_overrides(&state, path, &identity);
            assert_eq!(overrides.headers["x-service-token"], "s".repeat(32));
        }
        let applicant = proxy_overrides(&state, "/v1/applicants", &identity);
        assert!(!applicant.headers.contains_key("x-service-token"));
    }

    #[test]
    fn legacy_api_key_routes_are_bound_to_the_authenticated_organization() {
        assert_eq!(
            compatibility_upstream_path("/v1/api-keys", Some("org-1")).expect("list path"),
            "/v1/organizations/org%2D1/api-keys"
        );
        assert_eq!(
            compatibility_upstream_path("/v1/api-keys/key-1", Some("org-1")).expect("key path"),
            "/v1/organizations/org%2D1/api-keys/key-1"
        );
        assert!(compatibility_upstream_path("/v1/api-keys", None).is_err());
        assert!(compatibility_upstream_path("/v1/api-keys/a/b", Some("org-1")).is_err());
    }

    #[test]
    fn console_compatibility_paths_preserve_the_authorized_tenant() {
        let organization_id = "66955e44-28fd-431e-a4e1-4c2579a66e66";
        assert_eq!(
            compatibility_upstream_path("/v1/policy-sets", Some(organization_id))
                .expect("policy list"),
            "/__gateway/composition/organizations/v1/organizations/66955e44%2D28fd%2D431e%2Da4e1%2D4c2579a66e66/policy-sets"
        );
        assert_eq!(
            compatibility_upstream_path(
                &format!("/v1/organizations/{organization_id}/audit-events"),
                Some(organization_id),
            )
            .expect("audit list"),
            "/__gateway/composition/organizations/v1/organizations/audit/events"
        );
        assert_eq!(
            compatibility_upstream_path(
                &format!("/v1/organizations/{organization_id}/audit-events/export"),
                Some(organization_id),
            )
            .expect("audit export"),
            "/__gateway/composition/organizations/v1/organizations/audit/events/export"
        );
        assert!(matches!(
            compatibility_upstream_path(
                &format!("/v1/organizations/{organization_id}/audit-events"),
                Some("67e9df9d-a3c1-4ada-a2d7-0789992097a2"),
            ),
            Err((403, _))
        ));
    }

    #[test]
    fn legacy_api_key_routes_prefer_the_tenant_authorized_organization() {
        let trusted_identity = TrustedIdentityContext {
            organization_id: Some("authorized-org".into()),
            ..TrustedIdentityContext::default()
        };
        let session_identity = GatewayIdentity {
            source: AuthenticationSource::Session,
            user_id: "user-1".into(),
            user_email: None,
            user_domain: None,
            session_organization_id: Some("stale-session-org".into()),
            api_key_id: None,
            api_key_prefix: None,
            api_key_scopes: Vec::new(),
        };

        assert_eq!(
            api_key_organization_id(
                &trusted_identity,
                session_identity.session_organization_id.as_deref(),
            )
            .as_deref(),
            Some("authorized-org")
        );
        assert_eq!(
            api_key_organization_id(
                &TrustedIdentityContext::default(),
                session_identity.session_organization_id.as_deref(),
            )
            .as_deref(),
            Some("stale-session-org")
        );
    }

    #[tokio::test]
    async fn legacy_api_key_routes_accept_an_authorized_query_organization_without_session_scope() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/api-keys?organization_id=org-1")
                    .header("cookie", "sessionId=valid-no-org")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    #[tokio::test]
    async fn console_policy_and_audit_compatibility_routes_reach_canonical_rust_upstreams() {
        let organization_id = "11111111-1111-1111-1111-111111111111";
        for uri in [
            format!("/v1/policy-sets?organization_id={organization_id}"),
            format!("/v1/organizations/{organization_id}/audit-events?limit=5"),
        ] {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("cookie", "sessionId=valid-uuid")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = response.status();
            let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body");
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        }
    }

    #[tokio::test]
    async fn organization_composition_uses_membership_authorized_tenant_over_stale_session_scope() {
        let organization_id = "11111111-1111-1111-1111-111111111111";
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/organizations/{organization_id}/integration-info"
                    ))
                    // This session names org-1, but RuntimeProvider confirms an
                    // active membership in the organization selected by path.
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("integration info");
        assert_eq!(body["org_id"], organization_id);
    }

    #[test]
    fn signing_proxy_overrides_untrusted_tenant_query_with_session_scope() {
        let state = runtime_state();
        let identity = TrustedIdentityContext {
            organization_id: Some("trusted-org".into()),
            ..TrustedIdentityContext::default()
        };
        let overrides = proxy_overrides(&state, "/v1/signing-keys/issuer-identities", &identity);
        assert_eq!(
            overrides.trusted_query["organization_id"],
            vec!["trusted-org"]
        );
    }

    #[tokio::test]
    async fn axum_chain_preserves_outer_auth_and_content_type_order() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/signing-keys?organization_id=org-1")
                    .header("content-type", "text/plain")
                    .body(Body::from("invalid"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["x-mip-version"], MIP_VERSION);

        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/signing-keys?organization_id=org-1")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "text/plain")
                    .body(Body::from("invalid"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn public_proxy_response_runs_rate_etag_cors_and_mip_stages() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/auth/session/validate")
                    .header("origin", "https://beta.elevenidllc.com")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-mip-version"], MIP_VERSION);
        assert_eq!(response.headers()["x-ratelimit-limit"], "120");
        assert!(response.headers().contains_key("etag"));
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://beta.elevenidllc.com"
        );
    }

    #[tokio::test]
    async fn proxy_enforces_service_credentials_and_special_rewrites() {
        let token = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuance/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(token.status(), StatusCode::OK);

        let jwks = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/integrations/canvas/lti/jwks")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(jwks.status(), StatusCode::OK);

        let evidence = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/organizations/org-1/applicants/app-1/evidence-summary")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(evidence.status(), StatusCode::OK);

        let lifecycle = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/organizations/org-1/lifecycle")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(lifecycle.status(), StatusCode::OK);

        let retired = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/integrations/canvas/lti/experience-sessions/state-1")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(retired.status(), StatusCode::GONE);
        let retired: Value = serde_json::from_slice(
            &to_bytes(retired.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(
            retired["detail"],
            "State-addressed Canvas sessions are no longer supported"
        );
    }

    #[tokio::test]
    async fn issuance_management_responses_are_rewritten_and_privacy_projected() {
        let transactions = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/issuance?organization_id=org-1")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(transactions.status(), StatusCode::OK);
        let transactions: Value = serde_json::from_slice(
            &to_bytes(transactions.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(transactions[0]["id"], "iss-1");
        assert!(transactions[0].get("pre_auth_code").is_none());

        let credential = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/issued-credentials/credential-1")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(credential.status(), StatusCode::OK);
        let credential: Value = serde_json::from_slice(
            &to_bytes(credential.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(credential["id"], "credential-1");
        assert!(credential.get("deliveries").is_none());

        let create = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuance")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "organization_id": "org-1",
                            "credential_template_id": "template-1",
                            "claims": {"employee_id": "123"}
                        }))
                        .expect("request JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let create_status = create.status();
        let create_body = to_bytes(create.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(
            create_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&create_body)
        );
        let create: Value = serde_json::from_slice(&create_body).expect("json");
        assert_eq!(create["id"], "iss-1");
        assert!(create.get("pre_auth_code").is_none());
    }

    #[tokio::test]
    async fn didcomm_delivery_is_tenant_bound_canonical_and_privacy_projected() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuance/didcomm/deliver")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "organization_id":"org-1", "transaction_id":"tx-123",
                            "holder_did":"did:peer:2.EzExample"
                        }))
                        .expect("DIDComm request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("DIDComm response");
        assert_eq!(body["status"], "delivered");
        assert!(body.get("provider_delivery_receipt").is_none());

        for (organization_id, extra, expected) in [
            ("org-other", None, StatusCode::FORBIDDEN),
            (
                "org-1",
                Some(("universal_resolver_url", "https://attacker.example")),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let mut request = json!({
                "organization_id":organization_id, "transaction_id":"tx-123",
                "holder_did":"did:peer:2.EzExample"
            });
            if let Some((key, value)) = extra {
                request[key] = Value::String(value.into());
            }
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/issuance/didcomm/deliver")
                        .header("cookie", "sessionId=valid")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&request).unwrap()))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn trusted_tenant_query_replaces_client_controlled_organization() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/organizations/11111111-1111-1111-1111-111111111111/roles?organization_id=attacker-org")
                    .header("cookie", "sessionId=valid-uuid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deployment_profile_create_preflights_and_projects_in_rust() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/deployment-profiles")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "organization_id":"org-1",
                            "name":"Campus runtime",
                            "trust_profile_id":"trust-1",
                            "default_policy_id":"policy-1",
                            "credential_template_ids":["template-1"]
                        }))
                        .expect("deployment request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("deployment response");
        assert_eq!(body["id"], "deployment-1");
        assert!(body.get("api_key").is_none());
        assert_eq!(body["canvas_feature_flags"], json!({}));
    }

    #[tokio::test]
    async fn organization_composition_routes_execute_in_rust() {
        let cases = [
            (
                "GET",
                "/v1/organizations/org-1/runtime/status",
                "can_issue",
                json!(true),
            ),
            (
                "GET",
                "/v1/organizations/org-1/dashboard/applicant-stats",
                "issuable",
                json!(2),
            ),
            (
                "GET",
                "/v1/organizations/org-1/lifecycle",
                "audit_retention_days",
                json!(30),
            ),
            (
                "GET",
                "/v1/organizations/org-1/integration-info",
                "base_url",
                json!("https://issuer.example/v1"),
            ),
            (
                "POST",
                "/v1/organizations/org-1/lifecycle/purge",
                "organization_id",
                json!("org-1"),
            ),
        ];
        for (method, path, field, expected) in cases {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("cookie", "sessionId=valid")
                        .header("content-type", "application/json")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = response.status();
            let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body");
            assert_eq!(
                status,
                StatusCode::OK,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
            let body: Value = serde_json::from_slice(&body).expect("composition JSON");
            assert_eq!(body[field], expected, "{path}");
            assert!(body.get("deletion_token").is_none(), "{path}");
        }
    }

    #[tokio::test]
    async fn hosted_pilot_sweep_uses_composed_lifecycle_and_purge_transaction() {
        let stats = run_hosted_pilot_auto_purge_sweep(&runtime_state(), 50).await;
        assert_eq!(
            stats,
            HostedPilotPurgeSweepStats {
                organizations_scanned: 1,
                hosted_pilot_orgs: 1,
                purge_requests: 1,
                purged_records: 2,
            }
        );
    }

    #[tokio::test]
    async fn language_neutral_sse_contract_filters_tenants_and_preserves_frames() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-sse-behavior.json"
        ))
        .expect("SSE contract");
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/notifications/events/push?{}",
                        contract["valid_query"].as_str().unwrap()
                    ))
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("SSE body");
        let expected = contract["expected_frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .unwrap()
            .join("");
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), expected);
        for query in contract["rejected_queries"].as_array().unwrap() {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/notifications/events/push?{}",
                            query.as_str().unwrap()
                        ))
                        .header("cookie", "sessionId=valid")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
        }
    }

    #[tokio::test]
    async fn dropping_sse_body_signals_backend_stream_cancellation() {
        let (sender, receiver) = mpsc::channel(1);
        let (cancel, mut cancelled) = watch::channel(false);
        let stream = DisconnectStream {
            inner: ReceiverStream::new(receiver),
            cancellation: cancel,
        };
        drop(stream);
        cancelled.changed().await.expect("cancellation signal");
        assert!(*cancelled.borrow());
        drop(sender);
    }

    struct PendingEventStream {
        dropped: Arc<AtomicBool>,
    }

    impl Stream for PendingEventStream {
        type Item = Result<GatewayDomainEvent, SecurityError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for PendingEventStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct TrackingEventProvider {
        subscribed: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    struct ErrorEventProvider;

    #[async_trait]
    impl EventStreamProvider for ErrorEventProvider {
        async fn subscribe(
            &self,
            _: EventStreamSubscription,
        ) -> Result<GatewayDomainEventStream, SecurityError> {
            Err(SecurityError::ProviderUnavailable(
                "event stream unavailable".into(),
            ))
        }
    }

    #[tokio::test]
    async fn sse_backend_failure_preserves_the_public_stream_error_frame() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-sse-behavior.json"
        ))
        .expect("SSE contract");
        let response = gateway_router(runtime_state_with_events(Arc::new(ErrorEventProvider)))
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/notifications/events/push?{}",
                        contract["valid_query"].as_str().unwrap()
                    ))
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("error stream body");
        let expected = contract["expected_error_frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .unwrap()
            .join("");
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), expected);
    }

    #[async_trait]
    impl EventStreamProvider for TrackingEventProvider {
        async fn subscribe(
            &self,
            _: EventStreamSubscription,
        ) -> Result<GatewayDomainEventStream, SecurityError> {
            self.subscribed.store(true, Ordering::SeqCst);
            Ok(Box::pin(PendingEventStream {
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    #[tokio::test]
    async fn client_disconnect_drops_the_live_backend_subscription() {
        let subscribed = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let state = runtime_state_with_events(Arc::new(TrackingEventProvider {
            subscribed: Arc::clone(&subscribed),
            dropped: Arc::clone(&dropped),
        }));
        let response = gateway_router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/notifications/events/push?organization_id=org-1")
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        for _ in 0..20 {
            if subscribed.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(subscribed.load(Ordering::SeqCst));
        drop(response);
        for _ in 0..20 {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn organization_requests_and_responses_use_strict_public_contract() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/organizations")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"name":"example-issuer","display_name":"Example Issuer","org_type":"healthcare","visibility":"PUBLIC","join_mechanism":"open","requires_approval":true}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["name"], "example-issuer");
        assert!(body.get("join_code").is_none());
        assert!(body.get("contact_phone").is_none());
    }

    #[tokio::test]
    async fn issuer_entities_use_strict_public_trust_contract() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuer-entities")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","issuer_id":"did:web:issuer.example","display_name":"Example Issuer","accreditations":[" ISO27001 "]}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(body["issuer_id"], "did:web:issuer.example");
        assert_eq!(body["accreditations"], json!(["ISO27001"]));
        assert!(body.get("description").is_none());
        assert!(body.get("trust_anchor_id").is_none());
    }

    #[tokio::test]
    async fn trust_profiles_use_canonical_policy_and_strict_public_projection() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/trust-profiles")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .header("content-length", "999")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Registry profile","trust_sources":[{"source_type":"trust_list","url":"https://registry.example/sync","registry_sync":{"protocol":"MARTY_TRUST_REGISTRY_SYNC_V1","refresh_interval_hours":24}}],"revocation_policy":{},"time_policy":{"require_freshness":true,"freshness_window_seconds":21600}}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(body["status"], "draft");
        assert_eq!(body["trust_sources"][0]["source_type"], "TRUST_LIST");
        assert_eq!(body["system_issuer_overrides"], json!({}));
        assert!(body.get("description").is_none());
        assert!(body.get("revocation_services").is_none());
    }

    #[tokio::test]
    async fn verification_flow_start_preflights_and_projects_in_rust() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/verify")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"presentation_policy_id":"policy-1","organization_id":"org-1","issuer_did":"did:web:verifier.example","request_uri_method":"post"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(body["instance_id"], "instance-1");
        assert_eq!(body["presentation_policy_id"], "policy-1");
        assert!(body.get("flow_definition_id").is_none());
        assert!(body.get("issuer_profile_id").is_none());
    }

    #[tokio::test]
    async fn presentation_policy_uses_authoritative_template_format_and_public_projection() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/presentation-policies")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Verify DTC","credential_requirements":[{"credential_template_id":"template-dtc","credential_payload_format":"caller-controlled","requested_claims":[{"claim_name":"document_number"}]}]}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            body["credential_requirements"][0]["credential_payload_format"],
            "MDOC"
        );
        assert_eq!(body["holder_binding"], json!({"required": false}));
        assert!(body.get("issuer_profile_id").is_none());
        assert!(body.get("description").is_none());
    }

    #[tokio::test]
    async fn flow_definitions_and_instances_use_rust_contracts() {
        let definition = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/definitions")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Issue employee","flow_type":"oid4vci_pre_authorized","credential_template_id":"template-1"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = definition.status();
        let body = to_bytes(definition.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let definition: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(definition["id"], "flow-1");
        assert!(definition.get("private_execution_plan").is_none());
        assert!(definition.get("description").is_none());

        let instance = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/instances")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","flow_definition_id":"flow-1","initial_context":{"application_id":"application-1"}}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = instance.status();
        let body = to_bytes(instance.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let instance: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(instance["id"], "instance-1");
        assert_eq!(instance["context_data"]["application_id"], "application-1");
        assert!(instance.get("private_runtime").is_none());
    }

    #[tokio::test]
    async fn credential_template_claims_are_canonicalized_and_privacy_projected() {
        let response = runtime_router().oneshot(
            Request::builder().method("PATCH")
                .uri("/v1/credential-templates/template%2D1?organization_id=org-1")
                .header("cookie", "sessionId=valid").header("content-type", "application/json")
                .body(Body::from(br#"{"claims":[{"name":"birth_date","claim_type":"date","required":true,"selectively_disclosable":true,"namespace":"org.iso.18013.5.1"}]}"#.as_slice())).expect("request")
        ).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["claims"][0]["type"], "DATE");
        assert_eq!(body["claims"][0]["namespace"], "org.iso.18013.5.1");
        assert!(body.get("issuer_profile_id").is_none());
        assert!(body["claims"][0].get("derivable").is_none());

        let create = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/credential-templates")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(br#"{"organization_id":"org-1","name":"employee","credential_type":"EmployeeCredential","vct":"EmployeeCredential","claims":[{"name":"birth_date","claim_type":"date","required":true,"selectively_disclosable":true,"namespace":"org.iso.18013.5.1"}],"supported_formats":["sd_jwt_vc"],"compliance_profile_id":"profile-1","issuer_did":"did:web:issuer.example"}"#.as_slice()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(create.status(), StatusCode::OK);
        let create: Value = serde_json::from_slice(
            &to_bytes(create.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(create["id"], "template-1");
        assert!(create.get("issuer_profile_id").is_none());
    }

    #[tokio::test]
    async fn vc_api_verification_handler_adapts_to_canonical_policy_service() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(
                        "/v1/vc-api/credentials/verify?organization_id=org-1&presentation_policy_id=policy-1",
                    )
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"verifiableCredential":"header.payload.signature","options":{"challenge":"n","domain":"aud"}}"#
                            .as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["verified"], true);
        assert_eq!(body["results"]["decision"], "allow");
    }

    #[tokio::test]
    async fn vc_api_issuance_handler_redeems_through_canonical_oid4vci_service() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(
                        "/v1/vc-api/credentials/issue?organization_id=org-1&credential_template_id=template-1&issuer_did=did%3Aweb%3Aissuer.example",
                    )
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"credential":{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:web:issuer.example","credentialSubject":{"id":"did:example:subject"}}}"#
                            .as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            body["verifiableCredential"]["proof"]["cryptosuite"],
            "eddsa-rdfc-2022"
        );
    }

    #[tokio::test]
    async fn credential_metadata_handler_is_public_cacheable_and_exact() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/credentials/marty-verified-member-badge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        assert!(response.headers().contains_key("etag"));
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            body["vct"],
            "https://issuer.example/credentials/marty-verified-member-badge"
        );
    }

    #[tokio::test]
    async fn discovery_and_health_handlers_are_gateway_owned_and_public() {
        let openid = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(openid.status(), StatusCode::OK);
        let openid: Value = serde_json::from_slice(
            &to_bytes(openid.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(openid["issuer"], "https://issuer.example");

        let mip = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/mip-configuration")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(mip.status(), StatusCode::OK);
        let mip: Value = serde_json::from_slice(
            &to_bytes(mip.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(
            mip["supported_compliance_profiles"],
            json!(["OPEN_BADGES_3"])
        );

        let health = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(health.status(), StatusCode::OK);

        for path in ["/ready", "/health/ready"] {
            let ready = runtime_router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(ready.status(), StatusCode::OK, "{path}");
            let ready: Value = serde_json::from_slice(
                &to_bytes(ready.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                    .await
                    .expect("body"),
            )
            .expect("json");
            assert_eq!(ready["status"], "ready");
            assert_eq!(ready["services"]["auth"]["status"], "healthy");
        }

        let services = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/health/services")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(services.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn well_known_routes_proxy_and_apply_wallet_specific_normalization() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/org/org-1/waltid/.well-known/openid-credential-issuer")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(
            body["credential_issuer"],
            "https://issuer.example/org/org-1/waltid"
        );
        assert!(body["credentials_supported"].is_array());

        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/credentials/default")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn public_did_web_routes_use_the_canonical_signing_service() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/orgs/Acme/did.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/did+json");
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("DID JSON");
        assert_eq!(body["id"], "did:web:issuer.example%3A8443:orgs:acme");

        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/did.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("root DID JSON");
        assert_eq!(body["id"], "did:web:issuer.example%3A8443");

        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/orgs/..%2F..%2Fetc/did.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn internal_profile_reads_and_deletes_use_dedicated_auth_and_rust_store() {
        let unauthorized = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-profiles?organization_id=org-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let profiles = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-profiles?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(profiles.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(profiles.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("profiles JSON");
        assert_eq!(body["profiles"][0]["id"], "profile-1");

        let deleted = runtime_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/internal/signing-keys/issuer-profiles/profile-1?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(deleted.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(deleted.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("delete JSON");
        assert_eq!(body, json!({"ok": true, "deleted": "profile-1"}));
    }

    #[tokio::test]
    async fn flow_envelope_routes_replace_client_scope_with_trusted_scope() {
        let wrapped = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(
                        "/internal/signing-keys/flow-key-envelopes/wrap?organization_id=org-1",
                    )
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"attacker-org","flow_instance_id":"flow-1","plaintext_b64":"cHJpdmF0ZS1qd2s"}"#
                            .as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(wrapped.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(wrapped.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("wrap JSON");
        assert_eq!(body["ciphertext"], "vault:v1:test");

        let unwrapped = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/flow-key-envelopes/unwrap?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"flow_instance_id":"flow-1","ciphertext":"vault:v1:test"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unwrapped.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(unwrapped.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("unwrap JSON");
        assert_eq!(body["plaintext_b64"], "cHJpdmF0ZS1qd2s");
    }

    #[tokio::test]
    async fn issuer_context_rejects_profile_selectors_and_delegates_did_resolution() {
        let rejected = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-context?organization_id=org-1&issuer_profile_id=private-selector")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let resolved = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-context?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&credential_format=dc%2Bsd-jwt&key_purpose=vc_jwt_issuer&algorithm=ES256")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resolved.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("issuer context JSON");
        assert_eq!(body["issuer_profile_id"], "profile-1");
        assert_eq!(body["issuer_did"], "did:web:issuer.example");
    }

    #[tokio::test]
    async fn issuer_identity_routes_delegate_only_trusted_organization_scope() {
        let resolved = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/resolve-issuer-did?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&key_purpose=vc_jwt_issuer&algorithm=ES256")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resolved.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("issuer identity JSON");
        assert_eq!(
            body["verification_method_id"],
            "did:web:issuer.example#issuer-key"
        );

        for (path, expected_field) in [
            (
                "/internal/signing-keys/issuer-profiles/profile-1/identity?organization_id=org-1",
                "did_document",
            ),
            (
                "/internal/signing-keys/issuer-profiles/profile-1/public-identity?organization_id=org-1",
                "x5c",
            ),
        ] {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("x-api-key", "internal-signing-key")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                    .await
                    .expect("body"),
            )
            .expect("profile identity JSON");
            assert_eq!(body["issuer_profile_id"], "profile-1");
            assert!(body.get(expected_field).is_some());
        }

        let rejected = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/resolve-issuer-did?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&issuer_profile_id=private-selector")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn signing_routes_replace_body_scope_and_preserve_custody_privacy() {
        let direct = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/services/service-1/sign?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"attacker","payload_b64":"cGF5bG9hZA","algorithm":"ES256"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(direct.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(direct.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("service sign JSON");
        assert_eq!(body["service_id"], "service-1");

        let did = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/issuer-dids/sign?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"attacker","issuer_did":"did:web:issuer.example","credential_format":"dc+sd-jwt","key_purpose":"vc_jwt_issuer","algorithm":"ES256","payload_b64":"cGF5bG9hZA"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(did.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(did.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("DID sign JSON");
        assert!(body.get("service_id").is_none());
        assert_eq!(body["issuer_did"], "did:web:issuer.example");
    }

    #[tokio::test]
    async fn profile_write_routes_wrap_body_with_trusted_scope() {
        for (method, path, input, expected) in [
            (
                "POST",
                "/internal/signing-keys/issuer-profiles?organization_id=org-1",
                json!({"organization_id": "attacker", "issuer_did": "did:web:issuer.example"}),
                "profile",
            ),
            (
                "PATCH",
                "/internal/signing-keys/issuer-profiles/profile-1?organization_id=org-1",
                json!({"organization_id": "attacker", "status": "active"}),
                "profile",
            ),
            (
                "PUT",
                "/internal/signing-keys/issuer-profiles/profile-1/certificate?organization_id=org-1",
                json!({"organization_id": "attacker", "cert_pem": "certificate"}),
                "issuer_profile_id",
            ),
        ] {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("x-api-key", "internal-signing-key")
                        .header("content-type", "application/json")
                        .body(Body::from(input.to_string()))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                    .await
                    .expect("body"),
            )
            .expect("profile write JSON");
            assert!(body.get(expected).is_some());
        }
    }
}
