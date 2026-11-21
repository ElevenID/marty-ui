//! Explicit internal transport for retained P03 use commands.
//!
//! The explicit default-off delegated-use host selects mandatory mutual TLS.
//! A separately composed trusted forwarder can instead supply the complete typed
//! actor and a bounded observation using its dedicated service credential. The
//! application independently authorizes the actor and verifies proof in either
//! composition. No public Gateway installs this router.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::json;
use uuid::Uuid;

use crate::{
    decode_delegation_use_command, DelegationCommandCaller, DelegationUseCommandError,
    DelegationUseCommandResponse, DelegationUseCommandService, Principal, PrincipalType,
};

/// Created only after the configured service-hop credential is authenticated.
/// This is neither verified machine proof nor a replacement for current actor
/// authorization. There is deliberately no deserializing/public constructor.
pub struct AuthenticatedDelegationUseContext {
    caller: DelegationCommandCaller,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    workload_identity_ref: Option<String>,
}
impl AuthenticatedDelegationUseContext {
    pub fn caller(&self) -> &DelegationCommandCaller {
        &self.caller
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
    /// Certificate authentication provenance, separate from human approval
    /// sessions and from the machine key proof required by finalization.
    pub fn workload_identity_ref(&self) -> Option<&str> {
        self.workload_identity_ref.as_deref()
    }
    pub fn check(&self, now: DateTime<Utc>) -> Result<(), UseHttpError> {
        if self.observed_at > now
            || self.valid_until <= now
            || self
                .observed_at
                .checked_add_signed(chrono::Duration::seconds(30))
                .is_none_or(|maximum| self.valid_until > maximum)
        {
            return Err(denied());
        }
        Ok(())
    }
}

#[async_trait]
pub trait DelegationUseHttpApplication: Send + Sync {
    async fn execute(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError>;
}

#[async_trait]
impl DelegationUseHttpApplication for DelegationUseCommandService {
    async fn execute(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        self.execute_before(
            context.caller(),
            raw,
            context.observed_at(),
            context.valid_until(),
        )
        .await
    }
}

#[derive(Clone)]
pub struct DelegationUseHttpState {
    application: Arc<dyn DelegationUseHttpApplication>,
    authenticator: Arc<DelegationUseHttpAuthenticator>,
}

/// Explicit transport selection shared by commands and the Flow ingress. The
/// mutual-TLS mode derives the actor from an authenticated leaf certificate;
/// the older service-forwarding mode remains a separate trusted-adapter choice.
#[derive(Clone)]
pub struct DelegationUseHttpAuthenticator {
    mode: UseAuthenticationMode,
    organization_id: Uuid,
}

#[derive(Clone)]
enum UseAuthenticationMode {
    TrustedForwarder(Arc<ServiceTokenAuthenticator>),
    MutualTls(Arc<crate::use_mtls::DelegatedUseWorkloadBindings>),
}

impl DelegationUseHttpAuthenticator {
    pub fn trusted_forwarder(
        service_token: String,
        organization_id: Uuid,
    ) -> Result<Self, DelegationUseCommandError> {
        if organization_id.is_nil()
            || !(32..=1024).contains(&service_token.len())
            || !service_token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let authenticator = ServiceTokenAuthenticator::new(Some(service_token), true)
            .map_err(|_| DelegationUseCommandError::InvalidCommand)?;
        Ok(Self {
            mode: UseAuthenticationMode::TrustedForwarder(Arc::new(authenticator)),
            organization_id,
        })
    }

    pub fn mutual_tls(
        organization_id: Uuid,
        bindings: crate::use_mtls::DelegatedUseWorkloadBindings,
    ) -> Result<Self, DelegationUseCommandError> {
        if organization_id.is_nil() {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        Ok(Self {
            mode: UseAuthenticationMode::MutualTls(Arc::new(bindings)),
            organization_id,
        })
    }

    pub fn authenticate(
        &self,
        organization: &str,
        request: &Request,
    ) -> Result<AuthenticatedDelegationUseContext, UseHttpError> {
        match &self.mode {
            UseAuthenticationMode::TrustedForwarder(authenticator) => authenticate_forwarded(
                self.organization_id,
                authenticator,
                organization,
                request.headers(),
            ),
            UseAuthenticationMode::MutualTls(bindings) => {
                let organization_id = canonical_uuid(organization)?;
                if organization_id != self.organization_id
                    || request.headers().keys().any(|key| {
                        matches!(
                            key.as_str(),
                            "authorization"
                                | "cookie"
                                | "x-service-token"
                                | "x-user-id"
                                | "x-api-key-id"
                                | "x-workload-identity"
                                | "x-client-cert"
                                | "x-forwarded-client-cert"
                        ) || key.as_str().starts_with("x-marty-use-")
                            || key.as_str().starts_with("x-marty-command-")
                            || key.as_str().starts_with("x-marty-approval-")
                    })
                {
                    return Err(denied());
                }
                let peer = request
                    .extensions()
                    .get::<crate::use_mtls::AuthenticatedUseTlsPeer>()
                    .ok_or_else(authentication_required)?;
                let now = Utc::now();
                let (caller, valid_until) = bindings.authenticate(organization_id, peer, now)?;
                let context = AuthenticatedDelegationUseContext {
                    caller,
                    observed_at: now,
                    valid_until,
                    workload_identity_ref: Some(peer.identity_ref()),
                };
                context.check(now)?;
                Ok(context)
            }
        }
    }
}

impl DelegationUseHttpState {
    pub fn new(
        application: Arc<dyn DelegationUseHttpApplication>,
        service_token: String,
        organization_id: Uuid,
    ) -> Result<Self, DelegationUseCommandError> {
        Ok(Self::with_authenticator(
            application,
            Arc::new(DelegationUseHttpAuthenticator::trusted_forwarder(
                service_token,
                organization_id,
            )?),
        ))
    }

    pub fn with_authenticator(
        application: Arc<dyn DelegationUseHttpApplication>,
        authenticator: Arc<DelegationUseHttpAuthenticator>,
    ) -> Self {
        Self {
            application,
            authenticator,
        }
    }
}

/// Explicit assembly only. Human lifecycle/approval hosts remain separate and
/// this path is absent from the public Gateway route tables and discovery.
pub fn delegated_use_command_router(state: DelegationUseHttpState) -> Router {
    Router::new()
        .route(
            "/internal/v1/organizations/{organization_id}/delegated-use-commands",
            post(execute),
        )
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

pub(crate) async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn execute(
    State(state): State<DelegationUseHttpState>,
    Path(organization): Path<String>,
    request: Request,
) -> Result<Json<DelegationUseCommandResponse>, UseHttpError> {
    let context = state.authenticator.authenticate(&organization, &request)?;
    if request.uri().query().is_some() {
        return Err(invalid());
    }
    let content_type = single_header(request.headers(), "content-type")?;
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(UseHttpError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "delegation_use_json_required",
        ));
    }
    let raw = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), crate::wire::MAX_GRANT_WIRE_BYTES),
    )
    .await
    .map_err(|_| UseHttpError(StatusCode::REQUEST_TIMEOUT, "delegation_use_body_timeout"))?
    .map_err(|_| {
        UseHttpError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "delegation_use_body_too_large",
        )
    })?;
    decode_delegation_use_command(&raw)?;
    context.check(Utc::now())?;
    // No timeout, cache, normalization or retry surrounds external preparation,
    // signing or COMMIT. The original identity is the only recovery key.
    Ok(Json(state.application.execute(&context, &raw).await?))
}

fn authenticate_forwarded(
    configured_organization_id: Uuid,
    authenticator: &ServiceTokenAuthenticator,
    organization: &str,
    headers: &HeaderMap,
) -> Result<AuthenticatedDelegationUseContext, UseHttpError> {
    let token = single_header(headers, "x-service-token").map_err(|_| authentication_required())?;
    authenticator
        .authenticate(Some(token))
        .map_err(|_| authentication_required())?;
    // These are different authentication paths; no user session or caller API
    // key metadata is silently converted into a workload identity.
    if headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::COOKIE)
        || headers.contains_key("x-user-id")
        || headers.contains_key("x-api-key-id")
        || headers.keys().any(|key| {
            key.as_str().starts_with("x-marty-command-")
                || key.as_str().starts_with("x-marty-approval-")
        })
    {
        return Err(denied());
    }
    let organization_id = canonical_uuid(organization)?;
    if organization_id != configured_organization_id
        || single_header(headers, "x-marty-use-organization-id")? != organization
    {
        return Err(denied());
    }
    let principal_type = match single_header(headers, "x-marty-use-principal-type")? {
        "SERVICE_ACCOUNT" => PrincipalType::ServiceAccount,
        "MACHINE_IDENTITY" => PrincipalType::MachineIdentity,
        _ => return Err(denied()),
    };
    let caller = DelegationCommandCaller::from_authenticated_context(
        organization_id,
        Principal {
            principal_type,
            id: single_header(headers, "x-marty-use-principal-id")?.into(),
        },
    )
    .map_err(|_| denied())?;
    let context = AuthenticatedDelegationUseContext {
        caller,
        observed_at: timestamp(single_header(headers, "x-marty-use-observed-at")?)?,
        valid_until: timestamp(single_header(headers, "x-marty-use-valid-until")?)?,
        workload_identity_ref: None,
    };
    context.check(Utc::now())?;
    Ok(context)
}

pub(crate) fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, UseHttpError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid)?;
    if values.next().is_some() || value.is_empty() || value.len() > 1024 || value.trim() != value {
        return Err(invalid());
    }
    Ok(value)
}
fn canonical_uuid(value: &str) -> Result<Uuid, UseHttpError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
        .ok_or_else(invalid)
}
fn timestamp(value: &str) -> Result<DateTime<Utc>, UseHttpError> {
    if value.len() > 64 || !value.ends_with('Z') {
        return Err(invalid());
    }
    let time = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid())?
        .with_timezone(&Utc);
    if !crate::consent::valid_time(time) {
        return Err(invalid());
    }
    Ok(time)
}

#[derive(Debug)]
pub struct UseHttpError(StatusCode, &'static str);
impl UseHttpError {
    pub fn new(status: StatusCode, public_code: &'static str) -> Self {
        Self(status, public_code)
    }
}
fn invalid() -> UseHttpError {
    UseHttpError(StatusCode::BAD_REQUEST, "invalid_delegation_use_command")
}
fn denied() -> UseHttpError {
    UseHttpError(StatusCode::FORBIDDEN, "delegation_use_access_denied")
}
fn authentication_required() -> UseHttpError {
    UseHttpError(
        StatusCode::UNAUTHORIZED,
        "delegation_use_service_authentication_required",
    )
}
impl From<DelegationUseCommandError> for UseHttpError {
    fn from(error: DelegationUseCommandError) -> Self {
        match error {
            DelegationUseCommandError::InvalidCommand => invalid(),
            DelegationUseCommandError::AccessDenied => denied(),
            DelegationUseCommandError::Conflict => {
                Self(StatusCode::CONFLICT, "delegation_use_conflict")
            }
            DelegationUseCommandError::PreparationPending => {
                Self(StatusCode::CONFLICT, "delegation_use_preparation_pending")
            }
            DelegationUseCommandError::ResultNotFound => {
                Self(StatusCode::NOT_FOUND, "delegation_use_result_not_found")
            }
            DelegationUseCommandError::Expired => {
                Self(StatusCode::CONFLICT, "delegation_use_evidence_expired")
            }
            DelegationUseCommandError::Unavailable => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "delegation_use_unavailable",
            ),
            DelegationUseCommandError::Unsupported => Self(
                StatusCode::BAD_REQUEST,
                "unsupported_delegation_use_command",
            ),
        }
    }
}
impl IntoResponse for UseHttpError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"detail":self.1}))).into_response()
    }
}

#[cfg(test)]
#[path = "use_http_tests.rs"]
mod tests;
