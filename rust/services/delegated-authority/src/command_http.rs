//! Human lifecycle command host behind the authenticated Gateway service hop.
//! Actor/session context is reconstructed from authenticated internal metadata;
//! original strict command bytes are passed through without normalization.

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
    command_postgres::PgOrganizationCommandService, decode_delegation_command,
    AuthenticatedApprovalSession, DelegationCommandError, DelegationCommandResponse,
};

#[async_trait]
pub trait CommandHttpApplication: Send + Sync {
    async fn execute(
        &self,
        session: &AuthenticatedApprovalSession,
        raw: &[u8],
    ) -> Result<DelegationCommandResponse, DelegationCommandError>;
}

#[async_trait]
impl CommandHttpApplication for PgOrganizationCommandService {
    async fn execute(
        &self,
        session: &AuthenticatedApprovalSession,
        raw: &[u8],
    ) -> Result<DelegationCommandResponse, DelegationCommandError> {
        PgOrganizationCommandService::execute(self, session, raw).await
    }
}

#[derive(Clone)]
pub struct CommandHttpState {
    application: Arc<dyn CommandHttpApplication>,
    authenticator: Arc<ServiceTokenAuthenticator>,
    organization_id: Uuid,
}

impl CommandHttpState {
    pub fn new(
        application: Arc<dyn CommandHttpApplication>,
        service_token: String,
        organization_id: Uuid,
    ) -> Result<Self, DelegationCommandError> {
        if organization_id.is_nil()
            || !(32..=1024).contains(&service_token.len())
            || !service_token
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(DelegationCommandError::InvalidCommand);
        }
        let authenticator = ServiceTokenAuthenticator::new(Some(service_token), true)
            .map_err(|_| DelegationCommandError::InvalidCommand)?;
        Ok(Self {
            application,
            authenticator: Arc::new(authenticator),
            organization_id,
        })
    }
}

pub fn organization_command_router(state: CommandHttpState) -> Router {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/delegation-commands",
            post(execute),
        )
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn execute(
    State(state): State<CommandHttpState>,
    Path(organization): Path<String>,
    request: Request,
) -> Result<Json<DelegationCommandResponse>, CommandHttpError> {
    let session = authenticate(&state, &organization, request.headers())?;
    if request.uri().query().is_some() {
        return Err(invalid());
    }
    let content_type = single_header(request.headers(), "content-type")?;
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(CommandHttpError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "delegation_command_json_required",
        ));
    }
    let raw = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), crate::wire::MAX_GRANT_WIRE_BYTES),
    )
    .await
    .map_err(|_| {
        CommandHttpError(
            StatusCode::REQUEST_TIMEOUT,
            "delegation_command_body_timeout",
        )
    })?
    .map_err(|_| {
        CommandHttpError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "delegation_command_body_too_large",
        )
    })?;
    // Includes duplicate keys, explicit nulls, aliases, unsafe numbers, unknown
    // fields, and unsupported use commands. The application independently decodes.
    decode_delegation_command(&raw)?;
    session
        .check(state.organization_id, Utc::now())
        .map_err(|_| denied())?;
    // No timeout wraps execution/COMMIT. Uncertain outcomes can only be recovered
    // with the original command identity and digest, never an automatic retry.
    Ok(Json(state.application.execute(&session, &raw).await?))
}

fn authenticate(
    state: &CommandHttpState,
    organization: &str,
    headers: &HeaderMap,
) -> Result<AuthenticatedApprovalSession, CommandHttpError> {
    let token = single_header(headers, "x-service-token").map_err(|_| authentication_required())?;
    state
        .authenticator
        .authenticate(Some(token))
        .map_err(|_| authentication_required())?;
    if headers.contains_key("x-api-key-id") {
        return Err(denied());
    }
    let organization_id = canonical_uuid(organization)?;
    if organization_id != state.organization_id
        || single_header(headers, "x-marty-command-organization-id")? != organization
    {
        return Err(denied());
    }
    let user = canonical_uuid(single_header(headers, "x-marty-command-user-id")?)?;
    let session = AuthenticatedApprovalSession::from_authenticated_gateway_context(
        organization_id,
        user,
        single_header(headers, "x-marty-command-session-ref")?.to_owned(),
        timestamp(single_header(headers, "x-marty-command-observed-at")?)?,
        timestamp(single_header(headers, "x-marty-command-valid-until")?)?,
    )
    .map_err(|_| denied())?;
    session
        .check(organization_id, Utc::now())
        .map_err(|_| denied())?;
    Ok(session)
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, CommandHttpError> {
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
fn canonical_uuid(value: &str) -> Result<Uuid, CommandHttpError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
        .ok_or_else(invalid)
}
fn timestamp(value: &str) -> Result<DateTime<Utc>, CommandHttpError> {
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
pub struct CommandHttpError(StatusCode, &'static str);
fn invalid() -> CommandHttpError {
    CommandHttpError(StatusCode::BAD_REQUEST, "invalid_delegation_command")
}
fn denied() -> CommandHttpError {
    CommandHttpError(StatusCode::FORBIDDEN, "delegation_command_access_denied")
}
fn authentication_required() -> CommandHttpError {
    CommandHttpError(
        StatusCode::UNAUTHORIZED,
        "delegation_command_service_authentication_required",
    )
}
impl From<DelegationCommandError> for CommandHttpError {
    fn from(error: DelegationCommandError) -> Self {
        match error {
            DelegationCommandError::InvalidCommand => invalid(),
            DelegationCommandError::UnsupportedCommand => {
                Self(StatusCode::BAD_REQUEST, "unsupported_delegation_command")
            }
            DelegationCommandError::AccessDenied => denied(),
            DelegationCommandError::Conflict => {
                Self(StatusCode::CONFLICT, "delegation_command_conflict")
            }
            DelegationCommandError::ResultNotFound => {
                Self(StatusCode::NOT_FOUND, "delegation_command_result_not_found")
            }
            DelegationCommandError::ConfirmationUnavailable => Self(
                StatusCode::CONFLICT,
                "delegation_command_confirmation_unavailable",
            ),
            DelegationCommandError::LifecycleRejected => Self(
                StatusCode::CONFLICT,
                "delegation_command_lifecycle_rejected",
            ),
            DelegationCommandError::Unavailable => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "delegation_command_unavailable",
            ),
        }
    }
}
impl IntoResponse for CommandHttpError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"detail": self.1}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use chrono::Duration;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    const ORG: &str = "6353458f-4d83-4c1a-82e4-579d1b2a153a";
    const USER: &str = "fe5812a0-b048-4604-a2ec-9cc4a164988e";
    const TOKEN: &str = "synthetic-command-internal-service-token";
    #[derive(Default)]
    struct CountingApplication(AtomicUsize);
    #[async_trait]
    impl CommandHttpApplication for CountingApplication {
        async fn execute(
            &self,
            session: &AuthenticatedApprovalSession,
            raw: &[u8],
        ) -> Result<DelegationCommandResponse, DelegationCommandError> {
            assert_eq!(session.user_id().to_string(), USER);
            assert!(matches!(
                decode_delegation_command(raw),
                Ok(crate::DecodedDelegationCommand::Recover { .. })
            ));
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(DelegationCommandError::ResultNotFound)
        }
    }
    fn setup() -> (Router, Arc<CountingApplication>) {
        let app = Arc::new(CountingApplication::default());
        let state = CommandHttpState::new(app.clone(), TOKEN.into(), ORG.parse().unwrap()).unwrap();
        (organization_command_router(state), app)
    }
    fn request(body: String) -> Request<Body> {
        let now = Utc::now();
        Request::builder()
            .method("POST")
            .uri(format!("/v1/organizations/{ORG}/delegation-commands"))
            .header("content-type", "application/json")
            .header("x-service-token", TOKEN)
            .header("x-marty-command-organization-id", ORG)
            .header("x-marty-command-user-id", USER)
            .header(
                "x-marty-command-session-ref",
                format!("urn:marty:session:sha256:{}", "11".repeat(32)),
            )
            .header(
                "x-marty-command-observed-at",
                now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .header(
                "x-marty-command-valid-until",
                (now + Duration::seconds(25)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .body(Body::from(body))
            .unwrap()
    }
    fn recover() -> String {
        json!({"profile": crate::DELEGATION_COMMAND_PROFILE, "command":"RECOVER_RESULT", "original_command_id":Uuid::new_v4(), "expected_command_digest":format!("sha256:{}", "22".repeat(32))}).to_string()
    }
    #[tokio::test]
    async fn exact_authenticated_session_reaches_application_once_without_retry() {
        let (router, app) = setup();
        let response = router.oneshot(request(recover())).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(app.0.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn missing_duplicate_spoofed_and_expired_context_never_reaches_application() {
        for case in 0..9 {
            let (router, app) = setup();
            let mut request = request(recover());
            match case {
                0 => {
                    request.headers_mut().remove("x-service-token");
                }
                1 => {
                    request
                        .headers_mut()
                        .insert("x-service-token", HeaderValue::from_static("wrong"));
                }
                2 => {
                    request
                        .headers_mut()
                        .append("x-marty-command-user-id", HeaderValue::from_static(USER));
                }
                3 => {
                    request.headers_mut().insert(
                        "x-marty-command-organization-id",
                        HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
                    );
                }
                4 => {
                    request
                        .headers_mut()
                        .insert("x-api-key-id", HeaderValue::from_static("api-key"));
                }
                5 => {
                    request.headers_mut().insert(
                        "x-marty-command-session-ref",
                        HeaderValue::from_static("raw-cookie"),
                    );
                }
                6 => {
                    request.headers_mut().insert(
                        "x-marty-command-valid-until",
                        HeaderValue::from_static("2020-01-01T00:00:00Z"),
                    );
                }
                7 => {
                    request.headers_mut().insert(
                        "x-marty-command-valid-until",
                        HeaderValue::from_str(
                            &(Utc::now() + Duration::hours(1))
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        )
                        .unwrap(),
                    );
                }
                _ => {
                    request.headers_mut().remove("x-marty-command-user-id");
                    request
                        .headers_mut()
                        .insert("x-user-id", HeaderValue::from_static(USER));
                }
            }
            assert!(
                router
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status()
                    .is_client_error(),
                "case {case}"
            );
            assert_eq!(app.0.load(Ordering::SeqCst), 0, "case {case}");
        }
    }
    #[tokio::test]
    async fn strict_body_profile_and_use_exclusion_precede_application() {
        for body in [
            format!(
                "{{\"profile\":\"{}\",\"command\":\"START_USE\"}}",
                crate::DELEGATION_COMMAND_PROFILE
            ),
            format!(
                "{{\"profile\":\"{}\",\"command\":\"FINALIZE_USE\"}}",
                crate::DELEGATION_COMMAND_PROFILE
            ),
            recover().replacen("{", "{\"actor\":{},", 1),
            recover().replacen("{", "{\"command\":\"RECOVER_RESULT\",", 1),
            recover().replace("RECOVER_RESULT", "recover_result"),
        ] {
            let (router, app) = setup();
            assert_eq!(
                router.oneshot(request(body)).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(app.0.load(Ordering::SeqCst), 0);
        }
    }
}
