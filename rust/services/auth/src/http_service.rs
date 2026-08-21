use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    build_session_impersonation, build_ui_redirect_url, oidc_callback_url, sanitize_redirect_uri,
    AuthApplication, AuthApplicationError, CanvasFinalizeContext, CanvasLtiApplication,
    HandleCallbackCommand, HandleCallbackResult, InitiateLoginCommand, PortError, Session,
    SessionRepository, UiOriginPolicy,
};

pub const AUTH_CORE_HTTP_ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/auth/login"),
    ("GET", "/v1/auth/register"),
    ("GET", "/v1/auth/canvas-lti/finalize"),
    ("POST", "/v1/auth/canvas-lti/finalize"),
    ("GET", "/v1/auth/callback"),
    ("POST", "/v1/auth/logout"),
    ("GET", "/v1/auth/me"),
    ("PATCH", "/v1/auth/me"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCookieConfig {
    pub name: String,
    pub secure: bool,
    pub same_site: String,
    pub maximum_age_seconds: u64,
    pub path: String,
}

impl SessionCookieConfig {
    pub fn validate(&self) -> Result<(), PortError> {
        if self.name.is_empty()
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !matches!(
                self.same_site.to_ascii_lowercase().as_str(),
                "lax" | "strict" | "none"
            )
            || self.maximum_age_seconds == 0
            || !self.path.starts_with('/')
        {
            return Err(PortError::new(
                "auth_cookie_configuration_invalid",
                "Auth session cookie configuration is invalid",
            ));
        }
        if self.same_site.eq_ignore_ascii_case("none") && !self.secure {
            return Err(PortError::new(
                "auth_cookie_configuration_invalid",
                "SameSite=None requires a secure Auth session cookie",
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub trait AuthHttpApplication: Send + Sync {
    async fn initiate(
        &self,
        registration: bool,
        redirect_uri: String,
        oidc_redirect_uri: String,
    ) -> Result<String, PortError>;
    async fn callback(
        &self,
        command: HandleCallbackCommand,
    ) -> Result<HandleCallbackResult, PortError>;
    async fn logout(&self, session_id: &str) -> Result<Option<String>, PortError>;
    async fn validate_session(&self, session_id: &str) -> Result<Option<Session>, PortError>;
}

#[async_trait]
impl AuthHttpApplication for AuthApplication {
    async fn initiate(
        &self,
        registration: bool,
        redirect_uri: String,
        oidc_redirect_uri: String,
    ) -> Result<String, PortError> {
        let command = InitiateLoginCommand {
            redirect_uri: Some(redirect_uri),
            oidc_redirect_uri: Some(oidc_redirect_uri),
        };
        let result = if registration {
            self.initiate_registration(command, Utc::now()).await
        } else {
            self.initiate_login(command, Utc::now()).await
        };
        result
            .map(|result| result.authorization_url)
            .map_err(application_error)
    }

    async fn callback(
        &self,
        command: HandleCallbackCommand,
    ) -> Result<HandleCallbackResult, PortError> {
        self.handle_callback(command, Utc::now())
            .await
            .map_err(application_error)
    }

    async fn logout(&self, session_id: &str) -> Result<Option<String>, PortError> {
        self.logout(session_id)
            .await
            .map(|result| result.sso_logout_url)
            .map_err(application_error)
    }

    async fn validate_session(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        self.validate_session(session_id, Utc::now())
            .await
            .map_err(application_error)
    }
}

#[async_trait]
pub trait CanvasHttpApplication: Send + Sync {
    async fn finalize(&self, context: &CanvasFinalizeContext) -> Result<Session, PortError>;
}

#[async_trait]
impl CanvasHttpApplication for CanvasLtiApplication {
    async fn finalize(&self, context: &CanvasFinalizeContext) -> Result<Session, PortError> {
        self.finalize(context, Utc::now()).await
    }
}

#[derive(Clone)]
pub struct AuthHttpState {
    pub application: Arc<dyn AuthHttpApplication>,
    pub canvas: Arc<dyn CanvasHttpApplication>,
    pub sessions: Arc<dyn SessionRepository>,
    pub origins: UiOriginPolicy,
    pub cookie: SessionCookieConfig,
    pub canvas_session_ttl_seconds: u64,
    pub impersonation_handoff_cookie_name: String,
}

impl AuthHttpState {
    pub fn validate(&self) -> Result<(), PortError> {
        self.cookie.validate()?;
        if self.canvas_session_ttl_seconds == 0 || self.impersonation_handoff_cookie_name.is_empty()
        {
            return Err(PortError::new(
                "auth_http_configuration_invalid",
                "Auth HTTP configuration is invalid",
            ));
        }
        Ok(())
    }
}

pub fn auth_core_router(state: AuthHttpState) -> Result<Router, PortError> {
    state.validate()?;
    Ok(Router::new()
        .route("/v1/auth/login", get(login))
        .route("/v1/auth/register", get(register))
        .route(
            "/v1/auth/canvas-lti/finalize",
            get(canvas_legacy_finalize).post(canvas_finalize),
        )
        .route("/v1/auth/callback", get(callback))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(me).patch(update_me))
        .with_state(state))
}

#[derive(Deserialize)]
struct LoginQuery {
    redirect_uri: Option<String>,
}

async fn login(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    initiate(state, headers, query, false).await
}

async fn register(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    initiate(state, headers, query, true).await
}

async fn initiate(
    state: AuthHttpState,
    headers: HeaderMap,
    query: LoginQuery,
    registration: bool,
) -> Response {
    let ui_base = request_ui_base(&state.origins, &headers);
    let redirect = sanitize_redirect_uri(query.redirect_uri.as_deref(), ui_base);
    match state
        .application
        .initiate(registration, redirect, oidc_callback_url(ui_base))
        .await
    {
        Ok(location) => redirect_response(&location),
        Err(_) => detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        ),
    }
}

async fn canvas_legacy_finalize() -> Response {
    detail(
        StatusCode::GONE,
        "Canvas LTI state finalization is no longer supported",
    )
}

async fn canvas_finalize(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return detail(
            StatusCode::UNAUTHORIZED,
            "Canvas LTI session token is required",
        );
    };
    match state
        .canvas
        .finalize(&CanvasFinalizeContext {
            bearer_token: token.into(),
            ip_address: client_ip(&headers),
            user_agent: header_text(&headers, header::USER_AGENT).map(str::to_owned),
        })
        .await
    {
        Ok(session) => {
            let mut response = Json(json!({
                "authenticated": true,
                "expires_in": state.canvas_session_ttl_seconds,
            }))
            .into_response();
            set_session_cookie(&mut response, &state.cookie, &session.session_id);
            response
        }
        Err(error) if error.code == "canvas_lti_session_expired" => detail(
            StatusCode::UNAUTHORIZED,
            "Canvas LTI session is invalid or expired",
        ),
        Err(error) if error.code == "canvas_lti_session_invalid" => {
            detail(StatusCode::BAD_REQUEST, &error.message)
        }
        Err(_) => detail(StatusCode::BAD_GATEWAY, "Canvas LTI session service failed"),
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let ui_base = request_ui_base(&state.origins, &headers);
    if let Some(error) = query.error {
        let location = if matches!(
            error.as_str(),
            "different_user_authenticated" | "already_logged_in"
        ) {
            format!("{ui_base}/?auth_error=already_authenticated&message=Please+logout+first+to+login+as+a+different+user")
        } else {
            let message = query.error_description.as_deref().unwrap_or(&error);
            format!(
                "{ui_base}/?auth_error={}",
                url::form_urlencoded::byte_serialize(message.as_bytes()).collect::<String>()
            )
        };
        return redirect_response(&location);
    }
    let (Some(code), Some(callback_state)) = (query.code, query.state) else {
        return redirect_response(&format!(
            "{ui_base}/?auth_error=Missing+authentication+parameters"
        ));
    };
    let result = state
        .application
        .callback(HandleCallbackCommand {
            code,
            state: callback_state,
            ip_address: client_ip(&headers),
            user_agent: header_text(&headers, header::USER_AGENT).map(str::to_owned),
        })
        .await;
    let Ok(mut result) = result else {
        return redirect_response(&format!(
            "{ui_base}/?auth_error=Session+expired.+Please+try+again."
        ));
    };
    if let Some(impersonation) = build_session_impersonation(
        &result.session,
        cookie(&headers, &state.impersonation_handoff_cookie_name),
    ) {
        result.session.user.impersonation = Some(impersonation);
        if state.sessions.save(&result.session).await.is_err() {
            return detail(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable");
        }
    }
    let mut response =
        redirect_response(&build_ui_redirect_url(Some(&result.redirect_uri), ui_base));
    set_session_cookie(&mut response, &state.cookie, &result.session.session_id);
    delete_cookie(
        &mut response,
        &state.impersonation_handoff_cookie_name,
        "/",
        state.cookie.secure,
        &state.cookie.same_site,
    );
    response
}

async fn logout(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let location = if let Some(session_id) = cookie(&headers, &state.cookie.name) {
        match state.application.logout(session_id).await {
            Ok(Some(location)) => location,
            Ok(None) => "/".into(),
            Err(_) => {
                return detail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authentication service unavailable",
                )
            }
        }
    } else {
        "/".into()
    };
    let mut response = redirect_response(&location);
    delete_cookie(
        &mut response,
        &state.cookie.name,
        &state.cookie.path,
        state.cookie.secure,
        &state.cookie.same_site,
    );
    delete_cookie(
        &mut response,
        &state.impersonation_handoff_cookie_name,
        "/",
        state.cookie.secure,
        &state.cookie.same_site,
    );
    response
}

async fn me(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let session = if let Some(session_id) = cookie(&headers, &state.cookie.name) {
        match state.application.validate_session(session_id).await {
            Ok(session) => session,
            Err(_) => return detail(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable"),
        }
    } else {
        None
    };
    auth_status(session.as_ref().map(|session| &session.user))
}

#[derive(Deserialize)]
struct UpdateMeRequest {
    picture: Option<String>,
}

async fn update_me(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(body): Json<UpdateMeRequest>,
) -> Response {
    let Some(session_id) = cookie(&headers, &state.cookie.name) else {
        return detail(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    let Ok(Some(mut session)) = state.sessions.get(session_id).await else {
        return detail(StatusCode::UNAUTHORIZED, "Session not found or expired");
    };
    if !session.is_valid_at(Utc::now()) {
        return detail(StatusCode::UNAUTHORIZED, "Session not found or expired");
    }
    if let Some(picture) = body.picture {
        if !picture.starts_with("data:image/") && !picture.starts_with("https://") {
            return detail(
                StatusCode::BAD_REQUEST,
                "picture must be an image data URL or https URL",
            );
        }
        session.user.picture = Some(picture);
        if state.sessions.save(&session).await.is_err() {
            return detail(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable");
        }
    }
    auth_status(Some(&session.user))
}

fn auth_status(user: Option<&crate::AuthenticatedUser>) -> Response {
    let mut response = Json(if let Some(user) = user {
        json!({"authenticated": true, "user": user_response(user)})
    } else {
        json!({"authenticated": false})
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn user_response(user: &crate::AuthenticatedUser) -> Value {
    let mut value = serde_json::to_value(user).expect("authenticated users serialize");
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, value| !value.is_null());
        object.insert(
            "user_type".into(),
            Value::String(user.user_type.as_str().into()),
        );
    }
    value
}

fn request_ui_base<'a>(policy: &'a UiOriginPolicy, headers: &HeaderMap) -> &'a str {
    policy.select(
        header_text(headers, "x-forwarded-host"),
        header_text(headers, header::HOST),
        header_text(headers, "x-forwarded-proto"),
        Some("https"),
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let authorization = header_text(headers, header::AUTHORIZATION)?;
    let (scheme, token) = authorization.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    header_text(headers, "x-forwarded-for")
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn header_text(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name)?.to_str().ok()
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    header_text(headers, header::COOKIE)?
        .split(';')
        .filter_map(|item| item.trim().split_once('='))
        .find_map(|(key, value)| (key == name && !value.is_empty()).then_some(value))
}

fn redirect_response(location: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

fn detail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"detail": message}))).into_response()
}

fn set_session_cookie(response: &mut Response, config: &SessionCookieConfig, session_id: &str) {
    let cookie = format!(
        "{}={session_id}; Max-Age={}; Path={}; SameSite={};{} HttpOnly",
        config.name,
        config.maximum_age_seconds,
        config.path,
        title_case(&config.same_site),
        if config.secure { " Secure;" } else { "" }
    );
    append_set_cookie(response, &cookie);
}

fn delete_cookie(response: &mut Response, name: &str, path: &str, secure: bool, same_site: &str) {
    let cookie = format!(
        "{name}=; Max-Age=0; Path={path}; SameSite={};{}",
        title_case(same_site),
        if secure { " Secure" } else { "" }
    );
    append_set_cookie(response, &cookie);
}

fn append_set_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn title_case(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "strict" => "Strict",
        "none" => "None",
        _ => "Lax",
    }
}

fn application_error(error: AuthApplicationError) -> PortError {
    PortError::new("auth_application_error", error.to_string())
}
