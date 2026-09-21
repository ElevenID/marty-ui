use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::{RawQuery, Request, State},
    http::{header, HeaderMap, HeaderValue, Response, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use marty_oid4vci::{
    issuer::IssuanceEngine, AuthorizationDetail, AuthorizationRequest, AuthorizationSession,
    CodeChallengeMethod,
};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{json, Value};
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

use crate::{
    canvas_award_candidate::python_canonical_json,
    dpop::verify_bound_dpop,
    token_exchange::DpopProofVerifier,
    token_rate_limit::{token_rate_limit_middleware, TokenRateLimiter},
};

const PAR_TTL_SECONDS: u64 = 90;
const PAR_MAX_PAYLOAD_BYTES: usize = 16 * 1024;
// The gateway transport owns the released 10 MiB request envelope. Do not add
// a smaller application limit to protocol bodies that had no Python limit.
const TRANSPORT_OWNED_BODY_LIMIT: usize = usize::MAX;
const AUTHORIZATION_SESSION_SECONDS: u64 = 600;

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct AuthorizationParameters {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub issuer_state: Option<String>,
    pub authorization_details: Option<String>,
    pub organization_id: Option<String>,
}

impl AuthorizationParameters {
    fn overlay_truthy(&mut self, stored: Self) {
        macro_rules! replace_truthy {
            ($field:ident) => {
                if stored
                    .$field
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                {
                    self.$field = stored.$field;
                }
            };
        }
        replace_truthy!(response_type);
        replace_truthy!(client_id);
        replace_truthy!(redirect_uri);
        replace_truthy!(scope);
        replace_truthy!(state);
        replace_truthy!(code_challenge);
        replace_truthy!(code_challenge_method);
        replace_truthy!(issuer_state);
        replace_truthy!(authorization_details);
        replace_truthy!(organization_id);
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuthorizationQuery {
    #[serde(flatten)]
    parameters: AuthorizationParameters,
    issuer_org: Option<String>,
    request_uri: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ParQuery {
    issuer_org: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredAuthorizationClient {
    pub active: bool,
    pub redirect_uris: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AuthorizationSessionWrite {
    pub id: String,
    pub session: AuthorizationSession,
    pub organization_id: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredStatus {
    Pending,
    Authorized,
    Issued,
    Signing,
    Failed,
    Expired,
    Revoked,
}

impl DeferredStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Issued => "issued",
            Self::Signing => "signing",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredCredentialRecord {
    pub status: DeferredStatus,
    pub credential: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeferredCredentialLookup {
    Missing,
    Unbound,
    Bound(DeferredCredentialRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationLookup {
    Missing,
    Unbound,
    Bound(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessTokenGrant {
    pub dpop_jkt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: NotificationEvent,
    pub event_description: Option<String>,
}

impl<'de> Deserialize<'de> for NotificationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NotificationVisitor;

        impl<'de> Visitor<'de> for NotificationVisitor {
            type Value = NotificationRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OID4VCI notification request")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut notification_id = None;
                let mut event = None;
                let mut event_description = None;
                let mut seen_notification_id = false;
                let mut seen_event = false;
                let mut seen_event_description = false;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "notification_id" if !seen_notification_id => {
                            seen_notification_id = true;
                            notification_id = Some(map.next_value()?);
                        }
                        "event" if !seen_event => {
                            seen_event = true;
                            event = Some(map.next_value()?);
                        }
                        "event_description" if !seen_event_description => {
                            seen_event_description = true;
                            event_description = map.next_value()?;
                        }
                        "notification_id" | "event" | "event_description" => {
                            return Err(de::Error::duplicate_field(match field.as_str() {
                                "notification_id" => "notification_id",
                                "event" => "event",
                                _ => "event_description",
                            }));
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &field,
                                &["notification_id", "event", "event_description"],
                            ));
                        }
                    }
                }
                Ok(NotificationRequest {
                    notification_id: notification_id
                        .ok_or_else(|| de::Error::missing_field("notification_id"))?,
                    event: event.ok_or_else(|| de::Error::missing_field("event"))?,
                    event_description,
                })
            }
        }

        deserializer.deserialize_map(NotificationVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum NotificationEvent {
    #[serde(rename = "credential_accepted")]
    Accepted,
    #[serde(rename = "credential_failure")]
    Failure,
    #[serde(rename = "credential_deleted")]
    Deleted,
}

impl NotificationEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "credential_accepted",
            Self::Failure => "credential_failure",
            Self::Deleted => "credential_deleted",
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("OID4VCI authorization repository is unavailable")]
pub struct Oid4vciAuthorizationRepositoryError;

#[async_trait]
pub trait Oid4vciAuthorizationRepository: Send + Sync {
    async fn store_par(
        &self,
        request_uri: &str,
        parameters: &AuthorizationParameters,
        ttl_seconds: u64,
    ) -> Result<bool, Oid4vciAuthorizationRepositoryError>;
    async fn consume_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationParameters>, Oid4vciAuthorizationRepositoryError>;
    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredAuthorizationClient>, Oid4vciAuthorizationRepositoryError>;
    async fn save_authorization_session(
        &self,
        session: &AuthorizationSessionWrite,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError>;
    async fn access_token_grant(
        &self,
        access_token: &str,
    ) -> Result<Option<AccessTokenGrant>, Oid4vciAuthorizationRepositoryError>;
    async fn deferred_credential(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> Result<DeferredCredentialLookup, Oid4vciAuthorizationRepositoryError>;
    async fn notification_transaction(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> Result<NotificationLookup, Oid4vciAuthorizationRepositoryError>;
    async fn record_notification(
        &self,
        transaction_id: &str,
        request: &NotificationRequest,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError>;
}

#[derive(Clone)]
pub struct Oid4vciAuthorizationService {
    repository: Arc<dyn Oid4vciAuthorizationRepository>,
    dpop_verifier: Arc<dyn DpopProofVerifier>,
    engine: Arc<IssuanceEngine>,
    issuer_base_url: Arc<str>,
    allowed_redirect_uris: Arc<BTreeSet<String>>,
}

impl std::fmt::Debug for Oid4vciAuthorizationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Oid4vciAuthorizationService")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl Oid4vciAuthorizationService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn Oid4vciAuthorizationRepository>,
        dpop_verifier: Arc<dyn DpopProofVerifier>,
        engine: IssuanceEngine,
        issuer_base_url: &str,
        allowed_redirect_uris: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            repository,
            dpop_verifier,
            engine: Arc::new(engine),
            issuer_base_url: Arc::from(issuer_base_url.trim_end_matches('/')),
            allowed_redirect_uris: Arc::new(allowed_redirect_uris.into_iter().collect()),
        }
    }

    async fn par(
        &self,
        mut parameters: AuthorizationParameters,
        issuer_org: Option<String>,
    ) -> Result<Value, ProtocolError> {
        parameters.organization_id = nonempty(issuer_org).or(parameters.organization_id);
        let encoded = serde_json::to_value(&parameters).map_err(|_| ProtocolError::Unavailable)?;
        if python_canonical_json(&encoded).len() > PAR_MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::invalid_request(
                "Pushed authorization request is too large",
            ));
        }
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());
        if !self
            .repository
            .store_par(&request_uri, &parameters, PAR_TTL_SECONDS)
            .await
            .map_err(|_| ProtocolError::ParUnavailable)?
        {
            return Err(ProtocolError::ParUnavailable);
        }
        Ok(json!({"request_uri": request_uri, "expires_in": PAR_TTL_SECONDS}))
    }

    async fn authorize(
        &self,
        mut query: AuthorizationQuery,
    ) -> Result<AuthorizationOutcome, ProtocolError> {
        query.parameters.organization_id =
            nonempty(query.issuer_org).or(query.parameters.organization_id);
        if let Some(request_uri) = nonempty(query.request_uri) {
            let stored = self
                .repository
                .consume_par(&request_uri)
                .await
                .map_err(|_| ProtocolError::ParUnavailable)?
                .ok_or(ProtocolError::InvalidRequestUri)?;
            query.parameters.overlay_truthy(stored);
        }
        let response_type = required(&query.parameters.response_type).ok_or_else(|| {
            ProtocolError::invalid_request("response_type and client_id are required")
        })?;
        let client_id = required(&query.parameters.client_id).ok_or_else(|| {
            ProtocolError::invalid_request("response_type and client_id are required")
        })?;
        if let Some(organization_id) = query.parameters.organization_id.as_deref() {
            if let Some(client) = self
                .repository
                .registered_client(organization_id, client_id)
                .await
                .map_err(|_| ProtocolError::Unavailable)?
            {
                if !client.active {
                    return Err(ProtocolError::oauth(
                        "unauthorized_client",
                        "Client registration is inactive",
                    ));
                }
                if query
                    .parameters
                    .redirect_uri
                    .as_ref()
                    .is_none_or(|redirect| !client.redirect_uris.contains(redirect))
                {
                    return Err(ProtocolError::invalid_request(
                        "redirect_uri is not registered for this client",
                    ));
                }
            }
        }
        if let Some(redirect_uri) = query.parameters.redirect_uri.as_deref() {
            self.validate_redirect(redirect_uri)?;
        }
        let details =
            match parse_authorization_details(query.parameters.authorization_details.as_deref()) {
                Ok(details) => details,
                Err(error) => return authorization_error_outcome(&query.parameters, error),
            };
        let code_challenge_method = match query
            .parameters
            .code_challenge_method
            .as_deref()
            .map(parse_code_challenge_method)
            .transpose()
        {
            Ok(method) => method,
            Err(error) => return authorization_error_outcome(&query.parameters, error),
        };
        let request = AuthorizationRequest {
            response_type: response_type.to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri: query.parameters.redirect_uri.clone(),
            scope: query.parameters.scope.clone(),
            state: query.parameters.state.clone(),
            issuer_state: query.parameters.issuer_state.clone(),
            code_challenge: query.parameters.code_challenge.clone(),
            code_challenge_method,
            authorization_details: details,
        };
        let (response, session) = match self
            .engine
            .create_authorization_response(&request, AUTHORIZATION_SESSION_SECONDS)
        {
            Ok(output) => output,
            Err(error) => {
                let error = ProtocolError::native(error.to_string());
                return authorization_error_outcome(&query.parameters, error);
            }
        };
        self.repository
            .save_authorization_session(&AuthorizationSessionWrite {
                id: Uuid::new_v4().to_string(),
                session,
                organization_id: query.parameters.organization_id.clone(),
                scope: query.parameters.scope.clone(),
                state: query.parameters.state.clone(),
            })
            .await
            .map_err(|_| ProtocolError::Unavailable)?;
        let body = serde_json::to_value(&response).map_err(|_| ProtocolError::Unavailable)?;
        let Some(redirect_uri) = query.parameters.redirect_uri.as_deref() else {
            return Ok(AuthorizationOutcome::Json(body));
        };
        let issuer = format!(
            "{}/org/{}",
            self.issuer_base_url,
            query
                .parameters
                .organization_id
                .as_deref()
                .unwrap_or("None")
        );
        let mut parameters = vec![("code", response.code.as_str()), ("iss", issuer.as_str())];
        if let Some(state) = response.state.as_deref().filter(|state| !state.is_empty()) {
            parameters.push(("state", state));
        }
        Ok(AuthorizationOutcome::Redirect(append_query(
            redirect_uri,
            &parameters,
        )?))
    }

    fn validate_redirect(&self, redirect_uri: &str) -> Result<(), ProtocolError> {
        let parsed = Url::parse(redirect_uri)
            .map_err(|_| ProtocolError::invalid_request("redirect_uri must use HTTPS"))?;
        let localhost = match parsed.host() {
            Some(Host::Domain(host)) => host == "localhost",
            Some(Host::Ipv4(address)) => address == Ipv4Addr::LOCALHOST,
            Some(Host::Ipv6(address)) => address == Ipv6Addr::LOCALHOST,
            None => false,
        };
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && localhost) {
            return Err(ProtocolError::invalid_request(
                "redirect_uri must use HTTPS",
            ));
        }
        if !self.allowed_redirect_uris.is_empty() {
            return self
                .allowed_redirect_uris
                .contains(redirect_uri)
                .then_some(())
                .ok_or_else(|| ProtocolError::invalid_request("redirect_uri is not registered"));
        }
        Ok(())
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
        endpoint_path: &str,
    ) -> Result<String, ProtocolError> {
        let token = bearer(headers).ok_or(ProtocolError::InvalidToken)?;
        let grant = self
            .repository
            .access_token_grant(token)
            .await
            .map_err(|_| ProtocolError::Unavailable)?
            .ok_or(ProtocolError::InvalidToken)?;
        let proof = headers
            .get("dpop")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty());
        let endpoint = format!("{}{}", self.issuer_base_url, endpoint_path);
        verify_bound_dpop(
            self.dpop_verifier.as_ref(),
            grant.dpop_jkt.as_deref(),
            proof,
            "POST",
            &endpoint,
        )
        .map_err(|_| ProtocolError::InvalidToken)?;
        Ok(token.to_owned())
    }

    async fn deferred(
        &self,
        token: &str,
        request: DeferredRequest,
    ) -> Result<DeferredOutcome, ProtocolError> {
        let transaction_id = request
            .transaction_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ProtocolError::invalid_request("transaction_id is required"))?;
        let record = self
            .repository
            .deferred_credential(token, &transaction_id)
            .await
            .map_err(|_| ProtocolError::Unavailable)?;
        let record = match record {
            DeferredCredentialLookup::Bound(record) => record,
            DeferredCredentialLookup::Unbound => return Err(ProtocolError::InvalidToken),
            DeferredCredentialLookup::Missing => {
                return Err(ProtocolError::oauth(
                    "invalid_transaction_id",
                    "No transaction found for the given ID",
                ));
            }
        };
        match (record.status, record.credential) {
            (DeferredStatus::Pending | DeferredStatus::Authorized, _) => {
                Ok(DeferredOutcome::Pending(transaction_id))
            }
            (DeferredStatus::Issued, Some(credential)) => Ok(DeferredOutcome::Issued(credential)),
            (status, _) => Err(ProtocolError::oauth(
                "invalid_transaction_id",
                format!("Transaction is in {} state", status.as_str()),
            )),
        }
    }

    async fn notify(&self, token: &str, request: NotificationRequest) -> Result<(), ProtocolError> {
        validate_notification(&request)?;
        let lookup = self
            .repository
            .notification_transaction(token, &request.notification_id)
            .await
            .map_err(|_| ProtocolError::Unavailable)?;
        let transaction_id = match lookup {
            NotificationLookup::Bound(transaction_id) => transaction_id,
            NotificationLookup::Unbound => return Err(ProtocolError::InvalidToken),
            NotificationLookup::Missing => return Err(ProtocolError::InvalidNotificationId),
        };
        self.repository
            .record_notification(&transaction_id, &request)
            .await
            .map_err(|_| ProtocolError::Unavailable)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct DeferredRequest {
    transaction_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorizationOutcome {
    Json(Value),
    Redirect(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DeferredOutcome {
    Pending(String),
    Issued(String),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
enum ProtocolError {
    #[error("{1}")]
    OAuth(&'static str, String),
    #[error("request_uri is invalid or expired")]
    InvalidRequestUri,
    #[error("authorization request storage is unavailable")]
    ParUnavailable,
    #[error("OID4VCI service is temporarily unavailable")]
    Unavailable,
    #[error("client authentication failed")]
    InvalidToken,
    #[error("invalid notification identifier")]
    InvalidNotificationId,
    #[error("invalid notification request")]
    InvalidNotificationRequest,
}

impl ProtocolError {
    fn oauth(code: &'static str, description: impl Into<String>) -> Self {
        Self::OAuth(code, description.into())
    }

    fn invalid_request(description: impl Into<String>) -> Self {
        Self::oauth("invalid_request", description)
    }

    fn native(message: String) -> Self {
        let description = message
            .strip_prefix("Invalid offer: ")
            .unwrap_or(&message)
            .replace("'code'", "code");
        Self::invalid_request(description)
    }

    fn response(&self) -> Response<Body> {
        let (status, value, bearer) = match self {
            Self::OAuth(code, description) => (
                StatusCode::BAD_REQUEST,
                json!({"error": code, "error_description": description}),
                false,
            ),
            Self::InvalidRequestUri => (
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_request", "error_description":"request_uri is invalid or expired"}),
                false,
            ),
            Self::ParUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"temporarily_unavailable", "error_description":"Authorization request storage is unavailable"}),
                false,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"temporarily_unavailable", "error_description":"OID4VCI service is temporarily unavailable"}),
                false,
            ),
            Self::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_token", "error_description":"Client authentication failed"}),
                true,
            ),
            Self::InvalidNotificationId => (
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_notification_id"}),
                false,
            ),
            Self::InvalidNotificationRequest => (
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_notification_request"}),
                false,
            ),
        };
        let mut response = (status, Json(value)).into_response();
        if bearer {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

pub fn router(service: Oid4vciAuthorizationService) -> Router {
    router_with_optional_rate_limit(service, None)
}

pub fn router_with_rate_limit(
    service: Oid4vciAuthorizationService,
    limiter: TokenRateLimiter,
) -> Router {
    router_with_optional_rate_limit(service, Some(limiter))
}

pub(crate) fn router_with_optional_rate_limit(
    service: Oid4vciAuthorizationService,
    limiter: Option<TokenRateLimiter>,
) -> Router {
    let oauth = Router::new()
        .route("/v1/issuance/authorize", get(authorize))
        .route("/v1/issuance/par", post(par))
        .route_layer(middleware::from_fn_with_state(
            limiter,
            token_rate_limit_middleware,
        ));
    oauth
        .merge(
            Router::new()
                .route("/v1/issuance/deferred-credential", post(deferred))
                .route("/v1/issuance/notification", post(notification)),
        )
        .with_state(service)
}

async fn par(
    State(service): State<Oid4vciAuthorizationService>,
    RawQuery(raw_query): RawQuery,
    request: Request,
) -> Response<Body> {
    if !has_content_type(request.headers(), "application/x-www-form-urlencoded") {
        return ProtocolError::invalid_request("Invalid form request body").response();
    }
    let query = parse_par_query(raw_query.as_deref());
    let body = match to_bytes(request.into_body(), TRANSPORT_OWNED_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => {
            return ProtocolError::invalid_request("Pushed authorization request is too large")
                .response();
        }
    };
    let parameters = match parse_authorization_parameters(&body) {
        Ok(parameters) => parameters,
        Err(error) => return error.response(),
    };
    match service.par(parameters, query.issuer_org).await {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(error) => error.response(),
    }
}

async fn authorize(
    State(service): State<Oid4vciAuthorizationService>,
    RawQuery(raw_query): RawQuery,
) -> Response<Body> {
    let query = parse_authorization_query(raw_query.as_deref());
    match service.authorize(query).await {
        Ok(AuthorizationOutcome::Json(value)) => Json(value).into_response(),
        Ok(AuthorizationOutcome::Redirect(location)) => redirect_response(location),
        Err(error) => error.response(),
    }
}

async fn deferred(
    State(service): State<Oid4vciAuthorizationService>,
    request: Request,
) -> Response<Body> {
    let token = match service
        .authenticate(request.headers(), "/v1/issuance/deferred-credential")
        .await
    {
        Ok(token) => token,
        Err(error) => return error.response(),
    };
    let body = match to_bytes(request.into_body(), TRANSPORT_OWNED_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return ProtocolError::invalid_request("Invalid JSON request body").response(),
    };
    let request = match serde_json::from_slice::<DeferredRequest>(&body) {
        Ok(request) => request,
        Err(_) => return ProtocolError::invalid_request("Invalid JSON request body").response(),
    };
    match service.deferred(&token, request).await {
        Ok(DeferredOutcome::Pending(transaction_id)) => {
            let mut response = (
                StatusCode::ACCEPTED,
                Json(json!({"transaction_id": transaction_id})),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            response
        }
        Ok(DeferredOutcome::Issued(credential)) => {
            Json(json!({"credential": credential})).into_response()
        }
        Err(error) => error.response(),
    }
}

async fn notification(
    State(service): State<Oid4vciAuthorizationService>,
    request: Request,
) -> Response<Body> {
    let token = match service
        .authenticate(request.headers(), "/v1/issuance/notification")
        .await
    {
        Ok(token) => token,
        Err(error) => return error.response(),
    };
    if !has_content_type(request.headers(), "application/json") {
        return ProtocolError::InvalidNotificationRequest.response();
    }
    let body = match to_bytes(request.into_body(), TRANSPORT_OWNED_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return ProtocolError::InvalidNotificationRequest.response(),
    };
    let request = match serde_json::from_slice::<NotificationRequest>(&body) {
        Ok(request) => request,
        Err(_) => return ProtocolError::InvalidNotificationRequest.response(),
    };
    match service.notify(&token, request).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.response(),
    }
}

fn has_content_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
        })
}

fn parse_par_query(raw: Option<&str>) -> ParQuery {
    let mut query = ParQuery::default();
    for (name, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        if name == "issuer_org" {
            query.issuer_org = Some(value.into_owned());
        }
    }
    query
}

fn parse_authorization_query(raw: Option<&str>) -> AuthorizationQuery {
    let mut query = AuthorizationQuery::default();
    for (name, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        let value = value.into_owned();
        match name.as_ref() {
            "issuer_org" => query.issuer_org = Some(value),
            "request_uri" => query.request_uri = Some(value),
            name => set_authorization_parameter(&mut query.parameters, name, value),
        }
    }
    query
}

fn parse_authorization_parameters(body: &[u8]) -> Result<AuthorizationParameters, ProtocolError> {
    let body = std::str::from_utf8(body)
        .map_err(|_| ProtocolError::invalid_request("Invalid form request body"))?;
    let mut parameters = AuthorizationParameters::default();
    for (name, value) in url::form_urlencoded::parse(body.as_bytes()) {
        set_authorization_parameter(&mut parameters, name.as_ref(), value.into_owned());
    }
    Ok(parameters)
}

fn set_authorization_parameter(
    parameters: &mut AuthorizationParameters,
    name: &str,
    value: String,
) {
    match name {
        "response_type" => parameters.response_type = Some(value),
        "client_id" => parameters.client_id = Some(value),
        "redirect_uri" => parameters.redirect_uri = Some(value),
        "scope" => parameters.scope = Some(value),
        "state" => parameters.state = Some(value),
        "code_challenge" => parameters.code_challenge = Some(value),
        "code_challenge_method" => parameters.code_challenge_method = Some(value),
        "issuer_state" => parameters.issuer_state = Some(value),
        "authorization_details" => parameters.authorization_details = Some(value),
        "organization_id" => parameters.organization_id = Some(value),
        _ => {}
    }
}

fn redirect_response(location: String) -> Response<Body> {
    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    match HeaderValue::from_str(&location) {
        Ok(location) => {
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => ProtocolError::Unavailable.response(),
    }
}

fn append_query(base: &str, parameters: &[(&str, &str)]) -> Result<String, ProtocolError> {
    Url::parse(base).map_err(|_| ProtocolError::invalid_request("invalid redirect_uri"))?;
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(parameters.iter().copied())
        .finish();
    let separator = if base.contains('?') { '&' } else { '?' };
    Ok(format!("{base}{separator}{encoded}"))
}

fn parse_code_challenge_method(value: &str) -> Result<CodeChallengeMethod, ProtocolError> {
    match value {
        "S256" => Ok(CodeChallengeMethod::S256),
        "plain" => Ok(CodeChallengeMethod::Plain),
        _ => Err(ProtocolError::invalid_request(
            "Unsupported code_challenge_method",
        )),
    }
}

fn parse_authorization_details(
    value: Option<&str>,
) -> Result<Option<Vec<AuthorizationDetail>>, ProtocolError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let decoded = match serde_json::from_str::<Value>(value) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(None),
    };
    serde_json::from_value(decoded)
        .map(Some)
        .map_err(|_| ProtocolError::invalid_request("Invalid authorization_details"))
}

fn authorization_error_outcome(
    parameters: &AuthorizationParameters,
    error: ProtocolError,
) -> Result<AuthorizationOutcome, ProtocolError> {
    let Some(redirect_uri) = parameters.redirect_uri.as_deref() else {
        return Err(error);
    };
    let ProtocolError::OAuth(code, description) = error else {
        return Err(error);
    };
    let mut query = vec![("error", code), ("error_description", description.as_str())];
    if let Some(state) = parameters
        .state
        .as_deref()
        .filter(|state| !state.is_empty())
    {
        query.push(("state", state));
    }
    Ok(AuthorizationOutcome::Redirect(append_query(
        redirect_uri,
        &query,
    )?))
}

fn validate_notification(request: &NotificationRequest) -> Result<(), ProtocolError> {
    if request.notification_id.trim().is_empty()
        || request
            .event_description
            .as_deref()
            .is_some_and(|description| {
                description
                    .bytes()
                    .any(|byte| !matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            })
    {
        return Err(ProtocolError::InvalidNotificationRequest);
    }
    Ok(())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn required(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}
