//! Internal HTTP host behind the authenticated public Gateway.
//! The service token is mandatory in every environment. Only the Gateway's
//! independently authenticated session observation can supply actor context.

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
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    approval::{
        ApprovalConfirmation, ApprovalProducerError, ApprovalReview, ApprovalReviewRequest,
        ApprovalWithdrawal, AuthenticatedApprovalSession, ExplicitApprovalConfirmation,
    },
    approval_postgres::PgOrganizationApprovalService,
    CommandGrantReference, MAX_GRANT_REVISION,
};

const MAX_APPROVAL_BODY_BYTES: usize = 8192;

#[async_trait]
pub trait ApprovalHttpApplication: Send + Sync {
    async fn review(
        &self,
        session: &AuthenticatedApprovalSession,
        grant: &CommandGrantReference,
    ) -> Result<ApprovalReview, ApprovalProducerError>;
    async fn confirm(
        &self,
        session: &AuthenticatedApprovalSession,
        grant_id: Uuid,
        review_id: Uuid,
        confirmation: &ExplicitApprovalConfirmation,
    ) -> Result<ApprovalConfirmation, ApprovalProducerError>;
    async fn withdraw(
        &self,
        session: &AuthenticatedApprovalSession,
        grant_id: Uuid,
        confirmation_id: Uuid,
    ) -> Result<ApprovalWithdrawal, ApprovalProducerError>;
}

#[async_trait]
impl ApprovalHttpApplication for PgOrganizationApprovalService {
    async fn review(
        &self,
        session: &AuthenticatedApprovalSession,
        grant: &CommandGrantReference,
    ) -> Result<ApprovalReview, ApprovalProducerError> {
        PgOrganizationApprovalService::review(self, session, grant).await
    }
    async fn confirm(
        &self,
        session: &AuthenticatedApprovalSession,
        grant_id: Uuid,
        review_id: Uuid,
        confirmation: &ExplicitApprovalConfirmation,
    ) -> Result<ApprovalConfirmation, ApprovalProducerError> {
        PgOrganizationApprovalService::confirm(self, session, grant_id, review_id, confirmation)
            .await
    }
    async fn withdraw(
        &self,
        session: &AuthenticatedApprovalSession,
        grant_id: Uuid,
        confirmation_id: Uuid,
    ) -> Result<ApprovalWithdrawal, ApprovalProducerError> {
        PgOrganizationApprovalService::withdraw(self, session, grant_id, confirmation_id).await
    }
}

#[derive(Clone)]
pub struct ApprovalHttpState {
    application: Arc<dyn ApprovalHttpApplication>,
    service_authenticator: Arc<ServiceTokenAuthenticator>,
    organization_id: Uuid,
}

impl ApprovalHttpState {
    pub fn new(
        application: Arc<dyn ApprovalHttpApplication>,
        service_token: String,
        organization_id: Uuid,
    ) -> Result<Self, ApprovalProducerError> {
        if organization_id.is_nil()
            || !(32..=1024).contains(&service_token.len())
            || !service_token.bytes().all(|v| (0x21..=0x7e).contains(&v))
        {
            return Err(ApprovalProducerError::InvalidInput);
        }
        let service_authenticator = ServiceTokenAuthenticator::new(Some(service_token), true)
            .map_err(|_| ApprovalProducerError::InvalidInput)?;
        Ok(Self {
            application,
            service_authenticator: Arc::new(service_authenticator),
            organization_id,
        })
    }
}

pub fn organization_approval_router(state: ApprovalHttpState) -> Router {
    Router::new()
        .route("/v1/organizations/{organization_id}/delegation-grants/{grant_id}/approval-reviews", post(review))
        .route("/v1/organizations/{organization_id}/delegation-grants/{grant_id}/approval-reviews/{review_id}/confirm", post(confirm))
        .route("/v1/organizations/{organization_id}/delegation-grants/{grant_id}/approval-confirmations/{confirmation_id}/withdraw", post(withdraw))
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

async fn review(
    State(state): State<ApprovalHttpState>,
    Path((organization, grant)): Path<(String, String)>,
    request: Request,
) -> Result<Json<ApprovalReview>, ApprovalHttpError> {
    let session = authenticate(&state, &organization, request.headers())?;
    let grant_id = canonical_uuid(&grant)?;
    let body = document(request).await?;
    let input: ApprovalReviewRequest = decode(body)?;
    if input.grant.id != grant_id
        || !(1..=MAX_GRANT_REVISION).contains(&input.grant.revision)
        || !crate::consent::valid_digest(&input.grant.terms_digest)
    {
        return Err(invalid());
    }
    Ok(Json(
        state.application.review(&session, &input.grant).await?,
    ))
}

async fn confirm(
    State(state): State<ApprovalHttpState>,
    Path((organization, grant, review)): Path<(String, String, String)>,
    request: Request,
) -> Result<Json<ApprovalConfirmation>, ApprovalHttpError> {
    let session = authenticate(&state, &organization, request.headers())?;
    let grant_id = canonical_uuid(&grant)?;
    let review_id = canonical_uuid(&review)?;
    let input: ExplicitApprovalConfirmation = decode(document(request).await?)?;
    if input.confirmation_id.is_nil() || !crate::consent::valid_digest(&input.terms_digest) {
        return Err(invalid());
    }
    // Do not cancel a committing transaction with an HTTP timeout. The producer
    // itself enforces the session/authority deadlines at its write boundary.
    Ok(Json(
        state
            .application
            .confirm(&session, grant_id, review_id, &input)
            .await?,
    ))
}

async fn withdraw(
    State(state): State<ApprovalHttpState>,
    Path((organization, grant, confirmation)): Path<(String, String, String)>,
    request: Request,
) -> Result<Json<ApprovalWithdrawal>, ApprovalHttpError> {
    let session = authenticate(&state, &organization, request.headers())?;
    let grant_id = canonical_uuid(&grant)?;
    let confirmation_id = canonical_uuid(&confirmation)?;
    if document(request).await? != json!({}) {
        return Err(invalid());
    }
    Ok(Json(
        state
            .application
            .withdraw(&session, grant_id, confirmation_id)
            .await?,
    ))
}

fn authenticate(
    state: &ApprovalHttpState,
    organization: &str,
    headers: &HeaderMap,
) -> Result<AuthenticatedApprovalSession, ApprovalHttpError> {
    let token = single_header(headers, "x-service-token").map_err(|_| authentication_required())?;
    state
        .service_authenticator
        .authenticate(Some(token))
        .map_err(|_| authentication_required())?;
    if headers.contains_key("x-api-key-id") {
        return Err(ApprovalProducerError::AccessDenied.into());
    }
    let organization_id = canonical_uuid(organization)?;
    if organization_id != state.organization_id
        || single_header(headers, "x-marty-approval-organization-id")? != organization
    {
        return Err(ApprovalProducerError::AccessDenied.into());
    }
    let user = canonical_uuid(single_header(headers, "x-marty-approval-user-id")?)?;
    let session_ref = single_header(headers, "x-marty-approval-session-ref")?.to_owned();
    let observed_at = timestamp(single_header(headers, "x-marty-approval-observed-at")?)?;
    let valid_until = timestamp(single_header(headers, "x-marty-approval-valid-until")?)?;
    let session = AuthenticatedApprovalSession::from_authenticated_gateway_context(
        organization_id,
        user,
        session_ref,
        observed_at,
        valid_until,
    )?;
    session.check(organization_id, Utc::now())?;
    Ok(session)
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, ApprovalHttpError> {
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

fn canonical_uuid(value: &str) -> Result<Uuid, ApprovalHttpError> {
    let id = Uuid::parse_str(value).map_err(|_| invalid())?;
    if id.is_nil() || id.to_string() != value {
        return Err(invalid());
    }
    Ok(id)
}

fn timestamp(value: &str) -> Result<DateTime<Utc>, ApprovalHttpError> {
    if value.len() > 64 || !value.ends_with('Z') {
        return Err(invalid());
    }
    let value = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid())?
        .with_timezone(&Utc);
    if !crate::consent::valid_time(value) {
        return Err(invalid());
    }
    Ok(value)
}

async fn document(request: Request) -> Result<Value, ApprovalHttpError> {
    if request.uri().query().is_some() {
        return Err(invalid());
    }
    let content_type = single_header(request.headers(), "content-type")?;
    if !content_type
        .split(';')
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ApprovalHttpError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "approval_json_required",
        ));
    }
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_APPROVAL_BODY_BYTES),
    )
    .await
    .map_err(|_| ApprovalHttpError(StatusCode::REQUEST_TIMEOUT, "approval_body_timeout"))?
    .map_err(|_| ApprovalHttpError(StatusCode::PAYLOAD_TOO_LARGE, "approval_body_too_large"))?;
    crate::wire::read_document(&bytes).map_err(|_| invalid())
}

fn decode<T: DeserializeOwned + Serialize>(body: Value) -> Result<T, ApprovalHttpError> {
    let value: T = serde_json::from_value(body.clone()).map_err(|_| invalid())?;
    if serde_json::to_value(&value).map_err(|_| invalid())? != body {
        return Err(invalid());
    }
    Ok(value)
}

#[derive(Debug)]
pub struct ApprovalHttpError(StatusCode, &'static str);
fn invalid() -> ApprovalHttpError {
    ApprovalHttpError(StatusCode::BAD_REQUEST, "invalid_approval_request")
}
fn authentication_required() -> ApprovalHttpError {
    ApprovalHttpError(
        StatusCode::UNAUTHORIZED,
        "approval_service_authentication_required",
    )
}
impl From<ApprovalProducerError> for ApprovalHttpError {
    fn from(error: ApprovalProducerError) -> Self {
        match error {
            ApprovalProducerError::InvalidInput => invalid(),
            ApprovalProducerError::AccessDenied => {
                Self(StatusCode::FORBIDDEN, "approval_access_denied")
            }
            ApprovalProducerError::Conflict => {
                Self(StatusCode::CONFLICT, "approval_binding_conflict")
            }
            ApprovalProducerError::NotFound => Self(StatusCode::NOT_FOUND, "approval_not_found"),
            ApprovalProducerError::Stale => Self(StatusCode::CONFLICT, "approval_expired"),
            ApprovalProducerError::Unavailable | ApprovalProducerError::NotReady => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_source_unavailable",
            ),
        }
    }
}
impl IntoResponse for ApprovalHttpError {
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
    const GRANT: &str = "f70222c0-c32c-4699-9ff2-afc8b0066008";
    const REVIEW: &str = "6ef85fbe-ea26-461f-be20-7961d597a857";
    const TOKEN: &str = "synthetic-approval-internal-service-token";

    #[derive(Default)]
    struct CountingApplication(AtomicUsize);
    #[async_trait]
    impl ApprovalHttpApplication for CountingApplication {
        async fn review(
            &self,
            session: &AuthenticatedApprovalSession,
            grant: &CommandGrantReference,
        ) -> Result<ApprovalReview, ApprovalProducerError> {
            assert_eq!(session.user_id().to_string(), USER);
            assert_eq!(grant.id.to_string(), GRANT);
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ApprovalProducerError::Unavailable)
        }
        async fn confirm(
            &self,
            _: &AuthenticatedApprovalSession,
            grant: Uuid,
            review: Uuid,
            _: &ExplicitApprovalConfirmation,
        ) -> Result<ApprovalConfirmation, ApprovalProducerError> {
            assert_eq!(grant.to_string(), GRANT);
            assert_eq!(review.to_string(), REVIEW);
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ApprovalProducerError::Conflict)
        }
        async fn withdraw(
            &self,
            _: &AuthenticatedApprovalSession,
            _: Uuid,
            _: Uuid,
        ) -> Result<ApprovalWithdrawal, ApprovalProducerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ApprovalProducerError::NotFound)
        }
    }
    fn setup() -> (Router, Arc<CountingApplication>) {
        let application = Arc::new(CountingApplication::default());
        let state = ApprovalHttpState::new(application.clone(), TOKEN.into(), ORG.parse().unwrap())
            .unwrap();
        (organization_approval_router(state), application)
    }
    fn request(body: String) -> Request<Body> {
        let now = Utc::now();
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/organizations/{ORG}/delegation-grants/{GRANT}/approval-reviews"
            ))
            .header("content-type", "application/json")
            .header("x-service-token", TOKEN)
            .header("x-marty-approval-organization-id", ORG)
            .header("x-marty-approval-user-id", USER)
            .header(
                "x-marty-approval-session-ref",
                format!("urn:marty:session:sha256:{}", "b".repeat(64)),
            )
            .header(
                "x-marty-approval-observed-at",
                (now - Duration::seconds(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .header(
                "x-marty-approval-valid-until",
                (now + Duration::seconds(20)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .body(Body::from(body))
            .unwrap()
    }
    fn body() -> String {
        json!({"grant":{"id":GRANT,"revision":1,"terms_digest":format!("sha256:{}","a".repeat(64))}}).to_string()
    }
    #[tokio::test]
    async fn requires_service_authentication_and_one_unambiguous_context() {
        for field in [
            "x-service-token",
            "x-marty-approval-user-id",
            "x-marty-approval-session-ref",
        ] {
            for duplicate in [false, true] {
                let (router, application) = setup();
                let mut req = request(body());
                if duplicate {
                    let v = req.headers()[field].clone();
                    req.headers_mut().append(field, v);
                } else {
                    req.headers_mut().remove(field);
                }
                assert!(router
                    .oneshot(req)
                    .await
                    .unwrap()
                    .status()
                    .is_client_error());
                assert_eq!(application.0.load(Ordering::SeqCst), 0);
            }
        }
    }
    #[tokio::test]
    async fn strict_bytes_reject_duplicates_unknowns_wrong_path_and_unsafe_revision() {
        for body in [
            body().replace("\"revision\":1", "\"revision\":1,\"revision\":1"),
            body().replace("\"revision\":1", "\"revision\":1.0"),
            body().replace("\"revision\":1", "\"revision\":9007199254740992"),
            body().replace(GRANT, REVIEW),
            body().replacen("{", "{\"actor\":\"trusted\",", 1),
        ] {
            let (router, application) = setup();
            assert_eq!(
                router.oneshot(request(body)).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(application.0.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn expired_context_and_tenant_substitution_never_reach_producer() {
        for field in [
            "x-marty-approval-organization-id",
            "x-marty-approval-valid-until",
            "x-api-key-id",
        ] {
            let (router, application) = setup();
            let mut req = request(body());
            let value = match field {
                "x-marty-approval-organization-id" => REVIEW.to_owned(),
                "x-api-key-id" => "machine-key".into(),
                _ => (Utc::now() - Duration::seconds(2))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            };
            req.headers_mut().insert(field, value.parse().unwrap());
            assert!(router
                .oneshot(req)
                .await
                .unwrap()
                .status()
                .is_client_error());
            assert_eq!(application.0.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn authorized_review_preserves_tenant_actor_and_source_failure() {
        let (router, application) = setup();
        let response = router.oneshot(request(body())).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(application.0.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn confirm_requires_explicit_decision_and_retains_both_route_bindings() {
        for decision in ["CONFIRM", "LOGIN_SUCCEEDED"] {
            let (router, application) = setup();
            let mut req = request(json!({"confirmation_id":Uuid::new_v4(),"terms_digest":format!("sha256:{}","a".repeat(64)),"decision":decision}).to_string());
            *req.uri_mut() = format!("/v1/organizations/{ORG}/delegation-grants/{GRANT}/approval-reviews/{REVIEW}/confirm").parse().unwrap();
            let response = router.oneshot(req).await.unwrap();
            assert_eq!(
                response.status(),
                if decision == "CONFIRM" {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                }
            );
            assert_eq!(
                application.0.load(Ordering::SeqCst),
                usize::from(decision == "CONFIRM")
            );
        }
    }
}
