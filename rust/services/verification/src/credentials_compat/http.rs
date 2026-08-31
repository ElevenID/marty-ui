use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use super::{
    CreateSessionRequest, GovernanceEngine, GovernanceError, GovernancePurpose, GovernanceSnapshot,
    SessionResponse, SubmitPresentationRequest, VerificationResult, VerifyDirectRequest,
    VerifyVdsNcRequest,
};

#[derive(Clone)]
pub struct CompatibilityState {
    pub use_cases: Arc<dyn CompatibilityUseCases>,
    pub governance: Option<GovernanceEngine>,
}

#[async_trait]
pub trait CompatibilityUseCases: Send + Sync {
    async fn create_session(
        &self,
        request: CreateSessionRequest,
        governance: GovernanceSnapshot,
    ) -> Result<SessionResponse, CompatibilityError>;

    async fn submit_presentation(
        &self,
        session_id: &str,
        request: SubmitPresentationRequest,
    ) -> Result<VerificationResult, CompatibilityError>;

    async fn get_session(&self, session_id: &str) -> Result<SessionResponse, CompatibilityError>;

    async fn verify_direct(
        &self,
        request: VerifyDirectRequest,
        governance: GovernanceSnapshot,
    ) -> Result<VerificationResult, CompatibilityError>;

    async fn verify_vds_nc(
        &self,
        request: VerifyVdsNcRequest,
        governance: GovernanceSnapshot,
    ) -> Result<VerificationResult, CompatibilityError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    NotFound,
    Expired,
    Busy,
    Conflict,
    UnsupportedPresentation,
    InvalidPresentation,
    PolicyMismatch,
    UnusableIssuerDid,
    Internal,
}

#[derive(Clone, Copy)]
enum Operation {
    Create,
    Submit,
    Get,
    Direct,
    VdsNc,
}

#[derive(Clone, Copy)]
enum AuthorizationFailure {
    Missing,
    Unauthorized,
    Unavailable,
}

impl AuthorizationFailure {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Missing => (StatusCode::UNAUTHORIZED, "X-API-Key header is missing"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Invalid or unauthorized API key"),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Verification governance is unavailable",
            ),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

impl CompatibilityError {
    fn into_response_for(self, operation: Operation) -> Response {
        let (status, detail) = match (operation, self) {
            (Operation::Create | Operation::Direct, Self::PolicyMismatch) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Verification request does not match its governed policy",
            ),
            (Operation::Submit, Self::NotFound) => {
                (StatusCode::NOT_FOUND, "Verification session not found")
            }
            (Operation::Get, Self::NotFound) => (StatusCode::NOT_FOUND, "Session not found"),
            (Operation::Submit, Self::Expired) => {
                (StatusCode::GONE, "Verification session has expired")
            }
            (Operation::Submit, Self::Busy | Self::Conflict) => (
                StatusCode::CONFLICT,
                "Verification session submission conflicts",
            ),
            (Operation::Submit, Self::UnsupportedPresentation) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Session presentation cannot be bound to the verifier nonce",
            ),
            (Operation::Submit, Self::InvalidPresentation) => {
                (StatusCode::BAD_REQUEST, "Invalid presentation data")
            }
            (Operation::VdsNc, Self::UnusableIssuerDid) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "issuer_did did not resolve to a usable public JWK",
            ),
            (Operation::Create, Self::Internal) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create verification session",
            ),
            (Operation::Submit, Self::Internal) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Presentation submission failed",
            ),
            (Operation::Direct, Self::Internal) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Verification failed")
            }
            (Operation::VdsNc, Self::Internal) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "VDS-NC verification failed",
            ),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Verification failed"),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

pub fn router(state: CompatibilityState) -> Router {
    Router::new()
        .route("/v1/verification/sessions", post(create_session))
        .route(
            "/v1/verification/sessions/{session_id}/submit",
            post(submit_presentation),
        )
        .route("/v1/verification/sessions/{session_id}", get(get_session))
        .route("/v1/verification/verify", post(verify_direct))
        .route("/v1/verification/verify/vds-nc", post(verify_vds_nc))
        .route("/v1/verification/health", get(health))
        .with_state(state)
}

async fn create_session(
    State(state): State<CompatibilityState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let value = match parse_protected_json_syntax(&headers, &body) {
        Ok(value) => value,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::SessionCreate) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
    };
    let request = match value.and_then(|value| serde_json::from_value(value).ok()) {
        Some(request) => request,
        None => return validation_response(),
    };
    match state.use_cases.create_session(request, governance).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::Create),
    }
}

async fn submit_presentation(
    State(state): State<CompatibilityState>,
    Path(session_id): Path<String>,
    request: Result<Json<SubmitPresentationRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(_) => return validation_response(),
    };
    match state
        .use_cases
        .submit_presentation(&session_id, request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::Submit),
    }
}

async fn get_session(
    State(state): State<CompatibilityState>,
    Path(session_id): Path<String>,
) -> Response {
    match state.use_cases.get_session(&session_id).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::Get),
    }
}

async fn verify_direct(
    State(state): State<CompatibilityState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let value = match parse_protected_json_syntax(&headers, &body) {
        Ok(value) => value,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::Direct) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
    };
    let request = match value.and_then(|value| serde_json::from_value(value).ok()) {
        Some(request) => request,
        None => return validation_response(),
    };
    match state.use_cases.verify_direct(request, governance).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::Direct),
    }
}

async fn verify_vds_nc(
    State(state): State<CompatibilityState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let value = match parse_protected_json_syntax(&headers, &body) {
        Ok(value) => value,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::VdsNc) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
    };
    let request = match value.and_then(|value| serde_json::from_value(value).ok()) {
        Some(request) => request,
        None => return validation_response(),
    };
    match state.use_cases.verify_vds_nc(request, governance).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::VdsNc),
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "healthy"}))
}

fn authorize(
    state: &CompatibilityState,
    headers: &HeaderMap,
    purpose: GovernancePurpose,
) -> Result<GovernanceSnapshot, AuthorizationFailure> {
    let api_key = match headers.get("x-api-key") {
        None => return Err(AuthorizationFailure::Missing),
        Some(value) => value
            .to_str()
            .map_err(|_| AuthorizationFailure::Unauthorized)?,
    };
    if api_key.is_empty() {
        return Err(AuthorizationFailure::Missing);
    }
    let Some(governance) = &state.governance else {
        return Err(AuthorizationFailure::Unavailable);
    };
    governance.authorize(api_key, purpose).map_err(|error| {
        if error == GovernanceError::Configuration {
            AuthorizationFailure::Unavailable
        } else {
            AuthorizationFailure::Unauthorized
        }
    })
}

fn validation_response() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail": "Request validation failed"})),
    )
        .into_response()
}

fn parse_protected_json_syntax(
    headers: &HeaderMap,
    body: &[u8],
) -> serde_json::Result<Option<serde_json::Value>> {
    if body.is_empty() || !has_json_media_type(headers) {
        return Ok(None);
    }
    serde_json::from_slice(body).map(Some)
}

fn has_json_media_type(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|media_type| {
            media_type.eq_ignore_ascii_case("application/json")
                || media_type.to_ascii_lowercase().ends_with("+json")
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::{
        body::{to_bytes, Body},
        http::{HeaderValue, Request},
    };
    use tower::ServiceExt;

    use super::*;

    struct MockUseCases;

    struct RecordingUseCases {
        calls: Arc<Mutex<Vec<String>>>,
    }

    struct ErrorUseCases {
        error: CompatibilityError,
    }

    fn session() -> SessionResponse {
        SessionResponse {
            id: "session-1".into(),
            organization_id: "123e4567-e89b-42d3-a456-426614174000".into(),
            verifier_did: "did:web:verifier.example".into(),
            status: "PENDING".into(),
            request_uri: "https://verifier.example/request/session-1".into(),
            nonce: "nonce".into(),
            expires_at: "2026-08-30T12:10:00Z".into(),
            created_at: "2026-08-30T12:00:00Z".into(),
        }
    }

    #[async_trait]
    impl CompatibilityUseCases for MockUseCases {
        async fn create_session(
            &self,
            _: CreateSessionRequest,
            _: GovernanceSnapshot,
        ) -> Result<SessionResponse, CompatibilityError> {
            Ok(session())
        }

        async fn submit_presentation(
            &self,
            _: &str,
            _: SubmitPresentationRequest,
        ) -> Result<VerificationResult, CompatibilityError> {
            Ok(VerificationResult::from_canonical(None, None, None))
        }

        async fn get_session(&self, _: &str) -> Result<SessionResponse, CompatibilityError> {
            Ok(session())
        }

        async fn verify_direct(
            &self,
            _: VerifyDirectRequest,
            _: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            Ok(VerificationResult::from_canonical(None, None, None))
        }

        async fn verify_vds_nc(
            &self,
            _: VerifyVdsNcRequest,
            _: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            Ok(VerificationResult::from_canonical(None, None, None))
        }
    }

    #[async_trait]
    impl CompatibilityUseCases for RecordingUseCases {
        async fn create_session(
            &self,
            _: CreateSessionRequest,
            governance: GovernanceSnapshot,
        ) -> Result<SessionResponse, CompatibilityError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("create:{}", governance.purpose()));
            Ok(session())
        }

        async fn submit_presentation(
            &self,
            session_id: &str,
            _: SubmitPresentationRequest,
        ) -> Result<VerificationResult, CompatibilityError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("submit:{session_id}"));
            Ok(VerificationResult::from_canonical(None, None, None))
        }

        async fn get_session(
            &self,
            session_id: &str,
        ) -> Result<SessionResponse, CompatibilityError> {
            self.calls.lock().unwrap().push(format!("get:{session_id}"));
            Ok(session())
        }

        async fn verify_direct(
            &self,
            _: VerifyDirectRequest,
            governance: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("direct:{}", governance.purpose()));
            Ok(VerificationResult::from_canonical(None, None, None))
        }

        async fn verify_vds_nc(
            &self,
            _: VerifyVdsNcRequest,
            governance: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("vds:{}", governance.purpose()));
            Ok(VerificationResult::from_canonical(None, None, None))
        }
    }

    #[async_trait]
    impl CompatibilityUseCases for ErrorUseCases {
        async fn create_session(
            &self,
            _: CreateSessionRequest,
            _: GovernanceSnapshot,
        ) -> Result<SessionResponse, CompatibilityError> {
            Err(self.error.clone())
        }

        async fn submit_presentation(
            &self,
            _: &str,
            _: SubmitPresentationRequest,
        ) -> Result<VerificationResult, CompatibilityError> {
            Err(self.error.clone())
        }

        async fn get_session(&self, _: &str) -> Result<SessionResponse, CompatibilityError> {
            Err(self.error.clone())
        }

        async fn verify_direct(
            &self,
            _: VerifyDirectRequest,
            _: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            Err(self.error.clone())
        }

        async fn verify_vds_nc(
            &self,
            _: VerifyVdsNcRequest,
            _: GovernanceSnapshot,
        ) -> Result<VerificationResult, CompatibilityError> {
            Err(self.error.clone())
        }
    }

    fn app(governance: bool) -> Router {
        app_with(Arc::new(MockUseCases), governance)
    }

    fn app_with(use_cases: Arc<dyn CompatibilityUseCases>, governance: bool) -> Router {
        let mut fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let direct = fixture["governance"]["clients"][0]["purposes"]["verification.direct"].clone();
        fixture["governance"]["clients"][0]["purposes"]["verification.vds-nc"] = direct;
        let engine =
            governance.then(|| GovernanceEngine::new(&fixture["governance"].to_string()).unwrap());
        router(CompatibilityState {
            use_cases,
            governance: engine,
        })
    }

    fn create_request(api_key: Option<&str>) -> Request<Body> {
        let mut request = Request::post("/v1/verification/sessions")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "verifier_did": "did:web:verifier.example",
                    "presentation_definition": {"id":"pd-1","input_descriptors":[]}
                })
                .to_string(),
            ))
            .unwrap();
        if let Some(api_key) = api_key {
            request
                .headers_mut()
                .insert("x-api-key", api_key.parse().unwrap());
        }
        request
    }

    fn json_request(
        method: &str,
        path: &str,
        body: serde_json::Value,
        auth: bool,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if auth {
            request.headers_mut().insert(
                "x-api-key",
                HeaderValue::from_static("purpose-scoped-test-key"),
            );
        }
        request
    }

    fn direct_body() -> serde_json::Value {
        json!({
            "presentation": "vp.jwt",
            "presentation_definition": {"id":"pd-1","input_descriptors":[]},
            "verifier_did": "did:web:verifier.example"
        })
    }

    fn vds_body() -> serde_json::Value {
        json!({"barcode":"header~payload~signature","issuer_did":"did:web:issuer.example"})
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn public_auth_errors_match_the_released_contract() {
        let response = app(true).oneshot(create_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await["detail"],
            "X-API-Key header is missing"
        );

        let response = app(true)
            .oneshot(create_request(Some("wrong")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await["detail"],
            "Invalid or unauthorized API key"
        );

        let response = app(false)
            .oneshot(create_request(Some("anything")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_json(response).await["detail"],
            "Verification governance is unavailable"
        );

        let response = app(false).oneshot(create_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await["detail"],
            "X-API-Key header is missing"
        );

        let mut request = create_request(None);
        request
            .headers_mut()
            .insert("x-api-key", HeaderValue::from_bytes(&[0xff]).unwrap());
        let response = app(false).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await["detail"],
            "Invalid or unauthorized API key"
        );
    }

    #[tokio::test]
    async fn protected_routes_parse_syntax_then_authorize_then_validate_schema() {
        for path in [
            "/v1/verification/sessions",
            "/v1/verification/verify",
            "/v1/verification/verify/vds-nc",
        ] {
            let response = app(true)
                .oneshot(json_request(
                    "POST",
                    path,
                    json!({"well_formed_but_invalid":true}),
                    false,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(
                response_json(response).await,
                json!({"detail":"X-API-Key header is missing"})
            );

            let response = app(true)
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );

            for body in ["", "{", r#"{"well_formed_but_invalid":true}"#] {
                let response = app(true)
                    .oneshot(
                        Request::post(path)
                            .header("content-type", "text/plain")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            }

            let response = app(true)
                .oneshot(
                    Request::post(path)
                        .header("content-type", "text/plain")
                        .header("x-api-key", "purpose-scoped-test-key")
                        .body(Body::from(r#"{"well_formed_but_invalid":true}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );

            let response = app(true)
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[tokio::test]
    async fn authorized_create_and_unscoped_health_preserve_shapes() {
        let response = app(true)
            .oneshot(create_request(Some("purpose-scoped-test-key")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["id"], "session-1");

        let response = app(false)
            .oneshot(
                Request::get("/v1/verification/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await, json!({"status":"healthy"}));
    }

    #[tokio::test]
    async fn every_route_preserves_auth_mode_forwarding_and_governed_purpose() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let use_cases = Arc::new(RecordingUseCases {
            calls: calls.clone(),
        });
        let requests = [
            create_request(Some("purpose-scoped-test-key")),
            json_request(
                "POST",
                "/v1/verification/sessions/session-submit/submit",
                json!({"presentation":"vp.jwt"}),
                false,
            ),
            json_request(
                "GET",
                "/v1/verification/sessions/session-get",
                json!(null),
                false,
            ),
            json_request("POST", "/v1/verification/verify", direct_body(), true),
            json_request("POST", "/v1/verification/verify/vds-nc", vds_body(), true),
        ];
        for request in requests {
            let response = app_with(use_cases.clone(), true)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "create:verification.session.create",
                "submit:session-submit",
                "get:session-get",
                "direct:verification.direct",
                "vds:verification.vds-nc",
            ]
        );
    }

    #[tokio::test]
    async fn every_json_route_rejects_malformed_or_unknown_fields() {
        let cases = [
            ("/v1/verification/sessions", true),
            ("/v1/verification/sessions/session-1/submit", false),
            ("/v1/verification/verify", true),
            ("/v1/verification/verify/vds-nc", true),
        ];
        for (path, auth) in cases {
            for body in [json!({"unexpected":true}), json!("not-an-object")] {
                let response = app(true)
                    .oneshot(json_request("POST", path, body, auth))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                assert_eq!(
                    response_json(response).await,
                    json!({"detail":"Request validation failed"})
                );
            }
        }
    }

    #[tokio::test]
    async fn declared_errors_are_stable_at_the_route_boundary() {
        let cases = [
            (
                "POST",
                "/v1/verification/sessions",
                json!({
                    "verifier_did":"did:web:verifier.example",
                    "presentation_definition":{"id":"pd-1","input_descriptors":[]}
                }),
                true,
                CompatibilityError::PolicyMismatch,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Verification request does not match its governed policy",
            ),
            (
                "POST",
                "/v1/verification/sessions",
                json!({
                    "verifier_did":"did:web:verifier.example",
                    "presentation_definition":{"id":"pd-1","input_descriptors":[]}
                }),
                true,
                CompatibilityError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create verification session",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::NotFound,
                StatusCode::NOT_FOUND,
                "Verification session not found",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::Expired,
                StatusCode::GONE,
                "Verification session has expired",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::Busy,
                StatusCode::CONFLICT,
                "Verification session submission conflicts",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::Conflict,
                StatusCode::CONFLICT,
                "Verification session submission conflicts",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::UnsupportedPresentation,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Session presentation cannot be bound to the verifier nonce",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::InvalidPresentation,
                StatusCode::BAD_REQUEST,
                "Invalid presentation data",
            ),
            (
                "POST",
                "/v1/verification/sessions/id/submit",
                json!({"presentation":"vp.jwt"}),
                false,
                CompatibilityError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Presentation submission failed",
            ),
            (
                "GET",
                "/v1/verification/sessions/id",
                json!(null),
                false,
                CompatibilityError::NotFound,
                StatusCode::NOT_FOUND,
                "Session not found",
            ),
            (
                "POST",
                "/v1/verification/verify",
                direct_body(),
                true,
                CompatibilityError::PolicyMismatch,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Verification request does not match its governed policy",
            ),
            (
                "POST",
                "/v1/verification/verify",
                direct_body(),
                true,
                CompatibilityError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed",
            ),
            (
                "POST",
                "/v1/verification/verify/vds-nc",
                vds_body(),
                true,
                CompatibilityError::UnusableIssuerDid,
                StatusCode::UNPROCESSABLE_ENTITY,
                "issuer_did did not resolve to a usable public JWK",
            ),
            (
                "POST",
                "/v1/verification/verify/vds-nc",
                vds_body(),
                true,
                CompatibilityError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "VDS-NC verification failed",
            ),
        ];
        for (method, path, body, auth, error, status, detail) in cases {
            let response = app_with(Arc::new(ErrorUseCases { error }), true)
                .oneshot(json_request(method, path, body, auth))
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{method} {path}");
            assert_eq!(
                response_json(response).await["detail"],
                detail,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn operation_specific_error_mapping_is_exact_and_non_leaking() {
        let cases = [
            (
                Operation::Submit,
                CompatibilityError::NotFound,
                StatusCode::NOT_FOUND,
                "Verification session not found",
            ),
            (
                Operation::Submit,
                CompatibilityError::Expired,
                StatusCode::GONE,
                "Verification session has expired",
            ),
            (
                Operation::Submit,
                CompatibilityError::Busy,
                StatusCode::CONFLICT,
                "Verification session submission conflicts",
            ),
            (
                Operation::Direct,
                CompatibilityError::PolicyMismatch,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Verification request does not match its governed policy",
            ),
        ];
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for (operation, error, status, detail) in cases {
            let response = error.into_response_for(operation);
            assert_eq!(response.status(), status);
            assert_eq!(runtime.block_on(response_json(response))["detail"], detail);
        }
    }
}
