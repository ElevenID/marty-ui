use std::sync::Arc;

use async_trait::async_trait;
use axum::{
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
    Unprocessable(&'static str),
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
            (Operation::VdsNc, Self::Unprocessable(detail)) => {
                (StatusCode::UNPROCESSABLE_ENTITY, detail)
            }
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
    request: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::SessionCreate) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
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
    request: Result<Json<VerifyDirectRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::Direct) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
    };
    match state.use_cases.verify_direct(request, governance).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response_for(Operation::Direct),
    }
}

async fn verify_vds_nc(
    State(state): State<CompatibilityState>,
    headers: HeaderMap,
    request: Result<Json<VerifyVdsNcRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(_) => return validation_response(),
    };
    let governance = match authorize(&state, &headers, GovernancePurpose::VdsNc) {
        Ok(governance) => governance,
        Err(error) => return error.into_response(),
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
    let Some(governance) = &state.governance else {
        return Err(AuthorizationFailure::Unavailable);
    };
    let Some(api_key) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return Err(AuthorizationFailure::Missing);
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

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;

    struct MockUseCases;

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

    fn app(governance: bool) -> Router {
        let fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let engine =
            governance.then(|| GovernanceEngine::new(&fixture["governance"].to_string()).unwrap());
        router(CompatibilityState {
            use_cases: Arc::new(MockUseCases),
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
