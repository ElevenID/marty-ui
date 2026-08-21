use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tonic::{Request, Response, Status};

use crate::{
    auth_proto::{
        auth_service_server::AuthService, AuthStatusResponse, CreateSessionRequest,
        CreateSessionResponse, CredentialVerifiedRequest, CredentialVerifiedResponse,
        GetAuthStatusRequest, HealthCheckRequest, HealthCheckResponse, InvalidateSessionRequest,
        InvalidateSessionResponse, UserInfo, ValidateSessionRequest, ValidateSessionResponse,
    },
    AuthApplication, AuthApplicationError, AuthenticatedUser,
};

pub const AUTH_GRPC_METHODS: &[&str] = &[
    "ValidateSession",
    "CreateSession",
    "InvalidateSession",
    "GetAuthStatus",
    "CredentialVerified",
    "HealthCheck",
];

#[async_trait]
pub trait AuthSessionService: Send + Sync {
    async fn validate_session(&self, session_id: &str) -> Result<Option<crate::Session>, Status>;
    async fn invalidate_session(&self, session_id: &str) -> Result<bool, Status>;
}

#[async_trait]
impl AuthSessionService for AuthApplication {
    async fn validate_session(&self, session_id: &str) -> Result<Option<crate::Session>, Status> {
        self.validate_session(session_id, Utc::now())
            .await
            .map_err(application_status)
    }

    async fn invalidate_session(&self, session_id: &str) -> Result<bool, Status> {
        self.invalidate_session(session_id)
            .await
            .map_err(application_status)
    }
}

#[derive(Clone)]
pub struct AuthGrpcService {
    application: Arc<dyn AuthSessionService>,
}

impl AuthGrpcService {
    #[must_use]
    pub fn new(application: Arc<dyn AuthSessionService>) -> Self {
        Self { application }
    }
}

#[tonic::async_trait]
impl AuthService for AuthGrpcService {
    async fn validate_session(
        &self,
        request: Request<ValidateSessionRequest>,
    ) -> Result<Response<ValidateSessionResponse>, Status> {
        let session = self
            .application
            .validate_session(&request.get_ref().session_id)
            .await?;
        let response = session.map_or_else(
            || ValidateSessionResponse {
                valid: false,
                user: None,
                expires_at: String::new(),
            },
            |session| ValidateSessionResponse {
                valid: true,
                user: Some(user_info(&session.user)),
                expires_at: session.expires_at.to_rfc3339(),
            },
        );
        Ok(Response::new(response))
    }

    async fn create_session(
        &self,
        _request: Request<CreateSessionRequest>,
    ) -> Result<Response<CreateSessionResponse>, Status> {
        Err(Status::unimplemented(
            "Direct session creation is retired; use an authoritative login flow",
        ))
    }

    async fn invalidate_session(
        &self,
        request: Request<InvalidateSessionRequest>,
    ) -> Result<Response<InvalidateSessionResponse>, Status> {
        let success = self
            .application
            .invalidate_session(&request.get_ref().session_id)
            .await?;
        Ok(Response::new(InvalidateSessionResponse { success }))
    }

    async fn get_auth_status(
        &self,
        request: Request<GetAuthStatusRequest>,
    ) -> Result<Response<AuthStatusResponse>, Status> {
        let session = self
            .application
            .validate_session(&request.get_ref().session_id)
            .await?;
        let response = session.map_or_else(
            || AuthStatusResponse {
                authenticated: false,
                user: None,
            },
            |session| AuthStatusResponse {
                authenticated: true,
                user: Some(user_info(&session.user)),
            },
        );
        Ok(Response::new(response))
    }

    async fn credential_verified(
        &self,
        _request: Request<CredentialVerifiedRequest>,
    ) -> Result<Response<CredentialVerifiedResponse>, Status> {
        Err(Status::unimplemented(
            "The gRPC credential callback is retired; use the authenticated internal HTTP callback",
        ))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

fn user_info(user: &AuthenticatedUser) -> UserInfo {
    UserInfo {
        user_id: user.user_id.clone(),
        email: user.email.clone(),
        username: user.username.clone().unwrap_or_default(),
        given_name: user.given_name.clone().unwrap_or_default(),
        family_name: user.family_name.clone().unwrap_or_default(),
        user_type: user.user_type.as_str().into(),
        applicant_id: user.applicant_id.clone().unwrap_or_default(),
        roles: user.roles.clone(),
        organization_id: user.organization_id.clone().unwrap_or_default(),
        organization_name: user.organization_name.clone().unwrap_or_default(),
        onboarding_completed: user.onboarding_completed.is_some(),
        picture: user.picture.clone().unwrap_or_default(),
    }
}

fn application_status(error: AuthApplicationError) -> Status {
    match error {
        AuthApplicationError::InvalidState
        | AuthApplicationError::ExpiredState
        | AuthApplicationError::MissingNonce
        | AuthApplicationError::MissingAccessToken
        | AuthApplicationError::MissingIdToken => Status::invalid_argument(error.to_string()),
        AuthApplicationError::Port { .. } => Status::unavailable("AUTH.BACKEND_UNAVAILABLE"),
    }
}
