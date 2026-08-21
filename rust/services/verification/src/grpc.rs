use std::sync::Arc;

use serde_json::{Map, Value};
use tonic::{Request, Response, Status};

use crate::{
    verification_proto::{
        verification_service_server::VerificationService as VerificationGrpc,
        EvaluatePresentationRequest, GetSessionRequest, HealthCheckRequest, HealthCheckResponse,
        InspectionResultResponse, ListSessionsRequest, ListSessionsResponse,
        StartVerificationRequest as GrpcStartRequest, SubmitPresentationRequest,
        VerificationResult, VerificationSession as GrpcSession,
    },
    EvaluateRequest, ManagementPrincipal, SessionStatus, StartVerificationRequest,
    VerificationError, VerificationService, VerificationSession,
};

#[derive(Clone)]
pub struct VerificationGrpcService {
    service: Arc<VerificationService>,
}

impl VerificationGrpcService {
    #[must_use]
    pub const fn new(service: Arc<VerificationService>) -> Self {
        Self { service }
    }

    fn session_message(&self, session: &VerificationSession) -> GrpcSession {
        let request_uri = self.service.public_request_uri(&session.session_id);
        GrpcSession {
            session_id: session.session_id.clone(),
            organization_id: session.organization_id.clone(),
            presentation_policy_id: session.presentation_policy_id.clone().unwrap_or_default(),
            response_type: session.response_type.clone(),
            status: status_name(session.status).into(),
            qr_code_data: format!("openid4vp://authorize?request_uri={request_uri}"),
            request_uri,
            nonce: session.nonce.clone(),
            expires_at: session.expires_at.to_rfc3339(),
            created_at: session.created_at.to_rfc3339(),
            external_reference: session.external_reference.clone().unwrap_or_default(),
            result: session.result.clone().unwrap_or_default(),
            decision: session.decision.clone().unwrap_or_default(),
            verified_claims_json: json_string(&session.verified_claims),
        }
    }
}

#[tonic::async_trait]
impl VerificationGrpc for VerificationGrpcService {
    async fn start_verification(
        &self,
        request: Request<GrpcStartRequest>,
    ) -> Result<Response<GrpcSession>, Status> {
        let request = request.into_inner();
        let session = self
            .service
            .start_session(
                StartVerificationRequest {
                    organization_id: request.organization_id,
                    presentation_policy_id: nonempty(request.presentation_policy_id),
                    response_type: nonempty(request.response_type)
                        .unwrap_or_else(|| "vp_token".into()),
                    trust_profile_id: nonempty(request.trust_profile_id),
                    deployment_profile_id: nonempty(request.deployment_profile_id),
                    external_reference: nonempty(request.external_reference),
                    callback_url: nonempty(request.callback_url),
                    expiry_minutes: if request.expiry_minutes == 0 {
                        15
                    } else {
                        request.expiry_minutes
                    },
                    purpose: request.purpose,
                },
                &ManagementPrincipal::default(),
            )
            .await
            .map_err(status)?;
        Ok(Response::new(self.session_message(&session)))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GrpcSession>, Status> {
        let session = self
            .service
            .session_record(&request.into_inner().session_id)
            .await
            .map_err(status)?;
        Ok(Response::new(self.session_message(&session)))
    }

    async fn submit_presentation(
        &self,
        request: Request<SubmitPresentationRequest>,
    ) -> Result<Response<VerificationResult>, Status> {
        let request = request.into_inner();
        let session = self
            .service
            .submit_session(&request.session_id, &request.vp_token, false)
            .await
            .map_err(status)?;
        Ok(Response::new(result_message(&session)))
    }

    async fn evaluate_presentation(
        &self,
        request: Request<EvaluatePresentationRequest>,
    ) -> Result<Response<VerificationResult>, Status> {
        let request = request.into_inner();
        let context = if request.context_json.trim().is_empty() {
            Map::new()
        } else {
            serde_json::from_str::<Map<String, Value>>(&request.context_json)
                .map_err(|_| Status::invalid_argument("context_json must be a JSON object"))?
        };
        let result = self
            .service
            .evaluate(
                EvaluateRequest {
                    vp_token: request.vp_token,
                    presentation_policy_id: request.presentation_policy_id,
                    nonce: nonempty(request.nonce),
                    audience: nonempty(request.audience),
                    context: Some(context),
                },
                &ManagementPrincipal::default(),
            )
            .await
            .map_err(status)?;
        Ok(Response::new(VerificationResult {
            result: string_field(&result, "result"),
            decision: string_field(&result, "decision"),
            decision_reason: string_field(&result, "decision_reason"),
            verified_claims_json: json_string(&result["verified_claims"]),
            credential_results_json: json_string(&result["credential_results"]),
            total_requirements: integer_field(&result, "total_requirements"),
            satisfied_requirements: integer_field(&result, "satisfied_requirements"),
            evaluation_timestamp: string_field(&result, "evaluation_timestamp"),
            nonce: string_field(&result, "nonce"),
            ..VerificationResult::default()
        }))
    }

    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let request = request.into_inner();
        let sessions = self
            .service
            .list_records(
                &request.organization_id,
                nonempty(request.status).as_deref(),
            )
            .await
            .map_err(status)?;
        let total = i32::try_from(sessions.len()).unwrap_or(i32::MAX);
        let offset = usize::try_from(request.offset.max(0)).unwrap_or_default();
        let limit = usize::try_from(if request.limit <= 0 {
            50
        } else {
            request.limit
        })
        .unwrap_or(50);
        let sessions = sessions
            .iter()
            .skip(offset)
            .take(limit)
            .map(|session| self.session_message(session))
            .collect();
        Ok(Response::new(ListSessionsResponse { sessions, total }))
    }

    async fn get_inspection_result(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<InspectionResultResponse>, Status> {
        let session = self
            .service
            .session_record(&request.into_inner().session_id)
            .await
            .map_err(status)?;
        let detail = session.inspection_result_sha256.as_ref().map_or_else(
            || "{}".into(),
            |digest| json_string(&serde_json::json!({"result_sha256": digest})),
        );
        Ok(Response::new(InspectionResultResponse {
            session_id: session.session_id,
            performed: session.inspection_performed,
            result: session.inspection_result,
            detail_json: detail,
            timestamp: session
                .completed_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_default(),
        }))
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

fn result_message(session: &VerificationSession) -> VerificationResult {
    VerificationResult {
        session_id: session.session_id.clone(),
        result: session.result.clone().unwrap_or_default(),
        decision: session.decision.clone().unwrap_or_default(),
        decision_reason: session.decision_reason.clone(),
        verified_claims_json: json_string(&session.verified_claims),
        credential_results_json: json_string(&session.credential_results),
        total_requirements: session.total_requirements,
        satisfied_requirements: session.satisfied_requirements,
        evaluation_timestamp: session
            .completed_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
        nonce: session.nonce.clone(),
        inspection_performed: session.inspection_performed,
        inspection_result: session.inspection_result.clone(),
    }
}

const fn status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Completed => "completed",
        SessionStatus::Expired => "expired",
        SessionStatus::Failed => "failed",
    }
}

fn status(error: VerificationError) -> Status {
    match error {
        VerificationError::BadRequest(message) => Status::invalid_argument(message),
        VerificationError::Unauthorized(message) => Status::unauthenticated(message),
        VerificationError::Forbidden(message) => Status::permission_denied(message),
        VerificationError::NotFound(message) => Status::not_found(message),
        VerificationError::Conflict(message) => Status::aborted(message),
        VerificationError::Gone(message) => Status::failed_precondition(message),
        VerificationError::Dependency(message) | VerificationError::Coordination(message) => {
            Status::unavailable(message)
        }
        VerificationError::Internal(message) => Status::internal(message),
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn json_string(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

fn string_field(value: &Value, name: &str) -> String {
    value[name].as_str().unwrap_or_default().into()
}

fn integer_field(value: &Value, name: &str) -> i32 {
    value[name]
        .as_i64()
        .and_then(|number| i32::try_from(number).ok())
        .unwrap_or_default()
}
