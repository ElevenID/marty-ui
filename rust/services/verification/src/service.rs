use std::{collections::BTreeSet, sync::Arc};

use chrono::Utc;
use marty_flow::{
    build_flow_presentation_request, resolve_flow_presentation_policy,
    FlowPresentationRequestError, FlowProviderError, PresentationEvaluationRequest,
    PresentationPolicyReference,
};
use mmf_security::{
    authorize_tenant_api_key, authorize_tenant_membership, TenantAuthorizationFailure,
};
use serde_json::{json, Value};

use crate::{
    normalize_holder_binding, sha256_text, EvaluateRequest, EvaluationResult, SessionStatus,
    SessionStore, StartVerificationRequest, SubmissionOutcome, VerificationError,
    VerificationProviders, VerificationSession, ZkpSubmitRequest,
};

const API_KEY_SCOPES: &[&str] = &["credentials:read", "flows:execute", "admin:full"];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagementPrincipal {
    pub user_id: String,
    pub organization_id: String,
    pub api_key_id: String,
    pub api_key_scopes: String,
    pub required_permission: String,
}

#[derive(Clone)]
pub struct VerificationService {
    store: Arc<dyn SessionStore>,
    providers: VerificationProviders,
    public_base_url: Arc<str>,
    management_authorization: bool,
}

impl VerificationService {
    #[must_use]
    pub fn new(
        store: Arc<dyn SessionStore>,
        providers: VerificationProviders,
        public_base_url: impl Into<Arc<str>>,
        management_authorization: bool,
    ) -> Self {
        Self {
            store,
            providers,
            public_base_url: public_base_url.into(),
            management_authorization,
        }
    }

    pub async fn start(
        &self,
        body: StartVerificationRequest,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        let session = self.start_session(body, principal).await?;
        let mut response = session.protocol_value();
        let request_uri = self.request_uri(&session.session_id);
        response["request_uri"] = json!(request_uri);
        response["qr_code_data"] = json!(format!(
            "openid4vp://authorize?request_uri={}",
            self.request_uri(&session.session_id)
        ));
        Ok(response)
    }

    pub async fn start_session(
        &self,
        body: StartVerificationRequest,
        principal: &ManagementPrincipal,
    ) -> Result<VerificationSession, VerificationError> {
        validate_start(&body)?;
        if !principal.organization_id.trim().is_empty()
            && !body.organization_id.trim().is_empty()
            && principal.organization_id != body.organization_id
        {
            return Err(VerificationError::Forbidden("Organization mismatch".into()));
        }
        if body.response_type == "vp_token" && body.presentation_policy_id.is_none() {
            return Err(VerificationError::BadRequest(
                "presentation_policy_id is required for vp_token response_type".into(),
            ));
        }
        if body.callback_url.is_some() {
            return Err(VerificationError::BadRequest(
                "Standalone Verification callbacks are not supported; use the Flow service transactional callback outbox".into(),
            ));
        }
        if self.management_authorization
            && (body.trust_profile_id.is_some() || body.deployment_profile_id.is_some())
        {
            return Err(VerificationError::BadRequest(
                "Standalone trust/deployment profile overrides are not supported; use the Flow verification endpoint".into(),
            ));
        }
        if self.management_authorization {
            self.authorize(principal, &body.organization_id).await?;
            if let Some(policy_id) = body.presentation_policy_id.as_deref() {
                self.resolve_policy(policy_id, &body.organization_id)
                    .await?;
            }
        }
        let mut session = VerificationSession::new(&body, Utc::now())?;
        session.evaluation_principal_id = principal.user_id.clone();
        self.store
            .save(session.clone())
            .await
            .map_err(|_| coordination())?;
        Ok(session)
    }

    pub async fn list(
        &self,
        organization_id: &str,
        status: Option<&str>,
        limit: usize,
        offset: usize,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        self.authorize(principal, organization_id).await?;
        let sessions = self
            .store
            .list_by_org(organization_id, status)
            .await
            .map_err(|_| coordination())?;
        let total = sessions.len();
        let page = sessions
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|session| session.protocol_value())
            .collect::<Vec<_>>();
        Ok(json!({"sessions": page, "total": total}))
    }

    pub async fn get(
        &self,
        session_id: &str,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        let session = self.session(session_id).await?;
        self.authorize(principal, &session.organization_id).await?;
        Ok(session.protocol_value())
    }

    pub async fn request_object(&self, session_id: &str) -> Result<Value, VerificationError> {
        let session = self.session(session_id).await?;
        if session.status == SessionStatus::Expired {
            return Err(VerificationError::Gone("Session expired".into()));
        }
        let response_uri = format!(
            "{}/submit",
            self.request_uri(session_id).trim_end_matches("/request")
        );
        if session.response_type == "id_token" {
            return Ok(json!({
                "response_type": "id_token",
                "client_id": self.public_base_url,
                "nonce": session.nonce,
                "response_uri": response_uri,
                "scope": "openid"
            }));
        }
        let policy_id = session.presentation_policy_id.as_deref().ok_or_else(|| {
            VerificationError::Conflict(
                "Verification session has no saved presentation policy".into(),
            )
        })?;
        let artifacts = build_flow_presentation_request(
            &self.providers.flow,
            policy_id,
            &session.organization_id,
        )
        .await
        .map_err(map_presentation_error)?;
        Ok(json!({
            "response_type": session.response_type,
            "client_id": self.public_base_url,
            "nonce": session.nonce,
            "response_uri": response_uri,
            "dcql_query": artifacts.dcql_query
        }))
    }

    pub async fn submit(
        &self,
        session_id: &str,
        vp_token: &str,
        validate_references: bool,
    ) -> Result<Value, VerificationError> {
        Ok(self
            .submit_session(session_id, vp_token, validate_references)
            .await?
            .protocol_value())
    }

    pub async fn submit_session(
        &self,
        session_id: &str,
        vp_token: &str,
        validate_references: bool,
    ) -> Result<VerificationSession, VerificationError> {
        if vp_token.len() > 1_000_000 {
            return Err(VerificationError::BadRequest(
                "Request validation failed".into(),
            ));
        }
        if validate_references {
            let session = self.session(session_id).await?;
            let policy_id = session.presentation_policy_id.as_deref().ok_or_else(|| {
                VerificationError::Conflict(
                    "Verification session has no saved presentation policy".into(),
                )
            })?;
            self.resolve_policy(policy_id, &session.organization_id)
                .await?;
        }
        let digest = sha256_text(vp_token);
        let transition = self
            .store
            .claim_submission(session_id, &digest)
            .await
            .map_err(|_| coordination())?;
        if transition.outcome == SubmissionOutcome::Duplicate {
            return transition.session.ok_or_else(coordination);
        }
        if transition.outcome != SubmissionOutcome::Claimed {
            return Err(submission_error(transition.outcome));
        }
        let mut session = transition.session.ok_or_else(coordination)?;
        let token = transition.token.ok_or_else(coordination)?;
        let policy_id = session.presentation_policy_id.clone().unwrap_or_default();
        let evaluation = self
            .providers
            .evaluation
            .evaluate(&PresentationEvaluationRequest {
                policy_id,
                organization_id: session.organization_id.clone(),
                principal_id: session.evaluation_principal_id.clone(),
                presentation: vp_token.into(),
                nonce: session.nonce.clone(),
                audience: String::new(),
                context: [("session_id".into(), json!(session_id))]
                    .into_iter()
                    .collect(),
            })
            .await;
        match evaluation {
            Ok(result) => apply_evaluation(&mut session, &result),
            Err(_) => {
                session.result = Some("failed".into());
                session.decision = Some("deny".into());
                session.decision_reason = "Credential evaluation failed".into();
                session.holder_binding_evidence = None;
                session.total_requirements = 0;
                session.satisfied_requirements = 0;
                session.error = Some("Credential evaluation failed".into());
            }
        }
        if session.result.as_deref() != Some("failed") {
            if let Ok(Some(result)) = self.providers.inspection.inspect(vp_token).await {
                session.inspection_performed = true;
                session.inspection_result = result;
            }
        }
        session.status = if session.result.as_deref() == Some("passed") {
            SessionStatus::Completed
        } else {
            SessionStatus::Failed
        };
        let completed_at = Utc::now();
        session.completed_at = Some(completed_at);
        session.updated_at = completed_at;
        let finalized = self
            .store
            .finalize_submission(session_id, &digest, &token, session)
            .await
            .map_err(|_| coordination())?;
        if matches!(
            finalized.outcome,
            SubmissionOutcome::Committed | SubmissionOutcome::Duplicate
        ) {
            return finalized.session.ok_or_else(coordination);
        }
        Err(submission_error(finalized.outcome))
    }

    pub async fn session_record(
        &self,
        session_id: &str,
    ) -> Result<VerificationSession, VerificationError> {
        self.session(session_id).await
    }

    pub async fn list_records(
        &self,
        organization_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<VerificationSession>, VerificationError> {
        self.store
            .list_by_org(organization_id, status)
            .await
            .map_err(|_| coordination())
    }

    #[must_use]
    pub fn public_request_uri(&self, session_id: &str) -> String {
        self.request_uri(session_id)
    }

    pub async fn evaluate(
        &self,
        body: EvaluateRequest,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        validate_evaluate(&body)?;
        let policy = self.policy_reference(&body.presentation_policy_id).await?;
        if !policy.status.eq_ignore_ascii_case("active") {
            return Err(VerificationError::Conflict(
                "Presentation policy is not active".into(),
            ));
        }
        self.authorize(principal, &policy.organization_id).await?;
        self.resolve_policy(&body.presentation_policy_id, &policy.organization_id)
            .await?;
        let result = self
            .providers
            .evaluation
            .evaluate(&PresentationEvaluationRequest {
                policy_id: body.presentation_policy_id,
                organization_id: policy.organization_id,
                principal_id: principal.user_id.clone(),
                presentation: body.vp_token,
                nonce: body.nonce.unwrap_or_default(),
                audience: body.audience.unwrap_or_default(),
                context: body.context.unwrap_or_default().into_iter().collect(),
            })
            .await
            .map_err(|_| VerificationError::Dependency("Evaluation failed".into()))?;
        Ok(result.as_value())
    }

    pub async fn evaluate_zkp(
        &self,
        body: ZkpSubmitRequest,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        let vp_token = body
            .vp_token
            .or(body.proof)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| VerificationError::BadRequest("vp_token or proof is required".into()))?;
        let policy_id = body
            .presentation_policy_id
            .or(body.policy_id)
            .unwrap_or_default();
        if self.management_authorization && policy_id.is_empty() {
            return Err(VerificationError::BadRequest(
                "presentation_policy_id or policy_id is required".into(),
            ));
        }
        self.evaluate(
            EvaluateRequest {
                vp_token,
                presentation_policy_id: policy_id,
                nonce: body.nonce,
                audience: None,
                context: None,
            },
            principal,
        )
        .await
        .map_err(|error| match error {
            VerificationError::Dependency(_) => {
                VerificationError::Dependency("ZKP verification failed".into())
            }
            error => error,
        })
    }

    pub async fn inspection(
        &self,
        session_id: &str,
        principal: &ManagementPrincipal,
    ) -> Result<Value, VerificationError> {
        let session = self.session(session_id).await?;
        self.authorize(principal, &session.organization_id).await?;
        Ok(json!({
            "session_id": session_id,
            "performed": session.inspection_performed,
            "result": session.inspection_result,
            "result_sha256": session.inspection_result_sha256,
            "timestamp": session.completed_at.map(|value| value.to_rfc3339()).unwrap_or_default()
        }))
    }

    async fn session(&self, session_id: &str) -> Result<VerificationSession, VerificationError> {
        self.store
            .get(session_id)
            .await
            .map_err(|_| coordination())?
            .ok_or_else(|| VerificationError::NotFound("Session not found".into()))
    }

    async fn authorize(
        &self,
        principal: &ManagementPrincipal,
        organization_id: &str,
    ) -> Result<(), VerificationError> {
        if !self.management_authorization {
            return Ok(());
        }
        if principal.user_id.trim().is_empty() {
            return Err(VerificationError::Unauthorized(
                "Authentication required".into(),
            ));
        }
        let api_context = principal.user_id.starts_with("api_key:")
            || !principal.api_key_id.is_empty()
            || !principal.api_key_scopes.trim().is_empty();
        if api_context {
            let scopes = principal
                .api_key_scopes
                .split(',')
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .collect::<BTreeSet<_>>();
            let scope_allowed = scopes.iter().any(|scope| API_KEY_SCOPES.contains(scope));
            if !scope_allowed
                || authorize_tenant_api_key(
                    "verification:execute",
                    &principal.user_id,
                    organization_id,
                    &principal.api_key_id,
                    &principal.organization_id,
                    &principal.required_permission,
                    false,
                )
                .is_err()
            {
                return Err(VerificationError::Forbidden(
                    "API key is not authorized to execute verification".into(),
                ));
            }
            return Ok(());
        }
        let membership = self
            .providers
            .membership
            .membership(&principal.user_id, organization_id)
            .await
            .map_err(|_| {
                VerificationError::Dependency("Organization service unavailable".into())
            })?;
        authorize_tenant_membership(
            "verification:execute",
            &principal.user_id,
            organization_id,
            membership.as_ref(),
            false,
        )
        .map_err(map_authorization)
    }

    async fn policy_reference(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, VerificationError> {
        self.providers
            .flow
            .presentation_policy
            .as_ref()
            .ok_or_else(|| {
                VerificationError::Dependency("Presentation policy service unavailable".into())
            })?
            .get_policy(policy_id)
            .await
            .map_err(map_policy_provider)
    }

    async fn resolve_policy(
        &self,
        policy_id: &str,
        organization_id: &str,
    ) -> Result<(), VerificationError> {
        resolve_flow_presentation_policy(&self.providers.flow, policy_id, organization_id)
            .await
            .map(|_| ())
            .map_err(map_presentation_error)
    }

    fn request_uri(&self, session_id: &str) -> String {
        format!(
            "{}/v1/verify/{session_id}/request",
            self.public_base_url.trim_end_matches('/')
        )
    }
}

fn validate_start(body: &StartVerificationRequest) -> Result<(), VerificationError> {
    let valid = body.organization_id.len() <= 255
        && body
            .presentation_policy_id
            .as_ref()
            .is_none_or(|value| value.len() <= 255)
        && body.response_type.len() <= 50
        && body
            .trust_profile_id
            .as_ref()
            .is_none_or(|value| value.len() <= 255)
        && body
            .deployment_profile_id
            .as_ref()
            .is_none_or(|value| value.len() <= 255)
        && body
            .external_reference
            .as_ref()
            .is_none_or(|value| value.len() <= 500)
        && body
            .callback_url
            .as_ref()
            .is_none_or(|value| value.len() <= 2048)
        && body.purpose.len() <= 1000;
    if valid {
        Ok(())
    } else {
        Err(VerificationError::BadRequest(
            "Request validation failed".into(),
        ))
    }
}

fn validate_evaluate(body: &EvaluateRequest) -> Result<(), VerificationError> {
    let valid = body.vp_token.len() <= 1_000_000
        && body.presentation_policy_id.len() <= 255
        && body.nonce.as_ref().is_none_or(|value| value.len() <= 512)
        && body
            .audience
            .as_ref()
            .is_none_or(|value| value.len() <= 512);
    if valid {
        Ok(())
    } else {
        Err(VerificationError::BadRequest(
            "Request validation failed".into(),
        ))
    }
}

fn apply_evaluation(session: &mut VerificationSession, result: &EvaluationResult) {
    session.result = Some(if result.result.is_empty() {
        "failed".into()
    } else {
        result.result.clone()
    });
    session.decision = Some(if result.decision.is_empty() {
        "deny".into()
    } else {
        result.decision.clone()
    });
    session.decision_reason = result.decision_reason.clone();
    session.verified_claims = result.verified_claims.clone();
    session.credential_results = result.credential_results.clone();
    let mut normalized = result.as_value();
    if let Some(evidence) = &result.holder_binding_evidence {
        normalized["holder_binding_evidence"] = evidence.clone();
    }
    session.holder_binding_evidence = normalize_holder_binding(&normalized);
    session.total_requirements = result.total_requirements;
    session.satisfied_requirements = result.satisfied_requirements;
    session.error = None;
}

fn submission_error(outcome: SubmissionOutcome) -> VerificationError {
    match outcome {
        SubmissionOutcome::Missing => VerificationError::NotFound("Session not found".into()),
        SubmissionOutcome::Expired => VerificationError::Gone("Session expired".into()),
        SubmissionOutcome::Conflict => VerificationError::Conflict(
            "Session is already bound to a different presentation".into(),
        ),
        SubmissionOutcome::Busy => {
            VerificationError::Conflict("Presentation evaluation is already in progress".into())
        }
        _ => coordination(),
    }
}

fn map_authorization(error: TenantAuthorizationFailure) -> VerificationError {
    match error {
        TenantAuthorizationFailure::AuthenticationRequired => {
            VerificationError::Unauthorized("Authentication required".into())
        }
        _ => VerificationError::Forbidden("Permission denied".into()),
    }
}

fn map_policy_provider(error: FlowProviderError) -> VerificationError {
    match error {
        FlowProviderError::NotFound { .. } => {
            VerificationError::NotFound("Presentation policy not found".into())
        }
        _ => VerificationError::Dependency("Presentation policy service unavailable".into()),
    }
}

fn map_presentation_error(error: FlowPresentationRequestError) -> VerificationError {
    match error {
        FlowPresentationRequestError::PolicyNotVisible => {
            VerificationError::NotFound("Presentation policy not found".into())
        }
        FlowPresentationRequestError::PolicyInactive => {
            VerificationError::Conflict("Presentation policy is not active".into())
        }
        FlowPresentationRequestError::TemplateNotVisible
        | FlowPresentationRequestError::Provider(FlowProviderError::NotFound {
            provider: "credential_template",
            ..
        }) => VerificationError::NotFound("Credential template not found".into()),
        FlowPresentationRequestError::TemplateInactive => {
            VerificationError::Conflict("Credential template is not active".into())
        }
        FlowPresentationRequestError::Provider(FlowProviderError::NotFound { .. }) => {
            VerificationError::NotFound("Presentation policy not found".into())
        }
        FlowPresentationRequestError::InvalidPolicy(_)
        | FlowPresentationRequestError::InvalidTemplate(_) => VerificationError::Conflict(
            "Presentation policy contains an invalid credential requirement".into(),
        ),
        _ => VerificationError::Dependency("Presentation policy service unavailable".into()),
    }
}

fn coordination() -> VerificationError {
    VerificationError::Coordination("Verification session coordination unavailable".into())
}
