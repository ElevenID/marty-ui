//! Learner claims use the canonical Canvas application and the shared offer
//! coordinator. A session is authority, never a caller-selected application ID.
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    canvas_lti_evidence::{
        CanvasLtiEvidenceError, CanvasLtiEvidenceScope, CanvasLtiEvidenceService,
    },
    canvas_lti_experience::{lti_subject, CanvasLtiExperienceSessionContext},
    internal_application_domain::ApplicationRecord,
    internal_application_offer::IssuanceOfferResponse,
    internal_application_service::InternalApplicationService,
};

pub(crate) struct CanvasClaimAuthority {
    scope: CanvasLtiEvidenceScope,
    subject: String,
}

impl CanvasClaimAuthority {
    fn from_session(
        context: &CanvasLtiExperienceSessionContext,
        scope: CanvasLtiEvidenceScope,
    ) -> Option<Self> {
        let learner = context
            .verified_launch
            .get("roles")?
            .as_array()?
            .iter()
            .any(|role| {
                matches!(
                    role.as_str(),
                    Some("http://purl.imsglobal.org/vocab/lis/v2/membership#Learner")
                        | Some("http://purl.imsglobal.org/vocab/lis/v2/membership/Learner")
                        | Some("urn:lti:role:ims/lis/Learner")
                )
            });
        let message = context
            .verified_launch
            .get("raw_claims")?
            .get("https://purl.imsglobal.org/spec/lti/claim/message_type")?
            .as_str()?;
        if !learner || message != "LtiResourceLinkRequest" {
            return None;
        }
        Some(Self {
            scope,
            subject: lti_subject(&context.verified_launch)?,
        })
    }

    pub(crate) fn application_id(&self) -> &str {
        &self.scope.application.id
    }
    pub(crate) fn organization_id(&self) -> &str {
        &self.scope.application.organization_id
    }
    pub(crate) fn matches(&self, application: &ApplicationRecord) -> bool {
        application.id == self.application_id()
            && application.organization_id == self.organization_id()
            && application.application_template_id == self.scope.application.application_template_id
            && application.applicant_identifier == format!("canvas_lti:{}", self.subject)
            && self.scope.application.integration_context.as_object()
                == Some(&application.integration_context)
    }
}

#[derive(Debug, Serialize)]
pub struct CanvasClaimResponse {
    pub id: String,
    pub organization_id: String,
    pub claim_state: &'static str,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub offer: Option<IssuanceOfferResponse>,
}

#[derive(Clone)]
struct ClaimState {
    evidence: CanvasLtiEvidenceService,
    applications: InternalApplicationService,
}

pub fn router(
    evidence: CanvasLtiEvidenceService,
    applications: InternalApplicationService,
) -> Router {
    Router::new()
        .route(
            "/v1/integrations/canvas/lti/experience-sessions/current/claim",
            get(read_claim).post(create_claim),
        )
        .with_state(ClaimState {
            evidence,
            applications,
        })
}

async fn read_claim(State(state): State<ClaimState>, request: Request) -> Response {
    claim(state, request, false).await
}

async fn create_claim(State(state): State<ClaimState>, request: Request) -> Response {
    claim(state, request, true).await
}

async fn claim(state: ClaimState, request: Request, generate: bool) -> Response {
    private_response(claim_inner(state, request, generate).await)
}

async fn claim_inner(state: ClaimState, request: Request, generate: bool) -> Response {
    let Some(token) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
        .map(|(_, token)| token.trim())
    else {
        return error(
            StatusCode::UNAUTHORIZED,
            "Canvas launch session is required",
        );
    };
    // Authenticate and resolve all stored scope bindings before caller input.
    let (context, scope) = match state.evidence.resolve_session_scope(token).await {
        Ok(resolved) => resolved,
        Err(CanvasLtiEvidenceError::RepositoryUnavailable) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Canvas claim is temporarily unavailable",
            )
        }
        Err(
            CanvasLtiEvidenceError::BootstrapRequired
            | CanvasLtiEvidenceError::EvidenceConfigurationUnavailable,
        ) => {
            return error(
                StatusCode::CONFLICT,
                "Canvas application must be ready before claiming",
            )
        }
        Err(_) => return error(StatusCode::NOT_FOUND, "Canvas claim context was not found"),
    };
    let Some(authority) = CanvasClaimAuthority::from_session(&context, scope) else {
        return error(
            StatusCode::FORBIDDEN,
            "Claiming requires an authenticated Canvas learner resource launch",
        );
    };
    // No destination, tenant, application, mirror, or authority overrides.
    if request.uri().query().is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "Canvas claim does not accept query options",
        );
    }
    let body = match to_bytes(request.into_body(), 1024).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "Canvas claim does not accept request options",
            )
        }
    };
    if !body.is_empty()
        && (!generate || serde_json::from_slice::<Value>(&body).ok() != Some(json!({})))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Canvas claim does not accept request options",
        );
    }
    match state.applications.canvas_claim(&authority, generate).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => crate::internal_application_http::service_error(failure),
    }
}

fn error(status: StatusCode, detail: &str) -> Response {
    (status, Json(json!({"detail": detail}))).into_response()
}

fn private_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());
    response
}
