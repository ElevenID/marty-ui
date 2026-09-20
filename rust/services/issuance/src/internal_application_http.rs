//! HTTP adapter for the completed internal Application management slice.
//!
//! All routes in the frozen 14-route contract are mounted by the issuance
//! executable as one atomic cutover.

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    internal_application_domain::{
        ApplicationApproval, ApplicationCreate, ApplicationDomainError, ApplicationRejection,
        ApplicationResponse, EvidenceFactResponse, EvidenceReconciliationRequest,
        EvidenceSubmission, ExternalEvidenceApiCheckRequest, IssuanceEventResponse,
    },
    internal_application_evidence::InternalApplicationEvidenceError,
    internal_application_offer::InternalApplicationOfferError,
    internal_application_reconciliation::EvidenceReconciliationError,
    internal_application_service::{
        InternalApplicationApprovalError, InternalApplicationRepositoryError,
        InternalApplicationService, InternalApplicationServiceError,
    },
    internal_external_evidence::ExternalEvidenceApiError,
    management_http::{header, malformed_json, missing_organization_query, security_error},
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";

pub fn router(service: InternalApplicationService) -> Router {
    Router::new()
        .route(
            "/internal/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/internal/applications/{application_id}",
            get(get_application),
        )
        .route(
            "/internal/applications/{application_id}/evidence-facts",
            get(list_evidence_facts),
        )
        .route(
            "/internal/applications/{application_id}/evidence-summary",
            get(get_evidence_summary),
        )
        .route(
            "/internal/applications/evidence/reconcile",
            post(reconcile_application_evidence),
        )
        .route(
            "/internal/applications/evidence/reconciliation-report",
            get(get_application_evidence_reconciliation_report),
        )
        .route(
            "/internal/applications/{application_id}/evidence/api-checks/{check_id}/run",
            post(run_external_evidence_api_check),
        )
        .route(
            "/internal/applications/{application_id}/submit-evidence",
            post(submit_evidence),
        )
        .route(
            "/internal/applications/{application_id}/approve",
            post(approve_application),
        )
        .route(
            "/internal/applications/{application_id}/reject",
            post(reject_application),
        )
        .route(
            "/internal/applications/{application_id}/issuance-events",
            get(list_issuance_events),
        )
        .route(
            "/internal/applications/{application_id}/issuance-offer",
            get(get_issuance_offer).post(generate_issuance_offer),
        )
        .with_state(service)
}

#[derive(Deserialize)]
struct ListQuery {
    organization_id: Option<String>,
    status: Option<String>,
    application_template_id: Option<String>,
}

#[derive(Deserialize)]
struct ReconciliationReportQuery {
    organization_id: Option<String>,
    limit: Option<i64>,
}

async fn create_application(
    State(service): State<InternalApplicationService>,
    headers: HeaderMap,
    body: Result<Json<ApplicationCreate>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(request) = match body {
        Ok(request) => request,
        Err(error) => return malformed_json(error),
    };
    result_application(
        service
            .create(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                request,
            )
            .await,
    )
}

async fn list_applications(
    State(service): State<InternalApplicationService>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Some(organization_id) = query.organization_id.as_deref() else {
        return missing_organization_query();
    };
    match service
        .list(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            organization_id,
            query.status.as_deref(),
            query.application_template_id.as_deref(),
        )
        .await
    {
        Ok(applications) => (
            StatusCode::OK,
            Json(
                applications
                    .iter()
                    .map(ApplicationResponse::from)
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error) => service_error(error),
    }
}

async fn get_application(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_application(
        service
            .get(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &application_id,
            )
            .await,
    )
}

async fn list_evidence_facts(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .list_evidence_facts(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
        )
        .await
    {
        Ok(facts) => (
            StatusCode::OK,
            Json(
                facts
                    .iter()
                    .map(EvidenceFactResponse::from)
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error) => service_error(error),
    }
}

async fn get_evidence_summary(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .evidence_summary(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
        )
        .await
    {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(error) => service_error(error),
    }
}

async fn reconcile_application_evidence(
    State(service): State<InternalApplicationService>,
    headers: HeaderMap,
    body: Result<Json<EvidenceReconciliationRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(request) = match body {
        Ok(request) => request,
        Err(error) => return malformed_json(error),
    };
    match service
        .reconcile_evidence(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            request,
        )
        .await
    {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => service_error(error),
    }
}

async fn get_application_evidence_reconciliation_report(
    State(service): State<InternalApplicationService>,
    headers: HeaderMap,
    Query(query): Query<ReconciliationReportQuery>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Some(organization_id) = query.organization_id.as_deref() else {
        return missing_organization_query();
    };
    match service
        .evidence_reconciliation_report(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            organization_id,
            query.limit.unwrap_or(100),
        )
        .await
    {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => service_error(error),
    }
}

async fn submit_evidence(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<EvidenceSubmission>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(evidence) = match body {
        Ok(evidence) => evidence,
        Err(error) => return malformed_json(error),
    };
    result_application(
        service
            .submit_evidence(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &application_id,
                evidence,
            )
            .await,
    )
}

async fn run_external_evidence_api_check(
    State(service): State<InternalApplicationService>,
    Path((application_id, check_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Json<ExternalEvidenceApiCheckRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(request) = match body {
        Ok(request) => request,
        Err(error) => return malformed_json(error),
    };
    match service
        .run_external_evidence_api_check(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
            &check_id,
            request,
        )
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error(error),
    }
}

async fn reject_application(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ApplicationRejection>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(rejection) = match body {
        Ok(rejection) => rejection,
        Err(error) => return malformed_json(error),
    };
    result_application(
        service
            .reject(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &application_id,
                rejection,
            )
            .await,
    )
}

async fn approve_application(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ApplicationApproval>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_json_request(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
    ) {
        return service_error(error);
    }
    let Json(approval) = match body {
        Ok(approval) => approval,
        Err(error) => return malformed_json(error),
    };
    result_application(
        service
            .approve(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &application_id,
                approval,
            )
            .await,
    )
}

async fn list_issuance_events(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .list_issuance_events(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
        )
        .await
    {
        Ok(events) => (
            StatusCode::OK,
            Json(
                events
                    .iter()
                    .map(IssuanceEventResponse::from)
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error) => service_error(error),
    }
}

async fn generate_issuance_offer(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .generate_issuance_offer(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
        )
        .await
    {
        Ok(offer) => (StatusCode::OK, Json(offer)).into_response(),
        Err(error) => service_error(error),
    }
}

async fn get_issuance_offer(
    State(service): State<InternalApplicationService>,
    Path(application_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .get_issuance_offer(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &application_id,
        )
        .await
    {
        Ok(offer) => (StatusCode::OK, Json(offer)).into_response(),
        Err(error) => service_error(error),
    }
}

fn result_application(
    result: Result<
        crate::internal_application_domain::ApplicationRecord,
        InternalApplicationServiceError,
    >,
) -> Response {
    match result {
        Ok(application) => (
            StatusCode::OK,
            Json(ApplicationResponse::from(&application)),
        )
            .into_response(),
        Err(error) => service_error(error),
    }
}

fn service_error(error: InternalApplicationServiceError) -> Response {
    let error = match error {
        InternalApplicationServiceError::Domain(error) => {
            let status = match &error {
                ApplicationDomainError::InvalidTransition { .. } => StatusCode::BAD_REQUEST,
                ApplicationDomainError::TimestampOverflow => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (status, Json(json!({"detail": error.to_string()}))).into_response();
        }
        InternalApplicationServiceError::Approval(error) => {
            return approval_error_response(error);
        }
        InternalApplicationServiceError::Offer(error) => {
            return offer_error_response(error);
        }
        InternalApplicationServiceError::Evidence(error) => {
            return evidence_error_response(error);
        }
        InternalApplicationServiceError::Reconciliation(error) => {
            return reconciliation_error_response(error);
        }
        InternalApplicationServiceError::OfferRequiresApproved(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"detail": error.to_string()})),
            )
                .into_response();
        }
        error => error,
    };
    let (status, detail) = match error {
        InternalApplicationServiceError::Security(error) => {
            security_error(error, "Application management is temporarily unavailable")
        }
        InternalApplicationServiceError::Repository(error) => repository_error(error),
        InternalApplicationServiceError::Domain(_) => unreachable!("handled above"),
        InternalApplicationServiceError::Approval(_) => unreachable!("handled above"),
        InternalApplicationServiceError::Offer(_) => unreachable!("handled above"),
        InternalApplicationServiceError::Evidence(_) => unreachable!("handled above"),
        InternalApplicationServiceError::Reconciliation(_) => unreachable!("handled above"),
        InternalApplicationServiceError::OfferRequiresApproved(_) => {
            unreachable!("handled above")
        }
        InternalApplicationServiceError::InvalidStatus => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid application status",
        ),
        InternalApplicationServiceError::TemplateNotFound => {
            (StatusCode::NOT_FOUND, "Application template not found")
        }
        InternalApplicationServiceError::TemplateInactive => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Application template must be active",
        ),
        InternalApplicationServiceError::ApplicationNotFound => {
            (StatusCode::NOT_FOUND, "Application not found")
        }
        InternalApplicationServiceError::MissingApprovalTemplateBinding => (
            StatusCode::BAD_REQUEST,
            "Application template missing credential template ID",
        ),
        InternalApplicationServiceError::EvidenceConflict => (
            StatusCode::CONFLICT,
            "Application lifecycle changed during evidence submission",
        ),
        InternalApplicationServiceError::RejectionConflict => (
            StatusCode::CONFLICT,
            "Application lifecycle changed during rejection",
        ),
        InternalApplicationServiceError::OfferNotAvailable => (
            StatusCode::NOT_FOUND,
            "No issuance offer available for this application",
        ),
        InternalApplicationServiceError::ExternalCheckNotFound => (
            StatusCode::NOT_FOUND,
            "External evidence API check not found on application template",
        ),
        InternalApplicationServiceError::ExternalCheckInvalidStatus(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"detail": error.to_string()})),
            )
                .into_response();
        }
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn reconciliation_error_response(error: EvidenceReconciliationError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"detail": error.to_string()})),
    )
        .into_response()
}

fn evidence_error_response(error: InternalApplicationEvidenceError) -> Response {
    match error {
        InternalApplicationEvidenceError::External(
            ExternalEvidenceApiError::InvalidConfiguration(detail),
        ) => (StatusCode::BAD_REQUEST, Json(json!({"detail": detail}))).into_response(),
        InternalApplicationEvidenceError::External(ExternalEvidenceApiError::Transport) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"detail": "External evidence API request failed"})),
        )
            .into_response(),
        InternalApplicationEvidenceError::ConcurrentChange => (
            StatusCode::CONFLICT,
            Json(json!({
                "detail": "Application lifecycle changed during evidence processing"
            })),
        )
            .into_response(),
        InternalApplicationEvidenceError::Approval(error) => approval_error_response(error),
        error @ (InternalApplicationEvidenceError::Repository(_)
        | InternalApplicationEvidenceError::Policy) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": error.to_string()})),
        )
            .into_response(),
    }
}

fn approval_error_response(error: InternalApplicationApprovalError) -> Response {
    let status = match &error {
        InternalApplicationApprovalError::Unavailable
        | InternalApplicationApprovalError::CredentialTemplateUnavailable
        | InternalApplicationApprovalError::RevocationProfileUnavailable
        | InternalApplicationApprovalError::IssuerContextUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        InternalApplicationApprovalError::CredentialTemplateNotFound
        | InternalApplicationApprovalError::CredentialTemplateInvalid(_)
        | InternalApplicationApprovalError::RevocationProfileNotFound
        | InternalApplicationApprovalError::RevocationProfileForeign
        | InternalApplicationApprovalError::RevocationProfileInactive => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        InternalApplicationApprovalError::CanvasNotReady
        | InternalApplicationApprovalError::CanvasOfferNotReady
        | InternalApplicationApprovalError::ConcurrentChange => StatusCode::CONFLICT,
    };
    (status, Json(json!({"detail": error.to_string()}))).into_response()
}

fn offer_error_response(error: InternalApplicationOfferError) -> Response {
    match error {
        InternalApplicationOfferError::Approval(error) => approval_error_response(error),
        error @ InternalApplicationOfferError::CredentialTemplateRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail": error.to_string()})),
        )
            .into_response(),
        error @ InternalApplicationOfferError::ConcurrentChange => (
            StatusCode::CONFLICT,
            Json(json!({"detail": error.to_string()})),
        )
            .into_response(),
        error @ (InternalApplicationOfferError::MissingTransactionBinding
        | InternalApplicationOfferError::TransactionNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": error.to_string()})),
        )
            .into_response(),
        error @ InternalApplicationOfferError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": error.to_string()})),
        )
            .into_response(),
    }
}

fn repository_error(error: InternalApplicationRepositoryError) -> (StatusCode, &'static str) {
    match error {
        InternalApplicationRepositoryError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Application repository is unavailable",
        ),
    }
}
