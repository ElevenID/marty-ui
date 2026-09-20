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
    application_template_domain::{
        ApplicationTemplateCreate, ApplicationTemplateLifecycleError, ApplicationTemplatePatch,
        ApplicationTemplateRequestError,
    },
    application_template_service::{
        ApplicationTemplateRepositoryError, ApplicationTemplateService,
        ApplicationTemplateServiceError,
    },
    management_http::{header, malformed_json, missing_organization_query, security_error},
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

pub fn router(service: ApplicationTemplateService) -> Router {
    Router::new()
        .route(
            "/v1/application-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/v1/application-templates/{template_id}",
            get(get_template)
                .patch(patch_template)
                .delete(delete_template),
        )
        .route(
            "/v1/application-templates/{template_id}/validate",
            post(validate_template),
        )
        .route(
            "/v1/application-templates/{template_id}/activate",
            post(activate_template),
        )
        .route(
            "/v1/application-templates/{template_id}/deprecate",
            post(deprecate_template),
        )
        .with_state(service)
}

#[derive(Deserialize)]
struct ListQuery {
    organization_id: Option<String>,
}

async fn create_template(
    State(service): State<ApplicationTemplateService>,
    headers: HeaderMap,
    body: Result<Json<ApplicationTemplateCreate>, JsonRejection>,
) -> Response {
    if let Err(error) = service.preflight_create(
        header(&headers, API_KEY_HEADER),
        header(&headers, ORGANIZATION_HEADER),
        header(&headers, IDEMPOTENCY_HEADER),
    ) {
        return service_error(error);
    }
    let Json(request) = match body {
        Ok(request) => request,
        Err(error) => return malformed_json(error),
    };
    result_json(
        service
            .create(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                header(&headers, IDEMPOTENCY_HEADER),
                request,
            )
            .await,
    )
}

async fn list_templates(
    State(service): State<ApplicationTemplateService>,
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
    result_json(
        service
            .list(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                organization_id,
            )
            .await,
    )
}

async fn get_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_json(
        service
            .get(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &template_id,
            )
            .await,
    )
}

async fn patch_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ApplicationTemplatePatch>, JsonRejection>,
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
    result_json(
        service
            .patch(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &template_id,
                request,
            )
            .await,
    )
}

async fn validate_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_json(
        service
            .validate(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &template_id,
            )
            .await,
    )
}

async fn activate_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_json(
        service
            .activate(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &template_id,
            )
            .await,
    )
}

async fn deprecate_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_json(
        service
            .deprecate(
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
                &template_id,
            )
            .await,
    )
}

async fn delete_template(
    State(service): State<ApplicationTemplateService>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match service
        .delete(
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
            &template_id,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => service_error(error),
    }
}

fn result_json<T: serde::Serialize>(
    result: Result<T, ApplicationTemplateServiceError>,
) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => service_error(error),
    }
}

fn service_error(error: ApplicationTemplateServiceError) -> Response {
    let (status, detail) = match error {
        ApplicationTemplateServiceError::Validation(errors) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "detail": {
                        "error": "APPLICATION_TEMPLATE_INVALID",
                        "errors": errors,
                    }
                })),
            )
                .into_response();
        }
        ApplicationTemplateServiceError::Security(error) => security_error(
            error,
            "Application Template management is temporarily unavailable",
        ),
        ApplicationTemplateServiceError::Request(error) => request_error(error),
        ApplicationTemplateServiceError::Lifecycle(error) => lifecycle_error(error),
        ApplicationTemplateServiceError::Repository(error) => repository_error(error),
        ApplicationTemplateServiceError::NotFound => {
            (StatusCode::NOT_FOUND, "Application template not found")
        }
        ApplicationTemplateServiceError::IdempotencyRequired => (
            StatusCode::BAD_REQUEST,
            "Idempotency-Key header is required",
        ),
        ApplicationTemplateServiceError::InvalidIdempotencyKey => {
            (StatusCode::BAD_REQUEST, "Idempotency-Key header is invalid")
        }
        ApplicationTemplateServiceError::Canonicalization => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Application Template request could not be canonicalized",
        ),
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn request_error(error: ApplicationTemplateRequestError) -> (StatusCode, &'static str) {
    match error {
        ApplicationTemplateRequestError::NotDraft => (
            StatusCode::CONFLICT,
            "Only draft Application Templates can be edited",
        ),
        ApplicationTemplateRequestError::VersionExhausted => (
            StatusCode::CONFLICT,
            "Application Template version is exhausted",
        ),
        ApplicationTemplateRequestError::InvalidField(_)
        | ApplicationTemplateRequestError::UnknownField(_)
        | ApplicationTemplateRequestError::Projection => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid Application Template request",
        ),
    }
}

fn lifecycle_error(error: ApplicationTemplateLifecycleError) -> (StatusCode, &'static str) {
    match error {
        ApplicationTemplateLifecycleError::PatchRequiresDraft => (
            StatusCode::CONFLICT,
            "Only draft Application Templates can be edited",
        ),
        ApplicationTemplateLifecycleError::ActivateRequiresDraft => (
            StatusCode::CONFLICT,
            "Only draft Application Templates can be activated",
        ),
        ApplicationTemplateLifecycleError::DeprecateRequiresActive => (
            StatusCode::CONFLICT,
            "Only active Application Templates can be deprecated",
        ),
        ApplicationTemplateLifecycleError::DeleteRequiresDraft => (
            StatusCode::CONFLICT,
            "Only draft Application Templates can be deleted",
        ),
        ApplicationTemplateLifecycleError::ValidationFailed => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Application Template is invalid",
        ),
        ApplicationTemplateLifecycleError::VersionExhausted => (
            StatusCode::CONFLICT,
            "Application Template version is exhausted",
        ),
    }
}

fn repository_error(error: ApplicationTemplateRepositoryError) -> (StatusCode, &'static str) {
    match error {
        ApplicationTemplateRepositoryError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            "Idempotency key was already used for a different Application Template request",
        ),
        ApplicationTemplateRepositoryError::ConcurrentModification => (
            StatusCode::CONFLICT,
            "Application Template changed concurrently; refresh and retry",
        ),
        ApplicationTemplateRepositoryError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Application Template repository is unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_error_taxonomy_preserves_public_status_and_details() {
        for (error, status, detail) in [
            (
                ApplicationTemplateServiceError::IdempotencyRequired,
                StatusCode::BAD_REQUEST,
                "Idempotency-Key header is required",
            ),
            (
                ApplicationTemplateServiceError::NotFound,
                StatusCode::NOT_FOUND,
                "Application template not found",
            ),
            (
                ApplicationTemplateServiceError::Lifecycle(
                    ApplicationTemplateLifecycleError::DeleteRequiresDraft,
                ),
                StatusCode::CONFLICT,
                "Only draft Application Templates can be deleted",
            ),
            (
                ApplicationTemplateServiceError::Repository(
                    ApplicationTemplateRepositoryError::ConcurrentModification,
                ),
                StatusCode::CONFLICT,
                "Application Template changed concurrently; refresh and retry",
            ),
        ] {
            let response = service_error(error);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.extensions().get::<String>(),
                None,
                "public response must not leak repository diagnostics: {detail}"
            );
        }
    }
}
