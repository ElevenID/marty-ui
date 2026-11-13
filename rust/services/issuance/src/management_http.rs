//! Shared HTTP boundary helpers for management surfaces.

use axum::{
    extract::rejection::JsonRejection,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    credential_management::CredentialManagementError, transaction_reads::TransactionReadError,
};

#[derive(Clone, Copy)]
pub(crate) enum LifecycleSurface {
    Transaction,
    IssuedCredential,
}

pub(crate) fn lifecycle_error(
    error: CredentialManagementError,
    surface: LifecycleSurface,
) -> Response {
    let (status, detail) = match error {
        CredentialManagementError::NotFound => (StatusCode::NOT_FOUND, "Credential not found"),
        CredentialManagementError::ResourceNotFound => (
            StatusCode::NOT_FOUND,
            match surface {
                LifecycleSurface::Transaction => "Resource not found",
                LifecycleSurface::IssuedCredential => "Issued credential not found",
            },
        ),
        CredentialManagementError::AlreadyRevoked => {
            (StatusCode::BAD_REQUEST, "Credential already revoked")
        }
        CredentialManagementError::CannotSuspendRevoked => {
            (StatusCode::BAD_REQUEST, "Cannot suspend revoked credential")
        }
        CredentialManagementError::CannotReinstateRevoked => (
            StatusCode::BAD_REQUEST,
            "Cannot reinstate revoked credential",
        ),
        CredentialManagementError::NotSuspended => (
            StatusCode::BAD_REQUEST,
            "Only suspended credentials can be reinstated",
        ),
        CredentialManagementError::ReasonTooLong => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Credential lifecycle reason exceeds 2000 characters",
        ),
        CredentialManagementError::CommentsTooLong => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Credential lifecycle comments exceed 4000 characters",
        ),
        CredentialManagementError::PublicationUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Revocation service unavailable",
        ),
        CredentialManagementError::RepositoryUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Credential repository is temporarily unavailable",
        ),
        CredentialManagementError::CanvasRetryUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas lifecycle retry could not be recorded",
        ),
        CredentialManagementError::CanvasTextEncoding => match surface {
            LifecycleSurface::Transaction => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            LifecycleSurface::IssuedCredential => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Canvas lifecycle status text could not be encoded",
            ),
        },
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

pub(crate) fn authentication_error(
    error: &TransactionReadError,
) -> Option<(StatusCode, &'static str)> {
    Some(match error {
        TransactionReadError::ApiKeyNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        TransactionReadError::ApiKeyMissing => {
            (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
        _ => return None,
    })
}

pub(crate) fn security_error(
    error: TransactionReadError,
    unavailable_detail: &'static str,
) -> (StatusCode, &'static str) {
    if let Some(response) = authentication_error(&error) {
        return response;
    }
    match error {
        TransactionReadError::TrustedOrganizationRequired => (
            StatusCode::BAD_REQUEST,
            "X-Organization-ID is required for application management",
        ),
        TransactionReadError::OrganizationMismatch | TransactionReadError::ResourceNotFound => {
            (StatusCode::NOT_FOUND, "Application resource not found")
        }
        TransactionReadError::OrganizationIdRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "organization_id query parameter is required",
        ),
        _ => (StatusCode::SERVICE_UNAVAILABLE, unavailable_detail),
    }
}

pub(crate) fn malformed_json(error: JsonRejection) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail": error.body_text()})),
    )
        .into_response()
}

pub(crate) fn malformed_query() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"detail": "Query parameters are invalid"})),
    )
        .into_response()
}

pub(crate) fn missing_organization_query() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "detail": [{
                "type": "missing",
                "loc": ["query", "organization_id"],
                "msg": "Field required",
                "input": null,
            }]
        })),
    )
        .into_response()
}

pub(crate) fn missing_header(name: &'static str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "detail": [{
                "type": "missing",
                "loc": ["header", name],
                "msg": "Field required",
                "input": null,
            }]
        })),
    )
        .into_response()
}

pub(crate) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_surfaces_preserve_resource_hiding_and_encoding_envelopes() {
        for (surface, error, status, content_type, body) in [
            (
                LifecycleSurface::Transaction,
                CredentialManagementError::ResourceNotFound,
                StatusCode::NOT_FOUND,
                "application/json",
                r#"{"detail":"Resource not found"}"#,
            ),
            (
                LifecycleSurface::IssuedCredential,
                CredentialManagementError::ResourceNotFound,
                StatusCode::NOT_FOUND,
                "application/json",
                r#"{"detail":"Issued credential not found"}"#,
            ),
            (
                LifecycleSurface::Transaction,
                CredentialManagementError::CanvasTextEncoding,
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                "Internal Server Error",
            ),
            (
                LifecycleSurface::IssuedCredential,
                CredentialManagementError::CanvasTextEncoding,
                StatusCode::SERVICE_UNAVAILABLE,
                "application/json",
                r#"{"detail":"Canvas lifecycle status text could not be encoded"}"#,
            ),
        ] {
            let response = lifecycle_error(error, surface);
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["content-type"], content_type);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap()
                    .as_ref(),
                body.as_bytes()
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_failures_do_not_expose_repository_or_publication_diagnostics() {
        for surface in [
            LifecycleSurface::Transaction,
            LifecycleSurface::IssuedCredential,
        ] {
            for (error, detail) in [
                (
                    CredentialManagementError::RepositoryUnavailable("private diagnostic".into()),
                    "Credential repository is temporarily unavailable",
                ),
                (
                    CredentialManagementError::PublicationUnavailable("private diagnostic".into()),
                    "Revocation service unavailable",
                ),
                (
                    CredentialManagementError::CanvasRetryUnavailable("private diagnostic".into()),
                    "Canvas lifecycle retry could not be recorded",
                ),
            ] {
                let response = lifecycle_error(error, surface);
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    json!({"detail": detail})
                );
            }
        }
    }
    #[test]
    fn shared_authentication_does_not_choose_tenant_or_resource_policy() {
        for (error, status, detail) in [
            (
                TransactionReadError::ApiKeyMissing,
                StatusCode::UNAUTHORIZED,
                "X-API-Key header is missing",
            ),
            (
                TransactionReadError::InvalidApiKey,
                StatusCode::UNAUTHORIZED,
                "Invalid API Key",
            ),
            (
                TransactionReadError::ApiKeyNotConfigured,
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server",
            ),
        ] {
            assert_eq!(authentication_error(&error), Some((status, detail)));
            assert_eq!(security_error(error, "unavailable"), (status, detail));
        }
        for error in [
            TransactionReadError::TrustedOrganizationRequired,
            TransactionReadError::OrganizationMismatch,
            TransactionReadError::ResourceNotFound,
        ] {
            assert_eq!(authentication_error(&error), None);
        }
        assert_eq!(
            security_error(
                TransactionReadError::TrustedOrganizationRequired,
                "unavailable"
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            security_error(TransactionReadError::OrganizationMismatch, "unavailable").0,
            StatusCode::NOT_FOUND
        );
    }
}
