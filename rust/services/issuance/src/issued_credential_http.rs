use axum::{
    extract::{rejection::JsonRejection, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleAuditContext, CredentialManagementError,
    },
    issued_credential_records::{IssuedCredentialAdapterError, IssuedCredentialAdapterService},
    management_http::{header, malformed_json, missing_organization_query},
    transaction_reads::TransactionReadError,
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";

pub fn router(service: IssuedCredentialAdapterService) -> Router {
    Router::new()
        .route("/v1/issued-credentials", get(list_issued_credentials))
        .route(
            "/v1/issued-credentials/{credential_id}",
            get(get_issued_credential),
        )
        .route(
            "/v1/issued-credentials/{credential_id}/revoke",
            post(revoke_issued_credential),
        )
        .route(
            "/v1/issued-credentials/{credential_id}/suspend",
            post(suspend_issued_credential),
        )
        .route(
            "/v1/issued-credentials/{credential_id}/reinstate",
            post(reinstate_issued_credential),
        )
        .with_state(service)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleRequest {
    reason: Option<String>,
    comments: Option<String>,
}

async fn list_issued_credentials(
    State(service): State<IssuedCredentialAdapterService>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let organization_id = query_value(raw_query.as_deref(), "organization_id");
    let status = query_value(raw_query.as_deref(), "status");
    result_json(
        service
            .list(
                organization_id.as_deref(),
                status.as_deref(),
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
            )
            .await,
    )
}

async fn get_issued_credential(
    State(service): State<IssuedCredentialAdapterService>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    result_json(
        service
            .get(
                &credential_id,
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
            )
            .await,
    )
}

async fn revoke_issued_credential(
    state: State<IssuedCredentialAdapterService>,
    path: Path<String>,
    headers: HeaderMap,
    body: Result<Json<LifecycleRequest>, JsonRejection>,
) -> Response {
    transition(
        state,
        path,
        headers,
        body,
        CredentialLifecycleAction::Revoke,
    )
    .await
}

async fn suspend_issued_credential(
    state: State<IssuedCredentialAdapterService>,
    path: Path<String>,
    headers: HeaderMap,
    body: Result<Json<LifecycleRequest>, JsonRejection>,
) -> Response {
    transition(
        state,
        path,
        headers,
        body,
        CredentialLifecycleAction::Suspend,
    )
    .await
}

async fn reinstate_issued_credential(
    state: State<IssuedCredentialAdapterService>,
    path: Path<String>,
    headers: HeaderMap,
    body: Result<Json<LifecycleRequest>, JsonRejection>,
) -> Response {
    transition(
        state,
        path,
        headers,
        body,
        CredentialLifecycleAction::Reinstate,
    )
    .await
}

async fn transition(
    State(service): State<IssuedCredentialAdapterService>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<LifecycleRequest>, JsonRejection>,
    action: CredentialLifecycleAction,
) -> Response {
    if let Err(error) = service.preflight(header(&headers, API_KEY_HEADER)) {
        return adapter_error(error);
    }
    let Json(request) = match body {
        Ok(request) => request,
        Err(error) => return malformed_json(error),
    };
    let (actor_id, actor_type) = actor(&headers);
    let audit = CredentialLifecycleAuditContext {
        comments: request.comments,
        actor_id,
        actor_type,
    };
    result_json(
        service
            .transition(
                &credential_id,
                action,
                request.reason.as_deref(),
                &audit,
                header(&headers, API_KEY_HEADER),
                header(&headers, ORGANIZATION_HEADER),
            )
            .await,
    )
}

fn result_json<T: serde::Serialize>(result: Result<T, IssuedCredentialAdapterError>) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => adapter_error(error),
    }
}

fn adapter_error(error: IssuedCredentialAdapterError) -> Response {
    if matches!(
        error,
        IssuedCredentialAdapterError::Security(TransactionReadError::OrganizationIdRequired)
    ) {
        return missing_organization_query();
    }
    let (status, detail) = match error {
        IssuedCredentialAdapterError::NotFound
        | IssuedCredentialAdapterError::Security(TransactionReadError::ResourceNotFound) => {
            (StatusCode::NOT_FOUND, "Issued credential not found")
        }
        IssuedCredentialAdapterError::RepositoryUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Issued credential data is temporarily unavailable",
        ),
        IssuedCredentialAdapterError::Security(error) => security_error(error),
        IssuedCredentialAdapterError::Lifecycle(error) => lifecycle_error(error),
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn security_error(error: TransactionReadError) -> (StatusCode, &'static str) {
    match error {
        TransactionReadError::ApiKeyNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        TransactionReadError::ApiKeyMissing => {
            (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
        TransactionReadError::TrustedOrganizationRequired => (
            StatusCode::FORBIDDEN,
            "Trusted organization context is required",
        ),
        TransactionReadError::OrganizationMismatch => (
            StatusCode::FORBIDDEN,
            "Organization context does not match requested organization",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Issued credential data is temporarily unavailable",
        ),
    }
}

fn lifecycle_error(error: CredentialManagementError) -> (StatusCode, &'static str) {
    match error {
        CredentialManagementError::NotFound => (StatusCode::NOT_FOUND, "Credential not found"),
        CredentialManagementError::ResourceNotFound => {
            (StatusCode::NOT_FOUND, "Issued credential not found")
        }
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
        CredentialManagementError::CanvasTextEncoding => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas lifecycle status text could not be encoded",
        ),
    }
}

fn actor(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    for name in ["x-authenticated-user-id", "x-user-id"] {
        if let Some(value) = header(headers, name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return (Some(value.to_owned()), Some("user".to_owned()));
        }
    }
    header(headers, "x-api-key-id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| (Some(value.to_owned()), Some("api_key".to_owned())))
        .unwrap_or((None, None))
}

fn query_value(raw_query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(raw_query?.as_bytes())
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .last()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn query_parity_uses_last_duplicate_value() {
        assert_eq!(
            query_value(
                Some("organization_id=first&organization_id=last"),
                "organization_id"
            )
            .as_deref(),
            Some("last")
        );
    }

    #[test]
    fn actor_prefers_sanitized_user_over_api_key_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("user-1"));
        headers.insert("x-api-key-id", HeaderValue::from_static("key-1"));
        assert_eq!(
            actor(&headers),
            (Some("user-1".to_owned()), Some("user".to_owned()))
        );
    }
}
