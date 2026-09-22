use axum::{
    body::to_bytes,
    extract::{FromRequest, Path, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    credential_management::CredentialManagementError,
    management_http::{header, missing_organization_query},
    oid4vci_management::{
        Oid4vciManagementError, Oid4vciManagementService, RegisteredClientRequest,
    },
    transaction_reads::TransactionReadError,
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";
const MAX_MANAGEMENT_BODY_BYTES: usize = 1_048_576;

pub fn router(service: Oid4vciManagementService) -> Router {
    Router::new()
        .route("/v1/issuance/oid4vci-clients", put(put_registered_client))
        .route(
            "/v1/issuance/transactions/{transaction_id}/revoke",
            post(revoke_transaction),
        )
        .route("/v1/issuance/credentials", get(list_credentials))
        .with_state(service)
}

async fn put_registered_client(
    State(service): State<Oid4vciManagementService>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if let Err(error) = service.preflight(header(&headers, API_KEY_HEADER)) {
        return management_error(error, None);
    }
    let bytes = match to_bytes(request.into_body(), MAX_MANAGEMENT_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return validation_error(json!(null), "Request body is invalid"),
    };
    let input: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return validation_error(json!(null), "JSON body is invalid"),
    };
    let request: RegisteredClientRequest = match serde_json::from_value(input.clone()) {
        Ok(request) => request,
        Err(error) => return validation_error(input, &error.to_string()),
    };
    match service
        .put_registered_client(
            request,
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
        )
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => management_error(error, Some(input)),
    }
}

#[derive(Debug, Deserialize)]
struct CredentialQuery {
    organization_id: Option<String>,
    status: Option<String>,
}

async fn list_credentials(
    State(service): State<Oid4vciManagementService>,
    request: Request,
) -> Response {
    let headers = request.headers();
    if let Err(error) = service.preflight(header(headers, API_KEY_HEADER)) {
        return management_error(error, None);
    }
    let Query(query) = match Query::<CredentialQuery>::try_from_uri(request.uri()) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    match service
        .list_credentials(
            query.organization_id.as_deref(),
            query.status.as_deref(),
            header(headers, API_KEY_HEADER),
            header(headers, ORGANIZATION_HEADER),
        )
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => management_error(error, None),
    }
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    reason: Option<String>,
}

async fn revoke_transaction(
    State(service): State<Oid4vciManagementService>,
    Path(transaction_id): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if let Err(error) = service.preflight(header(&headers, API_KEY_HEADER)) {
        return management_error(error, None);
    }
    let Json(request) = match Json::<RevokeRequest>::from_request(request, &()).await {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": error.body_text()})),
            )
                .into_response()
        }
    };
    match service
        .revoke_transaction(
            &transaction_id,
            request.reason.as_deref(),
            header(&headers, API_KEY_HEADER),
            header(&headers, ORGANIZATION_HEADER),
        )
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => management_error(error, None),
    }
}

fn management_error(error: Oid4vciManagementError, input: Option<Value>) -> Response {
    if matches!(
        error,
        Oid4vciManagementError::Security(TransactionReadError::OrganizationIdRequired)
    ) {
        return missing_organization_query();
    }
    if let Oid4vciManagementError::InvalidRegistration(reason) = error {
        return validation_error(
            input.unwrap_or(Value::Null),
            &format!("Value error, {reason}"),
        );
    }
    if let Oid4vciManagementError::PrivateKeyMaterial(index) = error {
        return validation_error(
            input.unwrap_or(Value::Null),
            &format!("Value error, jwks.keys[{index}] contains private key material"),
        );
    }
    let (status, detail) = match error {
        Oid4vciManagementError::Security(error) => security_error(error),
        Oid4vciManagementError::RegisteredClientNotPersisted => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Registered client was not persisted",
        ),
        Oid4vciManagementError::TransactionNotFound => {
            (StatusCode::NOT_FOUND, "Transaction not found")
        }
        Oid4vciManagementError::CredentialTenantMismatch => (
            StatusCode::CONFLICT,
            "Issued credential organization does not match its transaction",
        ),
        Oid4vciManagementError::CredentialLifecycle(
            CredentialManagementError::PublicationUnavailable(_),
        ) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Revocation service rejected the status change",
        ),
        Oid4vciManagementError::RepositoryUnavailable
        | Oid4vciManagementError::CredentialLifecycle(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "OID4VCI management service is temporarily unavailable",
        ),
        Oid4vciManagementError::InvalidRegistration(_) => unreachable!(),
        Oid4vciManagementError::PrivateKeyMaterial(_) => unreachable!(),
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
        TransactionReadError::ResourceNotFound => (StatusCode::NOT_FOUND, "Resource not found"),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "OID4VCI management service is temporarily unavailable",
        ),
    }
}

fn validation_error(input: Value, message: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "detail": [{
                "type": "value_error",
                "loc": ["body"],
                "msg": message,
                "input": input,
                "ctx": {"error": {}}
            }]
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_errors_are_structured_and_sanitized() {
        let response = management_error(Oid4vciManagementError::RepositoryUnavailable, None);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = management_error(
            Oid4vciManagementError::Security(TransactionReadError::ResourceNotFound),
            None,
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn body_limit_is_explicit_and_bounded() {
        assert_eq!(MAX_MANAGEMENT_BODY_BYTES, 1_048_576);
    }
}
