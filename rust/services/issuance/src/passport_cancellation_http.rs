use super::*;
use crate::passport_cancellation::CancellationRequest;
use crate::passport_repository::CancellationError;

pub(super) async fn cancel_administratively(
    State(service): State<PassportHttpService>,
    Path(application_id): Path<String>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, PassportHttpError> {
    let principal = service.authenticate(&headers)?;
    if uri.query().is_some() || body.len() > 4096 {
        return Err(PassportHttpError::InvalidCancellationRequest);
    }
    let media_type = header(&headers, "content-type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(PassportHttpError::InvalidCancellationRequest);
    }
    // Typed deserialization rejects duplicate fields as well as unknown fields.
    let request: CancellationRequest =
        serde_json::from_slice(&body).map_err(|_| PassportHttpError::InvalidCancellationRequest)?;
    let key = passport_start_header_key(&headers)?
        .ok_or(PassportHttpError::InvalidCancellationRequest)?;
    let command = request
        .validate(principal.organization_id(), &key)
        .ok_or(PassportHttpError::InvalidCancellationRequest)?;
    // PassportTenantPrincipal exposes a verified organization, not a trusted
    // credential/user identifier. Audit the tenant credential honestly rather
    // than treating caller-supplied x-user-id as an authenticated person.
    let outcome = service
        .repository
        .cancel_administratively(
            &principal,
            &application_id,
            &command,
            database_precision_now(),
        )
        .await
        .map_err(|error| match error {
            CancellationError::Storage(error) => PassportHttpError::Storage(error),
            CancellationError::NotFound => PassportHttpError::ApplicationNotFound,
            CancellationError::StateConflict => PassportHttpError::CancellationConflict,
            CancellationError::ReplayConflict => PassportHttpError::CancellationReplayConflict,
        })?;
    Ok(Json(json!({
        "job":safe(&outcome.job), "administrative_cancellation":outcome.audit,
        "bureau_cancellation_requested":false, "flow_cancellation_requested":false,
        "replayed":outcome.replayed
    })))
}
