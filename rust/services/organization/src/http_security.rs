use axum::http::HeaderMap;
use mmf_security::ServiceTokenAuthenticator;
use thiserror::Error;
use uuid::Uuid;

use crate::ForwardedPrincipal;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HttpTrustError {
    #[error("ORGANIZATION.HTTP_SERVICE_AUTHENTICATION_REQUIRED")]
    ServiceAuthenticationRequired,
    #[error("ORGANIZATION.AUTHENTICATION_REQUIRED")]
    UserAuthenticationRequired,
    #[error("ORGANIZATION.INVALID_FORWARDED_API_KEY_CONTEXT")]
    InvalidApiKeyContext,
}

pub fn authenticate_forwarded_http_request(
    headers: &HeaderMap,
    service_authenticator: &ServiceTokenAuthenticator,
) -> Result<ForwardedPrincipal, HttpTrustError> {
    service_authenticator
        .authenticate(header(headers, "x-service-token"))
        .map_err(|_| HttpTrustError::ServiceAuthenticationRequired)?;
    let user_id = header(headers, "x-user-id")
        .ok_or(HttpTrustError::UserAuthenticationRequired)?
        .to_owned();
    let Some(api_key_id) = header(headers, "x-api-key-id") else {
        return Ok(ForwardedPrincipal::User { user_id });
    };
    let organization_id = header(headers, "x-organization-id")
        .and_then(|value| value.parse::<Uuid>().ok())
        .ok_or(HttpTrustError::InvalidApiKeyContext)?;
    let authorized_permission = header(headers, "x-required-permission")
        .ok_or(HttpTrustError::InvalidApiKeyContext)?
        .to_owned();
    Ok(ForwardedPrincipal::ApiKey {
        user_id,
        api_key_id: api_key_id.to_owned(),
        organization_id,
        authorized_permission,
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
