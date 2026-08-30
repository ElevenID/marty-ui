use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::{
    initiation::{
        InitiationDependencyError, InitiationRepositoryError, InitiationRequest, InitiationService,
        InitiationServiceError,
    },
    initiation_response::{
        InitiationOfferProjectionError, InitiationOfferProjector, InitiationOfferResponse,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

const DIRECT_SIGNING_HEADERS: &[&str] = &[
    "x-signing-service-id",
    "x-signing-key-reference",
    "x-key-reference",
    "x-issuer-profile-id",
    "x-issuer-mode",
    "x-issuer-did",
];
const DIRECT_SIGNING_DETAIL: &str =
    "Direct signing or issuer-profile selection is not allowed; supply issuer_did in the request body.";

#[derive(Clone, Debug)]
pub struct InitiationHttpService {
    initiation: InitiationService,
    projector: InitiationOfferProjector,
    security: ManagementSecurity,
}

impl InitiationHttpService {
    #[must_use]
    pub fn new(
        initiation: InitiationService,
        projector: InitiationOfferProjector,
        management_api_key: Option<&str>,
    ) -> Self {
        Self {
            initiation,
            projector,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub async fn initiate(
        &self,
        headers: &HeaderMap,
        request: &InitiationRequest,
    ) -> Result<InitiationOfferResponse, InitiationHttpError> {
        self.authorize(headers)?;
        self.initiate_authorized(headers, request).await
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), InitiationHttpError> {
        self.security
            .authorize(header(headers, "X-API-Key"))
            .map_err(Into::into)
    }

    pub async fn initiate_authorized(
        &self,
        headers: &HeaderMap,
        request: &InitiationRequest,
    ) -> Result<InitiationOfferResponse, InitiationHttpError> {
        reject_direct_signing_headers(headers)?;
        let reservation = self
            .initiation
            .initiate(request, header(headers, "Idempotency-Key"))
            .await?;
        self.projector
            .project(reservation, request)
            .await
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitiationHttpError {
    Security(TransactionReadError),
    DirectSigningSelection,
    Service(InitiationServiceError),
    Projection(InitiationOfferProjectionError),
    Unavailable,
}

impl From<TransactionReadError> for InitiationHttpError {
    fn from(value: TransactionReadError) -> Self {
        Self::Security(value)
    }
}

impl From<InitiationServiceError> for InitiationHttpError {
    fn from(value: InitiationServiceError) -> Self {
        Self::Service(value)
    }
}

impl From<InitiationOfferProjectionError> for InitiationHttpError {
    fn from(value: InitiationOfferProjectionError) -> Self {
        Self::Projection(value)
    }
}

impl IntoResponse for InitiationHttpError {
    fn into_response(self) -> Response {
        let failure = self.failure();
        (failure.status, Json(json!({"detail": failure.detail}))).into_response()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InitiationHttpFailure {
    status: StatusCode,
    detail: Value,
}

impl InitiationHttpError {
    fn failure(&self) -> InitiationHttpFailure {
        match self {
            Self::Security(error) => security_failure(error),
            Self::DirectSigningSelection => failure(422, DIRECT_SIGNING_DETAIL),
            Self::Service(error) => service_failure(error),
            Self::Projection(_) | Self::Unavailable => {
                failure(503, "Credential offer projection is unavailable")
            }
        }
    }
}

fn service_failure(error: &InitiationServiceError) -> InitiationHttpFailure {
    match error {
        InitiationServiceError::Request(error) => failure(422, error.to_string()),
        InitiationServiceError::Repository(InitiationRepositoryError::IdempotencyConflict) => {
            failure(409, error.to_string())
        }
        InitiationServiceError::Repository(_)
        | InitiationServiceError::InvalidIssuerBaseUrl
        | InitiationServiceError::AuthorizedClientDependency(_)
        | InitiationServiceError::IssuerUnavailable
        | InitiationServiceError::IssuerContextMismatch => failure(503, error.to_string()),
        InitiationServiceError::OrganizationNotFound => failure(404, error.to_string()),
        InitiationServiceError::AuthorizedClientNotRegistered
        | InitiationServiceError::AuthorizedClientInactive
        | InitiationServiceError::AuthorizedClientAuthMethod
        | InitiationServiceError::TemplateIssuerMissing
        | InitiationServiceError::TemplateIssuerMismatch
        | InitiationServiceError::TemplateAlgorithmUnsupported
        | InitiationServiceError::CredentialSubjectFormat
        | InitiationServiceError::CredentialDocumentFormat
        | InitiationServiceError::IdempotentDidcommUnsupported
        | InitiationServiceError::UnsupportedPayloadFormat => failure(422, error.to_string()),
        InitiationServiceError::Template(dependency) => template_failure(dependency),
        InitiationServiceError::RelatedResourceValidation(dependency) => {
            related_resource_failure(dependency)
        }
        InitiationServiceError::RevocationProfile(dependency) => revocation_failure(dependency),
    }
}

fn template_failure(error: &InitiationDependencyError) -> InitiationHttpFailure {
    match error {
        InitiationDependencyError::NotFound => failure(404, "Credential template not found"),
        InitiationDependencyError::Invalid(detail) => failure(422, detail),
        InitiationDependencyError::HttpClient { status, detail } => InitiationHttpFailure {
            status: StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY),
            detail: Value::String(detail.clone()),
        },
        InitiationDependencyError::Unavailable => {
            failure(503, "Credential template service unavailable")
        }
        InitiationDependencyError::Timeout => failure(504, "Credential template service timeout"),
    }
}

fn related_resource_failure(error: &InitiationDependencyError) -> InitiationHttpFailure {
    match error {
        InitiationDependencyError::Invalid(code) => InitiationHttpFailure {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            detail: json!({"error": code}),
        },
        InitiationDependencyError::NotFound | InitiationDependencyError::HttpClient { .. } => {
            failure(422, "related_resource_unavailable")
        }
        InitiationDependencyError::Unavailable => {
            failure(503, "VCDM related-resource validation is unavailable")
        }
        InitiationDependencyError::Timeout => {
            failure(504, "VCDM related-resource validation timed out")
        }
    }
}

fn revocation_failure(error: &InitiationDependencyError) -> InitiationHttpFailure {
    match error {
        InitiationDependencyError::NotFound => failure(422, "Revocation Profile not found."),
        InitiationDependencyError::Invalid(detail) => failure(422, detail),
        InitiationDependencyError::Unavailable
        | InitiationDependencyError::Timeout
        | InitiationDependencyError::HttpClient { .. } => {
            failure(503, "Revocation Profile validation is unavailable.")
        }
    }
}

fn security_failure(error: &TransactionReadError) -> InitiationHttpFailure {
    match error {
        TransactionReadError::ApiKeyNotConfigured => {
            failure(503, "ISSUANCE_API_KEY not configured on server")
        }
        TransactionReadError::ApiKeyMissing => failure(401, "X-API-Key header is missing"),
        TransactionReadError::InvalidApiKey => failure(401, "Invalid API Key"),
        _ => failure(503, "Management authentication is unavailable"),
    }
}

fn reject_direct_signing_headers(headers: &HeaderMap) -> Result<(), InitiationHttpError> {
    if DIRECT_SIGNING_HEADERS.iter().any(|name| {
        header(headers, name)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    }) {
        Err(InitiationHttpError::DirectSigningSelection)
    } else {
        Ok(())
    }
}

fn failure(status: u16, detail: impl Into<String>) -> InitiationHttpFailure {
    InitiationHttpFailure {
        status: StatusCode::from_u16(status).expect("static HTTP status is valid"),
        detail: Value::String(detail.into()),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initiation::InitiationError;

    #[test]
    fn direct_signing_headers_are_rejected_only_when_non_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-signing-service-id", "".parse().unwrap());
        assert_eq!(reject_direct_signing_headers(&headers), Ok(()));
        headers.insert("x-issuer-profile-id", "profile-1".parse().unwrap());
        assert_eq!(
            reject_direct_signing_headers(&headers),
            Err(InitiationHttpError::DirectSigningSelection)
        );
        assert_eq!(
            InitiationHttpError::DirectSigningSelection.failure(),
            failure(422, DIRECT_SIGNING_DETAIL)
        );
    }

    #[test]
    fn status_mapping_preserves_the_language_neutral_contract() {
        let cases = [
            (
                InitiationHttpError::Service(InitiationServiceError::OrganizationNotFound),
                404,
            ),
            (
                InitiationHttpError::Service(InitiationServiceError::Repository(
                    InitiationRepositoryError::IdempotencyConflict,
                )),
                409,
            ),
            (
                InitiationHttpError::Service(InitiationServiceError::Request(
                    InitiationError::IssuerDidRequired,
                )),
                422,
            ),
            (
                InitiationHttpError::Service(InitiationServiceError::Template(
                    InitiationDependencyError::Timeout,
                )),
                504,
            ),
            (
                InitiationHttpError::Service(InitiationServiceError::RevocationProfile(
                    InitiationDependencyError::Unavailable,
                )),
                503,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.failure().status.as_u16(), expected);
        }

        let client_error = InitiationHttpError::Service(InitiationServiceError::Template(
            InitiationDependencyError::HttpClient {
                status: 409,
                detail: "template conflict".into(),
            },
        ))
        .failure();
        assert_eq!(client_error.status, StatusCode::CONFLICT);
        assert_eq!(client_error.detail, "template conflict");

        let related =
            InitiationHttpError::Service(InitiationServiceError::RelatedResourceValidation(
                InitiationDependencyError::Invalid("related_resource_digest_mismatch".into()),
            ))
            .failure();
        assert_eq!(related.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            related.detail,
            json!({"error":"related_resource_digest_mismatch"})
        );
    }

    #[test]
    fn management_auth_statuses_match_existing_native_routes() {
        assert_eq!(
            InitiationHttpError::Security(TransactionReadError::ApiKeyNotConfigured)
                .failure()
                .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            InitiationHttpError::Security(TransactionReadError::ApiKeyMissing)
                .failure()
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            InitiationHttpError::Security(TransactionReadError::InvalidApiKey)
                .failure()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
}
