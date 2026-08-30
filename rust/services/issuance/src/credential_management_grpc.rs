use std::{pin::Pin, sync::Arc};

use futures_core::Stream;
use mmf_security::constant_time_secret_eq;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::{
    credential::{
        CredentialIssuanceError, CredentialIssuanceService, CredentialRequest, CredentialResponse,
        IssuedCredential,
    },
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleEvent, CredentialLifecycleEventSink,
        CredentialManagementError, CredentialManagementService, CredentialStatusView,
    },
    credential_management_events::{CredentialLifecycleEventBus, CredentialLifecycleEventFilter},
    initiation::{
        InitiationDependencyError, InitiationRepositoryError, InitiationRequest, InitiationService,
        InitiationServiceError,
    },
    initiation_response::{
        InitiationOfferProjectionError, InitiationOfferProjector, InitiationOfferResponse,
    },
    issuance_proto::{
        issuance_service_server::IssuanceService, CredentialEntry, CredentialEvent,
        CredentialLifecycleRequest, CredentialStatusResponse, ExchangeTokenRequest,
        GetCredentialStatusRequest, GetOfferRequest, GetTransactionRequest, HealthCheckRequest,
        HealthCheckResponse, InitiateIssuanceRequest, IssuanceResponse, IssueCredentialRequest,
        IssueCredentialResponse, ListTransactionsRequest, ListTransactionsResponse, OfferResponse,
        StreamCredentialEventsRequest, TokenResponse, TransactionResponse,
    },
    token_exchange::{
        TokenExchangeError, TokenExchangeRequest as DomainTokenExchangeRequest,
        TokenExchangeService,
    },
    transaction_reads::{
        IssuanceTransactionResponse, TransactionReadError, TransactionReadService,
        TransactionStatus,
    },
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct CredentialManagementGrpcService {
    lifecycle: CredentialManagementService,
    events: CredentialLifecycleEventBus,
    platform: Option<Arc<IssuanceGrpcPlatform>>,
    #[cfg(test)]
    initiation_override: Option<Arc<InitiationGrpcPlatform>>,
    service_token: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct InitiationGrpcPlatform {
    service: InitiationService,
    projector: InitiationOfferProjector,
}

/// Canonical issuance services exposed through the authenticated internal
/// gRPC transport. Keeping these services together makes partial production
/// registration impossible.
#[derive(Clone, Debug)]
pub struct IssuanceGrpcPlatform {
    initiation: InitiationGrpcPlatform,
    token_exchange: TokenExchangeService,
    credential: CredentialIssuanceService,
    transactions: TransactionReadService,
    issuer_base_url: Arc<str>,
}

impl IssuanceGrpcPlatform {
    #[must_use]
    pub fn new(
        initiation: InitiationService,
        projector: InitiationOfferProjector,
        token_exchange: TokenExchangeService,
        credential: CredentialIssuanceService,
        transactions: TransactionReadService,
        issuer_base_url: &str,
    ) -> Self {
        Self {
            initiation: InitiationGrpcPlatform {
                service: initiation,
                projector,
            },
            token_exchange,
            credential,
            transactions,
            issuer_base_url: Arc::from(issuer_base_url.trim_end_matches('/')),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer_base_url)
    }
}

impl std::fmt::Debug for CredentialManagementGrpcService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialManagementGrpcService")
            .field("service_token_configured", &self.service_token.is_some())
            .finish_non_exhaustive()
    }
}

impl CredentialManagementGrpcService {
    #[must_use]
    pub fn new(
        lifecycle: CredentialManagementService,
        events: CredentialLifecycleEventBus,
        platform: IssuanceGrpcPlatform,
        service_token: Option<&str>,
    ) -> Self {
        Self {
            lifecycle,
            events,
            platform: Some(Arc::new(platform)),
            #[cfg(test)]
            initiation_override: None,
            service_token: service_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec()),
        }
    }

    #[cfg(test)]
    fn lifecycle_candidate(
        lifecycle: CredentialManagementService,
        events: CredentialLifecycleEventBus,
        service_token: Option<&str>,
    ) -> Self {
        Self {
            lifecycle,
            events,
            platform: None,
            initiation_override: None,
            service_token: service_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec()),
        }
    }

    #[cfg(test)]
    fn with_initiation(
        mut self,
        service: InitiationService,
        projector: InitiationOfferProjector,
    ) -> Self {
        self.initiation_override = Some(Arc::new(InitiationGrpcPlatform { service, projector }));
        self
    }

    fn platform(&self) -> Result<&IssuanceGrpcPlatform, Status> {
        self.platform
            .as_deref()
            .ok_or_else(|| Status::internal("native issuance gRPC platform is not configured"))
    }

    fn initiation(&self) -> Result<&InitiationGrpcPlatform, Status> {
        #[cfg(test)]
        if let Some(platform) = self.initiation_override.as_deref() {
            return Ok(platform);
        }
        self.platform().map(|platform| &platform.initiation)
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let expected = self
            .service_token
            .as_deref()
            .ok_or_else(|| Status::internal("gRPC service token is not configured"))?;
        let supplied = request
            .metadata()
            .get(SERVICE_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::as_bytes)
            .ok_or_else(|| Status::unauthenticated("Missing or invalid service token"))?;
        if constant_time_secret_eq(supplied, expected) {
            Ok(())
        } else {
            Err(Status::unauthenticated("Missing or invalid service token"))
        }
    }

    async fn transition(
        &self,
        request: Request<CredentialLifecycleRequest>,
        action: CredentialLifecycleAction,
    ) -> Result<Response<CredentialStatusResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let reason = (!request.reason.is_empty()).then_some(request.reason.as_str());
        self.lifecycle
            .transition(&request.credential_id, None, action, reason)
            .await
            .map(status_response)
            .map(Response::new)
            .map_err(lifecycle_status)
    }

    async fn emit_issued(&self, credential: &IssuedCredential) {
        self.events.emit(issued_event(credential)).await;
    }
}

#[tonic::async_trait]
impl IssuanceService for CredentialManagementGrpcService {
    type StreamCredentialEventsStream =
        Pin<Box<dyn Stream<Item = Result<CredentialEvent, Status>> + Send + 'static>>;

    async fn initiate_issuance(
        &self,
        request: Request<InitiateIssuanceRequest>,
    ) -> Result<Response<IssuanceResponse>, Status> {
        self.authorize(&request)?;
        let platform = self.initiation()?;
        let request = initiation_request(request.into_inner())?;
        let idempotency_key = request
            .idempotency_key
            .as_deref()
            .filter(|value| !value.is_empty());
        let reservation = platform
            .service
            .initiate(&request.request, idempotency_key)
            .await
            .map_err(initiation_status)?;
        let created = reservation.created;
        let event = CredentialLifecycleEvent {
            event_type: "offer_created".to_owned(),
            credential_id: String::new(),
            transaction_id: reservation.transaction.id.clone(),
            organization_id: reservation.transaction.organization_id.clone(),
            credential_template_id: reservation.transaction.credential_template_id.clone(),
            status: "pending".to_owned(),
            timestamp: chrono::Utc::now(),
        };
        let response = platform
            .projector
            .project(reservation, &request.request)
            .await
            .map_err(projection_status)?;
        if created {
            self.events.emit(event).await;
        }
        Ok(Response::new(issuance_response(response)))
    }

    async fn exchange_token(
        &self,
        request: Request<ExchangeTokenRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        self.authorize(&request)?;
        let platform = self.platform()?;
        let response = platform
            .token_exchange
            .exchange(
                &token_exchange_request(request.into_inner()),
                None,
                &platform.endpoint("/v1/issuance/token"),
            )
            .await
            .map_err(token_status)?;
        Ok(Response::new(TokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: i32::try_from(response.expires_in).unwrap_or(i32::MAX),
            c_nonce: String::new(),
            nonce: String::new(),
        }))
    }

    async fn issue_credential(
        &self,
        request: Request<IssueCredentialRequest>,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        self.authorize(&request)?;
        let platform = self.platform()?;
        let request = request.into_inner();
        let authorization = format!("Bearer {}", request.access_token);
        let outcome = platform
            .credential
            .issue_with_outcome(
                &credential_request(request)?,
                Some(&authorization),
                None,
                &platform.endpoint("/v1/issuance/credential"),
            )
            .await
            .map_err(credential_status)?;
        let response = credential_response(outcome.response)?;
        if let Some(credential) = outcome.issued_credential.as_ref() {
            self.emit_issued(credential).await;
        }
        Ok(Response::new(response))
    }

    async fn get_offer(
        &self,
        request: Request<GetOfferRequest>,
    ) -> Result<Response<OfferResponse>, Status> {
        self.authorize(&request)?;
        let offer = self
            .platform()?
            .transactions
            .offer(&request.into_inner().transaction_id)
            .await
            .map_err(transaction_status)?;
        let offer_json = serde_json::to_string(&offer)
            .map_err(|_| Status::internal("credential offer could not be encoded"))?;
        Ok(Response::new(OfferResponse { offer_json }))
    }

    async fn list_transactions(
        &self,
        request: Request<ListTransactionsRequest>,
    ) -> Result<Response<ListTransactionsResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        if request.limit < 0 || request.offset < 0 || request.limit > 500 {
            return Err(Status::invalid_argument("pagination is out of range"));
        }
        let status = optional(request.status)
            .map(|value| grpc_transaction_status(&value))
            .transpose()?;
        let mut transactions = self
            .platform()?
            .transactions
            .list_authorized(&request.organization_id)
            .await
            .map_err(transaction_status)?;
        if let Some(status) = status {
            transactions.retain(|transaction| transaction.status == status);
        }
        let total = i32::try_from(transactions.len()).unwrap_or(i32::MAX);
        let take = if request.limit == 0 {
            100
        } else {
            request.limit as usize
        };
        let transactions = transactions
            .into_iter()
            .skip(request.offset as usize)
            .take(take)
            .map(transaction_response)
            .collect();
        Ok(Response::new(ListTransactionsResponse {
            transactions,
            total,
        }))
    }

    async fn get_transaction(
        &self,
        request: Request<GetTransactionRequest>,
    ) -> Result<Response<TransactionResponse>, Status> {
        self.authorize(&request)?;
        self.platform()?
            .transactions
            .get_authorized(&request.into_inner().transaction_id)
            .await
            .map(transaction_response)
            .map(Response::new)
            .map_err(transaction_status)
    }

    async fn revoke_credential(
        &self,
        request: Request<CredentialLifecycleRequest>,
    ) -> Result<Response<CredentialStatusResponse>, Status> {
        self.transition(request, CredentialLifecycleAction::Revoke)
            .await
    }

    async fn suspend_credential(
        &self,
        request: Request<CredentialLifecycleRequest>,
    ) -> Result<Response<CredentialStatusResponse>, Status> {
        self.transition(request, CredentialLifecycleAction::Suspend)
            .await
    }

    async fn reinstate_credential(
        &self,
        request: Request<CredentialLifecycleRequest>,
    ) -> Result<Response<CredentialStatusResponse>, Status> {
        self.transition(request, CredentialLifecycleAction::Reinstate)
            .await
    }

    async fn get_credential_status(
        &self,
        request: Request<GetCredentialStatusRequest>,
    ) -> Result<Response<CredentialStatusResponse>, Status> {
        self.authorize(&request)?;
        self.lifecycle
            .get_status(&request.into_inner().credential_id, None)
            .await
            .map(status_response)
            .map(Response::new)
            .map_err(lifecycle_status)
    }

    async fn stream_credential_events(
        &self,
        request: Request<StreamCredentialEventsRequest>,
    ) -> Result<Response<Self::StreamCredentialEventsStream>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let organization_id =
            (!request.organization_id.is_empty()).then_some(request.organization_id.as_str());
        let credential_template_id = (!request.credential_template_id.is_empty())
            .then_some(request.credential_template_id.as_str());
        let stream = self
            .events
            .subscribe(CredentialLifecycleEventFilter::new(
                organization_id,
                credential_template_id,
                request.event_types,
            ))
            .map(|event| {
                Ok(CredentialEvent {
                    event_type: event.event_type,
                    credential_id: event.credential_id,
                    transaction_id: event.transaction_id,
                    organization_id: event.organization_id,
                    credential_template_id: event.credential_template_id,
                    status: event.status,
                    timestamp: event
                        .timestamp
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false),
                })
            });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.authorize(&request)?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".to_owned(),
        }))
    }
}

struct ParsedInitiationRequest {
    request: InitiationRequest,
    idempotency_key: Option<String>,
}

fn initiation_request(value: InitiateIssuanceRequest) -> Result<ParsedInitiationRequest, Status> {
    if !value.claims_json.trim().is_empty() && !value.claims.is_empty() {
        return Err(Status::invalid_argument(
            "claims and claims_json cannot both be supplied",
        ));
    }
    let claims = if value.claims_json.trim().is_empty() {
        value
            .claims
            .into_iter()
            .map(|(name, value)| (name, serde_json::Value::String(value)))
            .collect()
    } else {
        serde_json::from_str::<serde_json::Value>(&value.claims_json)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .ok_or_else(|| Status::invalid_argument("claims_json must be a JSON object"))?
    };
    Ok(ParsedInitiationRequest {
        request: InitiationRequest {
            organization_id: value.organization_id,
            credential_template_id: optional(value.credential_template_id),
            application_id: optional(value.application_id),
            applicant_id: optional(value.applicant_id),
            subject_did: optional(value.subject_did),
            holder_did: optional(value.holder_did),
            issuer_did: value.issuer_did,
            authorized_client_id: optional(value.authorized_client_id),
            delivery_mode: value.delivery_mode,
            claims: Some(claims),
            credential_subject: None,
            credential_document: None,
        },
        idempotency_key: optional(value.idempotency_key),
    })
}

fn issuance_response(value: InitiationOfferResponse) -> IssuanceResponse {
    IssuanceResponse {
        id: value.id,
        organization_id: value.organization_id,
        credential_template_id: value.credential_template_id,
        status: value.status,
        credential_offer_uri: value.credential_offer_uri,
        credential_offer_uris: value.credential_offer_uris.into_iter().collect(),
        credential_offer_labels: value.credential_offer_labels.into_iter().collect(),
        pre_auth_code: value.pre_auth_code,
        expires_at: value.expires_at,
    }
}

fn initiation_status(error: InitiationServiceError) -> Status {
    match error {
        InitiationServiceError::Request(_) => Status::invalid_argument(error.to_string()),
        InitiationServiceError::Repository(InitiationRepositoryError::IdempotencyConflict) => {
            Status::already_exists(error.to_string())
        }
        InitiationServiceError::Repository(_) => Status::unavailable(error.to_string()),
        InitiationServiceError::OrganizationNotFound => Status::not_found(error.to_string()),
        InitiationServiceError::AuthorizedClientNotRegistered
        | InitiationServiceError::AuthorizedClientInactive
        | InitiationServiceError::AuthorizedClientAuthMethod => {
            Status::failed_precondition(error.to_string())
        }
        InitiationServiceError::AuthorizedClientDependency(_) => {
            Status::unavailable(error.to_string())
        }
        InitiationServiceError::Template(InitiationDependencyError::NotFound) => {
            Status::not_found(error.to_string())
        }
        InitiationServiceError::Template(
            InitiationDependencyError::Unavailable | InitiationDependencyError::Timeout,
        ) => Status::unavailable(error.to_string()),
        InitiationServiceError::Template(_) => Status::internal(error.to_string()),
        InitiationServiceError::TemplateIssuerMissing
        | InitiationServiceError::TemplateAlgorithmUnsupported => {
            Status::failed_precondition(error.to_string())
        }
        InitiationServiceError::TemplateIssuerMismatch
        | InitiationServiceError::CredentialSubjectFormat
        | InitiationServiceError::CredentialDocumentFormat
        | InitiationServiceError::IdempotentDidcommUnsupported
        | InitiationServiceError::UnsupportedPayloadFormat => {
            Status::invalid_argument(error.to_string())
        }
        InitiationServiceError::RelatedResourceValidation(_) => {
            Status::invalid_argument(error.to_string())
        }
        InitiationServiceError::RevocationProfile(InitiationDependencyError::NotFound) => {
            Status::not_found(error.to_string())
        }
        InitiationServiceError::RevocationProfile(InitiationDependencyError::Invalid(_)) => {
            Status::failed_precondition(error.to_string())
        }
        InitiationServiceError::RevocationProfile(_) => Status::unavailable(error.to_string()),
        InitiationServiceError::InvalidIssuerBaseUrl
        | InitiationServiceError::IssuerUnavailable => Status::unavailable(error.to_string()),
        InitiationServiceError::IssuerContextMismatch => {
            Status::failed_precondition(error.to_string())
        }
    }
}

fn projection_status(error: InitiationOfferProjectionError) -> Status {
    Status::unavailable(error.to_string())
}

fn optional(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn token_exchange_request(value: ExchangeTokenRequest) -> DomainTokenExchangeRequest {
    DomainTokenExchangeRequest {
        grant_type: value.grant_type,
        pre_authorized_code: optional(value.pre_authorized_code),
        code: optional(value.code),
        redirect_uri: optional(value.redirect_uri),
        client_id: optional(value.client_id),
        code_verifier: optional(value.code_verifier),
        client_assertion_type: optional(value.client_assertion_type),
        client_assertion: optional(value.client_assertion),
    }
}

fn credential_request(value: IssueCredentialRequest) -> Result<CredentialRequest, Status> {
    let mut proofs = serde_json::Map::new();
    for proof in value.proofs {
        let proof_type = proof.proof_type.trim();
        if proof_type.is_empty() || proof.jwt.is_empty() {
            return Err(Status::invalid_argument(
                "each credential proof requires proof_type and jwt",
            ));
        }
        let entry = proofs
            .entry(proof_type.to_owned())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        let serde_json::Value::Array(values) = entry else {
            return Err(Status::internal("credential proof projection failed"));
        };
        values.push(serde_json::Value::String(proof.jwt));
    }
    let credential_configuration_id = optional(value.credential_configuration_id);
    let credential_identifier = optional(value.credential_identifier);
    let legacy_format = optional(value.format).or_else(|| {
        (credential_configuration_id.is_none() && credential_identifier.is_none())
            .then(|| "vc+sd-jwt".to_owned())
    });
    Ok(CredentialRequest {
        proofs: (!proofs.is_empty()).then_some(proofs),
        credential_configuration_id,
        credential_identifier,
        legacy_format,
    })
}

fn credential_response(value: CredentialResponse) -> Result<IssueCredentialResponse, Status> {
    let credentials = value
        .credentials
        .into_iter()
        .map(|entry| {
            let object = entry.as_object().ok_or_else(|| {
                Status::internal("credential response entry is not a JSON object")
            })?;
            let format = object
                .get("format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let credential = object
                .get("credential")
                .ok_or_else(|| Status::internal("credential response entry has no credential"))?;
            let credential = credential.as_str().map_or_else(
                || serde_json::to_string(credential),
                |value| Ok(value.to_owned()),
            );
            Ok(CredentialEntry {
                format,
                credential: credential
                    .map_err(|_| Status::internal("credential response could not be encoded"))?,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    Ok(IssueCredentialResponse {
        credentials,
        notification_id: value.notification_id,
        c_nonce: String::new(),
    })
}

fn grpc_transaction_status(value: &str) -> Result<TransactionStatus, Status> {
    match value {
        "pending" => Ok(TransactionStatus::Pending),
        "authorized" => Ok(TransactionStatus::Authorized),
        "signing" => Ok(TransactionStatus::Signing),
        "issued" => Ok(TransactionStatus::Issued),
        "failed" => Ok(TransactionStatus::Failed),
        "expired" => Ok(TransactionStatus::Expired),
        "revoked" => Ok(TransactionStatus::Revoked),
        _ => Err(Status::invalid_argument("transaction status is invalid")),
    }
}

fn transaction_status_name(value: TransactionStatus) -> &'static str {
    match value {
        TransactionStatus::Pending => "pending",
        TransactionStatus::Authorized => "authorized",
        TransactionStatus::Signing => "signing",
        TransactionStatus::Issued => "issued",
        TransactionStatus::Failed => "failed",
        TransactionStatus::Expired => "expired",
        TransactionStatus::Revoked => "revoked",
    }
}

fn transaction_response(value: IssuanceTransactionResponse) -> TransactionResponse {
    let updated_at = value.created_at.clone();
    TransactionResponse {
        id: value.id,
        organization_id: value.organization_id,
        credential_template_id: value.credential_template_id,
        status: transaction_status_name(value.status).to_owned(),
        applicant_id: value.applicant_id.unwrap_or_default(),
        subject_did: value.subject_did.unwrap_or_default(),
        created_at: value.created_at,
        // The persisted issuance contract has no distinct updated_at column.
        // Keep the legacy protobuf member populated with the last timestamp we
        // can prove rather than inventing a mutation time.
        updated_at,
    }
}

fn token_status(error: TokenExchangeError) -> Status {
    use TokenExchangeError as Error;
    match error {
        Error::GrantTypeRequired
        | Error::AuthorizationCodeRequired
        | Error::PreAuthorizedCodeRequired
        | Error::UnsupportedGrantType
        | Error::InvalidDpopProof
        | Error::Protocol(_) => Status::invalid_argument(error.to_string()),
        Error::InvalidAuthorizationCode | Error::InvalidPreAuthorizedCode => {
            Status::not_found(error.to_string())
        }
        Error::InvalidClient => Status::unauthenticated(error.to_string()),
        Error::AuthorizationCodeExpired
        | Error::AuthorizationCodeUsed
        | Error::TransactionExpired
        | Error::PreAuthorizedCodeUsed
        | Error::InvalidTransactionState => Status::failed_precondition(error.to_string()),
        Error::RepositoryUnavailable => Status::internal(error.to_string()),
    }
}

fn credential_status(error: CredentialIssuanceError) -> Status {
    use CredentialIssuanceError as Error;
    match error {
        Error::MissingAuthorization | Error::InvalidAccessToken => {
            Status::unauthenticated(error.to_string())
        }
        Error::SelectorRequired
        | Error::UnknownConfiguration(_)
        | Error::UnknownIdentifier(_)
        | Error::ProofRequired
        | Error::MalformedProof
        | Error::AudienceMismatch { .. }
        | Error::InvalidNonce
        | Error::InvalidProof(_)
        | Error::MdocHolderKeyRequired
        | Error::UnsupportedFormat(_)
        | Error::InvalidDpopProof
        | Error::DpopMismatch => Status::invalid_argument(error.to_string()),
        Error::DpopRequired
        | Error::CredentialAlreadyIssued
        | Error::InvalidTransactionState
        | Error::IssuanceInProgress
        | Error::RevocationProfileRequired
        | Error::CanvasEligibilityDenied => Status::failed_precondition(error.to_string()),
        Error::IssuerUnavailable(_)
        | Error::SigningUnavailable(_)
        | Error::LifecycleUnavailable(_) => Status::unavailable(error.to_string()),
        Error::NonceRepositoryUnavailable
        | Error::RepositoryUnavailable
        | Error::BuilderChangedCredentialId
        | Error::InvalidStoredDataIntegrityCredential => Status::internal(error.to_string()),
    }
}

fn transaction_status(error: TransactionReadError) -> Status {
    use TransactionReadError as Error;
    match error {
        Error::OfferNotFound | Error::TransactionNotFound | Error::ResourceNotFound => {
            Status::not_found(error.to_string())
        }
        Error::OfferExpired => Status::failed_precondition(error.to_string()),
        Error::OrganizationIdRequired => Status::invalid_argument(error.to_string()),
        Error::ApiKeyMissing | Error::InvalidApiKey => Status::unauthenticated(error.to_string()),
        Error::TrustedOrganizationRequired | Error::OrganizationMismatch => {
            Status::permission_denied(error.to_string())
        }
        Error::RepositoryUnavailable | Error::OfferUnavailable | Error::ApiKeyNotConfigured => {
            Status::internal(error.to_string())
        }
    }
}

fn status_response(value: CredentialStatusView) -> CredentialStatusResponse {
    CredentialStatusResponse {
        id: value.id,
        status: value.status,
        status_updated_at: value
            .status_updated_at
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false),
        reason: value.reason.unwrap_or_default(),
    }
}

fn issued_event(credential: &IssuedCredential) -> CredentialLifecycleEvent {
    CredentialLifecycleEvent {
        event_type: "issued".to_owned(),
        credential_id: credential.id.clone(),
        transaction_id: credential.transaction_id.clone(),
        organization_id: credential.organization_id.clone(),
        credential_template_id: credential.credential_template_id.clone(),
        status: "issued".to_owned(),
        timestamp: chrono::Utc::now(),
    }
}

fn lifecycle_status(error: CredentialManagementError) -> Status {
    match error {
        CredentialManagementError::NotFound | CredentialManagementError::ResourceNotFound => {
            Status::not_found(error.to_string())
        }
        CredentialManagementError::ReasonTooLong => Status::invalid_argument(error.to_string()),
        CredentialManagementError::AlreadyRevoked
        | CredentialManagementError::CannotSuspendRevoked
        | CredentialManagementError::CannotReinstateRevoked
        | CredentialManagementError::NotSuspended => Status::failed_precondition(error.to_string()),
        CredentialManagementError::RepositoryUnavailable(_)
        | CredentialManagementError::PublicationUnavailable(_)
        | CredentialManagementError::CanvasRetryUnavailable(_) => {
            Status::internal(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration as StdDuration,
    };

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::credential_management::{
        CredentialManagementPortError, CredentialManagementRepository, CredentialStatusPublisher,
        ManagedCredential, ManagedCredentialStatus,
    };
    use crate::{
        credential::{
            CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
        },
        initiation::{
            IdempotencyBinding, InitiationApplicationClaimsResolver, InitiationClientRepository,
            InitiationClock, InitiationDependencyError, InitiationOrganizationValidator,
            InitiationPorts, InitiationRegisteredClient, InitiationRelatedResourceValidator,
            InitiationRepository, InitiationReservation, InitiationRevocationProfileValidator,
            InitiationSeed, InitiationSeedGenerator, InitiationTemplate,
            InitiationTemplateResolver, OrganizationValidation,
        },
        initiation_response::{
            InitiationDidcommDelivery, InitiationDidcommDeliveryError,
            InitiationDidcommDeliveryReceipt,
        },
    };

    const SERVICE_TOKEN: &str = "service-token-with-at-least-32-bytes";

    #[derive(Clone)]
    struct Harness {
        credential: Arc<Mutex<Option<ManagedCredential>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl CredentialManagementRepository for Harness {
        async fn get(
            &self,
            credential_id: &str,
        ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
            self.calls.lock().expect("calls").push("load".to_owned());
            Ok(self
                .credential
                .lock()
                .expect("credential")
                .clone()
                .filter(|credential| credential.id == credential_id))
        }

        async fn persist(
            &self,
            credential: &ManagedCredential,
            expected_status: ManagedCredentialStatus,
        ) -> Result<ManagedCredential, CredentialManagementPortError> {
            self.calls.lock().expect("calls").push("persist".to_owned());
            let mut stored = self.credential.lock().expect("credential");
            if stored.as_ref().map(|value| value.status) != Some(expected_status) {
                return Err(CredentialManagementPortError("stale status".to_owned()));
            }
            *stored = Some(credential.clone());
            Ok(credential.clone())
        }

        async fn synchronize_canvas(
            &self,
            _credential: &ManagedCredential,
            action: CredentialLifecycleAction,
            _reason: Option<&str>,
        ) -> Result<(), CredentialManagementPortError> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("canvas:{}", action.as_str()));
            Ok(())
        }
    }

    #[async_trait]
    impl CredentialStatusPublisher for Harness {
        async fn publish(
            &self,
            _credential: &ManagedCredential,
            action: CredentialLifecycleAction,
            _reason: Option<&str>,
        ) -> Result<(), CredentialManagementPortError> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("publish:{}", action.as_str()));
            Ok(())
        }
    }

    fn candidate() -> (CredentialManagementGrpcService, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let harness = Harness {
            credential: Arc::new(Mutex::new(Some(ManagedCredential {
                id: "credential-a".to_owned(),
                organization_id: "org-a".to_owned(),
                credential_template_id: "template-a".to_owned(),
                issuer_did: None,
                status: ManagedCredentialStatus::Active,
                status_updated_at: Utc
                    .with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
                    .single()
                    .expect("timestamp"),
                revoked: false,
                revoked_at: None,
                revocation_reason: None,
                revocation_profile_id: Some("profile-a".to_owned()),
                status_list_entries: vec![json!({"index": 1})],
            }))),
            calls: calls.clone(),
        };
        let events = CredentialLifecycleEventBus::default();
        let lifecycle = CredentialManagementService::new(
            Arc::new(harness.clone()),
            Arc::new(harness),
            Arc::new(events.clone()),
        );
        (
            CredentialManagementGrpcService::lifecycle_candidate(
                lifecycle,
                events,
                Some(SERVICE_TOKEN),
            ),
            calls,
        )
    }

    fn authenticated<T>(message: T) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert(SERVICE_TOKEN_HEADER, SERVICE_TOKEN.parse().expect("token"));
        request
    }

    struct GrpcInitiationRepository {
        first: AtomicBool,
        stored: Arc<Mutex<Option<CredentialTransaction>>>,
    }

    #[async_trait]
    impl InitiationRepository for GrpcInitiationRepository {
        async fn recover_idempotently(
            &self,
            _organization_id: &str,
            _binding: &IdempotencyBinding,
        ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
            Ok(None)
        }

        async fn reserve_idempotently(
            &self,
            transaction: &CredentialTransaction,
        ) -> Result<InitiationReservation, InitiationRepositoryError> {
            *self.stored.lock().expect("stored transaction") = Some(transaction.clone());
            Ok(InitiationReservation {
                transaction: transaction.clone(),
                created: self.first.swap(false, Ordering::SeqCst),
            })
        }
    }

    struct GrpcOrganizations;

    #[async_trait]
    impl InitiationOrganizationValidator for GrpcOrganizations {
        async fn validate(&self, _organization_id: &str) -> OrganizationValidation {
            OrganizationValidation::Found
        }
    }

    struct GrpcClients;

    #[async_trait]
    impl InitiationClientRepository for GrpcClients {
        async fn get(
            &self,
            _organization_id: &str,
            client_id: &str,
        ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
            Ok(Some(InitiationRegisteredClient {
                client_id: client_id.to_owned(),
                active: true,
                token_endpoint_auth_method: "private_key_jwt".into(),
            }))
        }
    }

    struct GrpcTemplates;

    #[async_trait]
    impl InitiationTemplateResolver for GrpcTemplates {
        async fn resolve(
            &self,
            _template_id: &str,
        ) -> Result<InitiationTemplate, InitiationDependencyError> {
            Ok(InitiationTemplate {
                credential_type: "EmployeeCredential".into(),
                credential_payload_format: "w3c_vcdm_v2_jwt_vc".into(),
                revocation_profile_id: Some("profile-1".into()),
                issuer_did: Some("did:web:issuer.example".into()),
                issuer_algorithm: Some("ES256".into()),
                ..InitiationTemplate::default()
            })
        }
    }

    struct GrpcRevocation;

    #[async_trait]
    impl InitiationRevocationProfileValidator for GrpcRevocation {
        async fn validate_active(
            &self,
            organization_id: &str,
            profile_id: Option<&str>,
        ) -> Result<(), InitiationDependencyError> {
            assert_eq!(organization_id, "org-a");
            assert_eq!(profile_id, Some("profile-1"));
            Ok(())
        }
    }

    struct GrpcApplications;

    #[async_trait]
    impl InitiationApplicationClaimsResolver for GrpcApplications {
        async fn resolve(&self, _application_id: &str) -> Result<Option<Map<String, Value>>, ()> {
            Ok(None)
        }
    }

    struct GrpcRelatedResources;

    #[async_trait]
    impl InitiationRelatedResourceValidator for GrpcRelatedResources {
        async fn validate(
            &self,
            _credential_document: &Value,
        ) -> Result<(), InitiationDependencyError> {
            Ok(())
        }
    }

    struct GrpcIssuer;

    #[async_trait]
    impl IssuerContextResolver for GrpcIssuer {
        async fn resolve(
            &self,
            transaction: &CredentialTransaction,
            credential_format: &str,
            force: bool,
        ) -> Result<IssuerContext, CredentialIssuanceError> {
            assert_eq!(
                transaction.issuer_did.as_deref(),
                Some("did:web:issuer.example")
            );
            assert_eq!(credential_format, "jwt_vc_json");
            assert!(!force);
            Ok(IssuerContext {
                issuer_profile_id: "issuer-profile-1".into(),
                issuer_did: "did:web:issuer.example".into(),
                signing_service_id: "kms-1".into(),
                algorithm: "ES256".into(),
                verification_method_id: Some("did:web:issuer.example#key-1".into()),
                public_jwk: None,
                certificate_chain: Vec::new(),
                raw_context: json!({}),
            })
        }
    }

    struct GrpcSeeds;

    impl InitiationSeedGenerator for GrpcSeeds {
        fn generate(&self) -> InitiationSeed {
            InitiationSeed {
                transaction_id: "00000000-0000-4000-8000-000000000001".into(),
                pre_authorized_code: "a".repeat(43),
            }
        }
    }

    struct GrpcClock;

    impl InitiationClock for GrpcClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
                .single()
                .unwrap()
        }
    }

    struct GrpcDidcomm;

    #[async_trait]
    impl InitiationDidcommDelivery for GrpcDidcomm {
        async fn deliver(
            &self,
            _transaction: &CredentialTransaction,
            _holder_did: &str,
        ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
            Err(InitiationDidcommDeliveryError)
        }
    }

    fn initiation_platform() -> (
        InitiationService,
        InitiationOfferProjector,
        Arc<Mutex<Option<CredentialTransaction>>>,
    ) {
        let stored = Arc::new(Mutex::new(None));
        let service = InitiationService::new(
            InitiationPorts {
                repository: Arc::new(GrpcInitiationRepository {
                    first: AtomicBool::new(true),
                    stored: stored.clone(),
                }),
                organizations: Arc::new(GrpcOrganizations),
                clients: Arc::new(GrpcClients),
                templates: Arc::new(GrpcTemplates),
                revocation_profiles: Arc::new(GrpcRevocation),
                applications: Arc::new(GrpcApplications),
                related_resources: Arc::new(GrpcRelatedResources),
                issuer_resolver: Arc::new(GrpcIssuer),
                seeds: Arc::new(GrpcSeeds),
                clock: Arc::new(GrpcClock),
            },
            "https://issuer.example",
        )
        .unwrap();
        let projector =
            InitiationOfferProjector::new("https://issuer.example", Arc::new(GrpcDidcomm)).unwrap();
        (service, projector, stored)
    }

    #[tokio::test]
    async fn initiation_rpc_reuses_the_domain_and_emits_only_committed_creation() {
        let (candidate, _calls) = candidate();
        let mut events = candidate
            .events
            .subscribe(CredentialLifecycleEventFilter::new(
                Some("org-a"),
                Some("template-a"),
                ["offer_created".to_owned()],
            ));
        let (initiation, projector, stored) = initiation_platform();
        let service = candidate.with_initiation(initiation, projector);
        let request = InitiateIssuanceRequest {
            organization_id: "org-a".into(),
            credential_template_id: "template-a".into(),
            applicant_id: "applicant-a".into(),
            subject_did: "did:key:holder".into(),
            claims: std::collections::HashMap::new(),
            holder_did: String::new(),
            authorized_client_id: String::new(),
            application_id: "application-a".into(),
            issuer_did: "did:web:issuer.example".into(),
            delivery_mode: "wallet_only".into(),
            idempotency_key: String::new(),
            claims_json: r#"{"profile":{"level":2},"roles":["member"]}"#.into(),
        };
        let response = service
            .initiate_issuance(authenticated(request.clone()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.id, "00000000-0000-4000-8000-000000000001");
        assert_eq!(response.organization_id, "org-a");
        assert_eq!(response.credential_template_id, "template-a");
        assert_eq!(response.status, "pending");
        assert_eq!(response.pre_auth_code.len(), 43);
        assert!(response
            .credential_offer_uri
            .starts_with("openid-credential-offer://"));
        let stored = stored
            .lock()
            .expect("stored transaction")
            .clone()
            .expect("committed transaction");
        assert_eq!(stored.claims["profile"], json!({"level":2}));
        assert_eq!(stored.claims["roles"], json!(["member"]));
        let event = events.recv().await.expect("offer-created event");
        assert_eq!(event.event_type, "offer_created");
        assert_eq!(event.transaction_id, response.id);
        assert_eq!(event.organization_id, "org-a");
        assert_eq!(event.credential_template_id, "template-a");

        service
            .initiate_issuance(authenticated(request))
            .await
            .expect("atomic recovery response");
        assert!(
            tokio::time::timeout(StdDuration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    #[test]
    fn initiation_grpc_projection_rejects_non_object_nested_claims() {
        let error = initiation_request(InitiateIssuanceRequest {
            claims_json: "[]".into(),
            ..InitiateIssuanceRequest::default()
        })
        .err()
        .expect("non-object claims are invalid");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let conflict = initiation_request(InitiateIssuanceRequest {
            claims: std::collections::HashMap::from([("name".into(), "Ada".into())]),
            claims_json: r#"{"name":"Ada"}"#.into(),
            ..InitiateIssuanceRequest::default()
        })
        .err()
        .expect("legacy and nested claims are mutually exclusive");
        assert_eq!(conflict.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn lifecycle_rpcs_authenticate_then_reuse_the_canonical_handler_and_stream() {
        let (service, calls) = candidate();
        let unauthenticated = service
            .suspend_credential(Request::new(CredentialLifecycleRequest {
                credential_id: "credential-a".to_owned(),
                reason: String::new(),
            }))
            .await
            .expect_err("service token required");
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
        assert!(calls.lock().expect("calls").is_empty());

        let mut events = service
            .stream_credential_events(authenticated(StreamCredentialEventsRequest {
                organization_id: "org-a".to_owned(),
                credential_template_id: "template-a".to_owned(),
                event_types: vec!["suspended".to_owned()],
            }))
            .await
            .expect("stream")
            .into_inner();
        let response = service
            .suspend_credential(authenticated(CredentialLifecycleRequest {
                credential_id: "credential-a".to_owned(),
                reason: "review".to_owned(),
            }))
            .await
            .expect("suspend")
            .into_inner();
        assert_eq!(response.id, "credential-a");
        assert_eq!(response.status, "suspended");
        assert_eq!(response.reason, "review");
        assert!(response.status_updated_at.ends_with("+00:00"));
        assert_eq!(
            *calls.lock().expect("calls"),
            ["load", "publish:suspend", "persist", "canvas:suspend"]
        );

        let event = events.next().await.expect("stream item").expect("event");
        assert_eq!(event.event_type, "suspended");
        assert_eq!(event.credential_id, "credential-a");
        assert_eq!(event.transaction_id, "");
        assert_eq!(event.organization_id, "org-a");
        assert_eq!(event.credential_template_id, "template-a");
        assert_eq!(event.status, "suspended");
        assert!(event.timestamp.ends_with("+00:00"));
    }

    #[tokio::test]
    async fn committed_issuance_preserves_the_legacy_issued_stream_event() {
        let (service, _calls) = candidate();
        let mut events = service
            .stream_credential_events(authenticated(StreamCredentialEventsRequest {
                organization_id: "org-a".to_owned(),
                credential_template_id: "template-a".to_owned(),
                event_types: vec!["issued".to_owned()],
            }))
            .await
            .expect("stream")
            .into_inner();
        let issued_at = Utc
            .with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
            .single()
            .expect("timestamp");
        service
            .emit_issued(&IssuedCredential {
                id: "credential-issued".to_owned(),
                transaction_id: "transaction-issued".to_owned(),
                organization_id: "org-a".to_owned(),
                credential_template_id: "template-a".to_owned(),
                applicant_id: Some("applicant-a".to_owned()),
                subject_did: Some("did:key:holder".to_owned()),
                issuer_did: "did:web:issuer.example".to_owned(),
                revocation_profile_id: Some("profile-a".to_owned()),
                renewed_from_credential_id: None,
                status_list_entries: vec![json!({"index": 1})],
                credential: "header.payload.signature".to_owned(),
                credential_hash: "credential-hash".to_owned(),
                issued_at,
                expires_at: issued_at + chrono::Duration::days(365),
            })
            .await;

        let event = events.next().await.expect("stream item").expect("event");
        assert_eq!(event.event_type, "issued");
        assert_eq!(event.credential_id, "credential-issued");
        assert_eq!(event.transaction_id, "transaction-issued");
        assert_eq!(event.organization_id, "org-a");
        assert_eq!(event.credential_template_id, "template-a");
        assert_eq!(event.status, "issued");
        assert!(event.timestamp.ends_with("+00:00"));
    }

    #[tokio::test]
    async fn lifecycle_rpc_errors_preserve_transport_specific_codes() {
        let (service, calls) = candidate();
        let not_suspended = service
            .reinstate_credential(authenticated(CredentialLifecycleRequest {
                credential_id: "credential-a".to_owned(),
                reason: "review".to_owned(),
            }))
            .await
            .expect_err("active credential cannot be reinstated");
        assert_eq!(not_suspended.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            not_suspended.message(),
            "Only suspended credentials can be reinstated"
        );
        assert_eq!(*calls.lock().expect("calls"), ["load"]);

        calls.lock().expect("calls").clear();
        let oversized = service
            .suspend_credential(authenticated(CredentialLifecycleRequest {
                credential_id: "credential-a".to_owned(),
                reason: "x".repeat(2_001),
            }))
            .await
            .expect_err("reason is bounded");
        assert_eq!(oversized.code(), tonic::Code::InvalidArgument);
        assert_eq!(*calls.lock().expect("calls"), ["load"]);

        calls.lock().expect("calls").clear();
        let status = service
            .get_credential_status(authenticated(GetCredentialStatusRequest {
                credential_id: "missing".to_owned(),
            }))
            .await
            .expect_err("missing credential");
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(status.message(), "Credential not found");
        assert_eq!(*calls.lock().expect("calls"), ["load"]);
    }

    #[test]
    fn complete_grpc_platform_is_registered_by_the_executable() {
        let main = include_str!("main.rs");
        assert!(main.contains("CredentialManagementGrpcService::new"));
        assert!(main.contains("IssuanceServiceServer::new"));
        assert!(main.contains("config.grpc_addr"));
        assert!(main.contains("tonic_health::server::health_reporter"));
        let production = include_str!("credential_management_grpc.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(!production.contains("Status::unimplemented"));
    }

    #[test]
    fn grpc_request_projections_preserve_canonical_protocol_fields() {
        let token = token_exchange_request(ExchangeTokenRequest {
            grant_type: "authorization_code".into(),
            code: "code-a".into(),
            redirect_uri: "https://wallet.example/callback".into(),
            client_id: "wallet-a".into(),
            code_verifier: "verifier-a".into(),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            client_assertion: "assertion-a".into(),
            ..ExchangeTokenRequest::default()
        });
        assert_eq!(token.grant_type, "authorization_code");
        assert_eq!(token.code.as_deref(), Some("code-a"));
        assert_eq!(token.client_id.as_deref(), Some("wallet-a"));
        assert_eq!(token.code_verifier.as_deref(), Some("verifier-a"));

        let credential = credential_request(IssueCredentialRequest {
            access_token: "access-a".into(),
            format: "OpenBadgeCredential#sd-jwt".into(),
            proofs: vec![
                crate::issuance_proto::ProofJwt {
                    proof_type: "jwt".into(),
                    jwt: "proof-a".into(),
                },
                crate::issuance_proto::ProofJwt {
                    proof_type: "jwt".into(),
                    jwt: "proof-b".into(),
                },
            ],
            credential_configuration_id: String::new(),
            credential_identifier: String::new(),
        })
        .expect("credential projection");
        assert!(credential.credential_configuration_id.is_none());
        assert_eq!(
            credential.legacy_format.as_deref(),
            Some("OpenBadgeCredential#sd-jwt")
        );
        assert_eq!(
            credential.proofs.as_ref().expect("proofs")["jwt"],
            json!(["proof-a", "proof-b"])
        );

        let default_format = credential_request(IssueCredentialRequest::default())
            .expect("legacy gRPC default format");
        assert_eq!(default_format.legacy_format.as_deref(), Some("vc+sd-jwt"));
    }

    #[test]
    fn grpc_response_projections_preserve_json_credentials_and_status_codes() {
        let response = credential_response(CredentialResponse {
            credentials: vec![json!({
                "format": "ldp_vc",
                "credential": {"@context": ["https://www.w3.org/ns/credentials/v2"]}
            })],
            notification_id: "notification-a".into(),
        })
        .expect("response projection");
        assert_eq!(response.notification_id, "notification-a");
        assert_eq!(response.credentials[0].format, "ldp_vc");
        assert_eq!(
            serde_json::from_str::<Value>(&response.credentials[0].credential).unwrap(),
            json!({"@context": ["https://www.w3.org/ns/credentials/v2"]})
        );
        assert_eq!(
            token_status(TokenExchangeError::InvalidClient).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            credential_status(CredentialIssuanceError::RepositoryUnavailable).code(),
            tonic::Code::Internal
        );
        assert_eq!(
            transaction_status(TransactionReadError::TransactionNotFound).code(),
            tonic::Code::NotFound
        );
    }
}
