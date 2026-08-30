use std::{pin::Pin, sync::Arc};

use futures_core::Stream;
use mmf_security::constant_time_secret_eq;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::{
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
        issuance_service_server::IssuanceService, CredentialEvent, CredentialLifecycleRequest,
        CredentialStatusResponse, ExchangeTokenRequest, GetCredentialStatusRequest,
        GetOfferRequest, GetTransactionRequest, HealthCheckRequest, HealthCheckResponse,
        InitiateIssuanceRequest, IssuanceResponse, IssueCredentialRequest, IssueCredentialResponse,
        ListTransactionsRequest, ListTransactionsResponse, OfferResponse,
        StreamCredentialEventsRequest, TokenResponse, TransactionResponse,
    },
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct CredentialManagementGrpcService {
    lifecycle: CredentialManagementService,
    events: CredentialLifecycleEventBus,
    initiation: Option<Arc<InitiationGrpcPlatform>>,
    service_token: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct InitiationGrpcPlatform {
    service: InitiationService,
    projector: InitiationOfferProjector,
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
    #[cfg(test)]
    pub(crate) fn new(
        lifecycle: CredentialManagementService,
        events: CredentialLifecycleEventBus,
        service_token: Option<&str>,
    ) -> Self {
        Self {
            lifecycle,
            events,
            initiation: None,
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
        self.initiation = Some(Arc::new(InitiationGrpcPlatform { service, projector }));
        self
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
        let platform = self.initiation.as_ref().ok_or_else(|| {
            Status::unimplemented("native InitiateIssuance is not registered yet")
        })?;
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
        Err(Status::unimplemented(
            "native ExchangeToken gRPC is not registered yet",
        ))
    }

    async fn issue_credential(
        &self,
        request: Request<IssueCredentialRequest>,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        self.authorize(&request)?;
        Err(Status::unimplemented(
            "native IssueCredential gRPC is not registered yet",
        ))
    }

    async fn get_offer(
        &self,
        request: Request<GetOfferRequest>,
    ) -> Result<Response<OfferResponse>, Status> {
        self.authorize(&request)?;
        Err(Status::unimplemented(
            "native GetOffer gRPC is not registered yet",
        ))
    }

    async fn list_transactions(
        &self,
        request: Request<ListTransactionsRequest>,
    ) -> Result<Response<ListTransactionsResponse>, Status> {
        self.authorize(&request)?;
        Err(Status::unimplemented(
            "native ListTransactions gRPC is not registered yet",
        ))
    }

    async fn get_transaction(
        &self,
        request: Request<GetTransactionRequest>,
    ) -> Result<Response<TransactionResponse>, Status> {
        self.authorize(&request)?;
        Err(Status::unimplemented(
            "native GetTransaction gRPC is not registered yet",
        ))
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
            CredentialManagementGrpcService::new(lifecycle, events, Some(SERVICE_TOKEN)),
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
            claims: std::collections::HashMap::from([("ignored".into(), "legacy".into())]),
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
        assert!(!stored.claims.contains_key("ignored"));
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
    fn partial_grpc_candidate_is_not_registered_by_the_executable() {
        let main = include_str!("main.rs");
        assert!(!main.contains("CredentialManagementGrpcService"));
        assert!(!main.contains("IssuanceServiceServer"));
    }
}
