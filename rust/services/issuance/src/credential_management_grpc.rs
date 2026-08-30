use std::pin::Pin;

use futures_core::Stream;
use mmf_security::constant_time_secret_eq;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::{
    credential_management::{
        CredentialLifecycleAction, CredentialManagementError, CredentialManagementService,
        CredentialStatusView,
    },
    credential_management_events::{CredentialLifecycleEventBus, CredentialLifecycleEventFilter},
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
    service_token: Option<Vec<u8>>,
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
            service_token: service_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec()),
        }
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
        Err(Status::unimplemented(
            "native InitiateIssuance is not registered yet",
        ))
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
                    transaction_id: String::new(),
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::credential_management::{
        CredentialManagementPortError, CredentialManagementRepository, CredentialStatusPublisher,
        ManagedCredential, ManagedCredentialStatus,
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
