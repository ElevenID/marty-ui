//! Shared complete native tonic platform. Only initiation is exercised; other
//! credential-service side-effect ports fail closed. Real DIDComm delivery, when
//! selected, belongs to the supplied shared initiation projector, not those ports.
use async_trait::async_trait;
use marty_issuance_service::{
    client_auth::RegisteredClientAuthenticator,
    credential::{
        AllocatedCredentialStatus, BuiltCredential, CredentialBuildRequest, CredentialBuilder,
        CredentialIssuanceError, CredentialIssuanceService, CredentialLifecycle, CredentialPorts,
        CredentialTransaction, IssuedCredential, IssuerContext, IssuerContextResolver,
        UuidNotificationIdGenerator,
    },
    credential_issuer::NativeCredentialProofVerifier,
    credential_management::{
        CredentialLifecycleAction, CredentialManagementPortError, CredentialManagementService,
        CredentialStatusPublisher, ManagedCredential,
    },
    credential_management_events::CredentialLifecycleEventBus,
    credential_management_grpc::{CredentialManagementGrpcService, IssuanceGrpcPlatform},
    credential_management_postgres::PostgresCredentialManagementRepository,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    issuance_proto::issuance_service_server::IssuanceServiceServer,
    token_exchange::{MartyTokenGenerator, TokenExchangeService},
    token_postgres::PostgresTokenExchangeRepository,
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::TransactionReadService,
};
use std::{sync::Arc, time::Duration};

use marty_issuance_service::{
    credential_postgres::PostgresCredentialRepository, initiation::InitiationService,
    initiation_response::InitiationOfferProjector,
};
use mmf_platform::{GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial};
use sqlx::PgPool;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
const ISSUER_URL: &str = "https://issuer.example";
struct Unused;

#[async_trait]
impl CredentialBuilder for Unused {
    async fn build(
        &self,
        _: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        panic!("non-initiation RPC service must not build a credential")
    }
}

#[async_trait]
impl CredentialLifecycle for Unused {
    async fn ensure_ready(
        &self,
        _: &CredentialTransaction,
        _: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        panic!("non-initiation RPC service must not enter credential lifecycle")
    }
    async fn allocate_status(
        &self,
        _: &CredentialTransaction,
        _: &str,
        _: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        panic!("non-initiation RPC service must not allocate status")
    }
    async fn after_issued(
        &self,
        _: &CredentialTransaction,
        _: &IssuedCredential,
        _: &str,
    ) -> Result<(), CredentialIssuanceError> {
        panic!("non-initiation RPC service must not project an issued credential")
    }
}

#[async_trait]
impl CredentialStatusPublisher for Unused {
    async fn publish(
        &self,
        _: &ManagedCredential,
        _: CredentialLifecycleAction,
        _: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        panic!("non-initiation RPC service must not publish credential status")
    }
}

pub(super) struct NativeInitiation {
    pub repository: Arc<PostgresCredentialRepository>,
    pub service: InitiationService,
    pub projector: InitiationOfferProjector,
    pub issuer_resolver: Arc<dyn IssuerContextResolver>,
}

pub(super) fn native_server(
    pool: &PgPool,
    initiation: NativeInitiation,
    events: CredentialLifecycleEventBus,
    token: &str,
    hmac: &[u8],
) -> CredentialManagementGrpcService {
    let NativeInitiation {
        repository,
        service,
        projector,
        issuer_resolver,
    } = initiation;
    let tokens = Arc::new(PostgresTokenExchangeRepository::new(pool.clone(), hmac));
    let token_exchange = TokenExchangeService::new(
        tokens.clone(),
        Arc::new(RegisteredClientAuthenticator::new(tokens)),
        Arc::new(MartyDpopProofVerifier),
        Arc::new(MartyTokenGenerator),
        ISSUER_URL,
    );
    let unused = Arc::new(Unused);
    let credential = CredentialIssuanceService::new(
        CredentialPorts {
            repository,
            nonce_repository: Arc::new(PostgresProofNonceRepository::new(pool.clone())),
            dpop_verifier: Arc::new(MartyDpopProofVerifier),
            proof_verifier: Arc::new(NativeCredentialProofVerifier),
            issuer_resolver,
            builder: unused.clone(),
            lifecycle: unused.clone(),
            notification_ids: Arc::new(UuidNotificationIdGenerator),
        },
        ISSUER_URL,
    );
    let transactions = TransactionReadService::new(
        Arc::new(PostgresTransactionReadRepository::new(pool.clone())),
        None,
        ISSUER_URL,
    );
    let lifecycle = CredentialManagementService::new(
        Arc::new(PostgresCredentialManagementRepository::new(pool.clone())),
        unused,
        Arc::new(events.clone()),
    );
    let platform = IssuanceGrpcPlatform::new(
        service,
        projector,
        token_exchange,
        credential,
        transactions,
        ISSUER_URL,
    );
    CredentialManagementGrpcService::new(lifecycle, events, platform, Some(token))
}
pub(super) struct OwnedGrpc {
    channel: Channel,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl OwnedGrpc {
    pub(super) async fn start(service: CredentialManagementGrpcService) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(
            Server::builder()
                .add_service(IssuanceServiceServer::new(service))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                    let _ = stopped.await;
                }),
        );
        let factory = GrpcChannelFactory::new(
            GrpcChannelConfig {
                target: format!("http://{address}"),
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::default(),
        )
        .unwrap();
        // Construct the guard before connect so a connection panic aborts the server too.
        let mut owned = Self {
            channel: factory.connect_lazy().unwrap(),
            shutdown: Some(shutdown),
            task,
        };
        owned.channel = tokio::time::timeout(Duration::from_secs(5), factory.connect())
            .await
            .unwrap()
            .unwrap();
        owned
    }

    pub(super) fn channel(&self) -> Channel {
        self.channel.clone()
    }

    pub(super) async fn close(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for OwnedGrpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
