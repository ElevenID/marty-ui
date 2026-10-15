//! Opt-in connected Auth mTLS proof against a marked disposable OpenBao.
//! Both workload certificates have non-exportable Transit signers; no TLS
//! private-key file enters this process.

use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use marty_auth::{
    auth_proto::{
        auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
        HealthCheckRequest,
    },
    AuthGrpcService, AuthSessionService, Session,
};
use mmf_platform::{KeylessGrpcTransportOptions, OpenBaoTlsIdentityFiles};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Server},
    Request, Status,
};

struct EmptySessions;

#[async_trait]
impl AuthSessionService for EmptySessions {
    async fn validate_session(&self, _session_id: &str) -> Result<Option<Session>, Status> {
        Ok(None)
    }

    async fn invalidate_session(&self, _session_id: &str) -> Result<bool, Status> {
        Ok(false)
    }
}

fn fixture(name: &str) -> String {
    std::env::var(format!("MARTY_TEST_AUTH_GATEWAY_{name}"))
        .unwrap_or_else(|_| panic!("missing disposable Auth/Gateway {name} fixture"))
}

fn identity(role: &str) -> OpenBaoTlsIdentityFiles {
    OpenBaoTlsIdentityFiles {
        certificate_chain_file: PathBuf::from(fixture(&format!("{role}_CERT"))),
        kms_ca_cert_file: PathBuf::from(fixture("KMS_CA")),
        kms_endpoint: fixture("KMS_URL"),
        kms_token_file: PathBuf::from(fixture(&format!("{role}_KMS_TOKEN_FILE"))),
        kms_key_name: fixture(&format!("{role}_KMS_KEY_NAME")),
        kms_key_version: 1,
        request_timeout: Duration::from_secs(10),
        max_concurrent_signs: 16,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/with_disposable_event_stream_kms.py --profile auth-gateway"]
async fn real_auth_rpc_requires_kms_backed_mutual_tls_and_service_token() {
    let ca = PathBuf::from(fixture("WORKLOAD_CA"));
    let server_identity = identity("AUTH_SERVER");
    let client_identity = identity("GATEWAY_CLIENT");
    let acceptor = server_identity
        .grpc_acceptor(&ca, 16, Duration::from_secs(10))
        .await
        .expect("Auth must load the remote server signer");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service_token = fixture("SERVICE_TOKEN");
    let service =
        AuthGrpcService::new(Arc::new(EmptySessions), Some(service_token.clone()), true).unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let incoming = TcpListenerStream::new(listener).then(move |connection| {
        let acceptor = acceptor.clone();
        async move {
            match connection {
                Ok(stream) => acceptor.accept(stream).await,
                Err(error) => Err(error),
            }
        }
    });
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
    });
    let target = format!("https://localhost:{}", address.port());
    let unauthenticated_transport = Endpoint::from_shared(target.clone())
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(std::fs::read(&ca).unwrap())),
        )
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await;
    if let Ok(channel) = unauthenticated_transport {
        let mut without_client_identity = AuthServiceClient::new(channel);
        assert!(without_client_identity
            .health_check(Request::new(HealthCheckRequest {}))
            .await
            .is_err());
    }
    let channel = client_identity
        .grpc_channel_connected(&target, &ca, KeylessGrpcTransportOptions::default())
        .await
        .expect("Gateway must connect with its remote client signer");
    let mut client = AuthServiceClient::new(channel);
    let request = || Request::new(HealthCheckRequest {});
    assert_eq!(
        client.health_check(request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    let mut authenticated = request();
    authenticated
        .metadata_mut()
        .insert("x-service-token", service_token.parse().unwrap());
    assert_eq!(
        client
            .health_check(authenticated)
            .await
            .unwrap()
            .into_inner()
            .status,
        "serving"
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
