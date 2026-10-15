use marty_event_stream::proto::{
    event_stream_service_client::EventStreamServiceClient, DomainEvent, EventSubscription,
    HealthCheckRequest, PublishEventRequest,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use std::{
    collections::HashMap,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::time::{sleep, timeout};
use tonic::{metadata::AsciiMetadataValue, Request};

struct ServiceProcess(Child);

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_ports() -> (u16, u16) {
    let http = TcpListener::bind("127.0.0.1:0").expect("reserve HTTP port");
    let grpc = TcpListener::bind("127.0.0.1:0").expect("reserve gRPC port");
    let ports = (
        http.local_addr().expect("HTTP address").port(),
        grpc.local_addr().expect("gRPC address").port(),
    );
    drop(http);
    drop(grpc);
    ports
}

async fn connect(endpoint: &str) -> EventStreamServiceClient<tonic::transport::Channel> {
    for _ in 0..50 {
        if let Ok(client) = EventStreamServiceClient::connect(endpoint.to_owned()).await {
            return client;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("event-stream did not expose its public gRPC contract")
}

#[tokio::test]
async fn executable_preserves_publish_subscribe_and_tenant_contract() {
    let (http_port, grpc_port) = unused_ports();
    let child = Command::new(env!("CARGO_BIN_EXE_marty-event-stream"))
        .env("EVENT_STREAM_SERVICE_PORT", http_port.to_string())
        .env("EVENT_STREAM_GRPC_PORT", grpc_port.to_string())
        .env("EVENT_STREAM_GRPC_ENABLED", "true")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start event-stream executable");
    let _service = ServiceProcess(child);
    let endpoint = format!("http://127.0.0.1:{grpc_port}");

    let mut subscriber_a = connect(&endpoint).await;
    let mut subscriber_b = connect(&endpoint).await;
    let mut publisher = connect(&endpoint).await;
    let mut stream_a = subscriber_a
        .subscribe(EventSubscription {
            event_types: vec!["application.approved".into()],
            organization_id: "org-a".into(),
            aggregate_type: String::new(),
            subscriber_id: "contract-a".into(),
        })
        .await
        .expect("subscribe org A")
        .into_inner();
    let mut stream_b = subscriber_b
        .subscribe(EventSubscription {
            event_types: vec!["application.approved".into()],
            organization_id: "org-b".into(),
            aggregate_type: String::new(),
            subscriber_id: "contract-b".into(),
        })
        .await
        .expect("subscribe org B")
        .into_inner();

    let response = publisher
        .publish(PublishEventRequest {
            event: Some(DomainEvent {
                event_id: "event-a".into(),
                event_type: "application.approved".into(),
                aggregate_id: "application-a".into(),
                aggregate_type: "application".into(),
                organization_id: "org-a".into(),
                data: HashMap::from([("application_id".into(), "application-a".into())]),
                timestamp: "2026-08-06T12:00:00+00:00".into(),
                correlation_id: String::new(),
            }),
        })
        .await
        .expect("publish event")
        .into_inner();
    assert!(response.success);
    assert_eq!(response.subscribers_notified, 1);

    let event = timeout(Duration::from_secs(1), stream_a.message())
        .await
        .expect("org A delivery timed out")
        .expect("org A stream failed")
        .expect("org A stream closed");
    assert_eq!(event.event_id, "event-a");
    assert_eq!(event.organization_id, "org-a");
    assert_eq!(event.data["application_id"], "application-a");
    assert!(timeout(Duration::from_millis(100), stream_b.message())
        .await
        .is_err());

    let health = publisher
        .health_check(HealthCheckRequest {})
        .await
        .expect("health check")
        .into_inner();
    assert_eq!(health.status, "serving");

    let default_event = publisher
        .publish(PublishEventRequest { event: None })
        .await
        .expect("publish default event")
        .into_inner();
    assert!(default_event.success);
}

#[tokio::test]
#[ignore = "requires a disposable, HTTPS OpenBao signer and public certificate fixture"]
async fn deployed_executable_uses_remote_tls_signer_and_authenticated_event_rpcs() {
    let fixture = |name: &str| std::env::var(name).expect("keyless Event Stream fixture setting");
    let (http_port, grpc_port) = unused_ports();
    let token = fixture("MARTY_TEST_EVENT_STREAM_SERVICE_TOKEN");
    let child = Command::new(env!("CARGO_BIN_EXE_marty-event-stream"))
        .env("ENVIRONMENT", "beta")
        .env("EVENT_STREAM_SERVICE_PORT", http_port.to_string())
        .env("EVENT_STREAM_GRPC_PORT", grpc_port.to_string())
        .env("GRPC_SERVICE_TOKEN", &token)
        .env(
            "GRPC_WORKLOAD_TLS_SERVER_CERT",
            fixture("MARTY_TEST_EVENT_STREAM_CERT"),
        )
        .env(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
            fixture("MARTY_TEST_EVENT_STREAM_KMS_URL"),
        )
        .env(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
            fixture("MARTY_TEST_EVENT_STREAM_KMS_CA"),
        )
        .env(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
            fixture("MARTY_TEST_EVENT_STREAM_KMS_TOKEN_FILE"),
        )
        .env(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
            fixture("MARTY_TEST_EVENT_STREAM_KMS_KEY_NAME"),
        )
        .env("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start deployed Event Stream executable");
    let mut service = ServiceProcess(child);
    let endpoint = format!("https://localhost:{grpc_port}");
    let ca = std::path::Path::new(&fixture("MARTY_TEST_EVENT_STREAM_WORKLOAD_CA")).to_owned();
    let factory = GrpcChannelFactory::new(
        GrpcChannelConfig {
            target: endpoint,
            security: GrpcTransportSecurity::ServerTls,
            trust: GrpcTrustMode::CustomCa,
            ..GrpcChannelConfig::default()
        },
        GrpcTlsMaterial::from_ca_pem_file(Some(&ca)).expect("public workload CA"),
    )
    .expect("CA-verified gRPC channel");
    let mut channel = None;
    for _ in 0..100 {
        if let Ok(connected) = factory.connect().await {
            channel = Some(connected);
            break;
        }
        assert!(
            service
                .0
                .try_wait()
                .expect("Event Stream process state")
                .is_none(),
            "deployed Event Stream exited before TLS became ready"
        );
        sleep(Duration::from_millis(100)).await;
    }
    let channel = channel.expect("keyless Event Stream TLS listener became ready");
    let mut client = EventStreamServiceClient::new(channel);
    let denied = client
        .publish(PublishEventRequest { event: None })
        .await
        .expect_err("unauthenticated publish must fail");
    assert_eq!(denied.code(), tonic::Code::Unauthenticated);
    let mut subscribe = Request::new(EventSubscription {
        event_types: vec!["keyless.acceptance".into()],
        organization_id: "org-keyless".into(),
        aggregate_type: String::new(),
        subscriber_id: "keyless-client".into(),
    });
    subscribe.metadata_mut().insert(
        "x-service-token",
        AsciiMetadataValue::try_from(token.as_str()).unwrap(),
    );
    let mut stream = client.subscribe(subscribe).await.unwrap().into_inner();
    let mut publish = Request::new(PublishEventRequest {
        event: Some(DomainEvent {
            event_id: "keyless-event".into(),
            event_type: "keyless.acceptance".into(),
            aggregate_id: "aggregate-1".into(),
            aggregate_type: "test".into(),
            organization_id: "org-keyless".into(),
            data: HashMap::new(),
            timestamp: String::new(),
            correlation_id: String::new(),
        }),
    });
    publish.metadata_mut().insert(
        "x-service-token",
        AsciiMetadataValue::try_from(token.as_str()).unwrap(),
    );
    assert!(client.publish(publish).await.unwrap().into_inner().success);
    let event = timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("TLS event delivery timed out")
        .expect("TLS event stream failed")
        .expect("TLS event stream closed");
    assert_eq!(event.event_id, "keyless-event");
}
