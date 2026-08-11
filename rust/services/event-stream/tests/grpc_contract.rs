use marty_event_stream::{
    bus::EventBus,
    grpc::EventStreamGrpc,
    proto::{
        event_stream_service_client::EventStreamServiceClient,
        event_stream_service_server::EventStreamServiceServer, DomainEvent, EventSubscription,
        HealthCheckRequest, PublishEventRequest,
    },
};
use std::{collections::HashMap, time::Duration};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

#[tokio::test]
async fn generated_client_preserves_publish_subscribe_and_tenant_contract() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let service = EventStreamGrpc::new(EventBus::default());
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(EventStreamServiceServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_receiver.await;
            })
            .await
            .unwrap();
    });

    let endpoint = format!("http://{address}");
    let mut subscriber_a = EventStreamServiceClient::connect(endpoint.clone())
        .await
        .unwrap();
    let mut subscriber_b = EventStreamServiceClient::connect(endpoint.clone())
        .await
        .unwrap();
    let mut publisher = EventStreamServiceClient::connect(endpoint).await.unwrap();
    let mut stream_a = subscriber_a
        .subscribe(EventSubscription {
            event_types: vec!["application.approved".into()],
            organization_id: "org-a".into(),
            aggregate_type: String::new(),
            subscriber_id: "rust-a".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut stream_b = subscriber_b
        .subscribe(EventSubscription {
            event_types: vec!["application.approved".into()],
            organization_id: "org-b".into(),
            aggregate_type: String::new(),
            subscriber_id: "rust-b".into(),
        })
        .await
        .unwrap()
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
        .unwrap()
        .into_inner();
    assert!(response.success);
    assert_eq!(response.subscribers_notified, 1);

    let event = timeout(Duration::from_secs(1), stream_a.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.event_id, "event-a");
    assert_eq!(event.organization_id, "org-a");
    assert!(timeout(Duration::from_millis(100), stream_b.message())
        .await
        .is_err());

    let health = publisher
        .health_check(HealthCheckRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, "serving");

    let default_event = publisher
        .publish(PublishEventRequest { event: None })
        .await
        .unwrap()
        .into_inner();
    assert!(default_event.success);

    drop(stream_a);
    drop(stream_b);
    drop(subscriber_a);
    drop(subscriber_b);
    drop(publisher);
    let _ = shutdown_sender.send(());
    timeout(Duration::from_secs(2), server)
        .await
        .expect("gRPC server shutdown timed out")
        .unwrap();
}
