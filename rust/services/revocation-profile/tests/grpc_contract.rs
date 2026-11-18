use marty_revocation_profile::{
    proto::{
        revocation_profile_service_client::RevocationProfileServiceClient,
        revocation_profile_service_server::RevocationProfileServiceServer,
        ActivateRevocationProfileRequest, AllocateIndexRequest, CreateRevocationProfileRequest,
        GetRevocationProfileRequest, ProcessRevocationRequest,
    },
    InMemoryProfileRepository, InMemoryStatusRepository, RevocationProfileGrpc,
    RevocationProfileService,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

#[tokio::test]
async fn generated_client_preserves_lifecycle_status_and_tenant_contract() {
    let service = RevocationProfileService::new(
        Arc::new(InMemoryProfileRepository::default()),
        Arc::new(InMemoryStatusRepository::default()),
        "https://status.example.test",
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(RevocationProfileServiceServer::new(
                RevocationProfileGrpc::new(service),
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let mut client = RevocationProfileServiceClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let created = client
        .create_revocation_profile(CreateRevocationProfileRequest {
            organization_id: "org-a".into(),
            name: "default".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.status, "draft");

    let active = client
        .activate_revocation_profile(ActivateRevocationProfileRequest {
            profile_id: created.id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(active.status, "active");

    let allocation = client
        .allocate_index(AllocateIndexRequest {
            profile_id: created.id.clone(),
            credential_format: "mdoc".into(),
            organization_id: "org-a".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(allocation.index, 0);
    assert!(allocation
        .status_list_url
        .ends_with("token-status-list/revocation"));

    let processed = client
        .process_revocation(ProcessRevocationRequest {
            profile_id: created.id.clone(),
            credential_id: "credential-a".into(),
            index: allocation.index,
            status: "suspended".into(),
            credential_format: "mdoc".into(),
            organization_id: "org-a".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(processed.success);
    assert!(processed
        .status_list_url
        .ends_with("token-status-list/suspension"));

    let fetched = client
        .get_revocation_profile(GetRevocationProfileRequest {
            profile_id: created.id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.organization_id, "org-a");

    let denied = client
        .allocate_index(AllocateIndexRequest {
            profile_id: created.id,
            credential_format: "mdoc".into(),
            organization_id: "org-b".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    server.abort();
}
