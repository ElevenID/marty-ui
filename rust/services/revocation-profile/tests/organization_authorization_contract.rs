use marty_revocation_profile::{
    organization_proto::{
        organization_service_server::{OrganizationService, OrganizationServiceServer},
        AddMemberRequest, CreateOrganizationRequest, GetMemberPermissionsRequest,
        GetMemberPermissionsResponse, GetMemberRequest, GetOrganizationRequest, HealthCheckRequest,
        HealthCheckResponse, ListMembersRequest, ListMembersResponse, ListOrganizationsRequest,
        ListOrganizationsResponse, MemberResponse, OrganizationResponse, RemoveMemberRequest,
        RemoveMemberResponse, UpdateMemberRequest, UpdateOrganizationRequest,
        ValidateApiKeyRequest, ValidateApiKeyResponse,
    },
    Authorization, AuthorizationError, OrganizationAuthorization,
};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Server, Request, Response, Status};

const TOKEN: &str = "organization-contract-token";

#[derive(Debug, Clone)]
struct FakeOrganizationService {
    member_exists: bool,
}

impl FakeOrganizationService {
    fn authenticated<T>(&self, request: &Request<T>) -> bool {
        request
            .metadata()
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            == Some(TOKEN)
    }
}

#[tonic::async_trait]
impl OrganizationService for FakeOrganizationService {
    async fn get_organization(
        &self,
        _request: Request<GetOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        Err(Status::unimplemented("get_organization"))
    }

    async fn create_organization(
        &self,
        _request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        Err(Status::unimplemented("create_organization"))
    }

    async fn update_organization(
        &self,
        _request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        Err(Status::unimplemented("update_organization"))
    }

    async fn list_organizations(
        &self,
        _request: Request<ListOrganizationsRequest>,
    ) -> Result<Response<ListOrganizationsResponse>, Status> {
        Err(Status::unimplemented("list_organizations"))
    }

    async fn get_member(
        &self,
        request: Request<GetMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        if !self.authenticated(&request) {
            return Err(Status::unauthenticated("missing service token"));
        }
        if !self.member_exists {
            return Err(Status::not_found("membership not found"));
        }
        let request = request.into_inner();
        Ok(Response::new(MemberResponse {
            organization_id: request.organization_id,
            user_id: request.user_id,
            status: "active".into(),
            permissions: vec!["revocation-profile:view".into()],
            ..Default::default()
        }))
    }

    async fn add_member(
        &self,
        _request: Request<AddMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        Err(Status::unimplemented("add_member"))
    }

    async fn update_member(
        &self,
        _request: Request<UpdateMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        Err(Status::unimplemented("update_member"))
    }

    async fn remove_member(
        &self,
        _request: Request<RemoveMemberRequest>,
    ) -> Result<Response<RemoveMemberResponse>, Status> {
        Err(Status::unimplemented("remove_member"))
    }

    async fn list_members(
        &self,
        _request: Request<ListMembersRequest>,
    ) -> Result<Response<ListMembersResponse>, Status> {
        Err(Status::unimplemented("list_members"))
    }

    async fn validate_api_key(
        &self,
        _request: Request<ValidateApiKeyRequest>,
    ) -> Result<Response<ValidateApiKeyResponse>, Status> {
        Err(Status::unimplemented("validate_api_key"))
    }

    async fn get_member_permissions(
        &self,
        _request: Request<GetMemberPermissionsRequest>,
    ) -> Result<Response<GetMemberPermissionsResponse>, Status> {
        Err(Status::unimplemented("get_member_permissions"))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        if !self.authenticated(&request) {
            return Err(Status::unauthenticated("missing service token"));
        }
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

async fn start_server(member_exists: bool) -> (String, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    tokio::spawn(async move {
        Server::builder()
            .add_service(OrganizationServiceServer::new(FakeOrganizationService {
                member_exists,
            }))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_receiver.await;
            })
            .await
            .unwrap();
    });
    (format!("http://{address}"), shutdown_sender)
}

#[tokio::test]
async fn propagates_service_token_and_preserves_permission_contract() {
    let (target, shutdown) = start_server(true).await;
    let authorization =
        OrganizationAuthorization::connect_lazy(target, Some(TOKEN.into())).unwrap();

    authorization.check_health().await.unwrap();
    authorization
        .require_permission("user-1", "org-1", "revocation-profile", "view")
        .await
        .unwrap();
    assert_eq!(
        authorization
            .require_permission("user-1", "org-1", "revocation-profile", "delete",)
            .await,
        Err(AuthorizationError::Denied)
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn missing_membership_is_denied_and_backend_auth_failure_is_unavailable() {
    let (target, shutdown) = start_server(false).await;
    let authorization =
        OrganizationAuthorization::connect_lazy(target.clone(), Some(TOKEN.into())).unwrap();
    assert_eq!(
        authorization
            .require_permission("user-1", "org-1", "revocation-profile", "view",)
            .await,
        Err(AuthorizationError::Denied)
    );

    let unauthenticated = OrganizationAuthorization::connect_lazy(target, None).unwrap();
    assert!(matches!(
        unauthenticated.check_health().await,
        Err(AuthorizationError::Unavailable(_))
    ));
    let _ = shutdown.send(());
}
