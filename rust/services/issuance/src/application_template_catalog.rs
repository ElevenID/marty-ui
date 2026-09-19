use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use thiserror::Error;
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};

use crate::{
    application_template_domain::CredentialTemplateValidationView,
    application_template_service::{ApplicationTemplateCatalog, ApplicationTemplateCatalogError},
    config::normalize_grpc_target,
    credential_template_proto::{
        credential_template_service_client::CredentialTemplateServiceClient, GetTemplateRequest,
        TemplateResponse,
    },
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

/// Build the production catalog without making unrelated issuance routes depend
/// on the optional internal service token at process startup. A missing token
/// remains fail-closed: no unauthenticated request can be sent, and validation
/// reports the catalog as unavailable until deployment configuration supplies
/// the token.
pub fn runtime_catalog(
    target: &str,
    service_token: Option<&str>,
    timeout: Duration,
) -> Result<Arc<dyn ApplicationTemplateCatalog>, ApplicationTemplateCatalogConfigurationError> {
    if service_token.map(str::trim).is_none_or(str::is_empty) {
        return Ok(Arc::new(UnavailableApplicationTemplateCatalog));
    }
    Ok(Arc::new(GrpcApplicationTemplateCatalog::connect_lazy(
        target,
        service_token,
        timeout,
    )?))
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableApplicationTemplateCatalog;

#[async_trait]
impl ApplicationTemplateCatalog for UnavailableApplicationTemplateCatalog {
    async fn get_strict(
        &self,
        _template_id: &str,
    ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError> {
        Err(ApplicationTemplateCatalogError::Unavailable)
    }
}

/// Strict internal credential-template lookup used while validating application
/// templates. This boundary intentionally has no HTTP fallback: authentication,
/// not-found semantics, and response integrity stay explicit and fail closed.
#[derive(Clone)]
pub struct GrpcApplicationTemplateCatalog {
    templates: CredentialTemplateServiceClient<Channel>,
    service_token: AsciiMetadataValue,
    timeout: Duration,
}

impl std::fmt::Debug for GrpcApplicationTemplateCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcApplicationTemplateCatalog")
            .field("service_token_configured", &true)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl GrpcApplicationTemplateCatalog {
    pub fn connect_lazy(
        target: &str,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, ApplicationTemplateCatalogConfigurationError> {
        if timeout.is_zero() {
            return Err(ApplicationTemplateCatalogConfigurationError::InvalidTimeout);
        }
        let service_token = service_token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(ApplicationTemplateCatalogConfigurationError::MissingServiceToken)?
            .parse()
            .map_err(|_| ApplicationTemplateCatalogConfigurationError::InvalidServiceToken)?;
        let target = normalize_grpc_target(target)
            .ok_or(ApplicationTemplateCatalogConfigurationError::InvalidTarget)?;
        let channel = Endpoint::from_shared(target)
            .map_err(|_| ApplicationTemplateCatalogConfigurationError::InvalidTarget)?
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect_lazy();
        Ok(Self {
            templates: CredentialTemplateServiceClient::new(channel),
            service_token,
            timeout,
        })
    }

    fn request<T>(&self, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        request
            .metadata_mut()
            .insert(SERVICE_TOKEN_HEADER, self.service_token.clone());
        request
    }
}

#[async_trait]
impl ApplicationTemplateCatalog for GrpcApplicationTemplateCatalog {
    async fn get_strict(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError> {
        let requested_id = template_id;
        if requested_id.is_empty() {
            return Ok(None);
        }
        let mut client = self.templates.clone();
        let response = match client
            .get_template(self.request(GetTemplateRequest {
                template_id: requested_id.to_owned(),
            }))
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(_) => return Err(ApplicationTemplateCatalogError::Unavailable),
        };
        response_view(requested_id, response)
    }
}

fn response_view(
    requested_id: &str,
    response: TemplateResponse,
) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError> {
    if response.id.is_empty() {
        return Ok(None);
    }
    if response.id != requested_id || response.organization_id.trim().is_empty() {
        return Err(ApplicationTemplateCatalogError::Unavailable);
    }
    Ok(Some(CredentialTemplateValidationView {
        organization_id: response.organization_id,
        status: response.status,
        revocation_profile_id: non_empty(response.revocation_profile_id),
        claims: response
            .claims
            .into_iter()
            .filter_map(|claim| non_empty(claim.name))
            .collect::<BTreeSet<_>>(),
    }))
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationTemplateCatalogConfigurationError {
    #[error("application-template credential catalog requires an internal service token")]
    MissingServiceToken,
    #[error("application-template credential catalog service token is not valid ASCII metadata")]
    InvalidServiceToken,
    #[error("application-template credential catalog requires a valid gRPC target")]
    InvalidTarget,
    #[error("application-template credential catalog dependency timeout must be positive")]
    InvalidTimeout,
}

#[cfg(test)]
mod tests {
    use tokio::{net::TcpListener, sync::watch};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{transport::Server, Response, Status};

    use super::*;
    use crate::credential_template_proto::{
        credential_template_service_server::{
            CredentialTemplateService, CredentialTemplateServiceServer,
        },
        ActivateTemplateRequest, ClaimDefinition, CreateTemplateRequest, DeleteTemplateRequest,
        DeleteTemplateResponse, DeprecateTemplateRequest, GetCredentialConfigurationsRequest,
        GetCredentialConfigurationsResponse, GetWalletRequest, HealthCheckRequest,
        HealthCheckResponse, ListTemplatesRequest, ListTemplatesResponse, ListWalletsRequest,
        ListWalletsResponse, NewVersionRequest, UpdateTemplateRequest, WalletRegistryEntry,
    };

    struct CatalogFixture;

    #[tonic::async_trait]
    impl CredentialTemplateService for CatalogFixture {
        async fn create_template(
            &self,
            _request: Request<CreateTemplateRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            Err(Status::unimplemented("create_template"))
        }

        async fn get_template(
            &self,
            request: Request<GetTemplateRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            if request
                .metadata()
                .get(SERVICE_TOKEN_HEADER)
                .and_then(|value| value.to_str().ok())
                != Some("fixture-token")
            {
                return Err(Status::unauthenticated("service token required"));
            }
            let template_id = request.into_inner().template_id;
            match template_id.as_str() {
                "missing" => Err(Status::not_found("missing")),
                "unavailable" => Err(Status::unavailable("unavailable")),
                _ => Ok(Response::new(TemplateResponse {
                    id: template_id,
                    organization_id: "org-a".to_owned(),
                    status: "ACTIVE".to_owned(),
                    revocation_profile_id: "revocation-1".to_owned(),
                    claims: vec![ClaimDefinition {
                        name: "member_number".to_owned(),
                        ..ClaimDefinition::default()
                    }],
                    ..TemplateResponse::default()
                })),
            }
        }

        async fn list_templates(
            &self,
            _request: Request<ListTemplatesRequest>,
        ) -> Result<Response<ListTemplatesResponse>, Status> {
            Err(Status::unimplemented("list_templates"))
        }

        async fn update_template(
            &self,
            _request: Request<UpdateTemplateRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            Err(Status::unimplemented("update_template"))
        }

        async fn activate_template(
            &self,
            _request: Request<ActivateTemplateRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            Err(Status::unimplemented("activate_template"))
        }

        async fn deprecate_template(
            &self,
            _request: Request<DeprecateTemplateRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            Err(Status::unimplemented("deprecate_template"))
        }

        async fn new_version(
            &self,
            _request: Request<NewVersionRequest>,
        ) -> Result<Response<TemplateResponse>, Status> {
            Err(Status::unimplemented("new_version"))
        }

        async fn delete_template(
            &self,
            _request: Request<DeleteTemplateRequest>,
        ) -> Result<Response<DeleteTemplateResponse>, Status> {
            Err(Status::unimplemented("delete_template"))
        }

        async fn get_credential_configurations(
            &self,
            _request: Request<GetCredentialConfigurationsRequest>,
        ) -> Result<Response<GetCredentialConfigurationsResponse>, Status> {
            Err(Status::unimplemented("get_credential_configurations"))
        }

        async fn list_wallets(
            &self,
            _request: Request<ListWalletsRequest>,
        ) -> Result<Response<ListWalletsResponse>, Status> {
            Err(Status::unimplemented("list_wallets"))
        }

        async fn get_wallet(
            &self,
            _request: Request<GetWalletRequest>,
        ) -> Result<Response<WalletRegistryEntry>, Status> {
            Err(Status::unimplemented("get_wallet"))
        }

        async fn health_check(
            &self,
            _request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, Status> {
            Err(Status::unimplemented("health_check"))
        }
    }

    #[tokio::test]
    async fn configuration_requires_authentication_and_valid_transport_settings() {
        let unavailable = runtime_catalog("credential-template:9003", None, Duration::from_secs(1))
            .expect("missing runtime token uses a fail-closed catalog");
        assert_eq!(
            unavailable.get_strict("template-1").await,
            Err(ApplicationTemplateCatalogError::Unavailable)
        );
        assert!(matches!(
            GrpcApplicationTemplateCatalog::connect_lazy(
                "credential-template:9003",
                None,
                Duration::from_secs(1)
            ),
            Err(ApplicationTemplateCatalogConfigurationError::MissingServiceToken)
        ));
        assert!(matches!(
            GrpcApplicationTemplateCatalog::connect_lazy(
                "credential-template:9003",
                Some("token\nvalue"),
                Duration::from_secs(1)
            ),
            Err(ApplicationTemplateCatalogConfigurationError::InvalidServiceToken)
        ));
        assert!(matches!(
            GrpcApplicationTemplateCatalog::connect_lazy(
                "credential template:9003",
                Some("token"),
                Duration::from_secs(1)
            ),
            Err(ApplicationTemplateCatalogConfigurationError::InvalidTarget)
        ));
        assert!(matches!(
            GrpcApplicationTemplateCatalog::connect_lazy(
                "credential-template:9003",
                Some("token"),
                Duration::ZERO
            ),
            Err(ApplicationTemplateCatalogConfigurationError::InvalidTimeout)
        ));

        let catalog = GrpcApplicationTemplateCatalog::connect_lazy(
            "credential-template:9003",
            Some("token"),
            Duration::from_secs(1),
        )
        .expect("valid catalog");
        let request = catalog.request(GetTemplateRequest {
            template_id: "template-1".to_owned(),
        });
        assert_eq!(
            request
                .metadata()
                .get(SERVICE_TOKEN_HEADER)
                .expect("service token metadata"),
            "token"
        );
        assert!(request.metadata().get("grpc-timeout").is_some());
    }

    #[test]
    fn response_projection_is_identity_checked_normalized_and_deduplicated() {
        let response = TemplateResponse {
            id: "template-1".to_owned(),
            organization_id: "org-a".to_owned(),
            status: "ACTIVE".to_owned(),
            revocation_profile_id: " revocation-1 ".to_owned(),
            claims: vec![
                ClaimDefinition {
                    name: " membership_number ".to_owned(),
                    ..ClaimDefinition::default()
                },
                ClaimDefinition {
                    name: "membership_number".to_owned(),
                    ..ClaimDefinition::default()
                },
                ClaimDefinition::default(),
            ],
            ..TemplateResponse::default()
        };
        assert_eq!(
            response_view("template-1", response),
            Ok(Some(CredentialTemplateValidationView {
                organization_id: "org-a".to_owned(),
                status: "ACTIVE".to_owned(),
                revocation_profile_id: Some("revocation-1".to_owned()),
                claims: BTreeSet::from(["membership_number".to_owned()]),
            }))
        );
    }

    #[test]
    fn empty_is_not_found_while_mismatched_or_unscoped_responses_fail_closed() {
        assert_eq!(
            response_view("template-1", TemplateResponse::default()),
            Ok(None)
        );
        for response in [
            TemplateResponse {
                id: "template-2".to_owned(),
                organization_id: "org-a".to_owned(),
                ..TemplateResponse::default()
            },
            TemplateResponse {
                id: "template-1".to_owned(),
                ..TemplateResponse::default()
            },
        ] {
            assert_eq!(
                response_view("template-1", response),
                Err(ApplicationTemplateCatalogError::Unavailable)
            );
        }
    }

    #[tokio::test]
    async fn transport_is_authenticated_strict_and_maps_only_not_found_to_absence() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("catalog fixture listener");
        let address = listener.local_addr().expect("catalog fixture address");
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(CredentialTemplateServiceServer::new(CatalogFixture))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await
                .expect("catalog fixture server");
        });

        let catalog = GrpcApplicationTemplateCatalog::connect_lazy(
            &format!("http://{address}"),
            Some("fixture-token"),
            Duration::from_secs(2),
        )
        .expect("authenticated catalog");
        assert_eq!(
            catalog.get_strict("missing").await,
            Ok(None),
            "only gRPC NOT_FOUND maps to a missing catalog record"
        );
        assert_eq!(
            catalog.get_strict("unavailable").await,
            Err(ApplicationTemplateCatalogError::Unavailable)
        );
        assert_eq!(
            catalog.get_strict("template-1").await,
            Ok(Some(CredentialTemplateValidationView {
                organization_id: "org-a".to_owned(),
                status: "ACTIVE".to_owned(),
                revocation_profile_id: Some("revocation-1".to_owned()),
                claims: BTreeSet::from(["member_number".to_owned()]),
            }))
        );

        let unauthenticated = GrpcApplicationTemplateCatalog::connect_lazy(
            &format!("http://{address}"),
            Some("wrong-token"),
            Duration::from_secs(2),
        )
        .expect("configured but unauthorized catalog");
        assert_eq!(
            unauthenticated.get_strict("template-1").await,
            Err(ApplicationTemplateCatalogError::Unavailable)
        );

        shutdown_tx.send(true).expect("catalog fixture shutdown");
        server.await.expect("catalog fixture task");
    }
}
