use crate::{
    http::{Authorization, AuthorizationError},
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest,
        HealthCheckRequest, MemberResponse,
    },
};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Code, Request};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct OrganizationAuthorization {
    client: OrganizationServiceClient<Channel>,
    service_token: Option<Arc<str>>,
    timeout: Duration,
}

impl std::fmt::Debug for OrganizationAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrganizationAuthorization")
            .field("service_token_configured", &self.service_token.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl OrganizationAuthorization {
    pub fn connect_lazy(
        target: String,
        service_token: Option<String>,
    ) -> Result<Self, AuthorizationError> {
        let channel = Channel::from_shared(target)
            .map_err(|error| AuthorizationError::Unavailable(error.to_string()))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .connect_lazy();
        Ok(Self {
            client: OrganizationServiceClient::new(channel),
            service_token: service_token.map(Arc::<str>::from),
            timeout: Duration::from_secs(5),
        })
    }

    pub async fn check_health(&self) -> Result<(), AuthorizationError> {
        let mut client = self.client.clone();
        let request = self.request(HealthCheckRequest {})?;
        let response = client
            .health_check(request)
            .await
            .map_err(unavailable)?
            .into_inner();
        if response.status == "serving" {
            Ok(())
        } else {
            Err(AuthorizationError::Unavailable(format!(
                "organization service reported status {}",
                response.status
            )))
        }
    }

    fn request<T>(&self, body: T) -> Result<Request<T>, AuthorizationError> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            let token = AsciiMetadataValue::try_from(token.as_ref()).map_err(|_| {
                AuthorizationError::Unavailable("service token is not valid gRPC metadata".into())
            })?;
            request.metadata_mut().insert(SERVICE_TOKEN_HEADER, token);
        }
        Ok(request)
    }
}

#[async_trait]
impl Authorization for OrganizationAuthorization {
    async fn require_permission(
        &self,
        user_id: &str,
        organization_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthorizationError> {
        let mut client = self.client.clone();
        let request = self.request(GetMemberRequest {
            organization_id: organization_id.into(),
            user_id: user_id.into(),
        })?;
        let response = match client.get_member(request).await {
            Ok(response) => response.into_inner(),
            Err(status)
                if matches!(
                    status.code(),
                    Code::NotFound | Code::Unknown | Code::InvalidArgument
                ) =>
            {
                return Err(AuthorizationError::Denied)
            }
            Err(status) => return Err(unavailable(status)),
        };
        authorize_membership(&response, user_id, organization_id, resource, action)
    }
}

fn authorize_membership(
    membership: &MemberResponse,
    user_id: &str,
    organization_id: &str,
    resource: &str,
    action: &str,
) -> Result<(), AuthorizationError> {
    if membership.user_id != user_id
        || membership.organization_id != organization_id
        || membership.status != "active"
    {
        return Err(AuthorizationError::Denied);
    }
    let required = format!("{resource}:{action}");
    if membership
        .permissions
        .iter()
        .any(|permission| permission == &required)
    {
        Ok(())
    } else {
        Err(AuthorizationError::Denied)
    }
}

fn unavailable(status: tonic::Status) -> AuthorizationError {
    AuthorizationError::Unavailable(format!(
        "organization gRPC request failed with {}",
        status.code()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership() -> MemberResponse {
        MemberResponse {
            user_id: "user-1".into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            permissions: vec!["revocation-profile:view".into()],
            ..Default::default()
        }
    }

    #[test]
    fn active_exact_scope_permission_is_required() {
        assert_eq!(
            authorize_membership(
                &membership(),
                "user-1",
                "org-1",
                "revocation-profile",
                "view"
            ),
            Ok(())
        );
        assert_eq!(
            authorize_membership(
                &membership(),
                "user-1",
                "org-1",
                "revocation-profile",
                "delete"
            ),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn mismatched_or_inactive_membership_fails_closed() {
        let mut response = membership();
        response.status = "suspended".into();
        assert_eq!(
            authorize_membership(&response, "user-1", "org-1", "revocation-profile", "view"),
            Err(AuthorizationError::Denied)
        );

        assert_eq!(
            authorize_membership(
                &membership(),
                "user-1",
                "org-2",
                "revocation-profile",
                "view"
            ),
            Err(AuthorizationError::Denied)
        );
    }
}
