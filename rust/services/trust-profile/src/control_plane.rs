use std::time::Duration;

use async_trait::async_trait;
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};

use crate::{
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest, MemberResponse,
    },
    TrustAuthorizationError, TrustProfileControlPlane,
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct NativeTrustProfileControlPlane {
    organizations: OrganizationServiceClient<Channel>,
    service_token: Option<AsciiMetadataValue>,
    timeout: Duration,
}

impl std::fmt::Debug for NativeTrustProfileControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeTrustProfileControlPlane")
            .field("service_token_configured", &self.service_token.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl NativeTrustProfileControlPlane {
    pub fn connect_lazy(
        organization_target: &str,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, TrustAuthorizationError> {
        if timeout.is_zero() {
            return Err(TrustAuthorizationError::Unavailable);
        }
        let endpoint = Endpoint::from_shared(organization_target.to_owned())
            .map_err(|_| TrustAuthorizationError::Unavailable)?
            .connect_timeout(timeout)
            .timeout(timeout);
        let service_token = service_token
            .map(str::parse)
            .transpose()
            .map_err(|_| TrustAuthorizationError::Unavailable)?;
        Ok(Self {
            organizations: OrganizationServiceClient::new(endpoint.connect_lazy()),
            service_token,
            timeout,
        })
    }

    fn request<T>(&self, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request
    }

    pub async fn check_health(&self) -> Result<(), TrustAuthorizationError> {
        // A deliberately impossible lookup proves that the authenticated control
        // plane is reachable without granting access or depending on seed data.
        let mut client = self.organizations.clone();
        match client
            .get_member(self.request(GetMemberRequest {
                organization_id: "00000000-0000-0000-0000-000000000000".into(),
                user_id: "trust-profile-native-health".into(),
            }))
            .await
        {
            Ok(_) => Ok(()),
            Err(status)
                if matches!(
                    status.code(),
                    Code::NotFound | Code::InvalidArgument | Code::Unknown
                ) =>
            {
                Ok(())
            }
            Err(_) => Err(TrustAuthorizationError::Unavailable),
        }
    }

    async fn membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<MemberResponse, TrustAuthorizationError> {
        if user_id.trim().is_empty() || organization_id.trim().is_empty() {
            return Err(TrustAuthorizationError::MembershipRequired);
        }
        let mut client = self.organizations.clone();
        let member = match client
            .get_member(self.request(GetMemberRequest {
                organization_id: organization_id.to_owned(),
                user_id: user_id.to_owned(),
            }))
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status)
                if matches!(
                    status.code(),
                    Code::NotFound | Code::InvalidArgument | Code::Unknown
                ) =>
            {
                return Err(TrustAuthorizationError::MembershipRequired)
            }
            Err(_) => return Err(TrustAuthorizationError::Unavailable),
        };
        if member.user_id != user_id
            || member.organization_id != organization_id
            || !member.status.eq_ignore_ascii_case("active")
        {
            return Err(TrustAuthorizationError::MembershipRequired);
        }
        Ok(member)
    }
}

#[async_trait]
impl TrustProfileControlPlane for NativeTrustProfileControlPlane {
    async fn require_permission(
        &self,
        user_id: &str,
        organization_id: &str,
        resource: &'static str,
        action: &'static str,
    ) -> Result<(), TrustAuthorizationError> {
        let member = self.membership(user_id, organization_id).await?;
        let required = format!("{resource}:{action}");
        if member.is_owner
            || member.has_org_console_access
            || member.permissions.iter().any(|value| value == &required)
        {
            Ok(())
        } else {
            Err(TrustAuthorizationError::PermissionRequired { resource, action })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_control_plane_configuration_fails_closed() {
        assert!(matches!(
            NativeTrustProfileControlPlane::connect_lazy("not a URI", None, Duration::from_secs(1)),
            Err(TrustAuthorizationError::Unavailable)
        ));
        assert!(matches!(
            NativeTrustProfileControlPlane::connect_lazy(
                "http://organization:9002",
                Some("not\nmetadata"),
                Duration::from_secs(1)
            ),
            Err(TrustAuthorizationError::Unavailable)
        ));
    }
}
