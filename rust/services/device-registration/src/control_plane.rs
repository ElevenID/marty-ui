use async_trait::async_trait;
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use std::{path::Path, time::Duration};
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};

use crate::{
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest,
    },
    DeviceError,
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[async_trait]
pub trait MembershipAuthorizer: Send + Sync {
    async fn require_active(&self, user_id: &str, organization_id: &str)
        -> Result<(), DeviceError>;
}

#[derive(Debug, Clone, Default)]
pub struct AllowMembership;

#[async_trait]
impl MembershipAuthorizer for AllowMembership {
    async fn require_active(
        &self,
        _user_id: &str,
        _organization_id: &str,
    ) -> Result<(), DeviceError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct OrganizationMembershipClient {
    client: OrganizationServiceClient<Channel>,
    token: Option<AsciiMetadataValue>,
    timeout: Duration,
}

impl std::fmt::Debug for OrganizationMembershipClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrganizationMembershipClient")
            .field("token_configured", &self.token.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl OrganizationMembershipClient {
    pub fn connect_lazy(
        target: &str,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, DeviceError> {
        if timeout.is_zero() {
            return Err(DeviceError::AuthorizationUnavailable);
        }
        let endpoint = Endpoint::from_shared(target.to_owned())
            .map_err(|_| DeviceError::AuthorizationUnavailable)?
            .connect_timeout(timeout)
            .timeout(timeout);
        let token = service_token
            .map(str::parse)
            .transpose()
            .map_err(|_| DeviceError::AuthorizationUnavailable)?;
        Ok(Self {
            client: OrganizationServiceClient::new(endpoint.connect_lazy()),
            token,
            timeout,
        })
    }

    pub async fn connect_with_ca(
        target: &str,
        ca_certificate: &Path,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, DeviceError> {
        if !target.starts_with("https://") || timeout.is_zero() {
            return Err(DeviceError::AuthorizationUnavailable);
        }
        let token = service_token
            .map(str::parse)
            .transpose()
            .map_err(|_| DeviceError::AuthorizationUnavailable)?;
        let channel = GrpcChannelFactory::new(
            GrpcChannelConfig {
                target: target.into(),
                security: GrpcTransportSecurity::ServerTls,
                trust: GrpcTrustMode::CustomCa,
                connect_timeout_ms: timeout.as_millis() as u64,
                request_timeout_ms: timeout.as_millis() as u64,
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::from_ca_pem_file(Some(ca_certificate))
                .map_err(|_| DeviceError::AuthorizationUnavailable)?,
        )
        .map_err(|_| DeviceError::AuthorizationUnavailable)?
        .connect()
        .await
        .map_err(|_| DeviceError::AuthorizationUnavailable)?;
        let client = Self {
            client: OrganizationServiceClient::new(channel),
            token,
            timeout,
        };
        client.check_health().await?;
        Ok(client)
    }

    pub async fn check_health(&self) -> Result<(), DeviceError> {
        let mut client = self.client.clone();
        match client
            .get_member(self.request(GetMemberRequest {
                organization_id: "00000000-0000-0000-0000-000000000000".into(),
                user_id: "device-registration-native-health".into(),
            }))
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::NotFound => Ok(()),
            Err(_) => Err(DeviceError::AuthorizationUnavailable),
        }
    }

    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request
    }
}

#[async_trait]
impl MembershipAuthorizer for OrganizationMembershipClient {
    async fn require_active(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), DeviceError> {
        if user_id.trim().is_empty() || organization_id.trim().is_empty() {
            return Err(DeviceError::Forbidden(
                "Not a member of this organization".into(),
            ));
        }
        let mut client = self.client.clone();
        let member = match client
            .get_member(self.request(GetMemberRequest {
                organization_id: organization_id.into(),
                user_id: user_id.into(),
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
                return Err(DeviceError::Forbidden(
                    "Not a member of this organization".into(),
                ))
            }
            Err(_) => return Err(DeviceError::AuthorizationUnavailable),
        };
        if member.user_id != user_id
            || member.organization_id != organization_id
            || !member.status.eq_ignore_ascii_case("active")
        {
            return Err(DeviceError::Forbidden(
                "Not a member of this organization".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ca_verified_organization_channel_rejects_plaintext_and_zero_timeout() {
        for (target, timeout) in [
            ("http://organization:9002", Duration::from_secs(1)),
            ("https://organization:9002", Duration::ZERO),
        ] {
            assert!(matches!(
                OrganizationMembershipClient::connect_with_ca(
                    target,
                    Path::new("unused-public-ca.pem"),
                    None,
                    timeout,
                )
                .await,
                Err(DeviceError::AuthorizationUnavailable)
            ));
        }
    }
}
