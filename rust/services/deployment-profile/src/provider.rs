use std::sync::Arc;

use marty_flow::{
    organization_proto::organization_service_client::OrganizationServiceClient,
    GrpcTenantMembershipProvider,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use mmf_security::TenantMembershipProvider;

use crate::{DeploymentError, DeploymentServiceConfig};

pub fn tenant_membership_provider(
    config: &DeploymentServiceConfig,
) -> Result<Arc<dyn TenantMembershipProvider>, DeploymentError> {
    let (target, security, trust, material) = match &config.workload_tls {
        Some(files) => (
            config
                .organization_grpc_target
                .replacen("http://", "https://", 1),
            GrpcTransportSecurity::MutualTls,
            GrpcTrustMode::CustomCa,
            GrpcTlsMaterial::from_pem_files(
                Some(&files.ca_certificate),
                Some(&files.certificate),
                Some(&files.private_key),
            )
            .map_err(|_| unavailable("workload TLS material is invalid"))?,
        ),
        None if config.organization_grpc_target.starts_with("https://") => (
            config.organization_grpc_target.clone(),
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
        None => (
            config.organization_grpc_target.clone(),
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
    };
    let channel = GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security,
            trust,
            connect_timeout_ms: config.dependency_timeout.as_millis() as u64,
            request_timeout_ms: config.dependency_timeout.as_millis() as u64,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .map_err(|_| unavailable("Organization gRPC configuration is invalid"))?
    .connect_lazy()
    .map_err(|_| unavailable("Organization gRPC channel is invalid"))?;
    let client = OrganizationServiceClient::new(channel);
    Ok(Arc::new(
        GrpcTenantMembershipProvider::new(client, config.service_token.as_deref())
            .map_err(|_| unavailable("Organization service authentication is invalid"))?,
    ))
}

fn unavailable(message: &str) -> DeploymentError {
    DeploymentError::Dependency(message.into())
}
