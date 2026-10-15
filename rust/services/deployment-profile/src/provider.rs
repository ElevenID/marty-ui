use std::sync::Arc;

use marty_flow::{
    organization_proto::organization_service_client::OrganizationServiceClient,
    GrpcTenantMembershipProvider,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    KeylessGrpcTransportOptions, OpenBaoTlsIdentityFiles,
};
use mmf_security::TenantMembershipProvider;

use crate::{DeploymentError, DeploymentServiceConfig};

pub async fn tenant_membership_provider(
    config: &DeploymentServiceConfig,
) -> Result<Arc<dyn TenantMembershipProvider>, DeploymentError> {
    let channel = if let Some(files) = &config.workload_tls {
        OpenBaoTlsIdentityFiles {
            certificate_chain_file: files.certificate.clone(),
            kms_ca_cert_file: files.kms_ca_certificate.clone(),
            kms_endpoint: files.kms_endpoint.clone(),
            kms_token_file: files.kms_token_file.clone(),
            kms_key_name: files.kms_key_name.clone(),
            kms_key_version: files.kms_key_version,
            request_timeout: config.dependency_timeout,
            max_concurrent_signs: 64,
        }
        .grpc_channel_connected(
            &config.organization_grpc_target,
            &files.ca_certificate,
            KeylessGrpcTransportOptions {
                connect_timeout: config.dependency_timeout,
                request_timeout: config.dependency_timeout,
                ..KeylessGrpcTransportOptions::default()
            },
        )
        .await
        .map_err(|_| unavailable("Organization keyless gRPC connection is unavailable"))?
    } else {
        let (target, security, trust) = match &config.workload_tls {
            None if config.organization_grpc_target.starts_with("https://") => (
                config.organization_grpc_target.clone(),
                GrpcTransportSecurity::ServerTls,
                GrpcTrustMode::NativeRoots,
            ),
            None => (
                config.organization_grpc_target.clone(),
                GrpcTransportSecurity::Plaintext,
                GrpcTrustMode::NativeRoots,
            ),
            Some(_) => unreachable!("keyless workload TLS handled above"),
        };
        GrpcChannelFactory::new(
            GrpcChannelConfig {
                target,
                security,
                trust,
                connect_timeout_ms: config.dependency_timeout.as_millis() as u64,
                request_timeout_ms: config.dependency_timeout.as_millis() as u64,
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::default(),
        )
        .map_err(|_| unavailable("Organization gRPC configuration is invalid"))?
        .connect_lazy()
        .map_err(|_| unavailable("Organization gRPC channel is invalid"))?
    };
    let client = OrganizationServiceClient::new(channel);
    Ok(Arc::new(
        GrpcTenantMembershipProvider::new(client, config.service_token.as_deref())
            .map_err(|_| unavailable("Organization service authentication is invalid"))?,
    ))
}

fn unavailable(message: &str) -> DeploymentError {
    DeploymentError::Dependency(message.into())
}
