use crate::{ComplianceError, ComplianceServiceConfig};
use marty_flow::{
    organization_proto::organization_service_client::OrganizationServiceClient,
    GrpcTenantMembershipProvider,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    KeylessGrpcTransportOptions,
};
use mmf_security::TenantMembershipProvider;
use std::sync::Arc;
pub async fn tenant_membership_provider(
    c: &ComplianceServiceConfig,
) -> Result<Arc<dyn TenantMembershipProvider>, ComplianceError> {
    let ch = if let Some(f) = &c.workload_tls {
        f.identity
            .clone()
            .with_request_timeout(c.dependency_timeout)
            .grpc_channel_connected(
                &c.organization_grpc_target,
                &f.ca_certificate,
                KeylessGrpcTransportOptions {
                    connect_timeout: c.dependency_timeout,
                    request_timeout: c.dependency_timeout,
                    ..KeylessGrpcTransportOptions::default()
                },
            )
            .await
            .map_err(|_| bad())?
    } else {
        let (target, security, trust) = match &c.workload_tls {
            None if c.organization_grpc_target.starts_with("https://") => (
                c.organization_grpc_target.clone(),
                GrpcTransportSecurity::ServerTls,
                GrpcTrustMode::NativeRoots,
            ),
            None => (
                c.organization_grpc_target.clone(),
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
                connect_timeout_ms: c.dependency_timeout.as_millis() as u64,
                request_timeout_ms: c.dependency_timeout.as_millis() as u64,
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::default(),
        )
        .map_err(|_| bad())?
        .connect_lazy()
        .map_err(|_| bad())?
    };
    Ok(Arc::new(
        GrpcTenantMembershipProvider::new(
            OrganizationServiceClient::new(ch),
            c.service_token.as_deref(),
        )
        .map_err(|_| bad())?,
    ))
}
fn bad() -> ComplianceError {
    ComplianceError::Dependency("Organization service configuration is invalid".into())
}
