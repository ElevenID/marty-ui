use crate::{ComplianceError, ComplianceServiceConfig};
use marty_flow::{
    organization_proto::organization_service_client::OrganizationServiceClient,
    GrpcTenantMembershipProvider,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use mmf_security::TenantMembershipProvider;
use std::sync::Arc;
pub fn tenant_membership_provider(
    c: &ComplianceServiceConfig,
) -> Result<Arc<dyn TenantMembershipProvider>, ComplianceError> {
    let (target, security, trust, material) = match &c.workload_tls {
        Some(f) => (
            c.organization_grpc_target
                .replacen("http://", "https://", 1),
            GrpcTransportSecurity::MutualTls,
            GrpcTrustMode::CustomCa,
            GrpcTlsMaterial::from_pem_files(
                Some(&f.ca_certificate),
                Some(&f.certificate),
                Some(&f.private_key),
            )
            .map_err(|_| bad())?,
        ),
        None if c.organization_grpc_target.starts_with("https://") => (
            c.organization_grpc_target.clone(),
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
        None => (
            c.organization_grpc_target.clone(),
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
    };
    let ch = GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security,
            trust,
            connect_timeout_ms: c.dependency_timeout.as_millis() as u64,
            request_timeout_ms: c.dependency_timeout.as_millis() as u64,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .map_err(|_| bad())?
    .connect_lazy()
    .map_err(|_| bad())?;
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
