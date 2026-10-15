use std::path::Path;

use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use tonic::transport::Channel;

/// Keeps Applicant's outbox channel lazy while requiring public CA trust in deployed stacks.
pub fn event_stream_channel(
    target: &str,
    ca_certificate: Option<&Path>,
    deployed: bool,
) -> Result<Channel, String> {
    let target = if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    };
    if deployed && ca_certificate.is_none() {
        return Err("ES_GRPC_CA_CERT is required outside development".into());
    }
    if ca_certificate.is_some() && !target.starts_with("https://") {
        return Err("ES_GRPC_TARGET must use HTTPS with ES_GRPC_CA_CERT".into());
    }
    let (security, trust, material) = if target.starts_with("https://") {
        let trust = if ca_certificate.is_some() {
            GrpcTrustMode::CustomCa
        } else {
            GrpcTrustMode::NativeRoots
        };
        (
            GrpcTransportSecurity::ServerTls,
            trust,
            GrpcTlsMaterial::from_ca_pem_file(ca_certificate).map_err(|error| error.to_string())?,
        )
    } else {
        (
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        )
    };
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security,
            trust,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .map_err(|error| error.to_string())?
    .connect_lazy()
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deployed_event_stream_requires_https_and_a_public_ca() {
        assert!(event_stream_channel("event-stream:9015", None, false).is_ok());
        assert!(event_stream_channel("event-stream:9015", None, true).is_err());
        assert!(
            event_stream_channel("http://event-stream:9015", Some(Path::new("ca.pem")), true)
                .is_err()
        );
        assert!(event_stream_channel(
            "https://event-stream:9015",
            Some(Path::new("missing-ca.pem")),
            true
        )
        .is_err());
    }
}
