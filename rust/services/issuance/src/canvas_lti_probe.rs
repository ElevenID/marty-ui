//! Shared, provider-neutral Canvas LTI metadata probing.
//!
//! Network discovery and trust-profile validation live here so management,
//! launch-time JWKS refresh, and explicit probe routes cannot drift.

use std::time::Duration;

use async_trait::async_trait;
use marty_oid4vci::lti::{
    canvas_lti_trust_profile, normalize_canvas_base_url, probe_canvas_lti_platform,
    CanvasLtiPlatformProbe,
};

#[derive(Clone)]
pub struct CanvasLtiJwksRefreshConfig {
    pub timeout: Duration,
    pub ttl: Duration,
    pub self_managed_origins: Vec<String>,
    pub allow_private_networks: bool,
    pub allow_http_localhost: bool,
}

impl std::fmt::Debug for CanvasLtiJwksRefreshConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiJwksRefreshConfig")
            .field("timeout", &self.timeout)
            .field("ttl", &self.ttl)
            .field(
                "self_managed_origin_count",
                &self.self_managed_origins.len(),
            )
            .field("allow_private_networks", &self.allow_private_networks)
            .field("allow_http_localhost", &self.allow_http_localhost)
            .finish()
    }
}

#[async_trait]
pub trait CanvasLtiProbeClient: Send + Sync {
    async fn probe(
        &self,
        canvas_base_url: &str,
        config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String>;
}

#[derive(Debug)]
pub struct MartyCanvasLtiProbeClient;

#[async_trait]
impl CanvasLtiProbeClient for MartyCanvasLtiProbeClient {
    async fn probe(
        &self,
        canvas_base_url: &str,
        config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        probe_canvas_lti_platform(
            canvas_base_url,
            config.timeout.as_secs().max(1),
            config.allow_private_networks,
            config.allow_http_localhost,
        )
        .await
        .map_err(|error| error.to_string())
    }
}

/// Probe one Canvas origin and reject metadata outside its persisted trust
/// profile. The caller owns persistence and any lifecycle transition.
pub async fn probe_canvas_lti_metadata(
    canvas_base_url: &str,
    trust_profile: &str,
    config: &CanvasLtiJwksRefreshConfig,
    client: &dyn CanvasLtiProbeClient,
) -> Result<CanvasLtiPlatformProbe, String> {
    let normalized_origin = normalize_canvas_base_url(
        canvas_base_url,
        config.allow_private_networks,
        config.allow_http_localhost,
    )
    .map_err(|error| error.to_string())?;
    let expected = canvas_lti_trust_profile(
        &normalized_origin,
        trust_profile,
        &config.self_managed_origins,
    )
    .map_err(|_| "Canvas metadata probe did not use the persisted LTI trust profile".to_owned())?;
    let probe = client.probe(&normalized_origin, config).await?;
    if probe.canvas_base_url != normalized_origin
        || probe.issuer != expected.issuer
        || probe.authorization_endpoint.as_deref() != Some(expected.authorization_endpoint.as_str())
        || probe.token_endpoint.as_deref() != Some(expected.token_endpoint.as_str())
        || probe.jwks_uri != expected.jwks_uri
    {
        return Err(
            "Canvas metadata probe returned endpoints outside the persisted trust profile"
                .to_owned(),
        );
    }
    Ok(probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FixedProbe(CanvasLtiPlatformProbe);

    #[async_trait]
    impl CanvasLtiProbeClient for FixedProbe {
        async fn probe(
            &self,
            _canvas_base_url: &str,
            _config: &CanvasLtiJwksRefreshConfig,
        ) -> Result<CanvasLtiPlatformProbe, String> {
            Ok(self.0.clone())
        }
    }

    fn config() -> CanvasLtiJwksRefreshConfig {
        CanvasLtiJwksRefreshConfig {
            timeout: Duration::from_secs(10),
            ttl: Duration::from_secs(3_600),
            self_managed_origins: vec!["https://private.example.edu".to_owned()],
            allow_private_networks: false,
            allow_http_localhost: false,
        }
    }

    fn probe(jwks_uri: &str) -> CanvasLtiPlatformProbe {
        CanvasLtiPlatformProbe {
            canvas_base_url: "https://canvas.example.edu".to_owned(),
            issuer: "https://canvas.instructure.com".to_owned(),
            authorization_endpoint: Some(
                "https://sso.canvaslms.com/api/lti/authorize_redirect".to_owned(),
            ),
            token_endpoint: Some("https://canvas.example.edu/login/oauth2/token".to_owned()),
            jwks_uri: jwks_uri.to_owned(),
            registration_endpoint: None,
            raw_openid_configuration: json!({"issuer": "https://canvas.instructure.com"}),
            jwks_json: json!({"keys": []}),
        }
    }

    #[tokio::test]
    async fn shared_probe_rejects_profile_and_endpoint_drift() {
        let config = config();
        let invalid_profile = probe_canvas_lti_metadata(
            "https://canvas.example.edu",
            "unsupported-profile",
            &config,
            &FixedProbe(probe("https://sso.canvaslms.com/api/lti/security/jwks")),
        )
        .await
        .unwrap_err();
        assert_eq!(
            invalid_profile,
            "Canvas metadata probe did not use the persisted LTI trust profile"
        );

        let endpoint_drift = probe_canvas_lti_metadata(
            "https://canvas.example.edu",
            "hosted_global",
            &config,
            &FixedProbe(probe("https://attacker.example/jwks")),
        )
        .await
        .unwrap_err();
        assert_eq!(
            endpoint_drift,
            "Canvas metadata probe returned endpoints outside the persisted trust profile"
        );
    }

    #[test]
    fn probe_configuration_debug_redacts_operator_origins() {
        let debug = format!("{:?}", config());
        assert!(debug.contains("self_managed_origin_count: 1"));
        assert!(!debug.contains("private.example.edu"));
    }
}
