//! Authenticate gateway-forwarded API-key claims before parsing them.
//! Human authorization and tenant/resource permission checks stay with callers.

use http::HeaderMap;
use marty_api_key_policy::GatewayApiKeyActor;
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedPrincipalError {
    ServiceAuthentication,
    InvalidPrincipal,
}

/// Unconfigured admission allows callers to use their existing human path,
/// but always refuses service and forwarded-machine authentication.
#[derive(Clone, Default)]
pub struct ForwardedPrincipalAdmission {
    authenticator: Option<Arc<ServiceTokenAuthenticator>>,
}

impl ForwardedPrincipalAdmission {
    pub fn new(token: Option<String>) -> Result<Self, SecurityError> {
        Ok(Self {
            authenticator: token
                .map(|token| ServiceTokenAuthenticator::new(Some(token), true).map(Arc::new))
                .transpose()?,
        })
    }

    pub fn authenticate_service(&self, headers: &HeaderMap) -> Result<(), ForwardedPrincipalError> {
        self.authenticator
            .as_ref()
            .ok_or(ForwardedPrincipalError::ServiceAuthentication)?
            .authenticate(header(headers, "x-service-token"))
            .map_err(|_| ForwardedPrincipalError::ServiceAuthentication)
    }

    /// Header presence deliberately includes empty or non-UTF8 claims. Such
    /// attempts must never fall back to the human request path.
    pub fn gateway_actor(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<GatewayApiKeyActor>, ForwardedPrincipalError> {
        if !headers.contains_key("x-api-key-id") && !headers.contains_key("x-api-key-scopes") {
            return Ok(None);
        }
        self.authenticate_service(headers)?;
        GatewayApiKeyActor::parse(
            header(headers, "x-api-key-id").unwrap_or_default(),
            header(headers, "x-organization-id").unwrap_or_default(),
            header(headers, "x-api-key-scopes").unwrap_or_default(),
        )
        .map(Some)
        .map_err(|_| ForwardedPrincipalError::InvalidPrincipal)
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";

    fn configured() -> ForwardedPrincipalAdmission {
        ForwardedPrincipalAdmission::new(Some("s".repeat(32))).unwrap()
    }
    fn claims() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-api-key-id", KEY),
            ("x-organization-id", ORG),
            ("x-api-key-scopes", "compliance:read"),
        ] {
            headers.insert(name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }
    fn token(headers: &mut HeaderMap) {
        headers.insert(
            "x-service-token",
            HeaderValue::from_str(&format!(" {} ", "s".repeat(32))).unwrap(),
        );
    }
    #[test]
    fn absent_machine_headers_do_not_authenticate_or_change_the_human_path() {
        for admission in [ForwardedPrincipalAdmission::default(), configured()] {
            let mut headers = HeaderMap::new();
            for (name, value) in [
                ("x-user-id", "human"),
                ("x-organization-id", ORG),
                ("x-service-token", "invalid"),
            ] {
                headers.insert(name, HeaderValue::from_str(value).unwrap());
            }
            assert!(admission.gateway_actor(&headers).unwrap().is_none());
            assert_eq!(
                admission.authenticate_service(&headers),
                Err(ForwardedPrincipalError::ServiceAuthentication)
            );
        }
    }
    #[test]
    fn every_machine_attempt_authenticates_before_claim_validation() {
        for name in ["x-api-key-id", "x-api-key-scopes"] {
            for value in [
                HeaderValue::from_static(""),
                HeaderValue::from_static("invalid"),
                HeaderValue::from_bytes(&[0xff]).unwrap(),
            ] {
                let mut headers = HeaderMap::new();
                headers.insert(name, value);
                assert!(matches!(
                    configured().gateway_actor(&headers),
                    Err(ForwardedPrincipalError::ServiceAuthentication)
                ));
                token(&mut headers);
                assert!(matches!(
                    ForwardedPrincipalAdmission::default().gateway_actor(&headers),
                    Err(ForwardedPrincipalError::ServiceAuthentication)
                ));
                assert!(matches!(
                    configured().gateway_actor(&headers),
                    Err(ForwardedPrincipalError::InvalidPrincipal)
                ));
            }
        }
    }
    #[test]
    fn valid_trimmed_claims_remain_tenant_and_permission_bound() {
        let mut headers = claims();
        token(&mut headers);
        headers.insert(
            "x-api-key-id",
            HeaderValue::from_str(&format!(" {KEY} ")).unwrap(),
        );
        let actor = configured().gateway_actor(&headers).unwrap().unwrap();
        assert!(actor.authorizes(KEY, ORG, "compliance-profile:view"));
        assert!(!actor.authorizes(KEY, OTHER, "compliance-profile:view"));
        assert!(!actor.authorizes(KEY, ORG, "compliance-profile:create"));
        assert_eq!(configured().authenticate_service(&headers), Ok(()));
    }
    #[test]
    fn missing_wrong_malformed_and_empty_scope_inputs_keep_distinct_outcomes() {
        let admission = configured();
        let mut headers = claims();
        assert!(matches!(
            admission.gateway_actor(&headers),
            Err(ForwardedPrincipalError::ServiceAuthentication)
        ));
        headers.insert("x-service-token", HeaderValue::from_static("wrong"));
        assert!(matches!(
            admission.gateway_actor(&headers),
            Err(ForwardedPrincipalError::ServiceAuthentication)
        ));
        token(&mut headers);
        for key in ["invalid", "00000000-0000-0000-0000-000000000000"] {
            headers.insert("x-api-key-id", HeaderValue::from_str(key).unwrap());
            assert!(matches!(
                admission.gateway_actor(&headers),
                Err(ForwardedPrincipalError::InvalidPrincipal)
            ));
        }
        headers.insert("x-api-key-id", HeaderValue::from_static(KEY));
        headers.insert("x-api-key-scopes", HeaderValue::from_static(""));
        let actor = admission.gateway_actor(&headers).unwrap().unwrap();
        assert!(!actor.authorizes(KEY, ORG, "compliance-profile:view"));
    }
    #[test]
    fn configured_short_tokens_fail_construction_and_none_never_authenticates() {
        assert!(ForwardedPrincipalAdmission::new(Some("short".into())).is_err());
        let mut headers = claims();
        token(&mut headers);
        assert!(matches!(
            ForwardedPrincipalAdmission::new(None)
                .unwrap()
                .gateway_actor(&headers),
            Err(ForwardedPrincipalError::ServiceAuthentication)
        ));
    }
}
