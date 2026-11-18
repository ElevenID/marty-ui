//! Fail-closed organization binding for the native physical-passport proxy.

use std::fmt;

use marty_passport_auth::PassportCredentialLookup;
use mmf_platform::{HttpMethod, TrustedIdentityContext};

use crate::issuance_native::passport_required_permission;

#[derive(Clone, Eq, PartialEq)]
pub struct PassportUpstreamAuth {
    organization_id: String,
    api_key: Box<str>,
}

impl fmt::Debug for PassportUpstreamAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassportUpstreamAuth")
            .field("organization_id", &self.organization_id)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl PassportUpstreamAuth {
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassportGatewayAuthError {
    NotPublicPassportRoute,
    MissingTenantAuthorization,
    OrganizationMismatch,
    TenantKeyUnavailable,
}

/// Caller-provided organization hints are never used to select a key. They
/// may only agree with the organization authorized by gateway middleware.
pub fn passport_upstream_auth(
    keyring: &impl PassportCredentialLookup,
    identity: &TrustedIdentityContext,
    method: HttpMethod,
    path: &str,
    claimed_header_organization: Option<&str>,
    claimed_body_organization: Option<&str>,
    claimed_query_organization: Option<&str>,
) -> Result<PassportUpstreamAuth, PassportGatewayAuthError> {
    let required = passport_required_permission(method, path)
        .ok_or(PassportGatewayAuthError::NotPublicPassportRoute)?;
    if identity.required_permission.as_deref() != Some(required) {
        return Err(PassportGatewayAuthError::MissingTenantAuthorization);
    }
    let organization_id = identity
        .organization_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(PassportGatewayAuthError::MissingTenantAuthorization)?;
    if [
        claimed_header_organization,
        claimed_body_organization,
        claimed_query_organization,
    ]
    .into_iter()
    .flatten()
    .any(|claim| claim != organization_id)
    {
        return Err(PassportGatewayAuthError::OrganizationMismatch);
    }
    let api_key = keyring
        .key_for(organization_id)
        .ok_or(PassportGatewayAuthError::TenantKeyUnavailable)?;
    Ok(PassportUpstreamAuth {
        organization_id: organization_id.to_owned(),
        api_key: api_key.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_passport_auth::{PassportTenantCredentialSource, PassportTenantKeyring};

    #[test]
    fn internal_handoff_uses_only_authorized_organization_and_existing_service_token() {
        let token = "s".repeat(32);
        let source = PassportTenantCredentialSource::internal_service_token(&token).unwrap();
        let authorized = authorized("org-a", "issuance:initiate");
        let handoff = passport_upstream_auth(
            &source,
            &authorized,
            HttpMethod::Post,
            "/v1/passport/applications",
            Some("org-a"),
            Some("org-a"),
            None,
        )
        .unwrap();
        assert_eq!(handoff.organization_id(), "org-a");
        assert_eq!(handoff.api_key(), token);
        assert!(!format!("{handoff:?}").contains(&token));
        assert_eq!(
            passport_upstream_auth(
                &source,
                &authorized,
                HttpMethod::Post,
                "/v1/passport/applications",
                Some("org-b"),
                None,
                None
            )
            .unwrap_err(),
            PassportGatewayAuthError::OrganizationMismatch
        );
    }

    fn keyring() -> PassportTenantKeyring {
        PassportTenantKeyring::from_json(
            r#"{"org-a":"passport-native-key-for-org-a-00000001","org-b":"passport-native-key-for-org-b-00000002"}"#,
        )
        .unwrap()
    }

    fn authorized(organization_id: &str, permission: &str) -> TrustedIdentityContext {
        TrustedIdentityContext {
            organization_id: Some(organization_id.into()),
            required_permission: Some(permission.into()),
            ..TrustedIdentityContext::default()
        }
    }

    #[test]
    fn native_key_is_selected_only_from_the_authorized_tenant() {
        let keys = keyring();
        let identity = authorized("org-a", "issuance:initiate");
        let key = passport_upstream_auth(
            &keys,
            &identity,
            HttpMethod::Post,
            "/v1/passport/applications",
            Some("org-a"),
            Some("org-a"),
            Some("org-a"),
        )
        .unwrap();
        assert_eq!(key.organization_id(), "org-a");
        assert_eq!(key.api_key(), keys.key_for("org-a").unwrap());
        assert_ne!(key.api_key(), keys.key_for("org-b").unwrap());
        assert!(!format!("{key:?}").contains(key.api_key()));
        for (header, body, query) in [
            (Some("org-b"), None, None),
            (None, Some("org-b"), None),
            (None, None, Some("org-b")),
        ] {
            assert_eq!(
                passport_upstream_auth(
                    &keys,
                    &identity,
                    HttpMethod::Post,
                    "/v1/passport/applications",
                    header,
                    body,
                    query,
                )
                .unwrap_err(),
                PassportGatewayAuthError::OrganizationMismatch
            );
        }
    }

    #[test]
    fn missing_permission_unknown_tenant_and_webhook_fail_closed() {
        let keys = keyring();
        let path = "/v1/passport/applications/job-1/activate";
        assert_eq!(
            passport_upstream_auth(
                &keys,
                &TrustedIdentityContext::default(),
                HttpMethod::Post,
                path,
                None,
                None,
                None,
            )
            .unwrap_err(),
            PassportGatewayAuthError::MissingTenantAuthorization
        );
        assert_eq!(
            passport_upstream_auth(
                &keys,
                &authorized("org-a", "issuance:view"),
                HttpMethod::Post,
                path,
                None,
                None,
                None,
            )
            .unwrap_err(),
            PassportGatewayAuthError::MissingTenantAuthorization
        );
        assert_eq!(
            passport_upstream_auth(
                &keys,
                &authorized("org-c", "issuance:initiate"),
                HttpMethod::Post,
                path,
                None,
                None,
                None,
            )
            .unwrap_err(),
            PassportGatewayAuthError::TenantKeyUnavailable
        );
        assert_eq!(
            passport_upstream_auth(
                &keys,
                &authorized("org-a", "issuance:initiate"),
                HttpMethod::Post,
                "/v1/passport/webhooks/personalization",
                None,
                None,
                None,
            )
            .unwrap_err(),
            PassportGatewayAuthError::NotPublicPassportRoute
        );
    }
}
