//! Exact owner-granted OID4VCI service/configuration bindings.
use crate::Oid4vpContractError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const METADATA_KEY: &str = "marty_wallet_issuance_authorizations_v1";

/// `credential_issuer` is the OID4VCI service identifier, not the credential's
/// signed `iss`. The owning issuer relationship supplies that permitted `iss`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct IssuanceAuthorization {
    pub credential_issuer: String,
    pub credential_configuration_id: String,
    pub format: String,
    pub vct: String,
    pub authorization_server: Option<String>,
    pub token_endpoint: Option<String>,
}

fn invalid() -> Oid4vpContractError {
    Oid4vpContractError::InvalidField("wallet_issuer_authority.issuance_authorizations")
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn https(value: &str, query: bool) -> bool {
    text(value, 2048)
        && !value.contains('*')
        && url::Url::parse(value).is_ok_and(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
                && (query || u.query().is_none())
        })
}
impl IssuanceAuthorization {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        if !https(&self.credential_issuer, false)
            || !text(&self.credential_configuration_id, 256)
            || !matches!(self.format.as_str(), "dc+sd-jwt" | "vc+sd-jwt")
            || !text(&self.vct, 2048)
            || url::Url::parse(&self.vct).is_err()
            || match (&self.authorization_server, &self.token_endpoint) {
                (None, None) => false,
                (Some(server), Some(endpoint)) => !https(server, false) || !https(endpoint, true),
                _ => true,
            }
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Absence grants no issuance services. Validate before writes and again when
/// observing persisted state, without inferring service identity from a DID.
pub fn authorizations(metadata: &Value) -> Result<Vec<IssuanceAuthorization>, Oid4vpContractError> {
    let Some(value) = metadata.get(METADATA_KEY) else {
        return Ok(Vec::new());
    };
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > 300_000 {
        return Err(invalid());
    }
    let mut grants: Vec<IssuanceAuthorization> =
        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if grants.len() > 128 {
        return Err(invalid());
    }
    for grant in &grants {
        grant.validate()?;
    }
    grants.sort();
    if grants.windows(2).any(|v| v[0] == v[1]) {
        return Err(invalid());
    }
    Ok(grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn grant() -> Value {
        json!({"credential_issuer":"https://service.example/tenant",
        "credential_configuration_id":"employee","format":"dc+sd-jwt","vct":"urn:example:employee",
        "authorization_server":null,"token_endpoint":null})
    }
    #[test]
    fn grants_are_explicit_bounded_unique_and_preserve_distinct_service_identity() {
        assert!(authorizations(&json!({})).unwrap().is_empty());
        let value = grant();
        let parsed = authorizations(&json!({METADATA_KEY:[value.clone()]})).unwrap();
        assert_eq!(
            parsed[0].credential_issuer,
            "https://service.example/tenant"
        );
        assert_eq!(parsed[0].credential_configuration_id, "employee");
        assert!(authorizations(&json!({METADATA_KEY:[value.clone(),value.clone()]})).is_err());
        assert!(authorizations(&json!({METADATA_KEY:vec![value;129]})).is_err());
    }
    #[test]
    fn ambiguous_unsafe_or_partial_service_controls_are_rejected() {
        for (name, value) in [
            ("credential_issuer", json!("did:web:credential.example")),
            ("credential_issuer", json!("http://service.example")),
            (
                "credential_issuer",
                json!("https://user:pass@service.example"),
            ),
            ("credential_issuer", json!("https://service.example/*")),
            (
                "credential_issuer",
                json!("https://service.example?tenant=x"),
            ),
            ("credential_configuration_id", json!(" ")),
            ("credential_configuration_id", json!("x".repeat(257))),
            ("format", json!("MDOC")),
            ("vct", json!("not-a-uri")),
            (
                "authorization_server",
                json!("https://authorization.example"),
            ),
            (
                "token_endpoint",
                json!("https://authorization.example/token"),
            ),
            ("credential_iss", json!("did:web:unowned.example")),
        ] {
            let mut changed = grant();
            changed[name] = value;
            assert!(
                authorizations(&json!({METADATA_KEY:[changed]})).is_err(),
                "{name}"
            );
        }
        let mut delegated = grant();
        delegated["authorization_server"] = json!("https://authorization.example");
        delegated["token_endpoint"] = json!("https://authorization.example/token?realm=approved");
        assert!(authorizations(&json!({METADATA_KEY:[delegated]})).is_ok());
    }
}
