//! Canonical issuer type grants from the fixed, user-authorized HTTPS owner.
use crate::DeviceError;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use marty_key_material_policy::contains_private_key;
use marty_oid4vp_contract::{
    trust_authority::{
        issuer_public_key_algorithm, issuer_public_key_thumbprint, CredentialTypeAuthorizationV1,
    },
    EvidenceProfileReference,
};
use reqwest::{header::HeaderValue, Client, Url};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
fn invalid() -> DeviceError {
    DeviceError::AuthorizationUnavailable
}
fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
#[derive(Clone)]
pub struct WalletIssuerTrustClient {
    client: Client,
    origin: Url,
    service_token: HeaderValue,
}
impl WalletIssuerTrustClient {
    pub fn new(origin: &str, token: &str, ca_pem: Option<&[u8]>) -> Result<Self, DeviceError> {
        let origin = Url::parse(origin).map_err(|_| invalid())?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || token.len() < 32
            || token.len() > 8192
        {
            return Err(invalid());
        }
        let mut service_token = HeaderValue::from_str(token).map_err(|_| invalid())?;
        service_token.set_sensitive(true);
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = ca_pem {
            if pem.len() > 65536 {
                return Err(invalid());
            }
            let certificates = reqwest::Certificate::from_pem_bundle(pem).map_err(|_| invalid())?;
            if certificates.is_empty() {
                return Err(invalid());
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(Self {
            client: builder.build().map_err(|_| invalid())?,
            origin,
            service_token,
        })
    }
    pub async fn fetch(
        &self,
        profile: &str,
        organization: &str,
        user: &str,
    ) -> Result<Value, DeviceError> {
        let id = Uuid::parse_str(profile).map_err(|_| invalid())?;
        if id.is_nil() || id.to_string() != profile || !text(organization) || !text(user) {
            return Err(invalid());
        }
        let mut url = self
            .origin
            .join(&format!(
                "internal/v1/trust-profiles/{profile}/wallet-issuer-authority"
            ))
            .map_err(|_| invalid())?;
        url.query_pairs_mut()
            .append_pair("organization_id", organization);
        // Caller derives user from authenticated pairing, never mobile headers.
        let mut response = self
            .client
            .get(url)
            .header("x-service-token", self.service_token.clone())
            .header(
                "x-user-id",
                HeaderValue::from_str(user).map_err(|_| invalid())?,
            )
            .send()
            .await
            .map_err(|_| invalid())?;
        if matches!(response.status().as_u16(), 401 | 403 | 404) {
            return Err(DeviceError::Forbidden(
                "wallet issuer trust is unavailable".into(),
            ));
        }
        if response.status() != reqwest::StatusCode::OK
            || response.headers().get_all("content-type").iter().count() != 1
            || response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .map(str::trim)
                != Some("application/json")
        {
            return Err(invalid());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(invalid());
            }
            body.extend_from_slice(&chunk);
        }
        let snapshot = crate::wallet_verifier_trust::decode_unique_json(&body, MAX_RESPONSE_BYTES)?;
        validate_snapshot(&snapshot, profile, organization, Utc::now())?;
        Ok(snapshot)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    contract: String,
    organization_id: String,
    trust_profile_id: String,
    revision: EvidenceProfileReference,
    generated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    require_not_before: bool,
    issuer_keys: Vec<IssuerKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerKey {
    issuer: String,
    key_id: Option<String>,
    algorithm: String,
    public_jwk: Value,
    credential_authorizations: Vec<CredentialTypeAuthorizationV1>,
}
fn validate_snapshot(
    value: &Value,
    profile: &str,
    organization: &str,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    if contains_private_key(value) {
        return Err(invalid());
    }
    let snapshot: Snapshot = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    let digest = snapshot.revision.content_digest.strip_prefix("sha256:");
    if snapshot.contract != "marty.wallet/issuer-authority/v2"
        || snapshot.organization_id != organization
        || snapshot.trust_profile_id != profile
        || snapshot.revision.id != profile
        || snapshot.revision.version == 0
        || !digest.is_some_and(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || snapshot.generated_at > now
        || snapshot.expires_at <= now
        || snapshot.expires_at <= snapshot.generated_at
        || snapshot.expires_at > snapshot.generated_at + ChronoDuration::seconds(60)
        || snapshot.issuer_keys.is_empty()
        || snapshot.issuer_keys.len() > 256
    {
        return Err(invalid());
    }
    // Both explicit values are valid; native applies this control to the exact
    // signed credential. It is never inferred from a missing legacy field.
    let _require_not_before = snapshot.require_not_before;
    let mut identities = BTreeSet::new();
    for key in snapshot.issuer_keys {
        if !text(&key.issuer)
            || key.key_id.as_ref().is_some_and(|v| !text(v))
            || issuer_public_key_algorithm(&key.public_jwk).map_err(|_| invalid())? != key.algorithm
            || key
                .public_jwk
                .get("kid")
                .is_some_and(|v| v.as_str() != key.key_id.as_deref())
            || key.credential_authorizations.is_empty()
            || key.credential_authorizations.len() > 128
            || !identities.insert((
                key.issuer.clone(),
                key.key_id.clone(),
                key.algorithm.clone(),
            ))
        {
            return Err(invalid());
        }
        issuer_public_key_thumbprint(&key.public_jwk).map_err(|_| invalid())?;
        let mut grants = BTreeSet::new();
        for grant in key.credential_authorizations {
            grant.validate().map_err(|_| invalid())?;
            if !grants.insert(grant) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const PROFILE: &str = "11111111-2222-4333-8444-555555555555";
    fn snapshot(now: DateTime<Utc>) -> Value {
        json!({"contract":"marty.wallet/issuer-authority/v2","organization_id":"org-a","trust_profile_id":PROFILE,
            "revision":{"id":PROFILE,"version":1,"content_digest":format!("sha256:{}","a".repeat(64))},
            "generated_at":now,"expires_at":now+ChronoDuration::seconds(30),"require_not_before":true,
            "issuer_keys":[{"issuer":"did:web:issuer.example","key_id":"issuer-key","algorithm":"EdDSA",
                "public_jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"sig","kid":"issuer-key"},
                "credential_authorizations":[{"format":"SD_JWT_VC","vct":"https://credential.example/identity"}]}]})
    }
    #[test]
    fn unsafe_owner_configuration_is_rejected_before_fetch() {
        for origin in [
            "http://owner.example",
            "https://user:pass@owner.example",
            "https://owner.example/path",
            "https://owner.example?tenant=x",
            "https://owner.example#fragment",
        ] {
            assert!(WalletIssuerTrustClient::new(origin, &"s".repeat(32), None).is_err());
        }
        assert!(WalletIssuerTrustClient::new("https://owner.example", "short", None).is_err());
        assert!(WalletIssuerTrustClient::new(
            "https://owner.example",
            &"s".repeat(32),
            Some(b"invalid CA")
        )
        .is_err());
    }
    #[test]
    fn canonical_snapshot_rejects_policy_scope_key_and_grant_substitution() {
        let now = Utc::now();
        let original = snapshot(now);
        assert!(validate_snapshot(&original, PROFILE, "org-a", now).is_ok());
        for (pointer, value) in [
            ("/contract", json!("legacy")),
            ("/organization_id", json!("other")),
            ("/revision/id", json!(Uuid::new_v4().to_string())),
            ("/revision/version", json!(0)),
            ("/revision/content_digest", json!("unbound")),
            ("/generated_at", json!(now + ChronoDuration::seconds(1))),
            ("/expires_at", json!(now)),
            ("/issuer_keys/0/credential_authorizations", json!([])),
            (
                "/issuer_keys/0/credential_authorizations/0/format",
                json!("MDOC"),
            ),
            ("/issuer_keys/0/algorithm", json!("ES256")),
            ("/issuer_keys/0/public_jwk/kid", json!("other")),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_snapshot(&changed, PROFILE, "org-a", now).is_err(),
                "{pointer}"
            );
        }
        for name in ["contract", "revision", "require_not_before"] {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(name);
            assert!(validate_snapshot(&changed, PROFILE, "org-a", now).is_err());
        }
        let mut private = original.clone();
        private["issuer_keys"][0]["public_jwk"]["d"] = json!("sensitive");
        assert!(validate_snapshot(&private, PROFILE, "org-a", now).is_err());
        let raw = original.to_string().replacen(
            "\"organization_id\":",
            "\"organization_id\":\"attacker\",\"\\u006frganization_id\":",
            1,
        );
        assert!(crate::wallet_verifier_trust::decode_unique_json(
            raw.as_bytes(),
            MAX_RESPONSE_BYTES
        )
        .is_err());
    }
}
