//! Fresh, user-authorized verifier authority from the operator's fixed HTTPS owner.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use marty_key_material_policy::contains_private_key;
use reqwest::{header::HeaderValue, Client, Url};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

use crate::DeviceError;

const MAX_BYTES: usize = 65536;

#[derive(Clone)]
pub struct WalletVerifierTrustClient {
    client: Client,
    origin: Url,
    token: HeaderValue,
}

impl WalletVerifierTrustClient {
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
        let mut token = HeaderValue::from_str(token).map_err(|_| invalid())?;
        token.set_sensitive(true);
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = ca_pem {
            if pem.len() > MAX_BYTES {
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
            token,
        })
    }

    pub async fn admit(
        &self,
        profile: &str,
        organization: &str,
        user: &str,
    ) -> Result<(), DeviceError> {
        self.read(profile, organization, user, None).await?;
        Ok(())
    }

    pub async fn fetch(
        &self,
        profile: &str,
        organization: &str,
        user: &str,
        client: &str,
    ) -> Result<Value, DeviceError> {
        self.read(profile, organization, user, Some(client)).await
    }

    async fn read(
        &self,
        profile: &str,
        organization: &str,
        user: &str,
        client: Option<&str>,
    ) -> Result<Value, DeviceError> {
        let id = Uuid::parse_str(profile).map_err(|_| invalid())?;
        if id.is_nil()
            || id.to_string() != profile
            || !text(organization)
            || !text(user)
            || client.is_some_and(|value| !text(value) || value.contains(':'))
        {
            return Err(invalid());
        }
        let endpoint = if client.is_some() {
            "wallet-verifier-authority"
        } else {
            "wallet-verifier-profile-admission"
        };
        let mut url = self
            .origin
            .join(&format!("internal/v1/trust-profiles/{profile}/{endpoint}"))
            .map_err(|_| invalid())?;
        url.query_pairs_mut()
            .append_pair("organization_id", organization);
        if let Some(client) = client {
            url.query_pairs_mut().append_pair("client_id", client);
        }
        // user is derived from the confirmed pairing, never from mobile headers.
        let mut response = self
            .client
            .get(url)
            .header("x-service-token", self.token.clone())
            .header(
                "x-user-id",
                HeaderValue::from_str(user).map_err(|_| invalid())?,
            )
            .send()
            .await
            .map_err(|_| invalid())?;
        if matches!(response.status().as_u16(), 401 | 403 | 404) {
            return Err(DeviceError::Forbidden(
                "wallet verifier trust is unavailable".into(),
            ));
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = decode(&bytes)?;
        validate(&value, profile, organization, client, Utc::now())?;
        Ok(value)
    }
}

fn invalid() -> DeviceError {
    DeviceError::AuthorizationUnavailable
}

fn decode(bytes: &[u8]) -> Result<Value, DeviceError> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    serde_json::from_slice::<UniqueValue>(bytes)
        .map(|value| value.0)
        .map_err(|_| invalid())
}

// Decode member names before checking uniqueness, recursively including JWKs.
// serde_json's normal recursion limit remains enabled.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    contract: String,
    organization_id: String,
    trust_profile_id: String,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    authority: Option<Authority>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    authority_id: String,
    revision: String,
    key_purpose: String,
    algorithm: String,
    request_clock_skew_seconds: u32,
    max_request_lifetime_seconds: u32,
    registration: Registration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    client_id: String,
    request_key_id: String,
    public_jwk: Value,
    response_uris: Vec<String>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

fn validate(
    value: &Value,
    profile: &str,
    organization: &str,
    client: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    if contains_private_key(value) {
        return Err(invalid());
    }
    let snapshot: Snapshot = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    let contract = if client.is_some() {
        "marty.wallet/verifier-authority/v1"
    } else {
        "marty.wallet/verifier-profile-admission/v1"
    };
    if snapshot.contract != contract
        || snapshot.organization_id != organization
        || snapshot.trust_profile_id != profile
        || snapshot.observed_at > now
        || snapshot.expires_at <= now
        || snapshot.expires_at <= snapshot.observed_at
        || snapshot.expires_at > snapshot.observed_at + ChronoDuration::seconds(60)
    {
        return Err(invalid());
    }
    let Some(client) = client else {
        return if value.get("authority").is_none() {
            Ok(())
        } else {
            Err(invalid())
        };
    };
    let authority = snapshot.authority.ok_or_else(invalid)?;
    let Some(source) = authority.authority_id.strip_prefix(&format!("{profile}/")) else {
        return Err(invalid());
    };
    if Uuid::parse_str(source).map_or(true, |id| id.is_nil() || id.to_string() != source)
        || !text(&authority.revision)
        || authority.key_purpose != "oid4vp_request_signing"
        || authority.algorithm != "ES256"
        || authority.request_clock_skew_seconds != 30
        || authority.max_request_lifetime_seconds != 900
    {
        return Err(invalid());
    }
    let registration = authority.registration;
    if registration.client_id != client
        || !text(&registration.request_key_id)
        || registration.valid_from > now
        || registration.valid_until <= now
        || registration.valid_until < snapshot.expires_at
        || registration.valid_from.timestamp_subsec_nanos() != 0
        || registration.valid_until.timestamp_subsec_nanos() != 0
        || registration.response_uris.is_empty()
        || registration.response_uris.len() > 8
    {
        return Err(invalid());
    }
    let jwk = registration.public_jwk.as_object().ok_or_else(invalid)?;
    if jwk.keys().any(|key| {
        !["kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"].contains(&key.as_str())
    }) || jwk
        .get("kid")
        .is_some_and(|kid| kid.as_str() != Some(registration.request_key_id.as_str()))
        || marty_oid4vp_contract::trust_authority::issuer_public_key_algorithm(
            &registration.public_jwk,
        )
        .map_err(|_| invalid())?
            != "ES256"
    {
        return Err(invalid());
    }
    let mut recipients = BTreeSet::new();
    for recipient in registration.response_uris {
        let url = Url::parse(&recipient).map_err(|_| invalid())?;
        if !text(&recipient)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !recipients.insert(recipient)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PROFILE: &str = "00000000-0000-4000-8000-000000000002";

    #[test]
    fn rejects_duplicate_members_before_value_projection() {
        for raw in [
            r#"{"organization_id":"other","organization_id":"org-a"}"#,
            r#"{"authority":{"revision":"old","rev\u0069sion":"new"}}"#,
            r#"{"authority":{"registration":{"public_jwk":{"x":"first","\u0078":"last"}}}}"#,
            r#"{"recipients":[{"uri":1,"uri":2}]}"#,
        ] {
            assert!(decode(raw.as_bytes()).is_err());
        }
        assert!(decode(br#"{"a":[1,true,null,{"x":"ok"}]}"#).is_ok());
    }

    fn snapshot(now: DateTime<Utc>) -> Value {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../trust-profile/tests/fixtures/registered-verifier-source.json"
        ))
        .unwrap();
        let mut registration = fixture["registered_verifier"].clone();
        registration["valid_from"] = json!(now - ChronoDuration::seconds(60));
        registration["valid_until"] = json!(now + ChronoDuration::seconds(120));
        json!({
            "contract":"marty.wallet/verifier-authority/v1",
            "organization_id":"org-a", "trust_profile_id":PROFILE,
            "observed_at":now,"expires_at":now + ChronoDuration::seconds(60),
            "authority":{
                "authority_id":format!("{PROFILE}/00000000-0000-4000-8000-000000000001"),
                "revision":"owner-revision", "key_purpose":"oid4vp_request_signing",
                "algorithm":"ES256", "request_clock_skew_seconds":30,
                "max_request_lifetime_seconds":900,"registration":registration
            }
        })
    }

    #[test]
    fn rejects_unmanaged_transport_and_header_injection() {
        let token = "dedicated-service-token-at-least-32-bytes";
        for origin in [
            "http://owner.example",
            "https://user@owner.example",
            "https://owner.example/path",
            "https://owner.example/?redirect=1",
        ] {
            assert!(WalletVerifierTrustClient::new(origin, token, None).is_err());
        }
        assert!(WalletVerifierTrustClient::new(
            "https://owner.example",
            &format!("{token}\r\nx-secret: injected"),
            None
        )
        .is_err());
        assert!(
            WalletVerifierTrustClient::new("https://owner.example", token, Some(b"not a CA"))
                .is_err()
        );
        assert!(WalletVerifierTrustClient::new("https://owner.example", token, None).is_ok());
    }

    #[test]
    fn rejects_scope_key_policy_recipient_and_freshness_substitutions() {
        let now = DateTime::from_timestamp(1_795_000_000, 0).unwrap();
        let valid = snapshot(now);
        assert!(validate(&valid, PROFILE, "org-a", Some("registered-client"), now).is_ok());
        assert!(validate(&valid, PROFILE, "org-b", Some("registered-client"), now).is_err());
        assert!(validate(&valid, PROFILE, "org-a", Some("other-client"), now).is_err());
        assert!(validate(
            &valid,
            PROFILE,
            "org-a",
            Some("registered-client"),
            now + ChronoDuration::seconds(60)
        )
        .is_err());
        for (pointer, replacement) in [
            ("/authority/key_purpose", json!("credential_issuer")),
            ("/authority/request_clock_skew_seconds", json!(300)),
            ("/authority/max_request_lifetime_seconds", json!(901)),
            ("/authority/authority_id", json!("other-profile/source")),
            (
                "/authority/registration/response_uris",
                json!(["http://verifier.example/response"]),
            ),
            (
                "/authority/registration/response_uris",
                json!([
                    "https://verifier.example/response",
                    "https://verifier.example/response"
                ]),
            ),
            ("/authority/registration/public_jwk/x", json!("invalid")),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate(&changed, PROFILE, "org-a", Some("registered-client"), now).is_err(),
                "{pointer}"
            );
        }
        let mut private = valid.clone();
        private["authority"]["registration"]["public_jwk"]["d"] = json!("forbidden");
        assert!(validate(&private, PROFILE, "org-a", Some("registered-client"), now).is_err());
        let mut unknown = valid.clone();
        unknown["fallback_authority"] = json!({});
        assert!(validate(&unknown, PROFILE, "org-a", Some("registered-client"), now).is_err());
    }

    #[test]
    fn admission_has_no_authority_and_cannot_be_used_as_key_projection() {
        let now = DateTime::from_timestamp(1_795_000_000, 0).unwrap();
        let admission = json!({"contract":"marty.wallet/verifier-profile-admission/v1",
            "organization_id":"org-a","trust_profile_id":PROFILE,
            "observed_at":now,"expires_at":now + ChronoDuration::seconds(60)});
        assert!(validate(&admission, PROFILE, "org-a", None, now).is_ok());
        assert!(validate(&admission, PROFILE, "org-a", Some("registered-client"), now).is_err());
        let mut null_authority = admission;
        null_authority["authority"] = Value::Null;
        assert!(validate(&null_authority, PROFILE, "org-a", None, now).is_err());
    }
}
