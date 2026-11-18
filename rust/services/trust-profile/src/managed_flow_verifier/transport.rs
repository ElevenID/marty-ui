//! Fixed operator-selected HTTPS owner. Request locators never select a host.
use super::{invalid, FlowOwnerRequest};
use crate::TrustProfileApplicationError;
use reqwest::{header::HeaderValue, Client, Url};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct FlowOwnerClient {
    producer_id: String,
    origin: Url,
    token: HeaderValue,
    client: Client,
}

impl FlowOwnerClient {
    pub fn new(
        producer_id: &str,
        origin: &str,
        token: &str,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, TrustProfileApplicationError> {
        let origin = Url::parse(origin).map_err(|_| invalid())?;
        if producer_id.is_empty()
            || producer_id.len() > 128
            || !producer_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || origin.scheme() != "https"
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
            producer_id: producer_id.into(),
            origin,
            token,
            client: builder.build().map_err(|_| invalid())?,
        })
    }

    pub(crate) async fn fetch(
        &self,
        producer_id: &str,
        instance: &str,
    ) -> Result<FlowOwnerRequest, TrustProfileApplicationError> {
        let id = uuid::Uuid::parse_str(instance).map_err(|_| invalid())?;
        if producer_id != self.producer_id || id.is_nil() || id.to_string() != instance {
            return Err(invalid());
        }
        let url = self
            .origin
            .join(&format!("internal/v1/wallet-verifier-requests/{instance}"))
            .map_err(|_| invalid())?;
        let mut response = self
            .client
            .post(url)
            .header("x-service-token", self.token.clone())
            .send()
            .await
            .map_err(|_| invalid())?;
        if response.status() != reqwest::StatusCode::OK
            || response.headers().get_all("content-type").iter().count() != 1
            || response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split(';').next())
                .map(str::trim)
                != Some("application/json")
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if bytes.len().saturating_add(chunk.len()) > 65536 {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = serde_json::from_slice::<UniqueValue>(&bytes)
            .map_err(|_| invalid())?
            .0;
        crate::reject_private_custody_metadata(&value)?;
        serde_json::from_value(value).map_err(|_| invalid())
    }
}

// Decode names recursively before uniqueness checks, including the public JWK.
// Keep serde_json's ordinary nesting limit and require complete input.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<UniqueValue>()? {
                    values.push(v.0);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_https_transport_rejects_caller_hosts_and_ambiguous_recursive_json() {
        let token = "s".repeat(32);
        assert!(FlowOwnerClient::new("flow-primary", "https://flow.example", &token, None).is_ok());
        for origin in [
            "http://flow.example",
            "https://u:p@flow.example",
            "https://flow.example/path",
            "https://flow.example?next=evil",
            "https://flow.example#evil",
        ] {
            assert!(FlowOwnerClient::new("flow-primary", origin, &token, None).is_err());
        }
        assert!(FlowOwnerClient::new(
            "https://caller.example",
            "https://flow.example",
            &token,
            None
        )
        .is_err());
        assert!(
            FlowOwnerClient::new("flow-primary", "https://flow.example", "short", None).is_err()
        );
        assert!(FlowOwnerClient::new(
            "flow-primary",
            "https://flow.example",
            &token,
            Some(b"not a certificate")
        )
        .is_err());
        for bytes in [
            br#"{"a":1,"\u0061":2}"#.as_slice(),
            br#"{"outer":[{"key":1,"k\u0065y":2}]}"#.as_slice(),
            b"{} trailing".as_slice(),
        ] {
            assert!(serde_json::from_slice::<UniqueValue>(bytes).is_err());
        }
        assert!(
            serde_json::from_slice::<UniqueValue>(br#"{"outer":[{"key":1},null,true,1.5]}"#)
                .is_ok()
        );
    }
}
