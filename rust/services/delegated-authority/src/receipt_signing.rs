//! Explicitly selected, purpose-bound remote custody for delegated receipts.
//!
//! A receipt key is pinned by trusted deployment configuration. Resolver output
//! cannot replace that pin. The dedicated remote signing grant is consumed by
//! Signing Keys before KMS use; every returned signature is verified locally.
//! This adapter does not authenticate a caller, authorize an evaluation, or
//! expose a delegated-use route.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use marty_signing_grant::{
    delegated_decision::{self, ReceiptSigningInput},
    minter::{GrantMinter, GrantMinting},
    GrantBinding, SigningOrigin, HEADER_NAME,
};
use p256::ecdsa::{signature::Verifier, Signature};
use serde::{de, Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    DelegatedDecisionReceiptSigner, DelegatedReceiptSigningError, DelegatedReceiptSigningKey,
    DelegatedReceiptSigningRequest, Principal, DELEGATED_DECISION_JWS_PURPOSE,
};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
type Error = DelegatedReceiptSigningError;
type VerifyingKey = ecdsa_core::VerifyingKey<p256::NistP256>;

/// Public key and exact managed identity chosen independently of receipt input.
/// No private key is accepted, stored or used by this type.
#[derive(Clone)]
pub struct ManagedDelegatedReceiptKey {
    organization_id: Uuid,
    issuer: Principal,
    algorithm: String,
    key_id: String,
    key_reference: String,
    public_jwk: Value,
    verifying_key: PublicKey,
}

impl ManagedDelegatedReceiptKey {
    pub fn new(
        organization_id: Uuid,
        issuer: Principal,
        algorithm: String,
        key_id: String,
        key_reference: String,
        public_jwk: Value,
    ) -> Result<Self, Error> {
        if organization_id.is_nil()
            || !issuer.id.starts_with("did:")
            || issuer.id.len() > 500
            || !crate::domain::valid_uri(Some(&issuer.id))
            || !matches!(algorithm.as_str(), "ES256" | "EdDSA")
            || key_id.len() > 512
            || key_id
                .strip_prefix(&issuer.id)
                .is_none_or(|tail| !tail.starts_with('#') || tail.len() < 2)
            || !crate::domain::valid_uri(Some(&key_id))
            || !credential(&key_reference, 1, 512)
        {
            return Err(DelegatedReceiptSigningError);
        }
        let verifying_key = PublicKey::parse(&public_jwk, &algorithm, &key_id, false)?;
        Ok(Self {
            organization_id,
            issuer,
            algorithm,
            key_id,
            key_reference,
            public_jwk,
            verifying_key,
        })
    }
}

#[derive(Clone)]
enum PublicKey {
    Es256(VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}
impl PublicKey {
    fn parse(value: &Value, algorithm: &str, key_id: &str, metadata: bool) -> Result<Self, Error> {
        let map = value.as_object().ok_or(DelegatedReceiptSigningError)?;
        let fields: &[&str] = if algorithm == "ES256" {
            &["kty", "crv", "x", "y"]
        } else {
            &["kty", "crv", "x"]
        };
        if fields.iter().any(|name| !map.contains_key(*name))
            || map.keys().any(|name| {
                !(fields.contains(&name.as_str())
                    || metadata && ["kid", "alg", "use", "key_ops"].contains(&name.as_str()))
            })
            || value.get("kid").is_some_and(|v| v != key_id)
            || value.get("alg").is_some_and(|v| v != algorithm)
            || value.get("use").is_some_and(|v| v != "sig")
            || value
                .get("key_ops")
                .is_some_and(|v| v != &json!(["verify"]))
        {
            return Err(DelegatedReceiptSigningError);
        }
        let x: [u8; 32] = b64(value["x"].as_str().ok_or(DelegatedReceiptSigningError)?, 32)?
            .try_into()
            .map_err(|_| DelegatedReceiptSigningError)?;
        match algorithm {
            "ES256" if value["kty"] == "EC" && value["crv"] == "P-256" => {
                let y = b64(value["y"].as_str().ok_or(DelegatedReceiptSigningError)?, 32)?;
                if y.len() != 32 {
                    return Err(DelegatedReceiptSigningError);
                }
                let mut point = [0; 65];
                point[0] = 4;
                point[1..33].copy_from_slice(&x);
                point[33..].copy_from_slice(&y);
                Ok(Self::Es256(
                    VerifyingKey::from_sec1_bytes(&point)
                        .map_err(|_| DelegatedReceiptSigningError)?,
                ))
            }
            "EdDSA" if value["kty"] == "OKP" && value["crv"] == "Ed25519" => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(&x)
                    .map_err(|_| DelegatedReceiptSigningError)?;
                if key.is_weak() || key.to_edwards().compress().to_bytes() != x {
                    return Err(DelegatedReceiptSigningError);
                }
                Ok(Self::Ed25519(key))
            }
            _ => Err(DelegatedReceiptSigningError),
        }
    }

    fn same_key(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Es256(a), Self::Es256(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Self::Ed25519(a), Self::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            _ => false,
        }
    }

    fn verify_response(&self, input: &[u8], response: &Value) -> Result<Vec<u8>, Error> {
        let encoded = response["signature_b64"]
            .as_str()
            .ok_or(DelegatedReceiptSigningError)?;
        let signature = b64(encoded, 128)?;
        match self {
            Self::Es256(key) => {
                let signature = match response["signature_encoding"].as_str() {
                    Some("der") => {
                        let parsed = Signature::from_der(&signature)
                            .map_err(|_| DelegatedReceiptSigningError)?;
                        let raw = b64(
                            response["signature_raw_b64"]
                                .as_str()
                                .ok_or(DelegatedReceiptSigningError)?,
                            64,
                        )?;
                        if raw.as_slice() != parsed.to_bytes().as_slice() {
                            return Err(DelegatedReceiptSigningError);
                        }
                        parsed
                    }
                    Some("raw_ieee_p1363") => Signature::from_slice(&signature)
                        .map_err(|_| DelegatedReceiptSigningError)?,
                    _ => return Err(DelegatedReceiptSigningError),
                };
                let normalized = signature.normalize_s();
                key.verify(input, &normalized)
                    .map_err(|_| DelegatedReceiptSigningError)?;
                Ok(normalized.to_bytes().to_vec())
            }
            Self::Ed25519(key) => {
                if response["signature_encoding"] != "raw"
                    || response.get("signature_raw_b64").is_some()
                {
                    return Err(DelegatedReceiptSigningError);
                }
                let parsed = ed25519_dalek::Signature::from_slice(&signature)
                    .map_err(|_| DelegatedReceiptSigningError)?;
                key.verify_strict(input, &parsed)
                    .map_err(|_| DelegatedReceiptSigningError)?;
                Ok(signature)
            }
        }
    }
}

/// Uses the existing authenticated Signing Keys issuer resolver and KMS-only
/// signing kernel, with a separate DelegatedDecision signing-grant origin.
#[derive(Clone)]
pub struct HttpManagedDelegatedReceiptSigner {
    client: reqwest::Client,
    base_url: reqwest::Url,
    read_credential: String,
    sign_credential: String,
    key: ManagedDelegatedReceiptKey,
    minter: Arc<dyn GrantMinting>,
}

impl HttpManagedDelegatedReceiptSigner {
    pub fn new(
        signing_keys_origin: &str,
        read_credential: String,
        sign_credential: String,
        key: ManagedDelegatedReceiptKey,
        minter: GrantMinter,
    ) -> Result<Self, Error> {
        Self::build(
            signing_keys_origin,
            read_credential,
            sign_credential,
            key,
            Arc::new(minter),
            false,
        )
    }

    fn build(
        origin: &str,
        read_credential: String,
        sign_credential: String,
        key: ManagedDelegatedReceiptKey,
        minter: Arc<dyn GrantMinting>,
        test_loopback: bool,
    ) -> Result<Self, Error> {
        let base_url = reqwest::Url::parse(origin).map_err(|_| DelegatedReceiptSigningError)?;
        let scheme_ok = base_url.scheme() == "https"
            || (test_loopback
                && base_url.scheme() == "http"
                && matches!(
                    base_url.host_str(),
                    Some("127.0.0.1" | "[::1]" | "localhost")
                ));
        if !scheme_ok
            || base_url.host_str().is_none()
            || base_url.path() != "/"
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !credential(&read_credential, 32, 1024)
            || !credential(&sign_credential, 32, 1024)
            || read_credential == sign_credential
        {
            return Err(DelegatedReceiptSigningError);
        }
        let client = reqwest::Client::builder()
            .connect_timeout(HTTP_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(|_| DelegatedReceiptSigningError)?;
        Ok(Self {
            client,
            base_url,
            read_credential,
            sign_credential,
            key,
            minter,
        })
    }

    async fn post(
        &self,
        path: &str,
        credential: &str,
        body: Value,
        grant: Option<&str>,
    ) -> Result<Value, Error> {
        let mut request = self
            .client
            .post(
                self.base_url
                    .join(path)
                    .map_err(|_| DelegatedReceiptSigningError)?,
            )
            .header("x-api-key", credential)
            .header("Cache-Control", "no-store")
            .json(&body);
        if let Some(grant) = grant {
            request = request.header(HEADER_NAME, grant);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| DelegatedReceiptSigningError)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(DelegatedReceiptSigningError);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DelegatedReceiptSigningError)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(DelegatedReceiptSigningError);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<UniqueValue>(&bytes)
            .map(|v| v.0)
            .map_err(|_| DelegatedReceiptSigningError)
    }

    fn public_key_matches(&self, value: &Value) -> bool {
        PublicKey::parse(value, &self.key.algorithm, &self.key.key_id, true)
            .is_ok_and(|key| self.key.verifying_key.same_key(&key))
    }

    async fn current_key(&self) -> Result<(), Error> {
        let key = &self.key;
        let value = self
            .post(
                "internal/compat/resolve-issuer-did",
                &self.read_credential,
                json!({
                    "organization_id": key.organization_id,
                    "issuer_did": key.issuer.id,
                    "verification_method_id": key.key_id,
                    "key_purpose": delegated_decision::KEY_PURPOSE,
                    "credential_format": delegated_decision::PROFILE_FORMAT,
                    "algorithm": key.algorithm,
                }),
                None,
            )
            .await?;
        let profile = &value["issuer_profile"];
        if value["ok"] != true
            || value["organization_id"] != key.organization_id.to_string()
            || value["issuer_did"] != key.issuer.id
            || value["verification_method_id"] != key.key_id
            || value["signing_key_reference"] != key.key_reference
            || value["algorithm"] != key.algorithm
            || value["key_purpose"] != delegated_decision::KEY_PURPOSE
            || !self.public_key_matches(&value["public_jwk"])
            || profile["organization_id"] != key.organization_id.to_string()
            || profile["issuer_did"] != key.issuer.id
            || profile["status"] != "active"
            || profile["key_purpose"] != delegated_decision::KEY_PURPOSE
            || profile["credential_format"] != delegated_decision::PROFILE_FORMAT
            || profile["algorithm"] != key.algorithm
            || profile["signing_key_reference"] != key.key_reference
            || profile["verification_method_id"] != key.key_id
            || value["resolver"]["public_fallback_used"] != false
            || value["resolver"]["type"] != "organization_issuer_profile"
            || value["resolver"]["source"] != "gateway_signing_key_registry"
        {
            return Err(DelegatedReceiptSigningError);
        }
        Ok(())
    }
}

#[async_trait]
impl DelegatedDecisionReceiptSigner for HttpManagedDelegatedReceiptSigner {
    async fn resolve_key(
        &self,
        organization_id: Uuid,
        issuer: &Principal,
        purpose: &'static str,
    ) -> Result<DelegatedReceiptSigningKey, Error> {
        if organization_id != self.key.organization_id
            || issuer != &self.key.issuer
            || purpose != DELEGATED_DECISION_JWS_PURPOSE
        {
            return Err(DelegatedReceiptSigningError);
        }
        self.current_key().await?;
        Ok(DelegatedReceiptSigningKey {
            issuer: self.key.issuer.clone(),
            purpose: purpose.into(),
            key_id: self.key.key_id.clone(),
            algorithm: self.key.algorithm.clone(),
        })
    }

    async fn sign(&self, request: DelegatedReceiptSigningRequest) -> Result<Vec<u8>, Error> {
        let key = &self.key;
        let input = ReceiptSigningInput::decode(&request.signing_input)
            .map_err(|_| DelegatedReceiptSigningError)?;
        if request.organization_id != key.organization_id
            || request.key.issuer != key.issuer
            || request.key.purpose != DELEGATED_DECISION_JWS_PURPOSE
            || request.key.key_id != key.key_id
            || request.key.algorithm != key.algorithm
            || input.organization_id() != key.organization_id.to_string()
            || input.issuer()
                != &serde_json::to_value(&key.issuer).map_err(|_| DelegatedReceiptSigningError)?
            || input.algorithm() != key.algorithm
            || input.key_id() != key.key_id
            || !input.is_live_at(Utc::now())
        {
            return Err(DelegatedReceiptSigningError);
        }
        // Re-resolve after receipt preparation; rotation/revocation cannot be
        // hidden behind the earlier resolved header. Signing Keys repeats this.
        self.current_key().await?;
        if !input.is_live_at(Utc::now()) {
            return Err(DelegatedReceiptSigningError);
        }
        let org = key.organization_id.to_string();
        let binding = GrantBinding {
            origin: SigningOrigin::DelegatedDecision,
            operation_id: input.receipt_id(),
            organization_id: &org,
            route: delegated_decision::SIGN_ROUTE,
            service_id: None,
            issuer_did: Some(&key.issuer.id),
            key_reference: Some(&key.key_reference),
            key_purpose: delegated_decision::KEY_PURPOSE,
            algorithm: &key.algorithm,
            payload: &request.signing_input,
        };
        let grant = self
            .minter
            .mint(&binding)
            .await
            .map_err(|_| DelegatedReceiptSigningError)?;
        // Contract-test minters and external implementations cannot silently
        // substitute a different origin/tenant/key/payload envelope.
        marty_signing_grant::bound_input(&grant.claims, &binding, Utc::now().timestamp())
            .map_err(|_| DelegatedReceiptSigningError)?;
        let grant = grant
            .to_header_value()
            .map_err(|_| DelegatedReceiptSigningError)?;
        if !input.is_live_at(Utc::now()) {
            return Err(DelegatedReceiptSigningError);
        }
        let response = self.post("internal/compat/issuer-dids/sign", &self.sign_credential, json!({
            "organization_id": org, "issuer_did": key.issuer.id, "credential_format": delegated_decision::PROFILE_FORMAT,
            "key_purpose": delegated_decision::KEY_PURPOSE, "algorithm": key.algorithm, "key_reference": key.key_reference,
            "verification_method_id": key.key_id, "expected_public_jwk": key.public_jwk,
            "payload_b64": URL_SAFE_NO_PAD.encode(&request.signing_input),
        }), Some(&grant)).await?;
        if response["ok"] != true
            || response["issuer_did"] != key.issuer.id
            || response["verification_method_id"] != key.key_id
            || response["algorithm"] != key.algorithm
            || response["payload_length"].as_u64() != Some(request.signing_input.len() as u64)
            || !self.public_key_matches(&response["public_jwk"])
            || !input.is_live_at(Utc::now())
        {
            return Err(DelegatedReceiptSigningError);
        }
        key.verifying_key
            .verify_response(&request.signing_input, &response)
    }
}

fn credential(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn b64(value: &str, max: usize) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DelegatedReceiptSigningError)?;
    if bytes.is_empty() || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(DelegatedReceiptSigningError);
    }
    Ok(bytes)
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique JSON fields")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<UniqueValue>()? {
                    out.push(v.0);
                }
                Ok(UniqueValue(Value::Array(out)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = a.next_entry::<String, UniqueValue>()? {
                    if map.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate member"));
                    }
                }
                Ok(UniqueValue(Value::Object(map)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
#[path = "receipt_signing_tests.rs"]
mod tests;
