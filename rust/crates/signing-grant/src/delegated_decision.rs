//! Dedicated signing-grant boundary for delegated decision evidence.
//!
//! Shape and correspondence checks here constrain a signing origin. They do not
//! authenticate evidence, evaluate policy, or authorize a relying-domain action.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{GrantBinding, GrantError};

pub const KEY_PURPOSE: &str = "delegated_decision_signing";
pub const PROFILE_FORMAT: &str = "DELEGATED_DECISION_JWS";
pub const WIRE_FORMAT: &str = "mip-delegated-decision+jws";
pub const RECEIPT_PROFILE: &str = "urn:marty:delegated-decision-receipt:v1";
pub const EVALUATION_PROFILE: &str = "urn:marty:delegated-evaluation:v1";
pub const SIGN_ROUTE: &str = "/internal/compat/issuer-dids/sign";
pub const MAX_SIGNING_INPUT_BYTES: usize = 100_000;

/// Validated syntax only. This is not a verified receipt or an authorization.
pub struct ReceiptSigningInput {
    receipt_id: String,
    organization_id: String,
    issuer: Value,
    algorithm: String,
    key_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl ReceiptSigningInput {
    pub fn decode(input: &[u8]) -> Result<Self, GrantError> {
        if input.is_empty() || input.len() > MAX_SIGNING_INPUT_BYTES || !input.is_ascii() {
            return Err(GrantError::Malformed);
        }
        let input = std::str::from_utf8(input).map_err(|_| GrantError::Malformed)?;
        let mut parts = input.split('.');
        let header = read(&segment(parts.next().ok_or(GrantError::Malformed)?, 1024)?)?;
        let payload = read(&segment(
            parts.next().ok_or(GrantError::Malformed)?,
            75_000,
        )?)?;
        if parts.next().is_some() {
            return Err(GrantError::Malformed);
        }
        exact(&header, &["alg", "typ", "kid"], &[])?;
        exact(
            &payload,
            &[
                "profile",
                "id",
                "issuer",
                "decision",
                "evaluation",
                "policy",
                "issued_at",
                "expires_at",
            ],
            &[],
        )?;
        let algorithm = text(&header["alg"])?;
        let key_id = text(&header["kid"])?;
        let issuer = principal(&payload["issuer"])?;
        let issuer_id = text(&issuer["id"])?;
        if header["typ"] != WIRE_FORMAT
            || !matches!(algorithm, "ES256" | "EdDSA")
            || payload["profile"] != RECEIPT_PROFILE
            || !matches!(payload["decision"].as_str(), Some("PERMIT" | "DENY"))
            || !issuer_id.starts_with("did:")
            || key_id.len() > 512
            || key_id
                .strip_prefix(issuer_id)
                .is_none_or(|suffix| !suffix.starts_with('#') || suffix.len() < 2)
        {
            return Err(GrantError::Malformed);
        }
        uri(&header["kid"])?;
        let receipt_id = uuid(&payload["id"])?;
        let evaluated = &payload["evaluation"];
        exact(
            evaluated,
            &[
                "profile",
                "organization_id",
                "grant",
                "actor",
                "subject",
                "binding",
                "operation",
                "approval_evidence_ref",
                "authority_evidence_ref",
                "proof_evidence_ref",
                "challenge",
                "proof_verified_at",
                "proof_valid_until",
                "status",
                "evaluated_at",
            ],
            &["domain_evidence"],
        )?;
        if evaluated["profile"] != EVALUATION_PROFILE {
            return Err(GrantError::Malformed);
        }
        let organization_id = uuid(&evaluated["organization_id"])?;
        principal(&evaluated["actor"])?;
        principal(&evaluated["subject"])?;
        grant(&evaluated["grant"])?;
        operation(&evaluated["operation"])?;
        let binding = &evaluated["binding"];
        match binding["method"].as_str() {
            Some("KEY") => {
                exact(binding, &["method", "key_thumbprint"], &[])?;
                digest(&binding["key_thumbprint"])?;
            }
            Some("SESSION") => {
                exact(
                    binding,
                    &["method", "session_ref", "establishment_evidence_ref"],
                    &[],
                )?;
                uri(&binding["session_ref"])?;
                uri(&binding["establishment_evidence_ref"])?;
            }
            _ => return Err(GrantError::Malformed),
        }
        for name in [
            "approval_evidence_ref",
            "authority_evidence_ref",
            "proof_evidence_ref",
        ] {
            uri(&evaluated[name])?;
        }
        let challenge = text(&evaluated["challenge"])?;
        if !(22..=128).contains(&challenge.len())
            || !challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(GrantError::Malformed);
        }
        let status = &evaluated["status"];
        exact(
            status,
            &[
                "issuer",
                "grant",
                "state",
                "checked_at",
                "valid_until",
                "evidence_ref",
            ],
            &[],
        )?;
        principal(&status["issuer"])?;
        grant(&status["grant"])?;
        uri(&status["evidence_ref"])?;
        if status["grant"] != evaluated["grant"]
            || !matches!(
                status["state"].as_str(),
                Some("PENDING" | "ACTIVE" | "SUSPENDED" | "REVOKED" | "EXPIRED")
            )
            || (payload["decision"] == "PERMIT" && status["state"] != "ACTIVE")
        {
            return Err(GrantError::Malformed);
        }
        exact(&payload["policy"], &["id", "version_digest"], &[])?;
        uri(&payload["policy"]["id"])?;
        digest(&payload["policy"]["version_digest"])?;
        let issued_at = time(&payload["issued_at"])?;
        let expires_at = time(&payload["expires_at"])?;
        let evaluated_at = time(&evaluated["evaluated_at"])?;
        let proof_at = time(&evaluated["proof_verified_at"])?;
        let proof_until = time(&evaluated["proof_valid_until"])?;
        let status_at = time(&status["checked_at"])?;
        let status_until = time(&status["valid_until"])?;
        if proof_at > evaluated_at
            || status_at > evaluated_at
            || evaluated_at > issued_at
            || expires_at <= issued_at
            || expires_at > proof_until
            || expires_at > status_until
            || expires_at.signed_duration_since(issued_at) > chrono::Duration::seconds(600)
        {
            return Err(GrantError::Malformed);
        }
        if let Some(domain) = evaluated.get("domain_evidence") {
            exact(
                domain,
                &[
                    "evaluator",
                    "profile",
                    "document_digest",
                    "grant",
                    "operation",
                    "decision",
                    "checked_at",
                    "valid_until",
                    "evidence_ref",
                ],
                &[],
            )?;
            principal(&domain["evaluator"])?;
            uri(&domain["profile"])?;
            digest(&domain["document_digest"])?;
            uri(&domain["evidence_ref"])?;
            if domain["grant"] != evaluated["grant"]
                || domain["operation"] != evaluated["operation"]
                || !matches!(domain["decision"].as_str(), Some("PERMIT" | "DENY"))
                || (payload["decision"] == "PERMIT" && domain["decision"] != "PERMIT")
                || time(&domain["checked_at"])? > evaluated_at
                || expires_at > time(&domain["valid_until"])?
            {
                return Err(GrantError::Malformed);
            }
        }
        Ok(Self {
            receipt_id: receipt_id.into(),
            organization_id: organization_id.into(),
            issuer: issuer.clone(),
            algorithm: algorithm.into(),
            key_id: key_id.into(),
            issued_at,
            expires_at,
        })
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
    pub fn issuer(&self) -> &Value {
        &self.issuer
    }
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.issued_at <= now && now < self.expires_at
    }
}

pub(crate) fn validate_bound_input(binding: &GrantBinding<'_>, now: i64) -> Result<(), GrantError> {
    let input = ReceiptSigningInput::decode(binding.payload)?;
    if input.receipt_id() != binding.operation_id
        || input.organization_id() != binding.organization_id
        || input.issuer()["id"].as_str() != binding.issuer_did
        || input.algorithm() != binding.algorithm
    {
        return Err(GrantError::BindingMismatch);
    }
    // Signing-grant clocks have whole-second precision. Compare the issue
    // second here; the adapter checks the precise instant before and after each
    // remote operation, and retained finalization checks it again before commit.
    let now = DateTime::from_timestamp(now, 0).ok_or(GrantError::Expired)?;
    if now.timestamp() < input.issued_at.timestamp() || now >= input.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(())
}

fn exact(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), GrantError> {
    let map = value.as_object().ok_or(GrantError::Malformed)?;
    if required.iter().any(|name| !map.contains_key(*name))
        || map
            .keys()
            .any(|name| !required.contains(&name.as_str()) && !optional.contains(&name.as_str()))
    {
        return Err(GrantError::Malformed);
    }
    Ok(())
}
fn text(value: &Value) -> Result<&str, GrantError> {
    value.as_str().ok_or(GrantError::Malformed)
}
fn uuid(value: &Value) -> Result<&str, GrantError> {
    let s = text(value)?;
    let id = Uuid::parse_str(s).map_err(|_| GrantError::Malformed)?;
    if id.is_nil() || id.to_string() != s {
        return Err(GrantError::Malformed);
    }
    Ok(s)
}
fn uri(value: &Value) -> Result<(), GrantError> {
    let s = text(value)?;
    if s.is_empty()
        || s.len() > 1024
        || s.chars().any(|c| c.is_whitespace() || c.is_control())
        || reqwest::Url::parse(s).is_err()
    {
        return Err(GrantError::Malformed);
    }
    Ok(())
}
fn principal(value: &Value) -> Result<&Value, GrantError> {
    exact(value, &["type", "id"], &[])?;
    if !matches!(
        value["type"].as_str(),
        Some("USER" | "ORGANIZATION" | "SERVICE_ACCOUNT" | "MACHINE_IDENTITY" | "EXTERNAL")
    ) {
        return Err(GrantError::Malformed);
    }
    uri(&value["id"])?;
    Ok(value)
}
fn digest(value: &Value) -> Result<(), GrantError> {
    let s = text(value)?;
    if s.len() != 71
        || !s.starts_with("sha256:")
        || !s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(GrantError::Malformed);
    }
    Ok(())
}
fn grant(value: &Value) -> Result<(), GrantError> {
    exact(value, &["id", "revision", "terms_digest"], &[])?;
    uuid(&value["id"])?;
    if value["revision"]
        .as_u64()
        .is_none_or(|n| !(1..=9_007_199_254_740_991).contains(&n))
    {
        return Err(GrantError::Malformed);
    }
    digest(&value["terms_digest"])
}
fn operation(value: &Value) -> Result<(), GrantError> {
    exact(
        value,
        &[
            "action",
            "resource_id",
            "audience",
            "request_profile",
            "request_digest",
        ],
        &[],
    )?;
    for name in ["action", "resource_id", "audience", "request_profile"] {
        uri(&value[name])?;
    }
    digest(&value["request_digest"])
}
fn time(value: &Value) -> Result<DateTime<Utc>, GrantError> {
    let s = text(value)?;
    if !s.ends_with('Z') || !s.is_ascii() || s.len() > 40 {
        return Err(GrantError::Malformed);
    }
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|_| GrantError::Malformed)?
        .with_timezone(&Utc);
    if t.timestamp() <= 0 {
        return Err(GrantError::Malformed);
    }
    Ok(t)
}
fn segment(s: &str, max: usize) -> Result<Vec<u8>, GrantError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| GrantError::Malformed)?;
    if bytes.is_empty() || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != s {
        return Err(GrantError::Malformed);
    }
    Ok(bytes)
}
fn read(bytes: &[u8]) -> Result<Value, GrantError> {
    serde_json::from_slice::<UniqueValue>(bytes)
        .map(|v| v.0)
        .map_err(|_| GrantError::Malformed)
}
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("strict receipt JSON")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Self::Value, E> {
                if n > 9_007_199_254_740_991 {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(UniqueValue(Value::from(n)))
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Self::Value, E> {
                if n < 0 {
                    return Err(E::custom("negative integer"));
                }
                self.visit_u64(n as u64)
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
#[path = "delegated_decision_tests.rs"]
mod tests;
