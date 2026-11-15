// SPDX-License-Identifier: AGPL-3.0-only
//! Strict external-observation decoding. This module grants no authority.
//!
//! Authenticate at the Common Gateway before calling this decoder. The eventual
//! HTTP adapter must also enforce MAX_BODY_BYTES while reading the body, not
//! merely after allocating it. No route is registered by this module.

use std::{collections::BTreeMap, fmt};

use http::HeaderMap;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use crate::external_observation_admission::{Observation, Scalar, MAX_SAFE_INTEGER};

pub const MAX_BODY_BYTES: usize = 65_536;
const MAX_CLAIMS: usize = 32;
const MAX_TEXT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    BodyTooLarge,
    InvalidHeaders,
    UnsupportedMediaType,
    UnsupportedEncoding,
    InvalidEnvelope,
    InvalidIdempotencyKey,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include a parser error, field name, body, key, URL or claim.
        formatter.write_str(match self {
            Self::BodyTooLarge => "Observation body exceeds the size limit",
            Self::InvalidHeaders => "Invalid observation request headers",
            Self::UnsupportedMediaType => "Observation requires application/json",
            Self::UnsupportedEncoding => "Encoded observation bodies are unsupported",
            Self::InvalidEnvelope => "Invalid observation envelope",
            Self::InvalidIdempotencyKey => "Invalid observation idempotency key",
        })
    }
}
impl std::error::Error for WireError {}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

fn claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, WireError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(WireError::InvalidHeaders);
    }
    first
        .map(|value| value.to_str().map_err(|_| WireError::InvalidHeaders))
        .transpose()
}

fn check_headers(headers: &HeaderMap, size: usize) -> Result<&str, WireError> {
    let content_type = one_header(headers, "content-type")?
        .ok_or(WireError::UnsupportedMediaType)?;
    if content_type.len() > 128 {
        return Err(WireError::UnsupportedMediaType);
    }
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|part| part.eq_ignore_ascii_case("application/json"))
    {
        return Err(WireError::UnsupportedMediaType);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter
            .split_once('=')
            .ok_or(WireError::UnsupportedMediaType)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !matches!(value.trim().to_ascii_lowercase().as_str(), "utf-8" | "\"utf-8\"")
            || parts.next().is_some()
        {
            return Err(WireError::UnsupportedMediaType);
        }
    }
    if one_header(headers, "content-encoding")?
        .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(WireError::UnsupportedEncoding);
    }
    let length = one_header(headers, "content-length")?;
    let transfer = one_header(headers, "transfer-encoding")?;
    if headers.contains_key("trailer")
        || (length.is_some() && transfer.is_some())
        || transfer.is_some_and(|value| !value.trim().eq_ignore_ascii_case("chunked"))
    {
        return Err(WireError::InvalidHeaders);
    }
    if let Some(length) = length {
        if length.is_empty()
            || length.len() > 20
            || !length.bytes().all(|byte| byte.is_ascii_digit())
            || length.parse::<usize>().ok() != Some(size)
        {
            return Err(WireError::InvalidHeaders);
        }
    }
    let key = one_header(headers, "idempotency-key")?
        .ok_or(WireError::InvalidIdempotencyKey)?;
    if !identifier(key) {
        return Err(WireError::InvalidIdempotencyKey);
    }
    Ok(key)
}

/// Decode the original bytes, never a pre-parsed serde_json::Value: Value would
/// already have discarded duplicate object members. Header/body tenant and
/// identity assertions are never used to construct an authenticated principal.
pub fn decode_submission(headers: &HeaderMap, body: &[u8]) -> Result<Observation, WireError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(WireError::BodyTooLarge);
    }
    let key = check_headers(headers, body.len())?;
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let envelope = Envelope::deserialize(&mut decoder).map_err(|_| WireError::InvalidEnvelope)?;
    decoder.end().map_err(|_| WireError::InvalidEnvelope)?;
    let observation = envelope.0;
    if !identifier(&observation.binding_id)
        || !identifier(&observation.observation_id)
        || [
            observation.binding_revision,
            observation.sequence,
            observation.observed_at_ms,
            observation.effective_at_ms,
        ]
        .iter()
        .any(|value| !(1..=MAX_SAFE_INTEGER).contains(value))
        || observation.effective_at_ms > observation.observed_at_ms
    {
        return Err(WireError::InvalidEnvelope);
    }
    if key != observation.observation_id {
        return Err(WireError::InvalidIdempotencyKey);
    }
    Ok(observation)
}

struct Envelope(Observation);

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;
        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an observation object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Envelope, M::Error> {
                let mut binding_id = None;
                let mut binding_revision = None;
                let mut observation_id = None;
                let mut sequence = None;
                let mut observed_at_ms = None;
                let mut effective_at_ms = None;
                let mut claims = None;
                // The presence check precedes value parsing, including escaped
                // duplicates. Unknown fields are refused without descending.
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "binding_id" if binding_id.is_none() => binding_id = Some(map.next_value::<String>()?),
                        "binding_revision" if binding_revision.is_none() => binding_revision = Some(map.next_value::<u64>()?),
                        "observation_id" if observation_id.is_none() => observation_id = Some(map.next_value::<String>()?),
                        "sequence" if sequence.is_none() => sequence = Some(map.next_value::<u64>()?),
                        "observed_at_ms" if observed_at_ms.is_none() => observed_at_ms = Some(map.next_value::<u64>()?),
                        "effective_at_ms" if effective_at_ms.is_none() => effective_at_ms = Some(map.next_value::<u64>()?),
                        "claims" if claims.is_none() => claims = Some(map.next_value::<Claims>()?),
                        _ => return Err(de::Error::custom("duplicate or unknown field")),
                    }
                }
                Ok(Envelope(Observation {
                    binding_id: binding_id.ok_or_else(|| de::Error::custom("missing field"))?,
                    binding_revision: binding_revision.ok_or_else(|| de::Error::custom("missing field"))?,
                    observation_id: observation_id.ok_or_else(|| de::Error::custom("missing field"))?,
                    sequence: sequence.ok_or_else(|| de::Error::custom("missing field"))?,
                    observed_at_ms: observed_at_ms.ok_or_else(|| de::Error::custom("missing field"))?,
                    effective_at_ms: effective_at_ms.ok_or_else(|| de::Error::custom("missing field"))?,
                    claims: claims.ok_or_else(|| de::Error::custom("missing field"))?.0,
                }))
            }
        }
        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

struct Claims(BTreeMap<String, Scalar>);
impl<'de> Deserialize<'de> for Claims {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClaimsVisitor;
        impl<'de> Visitor<'de> for ClaimsVisitor {
            type Value = Claims;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded primitive claim object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Claims, M::Error> {
                let mut claims = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if claims.len() == MAX_CLAIMS || !claim_name(&name) || claims.contains_key(&name) {
                        return Err(de::Error::custom("invalid claim name or duplicate"));
                    }
                    claims.insert(name, map.next_value::<Primitive>()?.0);
                }
                if claims.is_empty() {
                    return Err(de::Error::custom("empty claims"));
                }
                Ok(Claims(claims))
            }
        }
        deserializer.deserialize_map(ClaimsVisitor)
    }
}

struct Primitive(Scalar);
impl<'de> Deserialize<'de> for Primitive {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The service enables arbitrary_precision. Deserialize raw JSON tokens,
        // not its synthetic Number map representation, which a real object
        // could otherwise mimic. Borrowing also bounds allocation by the body.
        let raw = <&RawValue>::deserialize(deserializer)?;
        let token = raw.get();
        let value = match token {
            "null" => Scalar::Null,
            "true" => Scalar::Boolean(true),
            "false" => Scalar::Boolean(false),
            _ if token.starts_with('"') => {
                let value: String = serde_json::from_str(token)
                    .map_err(|_| de::Error::custom("invalid text claim"))?;
                if value.is_empty()
                    || value.len() > MAX_TEXT_BYTES
                    || value.chars().any(char::is_control)
                {
                    return Err(de::Error::custom("invalid text claim"));
                }
                Scalar::Text(value)
            }
            _ if token.starts_with('-') || token.as_bytes().first().is_some_and(u8::is_ascii_digit) => {
                // Integer tokens are checked before any floating-point cast.
                // Decimal claims use the kernel's finite IEEE-754 model.
                if !token.contains(['.', 'e', 'E']) {
                    let integer = token.parse::<i64>()
                        .map_err(|_| de::Error::custom("unsafe integer claim"))?;
                    if integer.unsigned_abs() > MAX_SAFE_INTEGER {
                        return Err(de::Error::custom("unsafe integer claim"));
                    }
                    Scalar::Number(integer as f64)
                } else {
                    let number = token.parse::<f64>()
                        .map_err(|_| de::Error::custom("invalid numeric claim"))?;
                    let mantissa = token.split(['e', 'E']).next().unwrap_or_default();
                    if !number.is_finite()
                        || number.abs() > MAX_SAFE_INTEGER as f64
                        || (number == 0.0 && mantissa.bytes().any(|byte| (b'1'..=b'9').contains(&byte)))
                    {
                        return Err(de::Error::custom("invalid numeric claim"));
                    }
                    Scalar::Number(number)
                }
            }
            _ => return Err(de::Error::custom("claim must be primitive")),
        };
        Ok(Primitive(value))
    }
}

#[cfg(test)]
#[path = "external_observation_wire_tests.rs"]
mod tests;
