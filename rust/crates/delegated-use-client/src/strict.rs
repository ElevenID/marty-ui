use std::fmt;

use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use serde::{
    de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{ClientError, Result};

pub(crate) const MAX_REVISION: u64 = 9_007_199_254_740_991;

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

// Syntax only; callers must separately verify signatures and complete claims.
pub(crate) fn compact_jws(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
    }) && parts.next().is_none()
}

pub(crate) fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}

pub(crate) fn deserialize_uuid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Uuid, D::Error> {
    let value = String::deserialize(deserializer)?;
    canonical_uuid(&value).ok_or_else(|| D::Error::custom("invalid canonical UUID"))
}

pub(crate) fn deserialize_time<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<DateTime<Utc>, D::Error> {
    let value = String::deserialize(deserializer)?;
    let time = DateTime::parse_from_rfc3339(&value)
        .map_err(|_| D::Error::custom("invalid canonical timestamp"))?
        .with_timezone(&Utc);
    if !(1..=9999).contains(&time.year())
        || time.timestamp_subsec_nanos() >= 1_000_000_000
        || time.to_rfc3339_opts(SecondsFormat::AutoSi, true) != value
    {
        return Err(D::Error::custom("invalid canonical timestamp"));
    }
    Ok(time)
}

// These are opaque operation identifiers. This function never follows a URI.
pub(crate) fn valid_uri(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()+,;=%".contains(&byte))
        || value.bytes().filter(|byte| *byte == b'#').count() > 1
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
    {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
    }) {
        return false;
    }
    let authority = rest.strip_prefix("//").map(|rest| {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        rest.split_at(end)
    });
    if authority.is_some_and(|(host, _)| host.bytes().filter(|byte| *byte == b'@').count() > 1) {
        return false;
    }
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        let Some((host, _)) = authority else {
            return false;
        };
        let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
        if host.is_empty() || host.starts_with(':') {
            return false;
        }
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if value.bytes().any(|byte| matches!(byte, b'[' | b']')) {
        let Some((host, suffix)) = authority else {
            return false;
        };
        if suffix.bytes().any(|byte| matches!(byte, b'[' | b']')) {
            return false;
        }
        let host = if let Some((user, host)) = host.rsplit_once('@') {
            if user.bytes().any(|byte| matches!(byte, b'[' | b']' | b'@')) {
                return false;
            }
            host
        } else {
            host
        };
        let Some((address, port)) = host.strip_prefix('[').and_then(|host| host.split_once(']'))
        else {
            return false;
        };
        if address.parse::<std::net::Ipv6Addr>().is_err()
            || !matches!(parsed.host(), Some(url::Host::Ipv6(_)))
            || !(port.is_empty()
                || port
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit())))
        {
            return false;
        }
    }
    true
}

/// Canonicalization only for this closed command schema, whose sole numeric
/// field is a nonnegative JSON-safe grant revision. No arbitrary JSON API.
pub(crate) fn canonical_command(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            let mut result = vec![b'{'];
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    result.push(b',');
                }
                result.extend(serde_json::to_vec(key).map_err(|_| ClientError::InvalidCommand)?);
                result.push(b':');
                result.extend(canonical_command(&map[key])?);
            }
            result.push(b'}');
            Ok(result)
        }
        Value::String(_) => serde_json::to_vec(value).map_err(|_| ClientError::InvalidCommand),
        Value::Number(number) => number
            .as_u64()
            .filter(|value| *value <= MAX_REVISION)
            .map(|value| value.to_string().into_bytes())
            .ok_or(ClientError::InvalidCommand),
        _ => Err(ClientError::InvalidCommand),
    }
}

pub(crate) fn json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let strict: UniqueJson =
        serde_json::from_slice(bytes).map_err(|_| ClientError::InvalidResponse)?;
    serde_json::from_value(strict.0).map_err(|_| ClientError::InvalidResponse)
}

struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded JSON with unique fields and integer numbers")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(value)))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(value)))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(value)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom("duplicate JSON field"));
                    }
                    let UniqueJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
