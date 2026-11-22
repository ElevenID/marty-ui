use std::{cell::Cell, fmt};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::de::{DeserializeSeed, Error, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{ReceiptVerificationError as Failure, Result};

pub(crate) fn read(bytes: &[u8], maximum: usize) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Failure::InvalidWire);
    }
    let remaining = Cell::new(8192);
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Json {
        remaining: &remaining,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| Failure::InvalidWire)?;
    decoder.end().map_err(|_| Failure::InvalidWire)?;
    if !value.is_object() {
        return Err(Failure::InvalidWire);
    }
    Ok(value)
}

struct Json<'a> {
    remaining: &'a Cell<usize>,
    depth: usize,
}
impl Json<'_> {
    fn count<E: Error>(&self) -> std::result::Result<(), E> {
        if self.depth > 24 || self.remaining.get() == 0 {
            return Err(E::custom("receipt JSON limit"));
        }
        self.remaining.set(self.remaining.get() - 1);
        Ok(())
    }
}
impl<'de> DeserializeSeed<'de> for Json<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<Value, D::Error> {
        self.count()?;
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Json<'_> {
    type Value = Value;
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("strict delegated receipt JSON")
    }
    fn visit_str<E: Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_u64<E: Error>(self, value: u64) -> std::result::Result<Value, E> {
        if value > 9_007_199_254_740_991 {
            return Err(E::custom("unsafe receipt integer"));
        }
        Ok(Value::from(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> std::result::Result<Value, E> {
        if value < 0 {
            return Err(E::custom("negative receipt integer"));
        }
        self.visit_u64(value as u64)
    }
    // No v1 receipt/JWK field permits floats, null, arrays or booleans. The
    // visitor's default methods reject these instead of losing their spelling.
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> std::result::Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(name) = input.next_key::<String>()? {
            self.count()?;
            // Workspace feature unification can enable arbitrary_precision.
            // Reject its numeric escape representation as well as actual keys.
            if name == "$serde_json::private::Number" || map.contains_key(&name) {
                return Err(A::Error::custom("duplicate or unsupported receipt member"));
            }
            let value = input.next_value_seed(Json {
                remaining: self.remaining,
                depth: self.depth + 1,
            })?;
            map.insert(name, value);
        }
        Ok(Value::Object(map))
    }
}

pub(crate) fn segment(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(Failure::InvalidWire);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Failure::InvalidWire)?;
    if bytes.is_empty() || bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Failure::InvalidWire);
    }
    Ok(bytes)
}

pub(crate) fn canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.to_string() == value).then_some(parsed)
}
pub(crate) fn deserialize_uuid<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Uuid, D::Error> {
    canonical_uuid(&String::deserialize(decoder)?)
        .ok_or_else(|| D::Error::custom("noncanonical receipt UUID"))
}

pub(crate) fn instant(value: DateTime<Utc>) -> bool {
    value.timestamp() > 0
        && (1970..=9999).contains(&value.year())
        && value.nanosecond() < 1_000_000_000
}
pub(crate) fn deserialize_time<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<DateTime<Utc>, D::Error> {
    let value = String::deserialize(decoder)?;
    let b = value.as_bytes();
    let shape = value.is_ascii()
        && (b.len() == 20 || (22..=30).contains(&b.len()))
        && b.get(4) == Some(&b'-')
        && b.get(7) == Some(&b'-')
        && b.get(10) == Some(&b'T')
        && b.get(13) == Some(&b':')
        && b.get(16) == Some(&b':')
        && b.last() == Some(&b'Z')
        && [
            &b[..4.min(b.len())],
            b.get(5..7).unwrap_or(&[]),
            b.get(8..10).unwrap_or(&[]),
            b.get(11..13).unwrap_or(&[]),
            b.get(14..16).unwrap_or(&[]),
            b.get(17..19).unwrap_or(&[]),
        ]
        .iter()
        .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
        && (b.len() == 20
            || (b.get(19) == Some(&b'.') && b[20..b.len() - 1].iter().all(u8::is_ascii_digit)));
    if !shape {
        return Err(D::Error::custom("invalid receipt timestamp"));
    }
    let parsed = DateTime::parse_from_rfc3339(&value)
        .map_err(|_| D::Error::custom("invalid receipt timestamp"))?
        .with_timezone(&Utc);
    if !instant(parsed) {
        return Err(D::Error::custom("invalid receipt timestamp"));
    }
    Ok(parsed)
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn challenge(value: &str) -> bool {
    (22..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An identifier shape check only; the original spelling is never normalized.
pub(crate) fn uri(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()+,;=%".contains(&b))
        || value.bytes().filter(|b| *b == b'#').count() > 1
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
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return false;
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return false;
        }
    }
    let authority = rest
        .strip_prefix("//")
        .map(|rest| rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len())));
    if authority.is_some_and(|(authority, _)| authority.bytes().filter(|b| *b == b'@').count() > 1)
    {
        return false;
    }
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        let Some((authority, _)) = authority else {
            return false;
        };
        let host_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if host_port.is_empty() || host_port.starts_with(':') {
            return false;
        }
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if value.bytes().any(|b| matches!(b, b'[' | b']')) {
        let Some((authority, suffix)) = authority else {
            return false;
        };
        if suffix.bytes().any(|b| matches!(b, b'[' | b']')) {
            return false;
        }
        let host_port = if let Some((userinfo, host_port)) = authority.rsplit_once('@') {
            if userinfo.bytes().any(|b| matches!(b, b'[' | b']' | b'@')) {
                return false;
            }
            host_port
        } else {
            authority
        };
        let Some(literal) = host_port.strip_prefix('[') else {
            return false;
        };
        let Some((address, port)) = literal.split_once(']') else {
            return false;
        };
        if address.parse::<std::net::Ipv6Addr>().is_err()
            || !matches!(parsed.host(), Some(url::Host::Ipv6(_)))
            || !(port.is_empty()
                || port
                    .strip_prefix(':')
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())))
        {
            return false;
        }
    }
    true
}
