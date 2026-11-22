//! Bounded decoding before DTO construction. Never report submitted values.

use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{BindingError, ErrorKind};

pub const MAX_DOCUMENT_BYTES: usize = 65_536;
const MAX_DEPTH: usize = 32;
const DUPLICATE_FIELD: &str = "duplicate JSON field";

struct StrictValue {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("JSON nesting limit exceeded"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate fields or fractional numbers")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Value, E> {
        Err(E::custom("fractional numbers are not supported"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValue {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = fields.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_FIELD));
            }
            let value = fields.next_value_seed(StrictValue {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn integer_lexemes(raw: &[u8]) -> bool {
    // serde_json's arbitrary_precision feature changes number visitor dispatch
    // into a synthetic map for fractions/exponents/overflow. Inspect original
    // numeric tokens before deserialization so feature unification cannot turn
    // an unsupported number into an object or silently change its value.
    // This is not a second structural parser: serde still validates the JSON
    // grammar, string escapes/UTF-8, duplicate fields and nesting below.
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'"' => {
                index += 1;
                while index < raw.len() {
                    match raw[index] {
                        b'\\' => index += 2,
                        b'"' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                index += 1;
                while index < raw.len()
                    && (raw[index].is_ascii_digit()
                        || matches!(raw[index], b'.' | b'e' | b'E' | b'+' | b'-'))
                {
                    index += 1;
                }
                let Ok(literal) = std::str::from_utf8(&raw[start..index]) else {
                    return false;
                };
                let negative = literal.starts_with('-');
                let digits = literal.strip_prefix('-').unwrap_or(literal);
                if digits.is_empty()
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    || (digits.len() > 1 && digits.starts_with('0'))
                    || if negative {
                        // Without arbitrary_precision, -0 reaches visit_f64.
                        digits == "0" || literal.parse::<i64>().is_err()
                    } else {
                        literal.parse::<u64>().is_err()
                    }
                {
                    return false;
                }
            }
            _ => index += 1,
        }
    }
    true
}

pub(crate) fn object(raw: &[u8]) -> Result<Value, BindingError> {
    if raw.len() > MAX_DOCUMENT_BYTES || !integer_lexemes(raw) {
        return Err(BindingError::new(ErrorKind::InvalidJson, "document"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValue { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let kind = if error.to_string().starts_with(DUPLICATE_FIELD) {
                ErrorKind::DuplicateJsonField
            } else {
                ErrorKind::InvalidJson
            };
            BindingError::new(kind, "document")
        })?;
    deserializer
        .end()
        .map_err(|_| BindingError::new(ErrorKind::InvalidJson, "document"))?;
    if !value.is_object() {
        return Err(BindingError::new(ErrorKind::InvalidJson, "document"));
    }
    Ok(value)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    field: &'static str,
) -> Result<T, BindingError> {
    serde_json::from_value(object(raw)?)
        .map_err(|_| BindingError::new(ErrorKind::SchemaInvalid, field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_lexemes_reject_before_projection_independent_of_serde_features() {
        for literal in [
            "1.0",
            "0.0",
            "-0",
            "-0.0",
            "1e0",
            "1E+0",
            "1e-1",
            "1e999",
            "18446744073709551616",
            "-9223372036854775809",
            "01",
            "-01",
        ] {
            for raw in [
                format!("{{\"x\":{literal}}}"),
                format!("{{\"nested\":[{{\"x\":{literal}}}]}}"),
            ] {
                assert_eq!(
                    object(raw.as_bytes()).unwrap_err().kind(),
                    ErrorKind::InvalidJson,
                    "accepted {literal}",
                );
            }
        }
    }

    #[test]
    fn numeric_bounds_and_quoted_lexemes_preserve_original_values() {
        for literal in [
            "0",
            "1",
            "-1",
            "-9223372036854775808",
            "18446744073709551615",
        ] {
            let raw = format!("{{\"x\":{literal}}}");
            let parsed = object(raw.as_bytes()).unwrap();
            assert!(parsed["x"].is_number());
            assert_eq!(parsed["x"].to_string(), literal);
        }
        let raw = br#"{"1e999":"1.0","escaped":"a\"1e999\\-0","unicode":"\u0031e999","nested":["18446744073709551616","-9223372036854775809"]}"#;
        let parsed = object(raw).unwrap();
        assert_eq!(parsed["1e999"], "1.0");
        assert_eq!(parsed["escaped"], "a\"1e999\\-0");
        assert_eq!(parsed["unicode"], "1e999");
        assert_eq!(parsed["nested"][0], "18446744073709551616");
        assert_eq!(parsed["nested"][1], "-9223372036854775809");
    }
}
