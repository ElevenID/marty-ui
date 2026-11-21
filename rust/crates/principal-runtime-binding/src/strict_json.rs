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

pub(crate) fn object(raw: &[u8]) -> Result<Value, BindingError> {
    if raw.len() > MAX_DOCUMENT_BYTES {
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
