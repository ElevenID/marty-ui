use super::{AgentDirectoryError, MAX_AGENT_REQUEST_BYTES};
use serde::de::{DeserializeOwned, DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{cell::Cell, fmt};

/// Decode original bytes before any Value/DTO projection. Tenant, actor and
/// ownership remain separate trusted inputs; no request DTO contains them.
pub fn decode_agent_request<T: DeserializeOwned>(raw: &[u8]) -> Result<T, AgentDirectoryError> {
    if raw.len() > MAX_AGENT_REQUEST_BYTES {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    let remaining = Cell::new(8192);
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let value = Bounded {
        remaining: &remaining,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| AgentDirectoryError::InvalidRequest)?;
    decoder
        .end()
        .map_err(|_| AgentDirectoryError::InvalidRequest)?;
    if !value.is_object() {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    serde_json::from_value(value).map_err(|_| AgentDirectoryError::InvalidRequest)
}
struct Bounded<'a> {
    remaining: &'a Cell<usize>,
    depth: usize,
}
impl Bounded<'_> {
    fn child(&self) -> Bounded<'_> {
        Bounded {
            remaining: self.remaining,
            depth: self.depth + 1,
        }
    }
    fn count<E: Error>(&self) -> Result<(), E> {
        if self.depth > 24 || self.remaining.get() == 0 {
            return Err(E::custom("bounded input"));
        }
        self.remaining.set(self.remaining.get() - 1);
        Ok(())
    }
}
impl<'de> DeserializeSeed<'de> for Bounded<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        self.count()?;
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Bounded<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded agent administration JSON")
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("fractional input"))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(self.child())? {
            out.push(value);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.count()?;
            if key == "$serde_json::private::Number" || out.contains_key(&key) {
                return Err(A::Error::custom("ambiguous input"));
            }
            out.insert(key, map.next_value_seed(self.child())?);
        }
        Ok(Value::Object(out))
    }
}
