//! Recursive duplicate-key rejection shared by installer record readers.
//! Callers retain their own input limits, schemas and public refusal messages.
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(crate) fn decode(bytes: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice::<Unique>(bytes).map(|value| value.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_duplicate_members_at_every_nesting_level() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"nested":{"a":1,"a":2}}"#,
            br#"[{"a":1,"a":2}]"#,
        ] {
            assert!(decode(bytes).is_err());
        }
    }

    #[test]
    fn separate_objects_may_reuse_names_and_all_json_values_survive() {
        let bytes =
            br#"{"items":[{"a":1},{"a":2}],"flag":true,"nothing":null,"text":"ok","number":1.5}"#;
        assert_eq!(
            decode(bytes).unwrap(),
            json!({"items":[{"a":1},{"a":2}],"flag":true,"nothing":null,"text":"ok","number":1.5})
        );
    }

    #[test]
    fn refuses_trailing_values_and_malformed_json() {
        for bytes in [b"{} {}".as_slice(), b"", b"{", b"NaN"] {
            assert!(decode(bytes).is_err());
        }
    }
}
