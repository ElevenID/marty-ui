//! Recursive duplicate-key rejection shared by installer record readers.
//! Callers retain their own input limits, schemas and public refusal messages.
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        UniqueSeed(0).deserialize(deserializer)
    }
}

struct UniqueSeed(usize);
impl<'de> DeserializeSeed<'de> for UniqueSeed {
    type Value = Unique;
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        if self.0 >= 128 {
            return Err(de::Error::custom("JSON nesting limit exceeded"));
        }
        // Read the original JSON token so numbers are decoded by serde_json,
        // independently of arbitrary_precision feature unification. Objects go
        // through our map visitor, keeping literal private-marker keys as keys.
        let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
        let mut parser = serde_json::Deserializer::from_str(raw.get());
        struct UniqueVisitor(usize);
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element_seed(UniqueSeed(self.0 + 1))? {
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
                    let Unique(value) = map.next_value_seed(UniqueSeed(self.0 + 1))?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        let value = match raw.get().as_bytes()[0] {
            b'{' => parser
                .deserialize_map(UniqueVisitor(self.0))
                .map_err(de::Error::custom)?,
            b'[' => parser
                .deserialize_seq(UniqueVisitor(self.0))
                .map_err(de::Error::custom)?,
            _ => Unique(serde_json::from_str(raw.get()).map_err(de::Error::custom)?),
        };
        Ok(value)
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
    fn private_marker_names_remain_literal_object_members() {
        let value = decode(br#"{"$serde_json::private::Number":"1.5","nested":{"$serde_json::private::RawValue":"{}"}}"#).unwrap();
        assert_eq!(value["$serde_json::private::Number"], "1.5");
        assert_eq!(value["nested"]["$serde_json::private::RawValue"], "{}");
        assert!(value.is_object());
        assert!(decode(
            br#"{"$serde_json::private::Number":"1","$serde_json::private::Number":"2"}"#
        )
        .is_err());
    }

    #[test]
    fn refuses_excessive_nesting() {
        let nested = format!("{}null{}", "[".repeat(128), "]".repeat(128));
        assert!(decode(nested.as_bytes()).is_err());
    }

    #[test]
    fn refuses_trailing_values_and_malformed_json() {
        for bytes in [b"{} {}".as_slice(), b"", b"{", b"NaN"] {
            assert!(decode(bytes).is_err());
        }
    }
}
