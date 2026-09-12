//! Stack-safe ownership and database decoding for retained JSON metadata.
//! A serde Value view keeps existing consumers intact; explicit ownership drains
//! nested containers iteratively, and copies use the shared iterative JSON owner.
use crate::lossless_json_tree::JsonTree;
use serde_json::{Map, Value};

pub struct OwnedJsonValue(Value);

impl OwnedJsonValue {
    pub fn new(value: Value) -> Self {
        Self(value)
    }
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        JsonTree::from_json_bytes(bytes)?
            .to_scalar(false, false)
            .ok()
            .map(Self)
    }
    pub fn copy(value: &Value) -> Self {
        Self::from_json(crate::lossless_json_write::scalar(value).get().as_bytes())
            .expect("valid scalar JSON copy")
    }
    pub fn copy_map(value: &Map<String, Value>) -> Self {
        Self::from_json(
            crate::lossless_json_write::scalar_map(value)
                .get()
                .as_bytes(),
        )
        .expect("valid scalar JSON map copy")
    }
    /// Move a value only to another stack-safe owner or an explicitly bounded
    /// consumer. Prefer keeping this wrapper around retained arbitrary JSON.
    pub fn take(&mut self) -> Value {
        std::mem::take(&mut self.0)
    }
    pub fn replace_field(&mut self, key: &str, value: Self) {
        let mut value = value;
        let old = std::mem::replace(&mut self.0[key], value.take());
        drop(Self(old));
    }
    pub(crate) fn insert_map(map: &mut Map<String, Value>, key: String, value: Value) {
        if let Some(old) = map.insert(key, value) {
            drop_value(old);
        }
    }
    pub(crate) fn extend_map(map: &mut Map<String, Value>, values: Map<String, Value>) {
        for (key, value) in values {
            Self::insert_map(map, key, value);
        }
    }
}
impl From<Value> for OwnedJsonValue {
    fn from(value: Value) -> Self {
        Self(value)
    }
}
impl PartialEq for OwnedJsonValue {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(&self.0, &other.0)];
        while let Some((left, right)) = pending.pop() {
            match (left, right) {
                (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
                    pending.extend(left.iter().zip(right))
                }
                (Value::Object(left), Value::Object(right)) if left.len() == right.len() => {
                    for (key, left) in left {
                        let Some(right) = right.get(key) else {
                            return false;
                        };
                        pending.push((left, right));
                    }
                }
                (Value::Array(_), _)
                | (Value::Object(_), _)
                | (_, Value::Array(_))
                | (_, Value::Object(_)) => return false,
                _ if left != right => return false,
                _ => (),
            }
        }
        true
    }
}
impl std::fmt::Debug for OwnedJsonValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("OwnedJsonValue")
            .field(&crate::lossless_json_write::scalar(&self.0).get())
            .finish()
    }
}

impl std::ops::Deref for OwnedJsonValue {
    type Target = Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedJsonValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Clone for OwnedJsonValue {
    fn clone(&self) -> Self {
        Self::copy(&self.0)
    }
}
impl Drop for OwnedJsonValue {
    fn drop(&mut self) {
        drop_value(std::mem::take(&mut self.0));
    }
}

pub(crate) fn drop_value(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.into_iter().map(|(_, value)| value)),
            _ => (),
        }
    }
}
impl serde::Serialize for OwnedJsonValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::lossless_json_write::scalar(&self.0).serialize(serializer)
    }
}
impl sqlx::Type<sqlx::Postgres> for OwnedJsonValue {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <sqlx::types::Json<Box<serde_json::value::RawValue>> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <sqlx::types::Json<Box<serde_json::value::RawValue>> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for OwnedJsonValue {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let raw = <sqlx::types::Json<Box<serde_json::value::RawValue>> as sqlx::Decode<
            sqlx::Postgres,
        >>::decode(value)?;
        Self::from_json(raw.0.get().as_bytes()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "database JSON cannot be represented",
            )
            .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_database_values_copy_compare_serialize_replace_and_drop_on_a_small_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                for (open, close) in [("[", "]"), ("{\"nested\":", "}")] {
                    let source = format!(
                        "{{\"retained\":{}0{}}}",
                        open.repeat(1600),
                        close.repeat(1600)
                    );
                    let mut value = OwnedJsonValue::from_json(source.as_bytes()).unwrap();
                    let copy = value.clone();
                    assert_eq!(value, copy);
                    assert_eq!(serde_json::to_string(&copy).unwrap(), source);
                    value.replace_field("retained", OwnedJsonValue::new(Value::Null));
                    assert_ne!(value, copy);
                    drop(copy);
                    drop(value);
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn database_numbers_are_not_limited_or_coerced_like_python_response_numbers() {
        for source in ["9".repeat(4301), "1e10000".into(), "-0.0".into()] {
            let value = OwnedJsonValue::from_json(source.as_bytes()).unwrap();
            let expected: Value = serde_json::from_str(&source).unwrap();
            assert_eq!(*value, expected);
            assert_eq!(
                serde_json::to_string(&value).unwrap(),
                serde_json::to_string(&expected).unwrap()
            );
        }
        for invalid in ["NaN", "Infinity", "-Infinity"] {
            assert!(OwnedJsonValue::from_json(invalid.as_bytes()).is_none());
        }
    }

    #[test]
    fn failed_scalar_conversion_cleans_up_already_built_deep_values_without_recursion() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let source = format!("[{}0{},\"\\ud800\"]", "[".repeat(1600), "]".repeat(1600));
                let tree = JsonTree::from_response_bytes(source.as_bytes()).unwrap();
                assert!(tree.to_scalar(false, false).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
