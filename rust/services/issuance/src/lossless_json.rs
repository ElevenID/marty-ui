//! In-memory response values, distinct from UTF-8 JSON rendering/persistence.
//! Scalar JSON retains serde's existing representation. Text and containers can
//! carry Python codepoints until the caller explicitly reaches a wire boundary.
use crate::python_text::PythonText;
use serde::{ser::Error, Serialize, Serializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub type LosslessObject = BTreeMap<String, LosslessJson>;

#[derive(Clone, Debug, PartialEq)]
pub enum LosslessJson {
    Scalar(Value),
    Text(PythonText),
    Object(LosslessObject),
    Array(Vec<Self>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("response contains text that cannot be encoded as UTF-8 JSON")]
pub struct NonScalarJson;

impl From<Value> for LosslessJson {
    fn from(value: Value) -> Self {
        Self::Scalar(value)
    }
}

pub fn object(value: Map<String, Value>) -> LosslessObject {
    value
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
}

pub fn scalar_object(value: &LosslessObject) -> Result<Map<String, Value>, NonScalarJson> {
    value
        .iter()
        .map(|(key, value)| Ok((key.clone(), value.to_scalar()?)))
        .collect()
}

impl LosslessJson {
    /// Explicit conversion borrows rather than consumes the original value.
    /// Failure cannot replace, escape, truncate or destroy non-scalar text.
    pub fn to_scalar(&self) -> Result<Value, NonScalarJson> {
        Ok(match self {
            Self::Scalar(value) => value.clone(),
            Self::Text(text) => Value::String(text.as_scalar().ok_or(NonScalarJson)?.to_owned()),
            Self::Object(value) => Value::Object(scalar_object(value)?),
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(Self::to_scalar)
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

// This owner deliberately renders JSON, unlike PythonText (which has no implicit
// serializer or Display). Rendering non-scalar values fails without coercion.
impl Serialize for LosslessJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Scalar(value) => value.serialize(serializer),
            Self::Text(text) => text
                .as_scalar()
                .ok_or_else(|| S::Error::custom(NonScalarJson))?
                .serialize(serializer),
            Self::Object(value) => value.serialize(serializer),
            Self::Array(value) => value.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_is_explicit_and_does_not_destroy_non_scalar_values() {
        let text = PythonText::from_codepoints([0xd800, 0xdc00, 0x10000]).unwrap();
        let value = LosslessJson::Object(BTreeMap::from([(
            "nested".into(),
            LosslessJson::Array(vec![LosslessJson::Text(text)]),
        )]));
        let original = value.clone();
        assert_eq!(value.to_scalar(), Err(NonScalarJson));
        assert!(serde_json::to_vec(&value).is_err());
        assert_eq!(value, original);
        let scalar = serde_json::json!({"nested":[null, true, 42, "𐀀"]});
        assert_eq!(
            LosslessJson::from(scalar.clone()).to_scalar().unwrap(),
            scalar
        );
        let mixed = LosslessJson::Object(BTreeMap::from([(
            "nested".into(),
            LosslessJson::Array(vec![
                LosslessJson::Scalar(Value::Null),
                LosslessJson::Text("𐀀".to_owned().into()),
            ]),
        )]));
        let expected = serde_json::json!({"nested":[null,"𐀀"]});
        assert_eq!(mixed.to_scalar().unwrap(), expected);
        assert_eq!(serde_json::to_value(&mixed).unwrap(), expected);
    }
}
