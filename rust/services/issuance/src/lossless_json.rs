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
    /// JSON input order is needed when rendering changes two distinct keys
    /// into the same key. These are typed keys, never diagnostic marker objects.
    PythonObject(Vec<(PythonText, Self)>),
    Float(f64),
    Parsed(std::sync::Arc<crate::lossless_json_tree::JsonTree>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("response cannot be represented at the selected JSON boundary")]
pub struct NonScalarJson;

impl From<Value> for LosslessJson {
    fn from(value: Value) -> Self {
        if value.is_array() || value.is_object() {
            let owned = crate::owned_json_value::OwnedJsonValue::new(value);
            let raw = crate::lossless_json_write::scalar(&owned);
            Self::Parsed(std::sync::Arc::new(
                crate::lossless_json_tree::JsonTree::from_json_bytes(raw.get().as_bytes())
                    .expect("valid scalar JSON"),
            ))
        } else {
            Self::Scalar(value)
        }
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
            Self::Parsed(tree) => tree.to_scalar(false, false)?,
            Self::Scalar(value) => crate::owned_json_value::OwnedJsonValue::copy(value).take(),
            Self::Text(text) => Value::String(text.as_scalar().ok_or(NonScalarJson)?.to_owned()),
            Self::Object(value) => Value::Object(scalar_object(value)?),
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(Self::to_scalar)
                    .collect::<Result<_, _>>()?,
            ),
            Self::PythonObject(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            key.as_scalar().ok_or(NonScalarJson)?.to_owned(),
                            value.to_scalar()?,
                        ))
                    })
                    .collect::<Result<_, NonScalarJson>>()?,
            ),
            Self::Float(value) => {
                Value::Number(serde_json::Number::from_f64(*value).ok_or(NonScalarJson)?)
            }
        })
    }

    /// The published typed excerpt dictionary has a different key policy from
    /// nested arbitrary JSON values. Only this explicit HTTP-rendering boundary
    /// replaces top-level surrogate keys and projects non-finite floats to null.
    pub fn validation_value(&self, excerpt_root: bool) -> Result<Value, NonScalarJson> {
        if self.exceeds_validation_depth() {
            return Err(NonScalarJson);
        }
        self.validation_value_at(excerpt_root, 0)
    }

    fn exceeds_validation_depth(&self) -> bool {
        enum Ref<'a> {
            Lossless(&'a LosslessJson),
            Scalar(&'a Value),
        }
        let mut pending = vec![(Ref::Lossless(self), 0)];
        while let Some((value, parent)) = pending.pop() {
            match value {
                Ref::Lossless(Self::Parsed(tree)) if parent + tree.container_depth() > 255 => {
                    return true
                }
                Ref::Lossless(Self::Scalar(value)) => pending.push((Ref::Scalar(value), parent)),
                Ref::Lossless(Self::Array(values)) => {
                    if parent >= 255 {
                        return true;
                    }
                    pending.extend(
                        values
                            .iter()
                            .map(|value| (Ref::Lossless(value), parent + 1)),
                    );
                }
                Ref::Lossless(Self::Object(values)) => {
                    if parent >= 255 {
                        return true;
                    }
                    pending.extend(
                        values
                            .values()
                            .map(|value| (Ref::Lossless(value), parent + 1)),
                    );
                }
                Ref::Lossless(Self::PythonObject(values)) => {
                    if parent >= 255 {
                        return true;
                    }
                    pending.extend(
                        values
                            .iter()
                            .map(|(_, value)| (Ref::Lossless(value), parent + 1)),
                    );
                }
                Ref::Scalar(Value::Array(values)) => {
                    if parent >= 255 {
                        return true;
                    }
                    pending.extend(values.iter().map(|value| (Ref::Scalar(value), parent + 1)));
                }
                Ref::Scalar(Value::Object(values)) => {
                    if parent >= 255 {
                        return true;
                    }
                    pending.extend(
                        values
                            .values()
                            .map(|value| (Ref::Scalar(value), parent + 1)),
                    );
                }
                _ => (),
            }
        }
        false
    }

    fn validation_value_at(
        &self,
        excerpt_root: bool,
        parent_depth: usize,
    ) -> Result<Value, NonScalarJson> {
        // The published typed excerpt allows 255 container levels, including
        // the payload wrapper. This is not a parser or persistence limit.
        if let Self::Parsed(tree) = self {
            if parent_depth + tree.container_depth() > 255 {
                return Err(NonScalarJson);
            }
            return tree.to_scalar(true, excerpt_root);
        }
        if parent_depth >= 255
            && matches!(
                self,
                Self::Object(_) | Self::PythonObject(_) | Self::Array(_)
            )
        {
            return Err(NonScalarJson);
        }
        Ok(match self {
            Self::Float(value) => serde_json::Number::from_f64(*value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Self::PythonObject(entries) => {
                let mut output = Map::new();
                for (key, value) in entries {
                    let key = if excerpt_root {
                        let mut rendered = String::new();
                        for point in key.codepoints() {
                            if let Some(character) = char::from_u32(point) {
                                rendered.push(character);
                            } else {
                                rendered.push_str("\u{fffd}\u{fffd}\u{fffd}");
                            }
                        }
                        rendered
                    } else {
                        key.as_scalar().ok_or(NonScalarJson)?.to_owned()
                    };
                    output.insert(key, value.validation_value_at(false, parent_depth + 1)?);
                }
                Value::Object(output)
            }
            Self::Object(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            key.clone(),
                            value.validation_value_at(false, parent_depth + 1)?,
                        ))
                    })
                    .collect::<Result<_, NonScalarJson>>()?,
            ),
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| value.validation_value_at(false, parent_depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            _ => self.to_scalar()?,
        })
    }
}

pub fn serialize_validation_excerpt<S: Serializer>(
    value: &Option<LosslessJson>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .as_ref()
        .map(|value| value.validation_value(true))
        .transpose()
        .map_err(S::Error::custom)?
        .serialize(serializer)
}

/// PostgreSQL JSONB also rejects U+0000, which is valid scalar JSON text.
/// Keep this check at persistence, not at parsing or validation rendering.
pub fn postgres_object(value: &LosslessObject) -> Result<Map<String, Value>, NonScalarJson> {
    crate::lossless_json_write::lossless_map(value, true)?;
    scalar_object(value)
}

pub fn postgres_object_raw(
    value: &LosslessObject,
) -> Result<Box<serde_json::value::RawValue>, NonScalarJson> {
    crate::lossless_json_write::lossless_map(value, true)
}

// This owner deliberately renders JSON, unlike PythonText (which has no implicit
// serializer or Display). Rendering non-scalar values fails without coercion.
impl Serialize for LosslessJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::lossless_json_write::lossless(self, false)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_key_projection_is_root_only_and_last_wins() {
        let surrogate = PythonText::from_codepoints([0xd800]).unwrap();
        let rendered: PythonText = "\u{fffd}\u{fffd}\u{fffd}".to_owned().into();
        for keys in [
            [surrogate.clone(), rendered.clone()],
            [rendered.clone(), surrogate.clone()],
        ] {
            let object = LosslessJson::PythonObject(vec![
                (keys[0].clone(), serde_json::json!("first").into()),
                (keys[1].clone(), serde_json::json!("second").into()),
            ]);
            assert_eq!(
                object.validation_value(true).unwrap(),
                serde_json::json!({"���":"second"})
            );
            assert_eq!(object.validation_value(false), Err(NonScalarJson));
            assert_eq!(object.to_scalar(), Err(NonScalarJson));
        }
        let value = LosslessJson::Text(surrogate);
        assert_eq!(value.validation_value(true), Err(NonScalarJson));
    }

    #[test]
    fn nonfinite_projection_is_validation_only_and_recursive() {
        let value = LosslessJson::Array(vec![
            LosslessJson::Float(f64::NAN),
            LosslessJson::Float(f64::INFINITY),
            LosslessJson::Float(f64::NEG_INFINITY),
        ]);
        assert_eq!(
            value.validation_value(true).unwrap(),
            serde_json::json!([null, null, null])
        );
        assert_eq!(value.to_scalar(), Err(NonScalarJson));
        assert!(serde_json::to_vec(&value).is_err());
    }

    #[test]
    fn nul_is_valid_for_rendering_but_not_postgres_persistence() {
        for value in [
            serde_json::json!({"nested":["a\0b"]}),
            serde_json::json!({"nested":{"\0":true}}),
        ] {
            let value = object(value.as_object().unwrap().clone());
            assert!(scalar_object(&value).is_ok());
            assert!(serde_json::to_vec(&value).is_ok());
            assert_eq!(postgres_object(&value), Err(NonScalarJson));
        }
        let value = object(
            serde_json::json!({"nested":["a",0,false,null]})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert_eq!(
            postgres_object(&value).unwrap(),
            scalar_object(&value).unwrap()
        );
    }

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
