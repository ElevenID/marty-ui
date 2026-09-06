//! Test-only counterpart of scripts/canvas_observation_values.py. Encode only
//! AFTER execution; literal marker-shaped application data is never interpreted.
use marty_issuance_service::{lossless_json::LosslessJson, python_text::PythonText};
use serde_json::{json, Value};

const MARKERS: [&str; 4] = [
    "python_codepoints",
    "python_float",
    "python_integer",
    "python_object",
];

pub fn text(value: &PythonText) -> Value {
    match value.as_scalar() {
        Some(value) => json!(value),
        None => json!({"python_codepoints": value.codepoints().collect::<Vec<_>>()}),
    }
}

fn float(value: f64) -> Value {
    let marker = if value.is_nan() {
        Some("nan")
    } else if value == f64::INFINITY {
        Some("positive_infinity")
    } else if value == f64::NEG_INFINITY {
        Some("negative_infinity")
    } else if value == 0.0 && value.is_sign_negative() {
        Some("negative_zero")
    } else {
        None
    };
    marker.map_or_else(|| json!(value), |marker| json!({"python_float": marker}))
}

fn entries(values: Vec<(Value, Value)>) -> Value {
    if values
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| MARKERS.contains(&key)))
    {
        json!({"python_object": values})
    } else {
        Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key.as_str().unwrap().to_owned(), value))
                .collect(),
        )
    }
}

pub fn scalar(value: &Value) -> Value {
    match value {
        Value::Number(number) => {
            let token = number.to_string();
            if !token.contains(['.', 'e', 'E']) {
                let digits = token.strip_prefix('-').unwrap_or(&token);
                if digits.len() > 16 || (digits.len() == 16 && digits > "9007199254740991") {
                    return json!({"python_integer": token});
                }
                value.clone()
            } else {
                float(number.as_f64().expect("finite JSON observation number"))
            }
        }
        Value::Object(values) => entries(
            values
                .iter()
                .map(|(key, value)| (json!(key), scalar(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(scalar).collect()),
        _ => value.clone(),
    }
}

pub fn lossless(value: &LosslessJson) -> Value {
    match value {
        LosslessJson::Parsed(tree) => parsed(tree, tree.root()),
        LosslessJson::Scalar(value) => scalar(value),
        LosslessJson::Text(value) => text(value),
        LosslessJson::Object(values) => entries(
            values
                .iter()
                .map(|(key, value)| (json!(key), lossless(value)))
                .collect(),
        ),
        LosslessJson::PythonObject(values) => entries(
            values
                .iter()
                .map(|(key, value)| (text(key), lossless(value)))
                .collect(),
        ),
        LosslessJson::Array(values) => Value::Array(values.iter().map(lossless).collect()),
        LosslessJson::Float(value) => float(*value),
    }
}

fn parsed(tree: &marty_issuance_service::lossless_json_tree::JsonTree, id: usize) -> Value {
    use marty_issuance_service::lossless_json_tree::JsonNode;
    match tree.node(id) {
        JsonNode::Scalar(value) => scalar(value),
        JsonNode::Text(value) => text(value),
        JsonNode::Float(value) => float(*value),
        JsonNode::Array(values) => {
            Value::Array(values.iter().map(|id| parsed(tree, *id)).collect())
        }
        JsonNode::Object(values) => entries(
            values
                .iter()
                .map(|(key, id)| (text(key), parsed(tree, *id)))
                .collect(),
        ),
    }
}

#[test]
fn observation_encoding_preserves_numeric_and_literal_marker_distinctions() {
    assert_eq!(
        scalar(&json!(9007199254740991u64)),
        json!(9007199254740991u64)
    );
    assert_eq!(
        scalar(&json!(-9007199254740992i64)),
        json!({"python_integer":"-9007199254740992"})
    );
    assert_eq!(
        scalar(&serde_json::from_str::<Value>(&"9".repeat(4300)).unwrap()),
        json!({"python_integer":"9".repeat(4300)})
    );
    assert_eq!(
        scalar(&json!(-0.0)),
        json!({"python_float":"negative_zero"})
    );
    assert_eq!(
        lossless(&LosslessJson::Float(f64::NAN)),
        json!({"python_float":"nan"})
    );
    let literal = json!({"python_float":"nan"});
    assert_eq!(
        scalar(&literal),
        json!({"python_object":[["python_float","nan"]]})
    );
    assert_ne!(scalar(&literal), lossless(&LosslessJson::Float(f64::NAN)));
    assert_eq!(
        lossless(&LosslessJson::PythonObject(vec![(
            "python_object".to_owned().into(),
            literal.into()
        )])),
        json!({"python_object":[["python_object", {"python_object":[["python_float","nan"]]}]]})
    );
}
