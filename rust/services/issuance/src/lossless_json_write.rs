//! One iterative strict JSON writer for parsed arenas and existing metadata.
use crate::{
    lossless_json::{LosslessJson, NonScalarJson},
    lossless_json_tree::{JsonNode, JsonTree},
    python_text::PythonText,
};
use serde_json::{value::RawValue, Value};

enum Reference<'a> {
    Lossless(&'a LosslessJson),
    LosslessMap(&'a crate::lossless_json::LosslessObject),
    Scalar(&'a Value),
    Map(&'a serde_json::Map<String, Value>),
    Node(&'a JsonTree, usize),
}
enum Text<'a> {
    Scalar(&'a str),
    Python(&'a PythonText),
}
enum Task<'a> {
    Value(Reference<'a>),
    Text(Text<'a>),
    Byte(u8),
}

pub(crate) fn lossless(
    value: &LosslessJson,
    postgres: bool,
) -> Result<Box<RawValue>, NonScalarJson> {
    write(Reference::Lossless(value), postgres)
}

pub(crate) fn tree(value: &JsonTree, postgres: bool) -> Result<Box<RawValue>, NonScalarJson> {
    write(Reference::Node(value, value.root()), postgres)
}
pub(crate) fn lossless_map(
    value: &crate::lossless_json::LosslessObject,
    postgres: bool,
) -> Result<Box<RawValue>, NonScalarJson> {
    write(Reference::LosslessMap(value), postgres)
}

pub(crate) fn scalar(value: &Value) -> Box<RawValue> {
    write(Reference::Scalar(value), false).expect("serde Value contains valid scalar JSON")
}

pub(crate) fn scalar_map(value: &serde_json::Map<String, Value>) -> Box<RawValue> {
    write(Reference::Map(value), false).expect("serde Map contains valid scalar JSON")
}

fn array<'a>(
    output: &mut Vec<u8>,
    pending: &mut Vec<Task<'a>>,
    values: impl DoubleEndedIterator<Item = Reference<'a>>,
) {
    output.push(b'[');
    pending.push(Task::Byte(b']'));
    for (index, child) in values.rev().enumerate() {
        if index > 0 {
            pending.push(Task::Byte(b','));
        }
        pending.push(Task::Value(child));
    }
}

fn object<'a>(
    output: &mut Vec<u8>,
    pending: &mut Vec<Task<'a>>,
    values: impl DoubleEndedIterator<Item = (Text<'a>, Reference<'a>)>,
) {
    output.push(b'{');
    pending.push(Task::Byte(b'}'));
    for (index, (key, child)) in values.rev().enumerate() {
        if index > 0 {
            pending.push(Task::Byte(b','));
        }
        pending.push(Task::Value(child));
        pending.push(Task::Byte(b':'));
        pending.push(Task::Text(key));
    }
}

fn write(root: Reference<'_>, postgres: bool) -> Result<Box<RawValue>, NonScalarJson> {
    let mut output = Vec::new();
    let mut pending = vec![Task::Value(root)];
    while let Some(task) = pending.pop() {
        match task {
            Task::Byte(byte) => output.push(byte),
            Task::Text(text) => {
                let text = match text {
                    Text::Scalar(text) => text,
                    Text::Python(text) => text.as_scalar().ok_or(NonScalarJson)?,
                };
                if postgres && text.contains('\0') {
                    return Err(NonScalarJson);
                }
                serde_json::to_writer(&mut output, text).map_err(|_| NonScalarJson)?;
            }
            Task::Value(Reference::Lossless(value)) => match value {
                LosslessJson::Parsed(tree) => {
                    pending.push(Task::Value(Reference::Node(tree, tree.root())))
                }
                LosslessJson::Scalar(value) => pending.push(Task::Value(Reference::Scalar(value))),
                LosslessJson::Text(text) => pending.push(Task::Text(Text::Python(text))),
                LosslessJson::Float(value) => {
                    let number = serde_json::Number::from_f64(*value).ok_or(NonScalarJson)?;
                    serde_json::to_writer(&mut output, &number).map_err(|_| NonScalarJson)?;
                }
                LosslessJson::Array(values) => array(
                    &mut output,
                    &mut pending,
                    values.iter().map(Reference::Lossless),
                ),
                LosslessJson::Object(values) => object(
                    &mut output,
                    &mut pending,
                    values
                        .iter()
                        .map(|(key, value)| (Text::Scalar(key), Reference::Lossless(value))),
                ),
                LosslessJson::PythonObject(values) => {
                    let mut positions = std::collections::HashMap::new();
                    let mut entries = Vec::new();
                    for (key, value) in values {
                        if let Some(index) = positions.get(key).copied() {
                            entries[index] = (key, value);
                        } else {
                            positions.insert(key, entries.len());
                            entries.push((key, value));
                        }
                    }
                    object(
                        &mut output,
                        &mut pending,
                        entries
                            .into_iter()
                            .map(|(key, value)| (Text::Python(key), Reference::Lossless(value))),
                    );
                }
            },
            Task::Value(Reference::LosslessMap(values)) => object(
                &mut output,
                &mut pending,
                values
                    .iter()
                    .map(|(key, value)| (Text::Scalar(key), Reference::Lossless(value))),
            ),
            Task::Value(Reference::Map(values)) => object(
                &mut output,
                &mut pending,
                values
                    .iter()
                    .map(|(key, value)| (Text::Scalar(key), Reference::Scalar(value))),
            ),
            Task::Value(Reference::Scalar(value)) => match value {
                Value::String(text) => pending.push(Task::Text(Text::Scalar(text))),
                Value::Array(values) => array(
                    &mut output,
                    &mut pending,
                    values.iter().map(Reference::Scalar),
                ),
                Value::Object(values) => object(
                    &mut output,
                    &mut pending,
                    values
                        .iter()
                        .map(|(key, value)| (Text::Scalar(key), Reference::Scalar(value))),
                ),
                _ => serde_json::to_writer(&mut output, value).map_err(|_| NonScalarJson)?,
            },
            Task::Value(Reference::Node(tree, id)) => match tree.node(id) {
                JsonNode::Scalar(value) => pending.push(Task::Value(Reference::Scalar(value))),
                JsonNode::Text(text) => pending.push(Task::Text(Text::Python(text))),
                JsonNode::Float(value) => {
                    let number = serde_json::Number::from_f64(*value).ok_or(NonScalarJson)?;
                    serde_json::to_writer(&mut output, &number).map_err(|_| NonScalarJson)?;
                }
                JsonNode::Array(values) => array(
                    &mut output,
                    &mut pending,
                    values.iter().map(|id| Reference::Node(tree, *id)),
                ),
                JsonNode::Object(values) => object(
                    &mut output,
                    &mut pending,
                    values
                        .iter()
                        .map(|(key, id)| (Text::Python(key), Reference::Node(tree, *id))),
                ),
            },
        }
    }
    RawValue::from_string(String::from_utf8(output).map_err(|_| NonScalarJson)?)
        .map_err(|_| NonScalarJson)
}
