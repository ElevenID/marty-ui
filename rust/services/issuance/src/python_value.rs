//! Shared JSON-value display compatibility with the published Python runtime.
//! Unicode tables are frozen language-neutral observations, not host-version
//! heuristics. No Python process is used by the Rust runtime.
use crate::lossless_json_tree::{JsonNode, JsonTree};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct TextSemantics {
    printable_ranges: Vec<[u32; 2]>,
    whitespace: Vec<u32>,
}

fn semantics() -> &'static TextSemantics {
    static TABLE: OnceLock<TextSemantics> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../contracts/python-text-semantics.json"
        ))
        .expect("compiled published text-semantics contract")
    })
}

pub(crate) fn strip(value: &str) -> &str {
    value.trim_matches(|character: char| whitespace(character as u32))
}

fn whitespace(point: u32) -> bool {
    semantics().whitespace.binary_search(&point).is_ok()
}

pub(crate) fn strip_points(points: &[u32]) -> &[u32] {
    let start = points
        .iter()
        .position(|point| !whitespace(*point))
        .unwrap_or(points.len());
    let end = points
        .iter()
        .rposition(|point| !whitespace(*point))
        .map_or(start, |index| index + 1);
    &points[start..end]
}

fn printable(point: u32) -> bool {
    let ranges = &semantics().printable_ranges;
    let index = ranges.partition_point(|range| range[1] < point);
    ranges.get(index).is_some_and(|range| range[0] <= point)
}

pub(crate) fn python_truthy(value: &Value) -> bool {
    value_truthy(value)
}

pub(crate) fn python_string(value: &Value) -> Option<String> {
    Some(match value {
        Value::String(value) => value.clone(),
        _ => representation_points(value)
            .into_iter()
            .map(|point| char::from_u32(point).expect("scalar JSON representation"))
            .collect(),
    })
}

/// Borrowed views keep the single formatter independent of a JSON storage
/// model. Neither lossless callers nor scalar callers serialize/reparse JSON.
pub(crate) trait PythonValueView: Copy {
    fn view(self) -> PythonValueNode<Self>;
    fn truthy(self) -> bool;
}

pub(crate) enum PythonValueNode<V> {
    Null,
    Bool(bool),
    Number { representation: String, zero: bool },
    Text(Vec<u32>),
    Array(Vec<V>),
    Object(Vec<(Vec<u32>, V)>),
}

impl<V> PythonValueNode<V> {
    pub(crate) fn map<U>(self, map: impl Fn(V) -> U) -> PythonValueNode<U> {
        match self {
            Self::Null => PythonValueNode::Null,
            Self::Bool(value) => PythonValueNode::Bool(value),
            Self::Number {
                representation,
                zero,
            } => PythonValueNode::Number {
                representation,
                zero,
            },
            Self::Text(value) => PythonValueNode::Text(value),
            Self::Array(values) => PythonValueNode::Array(values.into_iter().map(map).collect()),
            Self::Object(values) => PythonValueNode::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, map(value)))
                    .collect(),
            ),
        }
    }
}

impl PythonValueView for &Value {
    fn truthy(self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Number(value) => value.as_f64() != Some(0.0),
            Value::String(value) => !value.is_empty(),
            Value::Array(value) => !value.is_empty(),
            Value::Object(value) => !value.is_empty(),
        }
    }
    fn view(self) -> PythonValueNode<Self> {
        match self {
            Value::Null => PythonValueNode::Null,
            Value::Bool(value) => PythonValueNode::Bool(*value),
            Value::Number(value) => PythonValueNode::Number {
                representation: number(value),
                zero: value.as_f64() == Some(0.0),
            },
            Value::String(value) => PythonValueNode::Text(value.chars().map(u32::from).collect()),
            Value::Array(values) => PythonValueNode::Array(values.iter().collect()),
            Value::Object(values) => PythonValueNode::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.chars().map(u32::from).collect(), value))
                    .collect(),
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PythonJsonValue<'a> {
    Scalar(&'a Value),
    Tree(&'a JsonTree, usize),
}

impl PythonValueView for PythonJsonValue<'_> {
    fn truthy(self) -> bool {
        match self {
            Self::Scalar(value) => value.truthy(),
            Self::Tree(tree, id) => match tree.node(id) {
                JsonNode::Scalar(value) => value.truthy(),
                JsonNode::Text(value) => value.codepoints().next().is_some(),
                JsonNode::Float(value) => *value != 0.0,
                JsonNode::Array(values) => !values.is_empty(),
                JsonNode::Object(values) => !values.is_empty(),
            },
        }
    }
    fn view(self) -> PythonValueNode<Self> {
        let Self::Tree(tree, id) = self else {
            let Self::Scalar(value) = self else {
                unreachable!()
            };
            return value.view().map(Self::Scalar);
        };
        match tree.node(id) {
            JsonNode::Scalar(value) => Self::Scalar(value).view(),
            JsonNode::Text(text) => PythonValueNode::Text(text.codepoints().collect()),
            JsonNode::Float(value) => PythonValueNode::Number {
                representation: float(*value),
                zero: *value == 0.0,
            },
            JsonNode::Array(values) => {
                PythonValueNode::Array(values.iter().map(|id| Self::Tree(tree, *id)).collect())
            }
            JsonNode::Object(values) => PythonValueNode::Object(
                values
                    .iter()
                    .map(|(key, id)| (key.codepoints().collect(), Self::Tree(tree, *id)))
                    .collect(),
            ),
        }
    }
}

impl<'a> PythonJsonValue<'a> {
    pub(crate) fn field(self, name: &str) -> Option<Self> {
        match self {
            Self::Scalar(value) => value.as_object()?.get(name).map(Self::Scalar),
            Self::Tree(tree, id) => {
                let JsonNode::Object(entries) = tree.node(id) else {
                    return None;
                };
                entries
                    .iter()
                    .find(|(key, _)| key.codepoints().eq(name.chars().map(u32::from)))
                    .map(|(_, id)| Self::Tree(tree, *id))
            }
        }
    }
    pub(crate) fn first(self) -> Option<Self> {
        match self {
            Self::Scalar(value) => value.as_array()?.first().map(Self::Scalar),
            Self::Tree(tree, id) => {
                let JsonNode::Array(values) = tree.node(id) else {
                    return None;
                };
                values.first().map(|id| Self::Tree(tree, *id))
            }
        }
    }
    pub(crate) fn is_object(self) -> bool {
        match self {
            Self::Scalar(value) => value.is_object(),
            Self::Tree(tree, id) => matches!(tree.node(id), JsonNode::Object(_)),
        }
    }
    pub(crate) fn string_points(self) -> Vec<u32> {
        match self.view() {
            PythonValueNode::Text(value) => value,
            _ => representation_points(self),
        }
    }
}

pub(crate) fn value_truthy(value: impl PythonValueView) -> bool {
    value.truthy()
}

pub(crate) fn representation_points<V: PythonValueView>(value: V) -> Vec<u32> {
    enum Task<V> {
        Value(V),
        Text(Vec<u32>),
        Literal(&'static str),
    }
    let mut tasks = vec![Task::Value(value)];
    let mut output = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Text(text) => output.extend(text),
            Task::Literal(text) => output.extend(text.chars().map(u32::from)),
            Task::Value(value) => match value.view() {
                PythonValueNode::Null => tasks.push(Task::Literal("None")),
                PythonValueNode::Bool(value) => {
                    tasks.push(Task::Literal(if value { "True" } else { "False" }))
                }
                PythonValueNode::Number { representation, .. } => {
                    output.extend(representation.chars().map(u32::from))
                }
                PythonValueNode::Text(text) => output.extend(quoted_points(&text)),
                PythonValueNode::Array(values) => {
                    output.push(u32::from('['));
                    tasks.push(Task::Literal("]"));
                    for (index, value) in values.into_iter().enumerate().rev() {
                        tasks.push(Task::Value(value));
                        if index > 0 {
                            tasks.push(Task::Literal(", "));
                        }
                    }
                }
                PythonValueNode::Object(values) => {
                    output.push(u32::from('{'));
                    tasks.push(Task::Literal("}"));
                    for (index, (key, value)) in values.into_iter().enumerate().rev() {
                        tasks.push(Task::Value(value));
                        tasks.push(Task::Literal(": "));
                        tasks.push(Task::Text(quoted_points(&key)));
                        if index > 0 {
                            tasks.push(Task::Literal(", "));
                        }
                    }
                }
            },
        }
    }
    output
}

fn quoted_points(value: &[u32]) -> Vec<u32> {
    let quote = if value.contains(&u32::from('\'')) && !value.contains(&u32::from('"')) {
        u32::from('"')
    } else {
        u32::from('\'')
    };
    let mut result = Vec::with_capacity(value.len() + 2);
    result.push(quote);
    for point in value.iter().copied() {
        let escaped = match point {
            92 => Some("\\\\".into()),
            10 => Some("\\n".into()),
            13 => Some("\\r".into()),
            9 => Some("\\t".into()),
            c if c == quote => {
                result.push(u32::from('\\'));
                result.push(c);
                None
            }
            c if printable(c) => {
                result.push(c);
                None
            }
            point => {
                if point <= 0xff {
                    Some(format!("\\x{point:02x}"))
                } else if point <= 0xffff {
                    Some(format!("\\u{point:04x}"))
                } else {
                    Some(format!("\\U{point:08x}"))
                }
            }
        };
        if let Some(escaped) = escaped {
            result.extend(escaped.chars().map(u32::from));
        }
    }
    result.push(quote);
    result
}

// Also used by the canonical JSON owner, keeping exponent formatting DRY.
pub(crate) fn number(value: &serde_json::Number) -> String {
    let lexical = value.to_string();
    if !lexical.contains(['.', 'e', 'E']) {
        // Arbitrary-precision JSON integers must never pass through f64.
        return lexical;
    }
    let Some(value) = value.as_f64() else {
        return value.to_string();
    };
    float(value)
}

pub(crate) fn float(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value == f64::INFINITY {
        return "inf".into();
    }
    if value == f64::NEG_INFINITY {
        return "-inf".into();
    }
    let rendered = format!("{value:?}");
    let Some((mantissa, exponent)) = rendered.split_once('e') else {
        return rendered;
    };
    let exponent = exponent.parse::<i32>().unwrap_or_default();
    format!("{mantissa}e{exponent:+03}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_json_view_retains_lossless_projection_and_scalar_compatibility() {
        let scalar = serde_json::json!({"nested": [null, false, 0, "text"]});
        let tree = JsonTree::from_response_bytes(br#"{"nested":[null,false,0,"text"]}"#).unwrap();
        for root in [
            PythonJsonValue::Scalar(&scalar),
            PythonJsonValue::Tree(&tree, tree.root()),
        ] {
            assert!(root.is_object());
            assert!(root.truthy());
            let first = root.field("nested").unwrap().first().unwrap();
            assert!(!first.truthy());
            assert!(!first.is_object());
            assert!(first.field("missing").is_none());
            assert!(first.first().is_none());
            assert_eq!(
                root.string_points(),
                python_string(&scalar)
                    .unwrap()
                    .chars()
                    .map(u32::from)
                    .collect::<Vec<_>>()
            );
        }
        let tree = JsonTree::from_response_bytes(
            br#"{"id":"\ud800","number":NaN,"values":[Infinity,-Infinity,-0.0]}"#,
        )
        .unwrap();
        let root = PythonJsonValue::Tree(&tree, tree.root());
        assert_eq!(root.field("id").unwrap().string_points(), [0xd800]);
        assert!(root.field("number").unwrap().truthy());
        assert_eq!(
            root.field("number").unwrap().string_points(),
            "nan".chars().map(u32::from).collect::<Vec<_>>()
        );
        assert_eq!(
            root.field("values").unwrap().string_points(),
            "[inf, -inf, -0.0]"
                .chars()
                .map(u32::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn truthiness_never_materializes_a_view() {
        #[derive(Clone, Copy)]
        struct Cheap(bool);
        impl PythonValueView for Cheap {
            fn truthy(self) -> bool {
                self.0
            }
            fn view(self) -> PythonValueNode<Self> {
                panic!("truthiness must not allocate a view")
            }
        }
        assert!(value_truthy(Cheap(true)));
        assert!(!value_truthy(Cheap(false)));
        assert!(!python_truthy(&Value::Null));
        assert!(python_truthy(&serde_json::json!([false])));
        let array = serde_json::json!([1, {"x": [false, null, "a'b"]}]);
        assert_eq!(
            python_string(&array).unwrap(),
            "[1, {'x': [False, None, \"a'b\"]}]"
        );
        match array.view().map(|value| value) {
            PythonValueNode::Array(values) => assert_eq!(values.len(), 2),
            _ => panic!("mapped array must retain its node kind"),
        }
    }

    #[test]
    fn frozen_unicode_ranges_are_valid_disjoint_and_sorted() {
        let table = semantics();
        assert_eq!(table.printable_ranges.len(), 711);
        for range in &table.printable_ranges {
            assert!(range[0] <= range[1] && range[1] <= 0x10ffff);
        }
        assert!(table
            .printable_ranges
            .windows(2)
            .all(|pair| pair[0][1] < pair[1][0]));
        assert!(table.whitespace.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(strip("\u{001c}x\u{001f}"), "x");
    }

    #[test]
    fn large_json_integers_keep_their_exact_decimal_identity() {
        for decimal in ["18446744073709551617", "-18446744073709551617"] {
            let value: Value = serde_json::from_str(decimal).unwrap();
            assert_eq!(value.to_string(), decimal);
            assert_eq!(python_string(&value).unwrap(), decimal);
        }
    }
}
