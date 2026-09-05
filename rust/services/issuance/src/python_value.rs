//! Shared JSON-value display compatibility with the published Python runtime.
//! Unicode tables are frozen language-neutral observations, not host-version
//! heuristics. No Python process is used by the Rust runtime.
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
    value.trim_matches(|character: char| {
        semantics()
            .whitespace
            .binary_search(&(character as u32))
            .is_ok()
    })
}

fn printable(character: char) -> bool {
    let point = character as u32;
    let ranges = &semantics().printable_ranges;
    let index = ranges.partition_point(|range| range[1] < point);
    ranges.get(index).is_some_and(|range| range[0] <= point)
}

pub(crate) fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

pub(crate) fn python_string(value: &Value) -> Option<String> {
    Some(match value {
        Value::String(value) => value.clone(),
        _ => representation(value),
    })
}

fn representation(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(value) => number(value),
        Value::String(value) => quoted(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(representation)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{}: {}", quoted(key), representation(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn quoted(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::with_capacity(value.len() + 2);
    result.push(quote);
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c == quote => {
                result.push('\\');
                result.push(c);
            }
            c if printable(c) => result.push(c),
            c => {
                let point = c as u32;
                if point <= 0xff {
                    result.push_str(&format!("\\x{point:02x}"));
                } else if point <= 0xffff {
                    result.push_str(&format!("\\u{point:04x}"));
                } else {
                    result.push_str(&format!("\\U{point:08x}"));
                }
            }
        }
    }
    result.push(quote);
    result
}

// Also used by the canonical JSON owner, keeping exponent formatting DRY.
pub(crate) fn number(value: &serde_json::Number) -> String {
    if value.is_i64() || value.is_u64() {
        return value.to_string();
    }
    let Some(value) = value.as_f64() else {
        return value.to_string();
    };
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
}
