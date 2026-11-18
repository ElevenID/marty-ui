//! Stable sorted, ASCII-escaped JSON for platform compatibility contracts.
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn python_canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(value) => python_json_number(value),
        Value::String(value) => python_json_string(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(python_canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(name, value)| format!(
                    "{}:{}",
                    python_json_string(name),
                    python_canonical_json(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn python_json_number(value: &serde_json::Number) -> String {
    crate::python_value::number(value)
}

fn python_json_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{0008}' => encoded.push_str("\\b"),
            '\u{000c}' => encoded.push_str("\\f"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => encoded.push_str(&format!("\\u{:04x}", character as u32)),
            '\u{0020}'..='\u{007e}' => encoded.push(character),
            character if (character as u32) <= 0xffff => {
                encoded.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => {
                let codepoint = character as u32 - 0x1_0000;
                let high = 0xd800 + (codepoint >> 10);
                let low = 0xdc00 + (codepoint & 0x03ff);
                encoded.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        }
    }
    encoded.push('"');
    encoded
}

#[cfg(test)]
mod canonical_json_tests {
    use serde_json::json;

    use super::python_canonical_json;

    #[test]
    fn canonical_numbers_match_python_exponent_threshold_and_padding() {
        let value: serde_json::Value = serde_json::from_str(
            r#"[0.0001,0.00001,0.000001,0.0000001,1000000000000000.0,10000000000000000.0,-0.0]"#,
        )
        .expect("number vector");
        assert_eq!(
            python_canonical_json(&value),
            "[0.0001,1e-05,1e-06,1e-07,1000000000000000.0,1e+16,-0.0]"
        );
    }

    #[test]
    fn canonical_strings_match_python_ascii_escaping() {
        assert_eq!(
            python_canonical_json(&json!({
                "emoji": "😀",
                "label": "café",
                "nested": {"z": 1, "a": "𝄞"},
                "del": "\u{007f}"
            })),
            r#"{"del":"\u007f","emoji":"\ud83d\ude00","label":"caf\u00e9","nested":{"a":"\ud834\udd1e","z":1}}"#
        );
    }
}
