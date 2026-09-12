//! Translate serde syntax diagnostics at the published Python HTTP boundary.
//! Serde remains the JSON parser; this module only renders error positions and
//! messages. Positions are Unicode character offsets, not UTF-8 byte offsets.

use serde_json::{json, Value};

pub(crate) fn diagnostic(bytes: &[u8], error: &serde_json::Error) -> Value {
    let source = String::from_utf8_lossy(bytes);
    let message = error.to_string();
    let category = message.split(" at line ").next().unwrap_or(&message);
    let line_start = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .take(error.line().saturating_sub(1))
        .last()
        .map_or(0, |(index, _)| index + 1);
    let mut position = (line_start + error.column().saturating_sub(1)).min(bytes.len());
    let description = match category {
        "EOF while parsing a value" => {
            position = bytes.len();
            "Expecting value"
        }
        "EOF while parsing an object" => {
            position = bytes.len();
            if source.trim_end().ends_with(['{', ',']) {
                "Expecting property name enclosed in double quotes"
            } else {
                "Expecting ',' delimiter"
            }
        }
        "EOF while parsing a list" => {
            position = bytes.len();
            "Expecting ',' delimiter"
        }
        "EOF while parsing a string" => {
            let mut opening = None;
            let mut escaped = false;
            for (index, byte) in bytes.iter().enumerate() {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' && opening.is_some() {
                    escaped = true;
                } else if *byte == b'"' {
                    opening = if opening.is_some() { None } else { Some(index) };
                }
            }
            position = opening.unwrap_or(position);
            "Unterminated string starting at"
        }
        "key must be a string" => "Expecting property name enclosed in double quotes",
        "trailing comma" if bytes.get(position) == Some(&b'}') => {
            "Expecting property name enclosed in double quotes"
        }
        "trailing comma" | "expected value" => "Expecting value",
        "trailing characters" => "Extra data",
        "invalid escape" => {
            position = position.saturating_sub(1);
            "Invalid \\escape"
        }
        "expected `:`" => "Expecting ':' delimiter",
        "expected `,` or `}`" | "expected `,` or `]`" => "Expecting ',' delimiter",
        "control character (\\u0000-\\u001F) found while parsing a string" => {
            "Invalid control character at"
        }
        other => other,
    };
    let characters = String::from_utf8_lossy(&bytes[..position]).chars().count();
    json!({"type":"json_invalid", "loc":["body",characters],
        "msg":"JSON decode error", "input":{}, "ctx":{"error":description}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_published_syntax_diagnostics() {
        let cases: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-review-input-scenarios.json"
        ))
        .unwrap();
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-review-input-oracle.json"
        ))
        .unwrap();
        let mut checked = 0;
        for (case, observation) in cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .zip(oracle["observations"].as_array().unwrap())
        {
            if observation["body"]["detail"][0]["type"] != "json_invalid" {
                continue;
            }
            let bytes = case["raw_body"].as_str().unwrap().as_bytes();
            let error = serde_json::from_slice::<Value>(bytes).unwrap_err();
            assert_eq!(
                diagnostic(bytes, &error),
                observation["body"]["detail"][0],
                "{}; serde={error}",
                case["name"]
            );
            checked += 1;
        }
        assert_eq!(checked, 9);
    }
}
