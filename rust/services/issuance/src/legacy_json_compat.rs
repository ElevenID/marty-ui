//! Frozen legacy JSON conversions used by Issuance adapters.
//! Numeric fallback and untrimmed strings retain their existing caller contract.

use serde_json::Value;

pub(crate) fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

pub(crate) fn untrimmed_json_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{json_truthy, untrimmed_json_text};
    use serde_json::{json, Value};

    #[test]
    fn legacy_truthiness_preserves_empty_and_whitespace_boundaries() {
        for value in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(-0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(!json_truthy(&value), "unexpected truthy value: {value}");
        }
        for value in [
            json!(true),
            json!(-1),
            json!(1.5),
            json!(" "),
            json!("\t\n"),
            json!([false]),
            json!({"x": null}),
        ] {
            assert!(json_truthy(&value), "unexpected falsy value: {value}");
        }
    }

    #[test]
    fn unavailable_float_conversion_keeps_the_legacy_fallback() {
        for raw in ["1e400", "-1e400"] {
            let value: Value = serde_json::from_str(raw).unwrap();
            assert!(value.is_number());
            assert!(value.as_f64().is_none());
            assert!(!json_truthy(&value));
            assert!(crate::python_value::python_truthy(&value));
        }
        let finite: Value = serde_json::from_str("1e308").unwrap();
        assert!(json_truthy(&finite));
        let underflow: Value = serde_json::from_str("1e-400").unwrap();
        assert!(!json_truthy(&underflow));
    }

    #[test]
    fn legacy_text_preserves_original_string_bytes() {
        for text in [
            "",
            "  text  ",
            "\"quoted\"",
            "\t\n",
            "\u{0085}\u{2003}text\u{2003}",
            "caf\u{e9}/\u{96ea}",
            "x\0y",
        ] {
            assert_eq!(untrimmed_json_text(Some(&json!(text))), text);
        }
        assert_eq!(untrimmed_json_text(None), "");
        assert_eq!(untrimmed_json_text(Some(&Value::Null)), "");
    }

    #[test]
    fn legacy_text_retains_nonstring_json_formatting() {
        for (value, expected) in [
            (json!(true), "true"),
            (json!(false), "false"),
            (json!(-42), "-42"),
            (json!([true, " a "]), "[true,\" a \"]"),
            (json!({"x": " a "}), "{\"x\":\" a \"}"),
        ] {
            assert_eq!(untrimmed_json_text(Some(&value)), expected);
        }
    }
}
