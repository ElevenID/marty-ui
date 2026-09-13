//! Pure signing diagnostic projections, not production adapter adoption.
//! Frozen HTTP request counts/methods/paths are not manufactured by this test.
//! HTTP ownership, byte decoding, JSON parsing, success parsing and real signing
//! remain separate integration gates. Neither protected signing files nor the
//! library module graph is imported or modified by this isolated target.
#[path = "../src/python_value.rs"]
mod python_value;
#[path = "../src/signing_error_detail.rs"]
mod signing_error_detail;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signing_error_detail::{
    error_detail, operation_response, SigningOperation, SigningResponseAction,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    sync::OnceLock,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextFailure {
    Unreadable,
}

fn reference() -> &'static Value {
    static REFERENCE: OnceLock<Value> = OnceLock::new();
    REFERENCE.get_or_init(|| {
        let raw = include_str!("../../../../contracts/canvas-worker-privacy-reference.json");
        assert_eq!(
            format!("{:x}", Sha256::digest(raw.replace("\r\n", "\n").as_bytes())),
            "2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05"
        );
        let value: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(value["schema"], "marty.canvas-privacy-reference/v1");
        assert_eq!(
            value["source_commit"],
            "d418ac0df283625f43b0c011fb1c72fd7d3013a9"
        );
        assert_eq!(
            value["source_blobs"]["services/issuance/infrastructure/api/signing_context.py"],
            "5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a"
        );
        assert_eq!(
            value["test_blobs"]["tests/unit/test_signing_context_error_bounds.py"],
            "c9e63e4de0cb29d0cc970efcd8cf0f8994408881"
        );
        let cases = value["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 63);
        let ids: BTreeSet<_> = cases
            .iter()
            .map(|case| case["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), cases.len());
        assert!(ids.iter().all(|id| !id.is_empty()));
        for (boundary, count) in [
            ("signing_error_detail", 45),
            ("signing_operation_error", 6),
            ("worker_error", 12),
        ] {
            assert_eq!(value["counts"][boundary], count);
            assert_eq!(
                cases
                    .iter()
                    .filter(|case| case["boundary"] == boundary)
                    .count(),
                count as usize
            );
        }
        value
    })
}

fn operation(value: &str) -> SigningOperation {
    match value {
        "context" => SigningOperation::Context,
        "resolve" => SigningOperation::Resolve,
        "sign" => SigningOperation::Sign,
        _ => panic!("frozen signing operation is not in the closed set"),
    }
}

fn detail(payload: Option<&Value>, body: &str) -> String {
    error_detail(
        payload,
        || Ok::<_, TextFailure>(body.to_owned()),
        "Service Unavailable",
    )
    .unwrap()
}

#[test]
fn all_45_frozen_detail_observations_match_exact_strings() {
    let mut visited = 0;
    for case in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] == "signing_error_detail")
    {
        let body = case["input"]["body"].as_str().unwrap();
        assert_eq!(case["input"]["status"], 503);
        let payload: Option<Value> = serde_json::from_str(body).ok();
        let text_reads = Cell::new(0);
        let actual = error_detail(
            payload.as_ref(),
            || {
                text_reads.set(text_reads.get() + 1);
                Ok::<_, TextFailure>(body.to_owned())
            },
            "Service Unavailable",
        )
        .unwrap();
        assert_eq!(
            actual,
            case["observed"].as_str().unwrap(),
            "frozen detail projection differs"
        );
        assert_eq!(
            text_reads.get(),
            1,
            "text must be evaluated even for JSON detail"
        );
        assert!(actual.chars().count() <= 500);
        visited += 1;
    }
    assert_eq!(visited, 45);
}

#[test]
fn all_six_frozen_operation_error_messages_match_without_claiming_http_execution() {
    let mut visited = BTreeSet::new();
    for case in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] == "signing_operation_error")
    {
        let body = case["input"]["body"].as_str().unwrap();
        let name = case["input"]["operation"].as_str().unwrap();
        let status = u16::try_from(case["input"]["status"].as_u64().unwrap()).unwrap();
        assert!(matches!(status, 401 | 503));
        assert!(visited.insert((name, status)));
        let events = RefCell::new(Vec::new());
        let actual = operation_response(
            operation(name),
            status,
            || {
                events.borrow_mut().push("json");
                serde_json::from_str(body).ok()
            },
            || {
                events.borrow_mut().push("text");
                Ok::<_, TextFailure>(body.to_owned())
            },
            if status == 401 {
                "Unauthorized"
            } else {
                "Service Unavailable"
            },
        )
        .unwrap();
        assert_eq!(case["observed"]["error_class"], "RuntimeError");
        assert_eq!(
            actual,
            SigningResponseAction::Error(case["observed"]["message"].as_str().unwrap().to_owned())
        );
        assert_eq!(
            *events.borrow(),
            if status == 401 {
                vec![]
            } else {
                vec!["json", "text"]
            }
        );
        // Request fields remain frozen metadata; the pure helper performs no HTTP.
    }
    assert_eq!(visited.len(), 6);
}

#[test]
fn whitespace_first_detail_does_not_fall_through_to_another_json_key() {
    for whitespace in ["   ", "\u{001c}\t\u{001f}"] {
        let payload =
            json!({"detail":whitespace,"error_description":"wrong-second","error":"wrong-third"});
        assert_eq!(detail(Some(&payload), "  raw fallback  "), "raw fallback");
        let raw_json = serde_json::to_string(&payload).unwrap();
        assert_eq!(detail(Some(&payload), &raw_json), raw_json);
    }
    let empty = json!({"detail":"","error_description":" second ","error":"third"});
    assert_eq!(detail(Some(&empty), "fallback"), "second");
}

#[test]
fn falsey_selection_preserves_the_unfiltered_final_operand_and_supported_types() {
    for falsey in [
        Value::Null,
        json!(false),
        json!(0),
        json!(-0.0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        let payload = json!({"detail":falsey,"error_description":"second","error":"third"});
        assert_eq!(detail(Some(&payload), "fallback"), "second");
    }
    assert_eq!(
        detail(
            Some(&json!({"detail":{},"error_description":false,"error":{}})),
            "fallback"
        ),
        "{}"
    );
    assert_eq!(
        detail(
            Some(&json!({"detail":{},"error_description":{}})),
            "fallback"
        ),
        "fallback"
    );
    for truthy_unsupported in [json!(true), json!(1), json!(["not-a-dict"])] {
        let payload = json!({"detail":truthy_unsupported,"error_description":"wrong-second"});
        assert_eq!(detail(Some(&payload), "original text"), "original text");
    }
    for root in [
        json!([]),
        json!([{"detail":"not-top-level"}]),
        json!(true),
        json!(7),
        json!("not-a-map"),
    ] {
        assert_eq!(detail(Some(&root), "  original text  "), "original text");
    }
}

#[test]
fn text_read_is_eager_and_its_error_survives_a_valid_json_detail() {
    for payload in [
        json!({"detail":"already-known"}),
        json!({"detail":{"reason":"known"}}),
    ] {
        let calls = Cell::new(0);
        let result = error_detail(
            Some(&payload),
            || {
                calls.set(calls.get() + 1);
                Err::<String, _>(TextFailure::Unreadable)
            },
            "unused reason",
        );
        assert_eq!(result, Err(TextFailure::Unreadable));
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn error_operations_evaluate_json_then_text_once_and_preserve_text_failures() {
    for parsed in [None, Some(json!({"detail":"known"}))] {
        let events = RefCell::new(Vec::new());
        let result = operation_response(
            SigningOperation::Sign,
            503,
            || {
                events.borrow_mut().push("json");
                parsed
            },
            || {
                events.borrow_mut().push("text");
                Err::<String, _>(TextFailure::Unreadable)
            },
            "Service Unavailable",
        );
        assert_eq!(result, Err(TextFailure::Unreadable));
        assert_eq!(*events.borrow(), vec!["json", "text"]);
    }
}

#[test]
fn status_short_circuits_never_evaluate_either_response_supplier() {
    for operation in [
        SigningOperation::Context,
        SigningOperation::Resolve,
        SigningOperation::Sign,
    ] {
        for status in [200, 204, 302, 399, 401, 404] {
            if operation == SigningOperation::Sign && status == 404 {
                continue;
            }
            let expected = match status {
                401 => SigningResponseAction::Error(
                    "Internal signing API rejected the service API key".into(),
                ),
                404 => SigningResponseAction::NotFound,
                _ => SigningResponseAction::Continue,
            };
            let actual = operation_response(
                operation,
                status,
                || -> Option<Value> { panic!("short circuit evaluated JSON") },
                || -> Result<String, TextFailure> { panic!("short circuit evaluated text") },
                "unused reason",
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn operation_prefix_and_status_are_outside_the_detail_character_bound() {
    for (operation, prefix) in [
        (
            SigningOperation::Context,
            "DID issuer context resolution failed",
        ),
        (SigningOperation::Resolve, "Issuer DID resolution failed"),
        (SigningOperation::Sign, "DID-mediated signing failed"),
    ] {
        for status in [400, 429, 500, 599] {
            let supplied = format!("{}synthetic-tail", "x".repeat(500));
            let result = operation_response(
                operation,
                status,
                || Some(json!({"detail":supplied})),
                || Ok::<_, TextFailure>("unused fallback".into()),
                "unused reason",
            )
            .unwrap();
            assert_eq!(
                result,
                SigningResponseAction::Error(format!(
                    "{prefix} (HTTP {status}): {}",
                    "x".repeat(500)
                ))
            );
        }
    }
    let calls = RefCell::new(Vec::new());
    let sign_missing = operation_response(
        SigningOperation::Sign,
        404,
        || {
            calls.borrow_mut().push("json");
            None
        },
        || {
            calls.borrow_mut().push("text");
            Ok::<_, TextFailure>(" ".into())
        },
        "Not Found",
    )
    .unwrap();
    assert_eq!(
        sign_missing,
        SigningResponseAction::Error("DID-mediated signing failed (HTTP 404): Not Found".into())
    );
    assert_eq!(*calls.borrow(), vec!["json", "text"]);
}

#[test]
fn python_dictionary_representation_preserves_order_types_quotes_and_unicode() {
    let payload: Value = serde_json::from_str(r#"{"detail":{"z":true,"a":null,"quote":"it's","line":"x\n","control":"\u001c","emoji":"🙂","nested":[false,null],"integer":18446744073709551617}}"#).unwrap();
    assert_eq!(detail(Some(&payload), "unused fallback"),
        "{'z': True, 'a': None, 'quote': \"it's\", 'line': 'x\\n', 'control': '\\x1c', 'emoji': '🙂', 'nested': [False, None], 'integer': 18446744073709551617}");
}

#[test]
fn truncation_counts_unicode_scalars_not_bytes_or_graphemes() {
    for expected in ["é🙂".repeat(250), "e\u{0301}".repeat(250)] {
        assert_eq!(expected.chars().count(), 500);
        assert!(expected.len() > 500);
        let longer = format!("\u{001c} {expected}synthetic-tail \u{001f}");
        assert_eq!(detail(Some(&json!({"detail":longer})), "unused"), expected);
        assert_eq!(detail(None, &longer), expected);
    }
    let non_whitespace = json!({"detail":"\u{200b}x\u{200b}"});
    assert_eq!(detail(Some(&non_whitespace), "unused"), "\u{200b}x\u{200b}");
}

#[test]
fn text_fallback_strips_python_whitespace_but_reason_phrase_is_not_trimmed() {
    assert_eq!(detail(None, "\u{001c} text \u{001f}"), "text");
    let reason = "  keep reason whitespace  ";
    assert_eq!(
        error_detail(
            None,
            || Ok::<_, TextFailure>("\u{001c}\t\u{001f}".into()),
            reason
        )
        .unwrap(),
        reason
    );
    assert_eq!(
        error_detail(None, || Ok::<_, TextFailure>(String::new()), "").unwrap(),
        ""
    );
    let long_reason = format!("{}tail", "é🙂".repeat(250));
    assert_eq!(
        error_detail(None, || Ok::<_, TextFailure>(String::new()), &long_reason).unwrap(),
        "é🙂".repeat(250)
    );
}
