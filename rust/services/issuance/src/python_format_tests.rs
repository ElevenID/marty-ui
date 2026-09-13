use super::*;
use crate::{
    canvas_credentials_protocol::quote_identifier,
    lossless_json_tree::{JsonNode, JsonTree},
    python_value::strip_points,
};
use serde_json::Value;

fn member(tree: &JsonTree, id: usize, key: &str) -> usize {
    let JsonNode::Object(fields) = tree.node(id) else {
        panic!("object required")
    };
    fields
        .iter()
        .find(|(name, _)| name.as_scalar() == Some(key))
        .unwrap()
        .1
}
fn maybe_member(tree: &JsonTree, id: usize, key: &str) -> Option<usize> {
    let JsonNode::Object(fields) = tree.node(id) else {
        panic!("object required")
    };
    fields
        .iter()
        .find(|(name, _)| name.as_scalar() == Some(key))
        .map(|(_, id)| *id)
}
fn value_text(tree: &JsonTree, id: usize) -> Option<PythonText> {
    match tree.node(id) {
        JsonNode::Scalar(Value::Null) => None,
        JsonNode::Scalar(Value::String(value)) => Some(value.clone().into()),
        JsonNode::Text(value) => Some(value.clone()),
        _ => panic!("text or null required"),
    }
}
fn scalar(tree: &JsonTree, id: usize) -> String {
    value_text(tree, id).unwrap().into_scalar().unwrap()
}
fn array(tree: &JsonTree, id: usize) -> &[usize] {
    let JsonNode::Array(values) = tree.node(id) else {
        panic!("array required")
    };
    values
}
fn run(template: &str, value: &str) -> Result<PythonText> {
    format_named(
        &template.to_owned().into(),
        &[("value", value.to_owned().into())],
    )
}

#[test]
fn every_frozen_pairwise_string_case_matches_without_capability_filtering() {
    let tree = JsonTree::from_json_bytes(include_bytes!(
        "../../../../contracts/python-named-format-reference.json"
    ))
    .unwrap();
    let rows = array(&tree, member(&tree, tree.root(), "observations"));
    assert_eq!(rows.len(), 777);
    let JsonNode::Object(fields) = tree.node(member(&tree, tree.root(), "fields")) else {
        panic!("fixed named string fields required");
    };
    let fields: Vec<_> = fields
        .iter()
        .map(|(key, id)| (key.as_scalar().unwrap(), value_text(&tree, *id).unwrap()))
        .collect();
    let mut mismatches = Vec::new();
    let mut successful = 0;
    for (index, &row) in rows.iter().enumerate() {
        let id = scalar(&tree, member(&tree, row, "id"));
        assert_eq!(id, format!("format-{index:04}"));
        let template = value_text(&tree, member(&tree, row, "template")).unwrap();
        let actual = format_named(&template, &fields);
        let expected = if let Some(value) = maybe_member(&tree, row, "value") {
            successful += 1;
            Ok(value_text(&tree, value).unwrap())
        } else {
            let error = member(&tree, row, "error");
            Err((
                scalar(&tree, member(&tree, error, "type")),
                value_text(&tree, member(&tree, error, "message")).unwrap(),
            ))
        };
        let actual =
            actual.map_err(|error| (format!("{:?}", error.kind()), error.message().clone()));
        if actual != expected {
            // Entirely synthetic fixed fixture text; no operator templates.
            mismatches.push(format!(
                "{id} template={template:?}: actual={actual:?}; expected={expected:?}"
            ));
        }
    }
    assert_eq!(successful, 125);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn candidate_matches_every_eligible_frozen_template_without_claiming_wrapper_adoption() {
    let cases = JsonTree::from_json_bytes(include_bytes!(
        "../../../../contracts/canvas-url-template-scenarios.json"
    ))
    .unwrap();
    let reference = JsonTree::from_json_bytes(include_bytes!(
        "../../../../contracts/canvas-url-template-python-reference.json"
    ))
    .unwrap();
    let inputs = array(&cases, member(&cases, cases.root(), "cases"));
    let rows = array(
        &reference,
        member(&reference, reference.root(), "observations"),
    );
    assert_eq!(inputs.len(), 123);
    assert_eq!(rows.len(), inputs.len());
    let (mut formatted, mut defaults, mut before_format) = (0, 0, 0);
    for (&input, &row) in inputs.iter().zip(rows) {
        let name = scalar(&cases, member(&cases, input, "id"));
        assert_eq!(name, scalar(&reference, member(&reference, row, "id")));
        let template = value_text(&cases, member(&cases, input, "template"));
        let Some(template) = template else {
            defaults += 1;
            continue;
        };
        let points: Vec<_> = template.codepoints().collect();
        let template = text(strip_points(&points).iter().copied());
        if template.codepoints().next().is_none() {
            defaults += 1;
            continue;
        }
        let operation = scalar(&cases, member(&cases, input, "operation"));
        let args = member(&cases, input, "arguments");
        let mut fields = vec![(
            "api_base_url",
            value_text(&cases, member(&cases, args, "api_base_url")).unwrap(),
        )];
        let keys = if operation == "revoke" {
            vec!["external_credential_id"]
        } else {
            vec!["scope", "badgeclass_id", "issuer_id"]
        };
        let mut quote_failure = false;
        for key in keys {
            let value = value_text(&cases, member(&cases, args, key));
            if value.is_none() && operation == "assertion" && key == "badgeclass_id" {
                quote_failure = true;
                break;
            }
            let value = value.unwrap_or_default();
            let Some(value) = value.as_scalar() else {
                quote_failure = true;
                break;
            };
            fields.push((key, quote_identifier(value).into()));
        }
        if quote_failure {
            assert!(maybe_member(&reference, row, "error").is_some(), "{name}");
            before_format += 1;
            continue;
        }
        let actual = format_named(&template, &fields);
        if let Some(url) = maybe_member(&reference, row, "url") {
            assert_eq!(actual, Ok(value_text(&reference, url).unwrap()), "{name}");
        } else {
            let expected = member(&reference, row, "error");
            let error = actual.expect_err(&name);
            assert_eq!(
                format!("{:?}", error.kind()),
                scalar(&reference, member(&reference, expected, "type")),
                "{name}"
            );
            assert_eq!(
                error.message(),
                &value_text(&reference, member(&reference, expected, "message")).unwrap(),
                "{name}"
            );
        }
        formatted += 1;
    }
    // These exclusions are actual wrapper defaults/eager quote errors, never
    // unsupported formatter behavior filtered out of the successful count.
    assert_eq!((formatted, defaults, before_format), (88, 28, 7));
}

#[test]
fn actual_builtin_inventory_distinguishes_absent_attributes_from_unmodeled_capabilities() {
    let tree = JsonTree::from_json_bytes(include_bytes!(
        "../../../../contracts/python-string-attribute-inventory.json"
    ))
    .unwrap();
    let absent = member(&tree, tree.root(), "absent");
    for (owner, prefix) in [
        ("str_instance", "value"),
        ("str_type", "value.__class__"),
        ("type_type", "value.__class__.__class__"),
    ] {
        for &row in array(&tree, member(&tree, absent, owner)) {
            let name = value_text(&tree, member(&tree, row, "name")).unwrap();
            let mut template = points(&format!("{{{prefix}."));
            template.extend(name.codepoints());
            template.push(125);
            let error =
                format_named(&text(template), &[("value", "x".to_owned().into())]).unwrap_err();
            assert_eq!(error.kind(), PythonFormatErrorKind::AttributeError);
            assert_eq!(
                error.message(),
                &value_text(&tree, member(&tree, row, "message")).unwrap()
            );
        }
    }
    for template in [
        "{value.upper}",
        "{value.__class__.__dict__}",
        "{value.__class__.__mro__[0]}",
        "{value.__doc__}",
    ] {
        assert_eq!(
            run(template, "x").unwrap_err().kind(),
            PythonFormatErrorKind::UnmodeledCapability
        );
    }
    assert_eq!(
        run(
            "{value.__class__.__name__}:{value.__class__.__module__}",
            "x"
        )
        .unwrap()
        .as_scalar(),
        Some("str:builtins")
    );
}

#[test]
fn codepoint_formatting_and_error_diagnostics_never_use_lossy_scalar_fallbacks() {
    let value = text([0xd800, 0x1f600, 0x61]);
    let actual =
        format_named(&"{value:.2}".to_owned().into(), &[("value", value.clone())]).unwrap();
    assert_eq!(actual.codepoints().collect::<Vec<_>>(), [0xd800, 0x1f600]);
    let actual = format_named(&"{value!a}".to_owned().into(), &[("value", value)]).unwrap();
    assert_eq!(actual.as_scalar(), Some("'\\ud800\\U0001f600a'"));
    let error = run("{private-operator-canary}", "x").unwrap_err();
    assert!(!format!("{error:?}").contains("private-operator-canary"));
    assert!(!format!("{error}").contains("private-operator-canary"));
    assert_eq!(
        error.message().as_scalar(),
        Some("'private-operator-canary'")
    );
}

#[test]
fn decimal_grammar_and_resource_bounds_are_explicit_without_clamping() {
    assert_eq!(run("{value:>٤}", "x").unwrap().as_scalar(), Some("   x"));
    assert_eq!(run("{value[٠]}", "x").unwrap().as_scalar(), Some("x"));
    assert_eq!(
        run("{value: 4}", "x").unwrap_err().message().as_scalar(),
        Some("Space not allowed in string format specifier")
    );
    assert_eq!(run("{value:0>4}", "x").unwrap().as_scalar(), Some("000x"));
    assert_eq!(
        run("{value:999999999999999999999999999}", "x")
            .unwrap_err()
            .kind(),
        PythonFormatErrorKind::ValueError
    );
    // A Vec<u32> cannot reserve this many elements on any supported target;
    // report resource failure instead of inventing a Python grammar error.
    let failure = run(&format!("{{value:{}}}", isize::MAX), "x").unwrap_err();
    assert_eq!(failure.kind(), PythonFormatErrorKind::ResourceFailure);
}
