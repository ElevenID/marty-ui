//! Apply template-owned claim mappings. Evidence is supplied by a consumer that
//! has already checked current heads, verification, scope and freshness.
//! No network requests, caller-supplied evidence or key custody belongs here.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

pub fn system_values(
    applicant: &Value,
    application: &Value,
    template: &Value,
    now: DateTime<Utc>,
    validity_days: i64,
) -> Map<String, Value> {
    let mut values = Map::new();
    for (namespace, value, fields) in [
        (
            "applicant",
            applicant,
            &["user_id", "email", "given_name", "family_name"][..],
        ),
        (
            "application",
            application,
            &["id", "reference_number", "organization_id"][..],
        ),
        ("template", template, &["name", "description"][..]),
    ] {
        for field in fields {
            if let Some(value) = value.get(field).filter(|value| !value.is_null()) {
                values.insert(format!("{namespace}.{field}"), value.clone());
            }
        }
    }
    values.insert(
        "current.date".into(),
        Value::String(now.date_naive().to_string()),
    );
    values.insert("current.datetime".into(), Value::String(now.to_rfc3339()));
    if let Some(expiry) = chrono::Duration::try_days(validity_days)
        .and_then(|duration| now.checked_add_signed(duration))
    {
        values.insert(
            "validity.expiry_date".into(),
            Value::String(expiry.date_naive().to_string()),
        );
    }
    values
}

/// A configured source always replaces a form fallback. If the configured
/// evidence is unavailable, ambiguous or malformed, the claim stays absent;
/// the consumer's required-claim policy decides whether issuance can proceed.
pub fn apply_rules(
    claims: &mut Map<String, Value>,
    form: &Map<String, Value>,
    rules: &[Value],
    system: &Map<String, Value>,
    verified_evidence: &[Value],
) {
    for rule in rules {
        let Some(name) = rule
            .get("claim_name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        claims.remove(name);
        let Some(config) = rule.get("source_config").and_then(Value::as_object) else {
            continue;
        };
        let value = match rule.get("source").and_then(Value::as_str) {
            Some("FORM_FIELD") => config
                .get("field_id")
                .and_then(Value::as_str)
                .and_then(|field| form.get(field))
                .cloned(),
            Some("SYSTEM") => config
                .get("system_field")
                .and_then(Value::as_str)
                .and_then(|field| {
                    if field == "constant" {
                        config.get("value")
                    } else {
                        system.get(field)
                    }
                })
                .cloned(),
            Some("EVIDENCE_EXTRACTION") => extract_evidence(config, verified_evidence),
            _ => None,
        };
        if let Some(value) = value.filter(|value| !value.is_null()) {
            claims.insert(name.into(), value);
        }
    }
}

pub fn valid_evidence_config(config: &Map<String, Value>) -> bool {
    let selector = ["requirement_id", "fact_type"].iter().any(|key| {
        config
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    });
    let pointer = config
        .get("json_pointer")
        .and_then(Value::as_str)
        .unwrap_or("");
    let root = pointer.split('/').nth(1).unwrap_or("");
    selector
        && pointer.starts_with('/')
        && pointer.len() <= 1024
        && matches!(root, "assertion" | "scope" | "effective_at" | "observed_at")
        && config.get("format").is_none_or(|format| format == "date")
        && config.keys().all(|key| {
            matches!(
                key.as_str(),
                "requirement_id" | "fact_type" | "json_pointer" | "format"
            )
        })
        && ["requirement_id", "fact_type"].iter().all(|key| {
            config
                .get(*key)
                .is_none_or(|value| value.as_str().is_some_and(|value| !value.trim().is_empty()))
        })
}

/// Whether a valid template rule requests one public field of this evidence.
/// Providers use the same selectors as projection when optional authoritative
/// metadata needs a separate read; unrelated rules cannot broaden that read.
pub fn evidence_pointer_requested(rules: &[Value], evidence: &Value, pointer: &str) -> bool {
    rules.iter().any(|rule| {
        rule.get("claim_name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
            && rule.get("source").and_then(Value::as_str) == Some("EVIDENCE_EXTRACTION")
            && rule
                .get("source_config")
                .and_then(Value::as_object)
                .is_some_and(|config| {
                    valid_evidence_config(config)
                        && config.get("json_pointer").and_then(Value::as_str) == Some(pointer)
                        && matches_evidence_selector(config, evidence)
                })
    })
}

fn matches_evidence_selector(config: &Map<String, Value>, evidence: &Value) -> bool {
    ["requirement_id", "fact_type"].iter().all(|key| {
        config
            .get(*key)
            .is_none_or(|expected| evidence.get(*key) == Some(expected))
    })
}

fn extract_evidence(config: &Map<String, Value>, evidence: &[Value]) -> Option<Value> {
    if !valid_evidence_config(config) {
        return None;
    }
    let matches = evidence
        .iter()
        .filter(|fact| matches_evidence_selector(config, fact))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return None;
    }
    let value = matches[0].pointer(config.get("json_pointer")?.as_str()?)?;
    if config.get("format").is_some() {
        DateTime::parse_from_rfc3339(value.as_str()?)
            .ok()
            .map(|time| Value::String(time.with_timezone(&Utc).date_naive().to_string()))
    } else {
        Some(value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_read_uses_the_same_valid_scoped_evidence_selector() {
        let requirement = json!({"requirement_id":"score","fact_type":"canvas.ags_result"});
        let pointer = "/assertion/activity_name";
        let rule = json!({"claim_name":"activity","source":"EVIDENCE_EXTRACTION",
            "source_config":{"requirement_id":"score","fact_type":"canvas.ags_result","json_pointer":pointer}});
        assert!(evidence_pointer_requested(
            std::slice::from_ref(&rule),
            &requirement,
            pointer
        ));
        for changed in [
            json!({"requirement_id":"other","fact_type":"canvas.ags_result"}),
            json!({"requirement_id":"score","fact_type":"canvas.quiz_score"}),
        ] {
            assert!(!evidence_pointer_requested(
                std::slice::from_ref(&rule),
                &changed,
                pointer
            ));
        }
        for (field, value) in [
            ("format", json!("invalid")),
            ("private_selector", json!(true)),
        ] {
            let mut changed = rule.clone();
            changed["source_config"][field] = value;
            assert!(!evidence_pointer_requested(
                &[changed],
                &requirement,
                pointer
            ));
        }
        let mut form = rule;
        form["source"] = json!("FORM_FIELD");
        assert!(!evidence_pointer_requested(&[form], &requirement, pointer));
    }

    #[test]
    fn configured_evidence_replaces_forged_form_and_rejects_ambiguous_heads() {
        let form = json!({"score":1000,"result":{"forged":true}})
            .as_object()
            .unwrap()
            .clone();
        let rules = json!([
            {"claim_name":"score","source":"EVIDENCE_EXTRACTION","source_config":{"fact_type":"canvas.quiz_score","json_pointer":"/assertion/score_percent"}},
            {"claim_name":"result","source":"EVIDENCE_EXTRACTION","source_config":{"requirement_id":"quiz","json_pointer":"/assertion"}}
        ]).as_array().unwrap().clone();
        let fact = json!({"requirement_id":"quiz","fact_type":"canvas.quiz_score","assertion":{"score_percent":0,"completed":false}});
        let mut claims = form.clone();
        apply_rules(
            &mut claims,
            &form,
            &rules,
            &Map::new(),
            std::slice::from_ref(&fact),
        );
        assert_eq!(claims["score"], 0);
        assert_eq!(claims["result"]["completed"], false);
        apply_rules(
            &mut claims,
            &form,
            &rules,
            &Map::new(),
            &[fact.clone(), fact],
        );
        assert!(!claims.contains_key("score") && !claims.contains_key("result"));
    }

    #[test]
    fn extraction_is_limited_to_public_fact_data_and_actual_timestamps() {
        for pointer in [
            "",
            "/source/access_token",
            "/verification",
            "assertion/value",
        ] {
            assert!(!valid_evidence_config(
                json!({"fact_type":"quiz","json_pointer":pointer})
                    .as_object()
                    .unwrap()
            ));
        }
        let config = json!({"fact_type":"quiz","json_pointer":"/effective_at","format":"date"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            extract_evidence(
                &config,
                &[json!({"fact_type":"quiz","effective_at":"2026-10-20T02:00:00Z"})]
            ),
            Some(json!("2026-10-20"))
        );
        assert_eq!(
            extract_evidence(
                &config,
                &[json!({"fact_type":"quiz","effective_at":"made-up"})]
            ),
            None
        );
    }
}
