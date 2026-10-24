//! One projection for manual/automatic approval, offer refresh and pre-signing.
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::canvas_issuance_guard::{
    fact_is_verified_and_fresh, fact_matches, validated_requirements,
};

pub(crate) fn project_canvas_claims(
    application: &Map<String, Value>,
    template: &Map<String, Value>,
    binding: &Map<String, Value>,
    current_facts: &[Value],
    claims_time: DateTime<Utc>,
    now: DateTime<Utc>,
    evidence_max_age: Duration,
) -> Result<Map<String, Value>, &'static str> {
    let form = application
        .get("form_data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let rules = template
        .get("claim_collection_rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rules.is_empty() {
        return Ok(form);
    }
    let canvas = application
        .get("integration_context")
        .and_then(|value| value.get("canvas"))
        .and_then(Value::as_object)
        .ok_or("canvas_claim_context_missing")?;
    let subject = canvas
        .get("lti_subject")
        .and_then(Value::as_str)
        .unwrap_or("");
    let requirements = validated_requirements(binding)?;
    let mut trusted = Vec::new();
    for requirement in &requirements {
        let candidates = current_facts
            .iter()
            .filter(|fact| fact.get("requirement_id") == requirement.get("requirement_id"))
            .collect::<Vec<_>>();
        if candidates.len() == 1
            && fact_matches(candidates[0], requirement, application, subject)
            && fact_is_verified_and_fresh(candidates[0], now, evidence_max_age)
        {
            trusted.push(candidates[0].clone());
        }
    }
    let mut system = marty_claim_collection::system_values(
        &canvas
            .get("learner_identity")
            .cloned()
            .unwrap_or_else(|| json!({})),
        &Value::Object(application.clone()),
        &Value::Object(template.clone()),
        claims_time,
        template
            .get("application_validity_days")
            .and_then(Value::as_i64)
            .unwrap_or(30),
    );
    if let Some(name) = canvas
        .get("canvas_context")
        .and_then(|value| value.get("title").or_else(|| value.get("label")))
    {
        system.insert("canvas.course_name".into(), name.clone());
    }
    let mut claims = Map::new();
    for field in template
        .get("form_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = field
            .get("field_id")
            .or_else(|| field.get("name"))
            .and_then(Value::as_str)
        {
            if !name.starts_with('_') {
                if let Some(value) = form.get(name) {
                    claims.insert(name.into(), value.clone());
                }
            }
        }
    }
    marty_claim_collection::apply_rules(&mut claims, &form, &rules, &system, &trusted);
    Ok(claims)
}
