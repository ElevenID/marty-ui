//! Bounded display metadata built from the same policy snapshot as its query.
use crate::{FlowProviderRegistry, PublicVerificationCatalog, PublicVerificationSelection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationPreviewSelection {
    pub catalog_revision: String,
    pub scenario_id: String,
    pub choice_id: String,
}
#[derive(Debug, Serialize)]
pub struct PublicVerificationRequestPreview {
    pub catalog_revision: String,
    pub scenario_id: String,
    pub choice_id: String,
    pub request_digest: String,
    pub claims: Vec<PublicVerificationClaimPreview>,
}
#[derive(Debug, Serialize)]
pub struct PublicVerificationClaimPreview {
    pub name: String,
    pub display_name: String,
    pub required: bool,
    pub purpose: Option<String>,
    pub intent_to_retain: Option<bool>,
    pub constraints: Vec<PublicVerificationConstraintPreview>,
}
#[derive(Debug, Serialize)]
pub struct PublicVerificationConstraintPreview {
    pub kind: String,
    pub value: Option<Value>,
}
#[derive(Debug, Error)]
pub enum PublicVerificationPreviewError {
    #[error(transparent)]
    Catalog(#[from] crate::PublicVerificationCatalogError),
    #[error(transparent)]
    Definition(#[from] crate::DefinedVerificationError),
    #[error(transparent)]
    Presentation(#[from] crate::FlowPresentationRequestError),
    #[error("FLOW.PUBLIC_PREVIEW_UNSUPPORTED")]
    Unsupported,
}

impl PublicVerificationCatalog {
    pub async fn request_preview(
        &self,
        providers: &FlowProviderRegistry,
        selection: &PublicVerificationPreviewSelection,
    ) -> Result<PublicVerificationRequestPreview, PublicVerificationPreviewError> {
        let choice = self.select(&PublicVerificationSelection {
            catalog_revision: selection.catalog_revision.clone(),
            scenario_id: selection.scenario_id.clone(),
            choice_id: selection.choice_id.clone(),
            consent: true,
            example_id: None,
            request_digest: None,
        })?;
        let resolved = crate::resolve_flow_presentation_policy(
            providers,
            &choice.presentation_policy_id,
            self.organization_id(),
        )
        .await?;
        // Digest and requirements must come from one owner GetPolicy response.
        // Separate reads cannot establish which rules produced this preview.
        if !crate::defined_verification::valid_policy_digest(&resolved.policy.configuration_digest)
        {
            return Err(PublicVerificationPreviewError::Unsupported);
        }
        if resolved.policy.configuration_digest != choice.policy_configuration_digest {
            return Err(crate::PublicVerificationCatalogError::ConfigurationChanged.into());
        }
        let artifacts = crate::presentation_request::build_resolved_flow_presentation_request(
            providers, &resolved,
        )
        .await?;
        let mut claims = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        for (index, (requirement, _)) in resolved.requirements.iter().enumerate() {
            let parsed = crate::presentation_request::requested_claims(
                requirement.get("requested_claims"),
                index,
            )?;
            let raw = requirement["requested_claims"]
                .as_array()
                .ok_or(PublicVerificationPreviewError::Unsupported)?;
            for (claim, raw) in parsed.into_iter().zip(raw) {
                if claims.len() >= 16
                    || !crate::public_verification_catalog::bounded_text(&claim.claim_name, 128)
                    || !names.insert(claim.claim_name.clone())
                    || raw.get("predicate_spec").is_some_and(|v| !v.is_null())
                {
                    return Err(PublicVerificationPreviewError::Unsupported);
                }
                let display_name = bounded(raw.get("display_name"), 160)?
                    .unwrap_or_else(|| claim.claim_name.clone());
                let purpose = bounded(raw.get("purpose").or_else(|| raw.get("description")), 400)?;
                let intent_to_retain = match raw.get("intent_to_retain") {
                    Some(Value::Bool(value)) => Some(*value),
                    None | Some(Value::Null) => None,
                    _ => return Err(PublicVerificationPreviewError::Unsupported),
                };
                let constraints = constraints(raw.get("constraints"), &claim.claim_name)?;
                claims.push(PublicVerificationClaimPreview {
                    name: claim.claim_name,
                    display_name,
                    required: claim.required,
                    purpose,
                    intent_to_retain,
                    constraints,
                });
            }
        }
        if claims.is_empty() {
            return Err(PublicVerificationPreviewError::Unsupported);
        }
        Ok(PublicVerificationRequestPreview {
            catalog_revision: selection.catalog_revision.clone(),
            scenario_id: selection.scenario_id.clone(),
            choice_id: selection.choice_id.clone(),
            request_digest: crate::defined_verification::verification_request_digest(&artifacts)?,
            claims,
        })
    }
}
fn bounded(
    value: Option<&Value>,
    max: usize,
) -> Result<Option<String>, PublicVerificationPreviewError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) if crate::public_verification_catalog::bounded_text(s, max) => {
            Ok(Some(s.clone()))
        }
        _ => Err(PublicVerificationPreviewError::Unsupported),
    }
}
fn scalar(value: &Value) -> bool {
    matches!(value, Value::Bool(_) | Value::Number(_))
        || value
            .as_str()
            .is_some_and(|s| s.len() <= 160 && !s.chars().any(char::is_control))
}
fn constraints(
    value: Option<&Value>,
    claim: &str,
) -> Result<Vec<PublicVerificationConstraintPreview>, PublicVerificationPreviewError> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let values = value
        .as_array()
        .filter(|v| v.len() <= 4)
        .ok_or(PublicVerificationPreviewError::Unsupported)?;
    values
        .iter()
        .map(|v| {
            let kind = v["constraint_type"]
                .as_str()
                .ok_or(PublicVerificationPreviewError::Unsupported)?;
            let value = v.get("value").filter(|v| !v.is_null()).cloned();
            if v["claim_name"].as_str() != Some(claim)
                || !matches!(
                    kind,
                    "presence"
                        | "equals"
                        | "not_equals"
                        | "greater_than"
                        | "less_than"
                        | "greater_or_equal"
                        | "less_or_equal"
                        | "in_set"
                        | "not_in_set"
                        | "regex"
                        | "age_over"
                )
                || value.as_ref().is_some_and(|v| {
                    !scalar(v)
                        && !v
                            .as_array()
                            .is_some_and(|a| a.len() <= 8 && a.iter().all(scalar))
                })
            {
                return Err(PublicVerificationPreviewError::Unsupported);
            }
            Ok(PublicVerificationConstraintPreview {
                kind: kind.into(),
                value,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn preview_does_not_approximate_unknown_rules_or_expose_nested_values() {
        let valid = json!([{"claim_name":"age_over_18","constraint_type":"equals","value":true}]);
        assert_eq!(
            constraints(Some(&valid), "age_over_18").unwrap()[0].value,
            Some(json!(true))
        );
        for invalid in [
            json!([{"claim_name":"age_over_18","constraint_type":"custom","value":true}]),
            json!([{"claim_name":"other","constraint_type":"equals","value":true}]),
            json!([{"claim_name":"age_over_18","constraint_type":"equals","value":{"credential":"private"}}]),
            json!([{"claim_name":"age_over_18","constraint_type":"in_set","value":[{"credential":"private"}]}]),
            json!(vec![valid[0].clone(); 5]),
        ] {
            assert!(constraints(Some(&invalid), "age_over_18").is_err());
        }
    }
}
