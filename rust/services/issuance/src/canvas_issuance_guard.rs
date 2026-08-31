use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use tracing::warn;

use crate::credential::{CredentialIssuanceError, CredentialTransaction, IssuerContext};

#[derive(Clone, Debug)]
pub struct CanvasGuardConfig {
    pub enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
    pub evidence_max_age: Duration,
    pub readiness_max_age: Duration,
}

#[derive(Clone, Debug)]
pub struct CanvasGuardSnapshot {
    pub application: Value,
    pub application_template: Value,
    pub platform: Value,
    pub binding: Value,
    pub evidence_facts: Vec<Value>,
    pub policy_set: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct PostgresCanvasIssuanceGuard {
    pool: PgPool,
    config: CanvasGuardConfig,
}

impl PostgresCanvasIssuanceGuard {
    #[must_use]
    pub fn new(pool: PgPool, config: CanvasGuardConfig) -> Self {
        Self { pool, config }
    }

    pub async fn ensure_ready(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<bool, CredentialIssuanceError> {
        match self.load_and_evaluate(transaction, issuer).await {
            Ok(guarded) => Ok(guarded),
            Err(code) => {
                warn!(transaction_id = %transaction.id, denial_code = code, "Canvas pre-signing guard denied credential issuance");
                Err(CredentialIssuanceError::CanvasEligibilityDenied)
            }
        }
    }

    async fn load_and_evaluate(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<bool, &'static str> {
        let Some(application_id) = transaction.application_id.as_deref() else {
            return Ok(false);
        };
        let application = sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_build_object(
                 'id', id,
                 'organization_id', organization_id,
                 'application_template_id', application_template_id,
                 'integration_context', integration_context,
                 'status', status,
                 'issuance_transaction_id', issuance_transaction_id
             )
             FROM issuance_service.applications
             WHERE id = $1",
        )
        .bind(application_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "canvas_guard_dependency_unavailable")?;
        let Some(application) = application else {
            return Ok(false);
        };
        let Some(canvas) = application
            .get("integration_context")
            .and_then(Value::as_object)
            .and_then(|integration| integration.get("canvas"))
            .and_then(Value::as_object)
            .filter(|canvas| has_canvas_marker(canvas))
        else {
            return Ok(false);
        };
        let platform_id = text(canvas.get("canvas_platform_id"));
        let binding_id = text(canvas.get("canvas_program_binding_id"));
        let application_template_id = text(application.get("application_template_id"));
        if platform_id.is_empty() || binding_id.is_empty() || application_template_id.is_empty() {
            return Err("canvas_transaction_context_incomplete");
        }
        let organization_id = transaction.organization_id.as_str();
        let (platform, binding, application_template, evidence_facts) = tokio::try_join!(
            self.load_platform(organization_id, &platform_id),
            self.load_binding(organization_id, &binding_id),
            self.load_application_template(organization_id, &application_template_id),
            self.load_evidence_facts(organization_id, application_id),
        )
        .map_err(|_| "canvas_guard_dependency_unavailable")?;
        let platform = platform.unwrap_or_else(|| json!({}));
        let binding = binding.unwrap_or_else(|| json!({}));
        let application_template = application_template.unwrap_or_else(|| json!({}));
        let policy_set_id = binding
            .get("approval_policy_set_id")
            .or_else(|| application_template.get("approval_policy_set_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        let policy_set = if let Some(policy_set_id) = policy_set_id {
            self.load_policy_set(organization_id, policy_set_id)
                .await
                .map_err(|_| "canvas_guard_dependency_unavailable")?
        } else {
            None
        };
        evaluate_canvas_guard_snapshot(
            transaction,
            issuer,
            &CanvasGuardSnapshot {
                application,
                application_template,
                platform,
                binding,
                evidence_facts,
                policy_set,
            },
            &self.config,
            Utc::now(),
        )?;
        Ok(true)
    }

    async fn load_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
                 'id', id, 'organization_id', organization_id,
                 'canvas_account_id', canvas_account_id,
                 'registration_status', registration_status,
                 'enabled', enabled, 'archived_at', archived_at
             )
             FROM issuance_service.canvas_platforms
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(platform_id)
        .fetch_optional(&self.pool)
        .await
    }

    async fn load_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
                 'id', id, 'organization_id', organization_id,
                 'platform_id', platform_id,
                 'application_template_id', application_template_id,
                 'credential_template_id', credential_template_id,
                 'auto_approve_on_evidence', auto_approve_on_evidence,
                 'evidence_requirements', evidence_requirements,
                 'approval_policy_set_id', approval_policy_set_id,
                 'config_version', config_version,
                 'validated_config_version', validated_config_version,
                 'readiness_checks', readiness_checks,
                 'readiness_validated_at', readiness_validated_at,
                 'activated_at', activated_at, 'archived_at', archived_at,
                 'credential_template_snapshot', credential_template_snapshot,
                 'enabled', enabled
             )
             FROM issuance_service.canvas_program_bindings
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(binding_id)
        .fetch_optional(&self.pool)
        .await
    }

    async fn load_application_template(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
                 'id', id, 'organization_id', organization_id,
                 'credential_template_id', credential_template_id,
                 'approval_policy_set_id', approval_policy_set_id,
                 'status', status
             )
             FROM issuance_service.application_templates
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
    }

    async fn load_evidence_facts(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<Vec<Value>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
                 'id', fact.id, 'organization_id', fact.organization_id,
                 'application_id', fact.application_id,
                 'subject_id', fact.subject_id, 'provider', fact.provider,
                 'fact_type', fact.fact_type, 'scope', fact.scope,
                 'assertion', fact.assertion, 'verification', fact.verification,
                 'source', fact.source, 'requirement_id', fact.requirement_id,
                 'logical_key', fact.logical_key,
                 'source_revision', fact.source_revision,
                 'payload_hash', fact.payload_hash,
                 'effective_at', fact.effective_at,
                 'observed_at', fact.observed_at, 'created_at', fact.created_at
             )
             FROM issuance_service.evidence_fact_heads AS head
             JOIN issuance_service.evidence_facts AS fact
               ON fact.organization_id = head.organization_id
              AND fact.application_id = head.application_id
              AND fact.logical_key = head.logical_key
              AND fact.id = head.fact_id
             WHERE head.organization_id = $1 AND head.application_id = $2
             ORDER BY fact.observed_at, fact.created_at, fact.id",
        )
        .bind(organization_id)
        .bind(application_id)
        .fetch_all(&self.pool)
        .await
    }

    async fn load_policy_set(
        &self,
        organization_id: &str,
        policy_set_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
                 'id', id, 'status', status, 'policy_type', policy_type,
                 'cedar_policies', cedar_policies
             )
             FROM organization_service.policy_sets
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(policy_set_id)
        .fetch_optional(&self.pool)
        .await
    }
}

pub fn evaluate_canvas_guard_snapshot(
    transaction: &CredentialTransaction,
    issuer: &IssuerContext,
    snapshot: &CanvasGuardSnapshot,
    config: &CanvasGuardConfig,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    let application = object(&snapshot.application, "canvas_transaction_context_mismatch")?;
    let canvas = application
        .get("integration_context")
        .and_then(Value::as_object)
        .and_then(|integration| integration.get("canvas"))
        .and_then(Value::as_object);
    if !canvas.is_some_and(has_canvas_marker) {
        return Ok(());
    }
    let canvas = canvas.expect("checked Canvas context");
    if !config.enabled
        || !config
            .pilot_organizations
            .contains(&transaction.organization_id)
    {
        return Err("canvas_rollout_disabled");
    }
    let platform_id = text(canvas.get("canvas_platform_id"));
    let binding_id = text(canvas.get("canvas_program_binding_id"));
    if platform_id.is_empty() || binding_id.is_empty() || transaction.organization_id.is_empty() {
        return Err("canvas_transaction_context_incomplete");
    }

    let platform = object(&snapshot.platform, "canvas_resource_ownership_mismatch")?;
    let binding = object(&snapshot.binding, "canvas_resource_ownership_mismatch")?;
    if text(platform.get("id")) != platform_id
        || text(binding.get("id")) != binding_id
        || text(platform.get("organization_id")) != transaction.organization_id
        || text(binding.get("organization_id")) != transaction.organization_id
    {
        return Err("canvas_resource_ownership_mismatch");
    }
    if !canvas_resources_active(platform, binding) {
        return Err("canvas_resources_inactive");
    }
    if !binding_readiness_is_current(binding, config.readiness_max_age, now) {
        return Err("canvas_readiness_not_current");
    }
    let template = object(
        &snapshot.application_template,
        "canvas_transaction_context_mismatch",
    )?;
    let expected = credential_snapshot(binding, &transaction.organization_id)?;
    if !binding_transaction_matches(
        transaction,
        application,
        canvas,
        platform,
        binding,
        template,
        expected,
    ) {
        return Err("canvas_transaction_context_mismatch");
    }
    if !resolved_issuer_matches(binding, issuer) {
        return Err("canvas_resolved_issuer_context_mismatch");
    }

    let requirements = validated_requirements(binding)?;
    let required = requirements
        .iter()
        .filter(|requirement| requirement.get("required").and_then(Value::as_bool) != Some(false))
        .collect::<Vec<_>>();
    let lti_subject = text(canvas.get("lti_subject"));
    for requirement in required {
        let requirement_id = text(requirement.get("requirement_id"));
        let candidates = snapshot
            .evidence_facts
            .iter()
            .filter(|fact| text(fact.get("requirement_id")) == requirement_id)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err("required_evidence_head_missing_or_ambiguous");
        }
        if !fact_matches(candidates[0], requirement, application, &lti_subject) {
            return Err("required_evidence_head_mismatch");
        }
        if !fact_is_verified_and_fresh(candidates[0], now, config.evidence_max_age) {
            return Err("required_evidence_head_unverified_or_stale");
        }
    }

    let decision = evaluate_canvas_evidence_policy(
        application,
        Some(template),
        Some(binding),
        &requirements,
        &snapshot.evidence_facts,
        snapshot.policy_set.as_ref(),
    )?;
    if decision.get("allowed").and_then(Value::as_bool) != Some(true) {
        return Err("current_evidence_policy_denied");
    }
    Ok(())
}

/// Evaluate the same persisted Canvas ownership, readiness and credential
/// snapshot used by the pre-signing guard before a management approval is
/// allowed to reserve an issuance transaction.
///
/// Evidence and policy are deliberately evaluated by the canonical
/// pre-signing guard after approval. Manual approval only establishes the
/// claimable transaction; it does not bypass the later issuance decision.
pub fn evaluate_canvas_approval_snapshot(
    organization_id: &str,
    application_id: &str,
    snapshot: &CanvasGuardSnapshot,
    config: &CanvasGuardConfig,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    let application = object(&snapshot.application, "canvas_application_not_found")?;
    let canvas = application
        .get("integration_context")
        .and_then(Value::as_object)
        .and_then(|integration| integration.get("canvas"))
        .and_then(Value::as_object)
        .ok_or("canvas_application_not_found")?;
    if !config.enabled || !config.pilot_organizations.contains(organization_id) {
        return Err("canvas_rollout_disabled");
    }
    if text(application.get("id")) != application_id
        || text(application.get("organization_id")) != organization_id
    {
        return Err("canvas_application_not_found");
    }
    if !text(application.get("status")).eq_ignore_ascii_case("pending") {
        return Err("canvas_application_invalid_status");
    }
    let platform_id = text(canvas.get("canvas_platform_id"));
    let binding_id = text(canvas.get("canvas_program_binding_id"));
    if platform_id.is_empty() || binding_id.is_empty() || organization_id.is_empty() {
        return Err("canvas_application_not_ready");
    }
    let platform = object(&snapshot.platform, "canvas_application_not_found")?;
    let binding = object(&snapshot.binding, "canvas_application_not_found")?;
    if text(platform.get("id")) != platform_id
        || text(binding.get("id")) != binding_id
        || text(platform.get("organization_id")) != organization_id
        || text(binding.get("organization_id")) != organization_id
    {
        return Err("canvas_application_not_found");
    }
    if !canvas_resources_active(platform, binding)
        || !binding_readiness_is_current(binding, config.readiness_max_age, now)
    {
        return Err("canvas_application_not_ready");
    }
    let template = object(
        &snapshot.application_template,
        "canvas_application_not_found",
    )?;
    if text(template.get("id")) != text(application.get("application_template_id"))
        || text(template.get("id")) != text(binding.get("application_template_id"))
        || text(template.get("organization_id")) != organization_id
        || !text(template.get("status")).eq_ignore_ascii_case("active")
        || text(template.get("credential_template_id"))
            != text(binding.get("credential_template_id"))
        || text(binding.get("platform_id")) != text(platform.get("id"))
        || text(canvas.get("canvas_account_id")) != text(platform.get("canvas_account_id"))
        || text(canvas.get("application_template_id"))
            != text(binding.get("application_template_id"))
        || text(canvas.get("credential_template_id")) != text(binding.get("credential_template_id"))
        || text(canvas.get("lti_subject")).is_empty()
        || credential_snapshot(binding, organization_id).is_err()
    {
        return Err("canvas_application_not_ready");
    }
    Ok(())
}

fn object<'a>(
    value: &'a Value,
    code: &'static str,
) -> Result<&'a Map<String, Value>, &'static str> {
    value.as_object().ok_or(code)
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').trim().to_owned(),
    }
}

fn optional_text(value: Option<&Value>) -> Option<String> {
    let value = text(value);
    (!value.is_empty()).then_some(value)
}

fn has_canvas_marker(canvas: &Map<String, Value>) -> bool {
    [
        "canvas_platform_id",
        "canvas_program_binding_id",
        "canvas_account_id",
    ]
    .iter()
    .any(|name| !text(canvas.get(*name)).is_empty())
        || text(canvas.get("source"))
            .to_ascii_lowercase()
            .starts_with("canvas")
}

fn canvas_resources_active(platform: &Map<String, Value>, binding: &Map<String, Value>) -> bool {
    platform.get("enabled").and_then(Value::as_bool) == Some(true)
        && platform.get("archived_at").is_none_or(Value::is_null)
        && matches!(
            text(platform.get("registration_status"))
                .to_ascii_lowercase()
                .as_str(),
            "installed" | "verified"
        )
        && binding.get("enabled").and_then(Value::as_bool) == Some(true)
        && binding.get("archived_at").is_none_or(Value::is_null)
        && binding
            .get("activated_at")
            .is_some_and(|value| !value.is_null())
}

pub(crate) fn binding_readiness_is_current(
    binding: &Map<String, Value>,
    max_age: Duration,
    now: DateTime<Utc>,
) -> bool {
    if max_age.is_zero()
        || binding
            .get("validated_config_version")
            .and_then(Value::as_i64)
            != binding.get("config_version").and_then(Value::as_i64)
        || binding
            .get("archived_at")
            .is_some_and(|value| !value.is_null())
        || binding
            .get("credential_template_snapshot")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
    {
        return false;
    }
    let Some(validated_at) = binding
        .get("readiness_validated_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
    else {
        return false;
    };
    let age = now.signed_duration_since(validated_at).num_seconds();
    if age < 0 || u64::try_from(age).map_or(true, |age| age > max_age.as_secs()) {
        return false;
    }
    binding
        .get("readiness_checks")
        .and_then(Value::as_array)
        .filter(|checks| !checks.is_empty())
        .is_some_and(|checks| {
            checks.iter().all(|check| {
                check.as_object().is_some_and(|check| {
                    check.get("blocking").and_then(Value::as_bool) != Some(true)
                        || matches!(
                            text(check.get("status")).to_ascii_lowercase().as_str(),
                            "ready" | "not_applicable"
                        )
                })
            })
        })
}

pub(crate) fn credential_snapshot<'a>(
    binding: &'a Map<String, Value>,
    organization_id: &str,
) -> Result<&'a Map<String, Value>, &'static str> {
    let snapshot = binding
        .get("credential_template_snapshot")
        .and_then(Value::as_object)
        .ok_or("canvas_credential_template_snapshot_mismatch")?;
    if text(snapshot.get("id")) != text(binding.get("credential_template_id"))
        || text(snapshot.get("organization_id")) != organization_id
        || !text(snapshot.get("status")).eq_ignore_ascii_case("active")
    {
        return Err("canvas_credential_template_snapshot_mismatch");
    }
    let credential_type = text(snapshot.get("credential_type"));
    let normalized = credential_type
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if !matches!(
        normalized.as_str(),
        "openbadge" | "openbadgev2" | "openbadgev3" | "openbadgecredential"
    ) || text(snapshot.get("credential_payload_format")).is_empty()
        || text(snapshot.get("revocation_profile_id")).is_empty()
        || !text(snapshot.get("issuer_did")).starts_with("did:")
        || !matches!(
            text(snapshot.get("issuer_algorithm")).as_str(),
            "ES256" | "ES384" | "RS256" | "EdDSA"
        )
    {
        return Err("canvas_credential_template_snapshot_invalid");
    }
    Ok(snapshot)
}

#[allow(clippy::too_many_arguments)]
fn binding_transaction_matches(
    transaction: &CredentialTransaction,
    application: &Map<String, Value>,
    canvas: &Map<String, Value>,
    platform: &Map<String, Value>,
    binding: &Map<String, Value>,
    template: &Map<String, Value>,
    expected: &Map<String, Value>,
) -> bool {
    let validity = expected.get("validity_rules").and_then(Value::as_object);
    let validity_days = validity
        .and_then(|value| value.get("default_validity_days"))
        .and_then(Value::as_i64)
        .unwrap_or(365)
        .max(1);
    let renewal_window_days = validity
        .and_then(|value| value.get("renewal_window_days"))
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .max(1);
    let renewable = validity
        .and_then(|value| value.get("renewable"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    transaction.organization_id == text(application.get("organization_id"))
        && text(application.get("status")).eq_ignore_ascii_case("approved")
        && text(application.get("issuance_transaction_id")) == transaction.id
        && text(application.get("application_template_id"))
            == text(binding.get("application_template_id"))
        && text(template.get("id")) == text(binding.get("application_template_id"))
        && text(template.get("organization_id")) == transaction.organization_id
        && text(template.get("status")).eq_ignore_ascii_case("active")
        && text(template.get("credential_template_id"))
            == text(binding.get("credential_template_id"))
        && transaction.credential_template_id == text(binding.get("credential_template_id"))
        && text(binding.get("platform_id")) == text(platform.get("id"))
        && text(canvas.get("canvas_platform_id")) == text(platform.get("id"))
        && text(canvas.get("canvas_program_binding_id")) == text(binding.get("id"))
        && text(canvas.get("canvas_account_id")) == text(platform.get("canvas_account_id"))
        && text(canvas.get("application_template_id"))
            == text(binding.get("application_template_id"))
        && text(canvas.get("credential_template_id")) == text(binding.get("credential_template_id"))
        && !text(canvas.get("lti_subject")).is_empty()
        && transaction.credential_type.as_deref()
            == Some(text(expected.get("credential_type")).as_str())
        && transaction.credential_payload_format == text(expected.get("credential_payload_format"))
        && transaction.revocation_profile_id.as_deref()
            == Some(text(expected.get("revocation_profile_id")).as_str())
        && transaction.issuer_did.as_deref() == Some(text(expected.get("issuer_did")).as_str())
        && transaction.issuer_algorithm.as_deref()
            == Some(text(expected.get("issuer_algorithm")).as_str())
        && transaction.validity_days == validity_days
        && transaction.renewable == renewable
        && transaction.renewal_window_days == renewal_window_days
        && transaction.wallet_configs == array(expected.get("wallet_configs"))
        && transaction.selective_disclosure_claims
            == string_array(expected.get("selective_disclosure_fields"))
        && transaction.zk_predicate_claims == string_array(expected.get("zk_predicate_claims"))
        && text(transaction.claims.get("_vct")) == text(expected.get("vct"))
        && transaction
            .issuer_profile_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && transaction
            .signing_service_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
}

fn array(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    array(value)
        .iter()
        .map(|value| text(Some(value)))
        .filter(|value| !value.is_empty())
        .collect()
}

pub(crate) fn resolved_issuer_matches(
    binding: &Map<String, Value>,
    issuer: &IssuerContext,
) -> bool {
    let expected = binding
        .get("credential_template_snapshot")
        .and_then(Value::as_object);
    let resolved = issuer.raw_context.as_object();
    let profile = resolved
        .and_then(|value| value.get("issuer_profile"))
        .and_then(Value::as_object);
    let service = resolved
        .and_then(|value| value.get("service"))
        .and_then(Value::as_object);
    let Some((expected, resolved, profile, service)) =
        expected.zip(resolved).zip(profile).zip(service).map(
            |(((expected, resolved), profile), service)| (expected, resolved, profile, service),
        )
    else {
        return false;
    };
    let expected_algorithm = text(expected.get("issuer_algorithm"));
    let actual_algorithm = first_text(&[
        resolved.get("algorithm"),
        profile.get("algorithm"),
        service.get("algorithm"),
    ]);
    let service_algorithms = string_array(service.get("algorithms"));
    let algorithm_matches = if actual_algorithm.is_empty() {
        service_algorithms.contains(&expected_algorithm)
    } else {
        actual_algorithm == expected_algorithm
    };
    text(profile.get("status")).eq_ignore_ascii_case("active")
        && first_text(&[
            resolved.get("organization_id"),
            profile.get("organization_id"),
        ]) == text(expected.get("organization_id"))
        && first_text(&[resolved.get("issuer_did"), profile.get("issuer_did")])
            == text(expected.get("issuer_did"))
        && first_text(&[
            resolved.get("verification_method_id"),
            profile.get("verification_method_id"),
        ])
        .starts_with(&format!("{}#", text(expected.get("issuer_did"))))
        && first_text(&[resolved.get("key_purpose"), profile.get("key_purpose")]) == "vc_jwt_issuer"
        && algorithm_matches
        && resolved.get("public_jwk").is_some_and(Value::is_object)
}

fn first_text(values: &[Option<&Value>]) -> String {
    values
        .iter()
        .map(|value| text(*value))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

pub(crate) fn validated_requirements(
    binding: &Map<String, Value>,
) -> Result<Vec<Value>, &'static str> {
    let requirements = binding
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .filter(|requirements| !requirements.is_empty())
        .ok_or("canvas_requirements_invalid")?;
    let mut ids = BTreeSet::new();
    let mut normalized = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let requirement = requirement
            .as_object()
            .ok_or("canvas_requirements_invalid")?;
        if requirement.keys().any(|key| {
            ![
                "requirement_id",
                "source",
                "fact_type",
                "scope",
                "pass_rule",
                "required",
            ]
            .contains(&key.as_str())
        }) || requirement
            .get("required")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err("canvas_requirements_invalid");
        }
        let id = text(requirement.get("requirement_id"));
        let source = text(requirement.get("source"));
        let fact_type = text(requirement.get("fact_type"));
        let scope = requirement
            .get("scope")
            .and_then(Value::as_object)
            .ok_or("canvas_requirements_invalid")?;
        let pass_rule = requirement
            .get("pass_rule")
            .and_then(Value::as_object)
            .ok_or("canvas_requirements_invalid")?;
        if id.is_empty()
            || !ids.insert(id)
            || !matches!(source.as_str(), "ags_result" | "canvas_rest")
            || !matches!(
                fact_type.as_str(),
                "canvas.assignment_score"
                    | "canvas.quiz_score"
                    | "canvas.course_completion"
                    | "canvas.module_completion"
            )
        {
            return Err("canvas_requirements_invalid");
        }
        let course_id = text(scope.get("course_id"));
        let activity_id = first_text(&[
            scope.get("activity_id"),
            scope.get("assignment_id"),
            scope.get("quiz_id"),
        ]);
        let module_id = text(scope.get("module_id"));
        let line_item_url = first_text(&[scope.get("line_item_url"), scope.get("lineitem_url")]);
        let resource_id = first_text(&[scope.get("resource_id"), scope.get("resourceId")]);
        if course_id.is_empty()
            || (!line_item_url.is_empty() && !line_item_url.starts_with("https://"))
            || pass_rule
                .keys()
                .any(|key| !matches!(key.as_str(), "min_score_percent" | "completed"))
        {
            return Err("canvas_requirements_invalid");
        }
        let min_score = pass_rule.get("min_score_percent").and_then(Value::as_f64);
        let completed = pass_rule.get("completed").and_then(Value::as_bool);
        let is_score = matches!(
            fact_type.as_str(),
            "canvas.assignment_score" | "canvas.quiz_score"
        );
        let valid_rule = if is_score {
            min_score.is_some_and(|score| (0.0..=100.0).contains(&score))
                && !pass_rule.contains_key("completed")
                && match source.as_str() {
                    "canvas_rest" => !activity_id.is_empty(),
                    "ags_result" => !line_item_url.is_empty() || !resource_id.is_empty(),
                    _ => false,
                }
        } else {
            source == "canvas_rest"
                && completed == Some(true)
                && !pass_rule.contains_key("min_score_percent")
                && (fact_type != "canvas.module_completion" || !module_id.is_empty())
        };
        if !valid_rule {
            return Err("canvas_requirements_invalid");
        }
        let mut normalized_scope = Map::new();
        normalized_scope.insert("course_id".to_owned(), Value::String(course_id));
        for (name, value) in [
            ("activity_id", activity_id),
            ("module_id", module_id),
            ("line_item_url", line_item_url),
            ("resource_id", resource_id),
        ] {
            if !value.is_empty() {
                normalized_scope.insert(name.to_owned(), Value::String(value));
            }
        }
        let normalized_rule = if let Some(score) = min_score {
            json!({"min_score_percent": score})
        } else {
            json!({"completed": true})
        };
        normalized.push(json!({
            "requirement_id": text(requirement.get("requirement_id")),
            "source": source,
            "fact_type": fact_type,
            "scope": normalized_scope,
            "pass_rule": normalized_rule,
            "required": requirement.get("required").and_then(Value::as_bool).unwrap_or(true),
        }));
    }
    Ok(normalized)
}

pub(crate) fn evaluate_canvas_evidence_policy(
    application: &Map<String, Value>,
    template: Option<&Map<String, Value>>,
    binding: Option<&Map<String, Value>>,
    requirements: &[Value],
    facts: &[Value],
    policy_set: Option<&Value>,
) -> Result<Value, &'static str> {
    let request = json!({
        "app": {
            "id": text(application.get("id")),
            "organization_id": text(application.get("organization_id")),
            "status": text(application.get("status")),
        },
        "template": template.map(|template| json!({
            "approval_policy_set_id": optional_text(template.get("approval_policy_set_id")),
        })),
        "binding": binding.map(|binding| json!({
            "approval_policy_set_id": optional_text(binding.get("approval_policy_set_id")),
            "auto_approve_on_evidence": binding
                .get("auto_approve_on_evidence")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })),
        "requirements": requirements,
        "facts": facts.iter().map(policy_fact_payload).collect::<Vec<_>>(),
        "policy_set": policy_set,
    });
    let decision = marty_verification::evidence_policy::evaluate_application_evidence_policy_json(
        &request.to_string(),
    )
    .map_err(|_| "current_evidence_policy_denied")?;
    serde_json::from_str(&decision).map_err(|_| "current_evidence_policy_denied")
}

fn fact_matches(
    fact: &Value,
    requirement: &Value,
    application: &Map<String, Value>,
    lti_subject: &str,
) -> bool {
    let Some(fact) = fact.as_object() else {
        return false;
    };
    let Some(requirement) = requirement.as_object() else {
        return false;
    };
    if text(fact.get("organization_id")) != text(application.get("organization_id"))
        || text(fact.get("application_id")) != text(application.get("id"))
        || text(fact.get("subject_id")) != lti_subject
        || text(fact.get("provider")) != "canvas"
        || text(fact.get("requirement_id")) != text(requirement.get("requirement_id"))
        || text(fact.get("fact_type")) != text(requirement.get("fact_type"))
        || text(fact.get("source").and_then(|source| source.get("source")))
            != text(requirement.get("source"))
        || text(fact.get("logical_key")).is_empty()
        || text(fact.get("source_revision")).is_empty()
        || text(fact.get("payload_hash")).is_empty()
    {
        return false;
    }
    let expected = requirement.get("scope").and_then(Value::as_object);
    let actual = fact.get("scope").and_then(Value::as_object);
    expected.zip(actual).is_some_and(|(expected, actual)| {
        expected
            .iter()
            .all(|(key, value)| text(actual.get(key)) == text(Some(value)))
    })
}

fn fact_is_verified_and_fresh(fact: &Value, now: DateTime<Utc>, max_age: Duration) -> bool {
    if max_age.is_zero()
        || !text(
            fact.get("verification")
                .and_then(|value| value.get("status")),
        )
        .eq_ignore_ascii_case("VERIFIED")
    {
        return false;
    }
    let Some(observed) = fact
        .get("observed_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
    else {
        return false;
    };
    let age = now.signed_duration_since(observed).num_seconds();
    age >= 0 && u64::try_from(age).is_ok_and(|age| age <= max_age.as_secs())
}

pub(crate) fn policy_fact_payload(fact: &Value) -> Value {
    let id = text(fact.get("id"));
    let logical_key = optional_text(fact.get("logical_key")).unwrap_or_else(|| id.clone());
    json!({
        "id": id,
        "logical_key": logical_key,
        "provider": text(fact.get("provider")),
        "fact_type": text(fact.get("fact_type")),
        "subject_id": text(fact.get("subject_id")),
        "requirement_id": text(fact.get("requirement_id")),
        "scope": fact.get("scope").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({})),
        "assertion": fact.get("assertion").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({})),
        "verification": fact.get("verification").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({})),
        "source": fact.get("source").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({})),
        "effective_at": fact.get("effective_at"),
        "observed_at": fact.get("observed_at"),
        "created_at": fact.get("created_at"),
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::credential::{CredentialTransactionStatus, IssuerContext};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0)
            .single()
            .expect("test instant")
    }

    fn config() -> CanvasGuardConfig {
        CanvasGuardConfig {
            enabled: true,
            pilot_organizations: BTreeSet::from(["org-1".to_owned()]),
            evidence_max_age: Duration::from_secs(900),
            readiness_max_age: Duration::from_secs(900),
        }
    }

    fn transaction() -> CredentialTransaction {
        CredentialTransaction {
            id: "transaction-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: "credential-template-1".to_owned(),
            revocation_profile_id: Some("status-profile-1".to_owned()),
            renewal_of_credential_id: None,
            applicant_id: None,
            application_id: Some("application-1".to_owned()),
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Authorized,
            pre_authorized_code: "pre-auth".to_owned(),
            nonce: Some("nonce".to_owned()),
            claims: Map::new(),
            credential_type: Some("OpenBadgeCredential".to_owned()),
            selective_disclosure_claims: Vec::new(),
            zk_predicate_claims: Vec::new(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            wallet_configs: Vec::new(),
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
            delivery_mode: "wallet_only".to_owned(),
            issuer_profile_id: Some("issuer-profile-1".to_owned()),
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some("did:web:issuer.example:orgs:org-1".to_owned()),
            issuer_algorithm: Some("ES256".to_owned()),
            signing_service_id: Some("kms-service-1".to_owned()),
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        }
    }

    fn issuer() -> IssuerContext {
        let issuer_did = "did:web:issuer.example:orgs:org-1";
        IssuerContext {
            issuer_profile_id: "issuer-profile-1".to_owned(),
            issuer_did: issuer_did.to_owned(),
            signing_service_id: "kms-service-1".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: Some(format!("{issuer_did}#badge-key-1")),
            public_jwk: Some(json!({"kty":"EC","crv":"P-256","x":"x","y":"y"})),
            certificate_chain: Vec::new(),
            raw_context: json!({
                "organization_id": "org-1",
                "issuer_did": issuer_did,
                "verification_method_id": format!("{issuer_did}#badge-key-1"),
                "key_purpose": "vc_jwt_issuer",
                "algorithm": "ES256",
                "public_jwk": {"kty":"EC","crv":"P-256","x":"x","y":"y"},
                "issuer_profile": {
                    "id": "issuer-profile-1",
                    "status": "active",
                    "organization_id": "org-1",
                    "issuer_did": issuer_did,
                    "verification_method_id": format!("{issuer_did}#badge-key-1"),
                    "key_purpose": "vc_jwt_issuer"
                },
                "service": {"id":"kms-service-1","algorithm":"ES256"}
            }),
        }
    }

    fn snapshot() -> CanvasGuardSnapshot {
        let timestamp = now().to_rfc3339();
        CanvasGuardSnapshot {
            application: json!({
                "id": "application-1",
                "organization_id": "org-1",
                "application_template_id": "application-template-1",
                "status": "approved",
                "issuance_transaction_id": "transaction-1",
                "integration_context": {"canvas": {
                    "source": "canvas_lti_bootstrap",
                    "canvas_account_id": "account-1",
                    "canvas_platform_id": "platform-1",
                    "canvas_program_binding_id": "binding-1",
                    "application_template_id": "application-template-1",
                    "credential_template_id": "credential-template-1",
                    "lti_subject": "opaque-lti-subject"
                }}
            }),
            application_template: json!({
                "id": "application-template-1",
                "organization_id": "org-1",
                "credential_template_id": "credential-template-1",
                "status": "active",
                "approval_policy_set_id": null
            }),
            platform: json!({
                "id": "platform-1",
                "organization_id": "org-1",
                "canvas_account_id": "account-1",
                "registration_status": "installed",
                "enabled": true,
                "archived_at": null
            }),
            binding: json!({
                "id": "binding-1",
                "organization_id": "org-1",
                "platform_id": "platform-1",
                "application_template_id": "application-template-1",
                "credential_template_id": "credential-template-1",
                "auto_approve_on_evidence": false,
                "approval_policy_set_id": null,
                "config_version": 4,
                "validated_config_version": 4,
                "readiness_validated_at": timestamp,
                "readiness_checks": [{"status":"ready","blocking":true}],
                "activated_at": timestamp,
                "archived_at": null,
                "enabled": true,
                "credential_template_snapshot": {
                    "id": "credential-template-1",
                    "organization_id": "org-1",
                    "status": "ACTIVE",
                    "credential_type": "OpenBadgeCredential",
                    "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
                    "revocation_profile_id": "status-profile-1",
                    "issuer_did": "did:web:issuer.example:orgs:org-1",
                    "issuer_algorithm": "ES256"
                },
                "evidence_requirements": [{
                    "requirement_id": "assignment-score",
                    "source": "canvas_rest",
                    "fact_type": "canvas.assignment_score",
                    "scope": {"course_id":"42","activity_id":"9"},
                    "pass_rule": {"min_score_percent":80},
                    "required": true
                }]
            }),
            evidence_facts: vec![json!({
                "id": "fact-1",
                "organization_id": "org-1",
                "application_id": "application-1",
                "subject_id": "opaque-lti-subject",
                "provider": "canvas",
                "fact_type": "canvas.assignment_score",
                "scope": {"course_id":"42","activity_id":"9"},
                "assertion": {"score_percent":92},
                "verification": {"status":"VERIFIED","method":"CANVAS_OAUTH_API_READ"},
                "source": {"source":"canvas_rest"},
                "requirement_id": "assignment-score",
                "logical_key": "platform-1:binding-1:assignment-score:learner-1",
                "source_revision": "revision-1",
                "payload_hash": "payload-1",
                "effective_at": timestamp,
                "observed_at": timestamp,
                "created_at": timestamp
            })],
            policy_set: None,
        }
    }

    #[test]
    fn current_canvas_snapshot_is_authorized_by_the_native_policy() {
        assert_eq!(
            evaluate_canvas_guard_snapshot(
                &transaction(),
                &issuer(),
                &snapshot(),
                &config(),
                now()
            ),
            Ok(())
        );
    }

    #[test]
    fn legacy_fact_projection_matches_python_null_and_object_fallbacks() {
        let projected = policy_fact_payload(&json!({
            "id":"legacy-fact-1",
            "organization_id":"org-1",
            "logical_key":null,
            "provider":"canvas",
            "fact_type":"canvas.course_completion",
            "subject_id":"learner-1",
            "requirement_id":null,
            "scope":["malformed"],
            "assertion":null,
            "verification":"malformed",
            "source":false,
            "effective_at":"2026-07-15T12:00:00+00:00",
            "observed_at":"2026-07-15T12:00:00+00:00",
            "created_at":"2026-07-15T12:00:00+00:00"
        }));
        assert_eq!(projected["logical_key"], "legacy-fact-1");
        assert_eq!(projected["requirement_id"], "");
        for field in ["scope", "assertion", "verification", "source"] {
            assert_eq!(projected[field], json!({}), "{field}");
        }
    }

    #[test]
    fn legacy_reservation_requires_preserved_verified_identity_and_typed_fact_binding_to_claim() {
        let mut missing_identity = snapshot();
        missing_identity.application["integration_context"]["canvas"]
            .as_object_mut()
            .expect("Canvas context")
            .remove("lti_subject");
        assert_denied(
            &transaction(),
            &issuer(),
            &missing_identity,
            &config(),
            "canvas_transaction_context_mismatch",
        );

        let mut unbound_legacy_fact = snapshot();
        unbound_legacy_fact.evidence_facts[0]["requirement_id"] = Value::Null;
        assert_denied(
            &transaction(),
            &issuer(),
            &unbound_legacy_fact,
            &config(),
            "required_evidence_head_missing_or_ambiguous",
        );

        // A legacy update that preserves the verified LTI context and later
        // receives a typed requirement binding remains claimable without any
        // guard relaxation.
        assert_eq!(
            evaluate_canvas_guard_snapshot(
                &transaction(),
                &issuer(),
                &snapshot(),
                &config(),
                now()
            ),
            Ok(())
        );
    }

    #[test]
    fn ordinary_application_is_not_subject_to_canvas_policy() {
        let mut snapshot = snapshot();
        snapshot.application["integration_context"] = json!({"source":"admin"});
        assert_eq!(
            evaluate_canvas_guard_snapshot(&transaction(), &issuer(), &snapshot, &config(), now()),
            Ok(())
        );
    }

    #[test]
    fn rollout_readiness_identity_and_evidence_drift_fail_closed() {
        let mut disabled = config();
        disabled.enabled = false;
        assert_denied(
            &transaction(),
            &issuer(),
            &snapshot(),
            &disabled,
            "canvas_rollout_disabled",
        );

        let mut stale = snapshot();
        stale.binding["config_version"] = json!(5);
        assert_denied(
            &transaction(),
            &issuer(),
            &stale,
            &config(),
            "canvas_readiness_not_current",
        );

        let mut drifted_transaction = transaction();
        drifted_transaction.credential_template_id = "drift".to_owned();
        assert_denied(
            &drifted_transaction,
            &issuer(),
            &snapshot(),
            &config(),
            "canvas_transaction_context_mismatch",
        );

        let mut drifted_issuer = issuer();
        drifted_issuer.raw_context["algorithm"] = json!("ES384");
        assert_denied(
            &transaction(),
            &drifted_issuer,
            &snapshot(),
            &config(),
            "canvas_resolved_issuer_context_mismatch",
        );

        let mut unverified = snapshot();
        unverified.evidence_facts[0]["verification"]["status"] = json!("UNVERIFIED");
        assert_denied(
            &transaction(),
            &issuer(),
            &unverified,
            &config(),
            "required_evidence_head_unverified_or_stale",
        );
    }

    #[test]
    fn private_kms_rotation_behind_the_same_did_is_allowed() {
        let mut issuer = issuer();
        issuer.raw_context["signing_key_reference"] = json!("rotated-private-key");
        issuer.raw_context["issuer_profile"]["signing_key_reference"] =
            json!("rotated-private-key");
        assert_eq!(
            evaluate_canvas_guard_snapshot(&transaction(), &issuer, &snapshot(), &config(), now()),
            Ok(())
        );
    }

    #[test]
    fn evidence_requirement_validation_matches_the_typed_python_boundary() {
        let mut invalid_score = snapshot();
        invalid_score.binding["evidence_requirements"][0]["pass_rule"] =
            json!({"min_score_percent":101});
        assert_denied(
            &transaction(),
            &issuer(),
            &invalid_score,
            &config(),
            "canvas_requirements_invalid",
        );

        let mut invalid_completion = snapshot();
        invalid_completion.binding["evidence_requirements"][0] = json!({
            "requirement_id":"module-complete",
            "source":"ags_result",
            "fact_type":"canvas.module_completion",
            "scope":{"course_id":"42"},
            "pass_rule":{"completed":true},
            "required":true
        });
        assert_denied(
            &transaction(),
            &issuer(),
            &invalid_completion,
            &config(),
            "canvas_requirements_invalid",
        );

        let mut aliases = snapshot();
        aliases.binding["evidence_requirements"][0]["scope"] =
            json!({"course_id":"42","assignment_id":"9"});
        assert_eq!(
            evaluate_canvas_guard_snapshot(&transaction(), &issuer(), &aliases, &config(), now()),
            Ok(())
        );
    }

    fn assert_denied(
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
        snapshot: &CanvasGuardSnapshot,
        config: &CanvasGuardConfig,
        expected: &'static str,
    ) {
        assert_eq!(
            evaluate_canvas_guard_snapshot(transaction, issuer, snapshot, config, now()),
            Err(expected)
        );
    }
}
