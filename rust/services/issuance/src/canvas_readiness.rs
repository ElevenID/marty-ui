//! Pure, fail-closed readiness policy for portable Canvas program bindings.
//!
//! Network calls and persistence stay in application adapters. This module
//! consumes their bounded projections so platform readiness, explicit
//! validation, activation, launch guards, and signing guards can share one
//! deterministic policy.

use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    canvas_binding_domain::{CanvasApplicationTemplateProjection, CanvasProgramBindingRecord},
    canvas_management::{
        CanvasEvidenceFactType, CanvasEvidenceRequirementInput, CanvasEvidenceSource,
        ValidateCanvasRequest,
    },
    canvas_management_domain::CanvasPlatformRecord,
    canvas_oauth::scopes_for_capabilities,
};

const AGS_RESULT_READ_SCOPE: &str = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly";
const SUPPORTED_ISSUER_ALGORITHMS: &[&str] = &["ES256", "ES384", "RS256", "EdDSA"];
const SUPPORTED_BADGE_FORMATS: &[&str] = &[
    "w3c_vcdm_v2_sd_jwt",
    "ietf_sd_jwt",
    "sd_jwt_vc",
    "vc+sd_jwt",
    "vc+sd-jwt",
    "dc+sd_jwt",
    "dc+sd-jwt",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanvasReadinessIssuerConfiguration {
    pub issuer_did: String,
    pub algorithm: String,
    pub credential_format: &'static str,
    pub key_purpose: &'static str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasReadinessCheck {
    pub code: String,
    pub component: String,
    pub status: String,
    pub blocking: bool,
    pub remediation: String,
    pub timestamp: String,
}

impl CanvasReadinessCheck {
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self.status.as_str(), "ready" | "not_applicable")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasBindingReadiness {
    pub organization_id: String,
    pub platform_id: String,
    pub binding_id: String,
    pub config_version: i64,
    pub ready: bool,
    pub checks: Vec<CanvasReadinessCheck>,
    pub credential_template_snapshot: Map<String, Value>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasOAuthReadinessConnection {
    pub connected: bool,
    pub reauthorization_required: bool,
    pub access_token_secret_configured: bool,
    pub capabilities: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CanvasSyncReadiness {
    pub dead_lettered: bool,
    pub stale_backlog: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CanvasReadinessInputs {
    pub rollout_allowed: bool,
    pub lti_metadata_ready: bool,
    pub lti_tool_signing_ready: bool,
    pub oauth_lookup_succeeded: bool,
    pub oauth_connection: Option<CanvasOAuthReadinessConnection>,
    pub worker_heartbeat_configured: bool,
    pub sync_state: Option<CanvasSyncReadiness>,
    pub application_template: Option<CanvasApplicationTemplateProjection>,
    pub credential_template: Map<String, Value>,
    pub credential_status_profile: Map<String, Value>,
    pub kms_did_signing_ready: bool,
    pub learner_identity_status: Option<String>,
    pub evidence_observed_at: Option<DateTime<Utc>>,
    pub evidence_max_age: Duration,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasReadinessResultError {
    #[error("Canvas readiness result does not belong to this binding")]
    ForeignResult,
    #[error("Canvas readiness result is stale for this binding version")]
    StaleResult,
}

#[must_use]
pub fn evaluate_canvas_binding_readiness(
    platform: &CanvasPlatformRecord,
    binding: &CanvasProgramBindingRecord,
    inputs: &CanvasReadinessInputs,
    evaluated_at: DateTime<Utc>,
) -> CanvasBindingReadiness {
    let timestamp = readiness_timestamp(evaluated_at);
    let mut checks = Vec::new();
    let organization_matches = !platform.organization_id.is_empty()
        && platform.organization_id == binding.organization_id
        && platform.id == binding.platform_id;

    push_check(
        &mut checks,
        "rollout_allowlist",
        "rollout",
        inputs.rollout_allowed,
        true,
        "Enable portable Canvas and add this organization to the pilot allowlist.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "tenant_ownership",
        "security",
        organization_matches,
        true,
        "Recreate the binding under the organization that owns the Canvas platform.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "platform_active",
        "lti",
        platform.enabled
            && platform.archived_at.is_none()
            && matches!(
                platform.registration_status.to_ascii_lowercase().as_str(),
                "verified" | "active" | "installed" | "ready"
            ),
        true,
        "Complete Canvas installation validation and enable the platform.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "lti_installation",
        "lti",
        non_empty(platform.lti_client_id.as_deref())
            && non_empty(platform.lti_deployment_id.as_deref()),
        true,
        "Enter the Canvas LTI client and deployment IDs.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "lti_metadata",
        "lti",
        inputs.lti_metadata_ready,
        true,
        "Probe and pin the Canvas HTTPS OIDC, token, and JWKS metadata again.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "lti_tool_sign_verify_challenge",
        "lti_tool_kms",
        inputs.lti_tool_signing_ready,
        true,
        "Configure the dedicated RS256 LTI tool key, publish its active kid, and rerun the live sign/verify challenge.",
        &timestamp,
        true,
    );

    let requirements = typed_requirements(binding);
    let requirements_valid = requirements.is_some();
    let requirements = requirements.unwrap_or_default();
    push_check(
        &mut checks,
        "typed_evidence_requirements",
        "evidence",
        requirements_valid,
        true,
        "Replace legacy evidence JSON with uniquely identified typed Canvas requirements.",
        &timestamp,
        true,
    );

    let ags_required = requirements
        .iter()
        .any(|requirement| requirement.source == CanvasEvidenceSource::AgsResult);
    push_check(
        &mut checks,
        "ags_result_capability",
        "evidence",
        ags_ready(platform, binding, &requirements),
        true,
        "Launch the Deep Linked activity and grant AGS Result read access for its verified line item.",
        &timestamp,
        ags_required,
    );
    let background_awards = binding
        .feature_flags
        .get("enable_background_awards")
        .copied()
        .unwrap_or(false);
    let background_required = binding
        .feature_flags
        .get("enable_canvas_nrps")
        .copied()
        .unwrap_or(false)
        || (background_awards && ags_required);
    push_check(
        &mut checks,
        "nrps_roster_capability",
        "evidence",
        nrps_ready(platform, binding, &requirements),
        true,
        "Grant NRPS membership access and complete a verified course launch.",
        &timestamp,
        background_required,
    );

    let required_capabilities = required_oauth_capabilities(binding, &requirements);
    let capability_mapping_valid = requirements_valid && required_capabilities.is_some();
    let required_capabilities = required_capabilities.unwrap_or_default();
    let oauth_applicable = !required_capabilities.is_empty() || !capability_mapping_valid;
    push_check(
        &mut checks,
        "oauth_capability_mapping",
        "oauth",
        capability_mapping_valid,
        true,
        "Map every REST evidence rule to a supported least-privilege Canvas capability.",
        &timestamp,
        oauth_applicable,
    );

    let connection = inputs.oauth_connection.as_ref();
    let connected = inputs.oauth_lookup_succeeded
        && connection.is_some_and(|connection| {
            connection.connected
                && !connection.reauthorization_required
                && connection.access_token_secret_configured
        });
    push_check(
        &mut checks,
        "oauth_connection",
        "oauth",
        connected,
        true,
        "Reconnect Canvas OAuth for this organization and platform.",
        &timestamp,
        oauth_applicable,
    );
    let required_scopes =
        scopes_for_capabilities(&required_capabilities.iter().cloned().collect::<Vec<_>>())
            .into_iter()
            .collect::<BTreeSet<_>>();
    let grant_ready = connected
        && connection.is_some_and(|connection| {
            required_capabilities.is_subset(&connection.capabilities)
                && required_scopes.is_subset(&connection.scopes)
        });
    push_check(
        &mut checks,
        "oauth_least_privilege_grant",
        "oauth",
        grant_ready,
        true,
        "Reauthorize Canvas with every capability required by the current evidence rules.",
        &timestamp,
        oauth_applicable,
    );

    push_check(
        &mut checks,
        "worker_heartbeat",
        "synchronization",
        inputs.worker_heartbeat_configured,
        true,
        "Start the PostgreSQL-backed Canvas worker and restore its heartbeat.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "sync_dead_letter_jobs",
        "synchronization",
        inputs.sync_state.is_some_and(|state| !state.dead_lettered),
        true,
        "Retry or resolve every dead-letter Canvas sync job for this platform and binding.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "sync_backlog_freshness",
        "synchronization",
        inputs.sync_state.is_some_and(|state| !state.stale_backlog),
        true,
        "Restore Canvas worker capacity and clear synchronization work older than two target intervals.",
        &timestamp,
        true,
    );

    let application_template_ready = application_template_ready(binding, inputs);
    push_check(
        &mut checks,
        "application_template",
        "templates",
        application_template_ready,
        true,
        "Link an active application template owned by this organization.",
        &timestamp,
        true,
    );
    let credential_template_ready =
        credential_template_ready(binding, inputs, application_template_ready);
    push_check(
        &mut checks,
        "open_badge_template",
        "templates",
        credential_template_ready,
        true,
        "Link the same active, KMS-supported Open Badge template used by the application template.",
        &timestamp,
        true,
    );
    let snapshot_matches = binding.credential_template_snapshot.is_empty()
        || binding.validated_config_version != Some(binding.config_version)
        || binding.credential_template_snapshot == inputs.credential_template;
    push_check(
        &mut checks,
        "credential_template_snapshot",
        "templates",
        credential_template_ready && snapshot_matches,
        true,
        "Increment the binding configuration and revalidate the changed credential template.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "credential_status_profile",
        "credential_status",
        credential_template_ready && status_profile_ready(binding, inputs),
        true,
        "Attach an active organization-owned credential status profile to the Open Badge template.",
        &timestamp,
        true,
    );
    let issuer_configuration_ready = application_template_ready
        && credential_template_ready
        && issuer_configuration_ready(&inputs.credential_template);
    push_check(
        &mut checks,
        "kms_issuer_configuration",
        "kms_did",
        issuer_configuration_ready,
        true,
        "Configure an active issuer DID and supported algorithm backed by a managed issuer profile.",
        &timestamp,
        true,
    );
    push_check(
        &mut checks,
        "kms_did_sign_verify_challenge",
        "kms_did",
        organization_matches && issuer_configuration_ready && inputs.kms_did_signing_ready,
        true,
        "Repair the exact KMS key/DID publication binding and rerun the live sign/verify challenge.",
        &timestamp,
        true,
    );

    let identity_applicable = inputs.learner_identity_status.is_some();
    let identity_ready = inputs
        .learner_identity_status
        .as_deref()
        .is_some_and(|status| {
            matches!(
                status.trim().to_ascii_lowercase().as_str(),
                "linked" | "verified" | "active"
            )
        });
    push_check(
        &mut checks,
        "learner_identity_mapping",
        "identity",
        identity_ready,
        false,
        "Have this learner launch Marty in Canvas to establish the verified opaque-to-numeric identity link.",
        &timestamp,
        identity_applicable,
    );
    let freshness_applicable = inputs.evidence_observed_at.is_some();
    let freshness_ready = inputs.evidence_observed_at.is_some_and(|observed_at| {
        let age = evaluated_at
            .signed_duration_since(observed_at)
            .num_seconds();
        age >= 0
            && u64::try_from(age)
                .ok()
                .is_some_and(|age| age <= inputs.evidence_max_age.as_secs())
    });
    push_check(
        &mut checks,
        "learner_evidence_freshness",
        "evidence",
        freshness_ready,
        false,
        "Enqueue a learner evidence refresh before approval.",
        &timestamp,
        freshness_applicable,
    );

    let ready = checks.iter().all(|check| !check.blocking || check.passed());
    CanvasBindingReadiness {
        organization_id: binding.organization_id.clone(),
        platform_id: platform.id.clone(),
        binding_id: binding.id.clone(),
        config_version: binding.config_version,
        ready,
        checks,
        credential_template_snapshot: if credential_template_ready {
            inputs.credential_template.clone()
        } else {
            Map::new()
        },
        evaluated_at,
    }
}

pub fn apply_canvas_readiness_result(
    binding: &mut CanvasProgramBindingRecord,
    result: &CanvasBindingReadiness,
) -> Result<(), CanvasReadinessResultError> {
    if result.binding_id != binding.id
        || result.platform_id != binding.platform_id
        || result.organization_id != binding.organization_id
    {
        return Err(CanvasReadinessResultError::ForeignResult);
    }
    if result.config_version != binding.config_version {
        return Err(CanvasReadinessResultError::StaleResult);
    }
    binding.readiness_checks = result
        .checks
        .iter()
        .map(|check| {
            json_check(
                &check.code,
                &check.component,
                &check.status,
                check.blocking,
                &check.remediation,
                &check.timestamp,
            )
        })
        .collect();
    binding.readiness_validated_at = Some(result.evaluated_at);
    binding.validated_config_version = Some(result.config_version);
    if result.ready {
        binding.credential_template_snapshot = result.credential_template_snapshot.clone();
    }
    Ok(())
}

fn json_check(
    code: &str,
    component: &str,
    status: &str,
    blocking: bool,
    remediation: &str,
    timestamp: &str,
) -> Value {
    Value::Object(Map::from_iter([
        ("code".to_owned(), Value::String(code.to_owned())),
        ("component".to_owned(), Value::String(component.to_owned())),
        ("status".to_owned(), Value::String(status.to_owned())),
        ("blocking".to_owned(), Value::Bool(blocking)),
        (
            "remediation".to_owned(),
            Value::String(remediation.to_owned()),
        ),
        ("timestamp".to_owned(), Value::String(timestamp.to_owned())),
    ]))
}

#[must_use]
pub fn canvas_binding_is_ready_for_activation(
    binding: &CanvasProgramBindingRecord,
    now: DateTime<Utc>,
    max_age: Duration,
) -> bool {
    if max_age.is_zero()
        || binding.archived_at.is_some()
        || binding.validated_config_version != Some(binding.config_version)
        || binding.readiness_checks.is_empty()
        || binding.credential_template_snapshot.is_empty()
    {
        return false;
    }
    let Some(validated_at) = binding.readiness_validated_at else {
        return false;
    };
    let age = now.signed_duration_since(validated_at).num_seconds();
    if age < 0
        || u64::try_from(age)
            .ok()
            .is_none_or(|age| age > max_age.as_secs())
    {
        return false;
    }
    binding.readiness_checks.iter().all(|value| {
        value.as_object().is_some_and(|check| {
            check.get("blocking").and_then(Value::as_bool) != Some(true)
                || matches!(
                    text(check.get("status")).to_ascii_lowercase().as_str(),
                    "ready" | "not_applicable"
                )
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn push_check(
    checks: &mut Vec<CanvasReadinessCheck>,
    code: &str,
    component: &str,
    ready: bool,
    blocking: bool,
    remediation: &str,
    timestamp: &str,
    applicable: bool,
) {
    let (status, remediation) = if !applicable {
        ("not_applicable", "")
    } else if ready {
        ("ready", "")
    } else if blocking {
        ("failed", remediation)
    } else {
        ("warning", remediation)
    };
    checks.push(CanvasReadinessCheck {
        code: code.to_owned(),
        component: component.to_owned(),
        status: status.to_owned(),
        blocking,
        remediation: remediation.to_owned(),
        timestamp: timestamp.to_owned(),
    });
}

fn typed_requirements(
    binding: &CanvasProgramBindingRecord,
) -> Option<Vec<CanvasEvidenceRequirementInput>> {
    let requirements: Vec<CanvasEvidenceRequirementInput> =
        serde_json::from_value(Value::Array(binding.evidence_requirements.clone())).ok()?;
    if requirements.is_empty()
        || requirements
            .iter()
            .any(|requirement| requirement.validate().is_err())
    {
        return None;
    }
    let ids = binding
        .evidence_requirements
        .iter()
        .filter_map(|requirement| requirement.get("requirement_id")?.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    (ids.len() == requirements.len()).then_some(requirements)
}

fn required_oauth_capabilities(
    binding: &CanvasProgramBindingRecord,
    requirements: &[CanvasEvidenceRequirementInput],
) -> Option<BTreeSet<String>> {
    let mut capabilities = BTreeSet::new();
    for requirement in requirements {
        if requirement.source != CanvasEvidenceSource::CanvasRest {
            continue;
        }
        capabilities.insert(
            match requirement.fact_type {
                CanvasEvidenceFactType::AssignmentScore | CanvasEvidenceFactType::QuizScore => {
                    "native_activity_scores"
                }
                CanvasEvidenceFactType::CourseCompletion => "course_completion",
                CanvasEvidenceFactType::ModuleCompletion => "module_completion",
            }
            .to_owned(),
        );
    }
    if binding
        .feature_flags
        .get("enable_canvas_nrps")
        .copied()
        .unwrap_or(false)
        || binding
            .feature_flags
            .get("enable_background_awards")
            .copied()
            .unwrap_or(false)
    {
        capabilities.insert("background_roster".to_owned());
    }
    Some(capabilities)
}

pub(crate) fn verified_canvas_binding_capabilities<'a>(
    platform: &'a CanvasPlatformRecord,
    binding: &CanvasProgramBindingRecord,
) -> Option<&'a Map<String, Value>> {
    let capabilities = platform
        .capability_snapshot
        .get("verified_binding_launches")?
        .as_object()?
        .get(&binding.id)?
        .as_object()?;
    (text(capabilities.get("verified_binding_id")) == binding.id
        && capabilities
            .get("verified_binding_config_version")
            .and_then(Value::as_i64)
            == Some(binding.config_version))
    .then_some(capabilities)
}

fn verified_launch_matches_course(
    capabilities: &Map<String, Value>,
    requirements: &[&CanvasEvidenceRequirementInput],
) -> bool {
    let courses = requirements
        .iter()
        .map(|requirement| requirement.scope.course_id.trim())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    courses.len() == 1 && courses.contains(text(capabilities.get("verified_course_id")).as_str())
}

fn ags_ready(
    platform: &CanvasPlatformRecord,
    binding: &CanvasProgramBindingRecord,
    requirements: &[CanvasEvidenceRequirementInput],
) -> bool {
    let Some(capabilities) = verified_canvas_binding_capabilities(platform, binding) else {
        return false;
    };
    let ags = requirements
        .iter()
        .filter(|requirement| requirement.source == CanvasEvidenceSource::AgsResult)
        .collect::<Vec<_>>();
    let pinned = ags
        .iter()
        .filter_map(|requirement| requirement.scope.line_item_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    let every_pinned = !ags.is_empty()
        && ags.iter().all(|requirement| {
            non_empty(requirement.scope.resource_id.as_deref())
                && requirement
                    .scope
                    .line_item_url
                    .as_deref()
                    .is_some_and(https_url)
        });
    let mut verified = string_set(capabilities.get("verified_ags_line_items"));
    let launch_line_item = text(capabilities.get("ags_lineitem_url"));
    if !launch_line_item.is_empty() {
        verified.insert(launch_line_item);
    }
    capabilities
        .get("assignment_grade_services")
        .and_then(Value::as_bool)
        == Some(true)
        && string_set(capabilities.get("ags_scopes")).contains(AGS_RESULT_READ_SCOPE)
        && [
            capabilities.get("ags_lineitem_url"),
            capabilities.get("ags_lineitems_url"),
        ]
        .into_iter()
        .flatten()
        .map(text_value)
        .find(|value| !value.is_empty())
        .is_some_and(|value| https_url(&value))
        && every_pinned
        && !pinned.is_empty()
        && pinned.iter().all(|value| verified.contains(*value))
        && verified_launch_matches_course(capabilities, &ags)
}

fn nrps_ready(
    platform: &CanvasPlatformRecord,
    binding: &CanvasProgramBindingRecord,
    requirements: &[CanvasEvidenceRequirementInput],
) -> bool {
    let Some(capabilities) = verified_canvas_binding_capabilities(platform, binding) else {
        return false;
    };
    let memberships_url = text(capabilities.get("nrps_context_memberships_url"));
    capabilities.get("names_roles").and_then(Value::as_bool) == Some(true)
        && https_url(&memberships_url)
        && verified_launch_matches_course(capabilities, &requirements.iter().collect::<Vec<_>>())
}

fn application_template_ready(
    binding: &CanvasProgramBindingRecord,
    inputs: &CanvasReadinessInputs,
) -> bool {
    inputs
        .application_template
        .as_ref()
        .is_some_and(|template| {
            template.id == binding.application_template_id
                && template.organization_id == binding.organization_id
                && template.active
        })
}

fn credential_template_ready(
    binding: &CanvasProgramBindingRecord,
    inputs: &CanvasReadinessInputs,
    application_ready: bool,
) -> bool {
    let credential = &inputs.credential_template;
    let template_id = first_text(&[
        credential.get("id"),
        credential.get("credential_template_id"),
    ]);
    let payload_format = payload_format(credential);
    application_ready
        && template_id == binding.credential_template_id
        && text(credential.get("organization_id")) == binding.organization_id
        && text(credential.get("status")).eq_ignore_ascii_case("active")
        && open_badge_type(&first_text(&[
            credential.get("credential_type"),
            credential.get("format"),
        ]))
        && SUPPORTED_BADGE_FORMATS
            .iter()
            .any(|value| value.eq_ignore_ascii_case(&payload_format))
        && inputs
            .application_template
            .as_ref()
            .and_then(|template| template.credential_template_id.as_deref())
            == Some(binding.credential_template_id.as_str())
}

fn status_profile_ready(
    binding: &CanvasProgramBindingRecord,
    inputs: &CanvasReadinessInputs,
) -> bool {
    let expected_id = text(inputs.credential_template.get("revocation_profile_id"));
    let actual_id = first_text(&[
        inputs.credential_status_profile.get("id"),
        inputs.credential_status_profile.get("profile_id"),
    ]);
    let profile_org = text(inputs.credential_status_profile.get("organization_id"));
    !expected_id.is_empty()
        && actual_id == expected_id
        && (profile_org.is_empty() || profile_org == binding.organization_id)
        && text(inputs.credential_status_profile.get("status")).eq_ignore_ascii_case("active")
}

fn issuer_configuration_ready(credential: &Map<String, Value>) -> bool {
    readiness_issuer_configuration(credential).is_some()
}

pub(crate) fn readiness_issuer_configuration(
    credential: &Map<String, Value>,
) -> Option<CanvasReadinessIssuerConfiguration> {
    let payload_format = payload_format(credential)
        .to_ascii_lowercase()
        .replace('-', "_");
    let issuer_did = text(credential.get("issuer_did"));
    let algorithm = text(credential.get("issuer_algorithm"));
    (issuer_did.starts_with("did:")
        && SUPPORTED_ISSUER_ALGORITHMS.contains(&algorithm.as_str())
        && matches!(
            payload_format.as_str(),
            "w3c_vcdm_v2_sd_jwt" | "ietf_sd_jwt" | "sd_jwt_vc" | "vc+sd_jwt" | "dc+sd_jwt"
        ))
    .then_some(CanvasReadinessIssuerConfiguration {
        issuer_did,
        algorithm,
        credential_format: "dc+sd-jwt",
        key_purpose: "vc_jwt_issuer",
    })
}

fn payload_format(credential: &Map<String, Value>) -> String {
    let direct = first_text(&[
        credential.get("credential_payload_format"),
        credential.get("payload_format"),
    ]);
    if !direct.is_empty() {
        return direct;
    }
    credential
        .get("supported_formats")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn open_badge_type(value: &str) -> bool {
    matches!(
        value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .as_str(),
        "openbadge" | "openbadgev2" | "openbadgev3" | "openbadgecredential"
    )
}

fn https_url(value: &str) -> bool {
    url::Url::parse(value.trim()).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn non_empty(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn text(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn text_value(value: &Value) -> String {
    value.as_str().unwrap_or_default().trim().to_owned()
}

fn first_text(values: &[Option<&Value>]) -> String {
    values
        .iter()
        .map(|value| text(*value))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn readiness_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::{
        canvas_binding_domain::CanvasApplicationTemplateProjection,
        canvas_management::{
            CanvasDeliveryMode, CanvasEvidencePassRuleInput, CanvasEvidenceScopeInput,
            CanvasPlatformRequest, CanvasProgramBindingRequest,
        },
        canvas_management_domain::CanvasOriginPolicy,
    };

    fn now(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 22, 0, second).unwrap()
    }

    fn fixture() -> (
        CanvasPlatformRecord,
        CanvasProgramBindingRecord,
        CanvasApplicationTemplateProjection,
    ) {
        let origin = CanvasOriginPolicy::default()
            .resolve("https://canvas.example.edu")
            .unwrap();
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            CanvasPlatformRequest {
                display_name: Some("Canvas".to_owned()),
                canvas_base_url: "https://canvas.example.edu".to_owned(),
                lti_client_id: Some("client-1".to_owned()),
                lti_deployment_id: Some("deployment-1".to_owned()),
                enabled: true,
            },
            origin,
            now(0),
        )
        .unwrap();
        platform.enabled = true;
        platform.registration_status = "installed".to_owned();
        let template = CanvasApplicationTemplateProjection {
            id: "application-template-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: Some("credential-template-1".to_owned()),
            approval_policy_set_id: Some("policy-1".to_owned()),
            active: true,
        };
        let binding = CanvasProgramBindingRecord::configure(
            &platform,
            CanvasProgramBindingRequest {
                application_template_id: template.id.clone(),
                credential_template_id: None,
                display_name: Some("Biology".to_owned()),
                auto_approve_on_evidence: false,
                evidence_requirements: vec![CanvasEvidenceRequirementInput {
                    requirement_id: Some("course-complete".to_owned()),
                    source: CanvasEvidenceSource::CanvasRest,
                    fact_type: CanvasEvidenceFactType::CourseCompletion,
                    scope: CanvasEvidenceScopeInput {
                        course_id: "course-1".to_owned(),
                        activity_id: None,
                        module_id: None,
                        line_item_url: None,
                        resource_id: None,
                    },
                    pass_rule: CanvasEvidencePassRuleInput {
                        min_score_percent: None,
                        completed: Some(true),
                    },
                    required: true,
                }],
                canvas_scope: BTreeMap::from([("course_id".to_owned(), "course-1".to_owned())]),
                delivery_mode: CanvasDeliveryMode::WalletOnly,
                approval_policy_set_id: None,
                deployment_profile_id: None,
                feature_flags: BTreeMap::new(),
                canvas_credentials: None,
            },
            &template,
            Map::new(),
            None,
            now(1),
        )
        .unwrap();
        (platform, binding, template)
    }

    fn ready_inputs(template: CanvasApplicationTemplateProjection) -> CanvasReadinessInputs {
        CanvasReadinessInputs {
            rollout_allowed: true,
            lti_metadata_ready: true,
            lti_tool_signing_ready: true,
            oauth_lookup_succeeded: true,
            oauth_connection: Some(CanvasOAuthReadinessConnection {
                connected: true,
                reauthorization_required: false,
                access_token_secret_configured: true,
                capabilities: BTreeSet::from(["course_completion".to_owned()]),
                scopes: scopes_for_capabilities(&["course_completion".to_owned()])
                    .into_iter()
                    .collect(),
            }),
            worker_heartbeat_configured: true,
            sync_state: Some(CanvasSyncReadiness {
                dead_lettered: false,
                stale_backlog: false,
            }),
            application_template: Some(template),
            credential_template: json!({
                "id": "credential-template-1",
                "organization_id": "org-1",
                "status": "active",
                "credential_type": "OpenBadgeCredential",
                "credential_payload_format": "dc+sd-jwt",
                "revocation_profile_id": "status-profile-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
                "issuer_algorithm": "ES256"
            })
            .as_object()
            .unwrap()
            .clone(),
            credential_status_profile: json!({
                "id": "status-profile-1",
                "organization_id": "org-1",
                "status": "active"
            })
            .as_object()
            .unwrap()
            .clone(),
            kms_did_signing_ready: true,
            learner_identity_status: None,
            evidence_observed_at: None,
            evidence_max_age: Duration::from_secs(900),
        }
    }

    #[test]
    fn complete_projection_is_ready_and_persists_an_exact_version_snapshot() {
        let (platform, mut binding, template) = fixture();
        let inputs = ready_inputs(template);
        let result = evaluate_canvas_binding_readiness(&platform, &binding, &inputs, now(2));
        assert!(result.ready);
        assert_eq!(result.checks.len(), 23);
        assert_eq!(result.checks[7].status, "not_applicable");
        assert_eq!(result.checks[8].status, "not_applicable");
        assert_eq!(result.checks[21].status, "not_applicable");
        assert_eq!(result.checks[22].status, "not_applicable");

        apply_canvas_readiness_result(&mut binding, &result).unwrap();
        assert_eq!(
            binding.validated_config_version,
            Some(binding.config_version)
        );
        assert_eq!(
            binding.credential_template_snapshot,
            inputs.credential_template
        );
        assert!(canvas_binding_is_ready_for_activation(
            &binding,
            now(3),
            Duration::from_secs(900)
        ));
        assert!(!canvas_binding_is_ready_for_activation(
            &binding,
            now(3),
            Duration::ZERO
        ));
    }

    #[test]
    fn readiness_is_stable_fail_closed_and_detects_template_drift() {
        let (platform, mut binding, template) = fixture();
        let missing = evaluate_canvas_binding_readiness(
            &platform,
            &binding,
            &CanvasReadinessInputs::default(),
            now(2),
        );
        assert!(!missing.ready);
        assert_eq!(
            missing
                .checks
                .iter()
                .filter(|check| check.blocking && !check.passed())
                .map(|check| check.code.as_str())
                .collect::<Vec<_>>(),
            [
                "rollout_allowlist",
                "lti_metadata",
                "lti_tool_sign_verify_challenge",
                "oauth_connection",
                "oauth_least_privilege_grant",
                "worker_heartbeat",
                "sync_dead_letter_jobs",
                "sync_backlog_freshness",
                "application_template",
                "open_badge_template",
                "credential_template_snapshot",
                "credential_status_profile",
                "kms_issuer_configuration",
                "kms_did_sign_verify_challenge",
            ]
        );

        let mut inputs = ready_inputs(template);
        let ready = evaluate_canvas_binding_readiness(&platform, &binding, &inputs, now(2));
        apply_canvas_readiness_result(&mut binding, &ready).unwrap();
        inputs.credential_template.insert(
            "issuer_algorithm".to_owned(),
            Value::String("RS256".to_owned()),
        );
        let drifted = evaluate_canvas_binding_readiness(&platform, &binding, &inputs, now(3));
        assert!(!drifted.ready);
        assert_eq!(
            drifted
                .checks
                .iter()
                .find(|check| check.code == "credential_template_snapshot")
                .unwrap()
                .status,
            "failed"
        );
    }

    #[test]
    fn foreign_and_stale_results_never_mutate_a_binding() {
        let (platform, mut binding, template) = fixture();
        let original = binding.clone();
        let mut result =
            evaluate_canvas_binding_readiness(&platform, &binding, &ready_inputs(template), now(2));
        result.binding_id = "other".to_owned();
        assert_eq!(
            apply_canvas_readiness_result(&mut binding, &result),
            Err(CanvasReadinessResultError::ForeignResult)
        );
        assert_eq!(binding, original);
        result.binding_id = binding.id.clone();
        result.config_version += 1;
        assert_eq!(
            apply_canvas_readiness_result(&mut binding, &result),
            Err(CanvasReadinessResultError::StaleResult)
        );
        assert_eq!(binding, original);
    }
}
