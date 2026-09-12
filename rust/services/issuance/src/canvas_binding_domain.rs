//! Pure Canvas program-binding configuration decisions.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    canvas_management::{
        CanvasDeliveryMode, CanvasEvidenceFactType, CanvasEvidenceRequirementInput,
        CanvasEvidenceSource, CanvasProgramBindingRequest, CanvasRequestValidationError,
        ValidateCanvasRequest,
    },
    canvas_management_domain::CanvasPlatformRecord,
};

const FLOW_MODE: &str = "elevenid_orchestrated_canvas_evidence";
const ISSUER_MODE: &str = "org_managed";
pub(crate) const CANVAS_FEATURE_FLAGS: &[&str] = &[
    "enable_canvas_evidence",
    "enable_canvas_lti",
    "enable_canvas_mirror_publish",
    "enable_canvas_mirror_ops",
    "enable_canvas_deep_linking",
    "enable_canvas_ags",
    "enable_canvas_nrps",
    "enable_background_awards",
];

#[derive(Debug, Error, PartialEq)]
pub enum CanvasBindingDomainError {
    #[error(transparent)]
    InvalidRequest(#[from] CanvasRequestValidationError),
    #[error("Application template belongs to a different organization")]
    ForeignApplicationTemplate,
    #[error("Application template lookup did not match the requested template")]
    ApplicationTemplateMismatch,
    #[error("Application template is not active")]
    ApplicationTemplateInactive,
    #[error("Existing Canvas binding belongs to a different tenant or platform")]
    ForeignExistingBinding,
    #[error("Program binding requires a credential template ID")]
    CredentialTemplateRequired,
    #[error("Credential template does not match application template")]
    CredentialTemplateMismatch,
    #[error("Canvas Credentials projection must use the binding credential template")]
    ProjectionTemplateMismatch,
    #[error("Canvas evidence requires enable_canvas_evidence in the deployment profile")]
    EvidenceFeatureDisabled,
    #[error("Canvas auto-approval requires enable_canvas_evidence in the deployment profile")]
    AutoApprovalFeatureDisabled,
    #[error(
        "Canvas mirror delivery requires enable_canvas_mirror_publish in the deployment profile"
    )]
    MirrorFeatureDisabled,
    #[error("Canvas evidence requirement_id values must be unique")]
    DuplicateRequirementId,
    #[error("{0}")]
    InvalidEvidence(&'static str),
    #[error("Canvas program binding configuration version is exhausted")]
    VersionExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasApplicationTemplateProjection {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: Option<String>,
    pub approval_policy_set_id: Option<String>,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasProgramBindingRecord {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub display_name: Option<String>,
    pub flow_mode: String,
    pub direct_issue_enabled: bool,
    pub auto_approve_on_evidence: bool,
    pub evidence_requirements: Vec<Value>,
    pub canvas_scope: BTreeMap<String, String>,
    pub delivery_mode: String,
    pub issuer_mode: String,
    pub approval_policy_set_id: Option<String>,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: BTreeMap<String, bool>,
    pub canvas_credentials: Map<String, Value>,
    pub config_version: i64,
    pub validated_config_version: Option<i64>,
    pub readiness_checks: Vec<Value>,
    pub readiness_validated_at: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub archived_at: Option<DateTime<Utc>>,
    pub credential_template_snapshot: Map<String, Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CanvasProgramBindingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        platform: &CanvasPlatformRecord,
        request: CanvasProgramBindingRequest,
        template: &CanvasApplicationTemplateProjection,
        validated_canvas_credentials: Map<String, Value>,
        existing: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<Self, CanvasBindingDomainError> {
        let request = request.normalize()?;
        if template.id != request.application_template_id {
            return Err(CanvasBindingDomainError::ApplicationTemplateMismatch);
        }
        if template.organization_id != platform.organization_id {
            return Err(CanvasBindingDomainError::ForeignApplicationTemplate);
        }
        if !template.active {
            return Err(CanvasBindingDomainError::ApplicationTemplateInactive);
        }
        if existing.is_some_and(|binding| {
            binding.organization_id != platform.organization_id
                || binding.platform_id != platform.id
        }) {
            return Err(CanvasBindingDomainError::ForeignExistingBinding);
        }
        let credential_template_id = request
            .credential_template_id
            .as_deref()
            .or(template.credential_template_id.as_deref())
            .filter(|value| !value.is_empty())
            .ok_or(CanvasBindingDomainError::CredentialTemplateRequired)?
            .to_owned();
        if template
            .credential_template_id
            .as_deref()
            .is_some_and(|expected| expected != credential_template_id)
        {
            return Err(CanvasBindingDomainError::CredentialTemplateMismatch);
        }
        if validated_canvas_credentials
            .get("credential_template_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|configured| configured != credential_template_id)
        {
            return Err(CanvasBindingDomainError::ProjectionTemplateMismatch);
        }

        let feature_flags = normalize_feature_flags(&request.feature_flags);
        if !feature_flags.is_empty() {
            if !feature_flags
                .get("enable_canvas_evidence")
                .copied()
                .unwrap_or(false)
            {
                if !request.evidence_requirements.is_empty() {
                    return Err(CanvasBindingDomainError::EvidenceFeatureDisabled);
                }
                if request.auto_approve_on_evidence {
                    return Err(CanvasBindingDomainError::AutoApprovalFeatureDisabled);
                }
            }
            if request.delivery_mode == CanvasDeliveryMode::WalletPlusCanvasMirror
                && !feature_flags
                    .get("enable_canvas_mirror_publish")
                    .copied()
                    .unwrap_or(false)
            {
                return Err(CanvasBindingDomainError::MirrorFeatureDisabled);
            }
        }

        let id = existing
            .map(|binding| binding.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let evidence_requirements = normalize_requirements(
            &id,
            &request.canvas_scope,
            request.evidence_requirements,
            existing,
        )?;
        let config_version = existing
            .map(|binding| {
                binding
                    .config_version
                    .checked_add(1)
                    .ok_or(CanvasBindingDomainError::VersionExhausted)
            })
            .transpose()?
            .unwrap_or(1);

        Ok(Self {
            id,
            organization_id: platform.organization_id.clone(),
            platform_id: platform.id.clone(),
            application_template_id: template.id.clone(),
            credential_template_id,
            display_name: request.display_name,
            flow_mode: FLOW_MODE.to_owned(),
            direct_issue_enabled: false,
            auto_approve_on_evidence: request.auto_approve_on_evidence,
            evidence_requirements,
            canvas_scope: request.canvas_scope,
            delivery_mode: delivery_mode(request.delivery_mode).to_owned(),
            issuer_mode: ISSUER_MODE.to_owned(),
            approval_policy_set_id: request
                .approval_policy_set_id
                .or_else(|| template.approval_policy_set_id.clone()),
            deployment_profile_id: request.deployment_profile_id,
            feature_flags,
            canvas_credentials: validated_canvas_credentials,
            config_version,
            validated_config_version: None,
            readiness_checks: Vec::new(),
            readiness_validated_at: None,
            activated_at: None,
            archived_at: None,
            credential_template_snapshot: Map::new(),
            enabled: false,
            created_at: existing.map(|binding| binding.created_at).unwrap_or(now),
            updated_at: now,
        })
    }

    pub fn archive(&mut self, now: DateTime<Utc>) {
        self.enabled = false;
        self.archived_at = Some(now);
        self.updated_at = now;
    }

    pub fn invalidate_readiness(&mut self, now: DateTime<Utc>) {
        if self.archived_at.is_some() {
            return;
        }
        self.enabled = false;
        self.validated_config_version = None;
        self.readiness_checks.clear();
        self.readiness_validated_at = None;
        self.activated_at = None;
        self.updated_at = now;
    }
}

fn normalize_feature_flags(flags: &BTreeMap<String, bool>) -> BTreeMap<String, bool> {
    CANVAS_FEATURE_FLAGS
        .iter()
        .filter_map(|key| flags.get(*key).map(|value| ((*key).to_owned(), *value)))
        .collect()
}

fn delivery_mode(mode: CanvasDeliveryMode) -> &'static str {
    match mode {
        CanvasDeliveryMode::WalletOnly => "wallet_only",
        CanvasDeliveryMode::WalletPlusCanvasMirror => "wallet_plus_canvas_mirror",
    }
}

fn normalize_requirements(
    binding_id: &str,
    canvas_scope: &BTreeMap<String, String>,
    requirements: Vec<CanvasEvidenceRequirementInput>,
    existing: Option<&CanvasProgramBindingRecord>,
) -> Result<Vec<Value>, CanvasBindingDomainError> {
    let existing_by_id = existing
        .into_iter()
        .flat_map(|binding| binding.evidence_requirements.iter())
        .filter_map(|value| {
            value
                .get("requirement_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let mut identifiers = BTreeSet::new();
    let mut normalized = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        requirement.validate()?;
        let requirement_id = requirement
            .requirement_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("canvas_req_{}", Uuid::new_v4().simple()));
        if !identifiers.insert(requirement_id.clone()) {
            return Err(CanvasBindingDomainError::DuplicateRequirementId);
        }
        let existing_scope = existing_by_id
            .get(&requirement_id)
            .and_then(|value| value.get("scope"))
            .and_then(Value::as_object);
        let mut course_id = requirement.scope.course_id.trim().to_owned();
        if course_id.is_empty() {
            course_id = canvas_scope.get("course_id").cloned().unwrap_or_default();
        }
        if course_id.is_empty() {
            return Err(CanvasBindingDomainError::InvalidEvidence(
                "scope.course_id is required",
            ));
        }
        let mut activity_id = trimmed(requirement.scope.activity_id);
        let module_id = trimmed(requirement.scope.module_id);
        let mut line_item_url = trimmed(requirement.scope.line_item_url);
        let mut resource_id = trimmed(requirement.scope.resource_id);
        if requirement.source == CanvasEvidenceSource::AgsResult {
            // Only a verified launch can set these provider-owned identifiers.
            line_item_url = existing_scope
                .and_then(|scope| scope.get("line_item_url"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            resource_id = existing_scope
                .and_then(|scope| scope.get("resource_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if line_item_url.is_none() && resource_id.is_none() {
                resource_id = Some(format!("marty:{binding_id}:{requirement_id}"));
            }
        }
        if let Some(url) = line_item_url.as_deref() {
            if !url.starts_with("https://") {
                return Err(CanvasBindingDomainError::InvalidEvidence(
                    "scope.line_item_url must use HTTPS",
                ));
            }
        }
        validate_evidence_semantics(
            requirement.source,
            requirement.fact_type,
            requirement.pass_rule.min_score_percent,
            requirement.pass_rule.completed,
            activity_id.as_deref(),
            module_id.as_deref(),
            line_item_url.as_deref(),
            resource_id.as_deref(),
        )?;

        let mut scope = Map::new();
        scope.insert("course_id".to_owned(), json!(course_id));
        insert_optional(&mut scope, "activity_id", activity_id.take());
        insert_optional(&mut scope, "module_id", module_id);
        insert_optional(&mut scope, "line_item_url", line_item_url);
        insert_optional(&mut scope, "resource_id", resource_id);
        let mut pass_rule = Map::new();
        if let Some(score) = requirement.pass_rule.min_score_percent {
            pass_rule.insert("min_score_percent".to_owned(), json!(score));
        }
        if let Some(completed) = requirement.pass_rule.completed {
            pass_rule.insert("completed".to_owned(), json!(completed));
        }
        normalized.push(json!({
            "requirement_id": requirement_id,
            "source": evidence_source(requirement.source),
            "fact_type": evidence_fact_type(requirement.fact_type),
            "scope": scope,
            "pass_rule": pass_rule,
            "required": requirement.required,
        }));
    }
    Ok(normalized)
}

#[allow(clippy::too_many_arguments)]
fn validate_evidence_semantics(
    source: CanvasEvidenceSource,
    fact_type: CanvasEvidenceFactType,
    min_score_percent: Option<f64>,
    completed: Option<bool>,
    activity_id: Option<&str>,
    module_id: Option<&str>,
    line_item_url: Option<&str>,
    resource_id: Option<&str>,
) -> Result<(), CanvasBindingDomainError> {
    let score = matches!(
        fact_type,
        CanvasEvidenceFactType::AssignmentScore | CanvasEvidenceFactType::QuizScore
    );
    if score {
        if min_score_percent.is_none() || completed.is_some() {
            return Err(CanvasBindingDomainError::InvalidEvidence(
                "score requirements need only pass_rule.min_score_percent",
            ));
        }
        if source == CanvasEvidenceSource::CanvasRest && activity_id.is_none() {
            return Err(CanvasBindingDomainError::InvalidEvidence(
                "Canvas REST score requirements need scope.activity_id",
            ));
        }
        if source == CanvasEvidenceSource::AgsResult
            && line_item_url.is_none()
            && resource_id.is_none()
        {
            return Err(CanvasBindingDomainError::InvalidEvidence(
                "AGS requirements need scope.line_item_url or scope.resource_id",
            ));
        }
        return Ok(());
    }
    if source != CanvasEvidenceSource::CanvasRest {
        return Err(CanvasBindingDomainError::InvalidEvidence(
            "completion requirements must use canvas_rest",
        ));
    }
    if completed != Some(true) || min_score_percent.is_some() {
        return Err(CanvasBindingDomainError::InvalidEvidence(
            "completion requirements need only pass_rule.completed=true",
        ));
    }
    if fact_type == CanvasEvidenceFactType::ModuleCompletion && module_id.is_none() {
        return Err(CanvasBindingDomainError::InvalidEvidence(
            "module completion requirements need scope.module_id",
        ));
    }
    Ok(())
}

fn trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn insert_optional(scope: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        scope.insert(key.to_owned(), json!(value));
    }
}

fn evidence_source(source: CanvasEvidenceSource) -> &'static str {
    match source {
        CanvasEvidenceSource::AgsResult => "ags_result",
        CanvasEvidenceSource::CanvasRest => "canvas_rest",
    }
}

fn evidence_fact_type(fact_type: CanvasEvidenceFactType) -> &'static str {
    match fact_type {
        CanvasEvidenceFactType::AssignmentScore => "canvas.assignment_score",
        CanvasEvidenceFactType::QuizScore => "canvas.quiz_score",
        CanvasEvidenceFactType::CourseCompletion => "canvas.course_completion",
        CanvasEvidenceFactType::ModuleCompletion => "canvas.module_completion",
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use marty_oid4vci::lti::CANVAS_LTI_TRUST_HOSTED_GLOBAL;
    use serde_json::json;

    use super::*;
    use crate::{
        canvas_management::{
            CanvasCredentialsConfigInput, CanvasEvidencePassRuleInput, CanvasEvidenceScopeInput,
        },
        canvas_management_domain::{CanvasPlatformRecord, ValidatedCanvasOrigin},
    };

    fn now(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 21, 0, second).unwrap()
    }

    fn platform() -> CanvasPlatformRecord {
        CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            crate::canvas_management::CanvasPlatformRequest {
                display_name: None,
                canvas_base_url: "https://canvas.example".to_owned(),
                lti_client_id: None,
                lti_deployment_id: None,
                enabled: false,
            },
            ValidatedCanvasOrigin {
                origin: "https://canvas.example".to_owned(),
                trust_profile: CANVAS_LTI_TRUST_HOSTED_GLOBAL.to_owned(),
            },
            now(0),
        )
        .unwrap()
    }

    fn template() -> CanvasApplicationTemplateProjection {
        CanvasApplicationTemplateProjection {
            id: "app-template-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: Some("credential-template-1".to_owned()),
            approval_policy_set_id: Some("policy-1".to_owned()),
            active: true,
        }
    }

    fn score_requirement(source: CanvasEvidenceSource) -> CanvasEvidenceRequirementInput {
        CanvasEvidenceRequirementInput {
            requirement_id: Some("score".to_owned()),
            source,
            fact_type: CanvasEvidenceFactType::AssignmentScore,
            scope: CanvasEvidenceScopeInput {
                course_id: "course-1".to_owned(),
                activity_id: (source == CanvasEvidenceSource::CanvasRest)
                    .then(|| "assignment-1".to_owned()),
                module_id: None,
                line_item_url: Some("https://caller.invalid/line-item".to_owned()),
                resource_id: None,
            },
            pass_rule: CanvasEvidencePassRuleInput {
                min_score_percent: Some(80.0),
                completed: None,
            },
            required: true,
        }
    }

    fn request(requirement: CanvasEvidenceRequirementInput) -> CanvasProgramBindingRequest {
        CanvasProgramBindingRequest {
            application_template_id: "app-template-1".to_owned(),
            credential_template_id: None,
            display_name: Some("Program".to_owned()),
            auto_approve_on_evidence: false,
            evidence_requirements: vec![requirement],
            canvas_scope: BTreeMap::new(),
            delivery_mode: CanvasDeliveryMode::WalletOnly,
            approval_policy_set_id: None,
            deployment_profile_id: None,
            feature_flags: BTreeMap::new(),
            canvas_credentials: None::<CanvasCredentialsConfigInput>,
        }
    }

    #[test]
    fn new_binding_uses_server_owned_modes_and_starts_disabled() {
        let binding = CanvasProgramBindingRecord::configure(
            &platform(),
            request(score_requirement(CanvasEvidenceSource::CanvasRest)),
            &template(),
            Map::new(),
            None,
            now(1),
        )
        .unwrap();
        assert_eq!(binding.credential_template_id, "credential-template-1");
        assert_eq!(binding.approval_policy_set_id.as_deref(), Some("policy-1"));
        assert_eq!(binding.flow_mode, FLOW_MODE);
        assert_eq!(binding.issuer_mode, ISSUER_MODE);
        assert!(!binding.direct_issue_enabled);
        assert!(!binding.enabled);
        assert_eq!(binding.config_version, 1);
        assert!(binding.validated_config_version.is_none());
    }

    #[test]
    fn ags_caller_url_is_discarded_and_server_resource_is_generated() {
        let binding = CanvasProgramBindingRecord::configure(
            &platform(),
            request(score_requirement(CanvasEvidenceSource::AgsResult)),
            &template(),
            Map::new(),
            None,
            now(1),
        )
        .unwrap();
        let scope = &binding.evidence_requirements[0]["scope"];
        assert!(scope.get("line_item_url").is_none());
        assert_eq!(
            scope["resource_id"],
            json!(format!("marty:{}:score", binding.id))
        );
    }

    #[test]
    fn update_preserves_verified_ags_identifiers_and_invalidates_readiness() {
        let selected_platform = platform();
        let mut existing = CanvasProgramBindingRecord::configure(
            &selected_platform,
            request(score_requirement(CanvasEvidenceSource::AgsResult)),
            &template(),
            Map::new(),
            None,
            now(1),
        )
        .unwrap();
        existing.evidence_requirements[0]["scope"]["line_item_url"] =
            json!("https://canvas.example/api/lti/line-items/1");
        existing.evidence_requirements[0]["scope"]["resource_id"] = json!("verified-resource");
        existing.enabled = true;
        existing.validated_config_version = Some(1);
        existing.readiness_checks.push(json!({"status": "pass"}));
        existing.readiness_validated_at = Some(now(2));
        existing.activated_at = Some(now(2));

        let updated = CanvasProgramBindingRecord::configure(
            &selected_platform,
            request(score_requirement(CanvasEvidenceSource::AgsResult)),
            &template(),
            Map::new(),
            Some(&existing),
            now(3),
        )
        .unwrap();
        assert_eq!(updated.id, existing.id);
        assert_eq!(updated.created_at, existing.created_at);
        assert_eq!(updated.config_version, 2);
        assert_eq!(
            updated.evidence_requirements[0]["scope"]["line_item_url"],
            json!("https://canvas.example/api/lti/line-items/1")
        );
        assert_eq!(
            updated.evidence_requirements[0]["scope"]["resource_id"],
            json!("verified-resource")
        );
        assert!(!updated.enabled);
        assert!(updated.validated_config_version.is_none());
        assert!(updated.readiness_checks.is_empty());
        assert!(updated.readiness_validated_at.is_none());
        assert!(updated.activated_at.is_none());
    }

    #[test]
    fn typed_evidence_semantics_fail_closed() {
        let mut completion = score_requirement(CanvasEvidenceSource::AgsResult);
        completion.fact_type = CanvasEvidenceFactType::CourseCompletion;
        completion.pass_rule = CanvasEvidencePassRuleInput {
            min_score_percent: None,
            completed: Some(true),
        };
        assert_eq!(
            CanvasProgramBindingRecord::configure(
                &platform(),
                request(completion),
                &template(),
                Map::new(),
                None,
                now(1),
            ),
            Err(CanvasBindingDomainError::InvalidEvidence(
                "completion requirements must use canvas_rest"
            ))
        );
    }

    #[test]
    fn deployment_feature_snapshot_is_closed_and_enforced() {
        let mut request = request(score_requirement(CanvasEvidenceSource::CanvasRest));
        request
            .feature_flags
            .insert("caller_defined_gate".to_owned(), true);
        request
            .feature_flags
            .insert("enable_canvas_evidence".to_owned(), false);
        assert_eq!(
            CanvasProgramBindingRecord::configure(
                &platform(),
                request,
                &template(),
                Map::new(),
                None,
                now(1),
            ),
            Err(CanvasBindingDomainError::EvidenceFeatureDisabled)
        );
    }

    #[test]
    fn projection_and_template_tenant_mismatches_are_rejected() {
        let mut foreign = template();
        foreign.organization_id = "org-2".to_owned();
        assert_eq!(
            CanvasProgramBindingRecord::configure(
                &platform(),
                request(score_requirement(CanvasEvidenceSource::CanvasRest)),
                &foreign,
                Map::new(),
                None,
                now(1),
            ),
            Err(CanvasBindingDomainError::ForeignApplicationTemplate)
        );

        let mut inactive = template();
        inactive.active = false;
        assert_eq!(
            CanvasProgramBindingRecord::configure(
                &platform(),
                request(score_requirement(CanvasEvidenceSource::CanvasRest)),
                &inactive,
                Map::new(),
                None,
                now(1),
            ),
            Err(CanvasBindingDomainError::ApplicationTemplateInactive)
        );

        let credentials = serde_json::from_value::<Map<String, Value>>(json!({
            "credential_template_id": "other-template"
        }))
        .unwrap();
        assert_eq!(
            CanvasProgramBindingRecord::configure(
                &platform(),
                request(score_requirement(CanvasEvidenceSource::CanvasRest)),
                &template(),
                credentials,
                None,
                now(1),
            ),
            Err(CanvasBindingDomainError::ProjectionTemplateMismatch)
        );
    }
}
