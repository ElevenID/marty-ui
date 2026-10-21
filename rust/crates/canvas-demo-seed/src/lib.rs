//! Demo Canvas seeding operations. This crate contains no issuer key material.
//! Signing remains resolved through the issuer profile and managed signing service.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::time::Duration;
use url::form_urlencoded;

mod canvas_rails;
mod canvas_rest;
mod cli_config;
mod database;
mod demo_evidence;
mod issuer_profile;
mod lms;
mod native_templates;
mod run;
mod transition;
mod wallet;
pub use canvas_rails::{
    canvas_admin_exists, docker_container_env_value, ensure_canvas_developer_key,
    ensure_canvas_external_tool, ensure_canvas_initial_data, ensure_canvas_public_domain,
    mint_canvas_admin_token, CanvasDocker, CanvasDockerOperation, CanvasDockerOutput,
    CanvasDockerTransport, CanvasRailsConfig, CANVAS_ADMIN_TOKEN_SCRIPT, CANVAS_LTI_SETUP_SCRIPT,
};
pub use canvas_rest::{
    ensure_course, ensure_enrollment, ensure_external_tool_assignment, ensure_module,
    ensure_module_external_tool_item, ensure_module_quiz_item, ensure_quiz, ensure_user,
    CanvasOperation, CanvasRestConfig, CanvasRestError, CanvasRestHttp, CanvasRestTransport,
};
pub use cli_config::{build_run_config, CanvasRunConfig, ConnectorRunConfig, SeedRunConfig};
pub use database::seed_open_badge_templates;
pub use demo_evidence::{
    ags_score_payload, application_payload, send_signed_ags, signed_ags_wire, DemoEvidenceConfig,
    SignedAgsWire,
};
pub use issuer_profile::IssuerProfileContext;
pub use lms::{seed_canvas_lms_objects, CanvasLmsSeedResult};
pub use native_templates::{native_badge_templates, NativeBadgeTemplateInput};
pub use run::run_seed;
pub use transition::{lookup_transition, transition_display_lines, transition_summary};
pub use wallet::{
    claim_wallet_credential, CanonicalWalletProof, WalletHttp, WalletOperation, WalletProof,
    WalletTransport,
};

#[derive(Clone, Debug)]
pub struct GatewaySeedConfig {
    pub base_url: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub credential_template_id: String,
    pub application_template_id: String,
    pub display_name: String,
    pub canvas_base_url: String,
    pub lti_client_id: String,
    pub lti_deployment_id: String,
    pub probe_after_upsert: bool,
    pub program_binding_display_name: String,
    pub program_binding_evidence_type: String,
    pub program_binding_delivery_mode: String,
    pub program_binding_auto_approve: bool,
    pub program_binding_direct_issue: bool,
    pub program_binding_score_threshold: i64,
    pub signing_keys_internal_base_url: String,
    pub badge_vct: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Operation {
    pub method: &'static str,
    pub url: String,
    pub payload: Option<Value>,
    pub timeout_seconds: u64,
}

impl Operation {
    fn get(url: String) -> Self {
        Self {
            method: "GET",
            url,
            payload: None,
            timeout_seconds: 20,
        }
    }

    fn json(method: &'static str, url: String, payload: Value) -> Self {
        Self {
            method,
            url,
            payload: Some(payload),
            timeout_seconds: 20,
        }
    }

    fn post(url: String) -> Self {
        Self {
            method: "POST",
            url,
            payload: None,
            timeout_seconds: 20,
        }
    }
}

#[async_trait]
pub trait GatewayTransport {
    async fn request(&self, operation: Operation) -> Result<Value, String>;
}

/// Shared transport for gateway seeding operations. The caller supplies an
/// organization-scoped gateway actor; issuance service credentials are not used.
pub struct GatewayHttp {
    client: reqwest::Client,
    api_key: String,
}

impl GatewayHttp {
    pub fn new(api_key: String) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("MARTY_API_KEY is required for Canvas gateway seeding".into());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, api_key })
    }
}

#[async_trait]
impl GatewayTransport for GatewayHttp {
    async fn request(&self, operation: Operation) -> Result<Value, String> {
        let method =
            reqwest::Method::from_bytes(operation.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut request = self
            .client
            .request(method, &operation.url)
            .timeout(Duration::from_secs(operation.timeout_seconds))
            .header("Accept", "application/json")
            .header("X-API-Key", &self.api_key);
        if let Some(payload) = operation.payload {
            request = request.json(&payload);
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("Canvas gateway request failed ({status})"));
        }
        let body = response.text().await.map_err(|e| e.to_string())?;
        if body.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&body).map_err(|e| e.to_string())
        }
    }
}

pub struct UpsertResult {
    pub action: &'static str,
    pub value: Value,
}

fn base(cfg: &GatewaySeedConfig) -> &str {
    cfg.base_url.trim_end_matches('/')
}

fn id(value: &Value) -> Option<&str> {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn object_id(value: &Value, error: &str) -> Result<String, String> {
    id(value).map(str::to_owned).ok_or_else(|| error.to_owned())
}

pub fn demo_scope(
    course_id: Option<&str>,
    quiz_id: Option<&str>,
    assignment_id: Option<&str>,
    module_id: Option<&str>,
) -> Value {
    let mut scope = Map::new();
    for (key, value) in [
        ("course_id", course_id),
        ("quiz_id", quiz_id),
        ("assignment_id", assignment_id),
        ("module_id", module_id),
    ] {
        if let Some(value) = value {
            scope.insert(key.into(), Value::String(value.into()));
        }
    }
    Value::Object(scope)
}

pub fn remote_signing_config(
    signing_keys_internal_base_url: &str,
    issuer: &IssuerProfileContext,
) -> Value {
    json!({
        "provider": "gateway-signing-key-registry",
        "issuer_profile_id": issuer.issuer_profile_id,
        "issuer_did": issuer.issuer_did,
        "verification_method_id": issuer.verification_method_id,
        "signing_service_id": issuer.signing_service_id,
        "signing_key_reference": issuer.signing_key_reference,
        "key_purpose": "vc_jwt_issuer",
        "credential_formats": ["sd_jwt_vc", "jwt_vc_json"],
        "secret_boundary": {
            "issuer_private_key_location": "external_remote_key_store",
            "beta_elevenidllc_com_private_key_material": "not_present",
            "canvas_private_key_material": "not_present"
        },
        "resolver": {
            "url": format!("{}/issuer-context", signing_keys_internal_base_url.trim_end_matches('/')),
            "api_key_source": "SIGNING_KEYS_INTERNAL_API_KEY"
        }
    })
}

const BADGE_VCT: &str =
    "https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge";
const BADGE_NAME: &str = "Interoperable Credentials Foundations Badge";
const BADGE_DESCRIPTION: &str = "Open Badge 3.0 credential for completing the Interoperable Credentials Foundations learning check in Canvas.";

fn badge_claims() -> Value {
    let claims: [(&str, &str, &str, bool); 18] = [
        ("email", "Learner email", "string", true),
        ("given_name", "Given name", "string", true),
        ("family_name", "Family name", "string", true),
        ("achievement_id", "Achievement ID", "string", false),
        ("achievement_name", "Achievement", "string", true),
        (
            "achievement_description",
            "Achievement description",
            "string",
            true,
        ),
        (
            "achievement_criteria",
            "Achievement criteria",
            "string",
            false,
        ),
        ("badge_image_url", "Badge image", "image", false),
        ("course_name", "Canvas course", "string", true),
        ("quiz_name", "Canvas quiz", "string", true),
        ("score_percent", "Score percent", "number", true),
        ("completion_date", "Completion date", "date", true),
        ("institution_name", "Institution", "string", true),
        ("certificate_id", "Certificate ID", "string", true),
        ("organization_id", "Issuer organization", "string", false),
        ("achievement", "Open Badge achievement", "object", false),
        ("result", "Canvas quiz result", "object", true),
        (
            "learning_context",
            "Canvas learning context",
            "object",
            true,
        ),
    ];
    Value::Array(
        claims
            .into_iter()
            .map(
                |(name, display_name, claim_type, selectively_disclosable)| {
                    json!({
                        "name": name,
                        "display_name": display_name,
                        "claim_type": claim_type,
                        "required": true,
                        "selectively_disclosable": selectively_disclosable
                    })
                },
            )
            .collect(),
    )
}

pub fn credential_template_payload(
    cfg: &GatewaySeedConfig,
    issuer: &IssuerProfileContext,
) -> Value {
    let mut payload = badge_credential_definition(&cfg.organization_id, &cfg.badge_vct);
    payload.as_object_mut().unwrap().extend(json!({
        "id": cfg.credential_template_id,
        "status": "active",
        "issuer_requirements": {"allowed_issuer_dids": [issuer.issuer_did], "trust_tier_required": "organization_managed_remote_signing", "audit_level_required": "standard"},
        "wallet_configs": [
            {"wallet_id": "waltid", "deep_link_scheme": "openid-credential-offer://", "format_variant": null},
            {"wallet_id": "spruceid", "deep_link_scheme": "spruceid://", "format_variant": "dc+sd-jwt"}
        ],
        "key_access_mode": "REMOTE_SIGNING",
        "issuer_key_id": issuer.signing_key_reference,
        "issuer_algorithm": "ES256",
        "remote_signing_config": remote_signing_config(&cfg.signing_keys_internal_base_url, issuer),
        "version": 1
    }).as_object().unwrap().clone());
    payload
}

fn badge_credential_definition(organization_id: &str, badge_vct: &str) -> Value {
    let image = format!("{badge_vct}/image.svg");
    json!({
        "organization_id": organization_id,
        "name": BADGE_NAME,
        "description": BADGE_DESCRIPTION,
        "credential_type": "OpenBadgeCredential",
        "vct": badge_vct,
        "doctype": "org.openbadges.v3",
        "claims": badge_claims(),
        "privacy_posture": "selective_disclosure",
        "selective_disclosure_fields": ["email", "given_name", "family_name", "achievement_name", "achievement_description", "course_name", "quiz_name", "score_percent", "completion_date", "institution_name", "certificate_id", "result", "learning_context"],
        "zk_predicate_claims": [],
        "derived_attributes": [],
        "display_style": {"background_color": "#0B5F7A", "text_color": "#ffffff", "icon": "award", "logo_url": image},
        "validity_rules": {"duration": "P1Y", "renewal_required": false},
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt"
    })
}

pub fn open_badge_evidence_requirement(cfg: &GatewaySeedConfig, scope: &Value) -> Value {
    json!({
        "id": "canvas-quiz-score",
        "label": "Canvas quiz score",
        "evidence_type": "EXTERNAL_FACT",
        "provider": "canvas",
        "fact_type": cfg.program_binding_evidence_type,
        "verification_method": "SIGNED_AGS_SCORE",
        "scope": scope,
        "pass_rule": {"path": "assertion.score_percent", "operator": ">=", "value": cfg.program_binding_score_threshold},
        "required": true,
        "auto_issue_on_permit": cfg.program_binding_auto_approve
    })
}

pub fn application_template_payload(
    cfg: &GatewaySeedConfig,
    scope: &Value,
    issuer: &IssuerProfileContext,
) -> Value {
    let badge_vct = &cfg.badge_vct;
    let fields = [
        ("email", "Email", "email"),
        ("given_name", "Given name", "text"),
        ("family_name", "Family name", "text"),
        ("course_name", "Canvas course", "text"),
        ("quiz_name", "Canvas quiz", "text"),
        ("score_percent", "Score percent", "number"),
    ];
    json!({
        "id": cfg.application_template_id,
        "organization_id": cfg.organization_id,
        "name": "Interoperable Credentials Foundations Application",
        "description": "Canvas-started application workflow for the interoperability Open Badge demonstration.",
        "credential_template_id": cfg.credential_template_id,
        "form_fields": fields.into_iter().map(|(name, label, kind)| json!({"name": name, "label": label, "type": kind, "required": true})).collect::<Vec<_>>(),
        "evidence_requirements": [open_badge_evidence_requirement(cfg, scope)],
        "claim_collection_rules": [],
        "required_checks": [],
        "approval_strategy": "policy",
        "approval_policy_set_id": null,
        "application_validity_days": 30,
        "auto_approval_rules": [],
        "ui_config": {
            "scenario": "canvas_mip_quiz_open_badge",
            "provider": "canvas",
            "fact_type": cfg.program_binding_evidence_type,
            "scope": scope,
            "delivery_mode": cfg.program_binding_delivery_mode,
            "issuer_mode": "org_managed",
            "issuer_did": issuer.issuer_did,
            "open_badge": {
                "vct": badge_vct,
                "name": BADGE_NAME,
                "image": format!("{badge_vct}/image.svg"),
                "criteria": format!("{badge_vct}/criteria")
            }
        },
        "notification_config": {},
        "status": "active"
    })
}

pub async fn upsert_platform<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
    update_existing: bool,
) -> Result<UpsertResult, String> {
    let platforms = transport
        .request(Operation::get(format!(
            "{}/v1/integrations/canvas/platforms?organization_id={}",
            base(cfg),
            cfg.organization_id
        )))
        .await?;
    let platforms = platforms
        .as_array()
        .ok_or("Unexpected Canvas platform list response from issuance API")?;
    let existing = platforms.iter().find(|item| {
        item.get("organization_id").and_then(Value::as_str) == Some(cfg.organization_id.as_str())
            && item
                .get("canvas_base_url")
                .and_then(Value::as_str)
                .is_some_and(|origin| {
                    origin.trim_end_matches('/') == cfg.canvas_base_url.trim_end_matches('/')
                })
    });
    let payload = json!({
        "display_name": cfg.display_name,
        "canvas_base_url": cfg.canvas_base_url,
        "lti_client_id": cfg.lti_client_id,
        "lti_deployment_id": cfg.lti_deployment_id,
        "enabled": true
    });
    if let Some(existing) = existing {
        let matches_request = [
            "display_name",
            "canvas_base_url",
            "lti_client_id",
            "lti_deployment_id",
        ]
        .iter()
        .all(|field| existing.get(*field) == payload.get(*field))
            && existing.get("enabled").and_then(Value::as_bool) == Some(true);
        if !update_existing || matches_request {
            return Ok(UpsertResult {
                action: "preserved",
                value: existing.clone(),
            });
        }
    }
    let (operation, action) = match existing.and_then(id) {
        Some(existing_id) => (
            Operation::json(
                "PUT",
                format!(
                    "{}/v1/integrations/canvas/platforms/{existing_id}",
                    base(cfg)
                ),
                payload,
            ),
            "updated",
        ),
        None => (
            Operation::json(
                "POST",
                format!("{}/v1/integrations/canvas/platforms", base(cfg)),
                payload,
            ),
            "created",
        ),
    };
    let mut platform = transport.request(operation).await?;
    let platform_id = object_id(
        &platform,
        "Canvas platform upsert did not return a valid platform payload",
    )?;
    if cfg.probe_after_upsert {
        let probed = transport
            .request(Operation::json(
                "POST",
                format!(
                    "{}/v1/integrations/canvas/platforms/{platform_id}/sandbox-probe",
                    base(cfg)
                ),
                json!({}),
            ))
            .await?;
        if let Some(probed_platform) = probed.get("platform").filter(|value| value.is_object()) {
            platform = probed_platform.clone();
        }
    }
    Ok(UpsertResult {
        action,
        value: platform,
    })
}

pub async fn refresh_platform_jwks<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
    platform_id: &str,
) -> Result<Value, String> {
    let refreshed = transport
        .request(Operation {
            method: "POST",
            url: format!(
                "{}/v1/integrations/canvas/platforms/{platform_id}/jwks-refresh",
                base(cfg)
            ),
            payload: None,
            timeout_seconds: 20,
        })
        .await?;
    if !refreshed.get("platform").is_some_and(Value::is_object) {
        return Err("Canvas platform JWKS refresh did not return a valid platform payload".into());
    }
    Ok(refreshed)
}

pub async fn install_platform<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
    platform_id: &str,
) -> Result<Value, String> {
    let registration = transport
        .request(Operation::json(
            "PUT",
            format!(
                "{}/v1/integrations/canvas/platforms/{platform_id}/lti-installation",
                base(cfg)
            ),
            json!({
                "lti_client_id": cfg.lti_client_id,
                "lti_deployment_id": cfg.lti_deployment_id,
                "rotate_config_token": false,
                "revoke_config_token": false
            }),
        ))
        .await?;
    if registration.get("platform_id").and_then(Value::as_str) != Some(platform_id) {
        return Err("Canvas LTI installation did not confirm the platform ID".into());
    }
    let platform = transport
        .request(Operation::get(format!(
            "{}/v1/integrations/canvas/platforms/{platform_id}",
            base(cfg)
        )))
        .await?;
    if platform.get("enabled").and_then(Value::as_bool) != Some(true)
        || !matches!(
            platform.get("registration_status").and_then(Value::as_str),
            Some("installed" | "verified")
        )
    {
        return Err("Canvas LTI platform is not installed and enabled".into());
    }
    Ok(platform)
}

pub fn binding_feature_flags(delivery_mode: &str) -> Value {
    let mirror = delivery_mode == "wallet_plus_canvas_mirror";
    json!({
        "enable_canvas_evidence": true,
        "enable_canvas_lti": true,
        "enable_canvas_mirror_publish": mirror,
        "enable_canvas_mirror_ops": mirror,
        "enable_canvas_deep_linking": true,
        "enable_canvas_ags": true,
        "enable_canvas_nrps": true
    })
}

pub fn binding_evidence_requirement(
    cfg: &GatewaySeedConfig,
    evidence_scope: &Value,
) -> Result<Value, String> {
    let score = cfg.program_binding_evidence_type.ends_with("_score");
    let course_id = evidence_scope
        .get("course_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Canvas binding evidence requires a course ID")?;
    let rule = if score {
        json!({"min_score_percent": cfg.program_binding_score_threshold})
    } else {
        json!({"completed": true})
    };
    Ok(json!({
        "requirement_id": null,
        "source": if score { "ags_result" } else { "canvas_rest" },
        "fact_type": cfg.program_binding_evidence_type,
        "scope": {
            "course_id": course_id,
            "activity_id": evidence_scope.get("quiz_id").or_else(|| evidence_scope.get("assignment_id")),
            "module_id": evidence_scope.get("module_id"),
            "line_item_url": null,
            "resource_id": null
        },
        "pass_rule": rule,
        "required": true
    }))
}

fn binding_matches_policy(binding: &Value, desired: &Value) -> bool {
    for field in [
        "application_template_id",
        "credential_template_id",
        "display_name",
        "auto_approve_on_evidence",
        "canvas_scope",
        "delivery_mode",
        "approval_policy_set_id",
        "deployment_profile_id",
        "feature_flags",
    ] {
        if binding.get(field) != desired.get(field) {
            return false;
        }
    }
    let Some(actual) = binding
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .and_then(|items| items.first())
    else {
        return false;
    };
    let expected = &desired["evidence_requirements"][0];
    for field in ["source", "fact_type", "pass_rule", "required"] {
        if actual.get(field) != expected.get(field) {
            return false;
        }
    }
    for field in ["course_id", "activity_id", "module_id"] {
        if actual["scope"].get(field).filter(|value| !value.is_null())
            != expected["scope"]
                .get(field)
                .filter(|value| !value.is_null())
        {
            return false;
        }
    }
    true
}

pub async fn upsert_binding<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
    platform: &Value,
    canvas_scope: &Value,
    evidence_scope: &Value,
    activate: bool,
) -> Result<UpsertResult, String> {
    if cfg.program_binding_direct_issue {
        return Err("Canvas direct issuance is unsupported by the program binding API".into());
    }
    let platform_id = object_id(
        platform,
        "Canvas program binding seed requires a platform ID",
    )?;
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("organization_id", &cfg.organization_id)
        .append_pair("platform_id", &platform_id)
        .append_pair("application_template_id", &cfg.application_template_id)
        .finish();
    let bindings = transport
        .request(Operation::get(format!(
            "{}/v1/integrations/canvas/program-bindings?{query}",
            base(cfg)
        )))
        .await?;
    let bindings = bindings
        .as_array()
        .ok_or("Unexpected Canvas program binding list response from issuance API")?;
    let empty_scope = json!({});
    let existing = bindings.iter().find(|item| {
        item.get("credential_template_id").and_then(Value::as_str)
            == Some(cfg.credential_template_id.as_str())
            && item
                .get("canvas_scope")
                .filter(|value| !value.is_null())
                .unwrap_or(&empty_scope)
                == canvas_scope
    });
    let requirement = binding_evidence_requirement(cfg, evidence_scope)?;
    let payload = json!({
        "application_template_id": cfg.application_template_id,
        "credential_template_id": cfg.credential_template_id,
        "display_name": cfg.program_binding_display_name,
        "auto_approve_on_evidence": cfg.program_binding_auto_approve,
        "evidence_requirements": [requirement],
        "canvas_scope": canvas_scope,
        "delivery_mode": cfg.program_binding_delivery_mode,
        "approval_policy_set_id": null,
        "deployment_profile_id": null,
        "feature_flags": binding_feature_flags(&cfg.program_binding_delivery_mode)
    });
    let already_active = existing.is_some_and(|binding| {
        binding.get("enabled").and_then(Value::as_bool) == Some(true)
            && binding
                .get("activated_at")
                .is_some_and(|value| !value.is_null())
    });
    let same_policy = existing.is_some_and(|binding| binding_matches_policy(binding, &payload));
    if already_active && !same_policy {
        return Err("Active Canvas program binding differs from the requested seed policy; review and reconfigure it explicitly".into());
    }
    let (operation, action) = match existing.and_then(id) {
        Some(existing_id) if same_policy => (
            Operation::get(format!(
                "{}/v1/integrations/canvas/program-bindings/{existing_id}",
                base(cfg)
            )),
            "preserved",
        ),
        Some(existing_id) => (
            Operation::json(
                "PUT",
                format!(
                    "{}/v1/integrations/canvas/program-bindings/{existing_id}",
                    base(cfg)
                ),
                payload,
            ),
            "updated",
        ),
        None => (
            Operation::json(
                "POST",
                format!(
                    "{}/v1/integrations/canvas/platforms/{platform_id}/program-bindings",
                    base(cfg)
                ),
                payload,
            ),
            "created",
        ),
    };
    let binding = transport.request(operation).await?;
    let binding_id = object_id(
        &binding,
        "Canvas program binding upsert did not return a valid binding payload",
    )?;
    if !activate {
        return Ok(UpsertResult {
            action,
            value: binding,
        });
    }
    let binding_base = format!(
        "{}/v1/integrations/canvas/program-bindings/{binding_id}",
        base(cfg)
    );
    let validation = transport
        .request(Operation::post(format!("{binding_base}/validate")))
        .await?;
    if validation.get("binding_id").and_then(Value::as_str) != Some(binding_id.as_str())
        || validation.get("ready").and_then(Value::as_bool) != Some(true)
        || validation.get("valid").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!("Canvas program binding {binding_id} is staged but not ready; complete a signed staff LTI Deep Linking launch, then rerun the seed to validate and activate"));
    }
    if !already_active {
        let activation = transport
            .request(Operation::post(format!("{binding_base}/activate")))
            .await?;
        if activation.get("binding_id").and_then(Value::as_str) != Some(binding_id.as_str())
            || activation.get("active").and_then(Value::as_bool) != Some(true)
        {
            return Err("Canvas program binding activation did not complete".into());
        }
    }
    let binding = transport.request(Operation::get(binding_base)).await?;
    if binding.get("enabled").and_then(Value::as_bool) != Some(true)
        || binding.get("activated_at").is_none_or(Value::is_null)
        || binding.get("validated_config_version") != binding.get("config_version")
    {
        return Err("Canvas program binding is not active at the validated config version".into());
    }
    Ok(UpsertResult {
        action,
        value: binding,
    })
}

pub async fn run_mirror_publish<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
) -> Result<Value, String> {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("organization_id", &cfg.organization_id)
        .append_pair("limit", "25")
        .append_pair("retry_failed", "true")
        .finish();
    let mut operation = Operation::json(
        "POST",
        format!(
            "{}/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle?{query}",
            base(cfg)
        ),
        json!({}),
    );
    operation.timeout_seconds = 60;
    let response = transport.request(operation).await?;
    if !response.is_object() {
        return Err("Unexpected Canvas credential mirror publish response".into());
    }
    Ok(response)
}

/// Issuer context is optional demo metadata. Managed signing and issuer profile
/// selection remain owned by the signing service; this never handles key material.
pub async fn resolve_issuer_context<T: GatewayTransport + Sync>(
    transport: &T,
    organization_id: &str,
    signing_keys_internal_base_url: &str,
    signing_keys_internal_api_key: &str,
) -> Option<Value> {
    if signing_keys_internal_api_key.trim().is_empty() {
        return None;
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("organization_id", organization_id)
        .append_pair("credential_format", "sd_jwt_vc")
        .append_pair("key_purpose", "vc_jwt_issuer")
        .finish();
    let response = transport
        .request(Operation::get(format!(
            "{}/issuer-context?{query}",
            signing_keys_internal_base_url.trim_end_matches('/')
        )))
        .await
        .ok()?;
    let context = response.as_object()?;
    Some(json!({
        "issuer_profile_id": context.get("issuer_profile_id"),
        "issuer_did": context.get("issuer_did"),
        "signing_service_id": context.get("signing_service_id"),
        "signing_key_reference": context.get("signing_key_reference"),
        "verification_method_id": context.get("verification_method_id"),
    }))
}
