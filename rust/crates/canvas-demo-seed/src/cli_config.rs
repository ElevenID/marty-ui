//! Canvas demo CLI configuration, kept separate from side effects.

use crate::{DemoEvidenceConfig, GatewaySeedConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorRunConfig {
    pub issuance_base_url: String,
    pub issuance_api_key: String,
    pub internal_issuance_base_url: String,
    pub internal_issuance_api_key: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub credential_template_id: String,
    pub application_template_id: String,
    pub display_name: String,
    pub canvas_base_url: String,
    pub lti_tool_base_url: String,
    pub lti_client_id: String,
    pub lti_deployment_id: String,
    pub probe_after_upsert: bool,
    pub program_binding_seed_enabled: bool,
    pub program_binding_display_name: String,
    pub program_binding_evidence_type: String,
    pub program_binding_delivery_mode: String,
    pub program_binding_auto_approve: bool,
    pub program_binding_direct_issue: bool,
    pub program_binding_score_threshold: i64,
    pub open_badge_scenario_enabled: bool,
    pub demo_application_seed_enabled: bool,
    pub demo_evidence_event_enabled: bool,
    pub demo_wallet_claim_enabled: bool,
    pub demo_mirror_publish_enabled: bool,
    pub signing_keys_internal_base_url: String,
    pub signing_keys_internal_api_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanvasRunConfig {
    pub enabled: bool,
    pub api_base_url: String,
    pub browser_base_url: String,
    pub admin_token: String,
    pub admin_email: String,
    pub admin_password: String,
    pub account_id: String,
    pub container_name: String,
    pub course_name: String,
    pub course_code: String,
    pub course_sis_id: String,
    pub learner_name: String,
    pub learner_email: String,
    pub learner_password: String,
    pub launch_seed_enabled: bool,
    pub launch_module_name: String,
    pub launch_item_title: String,
    pub launch_assignment_name: String,
    pub quiz_seed_enabled: bool,
    pub quiz_title: String,
    pub quiz_description: String,
    pub quiz_passing_score_percent: i64,
    pub quiz_points_possible: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedRunConfig {
    pub connector: ConnectorRunConfig,
    pub canvas: CanvasRunConfig,
}

impl From<&ConnectorRunConfig> for GatewaySeedConfig {
    fn from(config: &ConnectorRunConfig) -> Self {
        Self {
            base_url: config.issuance_base_url.clone(),
            organization_id: config.organization_id.clone(),
            canvas_account_id: config.canvas_account_id.clone(),
            credential_template_id: config.credential_template_id.clone(),
            application_template_id: config.application_template_id.clone(),
            display_name: config.display_name.clone(),
            canvas_base_url: config.canvas_base_url.clone(),
            lti_client_id: config.lti_client_id.clone(),
            lti_deployment_id: config.lti_deployment_id.clone(),
            probe_after_upsert: config.probe_after_upsert,
            program_binding_display_name: config.program_binding_display_name.clone(),
            program_binding_evidence_type: config.program_binding_evidence_type.clone(),
            program_binding_delivery_mode: config.program_binding_delivery_mode.clone(),
            program_binding_auto_approve: config.program_binding_auto_approve,
            program_binding_direct_issue: config.program_binding_direct_issue,
            program_binding_score_threshold: config.program_binding_score_threshold,
            signing_keys_internal_base_url: config.signing_keys_internal_base_url.clone(),
        }
    }
}

impl From<&CanvasRunConfig> for DemoEvidenceConfig {
    fn from(config: &CanvasRunConfig) -> Self {
        Self {
            learner_name: config.learner_name.clone(),
            learner_email: config.learner_email.clone(),
            course_name: config.course_name.clone(),
            quiz_title: config.quiz_title.clone(),
            quiz_passing_score_percent: config.quiz_passing_score_percent,
            quiz_points_possible: config.quiz_points_possible,
        }
    }
}

fn value(env: &HashMap<String, String>, name: &str, default: &str) -> String {
    env.get(name).cloned().unwrap_or_else(|| default.into())
}

fn trimmed(env: &HashMap<String, String>, name: &str, default: &str) -> String {
    value(env, name, default).trim().to_owned()
}

fn enabled(env: &HashMap<String, String>, name: &str, default: bool) -> bool {
    env.get(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn number(env: &HashMap<String, String>, name: &str, default: &str) -> Result<i64, String> {
    value(env, name, default)
        .parse::<i64>()
        .map_err(|error| format!("{name} must be an integer: {error}"))
}

fn system_id(ids: &serde_json::Value, name: &str) -> Result<String, String> {
    ids.get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("Missing Canvas system ID {name}"))
}

pub fn build_run_config(
    env: &HashMap<String, String>,
    skip_canvas_lms_seed: bool,
    probe_after_upsert: bool,
) -> Result<SeedRunConfig, String> {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/demo-seed-reference-v1.json"
    ))
    .map_err(|error| error.to_string())?;
    if reference["schema"] != "marty.demo-seed-reference/v1" {
        return Err("Unexpected demo seed reference schema".into());
    }
    let ids = &reference["canvas_system_ids"];
    let issuance_base_url = trimmed(env, "MARTY_API_BASE_URL", "http://localhost:8000")
        .trim_end_matches('/')
        .to_owned();
    let issuance_api_key = trimmed(env, "MARTY_API_KEY", "");
    if issuance_api_key.is_empty() {
        return Err("MARTY_API_KEY is required and must identify an organization-scoped gateway actor with scopes: integrations:read, integrations:write. ISSUANCE_API_KEY is a service credential and is not accepted by the gateway.".into());
    }
    let internal_issuance_base_url = trimmed(env, "ISSUANCE_INTERNAL_API_BASE_URL", "")
        .trim_end_matches('/')
        .to_owned();
    let internal_issuance_api_key = trimmed(env, "ISSUANCE_API_KEY", "");
    let open_badge = enabled(env, "CANVAS_OPEN_BADGE_SCENARIO_ENABLED", true);
    let demo_application = enabled(env, "CANVAS_DEMO_APPLICATION_SEED_ENABLED", true);
    if demo_application
        && (internal_issuance_base_url.is_empty() || internal_issuance_api_key.is_empty())
    {
        return Err("Canvas demo application seeding requires ISSUANCE_INTERNAL_API_BASE_URL and ISSUANCE_API_KEY for the direct internal issuance operation.".into());
    }
    if demo_application && internal_issuance_base_url == issuance_base_url {
        return Err("ISSUANCE_INTERNAL_API_BASE_URL must target the issuance service directly, not the public gateway.".into());
    }
    let raw_canvas_api_base_url = trimmed(env, "CANVAS_API_BASE_URL", "http://localhost:8088");
    let raw_canvas_connector_base_url = trimmed(env, "CANVAS_CONNECTOR_BASE_URL", "");
    let raw_lti_tool_base_url = trimmed(env, "CANVAS_LTI_EXPERIENCE_BASE_URL", "");
    let raw_lti_tool_base_url = if raw_lti_tool_base_url.is_empty() {
        trimmed(env, "CANVAS_LTI_TOOL_BASE_URL", "")
    } else {
        raw_lti_tool_base_url
    };
    let raw_canvas_browser_base_url = trimmed(env, "CANVAS_BROWSER_BASE_URL", "");
    let raw_canvas_public_host = trimmed(env, "CANVAS_REAL_PUBLIC_HOST", "");
    let inferred_connector = if raw_canvas_public_host.is_empty() {
        raw_canvas_api_base_url.trim_end_matches('/').to_owned()
    } else {
        format!("https://{raw_canvas_public_host}")
    };
    let inferred_browser = if raw_canvas_browser_base_url.is_empty() {
        if raw_canvas_public_host.is_empty() {
            raw_canvas_api_base_url.clone()
        } else {
            format!("https://{raw_canvas_public_host}")
        }
    } else {
        raw_canvas_browser_base_url
    };
    let lti_tool_base_url = if raw_lti_tool_base_url.is_empty() {
        let public_api = trimmed(env, "PUBLIC_API_URL", "");
        if public_api.is_empty() {
            "http://localhost:8000".into()
        } else {
            public_api
        }
    } else {
        raw_lti_tool_base_url
    };
    let default_credential_template = if open_badge {
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID"
    } else {
        "MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID"
    };
    let default_application_template = if open_badge {
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID"
    } else {
        "MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID"
    };
    let display_name = value(env, "CANVAS_CONNECTOR_DISPLAY_NAME", "Canvas Real LMS");
    let connector = ConnectorRunConfig {
        issuance_base_url,
        issuance_api_key,
        internal_issuance_base_url,
        internal_issuance_api_key,
        organization_id: value(
            env,
            "CANVAS_ORGANIZATION_ID",
            &system_id(ids, "MARTY_DEFAULT_ORG_ID")?,
        ),
        canvas_account_id: value(env, "CANVAS_ACCOUNT_ID", "canvas-real-account-1"),
        credential_template_id: value(
            env,
            "CANVAS_CREDENTIAL_TEMPLATE_ID",
            &system_id(ids, default_credential_template)?,
        ),
        application_template_id: value(
            env,
            "CANVAS_APPLICATION_TEMPLATE_ID",
            &system_id(ids, default_application_template)?,
        ),
        display_name: display_name.clone(),
        canvas_base_url: if raw_canvas_connector_base_url.is_empty() {
            inferred_connector
        } else {
            raw_canvas_connector_base_url
        },
        lti_tool_base_url,
        lti_client_id: value(env, "CANVAS_LTI_CLIENT_ID", "canvas-real-client-id"),
        lti_deployment_id: value(env, "CANVAS_LTI_DEPLOYMENT_ID", "canvas-real-deployment-id"),
        probe_after_upsert: probe_after_upsert || enabled(env, "CANVAS_PROBE_AFTER_UPSERT", false),
        program_binding_seed_enabled: enabled(env, "CANVAS_PROGRAM_BINDING_SEED_ENABLED", true),
        program_binding_display_name: value(
            env,
            "CANVAS_PROGRAM_BINDING_DISPLAY_NAME",
            &value(
                env,
                "CANVAS_CONNECTOR_DISPLAY_NAME",
                "Marty Canvas Experiment",
            ),
        ),
        program_binding_evidence_type: value(
            env,
            "CANVAS_PROGRAM_BINDING_EVIDENCE_TYPE",
            if open_badge {
                "canvas.quiz_score"
            } else {
                "canvas.course_completion"
            },
        ),
        program_binding_delivery_mode: value(
            env,
            "CANVAS_PROGRAM_BINDING_DELIVERY_MODE",
            if open_badge {
                "wallet_plus_canvas_mirror"
            } else {
                "wallet_only"
            },
        ),
        program_binding_auto_approve: enabled(env, "CANVAS_PROGRAM_BINDING_AUTO_APPROVE", true),
        program_binding_direct_issue: enabled(env, "CANVAS_PROGRAM_BINDING_DIRECT_ISSUE", false),
        program_binding_score_threshold: number(
            env,
            "CANVAS_PROGRAM_BINDING_SCORE_THRESHOLD",
            "80",
        )?,
        open_badge_scenario_enabled: open_badge,
        demo_application_seed_enabled: demo_application,
        demo_evidence_event_enabled: enabled(env, "CANVAS_DEMO_EVIDENCE_EVENT_ENABLED", false),
        demo_wallet_claim_enabled: enabled(env, "CANVAS_DEMO_WALLET_CLAIM_ENABLED", true),
        demo_mirror_publish_enabled: enabled(env, "CANVAS_DEMO_MIRROR_PUBLISH_ENABLED", true),
        signing_keys_internal_base_url: value(
            env,
            "SIGNING_KEYS_INTERNAL_BASE_URL",
            "http://localhost:8000/internal/signing-keys",
        ),
        signing_keys_internal_api_key: value(
            env,
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "dev-signing-keys-internal-api-key",
        ),
    };
    let admin_email = trimmed(env, "CANVAS_ADMIN_EMAIL", "admin@example.com");
    let container_name = trimmed(env, "CANVAS_REAL_CONTAINER_NAME", "marty-canvas-real");
    let canvas = CanvasRunConfig {
        enabled: !skip_canvas_lms_seed && enabled(env, "CANVAS_LMS_SEED_ENABLED", true),
        api_base_url: raw_canvas_api_base_url,
        browser_base_url: inferred_browser.trim_end_matches('/').to_owned(),
        admin_token: trimmed(env, "CANVAS_ADMIN_ACCESS_TOKEN", ""),
        admin_email: if admin_email.is_empty() { "admin@example.com".into() } else { admin_email },
        admin_password: value(env, "CANVAS_ADMIN_PASSWORD", "readystack123"),
        account_id: value(env, "CANVAS_ROOT_ACCOUNT_ID", "1"),
        container_name: if container_name.is_empty() { "marty-canvas-real".into() } else { container_name },
        course_name: value(env, "CANVAS_TEST_COURSE_NAME", "ElevenID LTI Test Course"),
        course_code: value(env, "CANVAS_TEST_COURSE_CODE", "ELEVENID-LTI-101"),
        course_sis_id: value(env, "CANVAS_TEST_COURSE_SIS_ID", "elevenid_lti_test"),
        learner_name: value(env, "CANVAS_TEST_LEARNER_NAME", "ElevenID Test Learner"),
        learner_email: value(env, "CANVAS_TEST_LEARNER_EMAIL", "learner+elevenid@example.edu"),
        learner_password: value(env, "CANVAS_TEST_LEARNER_PASSWORD", "ChangeMe123!"),
        launch_seed_enabled: enabled(env, "CANVAS_LAUNCH_SEED_ENABLED", true),
        launch_module_name: value(env, "CANVAS_TEST_MODULE_NAME", "ElevenID Credential Launch"),
        launch_item_title: value(env, "CANVAS_TEST_MODULE_ITEM_TITLE", "Launch ElevenID Credential Issuance"),
        launch_assignment_name: value(env, "CANVAS_TEST_ASSIGNMENT_NAME", "ElevenID Credential Issuance"),
        quiz_seed_enabled: enabled(env, "CANVAS_TEST_QUIZ_SEED_ENABLED", open_badge),
        quiz_title: value(env, "CANVAS_TEST_QUIZ_TITLE", "Interoperable Credentials Foundations Quiz"),
        quiz_description: value(env, "CANVAS_TEST_QUIZ_DESCRIPTION", "Demo quiz used to issue an ElevenID Open Badge through MIP policy and remote DID signing."),
        quiz_passing_score_percent: number(env, "CANVAS_TEST_QUIZ_PASSING_SCORE_PERCENT", "92")?,
        quiz_points_possible: number(env, "CANVAS_TEST_QUIZ_POINTS_POSSIBLE", "100")?,
    };
    Ok(SeedRunConfig { connector, canvas })
}
