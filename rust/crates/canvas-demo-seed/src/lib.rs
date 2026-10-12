//! Demo Canvas seeding operations. This crate contains no issuer key material.
//! Signing remains resolved through the issuer profile and managed signing service.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::time::Duration;
use url::form_urlencoded;

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
}

#[derive(Clone, Debug, PartialEq)]
pub struct Operation {
    pub method: &'static str,
    pub url: String,
    pub payload: Option<Value>,
}

impl Operation {
    fn get(url: String) -> Self {
        Self {
            method: "GET",
            url,
            payload: None,
        }
    }

    fn json(method: &'static str, url: String, payload: Value) -> Self {
        Self {
            method,
            url,
            payload: Some(payload),
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
            .header("Accept", "application/json")
            .header("X-API-Key", &self.api_key);
        if let Some(payload) = operation.payload {
            request = request.json(&payload);
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("Canvas gateway request failed ({status}): {body}"));
        }
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

pub fn remote_signing_config(signing_keys_internal_base_url: &str) -> Value {
    json!({
        "provider": "gateway-signing-key-registry",
        "issuer_profile_id": "ip-marty-vc-jwt-issuer",
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
        "verification_method_id": "did:web:beta.elevenidllc.com:orgs:marty#cred-issuer-marty-es256",
        "signing_service_id": "managed-openbao-transit",
        "signing_key_reference": "cred-issuer-marty-es256",
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

pub async fn upsert_platform<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
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
            && item.get("canvas_account_id").and_then(Value::as_str)
                == Some(cfg.canvas_account_id.as_str())
    });
    let mut payload = json!({
        "organization_id": cfg.organization_id,
        "canvas_account_id": cfg.canvas_account_id,
        "display_name": cfg.display_name,
        "canvas_base_url": cfg.canvas_base_url,
        "lti_client_id": cfg.lti_client_id,
        "lti_deployment_id": cfg.lti_deployment_id,
        "enabled": true
    });
    if let Some(existing) = existing {
        for key in [
            "lti_issuer",
            "lti_jwks_url",
            "lti_jwks_json",
            "lti_jwks_fetched_at",
            "lti_jwks_expires_at",
            "lti_openid_configuration",
        ] {
            if let Some(value) = existing.get(key).filter(|value| !value.is_null()) {
                payload[key] = value.clone();
            }
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
        })
        .await?;
    if !refreshed.get("platform").is_some_and(Value::is_object) {
        return Err("Canvas platform JWKS refresh did not return a valid platform payload".into());
    }
    Ok(refreshed)
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

pub fn binding_evidence_requirement(cfg: &GatewaySeedConfig, scope: &Value) -> Value {
    let score = cfg.program_binding_evidence_type.ends_with("_score");
    let rule = if score {
        json!({"path": "assertion.score_percent", "operator": ">=", "value": cfg.program_binding_score_threshold})
    } else {
        json!({"path": "assertion.completed", "operator": "equals", "value": true})
    };
    json!({
        "evidence_type": "EXTERNAL_FACT",
        "provider": "canvas",
        "fact_type": cfg.program_binding_evidence_type,
        "verification_method": if score { "SIGNED_AGS_SCORE" } else { "SIGNED_WEBHOOK" },
        "scope": scope,
        "auto_issue_on_permit": cfg.program_binding_auto_approve,
        "pass_rule": rule
    })
}

pub async fn upsert_binding<T: GatewayTransport + Sync>(
    transport: &T,
    cfg: &GatewaySeedConfig,
    platform: &Value,
    canvas_scope: &Value,
) -> Result<UpsertResult, String> {
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
    let payload = json!({
        "application_template_id": cfg.application_template_id,
        "credential_template_id": cfg.credential_template_id,
        "display_name": cfg.program_binding_display_name,
        "flow_mode": "elevenid_orchestrated_canvas_evidence",
        "direct_issue_enabled": cfg.program_binding_direct_issue,
        "auto_approve_on_evidence": cfg.program_binding_auto_approve,
        "evidence_requirements": [binding_evidence_requirement(cfg, canvas_scope)],
        "canvas_scope": canvas_scope,
        "delivery_mode": cfg.program_binding_delivery_mode,
        "issuer_mode": "org_managed",
        "approval_policy_set_id": null,
        "deployment_profile_id": null,
        "feature_flags": binding_feature_flags(&cfg.program_binding_delivery_mode),
        "enabled": true
    });
    let (operation, action) = match existing.and_then(id) {
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
    object_id(
        &binding,
        "Canvas program binding upsert did not return a valid binding payload",
    )?;
    Ok(UpsertResult {
        action,
        value: binding,
    })
}
