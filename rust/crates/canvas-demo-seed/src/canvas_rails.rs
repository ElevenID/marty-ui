//! Canvas Rails setup through the existing Canvas container.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

pub const CANVAS_LTI_SETUP_SCRIPT: &str = include_str!("../assets/canvas_lti_setup.rb");
const RESULT_PREFIX: &str = "__CANVAS_LTI_RESULT__";
const SETUP_COMMAND: &str = "cat >/tmp/ensure_canvas_lti_setup.rb; cd /usr/src/app; bin/rails runner -e production /tmp/ensure_canvas_lti_setup.rb";
const REQUIRED_SCOPES: [&str; 4] = [
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
];

#[derive(Clone, Debug)]
pub struct CanvasRailsConfig {
    pub container_name: String,
    pub account_id: String,
    pub admin_email: String,
    pub browser_base_url: String,
    pub lti_client_id: String,
    pub lti_tool_base_url: String,
    pub display_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasDockerOperation {
    pub args: Vec<String>,
    pub input: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct CanvasDockerOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait CanvasDockerTransport {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String>;
}

pub struct CanvasDocker;

#[async_trait]
impl CanvasDockerTransport for CanvasDocker {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        let mut child = Command::new("docker")
            .args(&operation.args)
            .stdin(if operation.input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| error.to_string())?;
        if let Some(input) = operation.input {
            let mut stdin = child.stdin.take().ok_or("Docker stdin unavailable")?;
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|error| error.to_string())?;
        }
        let output = timeout(
            Duration::from_secs(operation.timeout_seconds),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| "Docker operation timed out".to_owned())?
        .map_err(|error| error.to_string())?;
        Ok(CanvasDockerOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub async fn resolve_container_name<T: CanvasDockerTransport + Sync>(
    transport: &T,
    configured: &str,
) -> String {
    let configured = configured.trim();
    let result = transport
        .run(CanvasDockerOperation {
            args: vec!["ps".into(), "--format".into(), "{{.Names}}".into()],
            input: None,
            timeout_seconds: 20,
        })
        .await;
    let Ok(output) = result else {
        return configured.into();
    };
    if output.exit_code != 0 {
        return configured.into();
    }
    let names: Vec<&str> = output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if names.contains(&configured) {
        return configured.into();
    }
    let suffix = format!("_{configured}");
    names
        .into_iter()
        .find(|name| name.ends_with(&suffix))
        .unwrap_or(configured)
        .into()
}

pub async fn run_lti_setup<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
    payload: &Value,
) -> Result<Value, String> {
    let encoded = STANDARD.encode(serde_json::to_vec(payload).map_err(|error| error.to_string())?);
    let container_name = resolve_container_name(transport, &cfg.container_name).await;
    let output = transport
        .run(CanvasDockerOperation {
            args: vec![
                "exec".into(),
                "-i".into(),
                "-e".into(),
                format!("CANVAS_LTI_SETUP_B64={encoded}"),
                container_name,
                "bash".into(),
                "-lc".into(),
                SETUP_COMMAND.into(),
            ],
            input: Some(CANVAS_LTI_SETUP_SCRIPT.into()),
            timeout_seconds: 180,
        })
        .await
        .map_err(|error| format!("Canvas Rails setup failed: {error}"))?;
    if output.exit_code != 0 {
        let combined = [output.stdout.trim(), output.stderr.trim()]
            .into_iter()
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!(
            "Canvas Rails setup failed (exit {}): {}",
            output.exit_code,
            if combined.is_empty() {
                "no output"
            } else {
                &combined
            }
        ));
    }
    for line in output.stdout.lines().rev() {
        if let Some(payload) = line.strip_prefix(RESULT_PREFIX) {
            return serde_json::from_str(payload).map_err(|error| error.to_string());
        }
    }
    Err("Canvas Rails setup completed but did not emit a parseable result".into())
}

fn experience_url(cfg: &CanvasRailsConfig, platform_id: &str, suffix: &str) -> String {
    format!(
        "{}/v1/integrations/canvas/lti/platforms/{platform_id}/{suffix}",
        cfg.lti_tool_base_url.trim_end_matches('/')
    )
}

pub async fn ensure_canvas_developer_key<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
    platform_id: &str,
) -> Result<Value, String> {
    let result = run_lti_setup(
        transport,
        cfg,
        &json!({
            "account_id": cfg.account_id,
            "admin_email": cfg.admin_email,
            "client_id": cfg.lti_client_id,
            "notes": format!("ElevenID LTI Integration - {}", cfg.lti_client_id),
            "redirect_uri": experience_url(cfg, platform_id, "experience"),
            "scopes": REQUIRED_SCOPES,
        }),
    )
    .await?;
    let key = result
        .get("developer_key")
        .filter(|value| value.is_object() && value.get("id").is_some_and(|id| !id.is_null()))
        .ok_or("Developer key setup did not return a valid key payload")?;
    Ok(json!({"action": key.get("action").unwrap_or(&json!("updated")), "key": key}))
}

pub async fn ensure_canvas_public_domain<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
) -> Result<Value, String> {
    let host = url::Url::parse(&cfg.browser_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    if host.is_empty() {
        return Ok(json!({"action": "skipped", "domain": null, "accounts": []}));
    }
    let result = run_lti_setup(transport, cfg, &json!({"public_host": host})).await?;
    let domain = result
        .get("public_domain")
        .filter(|value| value.is_object())
        .ok_or("Canvas public domain setup did not return a valid payload")?;
    Ok(json!({
        "action": domain.get("action").unwrap_or(&json!("updated")),
        "domain": domain.get("host"),
        "accounts": domain.get("accounts").filter(|value| !value.is_null()).unwrap_or(&json!([])),
    }))
}

pub async fn ensure_canvas_external_tool<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
    platform_id: &str,
    course_id: &str,
) -> Result<Value, String> {
    let domain = url::Url::parse(&cfg.lti_tool_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| {
            cfg.lti_tool_base_url
                .trim_end_matches('/')
                .split("://")
                .last()
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .to_owned()
        });
    let result = run_lti_setup(
        transport,
        cfg,
        &json!({
            "account_id": cfg.account_id,
            "course_id": course_id,
            "client_id": cfg.lti_client_id,
            "display_name": cfg.display_name,
            "tool_domain": domain,
            "tool_url": experience_url(cfg, platform_id, "experience-login"),
        }),
    )
    .await?;
    let tool = result
        .get("external_tool")
        .filter(|value| value.is_object() && value.get("id").is_some_and(|id| !id.is_null()))
        .ok_or("External tool setup did not return a valid tool payload")?;
    Ok(json!({"action": tool.get("action").unwrap_or(&json!("updated")), "tool": tool}))
}
