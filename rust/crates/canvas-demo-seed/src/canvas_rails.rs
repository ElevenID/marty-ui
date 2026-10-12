//! Canvas Rails setup through the existing Canvas container.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

pub const CANVAS_LTI_SETUP_SCRIPT: &str = include_str!("../assets/canvas_lti_setup.rb");
pub const CANVAS_ADMIN_TOKEN_SCRIPT: &str = include_str!("../assets/mint_canvas_admin_token.rb");
const RESULT_PREFIX: &str = "__CANVAS_LTI_RESULT__";
const TOKEN_PREFIX: &str = "__CANVAS_ADMIN_TOKEN__";
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
    pub admin_password: String,
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

fn disposable_canvas_target(args: &[String], project: &str) -> Result<String, String> {
    let suffix = project
        .strip_prefix("marty-canvas-disposable-")
        .unwrap_or_default();
    if suffix.is_empty()
        || !suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("Invalid disposable Canvas project name".into());
    }
    let target = format!("{project}-canvas-real");
    if args.first().map(String::as_str) != Some("exec") || !args.iter().any(|arg| arg == &target) {
        return Err(
            "Disposable Canvas runner may only exec its project-owned Canvas container".into(),
        );
    }
    Ok(target)
}

#[async_trait]
impl CanvasDockerTransport for CanvasDocker {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        if let Ok(project) = std::env::var("CANVAS_DISPOSABLE_PROJECT") {
            let target = disposable_canvas_target(&operation.args, &project)?;
            let owner = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{ index .Config.Labels \"com.docker.compose.project\" }}",
                    &target,
                ])
                .output()
                .await
                .map_err(|error| error.to_string())?;
            if !owner.status.success() || String::from_utf8_lossy(&owner.stdout).trim() != project {
                return Err("Canvas container does not belong to the disposable project".into());
            }
        }
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
    if std::env::var_os("CANVAS_DISPOSABLE_PROJECT").is_some() {
        return configured.into();
    }
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

pub async fn canvas_admin_exists<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
) -> Result<bool, String> {
    let container = resolve_container_name(transport, &cfg.container_name).await;
    let command = "cd /usr/src/app && bin/rails runner -e production 'email=ENV.fetch(\"CANVAS_ADMIN_EMAIL\"); puts(Pseudonym.where(unique_id: email).exists? ? \"yes\" : \"no\")'";
    let output = transport
        .run(CanvasDockerOperation {
            args: vec![
                "exec".into(),
                "-e".into(),
                format!("CANVAS_ADMIN_EMAIL={}", cfg.admin_email),
                container,
                "bash".into(),
                "-lc".into(),
                command.into(),
            ],
            input: None,
            timeout_seconds: 90,
        })
        .await
        .map_err(|error| format!("Canvas admin state check failed: {error}"))?;
    if output.exit_code != 0 {
        return Err(format!(
            "Canvas admin state check failed (exit {}): {}",
            output.exit_code,
            output.stderr.trim()
        ));
    }
    Ok(output.stdout.lines().any(|line| line.trim() == "yes"))
}

pub async fn ensure_canvas_initial_data<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
) -> Result<bool, String> {
    if canvas_admin_exists(transport, cfg).await? {
        return Ok(false);
    }
    let container = resolve_container_name(transport, &cfg.container_name).await;
    let input = format!(
        "{0}\n{0}\n{1}\n{1}\nMarty Canvas Test\n3\n",
        cfg.admin_email, cfg.admin_password
    );
    let output = transport
        .run(CanvasDockerOperation {
            args: vec![
                "exec".into(),
                "-i".into(),
                container,
                "bash".into(),
                "-lc".into(),
                "cd /usr/src/app && bundle exec rake db:load_initial_data RAILS_ENV=production"
                    .into(),
            ],
            input: Some(input),
            timeout_seconds: 240,
        })
        .await
        .map_err(|error| format!("Canvas initial data setup failed: {error}"))?;
    if output.exit_code != 0 {
        return Err(format!(
            "Canvas initial data setup failed (exit {}): {}",
            output.exit_code,
            output.stderr.trim()
        ));
    }
    if !canvas_admin_exists(transport, cfg).await? {
        return Err("Canvas initial data setup completed but admin login was not created".into());
    }
    Ok(true)
}

pub async fn mint_canvas_admin_token<T: CanvasDockerTransport + Sync>(
    transport: &T,
    cfg: &CanvasRailsConfig,
) -> Result<String, String> {
    ensure_canvas_initial_data(transport, cfg).await?;
    let payload = json!({"admin_email": cfg.admin_email});
    let encoded = STANDARD.encode(serde_json::to_vec(&payload).map_err(|error| error.to_string())?);
    let container = resolve_container_name(transport, &cfg.container_name).await;
    let output = transport.run(CanvasDockerOperation {
        args: vec![
            "exec".into(), "-i".into(), "-e".into(),
            format!("CANVAS_ADMIN_TOKEN_SETUP_B64={encoded}"),
            container, "bash".into(), "-lc".into(),
            "cat >/tmp/mint_canvas_admin_token.rb; cd /usr/src/app; bin/rails runner -e production /tmp/mint_canvas_admin_token.rb".into(),
        ],
        input: Some(CANVAS_ADMIN_TOKEN_SCRIPT.into()),
        timeout_seconds: 120,
    }).await.map_err(|error| format!("Canvas admin token minting failed: {error}"))?;
    if output.exit_code != 0 {
        return Err(format!(
            "Canvas admin token minting failed (exit {}): {}",
            output.exit_code,
            output.stderr.trim()
        ));
    }
    output
        .stdout
        .lines()
        .rev()
        .find_map(|line| {
            line.strip_prefix(TOKEN_PREFIX)
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| "Canvas admin token minting completed but did not emit a token".into())
}

/// Reads one Docker container environment value for the legacy Canvas AGS
/// shared secret fallback. A missing container or malformed inspect response
/// remains an empty value, matching the existing demo behavior.
pub async fn docker_container_env_value<T: CanvasDockerTransport + Sync>(
    transport: &T,
    container_name: &str,
    key: &str,
) -> String {
    let output = transport
        .run(CanvasDockerOperation {
            args: vec![
                "inspect".into(),
                "--format".into(),
                "{{json .Config.Env}}".into(),
                container_name.into(),
            ],
            input: None,
            timeout_seconds: 20,
        })
        .await;
    let Ok(output) = output else {
        return String::new();
    };
    if output.exit_code != 0 {
        return String::new();
    }
    let Ok(Value::Array(values)) = serde_json::from_str::<Value>(output.stdout.trim()) else {
        return String::new();
    };
    let prefix = format!("{key}=");
    values
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .find_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod disposable_tests {
    use super::disposable_canvas_target;

    #[test]
    fn docker_exec_is_limited_to_project_owned_canvas() {
        let project = "marty-canvas-disposable-local";
        let own = vec![
            "exec".into(),
            "-i".into(),
            format!("{project}-canvas-real"),
            "bash".into(),
        ];
        assert_eq!(
            disposable_canvas_target(&own, project).unwrap(),
            "marty-canvas-disposable-local-canvas-real"
        );
        let other = vec!["exec".into(), "marty-canvas-real".into(), "bash".into()];
        assert!(disposable_canvas_target(&other, project).is_err());
        let inspect = vec!["inspect".into(), "marty-issuance".into()];
        assert!(disposable_canvas_target(&inspect, project).is_err());
        assert!(disposable_canvas_target(&own, "elevenid-beta").is_err());
    }
}
