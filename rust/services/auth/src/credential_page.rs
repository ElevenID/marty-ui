use std::collections::HashMap;

use crate::{
    build_wallet_options, configured_wallet_choices, CredentialLoginPageInput,
    CredentialLoginPageRenderer, PortError, WalletChoice, WalletOption,
};

pub const CREDENTIAL_LOGIN_ASSET_VERSION: &str = "20260519-credential-login-errors-v7";
pub const CREDENTIAL_LOGIN_CSS: &str =
    include_str!("../../../../services/auth/assets/credential-login.css");
pub const CREDENTIAL_LOGIN_JAVASCRIPT: &str =
    include_str!("../../../../services/auth/assets/credential-login.js");
const CREDENTIAL_LOGIN_PAGE: &str =
    include_str!("../../../../services/auth/assets/credential-login.html");
const CREDENTIAL_LOGIN_ERROR_PAGE: &str =
    include_str!("../../../../services/auth/assets/credential-login-error.html");

#[derive(Debug, Clone)]
pub struct RustCredentialLoginPageRenderer {
    wallet_choices: Vec<WalletChoice>,
}

impl RustCredentialLoginPageRenderer {
    #[must_use]
    pub fn new(wallet_choices: Vec<WalletChoice>) -> Self {
        Self { wallet_choices }
    }

    #[must_use]
    pub fn from_environment() -> Self {
        Self::new(configured_wallet_choices())
    }
}

impl Default for RustCredentialLoginPageRenderer {
    fn default() -> Self {
        Self::from_environment()
    }
}

impl CredentialLoginPageRenderer for RustCredentialLoginPageRenderer {
    fn render(&self, input: &CredentialLoginPageInput) -> Result<String, PortError> {
        render_credential_login_page(input, &self.wallet_choices)
    }
}

pub fn render_credential_login_page(
    input: &CredentialLoginPageInput,
    wallet_choices: &[WalletChoice],
) -> Result<String, PortError> {
    let wallet_options =
        build_wallet_options(&input.oid4vp_uri, &input.request_uri, wallet_choices)
            .map_err(|error| render_error(error.to_string()))?;
    let default_href = wallet_options
        .first()
        .map_or(input.oid4vp_uri.as_str(), |wallet| wallet.href.as_str());
    let default_help = wallet_options
        .first()
        .map_or("Open the login request in your wallet.", |wallet| {
            wallet.description.as_str()
        });
    let qr_encoded = percent_encode(default_href);
    let (dc_api_request_url, dc_api_submit_url) = if input.flow_instance_id.is_empty() {
        (String::new(), String::new())
    } else {
        let instance_id = percent_encode(&input.flow_instance_id);
        (
            format!("/v1/flows/instances/{instance_id}/request?transport=dc_api"),
            format!("/v1/flows/instances/{instance_id}/submit/dc-api"),
        )
    };
    let nonce_json =
        serde_json::to_string(&input.nonce).map_err(|error| render_error(error.to_string()))?;
    let values = HashMap::from([
        ("qr_encoded", qr_encoded),
        ("oid4vp_uri_escaped", html_escape(default_href, true)),
        ("nonce_attr", html_escape(&input.nonce, true)),
        (
            "dc_api_request_url_attr",
            html_escape(&dc_api_request_url, true),
        ),
        (
            "dc_api_submit_url_attr",
            html_escape(&dc_api_submit_url, true),
        ),
        (
            "dc_api_protocol_attr",
            html_escape("openid4vp-v1-signed", true),
        ),
        ("nonce_json", nonce_json),
        (
            "asset_version",
            html_escape(CREDENTIAL_LOGIN_ASSET_VERSION, true),
        ),
        (
            "wallet_option_tags",
            render_wallet_option_tags(&wallet_options),
        ),
        ("wallet_help_text", html_escape(default_help, true)),
    ]);
    render_template(CREDENTIAL_LOGIN_PAGE, &values)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLoginErrorPage<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub primary_action_href: &'a str,
    pub primary_action_label: &'a str,
    pub secondary_action_href: &'a str,
    pub secondary_action_label: &'a str,
    pub operator_details: &'a str,
}

pub fn render_credential_login_error_page(
    input: &CredentialLoginErrorPage<'_>,
) -> Result<String, PortError> {
    let mut actions = vec![render_action_link(
        input.primary_action_href,
        input.primary_action_label,
        true,
    )];
    if !input.secondary_action_href.is_empty() && !input.secondary_action_label.is_empty() {
        actions.push(render_action_link(
            input.secondary_action_href,
            input.secondary_action_label,
            false,
        ));
    }
    let operator_details_html = if input.operator_details.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"notice\"><summary>Operator details</summary><p>{}</p></details>",
            html_escape(input.operator_details, false)
        )
    };
    let values = HashMap::from([
        ("title", html_escape(input.title, false)),
        ("message", html_escape(input.message, false)),
        (
            "asset_version",
            html_escape(CREDENTIAL_LOGIN_ASSET_VERSION, true),
        ),
        ("actions_html", actions.join("\n")),
        ("operator_details_html", operator_details_html),
    ]);
    render_template(CREDENTIAL_LOGIN_ERROR_PAGE, &values)
}

fn render_action_link(href: &str, label: &str, primary: bool) -> String {
    let css_class = if primary { "open-btn" } else { "secondary-btn" };
    format!(
        "<a class=\"{css_class}\" href=\"{}\">{}</a>",
        html_escape(href, true),
        html_escape(label, false)
    )
}

fn render_wallet_option_tags(options: &[WalletOption]) -> String {
    options
        .iter()
        .enumerate()
        .map(|(index, option)| {
            let selected = if index == 0 { " selected" } else { "" };
            format!(
                "<option value=\"{}\" data-link=\"{}\" data-android-link=\"{}\" data-ios-link=\"{}\" data-label=\"{}\" data-description=\"{}\"{selected}>{}</option>",
                html_escape(&option.id, true),
                html_escape(&option.href, true),
                html_escape(&option.android_href, true),
                html_escape(&option.ios_href, true),
                html_escape(&option.label, true),
                html_escape(&option.description, true),
                html_escape(&option.label, true),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_template(template: &str, values: &HashMap<&str, String>) -> Result<String, PortError> {
    let bytes = template.as_bytes();
    let mut rendered = String::with_capacity(template.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                rendered.push('{');
                cursor += 2;
            }
            b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                rendered.push('}');
                cursor += 2;
            }
            b'{' => {
                let tail = &template[cursor + 1..];
                let Some(relative_end) = tail.find('}') else {
                    return Err(render_error("credential-login template has an open field"));
                };
                let name = &tail[..relative_end];
                let Some(value) = values.get(name) else {
                    return Err(render_error(format!(
                        "credential-login template field {name:?} is unsupported"
                    )));
                };
                rendered.push_str(value);
                cursor += relative_end + 2;
            }
            b'}' => {
                return Err(render_error(
                    "credential-login template has an unmatched closing brace",
                ));
            }
            _ => {
                let character = template[cursor..]
                    .chars()
                    .next()
                    .ok_or_else(|| render_error("credential-login template is invalid"))?;
                rendered.push(character);
                cursor += character.len_utf8();
            }
        }
    }
    Ok(rendered)
}

fn html_escape(value: &str, quote: bool) -> String {
    let escaped = value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    if quote {
        escaped.replace('"', "&quot;").replace('\'', "&#x27;")
    } else {
        escaped
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn render_error(message: impl Into<String>) -> PortError {
    PortError::new("auth_credential_login_render_failed", message)
}
