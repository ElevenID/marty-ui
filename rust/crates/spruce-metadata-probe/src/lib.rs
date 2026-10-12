//! Fail-closed beta SpruceKit OID4VCI metadata probe.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::future::Future;
use std::time::Duration;

const MEMBER_ID: &str = "MemberCredential#sd-jwt";
const MEMBER_PATH: &str = "/credentials/marty-verified-member-badge";
const ISSUER_NAME: &str = "ElevenID LLC";
const BADGE_NAME: &str = "Marty Verified Member Badge";

fn require(ok: bool, error: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(error.to_owned())
    }
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) if n.to_string() != "0" => n.to_string(),
        Some(Value::Bool(true)) => "True".into(),
        _ => String::new(),
    }
}

fn has_display_name(value: Option<&Value>, name: &str) -> bool {
    value.and_then(Value::as_array).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.as_object().is_some() && value_string(item.get("name")).trim() == name)
    })
}

fn has_any_display_name(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|items| {
        items.iter().any(|item| {
            item.as_object().is_some() && !value_string(item.get("name")).trim().is_empty()
        })
    })
}

fn python_list(values: &BTreeSet<String>) -> String {
    let quoted: Vec<String> = values
        .iter()
        .map(|value| {
            let mut escaped = String::new();
            for ch in value.chars() {
                match ch {
                    '\\' => escaped.push_str("\\\\"),
                    '\'' => escaped.push_str("\\'"),
                    '\n' => escaped.push_str("\\n"),
                    '\r' => escaped.push_str("\\r"),
                    '\t' => escaped.push_str("\\t"),
                    ch if ch.is_control() => escaped.push_str(&format!("\\x{:02x}", ch as u32)),
                    ch => escaped.push(ch),
                }
            }
            format!("'{escaped}'")
        })
        .collect();
    format!("[{}]", quoted.join(", "))
}

pub fn validate_issuer(metadata: &Value, issuer: &str, member_vct: &str) -> Result<Value, String> {
    require(
        metadata.get("credential_issuer").and_then(Value::as_str) == Some(issuer),
        "OID4VCI credential_issuer mismatch",
    )?;
    require(
        has_display_name(metadata.get("display"), ISSUER_NAME),
        "OID4VCI issuer display name mismatch",
    )?;
    let configs = metadata
        .get("credential_configurations_supported")
        .and_then(Value::as_object)
        .filter(|configs| !configs.is_empty())
        .ok_or("credential_configurations_supported is empty or malformed")?;
    require(
        configs.contains_key(MEMBER_ID),
        "MemberCredential configuration is missing",
    )?;
    let mut legacy = BTreeSet::new();
    let mut malformed = BTreeSet::new();
    for (id, config) in configs {
        if !config.is_object() {
            malformed.insert(id.clone());
            continue;
        }
        match config.get("format").and_then(Value::as_str) {
            Some("dc+sd-jwt") => {
                if !id.ends_with("#sd-jwt") && !id.ends_with("#credential-manager") {
                    malformed.insert(id.clone());
                }
                let vct = value_string(config.get("vct"));
                match url::Url::parse(&vct) {
                    Ok(url) if url.scheme() == "https" && url.host_str().is_some() => {
                        if url.host_str() == Some("marty.example") {
                            legacy.insert(vct);
                        }
                    }
                    _ => {
                        malformed.insert(id.clone());
                    }
                }
            }
            Some("mso_mdoc") => {
                let doctype = value_string(config.get("doctype"));
                let doctype = doctype.trim();
                if doctype.is_empty() || id != &format!("{doctype}#mdoc") {
                    malformed.insert(id.clone());
                }
            }
            _ => {}
        }
        if !config
            .get("credential_metadata")
            .is_some_and(Value::is_object)
            || !has_any_display_name(config.pointer("/credential_metadata/display"))
        {
            malformed.insert(id.clone());
        }
    }
    require(
        legacy.is_empty(),
        &format!(
            "OID4VCI metadata exposes legacy VCTs: {}",
            python_list(&legacy)
        ),
    )?;
    require(
        malformed.is_empty(),
        &format!(
            "Malformed credential configurations: {}",
            python_list(&malformed)
        ),
    )?;
    let member = &configs[MEMBER_ID];
    require(
        member.get("format").and_then(Value::as_str) == Some("dc+sd-jwt"),
        "MemberCredential format mismatch",
    )?;
    require(
        member.get("vct").and_then(Value::as_str) == Some(member_vct),
        "MemberCredential VCT mismatch",
    )?;
    Ok(json!({
        "credential_issuer": issuer,
        "issuer_display_name": ISSUER_NAME,
        "configuration_count": configs.len(),
        "member_configuration": MEMBER_ID,
        "member_vct": member_vct
    }))
}

pub fn validate_member_vct(metadata: &Value, expected: &str) -> Result<Value, String> {
    require(
        metadata.get("vct").and_then(Value::as_str) == Some(expected),
        "MemberCredential public VCT mismatch",
    )?;
    require(
        metadata.get("name").and_then(Value::as_str) == Some(BADGE_NAME),
        "MemberCredential badge display name mismatch",
    )?;
    require(
        has_display_name(metadata.get("display"), BADGE_NAME),
        "MemberCredential VCT display is missing the badge name",
    )?;
    Ok(json!({"member_badge_name": BADGE_NAME}))
}

pub async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| format!("{url} request failed"))?;
    let status = response.status();
    if status.as_u16() != 200 {
        return Err(format!("{url} returned HTTP {}", status.as_u16()));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    require(
        content_type.contains("application/json"),
        &format!("{url} is not JSON"),
    )?;
    let body: Value = response
        .json()
        .await
        .map_err(|_| format!("{url} contains invalid JSON"))?;
    require(
        body.is_object(),
        &format!("{url} must contain a JSON object"),
    )?;
    Ok(body)
}

pub async fn probe_with_fetch<F, Fut>(
    base: &str,
    org_id: &str,
    mut fetch: F,
) -> Result<Value, String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let base = base.trim_end_matches('/');
    let parsed = url::Url::parse(base).ok();
    require(
        parsed
            .as_ref()
            .is_some_and(|url| url.scheme() == "https" && url.host_str().is_some()),
        "Beta origin must be an absolute HTTPS URL",
    )?;
    let issuer = format!("{base}/org/{org_id}");
    let member_vct = format!("{base}{MEMBER_PATH}");
    let canonical = format!("/.well-known/openid-credential-issuer/org/{org_id}");
    let appended = format!("/org/{org_id}/.well-known/openid-credential-issuer");
    let primary = fetch(format!("{base}{canonical}")).await?;
    let secondary = fetch(format!("{base}{appended}")).await?;
    require(
        primary == secondary,
        "Canonical and appended metadata differ",
    )?;
    let issuer_summary = validate_issuer(&primary, &issuer, &member_vct)?;
    let vct_metadata = fetch(member_vct.clone()).await?;
    let vct_summary = validate_member_vct(&vct_metadata, &member_vct)?;
    let mut result = json!({
        "base": base,
        "organization_id": org_id,
        "paths": {
            "canonical": canonical,
            "appended": appended,
            "member_vct": MEMBER_PATH
        }
    });
    result
        .as_object_mut()
        .unwrap()
        .extend(issuer_summary.as_object().unwrap().clone());
    result
        .as_object_mut()
        .unwrap()
        .extend(vct_summary.as_object().unwrap().clone());
    Ok(result)
}

pub async fn probe(base: &str, org_id: &str) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("Marty-MIP-Conformance/0.5.0")
        .build()
        .map_err(|_| "HTTP client initialization failed".to_owned())?;
    probe_with_fetch(base, org_id, |url| {
        let client = client.clone();
        async move { fetch_json(&client, &url).await }
    })
    .await
}
