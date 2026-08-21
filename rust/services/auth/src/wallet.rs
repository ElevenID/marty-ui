use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletChoice {
    pub id: String,
    pub label: String,
    pub description: String,
    pub generic_template: String,
    pub android_template: String,
    pub ios_template: String,
    pub android_package: String,
    pub request_object_compat: Option<String>,
}

impl WalletChoice {
    #[must_use]
    pub fn sprucekit() -> Self {
        Self {
            id: "sprucekit".into(),
            label: "SpruceKit".into(),
            description: "Selected wallet: SpruceKit.".into(),
            generic_template: "{oid4vp_uri}".into(),
            android_template: "intent://authorize?{client_id_param}{request_uri_method_param}request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end".into(),
            ios_template: "{oid4vp_uri}".into(),
            android_package: "com.spruceid.mobilesdkexample".into(),
            request_object_compat: None,
        }
    }

    #[must_use]
    pub fn lissi() -> Self {
        Self {
            id: "lissi".into(),
            label: "LISSI Wallet".into(),
            description: "Selected wallet: LISSI Wallet.".into(),
            generic_template: "{oid4vp_uri}".into(),
            android_template: "intent://authorize?{client_id_param}{request_uri_method_param}request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end".into(),
            ios_template: "{oid4vp_uri}".into(),
            android_package: String::new(),
            request_object_compat: Some("lissi".into()),
        }
    }
}

#[must_use]
pub fn default_wallet_choices() -> Vec<WalletChoice> {
    vec![WalletChoice::sprucekit(), WalletChoice::lissi()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletOption {
    pub id: String,
    pub label: String,
    pub description: String,
    pub href: String,
    pub android_href: String,
    pub ios_href: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WalletLinkError {
    #[error("AUTH.WALLET_REQUEST_INVALID: {0}")]
    InvalidRequest(String),
}

pub fn build_wallet_options(
    oid4vp_uri: &str,
    request_uri: &str,
    choices: &[WalletChoice],
) -> Result<Vec<WalletOption>, WalletLinkError> {
    let outer = validated_outer_parameters(oid4vp_uri)?;
    let supplied = extract_request_uri(if request_uri.is_empty() {
        oid4vp_uri
    } else {
        request_uri
    })?;
    if supplied != outer.request_uri {
        return Err(invalid(
            "OID4VP request_uri must match the validated outer request",
        ));
    }
    let mut options = Vec::new();
    for choice in choices {
        let compat = choice.request_object_compat.as_deref().unwrap_or_default();
        let wallet_request_uri = if compat.is_empty() {
            supplied.clone()
        } else {
            set_query_parameter(&supplied, "compat", compat)?
        };
        let mut wallet_oid4vp =
            set_query_parameter(oid4vp_uri, "request_uri", &wallet_request_uri)?;
        if compat == "lissi" {
            let current = validated_outer_parameters(&wallet_oid4vp)?;
            if let Some(bare_did) = current
                .client_id
                .strip_prefix("decentralized_identifier:did:")
            {
                wallet_oid4vp =
                    set_query_parameter(&wallet_oid4vp, "client_id", &format!("did:{bare_did}"))?;
            }
            if !validated_outer_parameters(&wallet_oid4vp)?
                .client_id
                .starts_with("did:")
            {
                continue;
            }
        }
        options.push(WalletOption {
            id: choice.id.clone(),
            label: choice.label.clone(),
            description: choice.description.clone(),
            href: render_wallet_link(
                &choice.generic_template,
                &wallet_oid4vp,
                &wallet_request_uri,
                "",
            )?,
            android_href: render_wallet_link(
                &choice.android_template,
                &wallet_oid4vp,
                &wallet_request_uri,
                &choice.android_package,
            )?,
            ios_href: render_wallet_link(
                &choice.ios_template,
                &wallet_oid4vp,
                &wallet_request_uri,
                "",
            )?,
        });
    }
    Ok(options)
}

pub fn render_wallet_link(
    template: &str,
    oid4vp_uri: &str,
    request_uri: &str,
    android_package: &str,
) -> Result<String, WalletLinkError> {
    let outer = validated_outer_parameters(oid4vp_uri)?;
    let normalized = extract_request_uri(if request_uri.is_empty() {
        oid4vp_uri
    } else {
        request_uri
    })?;
    if normalized != outer.request_uri {
        return Err(invalid(
            "OID4VP request_uri must match the validated outer request",
        ));
    }
    let client_id_param = if outer.client_id.is_empty() {
        String::new()
    } else {
        format!("client_id={}&", percent_encode(&outer.client_id))
    };
    let method_param = outer
        .request_uri_method
        .as_deref()
        .map(|method| format!("request_uri_method={method}&"))
        .unwrap_or_default();
    let package_param = if android_package.is_empty() {
        String::new()
    } else {
        format!("package={android_package};")
    };
    let replacements = [
        ("{oid4vp_uri}", oid4vp_uri.to_owned()),
        ("{oid4vp_uri_encoded}", percent_encode(oid4vp_uri)),
        ("{request_uri}", normalized.clone()),
        ("{request_uri_encoded}", percent_encode(&normalized)),
        ("{client_id}", outer.client_id.clone()),
        ("{client_id_encoded}", percent_encode(&outer.client_id)),
        ("{client_id_param}", client_id_param),
        (
            "{request_uri_method}",
            outer.request_uri_method.clone().unwrap_or_default(),
        ),
        (
            "{request_uri_method_encoded}",
            outer.request_uri_method.clone().unwrap_or_default(),
        ),
        ("{request_uri_method_param}", method_param),
        ("{android_package}", android_package.to_owned()),
        ("{android_package_param}", package_param),
    ];
    let embeds_outer = template.contains("{oid4vp_uri");
    let mut rendered = template.to_owned();
    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, &value);
    }
    if rendered.is_empty() || rendered.contains('{') || rendered.contains('}') {
        return Ok(oid4vp_uri.into());
    }
    if !embeds_outer {
        rendered = set_query_parameter(&rendered, "request_uri", &normalized)?;
        rendered = if outer.client_id.is_empty() {
            remove_query_parameter(&rendered, "client_id")?
        } else {
            set_query_parameter(&rendered, "client_id", &outer.client_id)?
        };
        rendered = if let Some(method) = outer.request_uri_method {
            set_query_parameter(&rendered, "request_uri_method", &method)?
        } else {
            remove_query_parameter(&rendered, "request_uri_method")?
        };
    }
    Ok(rendered)
}

struct OuterParameters {
    request_uri: String,
    client_id: String,
    request_uri_method: Option<String>,
}

fn validated_outer_parameters(uri: &str) -> Result<OuterParameters, WalletLinkError> {
    let url = Url::parse(uri).map_err(|error| invalid(&error.to_string()))?;
    let pairs: Vec<_> = url.query_pairs().collect();
    let values = |name: &str| {
        pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .collect::<Vec<_>>()
    };
    let request_uris = values("request_uri");
    if request_uris.len() != 1 || request_uris[0].is_empty() {
        return Err(invalid(
            "OID4VP outer request must contain request_uri exactly once",
        ));
    }
    let client_ids = values("client_id");
    if client_ids.len() > 1 || client_ids.first().is_some_and(String::is_empty) {
        return Err(invalid(
            "OID4VP outer request must contain client_id at most once",
        ));
    }
    let methods = values("request_uri_method");
    if methods.len() > 1
        || methods
            .first()
            .is_some_and(|method| !matches!(method.as_str(), "get" | "post"))
    {
        return Err(invalid(
            "OID4VP request_uri_method must equal 'get' or 'post' when present",
        ));
    }
    Ok(OuterParameters {
        request_uri: request_uris[0].clone(),
        client_id: client_ids.first().cloned().unwrap_or_default(),
        request_uri_method: methods.first().cloned(),
    })
}

fn extract_request_uri(uri: &str) -> Result<String, WalletLinkError> {
    let url = Url::parse(uri).map_err(|error| invalid(&error.to_string()))?;
    Ok(url
        .query_pairs()
        .find(|(key, _)| key == "request_uri")
        .map_or_else(|| uri.to_owned(), |(_, value)| value.to_string()))
}

fn set_query_parameter(url: &str, key: &str, value: &str) -> Result<String, WalletLinkError> {
    mutate_query(url, key, Some(value))
}

fn remove_query_parameter(url: &str, key: &str) -> Result<String, WalletLinkError> {
    mutate_query(url, key, None)
}

fn mutate_query(url: &str, key: &str, value: Option<&str>) -> Result<String, WalletLinkError> {
    let mut url = Url::parse(url).map_err(|error| invalid(&error.to_string()))?;
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (name, existing) in url.query_pairs() {
        if name == key {
            if !replaced {
                if let Some(value) = value {
                    pairs.push((key.into(), value.into()));
                }
            }
            replaced = true;
        } else {
            pairs.push((name.into_owned(), existing.into_owned()));
        }
    }
    if !replaced {
        if let Some(value) = value {
            pairs.push((key.into(), value.into()));
        }
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
    Ok(url.into())
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn invalid(message: &str) -> WalletLinkError {
    WalletLinkError::InvalidRequest(message.into())
}
