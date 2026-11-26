use std::collections::BTreeSet;

use base64::Engine as _;
use serde_json::{Map, Value};
use url::Url;

use crate::{ImpersonationContext, PortError, Session};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UiOriginPolicy {
    primary: String,
    allowed: BTreeSet<String>,
    api_callback: Option<String>,
}

impl UiOriginPolicy {
    pub fn new(
        primary: &str,
        additional: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, PortError> {
        let primary = normalize_origin(primary).ok_or_else(invalid_origin_configuration)?;
        let mut allowed = BTreeSet::from([primary.clone()]);
        for candidate in additional {
            allowed.insert(
                normalize_origin(candidate.as_ref()).ok_or_else(invalid_origin_configuration)?,
            );
        }
        Ok(Self {
            primary,
            allowed,
            api_callback: None,
        })
    }

    /// Pin the provider callback to the API while the browser returns to the UI.
    /// Existing same-origin/alias deployments retain their selected callback.
    pub fn with_api_callback_origin(mut self, origin: &str) -> Result<Self, PortError> {
        self.api_callback = Some(api_callback_url(origin)?);
        Ok(self)
    }

    #[must_use]
    pub fn oidc_callback_url(&self, selected_ui_origin: &str) -> String {
        self.api_callback
            .clone()
            .unwrap_or_else(|| oidc_callback_url(selected_ui_origin))
    }

    #[must_use]
    pub fn local_logout_redirect(&self) -> String {
        if self.api_callback.is_some() {
            format!("{}/", self.primary)
        } else {
            "/".into()
        }
    }

    #[must_use]
    pub fn requires_browser_origin(&self) -> bool {
        self.api_callback.is_some()
    }

    #[must_use]
    pub fn accepts_browser_origin(&self, origin: Option<&str>, selected_ui_origin: &str) -> bool {
        origin.is_some_and(|origin| {
            if self.api_callback.is_some() {
                self.allowed.contains(origin)
            } else {
                origin == selected_ui_origin
            }
        })
    }

    /// A fixed API callback cannot recover the UI host from callback headers.
    /// Bind an allowlisted UI origin into the existing one-time PKCE return URI.
    #[must_use]
    pub fn login_redirect_uri(&self, requested: Option<&str>, selected_ui_origin: &str) -> String {
        if self.api_callback.is_some() {
            self.ui_redirect_url(requested, selected_ui_origin)
        } else {
            sanitize_redirect_uri(requested, selected_ui_origin)
        }
    }

    #[must_use]
    pub fn ui_redirect_url(&self, requested: Option<&str>, selected_ui_origin: &str) -> String {
        if self.api_callback.is_none() {
            return build_ui_redirect_url(requested, selected_ui_origin);
        }
        let requested = requested.filter(|value| {
            if value.bytes().any(|byte| byte <= 32 || byte == 127) || value.contains('\\') {
                return false;
            }
            if value.starts_with('/') {
                return !value.starts_with("//");
            }
            Url::parse(value).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
            })
        });
        let bound_origin = requested.and_then(|requested| {
            let url = Url::parse(requested).ok()?;
            self.allowed.get(&url.origin().ascii_serialization())
        });
        build_ui_redirect_url(
            requested,
            bound_origin.map_or(selected_ui_origin, String::as_str),
        )
    }

    #[must_use]
    pub fn select(
        &self,
        forwarded_host: Option<&str>,
        host: Option<&str>,
        forwarded_proto: Option<&str>,
        request_scheme: Option<&str>,
    ) -> &str {
        let Some(host) = forwarded_host
            .or(host)
            .and_then(first_forwarded_value)
            .filter(|value| !value.is_empty())
        else {
            return &self.primary;
        };
        let proto = forwarded_proto
            .or(request_scheme)
            .and_then(first_forwarded_value)
            .map(str::to_ascii_lowercase)
            .filter(|value| matches!(value.as_str(), "http" | "https"))
            .unwrap_or_else(|| "https".into());
        let Some(request_origin) = normalize_origin(&format!("{proto}://{host}")) else {
            return &self.primary;
        };
        if let Some(allowed) = self.allowed.get(&request_origin) {
            return allowed;
        }
        let request_authority = authority(&request_origin);
        self.allowed
            .iter()
            .find(|allowed| authority(allowed).eq_ignore_ascii_case(request_authority))
            .map_or(&self.primary, String::as_str)
    }

    #[must_use]
    pub fn primary(&self) -> &str {
        &self.primary
    }
}

pub(crate) fn api_callback_url(origin: &str) -> Result<String, PortError> {
    let invalid = || {
        PortError::new(
            "auth_api_origin_configuration_invalid",
            "AUTH_PUBLIC_API_ORIGIN must be an uncredentialed HTTPS origin (HTTP only on loopback)",
        )
    };
    if origin.len() > 2048 || origin.bytes().any(|byte| byte <= 32 || byte == 127) {
        return Err(invalid());
    }
    let url = Url::parse(origin).map_err(|_| invalid())?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(oidc_callback_url(&url.origin().ascii_serialization()))
}

#[must_use]
pub fn sanitize_redirect_uri(redirect_uri: Option<&str>, ui_base_url: &str) -> String {
    let Some(redirect_uri) = redirect_uri.filter(|value| !value.is_empty()) else {
        return "/".into();
    };
    if redirect_uri.starts_with("//") {
        return "/".into();
    }
    if redirect_uri.starts_with('/') {
        return redirect_uri.into();
    }
    let (Ok(parsed), Ok(base)) = (Url::parse(redirect_uri), Url::parse(ui_base_url)) else {
        return "/".into();
    };
    if parsed.scheme() == base.scheme() && authority_url(&parsed) == authority_url(&base) {
        return redirect_uri.into();
    }
    let path = parsed.path();
    if path.is_empty() {
        "/".into()
    } else {
        path.into()
    }
}

#[must_use]
pub fn resolve_post_auth_redirect(redirect_uri: Option<&str>, ui_base_url: &str) -> String {
    let sanitized = sanitize_redirect_uri(redirect_uri, ui_base_url);
    if sanitized == "/" || is_same_origin_root(&sanitized, ui_base_url) {
        "/console".into()
    } else {
        sanitized
    }
}

#[must_use]
pub fn build_ui_redirect_url(redirect_uri: Option<&str>, ui_base_url: &str) -> String {
    let resolved = resolve_post_auth_redirect(redirect_uri, ui_base_url);
    if resolved.starts_with('/') {
        format!("{}{resolved}", ui_base_url.trim_end_matches('/'))
    } else {
        resolved
    }
}

#[must_use]
pub fn oidc_callback_url(ui_base_url: &str) -> String {
    format!("{}/v1/auth/callback", ui_base_url.trim_end_matches('/'))
}

#[must_use]
pub fn decode_impersonation_handoff(raw_cookie: Option<&str>) -> Option<Map<String, Value>> {
    let raw_cookie = raw_cookie.filter(|value| !value.is_empty())?;
    let mut encoded = raw_cookie.to_owned();
    encoded.extend(std::iter::repeat_n('=', (4 - encoded.len() % 4) % 4));
    let payload = base64::engine::general_purpose::URL_SAFE
        .decode(encoded)
        .ok()?;
    serde_json::from_slice::<Value>(&payload)
        .ok()?
        .as_object()
        .cloned()
}

#[must_use]
pub fn build_session_impersonation(
    session: &Session,
    raw_handoff_cookie: Option<&str>,
) -> Option<ImpersonationContext> {
    let claims = session.oidc_claims.as_ref().and_then(Value::as_object);
    let (native_admin_user_id, native_admin_username) = native_impersonator_claims(claims);
    if let Some(handoff) = decode_impersonation_handoff(raw_handoff_cookie) {
        let target_user_id = text(&handoff, "target_user_id");
        let target_email = text(&handoff, "target_email");
        let matches_target = target_user_id.is_some_and(|target| target == session.user.user_id)
            || target_email.is_some_and(|target| target.eq_ignore_ascii_case(&session.user.email));
        if matches_target {
            return Some(ImpersonationContext {
                active: true,
                admin_user_id: native_admin_user_id
                    .or_else(|| owned_text(&handoff, "admin_user_id")),
                admin_username: native_admin_username
                    .or_else(|| owned_text(&handoff, "admin_username")),
                admin_email: owned_text(&handoff, "admin_email"),
                admin_display_name: owned_text(&handoff, "admin_display_name"),
                target_user_id: Some(session.user.user_id.clone()),
                target_email: Some(session.user.email.clone()),
                organization_id: owned_text(&handoff, "organization_id")
                    .or_else(|| session.user.organization_id.clone()),
                organization_name: owned_text(&handoff, "organization_name")
                    .or_else(|| session.user.organization_name.clone()),
                started_at: owned_text(&handoff, "started_at"),
                launch_mode: owned_text(&handoff, "launch_mode"),
            });
        }
    }
    if native_admin_user_id.is_some() || native_admin_username.is_some() {
        return Some(ImpersonationContext {
            active: true,
            admin_user_id: native_admin_user_id,
            admin_username: native_admin_username,
            admin_email: None,
            admin_display_name: None,
            target_user_id: Some(session.user.user_id.clone()),
            target_email: Some(session.user.email.clone()),
            organization_id: session.user.organization_id.clone(),
            organization_name: session.user.organization_name.clone(),
            started_at: None,
            launch_mode: None,
        });
    }
    None
}

fn normalize_origin(value: &str) -> Option<String> {
    let url = Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

fn first_forwarded_value(value: &str) -> Option<&str> {
    value.split(',').next().map(str::trim)
}

fn authority(origin: &str) -> &str {
    origin.split_once("://").map_or(origin, |(_, value)| value)
}

fn authority_url(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn is_same_origin_root(value: &str, ui_base_url: &str) -> bool {
    let (Ok(url), Ok(base)) = (Url::parse(value), Url::parse(ui_base_url)) else {
        return false;
    };
    authority_url(&url) == authority_url(&base)
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

fn native_impersonator_claims(
    claims: Option<&Map<String, Value>>,
) -> (Option<String>, Option<String>) {
    let Some(claims) = claims else {
        return (None, None);
    };
    if let Some(impersonator) = claims.get("impersonator").and_then(Value::as_object) {
        return (
            owned_text(impersonator, "id"),
            owned_text(impersonator, "username"),
        );
    }
    (
        owned_text(claims, "IMPERSONATOR_ID").or_else(|| owned_text(claims, "impersonator_id")),
        owned_text(claims, "IMPERSONATOR_USERNAME")
            .or_else(|| owned_text(claims, "impersonator_username")),
    )
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn owned_text(map: &Map<String, Value>, key: &str) -> Option<String> {
    text(map, key).map(str::to_owned)
}

fn invalid_origin_configuration() -> PortError {
    PortError::new(
        "auth_ui_origin_configuration_invalid",
        "UI origins must be uncredentialed HTTP(S) origins",
    )
}
