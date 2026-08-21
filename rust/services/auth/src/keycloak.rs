use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use url::Url;

use crate::{ExchangedTokenValidator, OidcUserInfo, OidcValidatedIdentity, PortError};

pub const KEYCLOAK_ADMIN_RESPONSE_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeycloakAdminConfig {
    pub admin_url: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: String,
    pub timeout_seconds: u64,
    pub token_exchange_enabled: bool,
}

impl KeycloakAdminConfig {
    pub fn validate(mut self) -> Result<Self, PortError> {
        self.admin_url = normalize_keycloak_admin_url(&self.admin_url)?;
        if self.realm.trim().is_empty()
            || self.client_id.trim().is_empty()
            || self.client_secret.is_empty()
        {
            return Err(PortError::new(
                "invalid_keycloak_admin_configuration",
                "Keycloak realm, client ID, and client secret are required",
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > 60 {
            return Err(PortError::new(
                "invalid_keycloak_admin_configuration",
                "Keycloak timeout must be between 1 and 60 seconds",
            ));
        }
        Ok(self)
    }

    #[must_use]
    pub fn token_url(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.admin_url, self.realm
        )
    }

    #[must_use]
    pub fn admin_base(&self) -> String {
        format!("{}/admin/realms/{}", self.admin_url, self.realm)
    }
}

pub fn normalize_keycloak_admin_url(input: &str) -> Result<String, PortError> {
    let candidate = if input.contains("://") {
        input.to_owned()
    } else {
        format!("http://{input}")
    };
    let mut url = Url::parse(&candidate).map_err(|error| {
        PortError::new(
            "invalid_keycloak_admin_configuration",
            format!("Keycloak admin URL is invalid: {error}"),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(PortError::new(
            "invalid_keycloak_admin_configuration",
            "Keycloak admin URL must be absolute HTTP(S)",
        ));
    }
    let mut path = url.path().trim_end_matches('/').to_owned();
    if path.ends_with("/admin") {
        path.truncate(path.len() - "/admin".len());
    }
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    if matches!(url.host_str(), Some("localhost" | "127.0.0.1")) {
        url.set_host(Some("keycloak")).map_err(|_| {
            PortError::new(
                "invalid_keycloak_admin_configuration",
                "Keycloak container host normalization failed",
            )
        })?;
        url.set_port(Some(8080)).map_err(|_| {
            PortError::new(
                "invalid_keycloak_admin_configuration",
                "Keycloak container port normalization failed",
            )
        })?;
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeycloakHttpMethod {
    Get,
    PostForm,
    PostJson,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeycloakHttpRequest {
    pub method: KeycloakHttpMethod,
    pub url: String,
    pub bearer_token: Option<String>,
    pub query: Vec<(String, String)>,
    pub form: Vec<(String, String)>,
    pub json: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeycloakHttpResponse {
    pub status: u16,
    pub body: Value,
    pub location: Option<String>,
}

impl KeycloakHttpResponse {
    fn require_success(self, operation: &str) -> Result<Self, PortError> {
        if (200..300).contains(&self.status) {
            Ok(self)
        } else {
            Err(PortError::new(
                "keycloak_admin_request_failed",
                format!("{operation} returned HTTP {}", self.status),
            ))
        }
    }
}

#[async_trait]
pub trait KeycloakAdminTransport: Send + Sync {
    async fn execute(
        &self,
        request: KeycloakHttpRequest,
    ) -> Result<KeycloakHttpResponse, PortError>;
}

pub struct ReqwestKeycloakAdminTransport {
    client: reqwest::Client,
}

impl ReqwestKeycloakAdminTransport {
    pub fn new(timeout_seconds: u64) -> Result<Self, PortError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                PortError::new("keycloak_http_configuration_failed", error.to_string())
            })?;
        Ok(Self { client })
    }

    async fn response(mut response: reqwest::Response) -> Result<KeycloakHttpResponse, PortError> {
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|length| length > KEYCLOAK_ADMIN_RESPONSE_MAX_BYTES as u64)
        {
            return Err(PortError::new(
                "keycloak_resource_limit",
                "Keycloak response exceeds the size limit",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| PortError::new("keycloak_http_request_failed", error.to_string()))?
        {
            if bytes.len().saturating_add(chunk.len()) > KEYCLOAK_ADMIN_RESPONSE_MAX_BYTES {
                return Err(PortError::new(
                    "keycloak_resource_limit",
                    "Keycloak response exceeds the size limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|error| {
                PortError::new(
                    "invalid_keycloak_response",
                    format!("Keycloak response is not valid JSON: {error}"),
                )
            })?
        };
        Ok(KeycloakHttpResponse {
            status,
            body,
            location,
        })
    }
}

#[async_trait]
impl KeycloakAdminTransport for ReqwestKeycloakAdminTransport {
    async fn execute(
        &self,
        request: KeycloakHttpRequest,
    ) -> Result<KeycloakHttpResponse, PortError> {
        let mut builder = match request.method {
            KeycloakHttpMethod::Get => {
                let mut url = Url::parse(&request.url).map_err(|error| {
                    PortError::new(
                        "invalid_keycloak_request",
                        format!("Keycloak request URL is invalid: {error}"),
                    )
                })?;
                url.query_pairs_mut().extend_pairs(request.query.iter());
                self.client.get(url)
            }
            KeycloakHttpMethod::PostJson => self
                .client
                .post(&request.url)
                .json(&request.json.unwrap_or(Value::Null)),
            KeycloakHttpMethod::PostForm => {
                let body = {
                    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                    for (name, value) in &request.form {
                        serializer.append_pair(name, value);
                    }
                    serializer.finish()
                };
                self.client
                    .post(&request.url)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body)
            }
        };
        if let Some(token) = request.bearer_token {
            builder = builder.bearer_auth(token);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| PortError::new("keycloak_http_request_failed", error.to_string()))?;
        Self::response(response).await
    }
}

pub struct KeycloakAdminAdapter {
    config: KeycloakAdminConfig,
    transport: Arc<dyn KeycloakAdminTransport>,
    token_validator: Arc<dyn ExchangedTokenValidator>,
}

impl KeycloakAdminAdapter {
    pub fn new(
        config: KeycloakAdminConfig,
        transport: Arc<dyn KeycloakAdminTransport>,
        token_validator: Arc<dyn ExchangedTokenValidator>,
    ) -> Result<Self, PortError> {
        Ok(Self {
            config: config.validate()?,
            transport,
            token_validator,
        })
    }

    pub fn with_reqwest(
        config: KeycloakAdminConfig,
        token_validator: Arc<dyn ExchangedTokenValidator>,
    ) -> Result<Self, PortError> {
        let config = config.validate()?;
        let transport = Arc::new(ReqwestKeycloakAdminTransport::new(config.timeout_seconds)?);
        Self::new(config, transport, token_validator)
    }

    async fn service_account_token(&self) -> Result<String, PortError> {
        let response = self
            .transport
            .execute(KeycloakHttpRequest {
                method: KeycloakHttpMethod::PostForm,
                url: self.config.token_url(),
                bearer_token: None,
                query: Vec::new(),
                form: vec![
                    ("grant_type".to_owned(), "client_credentials".to_owned()),
                    ("client_id".to_owned(), self.config.client_id.clone()),
                    (
                        "client_secret".to_owned(),
                        self.config.client_secret.clone(),
                    ),
                ],
                json: None,
            })
            .await?
            .require_success("Keycloak service-account authentication")?;
        response
            .body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                PortError::new(
                    "invalid_keycloak_response",
                    "Keycloak service-account response is missing access_token",
                )
            })
    }

    async fn find_users(
        &self,
        token: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<Value>, PortError> {
        let response = self
            .transport
            .execute(KeycloakHttpRequest {
                method: KeycloakHttpMethod::Get,
                url: format!("{}/users", self.config.admin_base()),
                bearer_token: Some(token.to_owned()),
                query: vec![
                    (field.to_owned(), value.to_owned()),
                    ("exact".to_owned(), "true".to_owned()),
                ],
                form: Vec::new(),
                json: None,
            })
            .await?
            .require_success("Keycloak user search")?;
        response.body.as_array().cloned().ok_or_else(|| {
            PortError::new(
                "invalid_keycloak_response",
                "Keycloak user search response must be an array",
            )
        })
    }

    pub async fn find_existing_user(
        &self,
        email: &str,
        username: Option<&str>,
    ) -> Result<Option<Value>, PortError> {
        let token = self.service_account_token().await?;
        if !email.is_empty() {
            if let Some(profile) = self
                .find_users(&token, "email", email)
                .await?
                .into_iter()
                .next()
            {
                return Ok(Some(profile));
            }
        }
        if let Some(username) = username.filter(|value| !value.is_empty()) {
            return Ok(self
                .find_users(&token, "username", username)
                .await?
                .into_iter()
                .next());
        }
        Ok(None)
    }

    pub async fn get_existing_verified_user_id(
        &self,
        email: &str,
        username: Option<&str>,
    ) -> Result<Option<String>, PortError> {
        let Some(profile) = self.find_existing_user(email, username).await? else {
            return Ok(None);
        };
        let user_id = required_profile_string(&profile, "id")?;
        if profile.get("enabled").and_then(Value::as_bool) == Some(false) {
            return Err(PortError::new(
                "keycloak_user_disabled",
                "Keycloak user is disabled",
            ));
        }
        if profile.get("emailVerified").and_then(Value::as_bool) != Some(true) {
            return Err(PortError::new(
                "keycloak_email_unverified",
                "Keycloak user email is not verified",
            ));
        }
        let profile_email = profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !email.is_empty()
            && !profile_email.is_empty()
            && !profile_email.eq_ignore_ascii_case(email)
        {
            return Err(PortError::new(
                "keycloak_email_mismatch",
                "Keycloak user email does not match credential email",
            ));
        }
        Ok(Some(user_id))
    }

    pub async fn get_or_create_user(
        &self,
        request: &KeycloakUserCreate,
    ) -> Result<Option<String>, PortError> {
        let token = self.service_account_token().await?;
        if !request.email.is_empty() {
            if let Some(profile) = self
                .find_users(&token, "email", &request.email)
                .await?
                .into_iter()
                .next()
            {
                return Ok(profile.get("id").and_then(Value::as_str).map(str::to_owned));
            }
        }
        if let Some(username) = request
            .username
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            if let Some(profile) = self
                .find_users(&token, "username", username)
                .await?
                .into_iter()
                .next()
            {
                return Ok(profile.get("id").and_then(Value::as_str).map(str::to_owned));
            }
        }
        let mut payload = json!({
            "username": request.username.as_deref().unwrap_or(&request.email),
            "email": request.email,
            "emailVerified": true,
            "enabled": true,
            "attributes": {"user_type": [request.role.clone()]},
        });
        if let Some(given_name) = &request.given_name {
            payload["firstName"] = Value::String(given_name.clone());
        }
        if let Some(family_name) = &request.family_name {
            payload["lastName"] = Value::String(family_name.clone());
        }
        let response = self
            .transport
            .execute(KeycloakHttpRequest {
                method: KeycloakHttpMethod::PostJson,
                url: format!("{}/users", self.config.admin_base()),
                bearer_token: Some(token),
                query: Vec::new(),
                form: Vec::new(),
                json: Some(payload),
            })
            .await?
            .require_success("Keycloak user creation")?;
        Ok(response.location.and_then(|location| {
            location
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        }))
    }

    pub async fn exchange_token_for_user(
        &self,
        user_id: &str,
        audience: &str,
    ) -> Result<Option<KeycloakTokenExchange>, PortError> {
        if !self.config.token_exchange_enabled {
            return Ok(None);
        }
        let service_token = self.service_account_token().await?;
        let response = self
            .transport
            .execute(KeycloakHttpRequest {
                method: KeycloakHttpMethod::PostForm,
                url: self.config.token_url(),
                bearer_token: None,
                query: Vec::new(),
                form: vec![
                    (
                        "grant_type".to_owned(),
                        "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
                    ),
                    ("client_id".to_owned(), self.config.client_id.clone()),
                    (
                        "client_secret".to_owned(),
                        self.config.client_secret.clone(),
                    ),
                    ("subject_token".to_owned(), service_token),
                    (
                        "subject_token_type".to_owned(),
                        "urn:ietf:params:oauth:token-type:access_token".to_owned(),
                    ),
                    ("requested_subject".to_owned(), user_id.to_owned()),
                    ("audience".to_owned(), audience.to_owned()),
                    (
                        "requested_token_type".to_owned(),
                        "urn:ietf:params:oauth:token-type:refresh_token".to_owned(),
                    ),
                ],
                json: None,
            })
            .await?;
        if response.status == 400 {
            return Ok(None);
        }
        let response = response.require_success("Keycloak token exchange")?;
        let identity = self
            .token_validator
            .validate_exchanged_identity(&response.body, audience)
            .await?
            .ok_or_else(|| {
                PortError::new(
                    "keycloak_token_exchange_unverifiable",
                    "Keycloak token exchange returned no verifiable identity token",
                )
            })?;
        Ok(Some(KeycloakTokenExchange {
            id_token: optional_string(&response.body, "id_token"),
            refresh_token: optional_string(&response.body, "refresh_token"),
            access_token: optional_string(&response.body, "access_token"),
            identity,
        }))
    }

    pub async fn get_user_info(&self, user_id: &str) -> Result<OidcUserInfo, PortError> {
        let token = self.service_account_token().await?;
        let profile = self
            .get_admin_json(
                &token,
                format!("{}/users/{user_id}", self.config.admin_base()),
            )
            .await?
            .require_success("Keycloak user profile")?
            .body;
        let attributes = profile
            .get("attributes")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut roles = attribute_strings(&attributes, &["roles", "role", "user_type"]);
        if let Ok(response) = self
            .get_admin_json(
                &token,
                format!("{}/users/{user_id}/role-mappings", self.config.admin_base()),
            )
            .await
        {
            if response.status != 404 {
                append_role_mappings(
                    &mut roles,
                    &response.require_success("Keycloak role mappings")?.body,
                );
            }
        }
        let mut organization = normalize_keycloak_organization_claim(
            first_attribute(&attributes, &["organization", "organizations"])
                .as_ref()
                .unwrap_or(&Value::Null),
        );
        if let Ok(response) = self
            .get_admin_json(
                &token,
                format!("{}/users/{user_id}/organizations", self.config.admin_base()),
            )
            .await
        {
            if response.status != 404 {
                let admin_organization = normalize_keycloak_organization_claim(
                    &response.require_success("Keycloak organizations")?.body,
                );
                if admin_organization.is_some() {
                    organization = admin_organization;
                }
            }
        }
        let mut claims = json!({
            "sub": optional_string(&profile, "id").unwrap_or_else(|| user_id.to_owned()),
            "email": optional_string(&profile, "email")
                .or_else(|| first_attribute_string(&attributes, &["email"]))
                .unwrap_or_default(),
            "email_verified": profile.get("emailVerified").and_then(Value::as_bool).unwrap_or(true),
            "name": optional_string(&profile, "name").or_else(|| first_attribute_string(&attributes, &["name"])),
            "given_name": optional_string(&profile, "firstName").or_else(|| first_attribute_string(&attributes, &["given_name"])),
            "family_name": optional_string(&profile, "lastName").or_else(|| first_attribute_string(&attributes, &["family_name"])),
            "preferred_username": optional_string(&profile, "username").or_else(|| first_attribute_string(&attributes, &["preferred_username", "username"])),
            "roles": roles,
        });
        if let Some(organization) = organization {
            claims["organization"] = organization;
        } else {
            if let Some(id) = first_attribute_string(&attributes, &["organization_id", "org_id"]) {
                claims["organization_id"] = Value::String(id);
            }
            if let Some(name) =
                first_attribute_string(&attributes, &["organization_name", "org_name"])
            {
                claims["organization_name"] = Value::String(name);
            }
        }
        Ok(OidcUserInfo::from_claims(&claims, None))
    }

    async fn get_admin_json(
        &self,
        token: &str,
        url: String,
    ) -> Result<KeycloakHttpResponse, PortError> {
        self.transport
            .execute(KeycloakHttpRequest {
                method: KeycloakHttpMethod::Get,
                url,
                bearer_token: Some(token.to_owned()),
                query: Vec::new(),
                form: Vec::new(),
                json: None,
            })
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeycloakUserCreate {
    pub email: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub role: String,
    pub username: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeycloakTokenExchange {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub identity: OidcValidatedIdentity,
}

#[must_use]
pub fn merge_oidc_user_info(
    primary: Option<&OidcUserInfo>,
    secondary: Option<&OidcUserInfo>,
) -> Option<OidcUserInfo> {
    match (primary, secondary) {
        (None, None) => None,
        (Some(user), None) | (None, Some(user)) => Some(user.clone()),
        (Some(primary), Some(secondary)) => Some(OidcUserInfo {
            sub: choose(&primary.sub, &secondary.sub),
            email: choose(&primary.email, &secondary.email),
            email_verified: primary.email_verified || secondary.email_verified,
            name: primary.name.clone().or_else(|| secondary.name.clone()),
            given_name: primary
                .given_name
                .clone()
                .or_else(|| secondary.given_name.clone()),
            family_name: primary
                .family_name
                .clone()
                .or_else(|| secondary.family_name.clone()),
            preferred_username: primary
                .preferred_username
                .clone()
                .or_else(|| secondary.preferred_username.clone()),
            picture: primary
                .picture
                .clone()
                .or_else(|| secondary.picture.clone()),
            locale: primary.locale.clone().or_else(|| secondary.locale.clone()),
            organization_id: primary
                .organization_id
                .clone()
                .or_else(|| secondary.organization_id.clone()),
            organization_name: primary
                .organization_name
                .clone()
                .or_else(|| secondary.organization_name.clone()),
            organization: primary
                .organization
                .clone()
                .or_else(|| secondary.organization.clone()),
            roles: merge_roles(&primary.roles, &secondary.roles),
        }),
    }
}

#[must_use]
pub fn attribute_strings(attributes: &Map<String, Value>, names: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for name in names {
        let Some(raw) = attributes.get(*name) else {
            continue;
        };
        let candidates = raw.as_array().cloned().unwrap_or_else(|| vec![raw.clone()]);
        for candidate in candidates
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            if let Ok(parsed) = serde_json::from_str::<Value>(candidate) {
                if let Some(items) = parsed.as_array() {
                    for item in items.iter().filter_map(Value::as_str) {
                        push_unique(&mut values, item);
                    }
                    continue;
                }
            }
            for part in candidate.split(',').map(str::trim) {
                push_unique(&mut values, part);
            }
        }
    }
    values
}

#[must_use]
pub fn normalize_keycloak_organization_claim(raw: &Value) -> Option<Value> {
    let parsed;
    let raw = if let Some(value) = raw.as_str() {
        parsed = serde_json::from_str::<Value>(value)
            .unwrap_or_else(|_| Value::String(value.to_owned()));
        &parsed
    } else {
        raw
    };
    if let Some(object) = raw.as_object() {
        if let Some(organizations) = object.get("organizations").and_then(Value::as_array) {
            return normalize_keycloak_organization_claim(&Value::Array(organizations.clone()));
        }
        if object.values().any(Value::is_object) {
            return Some(Value::Object(object.clone()));
        }
        return organization_entry(object).map(|(id, organization)| {
            let mut organizations = Map::new();
            organizations.insert(id, organization);
            Value::Object(organizations)
        });
    }
    let items = raw.as_array()?;
    let mut organizations = Map::new();
    for item in items {
        let normalized = if let Some(value) = item.as_str() {
            serde_json::from_str::<Value>(value)
                .unwrap_or_else(|_| json!({"id": value, "name": value}))
        } else {
            item.clone()
        };
        if let Some((id, organization)) = normalized.as_object().and_then(organization_entry) {
            organizations.insert(id, organization);
        }
    }
    (!organizations.is_empty()).then_some(Value::Object(organizations))
}

fn organization_entry(object: &Map<String, Value>) -> Option<(String, Value)> {
    let id = ["id", "alias", "name"]
        .into_iter()
        .find_map(|name| object.get(name).and_then(Value::as_str))?
        .to_owned();
    if id.is_empty() {
        return None;
    }
    let display = ["display_name", "displayName", "name", "alias"]
        .into_iter()
        .find_map(|name| object.get(name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .unwrap_or(&id)
        .to_owned();
    Some((id, json!({"name": display, "display_name": display})))
}

fn append_role_mappings(roles: &mut Vec<String>, mappings: &Value) {
    if let Some(realm) = mappings.get("realmMappings").and_then(Value::as_array) {
        for role in realm {
            if let Some(name) = role.get("name").and_then(Value::as_str) {
                push_unique(roles, name);
            }
        }
    }
    if let Some(clients) = mappings.get("clientMappings").and_then(Value::as_object) {
        for mapping in clients.values().filter_map(Value::as_object) {
            if let Some(items) = mapping.get("mappings").and_then(Value::as_array) {
                for role in items {
                    if let Some(name) = role.get("name").and_then(Value::as_str) {
                        push_unique(roles, name);
                    }
                }
            }
        }
    }
}

fn first_attribute(attributes: &Map<String, Value>, names: &[&str]) -> Option<Value> {
    for name in names {
        let Some(value) = attributes.get(*name) else {
            continue;
        };
        if let Some(first) = value.as_array().and_then(|values| values.first()) {
            if first.as_str().is_some_and(|value| !value.is_empty()) {
                return Some(first.clone());
            }
        }
        if value.as_str().is_some_and(|value| !value.is_empty()) {
            return Some(value.clone());
        }
    }
    None
}

fn first_attribute_string(attributes: &Map<String, Value>, names: &[&str]) -> Option<String> {
    first_attribute(attributes, names).and_then(|value| value.as_str().map(str::to_owned))
}

fn required_profile_string(profile: &Value, name: &str) -> Result<String, PortError> {
    optional_string(profile, name).ok_or_else(|| {
        PortError::new(
            "invalid_keycloak_response",
            format!("Keycloak user profile is missing {name}"),
        )
    })
}

fn optional_string(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn push_unique(target: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !target.iter().any(|candidate| candidate == value) {
        target.push(value.to_owned());
    }
}

fn merge_roles(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut roles = primary.to_vec();
    for role in secondary {
        push_unique(&mut roles, role);
    }
    roles
}

fn choose(primary: &str, secondary: &str) -> String {
    if primary.is_empty() {
        secondary.to_owned()
    } else {
        primary.to_owned()
    }
}
