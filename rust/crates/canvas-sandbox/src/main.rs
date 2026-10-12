//! Beta Canvas LTI and Credentials simulator. Mirror state is intentionally ephemeral.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::form_urlencoded;

type HmacSha256 = Hmac<Sha256>;

struct Config {
    public_base: String,
    issuer_base: String,
    credentials_public_base: String,
    shared_secret: String,
    api_token: String,
    credentials_issuer_id: String,
    badge_name: String,
    port: u16,
}

impl Config {
    fn from_env() -> Self {
        let host = env::var("CANVAS_SANDBOX_HOST").unwrap_or_else(|_| "canvas-sandbox".into());
        let scheme = env::var("CANVAS_SANDBOX_SCHEME").unwrap_or_else(|_| "http".into());
        let port = env::var("CANVAS_SANDBOX_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8017);
        let public_base = format!("{scheme}://{host}:{port}");
        let credentials_public_base = env::var("CANVAS_CREDENTIALS_PUBLIC_BASE_URL")
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let credentials_public_base = if !credentials_public_base.is_empty() {
            credentials_public_base
        } else {
            let public_host = env::var("CANVAS_SANDBOX_PUBLIC_HOST")
                .unwrap_or_default()
                .trim()
                .to_owned();
            let chosen_host = if public_host.is_empty() {
                host.trim()
            } else {
                public_host.trim()
            };
            let chosen_scheme = if scheme.trim().is_empty() {
                "https"
            } else {
                scheme.trim()
            };
            if chosen_host.is_empty() {
                public_base.trim_end_matches('/').to_owned()
            } else if !public_host.is_empty() || chosen_host.contains(':') {
                format!("{chosen_scheme}://{chosen_host}")
            } else if ["localhost", "127.0.0.1", "canvas-sandbox"].contains(&chosen_host) {
                format!("{chosen_scheme}://{chosen_host}:{port}")
            } else {
                format!("{chosen_scheme}://{chosen_host}")
            }
            .trim_end_matches('/')
            .to_owned()
        };
        Self {
            public_base,
            issuer_base: env::var("ISSUER_BASE_URL")
                .unwrap_or_else(|_| "http://gateway:8000".into()),
            credentials_public_base,
            shared_secret: env::var("CANVAS_CREDENTIALS_SHARED_SECRET").unwrap_or_default(),
            api_token: env::var("CANVAS_CREDENTIALS_API_TOKEN").unwrap_or_default(),
            credentials_issuer_id: env::var("CANVAS_CREDENTIALS_ISSUER_ID")
                .unwrap_or_else(|_| "canvas-credentials-test-sandbox-issuer".into()),
            badge_name: env::var("CANVAS_CREDENTIALS_BADGE_NAME")
                .unwrap_or_else(|_| "Interoperable Credentials Foundations Badge".into()),
            port,
        }
    }
}

struct AppState {
    config: Config,
    key: SigningKey,
    kid: String,
    records: RwLock<HashMap<String, Value>>,
    status_events: RwLock<Vec<Value>>,
    client: reqwest::Client,
}

impl AppState {
    fn new(config: Config) -> Self {
        Self {
            config,
            key: SigningKey::from_bytes(&rand::random()),
            kid: format!("canvas-sandbox-{}", random_hex::<4>()),
            records: RwLock::new(HashMap::new()),
            status_events: RwLock::new(Vec::new()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client"),
        }
    }

    fn credential_url(&self, id: &str) -> String {
        format!(
            "{}/credentials/{}",
            self.config.credentials_public_base,
            encode_component(id)
        )
    }

    fn provenance_url(&self, record: &Value) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in [
            ("external_credential_id", string(record.get("id"))),
            ("canvas_account_id", string(record.get("canvas_account_id"))),
            ("organization_id", string(record.get("organization_id"))),
        ] {
            if !value.is_empty() {
                query.append_pair(name, &value);
            }
        }
        format!(
            "{}/console/org/operate/verify?{}",
            self.config.issuer_base.trim_end(),
            query.finish()
        )
    }
}

fn random_hex<const N: usize>() -> String {
    hex::encode(rand::random::<[u8; N]>())
}

fn encode_component(value: &str) -> String {
    // urllib.parse.quote permits '/' and RFC 3986 unreserved bytes.
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~/".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => if *value { "True" } else { "False" }.to_owned(),
        _ => String::new(),
    }
}

fn nested_string(value: &Value, parent: &str, key: &str) -> String {
    string(
        value
            .get(parent)
            .and_then(Value::as_object)
            .and_then(|object| object.get(key))
            .filter(|value| python_truthy(value)),
    )
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonical_json(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

fn payload_hash(value: &Value) -> String {
    // Python json.dumps uses ensure_ascii=True for the existing mirror hash.
    let raw = serde_json::to_string(&canonical_json(value)).expect("JSON serialization");
    let mut ascii = String::with_capacity(raw.len());
    for character in raw.chars() {
        let code = character as u32;
        if character.is_ascii() {
            ascii.push(character);
        } else if code <= 0xffff {
            ascii.push_str(&format!("\\u{code:04x}"));
        } else {
            let adjusted = code - 0x10000;
            ascii.push_str(&format!(
                "\\u{:04x}\\u{:04x}",
                0xd800 + (adjusted >> 10),
                0xdc00 + (adjusted & 0x3ff)
            ));
        }
    }
    hex::encode(Sha256::digest(ascii.as_bytes()))
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if state.config.api_token.is_empty() {
        return Ok(());
    }
    let expected = format!("Bearer {}", state.config.api_token);
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if provided.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"invalid_canvas_credentials_token"})),
            )
                .into_response(),
        ))
    }
}

fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(|| async { "ok" }))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/api/lti/security/jwks", get(jwks))
        .route("/login/oauth2/auth", get(oidc_auth))
        .route("/api/lti/credentials/webhook", post(send_webhook))
        .route("/api/credentials/mirror/publish", post(publish))
        .route("/api/credentials/mirror/status", post(sync_status))
        .route(
            "/api/credentials/mirror/{external_credential_id}",
            get(get_mirror),
        )
        .route("/credentials/{external_credential_id}", get(display))
        .with_state(state)
}

async fn root(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "service":"canvas-credentials-test-sandbox", "issuer":state.config.public_base, "kid":state.kid,
        "endpoints":{
            "openid_configuration":"/.well-known/openid-configuration", "jwks":"/api/lti/security/jwks",
            "authorization":"/login/oauth2/auth", "credential_webhook":"/api/lti/credentials/webhook",
            "mirror_publish":"/api/credentials/mirror/publish", "mirror_status":"/api/credentials/mirror/status",
            "mirror_display":"/credentials/{external_credential_id}"
        },
        "usage":{"connector_config":{"canvas_base_url":state.config.public_base,
            "lti_client_id":"any-client-id", "lti_deployment_id":"test-deployment-sandbox"},
            "env_vars_needed":["CANVAS_ALLOW_PRIVATE_BASE_URLS=true","CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS=true"]}
    }))
}

async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
    let base = &state.config.public_base;
    Json(json!({
        "issuer":base, "authorization_endpoint":format!("{base}/login/oauth2/auth"),
        "token_endpoint":format!("{base}/login/oauth2/token"),
        "jwks_uri":format!("{base}/api/lti/security/jwks"),
        "registration_endpoint":format!("{base}/api/lti/registrations"),
        "scopes_supported":["openid"], "response_types_supported":["id_token"],
        "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["EdDSA"],
        "claims_supported":["iss","sub","aud","exp","iat","nonce",
            "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
            "https://purl.imsglobal.org/spec/lti/claim/context",
            "https://purl.imsglobal.org/spec/lti/claim/roles",
            "https://purl.imsglobal.org/spec/lti/claim/message_type",
            "https://purl.imsglobal.org/spec/lti/claim/version",
            "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"]
    }))
}

async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":state.kid,
        "alg":"EdDSA","use":"sig","x":URL_SAFE_NO_PAD.encode(state.key.verifying_key().as_bytes())}]}))
}

#[derive(Deserialize)]
struct AuthQuery {
    scope: Option<String>,
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    login_hint: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    lti_message_hint: Option<String>,
    prompt: Option<String>,
    response_mode: Option<String>,
}

async fn oidc_auth(State(state): State<Arc<AppState>>, Query(query): Query<AuthQuery>) -> Response {
    if [
        query.scope.as_ref(),
        query.response_type.as_ref(),
        query.client_id.as_ref(),
        query.redirect_uri.as_ref(),
        query.login_hint.as_ref(),
        query.state.as_ref(),
        query.nonce.as_ref(),
    ]
    .iter()
    .any(Option::is_none)
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":"missing OIDC query parameter"})),
        )
            .into_response();
    }
    let _ignored = (&query.prompt, &query.response_mode);
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss":state.config.public_base, "sub":format!("canvas-user-{}",random_hex::<4>()),
        "aud":[query.client_id], "exp":now+3600, "iat":now, "nonce":query.nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id":"test-deployment-sandbox",
        "https://purl.imsglobal.org/spec/lti/claim/context":{
            "id":"course-sandbox-101","label":"SANDBOX101","title":"Canvas Sandbox Course"},
        "https://purl.imsglobal.org/spec/lti/claim/roles":["Learner","Instructor"],
        "https://purl.imsglobal.org/spec/lti/claim/message_type":"LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version":"1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri":query.redirect_uri
    });
    if let Some(hint) = query.lti_message_hint.filter(|value| !value.is_empty()) {
        claims["https://purl.imsglobal.org/spec/lti/claim/lti_message_hint"] = Value::String(hint);
    }
    let header = json!({"alg":"EdDSA","typ":"JWT","kid":state.kid});
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = state.key.sign(signing_input.as_bytes());
    let jwt = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    let html = include_str!("auth_form.html")
        .replace(
            "{{REDIRECT_URI}}",
            &html_escape(query.redirect_uri.as_deref().unwrap_or("")),
        )
        .replace("{{ID_TOKEN}}", &jwt)
        .replace(
            "{{STATE}}",
            &html_escape(query.state.as_deref().unwrap_or("")),
        );
    Html(html).into_response()
}

fn default_course_id() -> String {
    "course-sandbox-101".into()
}
fn default_course_name() -> String {
    "Canvas Sandbox Course".into()
}
fn default_enrollment() -> String {
    "enrollment-sandbox-202".into()
}
fn default_user() -> String {
    "user-sandbox-303".into()
}
fn default_email() -> String {
    "student@sandbox.example.edu".into()
}
fn default_given() -> String {
    "Sandbox".into()
}
fn default_family() -> String {
    "Student".into()
}
fn default_achievement() -> String {
    "Canvas Sandbox Course Completion".into()
}
fn default_description() -> String {
    "Completed the sandbox course module.".into()
}
fn default_evidence_type() -> String {
    "canvas.course_completion".into()
}

#[derive(Deserialize, Serialize)]
struct CanvasCredentialEvent {
    canvas_event_id: String,
    #[serde(default)]
    application_id: String,
    #[serde(default)]
    organization_id: String,
    #[serde(default)]
    credential_template_id: String,
    #[serde(default = "default_evidence_type")]
    evidence_type: String,
    #[serde(default)]
    canvas_account_id: String,
    #[serde(default = "default_course_id")]
    canvas_course_id: String,
    #[serde(default = "default_course_name")]
    canvas_course_name: String,
    #[serde(default = "default_enrollment")]
    canvas_enrollment_id: String,
    #[serde(default = "default_user")]
    canvas_user_id: String,
    #[serde(default = "default_email")]
    learner_email: String,
    #[serde(default = "default_given")]
    learner_given_name: String,
    #[serde(default = "default_family")]
    learner_family_name: String,
    #[serde(default = "default_achievement")]
    achievement_name: String,
    #[serde(default = "default_description")]
    achievement_description: String,
    #[serde(default)]
    completion_at: String,
}

async fn send_webhook(
    State(state): State<Arc<AppState>>,
    Json(mut event): Json<CanvasCredentialEvent>,
) -> Response {
    if state.config.shared_secret.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"CANVAS_CREDENTIALS_SHARED_SECRET not configured in sandbox"})),
        )
            .into_response();
    }
    if event.completion_at.is_empty() {
        event.completion_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    }
    let body = serde_json::to_vec(&event).expect("event JSON");
    let timestamp = Utc::now().timestamp().to_string();
    let mut mac =
        HmacSha256::new_from_slice(state.config.shared_secret.as_bytes()).expect("HMAC key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&body);
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let target = format!(
        "{}/v1/integrations/canvas/evidence-events",
        state.config.issuer_base
    );
    let response = state
        .client
        .post(target)
        .header("X-Canvas-Timestamp", timestamp)
        .header("X-Canvas-Signature-256", signature)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;
    match response {
        Ok(response) => {
            let status = response.status();
            let body = if status.as_u16() < 500 {
                match response.json::<Value>().await {
                    Ok(body) => Some(body),
                    // The Python runtime raised here, yielding HTTP 500. Do not
                    // report malformed upstream success as a sent event.
                    Err(_) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                            .into_response()
                    }
                }
            } else {
                None
            };
            (
                status,
                Json(
                    json!({"sandbox_status":"sent","issuance_status":status.as_u16(),
                "issuance_response":body}),
                ),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":format!("Failed to reach issuance service: {error}")})),
        )
            .into_response(),
    }
}

fn parse_object(body: &Bytes) -> Result<Value, Box<Response>> {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) if value.is_object() => Ok(value),
        Ok(_) => Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"payload_must_be_object"})),
            )
                .into_response(),
        )),
        Err(_) => Err(Box::new(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":"invalid JSON"})),
            )
                .into_response(),
        )),
    }
}

async fn publish(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let payload = match parse_object(&body) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let credential_id = nested_string(&payload, "credential", "id")
        .trim()
        .to_owned();
    if credential_id.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"credential.id is required"})),
        )
            .into_response();
    }
    let external_id = format!("canvas-sandbox-{credential_id}");
    let issuer_id = payload
        .get("issuer_id")
        .filter(|value| python_truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(state.config.credentials_issuer_id.clone()));
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
    let mut record = json!({
        "id":external_id, "issuer_id":issuer_id, "canonical_credential_id":credential_id,
        "delivery_record_id":null_or_string(nested_string(&payload,"source","delivery_record_id")),
        "organization_id":payload.get("organization_id"), "canvas_account_id":payload.get("canvas_account_id"),
        "canvas_platform_id":payload.get("canvas_platform_id"),
        "canvas_program_binding_id":payload.get("canvas_program_binding_id"),
        "credential_hash":payload.get("credential").and_then(|value|value.get("hash")),
        "issuer_did":payload.get("credential").and_then(|value|value.get("issuer_did")),
        "subject_did":payload.get("recipient").and_then(Value::as_object).and_then(|value|value.get("subject_did")),
        "status":"active", "payload_hash":payload_hash(&payload), "created_at":now, "updated_at":now
    });
    record["credential_url"] = Value::String(state.credential_url(&external_id));
    record["console_provenance_url"] = Value::String(state.provenance_url(&record));
    state
        .records
        .write()
        .await
        .insert(external_id.clone(), record.clone());
    let mut response = Json(json!({
        "id":external_id, "credential_id":external_id, "issuer_id":issuer_id, "status":"active",
        "credential_url":record["credential_url"], "console_provenance_url":record["console_provenance_url"],
        "credential":{"id":external_id,"canonical_id":credential_id,
            "issuer_did":payload.get("credential").and_then(|value|value.get("issuer_did"))}
    })).into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&random_hex::<12>()).unwrap(),
    );
    response
}

fn null_or_string(value: String) -> Value {
    if value.trim().is_empty() {
        Value::Null
    } else {
        Value::String(value.trim().to_owned())
    }
}

async fn sync_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let payload = match parse_object(&body) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let id = nested_string(&payload, "credential", "external_credential_id");
    let id = if id.is_empty() {
        nested_string(&payload, "credential", "id")
    } else {
        id
    };
    let id = id.trim().to_owned();
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
    let event_id = format!("status-sync-{}", random_hex::<8>());
    let event = json!({
        "id":event_id, "external_credential_id":if id.is_empty(){None}else{Some(id.as_str())},
        "lifecycle_action":payload.get("lifecycle_action"),
        "status":payload.get("credential").and_then(|value|value.get("status")),
        "reason":payload.get("credential").and_then(|value|value.get("reason")),
        "payload_hash":payload_hash(&payload), "created_at":now
    });
    state.status_events.write().await.push(event);
    if !id.is_empty() {
        if let Some(record) = state.records.write().await.get_mut(&id) {
            let status = nested_string(&payload, "credential", "status").to_lowercase();
            record["status"] = Value::String(if status.is_empty() {
                "updated".into()
            } else {
                status
            });
            record["updated_at"] = Value::String(now);
        }
    }
    let mut response = Json(json!({"status":"synced","event_id":event_id,
        "external_credential_id":if id.is_empty(){None}else{Some(id.as_str())}}))
    .into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&random_hex::<12>()).unwrap(),
    );
    response
}

async fn get_mirror(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    match state.records.read().await.get(&id) {
        Some(record) => Json(record.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"credential_not_found"})),
        )
            .into_response(),
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

async fn display(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let records = state.records.read().await;
    let Some(record) = records.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Html(include_str!("not_found.html").replace("{{EXTERNAL_ID}}", &html_escape(&id))),
        )
            .into_response();
    };
    let status = string(record.get("status")).to_uppercase();
    let mut html = include_str!("display.html").to_owned();
    for (placeholder, value) in [
        ("{{BADGE_NAME}}", state.config.badge_name.clone()),
        ("{{STATUS}}", status),
        ("{{ID}}", string(record.get("id"))),
        (
            "{{CANONICAL_ID}}",
            string(record.get("canonical_credential_id")),
        ),
        ("{{ISSUER_DID}}", string(record.get("issuer_did"))),
        (
            "{{CANVAS_ACCOUNT_ID}}",
            string(record.get("canvas_account_id")),
        ),
        ("{{SUBJECT_DID}}", string(record.get("subject_did"))),
        ("{{CREATED_AT}}", string(record.get("created_at"))),
        (
            "{{PROVENANCE_URL}}",
            string(record.get("console_provenance_url")),
        ),
        (
            "{{BADGE_METADATA_URL}}",
            format!(
                "{}/credentials/canvas-interoperability-foundations-badge",
                state.config.issuer_base.trim_end()
            ),
        ),
    ] {
        html = html.replace(placeholder, &html_escape(&value));
    }
    Html(html).into_response()
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState::new(Config::from_env()));
    println!("[canvas-sandbox] issuer={}", state.config.public_base);
    println!("[canvas-sandbox] kid={}", state.kid);
    println!("[canvas-sandbox] jwks_keys=1");
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", state.config.port))
        .await
        .expect("bind sandbox port");
    axum::serve(listener, app(state))
        .await
        .expect("serve sandbox");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use ed25519_dalek::{Signature, Verifier};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config {
            public_base: "https://canvas-sandbox.example.test:8017".into(),
            issuer_base: "https://issuer.example.test".into(),
            credentials_public_base: "https://canvas-sandbox.example.test".into(),
            shared_secret: "test-shared-secret".into(),
            api_token: "test-api-token".into(),
            credentials_issuer_id: "sandbox-issuer".into(),
            badge_name: "Sandbox Badge".into(),
            port: 8017,
        }
    }

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState::new(test_config()))
    }

    async fn request(
        router: Router,
        method: &str,
        path: &str,
        body: Value,
        token: bool,
    ) -> Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if token {
            builder = builder.header(header::AUTHORIZATION, "Bearer test-api-token");
        }
        router
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    fn assert_subset(actual: &Value, expected: &Value) {
        match expected {
            Value::Object(fields) => {
                for (key, value) in fields {
                    assert_subset(&actual[key], value);
                }
            }
            Value::Array(items) => {
                let actual = actual.as_array().expect("expected JSON array");
                assert_eq!(actual.len(), items.len());
                for (actual, expected) in actual.iter().zip(items) {
                    assert_subset(actual, expected);
                }
            }
            _ => assert_eq!(actual, expected),
        }
    }

    #[tokio::test]
    async fn frozen_python_runtime_corpus_matches_rust_routes() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-sandbox-runtime-v1.json"
        ))
        .unwrap();
        assert_eq!(corpus["source"], "be17936d3:docker/canvas-sandbox/main.py");
        let router = app(test_state());
        for case in corpus["cases"].as_array().unwrap() {
            let route = if case["requires_empty_shared_secret"] == true {
                let mut config = test_config();
                config.shared_secret.clear();
                app(Arc::new(AppState::new(config)))
            } else {
                router.clone()
            };
            let response = request(
                route,
                case["method"].as_str().unwrap(),
                case["path"].as_str().unwrap(),
                case.get("body").cloned().unwrap_or(Value::Null),
                case["bearer"] == true,
            )
            .await;
            assert_eq!(
                response.status().as_u16(),
                case["status"].as_u64().unwrap() as u16,
                "{} {}",
                case["method"],
                case["path"]
            );
            if let Some(bytes) = case["request_id_hex_bytes"].as_u64() {
                let id = response.headers()["x-request-id"].to_str().unwrap();
                assert_eq!(id.len(), (bytes * 2) as usize);
                assert!(hex::decode(id).is_ok());
            }
            let body = response.into_body().collect().await.unwrap().to_bytes();
            if let Some(expected) = case.get("json") {
                assert_subset(&serde_json::from_slice::<Value>(&body).unwrap(), expected);
            }
            if let Some(expected) = case["text"].as_str() {
                assert_eq!(body.as_ref(), expected.as_bytes());
            }
            if let Some(needles) = case["html_contains"].as_array() {
                let html = std::str::from_utf8(&body).unwrap();
                for needle in needles {
                    assert!(
                        html.contains(needle.as_str().unwrap()),
                        "{}: missing {needle}",
                        case["path"]
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn oidc_discovery_jwks_and_signed_lti_launch_match_contract() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-sandbox-runtime-v1.json"
        ))
        .unwrap();
        let crypto = &corpus["crypto"];
        let state = test_state();
        let router = app(state.clone());
        let discovery = json_body(
            request(
                router.clone(),
                "GET",
                "/.well-known/openid-configuration",
                Value::Null,
                false,
            )
            .await,
        )
        .await;
        assert_eq!(discovery["issuer"], state.config.public_base);
        assert_eq!(
            discovery["id_token_signing_alg_values_supported"],
            json!(["EdDSA"])
        );
        let jwks = json_body(
            request(
                router.clone(),
                "GET",
                "/api/lti/security/jwks",
                Value::Null,
                false,
            )
            .await,
        )
        .await;
        assert_eq!(jwks["keys"][0]["kid"], state.kid);
        assert_eq!(jwks["keys"][0]["alg"], crypto["jwt_algorithm"]);
        assert_eq!(
            jwks["keys"][0]["x"],
            URL_SAFE_NO_PAD.encode(state.key.verifying_key().as_bytes())
        );
        let path = "/login/oauth2/auth?scope=openid&response_type=id_token&client_id=client-1&redirect_uri=https%3A%2F%2Ftool.example.test%2Flaunch&login_hint=hint&state=state-1&nonce=nonce-1&lti_message_hint=course-hint";
        let response = request(router.clone(), "GET", path, Value::Null, false).await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("action=\"https://tool.example.test/launch\""));
        assert!(html.contains("name=\"state\" value=\"state-1\""));
        let token = html
            .split("name=\"id_token\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["nonce"], crypto["jwt_nonce"]);
        assert_eq!(claims["aud"], crypto["jwt_audience"]);
        assert_eq!(
            claims["https://purl.imsglobal.org/spec/lti/claim/deployment_id"],
            crypto["deployment_id"]
        );
        assert_eq!(
            claims["https://purl.imsglobal.org/spec/lti/claim/lti_message_hint"],
            "course-hint"
        );
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            crypto["jwt_expiry_seconds"].as_i64().unwrap()
        );
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        state
            .key
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert_eq!(
            request(router, "GET", "/login/oauth2/auth", Value::Null, false)
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn mirror_publish_status_get_and_public_display_preserve_contract() {
        let router = app(test_state());
        let payload = json!({"credential":{"id":"urn:uuid:<x>","hash":"digest","issuer_did":"did:example:issuer"},
            "recipient":{"subject_did":"did:example:subject"}, "source":{"delivery_record_id":"delivery-1"},
            "canvas_account_id":"account-1", "organization_id":"org-1"});
        assert_eq!(
            request(
                router.clone(),
                "POST",
                "/api/credentials/mirror/publish",
                payload.clone(),
                false
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                router.clone(),
                "POST",
                "/api/credentials/mirror/publish",
                json!([]),
                true
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(
                router.clone(),
                "POST",
                "/api/credentials/mirror/publish",
                json!({}),
                true
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let response = request(
            router.clone(),
            "POST",
            "/api/credentials/mirror/publish",
            payload.clone(),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-request-id"].to_str().unwrap().len(),
            24
        );
        let published = json_body(response).await;
        let id = published["id"].as_str().unwrap();
        assert_eq!(id, "canvas-sandbox-urn:uuid:<x>");
        assert!(published["credential_url"]
            .as_str()
            .unwrap()
            .ends_with("/canvas-sandbox-urn%3Auuid%3A%3Cx%3E"));
        let route = format!("/api/credentials/mirror/{}", encode_component(id));
        let record =
            json_body(request(router.clone(), "GET", &route, Value::Null, true).await).await;
        assert_eq!(record["payload_hash"], payload_hash(&payload));
        assert_eq!(record["subject_did"], "did:example:subject");
        let status = json!({"credential":{"external_credential_id":id,"status":"REVOKED","reason":"test"},"lifecycle_action":"revoke"});
        let response = request(
            router.clone(),
            "POST",
            "/api/credentials/mirror/status",
            status,
            true,
        )
        .await;
        assert_eq!(
            response.headers()["x-request-id"].to_str().unwrap().len(),
            24
        );
        assert_eq!(json_body(response).await["status"], "synced");
        let record =
            json_body(request(router.clone(), "GET", &route, Value::Null, true).await).await;
        assert_eq!(record["status"], "revoked");
        let display = request(
            router.clone(),
            "GET",
            &format!("/credentials/{}", encode_component(id)),
            Value::Null,
            false,
        )
        .await;
        let html = String::from_utf8(
            display
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("REVOKED"));
        assert!(html.contains("&lt;x&gt;"));
        assert!(!html.contains("urn:uuid:<x>"));
        assert_eq!(
            request(
                router,
                "GET",
                "/api/credentials/mirror/missing",
                Value::Null,
                true
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn webhook_sends_defaulted_event_with_verifiable_hmac() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<(HeaderMap, Bytes)>(1);
        let upstream = Router::new().route(
            "/v1/integrations/canvas/evidence-events",
            post(move |headers: HeaderMap, body: Bytes| {
                let sender = sender.clone();
                async move {
                    sender.send((headers, body)).await.unwrap();
                    (StatusCode::CREATED, Json(json!({"accepted":true})))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut config = test_config();
        config.issuer_base = format!("http://{address}");
        let response = request(
            app(Arc::new(AppState::new(config))),
            "POST",
            "/api/lti/credentials/webhook",
            json!({"canvas_event_id":"event-1"}),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let result = json_body(response).await;
        assert_eq!(result["issuance_response"], json!({"accepted":true}));
        let (headers, body) = receiver.recv().await.unwrap();
        let timestamp = headers["x-canvas-timestamp"].to_str().unwrap();
        let signature = headers["x-canvas-signature-256"].to_str().unwrap();
        let mut mac = HmacSha256::new_from_slice(b"test-shared-secret").unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(&body);
        mac.verify_slice(&hex::decode(signature.strip_prefix("sha256=").unwrap()).unwrap())
            .unwrap();
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(event["canvas_event_id"], "event-1");
        assert_eq!(event["evidence_type"], "canvas.course_completion");
        assert!(event["completion_at"].as_str().unwrap().ends_with('Z'));
        server.abort();
    }

    #[tokio::test]
    async fn malformed_upstream_success_fails_webhook_instead_of_reporting_sent() {
        let upstream = Router::new().route(
            "/v1/integrations/canvas/evidence-events",
            post(|| async { (StatusCode::CREATED, "not-json") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut config = test_config();
        config.issuer_base = format!("http://{address}");
        let response = request(
            app(Arc::new(AppState::new(config))),
            "POST",
            "/api/lti/credentials/webhook",
            json!({"canvas_event_id":"event-1"}),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"Internal Server Error");
        server.abort();
    }

    #[tokio::test]
    async fn webhook_does_not_replay_signed_body_to_redirect_target() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Bytes>(1);
        let target = Router::new().route(
            "/capture",
            post(move |body: Bytes| {
                let sender = sender.clone();
                async move {
                    sender.send(body).await.unwrap();
                    StatusCode::OK
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target_server =
            tokio::spawn(async move { axum::serve(target_listener, target).await.unwrap() });
        let upstream = Router::new().route(
            "/v1/integrations/canvas/evidence-events",
            post(move || async move {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, format!("http://{target_address}/capture"))],
                    Json(json!({"redirect":true})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_server =
            tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut config = test_config();
        config.issuer_base = format!("http://{address}");
        let response = request(
            app(Arc::new(AppState::new(config))),
            "POST",
            "/api/lti/credentials/webhook",
            json!({"canvas_event_id":"event-1"}),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            json_body(response).await["issuance_response"],
            json!({"redirect":true})
        );
        assert!(receiver.try_recv().is_err());
        upstream_server.abort();
        target_server.abort();
    }

    #[test]
    fn python_sorted_payload_digest_is_preserved() {
        assert_eq!(
            payload_hash(&json!({"b":1,"a":{"d":2,"c":3}})),
            "78d48859c3252943aab7306f76c80f3f07783582e05ab8f944ce0696f2dbfc67"
        );
        assert_eq!(
            payload_hash(&json!({"name":"Café","emoji":"🎓"})),
            "edd6441f9c651a6a360139a5c75b0bc7540f6103f0a035fceeefe110f51d1ad9"
        );
    }
}
