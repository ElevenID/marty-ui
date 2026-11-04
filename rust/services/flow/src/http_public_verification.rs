use std::fmt;

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    FlowHttpError, FlowHttpState, PublicVerificationCatalog, PublicVerificationCatalogError,
    PublicVerificationSelection, PublicVerificationSessionError, PublicVerificationSessionKey,
    PublicVerificationSessionStatus, PublicVerificationStartError,
    PublicVerificationStartInvocation, VerificationStartContext,
};

#[path = "http_public_example.rs"]
mod example_http;

pub const PUBLIC_VERIFICATION_SESSION_HEADER: &str = "x-verification-session";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawLimits")]
pub struct PublicVerificationLimits {
    starts_per_minute: u32,
    starts_per_day: u32,
    maximum_active: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    starts_per_minute: u32,
    starts_per_day: u32,
    maximum_active: u32,
}

impl TryFrom<RawLimits> for PublicVerificationLimits {
    type Error = &'static str;
    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        if !(1..=240).contains(&raw.starts_per_minute)
            || !(1..=10_000).contains(&raw.starts_per_day)
            || !(1..=1_000).contains(&raw.maximum_active)
        {
            return Err("invalid public verification limits");
        }
        Ok(Self {
            starts_per_minute: raw.starts_per_minute,
            starts_per_day: raw.starts_per_day,
            maximum_active: raw.maximum_active,
        })
    }
}

impl PublicVerificationLimits {
    #[must_use]
    pub const fn starts_per_minute(self) -> u32 {
        self.starts_per_minute
    }
    #[must_use]
    pub const fn starts_per_day(self) -> u32 {
        self.starts_per_day
    }
    #[must_use]
    pub const fn maximum_active(self) -> u32 {
        self.maximum_active
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptions {
    catalog: Value,
    principal_id: String,
    issuer_did: String,
    #[serde(default)]
    demo_holder_did: Option<String>,
    limits: PublicVerificationLimits,
}

/// Absent by default. Enabling requires an operator-owned manifest and explicit
/// limits; visitor headers never choose the executing organization or actor.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicVerificationOptions {
    catalog: PublicVerificationCatalog,
    principal_id: String,
    issuer_did: String,
    demo_holder_did: Option<String>,
    limits: PublicVerificationLimits,
}

impl fmt::Debug for PublicVerificationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicVerificationOptions([CONFIGURED])")
    }
}

impl PublicVerificationOptions {
    pub(crate) fn demo_holder_enabled(&self) -> bool {
        self.demo_holder_did.is_some()
    }
    pub fn from_json(
        contents: &str,
        allow_http_loopback: bool,
    ) -> Result<Self, PublicVerificationCatalogError> {
        if contents.len() > 65_536 {
            return Err(PublicVerificationCatalogError::InvalidConfiguration);
        }
        let raw: RawOptions = serde_json::from_str(contents)
            .map_err(|_| PublicVerificationCatalogError::InvalidConfiguration)?;
        let valid_did = raw
            .issuer_did
            .strip_prefix("did:")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(method, id)| {
                !method.is_empty()
                    && !id.is_empty()
                    && method
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            });
        if raw.principal_id.is_empty()
            || raw.principal_id.len() > 128
            || raw.principal_id.trim() != raw.principal_id
            || raw.principal_id.chars().any(char::is_control)
            || !valid_did
            || raw.issuer_did.len() > 512
            || raw
                .issuer_did
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
            || raw
                .demo_holder_did
                .as_deref()
                .is_some_and(|did| !valid_holder_did(did) || did == raw.issuer_did)
        {
            return Err(PublicVerificationCatalogError::InvalidConfiguration);
        }
        let catalog =
            PublicVerificationCatalog::from_json(&raw.catalog.to_string(), allow_http_loopback)?;
        if catalog.has_examples() && raw.demo_holder_did.is_none() {
            return Err(PublicVerificationCatalogError::InvalidConfiguration);
        }
        Ok(Self {
            catalog,
            principal_id: raw.principal_id,
            issuer_did: raw.issuer_did,
            demo_holder_did: raw.demo_holder_did,
            limits: raw.limits,
        })
    }
}

fn valid_holder_did(did: &str) -> bool {
    did.len() <= 512
        && !did.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        && did
            .strip_prefix("did:")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(method, id)| {
                !method.is_empty()
                    && !id.is_empty()
                    && method
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
}

pub(crate) fn flow_public_verification_routes() -> Router<FlowHttpState> {
    Router::new()
        .route("/v1/flows/public/verification/catalog", get(catalog))
        .route("/v1/flows/public/verification/sessions", post(launch))
        .route(
            "/v1/flows/public/verification/sessions/{session_id}",
            get(session),
        )
        .route(
            "/v1/flows/public/verification/sessions/{session_id}/cancel",
            post(cancel),
        )
        .route(
            "/v1/flows/public/verification/sessions/{session_id}/example",
            post(example_http::example),
        )
        .layer(DefaultBodyLimit::max(4_096))
        .layer(middleware::map_response(no_store))
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn configured(state: &FlowHttpState) -> Result<&PublicVerificationOptions, FlowHttpError> {
    state
        .verification
        .public_verification
        .as_ref()
        .ok_or_else(unavailable)
}

fn unavailable() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::NOT_FOUND,
        "public_verification_unavailable",
        "Verification session unavailable",
    )
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, FlowHttpError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| unavailable())?;
    if values.next().is_some() {
        return Err(unavailable());
    }
    Ok(value)
}

fn origin<'a>(
    options: &PublicVerificationOptions,
    headers: &'a HeaderMap,
    required: bool,
) -> Result<Option<&'a str>, FlowHttpError> {
    let value = single_header(headers, "origin")?;
    if value.is_some() || required {
        options
            .catalog
            .require_origin(value)
            .map_err(catalog_error)?;
    }
    Ok(value)
}

fn capability(headers: &HeaderMap) -> Result<PublicVerificationSessionKey, FlowHttpError> {
    PublicVerificationSessionKey::parse(
        single_header(headers, PUBLIC_VERIFICATION_SESSION_HEADER)?.ok_or_else(unavailable)?,
    )
    .map_err(|_| unavailable())
}

async fn current_view(
    state: &FlowHttpState,
    options: &PublicVerificationOptions,
    key: &PublicVerificationSessionKey,
    instance: &crate::FlowInstanceRecord,
    now: chrono::DateTime<Utc>,
) -> Result<crate::PublicVerificationSessionView, FlowHttpError> {
    // Authenticate the visitor before touching any referenced organization
    // configuration. Terminal decisions remain readable without re-evaluation.
    let view = key
        .view(
            instance,
            options.catalog.organization_id(),
            options.catalog.origin(),
            now,
        )
        .map_err(session_error)?;
    if matches!(
        view.status,
        PublicVerificationSessionStatus::AwaitingWallet
            | PublicVerificationSessionStatus::Verifying
    ) && crate::defined_verification::validate_defined_submission(&state.providers, instance)
        .await?
        .is_none()
    {
        return Err(session_error(PublicVerificationSessionError::InvalidState));
    }
    Ok(view)
}

async fn catalog(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
) -> Result<Response, FlowHttpError> {
    let options = configured(&state)?;
    origin(options, &headers, false)?;
    Ok(Json(options.catalog.public_view()).into_response())
}

async fn launch(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, FlowHttpError> {
    let options = configured(&state)?;
    let browser_origin = origin(options, &headers, true)?.ok_or_else(unavailable)?;
    let key = capability(&headers)?;
    let selection: PublicVerificationSelection = serde_json::from_value(payload).map_err(|_| {
        FlowHttpError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_verification_selection",
            "Invalid verification selection",
        )
    })?;
    let choice = options.catalog.select(&selection).map_err(catalog_error)?;
    let organization_id = options.catalog.organization_id();
    let instance_id = key
        .instance_id(organization_id, options.catalog.origin())
        .to_string();
    let now = Utc::now();
    if let Some(instance) = state.repository.instance(&instance_id).await? {
        key.require_same_selection(
            &instance,
            organization_id,
            options.catalog.origin(),
            &selection,
            now,
        )
        .map_err(session_error)?;
        let view = current_view(&state, options, &key, &instance, now).await?;
        return Ok(Json(view).into_response());
    }
    let definition = state
        .repository
        .definition(&choice.definition.definition_id)
        .await?
        .ok_or_else(unavailable)?;
    let prepared = options
        .catalog
        .prepare_selection(
            &state.providers,
            &state.verification.callback_destinations,
            &definition,
            &state.verification.verification_start,
            PublicVerificationStartInvocation {
                selection: &selection,
                browser_origin,
                issuer_did: &options.issuer_did,
                context: VerificationStartContext {
                    public_base_url: &state.public_base_url,
                    allow_http_loopback: state.verification.allow_http_loopback,
                    principal_id: &options.principal_id,
                    now,
                },
                session_key: &key,
            },
        )
        .await
        .map_err(start_error)?;
    let inserted = state
        .repository
        .save_public_verification_start(&prepared.instance, options.limits)
        .await
        .map_err(|error| {
            if matches!(
                error,
                crate::RepositoryError::PublicVerificationCapacityExceeded
            ) {
                FlowHttpError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "public_verification_capacity",
                    "Please try again later",
                )
            } else {
                error.into()
            }
        })?;
    // A racing launch or a lost response returns the winning persisted nonce
    // and request; never return a losing candidate's protocol material.
    let instance = if inserted {
        prepared.instance
    } else {
        state
            .repository
            .instance(&instance_id)
            .await?
            .ok_or_else(unavailable)?
    };
    key.require_same_selection(
        &instance,
        organization_id,
        options.catalog.origin(),
        &selection,
        now,
    )
    .map_err(session_error)?;
    let view = current_view(&state, options, &key, &instance, now).await?;
    Ok((
        if inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(view),
    )
        .into_response())
}

async fn session(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, FlowHttpError> {
    let options = configured(&state)?;
    origin(options, &headers, false)?;
    let key = capability(&headers)?;
    let instance = state
        .repository
        .instance(&id.to_string())
        .await?
        .ok_or_else(unavailable)?;
    let view = current_view(&state, options, &key, &instance, Utc::now()).await?;
    Ok(Json(view).into_response())
}

async fn cancel(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, FlowHttpError> {
    let options = configured(&state)?;
    origin(options, &headers, true)?;
    let key = capability(&headers)?;
    let now = Utc::now();
    let instance = state
        .repository
        .instance(&id.to_string())
        .await?
        .ok_or_else(unavailable)?;
    let view = key
        .view(
            &instance,
            options.catalog.organization_id(),
            options.catalog.origin(),
            now,
        )
        .map_err(session_error)?;
    if !matches!(
        view.status,
        PublicVerificationSessionStatus::AwaitingWallet
            | PublicVerificationSessionStatus::Verifying
    ) {
        return Ok(Json(view).into_response());
    }
    let instance = match state
        .repository
        .cancel_instance(&instance.id, "public_verification_visitor", now)
        .await?
    {
        Some(instance) => instance,
        None => state
            .repository
            .instance(&instance.id)
            .await?
            .ok_or_else(unavailable)?,
    };
    let view = key
        .view(
            &instance,
            options.catalog.organization_id(),
            options.catalog.origin(),
            now,
        )
        .map_err(session_error)?;
    Ok(Json(view).into_response())
}

fn catalog_error(error: PublicVerificationCatalogError) -> FlowHttpError {
    match error {
        PublicVerificationCatalogError::OriginRejected => FlowHttpError::new(
            StatusCode::FORBIDDEN,
            "verification_origin_rejected",
            "Application origin rejected",
        ),
        PublicVerificationCatalogError::ConsentRequired => FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "verification_consent_required",
            "Review and accept the verification request",
        ),
        PublicVerificationCatalogError::CatalogChanged
        | PublicVerificationCatalogError::ConfigurationChanged => FlowHttpError::new(
            StatusCode::CONFLICT,
            "verification_configuration_changed",
            "Review the current request and start a new session",
        ),
        _ => unavailable(),
    }
}

fn session_error(error: PublicVerificationSessionError) -> FlowHttpError {
    match error {
        PublicVerificationSessionError::SelectionConflict => FlowHttpError::new(
            StatusCode::CONFLICT,
            "verification_selection_conflict",
            "Start a new session for the changed request",
        ),
        PublicVerificationSessionError::InvalidState => FlowHttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "verification_session_invalid",
            "Verification session unavailable",
        ),
        _ => unavailable(),
    }
}

fn start_error(error: PublicVerificationStartError) -> FlowHttpError {
    match error {
        PublicVerificationStartError::Catalog(error) => catalog_error(error),
        PublicVerificationStartError::Session(error) => session_error(error),
        PublicVerificationStartError::Definition(error) => error.into(),
        PublicVerificationStartError::Provider(error) => error.into(),
        PublicVerificationStartError::InvalidOperator => FlowHttpError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "verification_operator_unavailable",
            "Verification is temporarily unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn configuration() -> Value {
        json!({
            "catalog": {"organization_id":"demo-org", "application_origin":"https://site.example",
                "notice":"Use a synthetic credential.", "scenarios":[{"id":"age", "label":"Age",
                    "choices":[{"id":"over-18", "label":"18 or older", "definition":{
                        "organization_id":"demo-org", "definition_id":"demo-flow", "version":1
                    }, "presentation_policy_id":"demo-policy", "policy_configuration_digest":format!("sha256:{}", "a".repeat(64))}]}]},
            "principal_id":"website-operator", "issuer_did":"did:web:verifier.example",
            "limits":{"starts_per_minute":10,"starts_per_day":100,"maximum_active":20}
        })
    }

    #[test]
    fn operator_configuration_is_explicit_bounded_and_redacted() {
        let valid = configuration();
        let options = PublicVerificationOptions::from_json(&valid.to_string(), false).unwrap();
        let debug = format!("{options:?}");
        assert!(!debug.contains("website-operator") && !debug.contains("demo-policy"));
        for variant in 0..12 {
            let mut value = valid.clone();
            match variant {
                0 => value["principal_id"] = json!(""),
                1 => value["principal_id"] = json!("a".repeat(129)),
                2 => value["issuer_did"] = json!("did:"),
                3 => value["issuer_did"] = json!("did:web:"),
                4 => value["issuer_did"] = json!("did:Web:verifier.example"),
                5 => value["issuer_did"] = json!("did:web:verifier\u{0000}.example"),
                6 => value["limits"]["starts_per_minute"] = json!(0),
                7 => value["limits"]["starts_per_minute"] = json!(241),
                8 => value["limits"]["starts_per_day"] = json!(10_001),
                9 => value["limits"]["maximum_active"] = json!(1_001),
                10 => value["unknown"] = json!(true),
                _ => value["limits"]["unbounded"] = json!(true),
            }
            assert!(
                PublicVerificationOptions::from_json(&value.to_string(), false).is_err(),
                "variant {variant}"
            );
        }
        assert!(PublicVerificationOptions::from_json(&" ".repeat(65_537), false).is_err());
    }

    #[test]
    fn duplicate_capability_and_origin_headers_are_rejected() {
        for name in [PUBLIC_VERIFICATION_SESSION_HEADER, "origin"] {
            let mut headers = HeaderMap::new();
            headers.append(name, HeaderValue::from_static("first"));
            headers.append(name, HeaderValue::from_static("second"));
            assert!(single_header(&headers, name).is_err());
        }
    }

    #[test]
    fn demo_holder_is_optional_and_must_be_a_distinct_well_formed_identity() {
        assert!(
            !PublicVerificationOptions::from_json(&configuration().to_string(), false)
                .unwrap()
                .demo_holder_enabled()
        );
        for did in [
            "",
            "did:",
            "did:web:",
            "did:web:verifier.example",
            "did:Web:holder.example",
            "did:web:holder example",
        ] {
            let mut value = configuration();
            value["demo_holder_did"] = json!(did);
            assert!(
                PublicVerificationOptions::from_json(&value.to_string(), false).is_err(),
                "{did}"
            );
        }
        let mut value = configuration();
        value["demo_holder_did"] = json!("did:web:demo.example:holder");
        assert!(
            PublicVerificationOptions::from_json(&value.to_string(), false)
                .unwrap()
                .demo_holder_enabled()
        );
    }
}
