use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use mmf_platform::{
    AuthenticationType, GatewayRequest, HttpMethod, PlatformError, RouteConfig, RouteMatchType,
    RouteTable,
};
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};

pub const EXPECTED_ROUTE_COUNT: usize = 434;

#[derive(Debug, Deserialize)]
pub struct GatewayContract {
    pub middleware: MiddlewareContract,
    pub route_count: usize,
    pub routes: Vec<DeclaredRoute>,
}

#[derive(Debug, Deserialize)]
pub struct MiddlewareContract {
    pub execution_order: Vec<String>,
    pub registration_order: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DeclaredRoute {
    pub include_in_schema: bool,
    pub method: HttpMethod,
    pub path: String,
    pub status_code: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteOwnership {
    pub service: &'static str,
    pub requires_authentication: bool,
    pub gateway_owned: bool,
}

impl GatewayContract {
    pub fn load() -> Result<Self, PlatformError> {
        let contract: Self =
            serde_json::from_str(include_str!("../../../../contracts/gateway-routes.json"))
                .map_err(|error| PlatformError::InvalidConfiguration(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.route_count != EXPECTED_ROUTE_COUNT || self.routes.len() != self.route_count {
            return Err(PlatformError::InvalidConfiguration(format!(
                "gateway route contract must contain exactly {EXPECTED_ROUTE_COUNT} routes"
            )));
        }
        let unique = self
            .routes
            .iter()
            .map(|route| (route.method, route.path.as_str()))
            .collect::<BTreeSet<_>>();
        if unique.len() != self.route_count {
            return Err(PlatformError::InvalidConfiguration(
                "gateway route contract contains duplicate method/path entries".into(),
            ));
        }
        let expected_execution = [
            "MIPVersionMiddleware",
            "RateLimitMiddleware",
            "AuthMiddleware",
            "ContentTypeEnforcementMiddleware",
            "ETagMiddleware",
            "GatewayCedarAuthMiddleware",
            "IdempotencyMiddleware",
            "CORSMiddleware",
        ];
        if self.middleware.execution_order != expected_execution {
            return Err(PlatformError::InvalidConfiguration(
                "gateway middleware execution order drifted".into(),
            ));
        }
        let reverse = self
            .middleware
            .registration_order
            .iter()
            .rev()
            .collect::<Vec<_>>();
        if reverse != self.middleware.execution_order.iter().collect::<Vec<_>>() {
            return Err(PlatformError::InvalidConfiguration(
                "gateway middleware registration order must reverse execution order".into(),
            ));
        }
        Ok(())
    }

    pub fn route_table(&self) -> Result<RouteTable, PlatformError> {
        let mut table = RouteTable::default();
        for (index, declared) in self.routes.iter().enumerate() {
            let owner = route_ownership(&declared.path);
            table.add(RouteConfig {
                name: format!("{}:{index}:{}", method_name(declared.method), declared.path),
                pattern: declared.path.clone(),
                match_type: if declared.path.contains('{') {
                    RouteMatchType::Template
                } else {
                    RouteMatchType::Exact
                },
                upstream_service: owner.service.into(),
                methods: BTreeSet::from([declared.method]),
                host: None,
                required_headers: BTreeMap::new(),
                rewrite_path: upstream_rewrite(declared.method, &declared.path),
                timeout_ms: 30_000,
                retries: 2,
                auth_required: owner.requires_authentication,
                authentication_type: if owner.requires_authentication {
                    AuthenticationType::Jwt
                } else {
                    AuthenticationType::None
                },
                priority: route_priority(&declared.path),
                tags: BTreeSet::from([if owner.gateway_owned {
                    "gateway-owned".into()
                } else {
                    "proxied".into()
                }]),
            })?;
        }
        Ok(table)
    }

    /// Build the public table plus explicit gateway-to-service helper routes.
    /// Internal helpers are not public API declarations and therefore do not
    /// alter the frozen 434-route contract.
    pub fn proxy_route_table(&self) -> Result<RouteTable, PlatformError> {
        let mut table = self.route_table()?;
        add_gateway_documentation_routes(&mut table)?;
        table.add(RouteConfig {
            name: "internal:compliance-profiles:discoverable".into(),
            pattern: "/v1/compliance-profiles/system/discoverable".into(),
            match_type: RouteMatchType::Exact,
            upstream_service: "compliance-profiles".into(),
            methods: BTreeSet::from([HttpMethod::Get]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: None,
            timeout_ms: 5_000,
            retries: 1,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 20_000,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
        table.add(RouteConfig {
            name: "internal:issuance:public-discovery".into(),
            pattern: "/__gateway/issuance/{path:path}".into(),
            match_type: RouteMatchType::Template,
            upstream_service: "issuance".into(),
            methods: BTreeSet::from([HttpMethod::Get, HttpMethod::Post, HttpMethod::Put]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: Some("/{path}".into()),
            timeout_ms: 10_000,
            retries: 1,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 100,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
        for service in [
            "organizations",
            "applicant",
            "credential-templates",
            "presentation-policies",
            "deployment-profiles",
            "flows",
        ] {
            table.add(RouteConfig {
                name: format!("internal:composition:{service}"),
                pattern: format!("/__gateway/composition/{service}/{{path:path}}"),
                match_type: RouteMatchType::Template,
                upstream_service: service.into(),
                methods: BTreeSet::from([
                    HttpMethod::Get,
                    HttpMethod::Post,
                    HttpMethod::Put,
                    HttpMethod::Patch,
                    HttpMethod::Delete,
                ]),
                host: None,
                required_headers: BTreeMap::new(),
                rewrite_path: Some("/{path}".into()),
                timeout_ms: 30_000,
                retries: 1,
                auth_required: false,
                authentication_type: AuthenticationType::None,
                priority: 100,
                tags: BTreeSet::from(["gateway-internal".into()]),
            })?;
        }
        table.add(RouteConfig {
            name: "internal:signing-keys:compatibility".into(),
            pattern: "/__gateway/signing-keys/{path:path}".into(),
            match_type: RouteMatchType::Template,
            upstream_service: "signing-keys".into(),
            methods: BTreeSet::from([
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Patch,
                HttpMethod::Delete,
            ]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: Some("/{path}".into()),
            timeout_ms: 10_000,
            retries: 1,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 100,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
        table.add(RouteConfig {
            name: "internal:organizations:legacy-api-key-collection".into(),
            pattern: "/v1/organizations/{organization_id}/api-keys".into(),
            match_type: RouteMatchType::Template,
            upstream_service: "organizations".into(),
            methods: BTreeSet::from([HttpMethod::Get, HttpMethod::Post]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: None,
            timeout_ms: 10_000,
            retries: 1,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 20_000,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
        table.add(RouteConfig {
            name: "internal:organizations:legacy-api-key-item".into(),
            pattern: "/v1/organizations/{organization_id}/api-keys/{key_id}".into(),
            match_type: RouteMatchType::Template,
            upstream_service: "organizations".into(),
            methods: BTreeSet::from([HttpMethod::Delete]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: None,
            timeout_ms: 10_000,
            retries: 1,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 20_000,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
        Ok(table)
    }

    /// Build the table used by request middleware. Documentation handlers are
    /// real public routes, while proxy-only helper routes remain unreachable
    /// from the external request classifier.
    pub fn runtime_route_table(&self) -> Result<RouteTable, PlatformError> {
        let mut table = self.route_table()?;
        add_gateway_documentation_routes(&mut table)?;
        Ok(table)
    }

    /// Generate the public OpenAPI surface from the same frozen route
    /// contract used by the proxy. This keeps discovery DRY and prevents the
    /// documentation endpoint from silently drifting after the Python/FastAPI
    /// gateway is removed.
    #[must_use]
    pub fn openapi_document(&self) -> Value {
        let mut paths = Map::new();
        for route in self.routes.iter().filter(|route| route.include_in_schema) {
            let owner = route_ownership(&route.path);
            let path_item = paths
                .entry(route.path.clone())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("OpenAPI path items are objects");
            let mut operation = json!({
                "operationId": operation_id(route.method, &route.path),
                "tags": [owner.service],
                "responses": {
                    route.status_code.to_string(): {
                        "description": status_description(route.status_code)
                    }
                },
                "x-marty-upstream-service": owner.service,
                "x-marty-gateway-owned": owner.gateway_owned
            });
            let parameters = path_parameters(&route.path);
            if !parameters.is_empty() {
                operation["parameters"] = Value::Array(parameters);
            }
            operation["security"] = if owner.requires_authentication {
                json!([{"bearerAuth": []}, {"apiKeyAuth": []}, {"sessionCookie": []}])
            } else {
                json!([])
            };
            path_item.insert(method_name(route.method).to_ascii_lowercase(), operation);
        }
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Marty API Gateway",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Canonical public HTTP surface for the Marty Rust service platform."
            },
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                    "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                    "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "sessionId"}
                }
            }
        })
    }
}

fn add_gateway_documentation_routes(table: &mut RouteTable) -> Result<(), PlatformError> {
    for path in ["/openapi.json", "/docs", "/redoc"] {
        table.add(RouteConfig {
            name: format!("internal:gateway-documentation:{path}"),
            pattern: path.into(),
            match_type: RouteMatchType::Exact,
            upstream_service: "gateway".into(),
            methods: BTreeSet::from([HttpMethod::Get]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: None,
            timeout_ms: 5_000,
            retries: 0,
            auth_required: false,
            authentication_type: AuthenticationType::None,
            priority: 20_000,
            tags: BTreeSet::from(["gateway-internal".into()]),
        })?;
    }
    Ok(())
}

fn operation_id(method: HttpMethod, path: &str) -> String {
    let normalized = path
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!(
        "{}_{}",
        method_name(method).to_ascii_lowercase(),
        normalized.trim_matches('_')
    )
}

fn path_parameters(path: &str) -> Vec<Value> {
    path.split('{')
        .skip(1)
        .filter_map(|tail| tail.split_once('}').map(|(parameter, _)| parameter))
        .map(|parameter| parameter.split(':').next().unwrap_or(parameter))
        .filter(|parameter| !parameter.is_empty())
        .map(|parameter| {
            json!({
                "name": parameter,
                "in": "path",
                "required": true,
                "schema": {"type": "string"}
            })
        })
        .collect()
}

const fn status_description(status: u16) -> &'static str {
    match status {
        200 => "Successful response",
        201 => "Resource created",
        202 => "Request accepted",
        204 => "Successful response with no content",
        _ => "Declared response",
    }
}

pub fn route_ownership(path: &str) -> RouteOwnership {
    if gateway_owned(path) {
        return RouteOwnership {
            service: "gateway",
            requires_authentication: !public_route(path),
            gateway_owned: true,
        };
    }
    let service = special_service(path).unwrap_or_else(|| {
        SERVICE_PREFIXES
            .iter()
            .find(|(prefix, _)| path.starts_with(prefix))
            .map_or("gateway", |(_, service)| *service)
    });
    RouteOwnership {
        service,
        requires_authentication: !public_route(path),
        gateway_owned: service == "gateway",
    }
}

fn special_service(path: &str) -> Option<&'static str> {
    if STATUS_PUBLIC.is_match(path) {
        return Some("revocation-profiles");
    }
    if path == "/v1/me/preferences" {
        return Some("organizations");
    }
    if path == "/v1/issued-credentials/mine" {
        return Some("applicant");
    }
    if ORGANIZATION_APPLICANT.is_match(path) {
        return Some(if APPLICANT_ISSUANCE_ADAPTER.is_match(path) {
            "issuance"
        } else {
            "applicant"
        });
    }
    None
}

pub fn route_for(
    table: &RouteTable,
    method: HttpMethod,
    path: &str,
) -> Result<mmf_platform::RouteMatch, PlatformError> {
    table.find(&GatewayRequest::new(method, path, 0))
}

/// Preserve the legacy gateway's service credential boundary for direct
/// issuance management and wallet routes while leaving browser/webhook Canvas
/// protocol entry points credential-free.
#[must_use]
pub fn requires_issuance_service_auth(path: &str) -> bool {
    route_ownership(path).service == "issuance"
        && path != "/v1/issuance/authorize"
        && !CANVAS_PUBLIC.iter().any(|pattern| pattern.is_match(path))
        && !CANVAS_SIGNED_INGRESS.is_match(path)
}

#[must_use]
pub fn retired_canvas_state_route(path: &str) -> bool {
    CANVAS_STATE_ADDRESSED.is_match(path)
        && !CANVAS_PUBLIC.iter().any(|pattern| pattern.is_match(path))
}

const SERVICE_PREFIXES: &[(&str, &str)] = &[
    ("/v1/organizations/invitations/validate", "auth"),
    ("/v1/organizations/join/code/validate", "organizations"),
    (
        "/v1/issuance/delivery-records/canvas-credentials/provenance",
        "issuance",
    ),
    ("/v1/issuance/deferred-credential", "issuance"),
    ("/v1/issuance/didcomm/deliver", "issuance"),
    ("/v1/presentation-policies", "presentation-policies"),
    ("/v1/compliance-profiles", "compliance-profiles"),
    ("/v1/credential-templates", "credential-templates"),
    ("/v1/delivery-destinations", "credential-templates"),
    ("/v1/deployment-profiles", "deployment-profiles"),
    ("/v1/device-registration", "device-registration"),
    ("/v1/revocation-profiles", "revocation-profiles"),
    ("/v1/cascade-revocations", "revocation-profiles"),
    ("/v1/revocation-batches", "revocation-profiles"),
    ("/v1/application-templates", "issuance"),
    ("/v1/integrations/canvas", "issuance"),
    ("/v1/issued-credentials", "issuance"),
    ("/v1/trust-frameworks", "trust-profiles"),
    ("/v1/trust-registry", "trust-profiles"),
    ("/v1/trust-profiles", "trust-profiles"),
    ("/v1/issuer-entities", "trust-profiles"),
    ("/v1/wallet-registry", "credential-templates"),
    ("/v1/flows/instances", "flows"),
    ("/v1/flows/siop/submit", "flows"),
    ("/v1/issuance/offers", "issuance"),
    ("/v1/issuance/authorize", "issuance"),
    ("/v1/issuance/credential", "issuance"),
    ("/v1/issuance/notification", "issuance"),
    ("/v1/issuance/nonce", "issuance"),
    ("/v1/issuance/token", "issuance"),
    ("/v1/issuance/par", "issuance"),
    ("/v1/flows/siop", "flows"),
    ("/v1/organizations", "organizations"),
    ("/v1/notifications", "notifications"),
    ("/v1/subscriptions", "notifications"),
    ("/v1/webhooks", "notifications"),
    ("/v1/policy-sets", "organizations"),
    ("/v1/signing-keys", "signing-keys"),
    ("/v1/api-keys", "organizations"),
    ("/v1/passport", "issuance"),
    ("/v1/issuance", "issuance"),
    ("/v1/flows", "flows"),
    ("/v1/verify", "verification"),
    ("/v1/devices", "device-registration"),
    ("/v1/auth", "auth"),
    ("/v1/me", "applicant"),
];

static CANVAS_PUBLIC: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^/v1/integrations/canvas/lti/jwks/?$",
        r"^/v1/integrations/canvas/lti/config/[^/]+/?$",
        r"^/v1/integrations/canvas/lti/platforms/[^/]+/(?:login|experience-login|launch|experience)/?$",
        r"^/v1/integrations/canvas/oauth/callback/?$",
        r"^/v1/integrations/canvas/lti/experience-sessions/(?:exchange|current(?:/(?:bootstrap|evidence-sync|evidence-status|deep-linking-response))?)/?$",
    ]
    .into_iter()
    .map(|pattern| Regex::new(pattern).expect("static Canvas route regex"))
    .collect()
});

static CANVAS_SIGNED_INGRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/v1/integrations/canvas/(?:evidence-events|ags/score-events|nrps/membership-events)/?$",
    )
    .expect("static Canvas signed ingress regex")
});

static CANVAS_STATE_ADDRESSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/v1/integrations/canvas/lti/experience-sessions/[^/]+(?:/(?:bootstrap|evidence-sync|deep-linking-response))?/?$",
    )
    .expect("static retired Canvas state route regex")
});

static WALLET_PUBLIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/(?:flows/instances|verify)/[^/]+/(?:request|submit)$")
        .expect("static wallet route regex")
});

static STATUS_PUBLIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/organizations/[^/]+/revocation-profiles/[^/]+/status-lists/[^/]+/[^/]+$")
        .expect("static status route regex")
});

static ORGANIZATION_APPLICANT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/organizations/[^/]+/applicants(?:/|$)")
        .expect("static organization applicant regex")
});

static APPLICANT_ISSUANCE_ADAPTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/v1/organizations/[^/]+/applicants/[^/]+/(?:evidence-summary|evidence-facts|evidence/api-checks/[^/]+/run)$",
    )
    .expect("static applicant issuance adapter regex")
});

static ORGANIZATION_COMPOSITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/v1/organizations/[^/]+/(?:lifecycle(?:/purge)?|runtime/status|dashboard/applicant-stats|integration-info)$",
    )
    .expect("static organization composition regex")
});

static APPENDED_DISCOVERY_PUBLIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/org/[^/]+(?:/(?:waltid|credential-manager|apple-wallet))?/\.well-known/(?:openid-credential-issuer|oauth-authorization-server)$",
    )
    .expect("static appended discovery route regex")
});

static DID_WEB_PUBLIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/orgs/[^/]+/did\.json$").expect("static DID Web route regex"));

fn public_route(path: &str) -> bool {
    path == "/openapi.json"
        || path == "/docs"
        || path == "/redoc"
        || path == "/ready"
        || path == "/health"
        || path.starts_with("/health/")
        || path.starts_with("/.well-known/")
        || path.starts_with("/credentials/")
        || path.starts_with("/internal/signing-keys")
        || path.ends_with("/did.json")
        || path.starts_with("/v1/auth")
        || path == "/v1/organizations/invitations/validate"
        || path == "/v1/organizations/join/code/validate"
        || path.starts_with("/v1/trust-registry")
        || APPENDED_DISCOVERY_PUBLIC.is_match(path)
        || DID_WEB_PUBLIC.is_match(path)
        || [
            "/v1/issuance/offers",
            "/v1/issuance/token",
            "/v1/issuance/credential",
            "/v1/issuance/nonce",
            "/v1/issuance/notification",
            "/v1/issuance/deferred-credential",
            "/v1/issuance/authorize",
            "/v1/issuance/par",
            "/v1/flows/siop/submit",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix))
        || CANVAS_PUBLIC.iter().any(|pattern| pattern.is_match(path))
        || WALLET_PUBLIC.is_match(path)
        || STATUS_PUBLIC.is_match(path)
}

fn gateway_owned(path: &str) -> bool {
    path == "/openapi.json"
        || path == "/docs"
        || path == "/redoc"
        || path.starts_with("/.well-known/")
        || path.starts_with("/credentials/")
        || path.starts_with("/health")
        || path.starts_with("/internal/signing-keys")
        || path.starts_with("/org/")
        || path.starts_with("/orgs/")
        || path.starts_with("/v1/vc-api")
        || path == "/v1/notifications/events/push"
        || retired_canvas_state_route(path)
        || ORGANIZATION_COMPOSITION.is_match(path)
}

fn upstream_rewrite(method: HttpMethod, declared_path: &str) -> Option<String> {
    let path = match (method, declared_path) {
        (HttpMethod::Post, "/v1/issuance") => "/v1/issuance/initiate",
        (HttpMethod::Get, "/v1/issuance") => "/v1/issuance/transactions",
        (HttpMethod::Get, "/v1/issuance/{issuance_id}") => {
            "/v1/issuance/transactions/{issuance_id}"
        }
        (HttpMethod::Post, "/v1/issuance/{issuance_id}/revoke") => {
            "/v1/issuance/transactions/{issuance_id}/revoke"
        }
        (HttpMethod::Get, "/v1/issuance/{issuance_id}/revocation-status") => {
            "/v1/issuance/transactions/{issuance_id}/revocation-status"
        }
        (
            HttpMethod::Get,
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence-summary",
        ) => "/internal/applications/{application_id}/evidence-summary",
        (
            HttpMethod::Get,
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence-facts",
        ) => "/internal/applications/{application_id}/evidence-facts",
        (
            HttpMethod::Post,
            "/v1/organizations/{organization_id}/applicants/{application_id}/evidence/api-checks/{check_id}/run",
        ) => "/internal/applications/{application_id}/evidence/api-checks/{check_id}/run",
        _ => return None,
    };
    Some(path.into())
}

fn route_priority(path: &str) -> i32 {
    let segments = path.split('/').filter(|value| !value.is_empty());
    let mut priority = 0;
    for segment in segments {
        priority += if segment.contains(":path}") {
            1
        } else if segment.starts_with('{') {
            10
        } else {
            100
        };
    }
    if !path.contains('{') {
        priority += 10_000;
    }
    priority
}

const fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ProxyTrustContract {
        schema_version: u32,
        issuance_service_auth: Vec<IssuanceAuthCase>,
        special_ownership: Vec<OwnershipCase>,
    }

    #[derive(Deserialize)]
    struct IssuanceAuthCase {
        name: String,
        path: String,
        required: bool,
    }

    #[derive(Deserialize)]
    struct OwnershipCase {
        method: HttpMethod,
        path: String,
        service: String,
        gateway_owned: bool,
        upstream_path: String,
    }

    #[test]
    fn language_neutral_proxy_trust_boundary_contract() {
        let contract: ProxyTrustContract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-proxy-trust-boundary.json"
        ))
        .expect("proxy trust contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.issuance_service_auth {
            assert_eq!(
                requires_issuance_service_auth(&case.path),
                case.required,
                "{}",
                case.name
            );
        }
        for case in contract.special_ownership {
            let owner = route_ownership(&case.path);
            assert_eq!(owner.service, case.service, "{}", case.path);
            assert_eq!(owner.gateway_owned, case.gateway_owned, "{}", case.path);
            let matched = route_for(
                &GatewayContract::load()
                    .expect("gateway contract")
                    .route_table()
                    .expect("route table"),
                case.method,
                &case.path,
            )
            .expect("special ownership route");
            let rewritten = matched.route.rewrite_path.as_deref().map_or_else(
                || case.path.clone(),
                |template| {
                    matched
                        .params
                        .iter()
                        .fold(template.to_owned(), |path, (key, value)| {
                            path.replace(&format!("{{{key}}}"), value)
                        })
                },
            );
            assert_eq!(rewritten, case.upstream_path, "{}", case.path);
        }
    }

    #[test]
    fn frozen_route_and_middleware_contract_builds_one_mmf_table() {
        let contract = GatewayContract::load().expect("gateway contract");
        let table = contract.route_table().expect("route table");
        assert_eq!(table.routes().len(), EXPECTED_ROUTE_COUNT);
        assert_eq!(
            route_for(&table, HttpMethod::Get, "/v1/auth/session/validate")
                .expect("catch-all auth route")
                .route
                .upstream_service,
            "auth"
        );
        assert_eq!(
            route_for(
                &table,
                HttpMethod::Get,
                "/v1/organizations/org-1/scim/v2/Users/user-1",
            )
            .expect("catch-all SCIM route")
            .route
            .upstream_service,
            "organizations"
        );
    }

    #[test]
    fn openapi_is_derived_from_every_schema_visible_route() {
        let contract = GatewayContract::load().expect("gateway contract");
        let document = contract.openapi_document();
        assert_eq!(document["openapi"], "3.1.0");
        assert_eq!(document["info"]["title"], "Marty API Gateway");
        let paths = document["paths"].as_object().expect("OpenAPI paths");
        let mut operations = 0;
        for route in &contract.routes {
            let operation = paths
                .get(&route.path)
                .and_then(Value::as_object)
                .and_then(|item| item.get(&method_name(route.method).to_ascii_lowercase()));
            if route.include_in_schema {
                let operation = operation.unwrap_or_else(|| {
                    panic!(
                        "missing OpenAPI operation {} {}",
                        method_name(route.method),
                        route.path
                    )
                });
                assert!(operation["responses"]
                    .get(route.status_code.to_string())
                    .is_some());
                assert_eq!(
                    operation["x-marty-upstream-service"],
                    route_ownership(&route.path).service
                );
                operations += 1;
            } else {
                assert!(operation.is_none(), "excluded operation was documented");
            }
        }
        assert_eq!(
            operations,
            contract
                .routes
                .iter()
                .filter(|route| route.include_in_schema)
                .count()
        );
        assert_eq!(
            document["paths"]["/v1/organizations/{organization_id}/applicants"]["get"]
                ["parameters"][0]["name"],
            "organization_id"
        );
        assert!(document.to_string().find("commerce").is_none());
    }

    #[test]
    fn internal_proxy_routes_do_not_mutate_public_contract() {
        let contract = GatewayContract::load().expect("gateway contract");
        assert_eq!(contract.route_table().expect("public").routes().len(), 434);
        assert_eq!(
            contract
                .runtime_route_table()
                .expect("runtime")
                .routes()
                .len(),
            437
        );
        let proxy = contract.proxy_route_table().expect("proxy");
        assert_eq!(proxy.routes().len(), 448);
        assert_eq!(
            route_for(
                &proxy,
                HttpMethod::Get,
                "/v1/compliance-profiles/system/discoverable"
            )
            .expect("internal route")
            .route
            .upstream_service,
            "compliance-profiles"
        );
        assert_eq!(
            route_for(&proxy, HttpMethod::Get, "/v1/organizations/org-1/api-keys")
                .expect("legacy API-key upstream route")
                .route
                .upstream_service,
            "organizations"
        );
    }

    #[test]
    fn public_and_management_boundaries_match_legacy_gateway() {
        for path in [
            "/health",
            "/.well-known/openid-configuration",
            "/credentials/member-badge",
            "/v1/issuance/token",
            "/v1/flows/instances/flow-1/request",
            "/v1/integrations/canvas/lti/jwks",
            "/org/org-1/waltid/.well-known/openid-credential-issuer",
            "/orgs/example/did.json",
        ] {
            assert!(!route_ownership(path).requires_authentication, "{path}");
        }
        for path in [
            "/v1/organizations",
            "/v1/signing-keys/services",
            "/v1/flows",
            "/v1/verify",
            "/v1/devices/challenge",
        ] {
            assert!(route_ownership(path).requires_authentication, "{path}");
        }
        assert_eq!(
            route_ownership("/v1/devices/challenge").service,
            "device-registration"
        );
    }
}
