//! Routing boundary for incrementally migrated issuance HTTP operations.
//!
//! The language-neutral coverage contract is the only allow-list. Anything
//! absent from it stays on the legacy issuance service, which prevents an
//! incomplete Rust executable from silently deleting production behavior.

use std::{collections::BTreeSet, sync::LazyLock};

use mmf_platform::{
    AuthenticationType, GatewayRequest, HttpMethod, PlatformError, RouteConfig, RouteMatchType,
    RouteTable,
};
use serde::Deserialize;

pub const LEGACY_SERVICE: &str = "issuance";
pub const NATIVE_SERVICE: &str = "issuance-native";
const CREDENTIAL_LIFECYCLE_TAG: &str = "credential-lifecycle";
const ISSUED_CREDENTIAL_ADAPTER_TAG: &str = "issued-credential-adapter";
const OID4VCI_AUTHORIZATION_TAG: &str = "oid4vci-authorization";
const RETENTION_TAG: &str = "retention";
const NATIVE_EXTENSION_TAG: &str = "native-extension";
// Only the explicitly opt-in passport observation and administrative
// operations remain in this native extension inventory.
pub(crate) const NATIVE_EXTENSION_ROUTE_COUNT: usize = 0;
pub(crate) const PASSPORT_NATIVE_EXTENSION_ROUTE_COUNT: usize = 2;
const PASSPORT_READ_PATH: &str = "/v1/passport/applications/{application_id}";
const PASSPORT_CANCEL_PATH: &str = "/v1/passport/applications/{application_id}/cancel";
#[derive(Debug, Deserialize)]
struct Coverage {
    native_http: Vec<NativeHttpRoute>,
    /// Native-only operations are separate from the frozen legacy migration
    /// inventory; adding an endpoint must not claim historical parity.
    #[serde(default)]
    native_extension_http: Vec<NativeHttpExtension>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeHttpExtension {
    method: HttpMethod,
    path: String,
    operation: String,
    owner: String,
    source: String,
    behavior_test: String,
    adaptation: String,
}

fn validate_native_extensions(coverage: &Coverage) -> Result<(), &'static str> {
    let mut operations = BTreeSet::new();
    for route in &coverage.native_extension_http {
        let (operation, source, behavior_test) = match (route.method, route.path.as_str()) {
            (HttpMethod::Get, PASSPORT_READ_PATH) => (
                "read_passport_application",
                "rust/services/issuance/src/passport_http.rs",
                "rust/services/issuance/tests/passport_postgres_contract.rs",
            ),
            (HttpMethod::Post, PASSPORT_CANCEL_PATH) => (
                "administratively_cancel_passport_job",
                "rust/services/issuance/src/passport_cancellation_http.rs",
                "rust/services/issuance/tests/passport_postgres_contract.rs",
            ),
            _ => return Err("unreviewed native extension method or path"),
        };
        if route.operation != operation
            || route.owner != NATIVE_SERVICE
            || route.source != source
            || route.behavior_test != behavior_test
            || route.adaptation.is_empty()
            || !operations.insert(operation)
            || coverage
                .native_http
                .iter()
                .any(|existing| existing.method == route.method && existing.path == route.path)
        {
            return Err("native extension differs from reviewed contract");
        }
    }
    if operations.len() != NATIVE_EXTENSION_ROUTE_COUNT + PASSPORT_NATIVE_EXTENSION_ROUTE_COUNT {
        return Err("native extensions require every reviewed operation");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PassportCoverage {
    routes: Vec<NativeHttpRoute>,
}

#[derive(Debug, Deserialize)]
struct NativeHttpRoute {
    method: HttpMethod,
    path: String,
    #[serde(default)]
    credential_lifecycle_behavior_contract: bool,
    #[serde(default)]
    issued_credential_adapter_behavior_contract: bool,
    #[serde(default)]
    oid4vci_authorization_behavior_contract: bool,
    #[serde(default)]
    retention_behavior_contract: bool,
}

static NATIVE_ROUTES: LazyLock<RouteTable> = LazyLock::new(|| {
    let coverage: Coverage = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("embedded issuance native coverage contract must be valid");
    validate_native_extensions(&coverage).expect("native extension contract must be reviewed");
    let mut table = RouteTable::default();
    let routes = coverage
        .native_http
        .into_iter()
        .map(|route| (false, route))
        .chain(coverage.native_extension_http.into_iter().map(|route| {
            (
                true,
                NativeHttpRoute {
                    method: route.method,
                    path: route.path,
                    credential_lifecycle_behavior_contract: false,
                    issued_credential_adapter_behavior_contract: false,
                    oid4vci_authorization_behavior_contract: false,
                    retention_behavior_contract: false,
                },
            )
        }));
    for (index, (extension, route)) in routes.enumerate() {
        let mut tags = BTreeSet::from(["native-migration".into()]);
        if extension {
            tags.insert(NATIVE_EXTENSION_TAG.into());
        }
        if route.credential_lifecycle_behavior_contract {
            tags.insert(CREDENTIAL_LIFECYCLE_TAG.into());
        }
        if route.issued_credential_adapter_behavior_contract {
            tags.insert(ISSUED_CREDENTIAL_ADAPTER_TAG.into());
        }
        if route.oid4vci_authorization_behavior_contract {
            tags.insert(OID4VCI_AUTHORIZATION_TAG.into());
        }
        if route.retention_behavior_contract {
            tags.insert(RETENTION_TAG.into());
        }
        table
            .add(RouteConfig {
                name: format!("issuance-native:{index}"),
                match_type: if route.path.contains('{') {
                    RouteMatchType::Template
                } else {
                    RouteMatchType::Exact
                },
                pattern: route.path,
                upstream_service: NATIVE_SERVICE.into(),
                methods: BTreeSet::from([route.method]),
                host: None,
                required_headers: Default::default(),
                rewrite_path: None,
                timeout_ms: 30_000,
                retries: 2,
                auth_required: false,
                authentication_type: AuthenticationType::None,
                priority: 10_000,
                tags,
            })
            .expect("issuance native coverage routes must be unique and valid");
    }
    table
});

/// Register the reviewed native-only public routes as well as selecting their
/// upstream. The frozen gateway inventory cannot register new operations.
pub(crate) fn add_public_native_extensions(
    table: &mut RouteTable,
    passport_native: bool,
) -> Result<(), PlatformError> {
    let coverage: Coverage = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .map_err(|error| PlatformError::InvalidConfiguration(error.to_string()))?;
    validate_native_extensions(&coverage)
        .map_err(|error| PlatformError::InvalidConfiguration(error.into()))?;
    for extension in coverage.native_extension_http {
        if matches!(
            extension.path.as_str(),
            PASSPORT_CANCEL_PATH | PASSPORT_READ_PATH
        ) && !passport_native
        {
            continue;
        }
        // Reuse the validated native route and the public gateway's canonical
        // ownership policy. The upstream selector's authentication-free metadata
        // is not an authorization policy for newly registered public routes.
        let request = GatewayRequest::new(extension.method, extension.path, 0);
        let matched = NATIVE_ROUTES.find(&request)?;
        let mut route = matched.route.clone();
        route.auth_required =
            crate::contract::route_ownership(&route.pattern).requires_authentication;
        route.authentication_type = if route.auth_required {
            AuthenticationType::Jwt
        } else {
            AuthenticationType::None
        };
        table.add(route)?;
    }
    Ok(())
}

// The signed bureau webhook has its own HMAC-authenticated ingress boundary.
// Keep the tenant-key selector tied to the eight caller-authenticated routes,
// not to a broad prefix that could attach a tenant key to the webhook.
static PASSPORT_PUBLIC_ROUTES: LazyLock<Vec<NativeHttpRoute>> = LazyLock::new(|| {
    let coverage: PassportCoverage = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-physical-passport-native.json"
    ))
    .expect("embedded passport behavior contract must be valid");
    let routes = coverage
        .routes
        .into_iter()
        .filter(|route| route.path != "/v1/passport/webhooks/personalization")
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 8, "exactly eight public passport routes");
    routes
});

#[must_use]
pub fn is_passport_public_http(method: HttpMethod, path: &str) -> bool {
    is_canonical_absolute_path(path)
        && ((method == HttpMethod::Get && exact_template_shape(PASSPORT_READ_PATH, path))
            || is_passport_administrative_cancel(method, path)
            || PASSPORT_PUBLIC_ROUTES
                .iter()
                .any(|route| route.method == method && exact_template_shape(&route.path, path)))
}

#[must_use]
pub(crate) fn is_passport_administrative_cancel(method: HttpMethod, path: &str) -> bool {
    method == HttpMethod::Post
        && is_canonical_absolute_path(path)
        && exact_template_shape(PASSPORT_CANCEL_PATH, path)
}

#[must_use]
pub fn is_passport_signed_webhook(method: HttpMethod, path: &str) -> bool {
    method == HttpMethod::Post && path == "/v1/passport/webhooks/personalization"
}

/// Native passport requests use the existing issuance read/issue permissions.
/// Legacy routing does not call this policy; only the explicit native gateway
/// selector activates its authenticated tenant boundary.
#[must_use]
pub fn passport_required_permission(method: HttpMethod, path: &str) -> Option<&'static str> {
    if !is_passport_public_http(method, path) {
        return None;
    }
    if is_passport_administrative_cancel(method, path) {
        Some("issuance:revoke")
    } else if method == HttpMethod::Get {
        Some("issuance:view")
    } else {
        Some("issuance:initiate")
    }
}

#[must_use]
pub fn is_native_http(method: HttpMethod, path: &str) -> bool {
    if method == HttpMethod::Get && path == "/v1/issued-credentials/mine" {
        return false;
    }
    NATIVE_ROUTES
        .find(&GatewayRequest::new(method, path, 0))
        .is_ok_and(|matched| {
            let exact_shape_required = matched.route.tags.contains(CREDENTIAL_LIFECYCLE_TAG)
                || matched.route.tags.contains(ISSUED_CREDENTIAL_ADAPTER_TAG)
                || matched.route.tags.contains(OID4VCI_AUTHORIZATION_TAG)
                || matched.route.tags.contains(RETENTION_TAG)
                || matched.route.tags.contains(NATIVE_EXTENSION_TAG);
            !exact_shape_required
                || (is_canonical_absolute_path(path)
                    && exact_template_shape(&matched.route.pattern, path))
        })
}

fn exact_template_shape(pattern: &str, path: &str) -> bool {
    let mut pattern_segments = pattern.split('/');
    let mut path_segments = path.split('/');
    loop {
        match (pattern_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(pattern_segment), Some(path_segment)) => {
                let parameter = pattern_segment.starts_with('{') && pattern_segment.ends_with('}');
                if (parameter && path_segment.is_empty())
                    || (!parameter && pattern_segment != path_segment)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn is_canonical_absolute_path(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|relative| {
        !relative.is_empty()
            && !relative.starts_with('/')
            && !relative.ends_with('/')
            && !relative.contains("//")
    })
}

#[must_use]
pub fn upstream_service(method: HttpMethod, path: &str) -> &'static str {
    if is_native_http(method, path) {
        NATIVE_SERVICE
    } else {
        LEGACY_SERVICE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passport_public_classifier_selects_only_frozen_eight_routes() {
        for (method, path) in [
            (HttpMethod::Get, "/v1/passport/capabilities"),
            (HttpMethod::Post, "/v1/passport/applications"),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/generate-data-groups",
            ),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/generate-sod",
            ),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/submit-personalization",
            ),
            (
                HttpMethod::Get,
                "/v1/passport/applications/job-1/production-status",
            ),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/quality-verify",
            ),
            (HttpMethod::Post, "/v1/passport/applications/job-1/activate"),
        ] {
            assert!(is_passport_public_http(method, path), "{method:?} {path}");
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
        for (method, path) in [
            (HttpMethod::Post, "/v1/passport/webhooks/personalization"),
            (HttpMethod::Get, "/v1/passport/applications"),
            (HttpMethod::Post, "/v1/passport/capabilities"),
            (HttpMethod::Post, "/v1/passport/applications//activate"),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/activate/extra",
            ),
            (
                HttpMethod::Post,
                "/v1/passport/applications/job-1/activate/",
            ),
            (HttpMethod::Post, "//v1/passport/applications"),
        ] {
            assert!(!is_passport_public_http(method, path), "{method:?} {path}");
            assert_eq!(passport_required_permission(method, path), None);
        }
        assert!(is_passport_signed_webhook(
            HttpMethod::Post,
            "/v1/passport/webhooks/personalization"
        ));
        assert!(!is_passport_signed_webhook(
            HttpMethod::Get,
            "/v1/passport/webhooks/personalization"
        ));
        assert_eq!(
            passport_required_permission(HttpMethod::Get, "/v1/passport/capabilities"),
            Some("issuance:view")
        );
        assert_eq!(
            passport_required_permission(HttpMethod::Post, "/v1/passport/applications"),
            Some("issuance:initiate")
        );
        assert_eq!(
            passport_required_permission(
                HttpMethod::Post,
                "/v1/passport/applications/job-1/activate"
            ),
            Some("issuance:initiate")
        );
    }

    #[test]
    fn retention_selects_only_frozen_tenant_routes() {
        for (method, suffix) in [(HttpMethod::Get, ""), (HttpMethod::Post, "/purge")] {
            let path = format!("/v1/issuance/organizations/org-a/retention{suffix}");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
        }
        for (method, path) in [
            (
                HttpMethod::Post,
                "/v1/issuance/organizations/org-a/retention",
            ),
            (
                HttpMethod::Get,
                "/v1/issuance/organizations/org-a/retention/purge",
            ),
            (
                HttpMethod::Get,
                "/v1/issuance/organizations/org-a/retention/extra",
            ),
            (HttpMethod::Get, "/v1/issuance/organizations//retention"),
        ] {
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn application_templates_select_only_the_eight_frozen_methods_and_paths() {
        for (method, suffix) in [
            (HttpMethod::Post, ""),
            (HttpMethod::Get, ""),
            (HttpMethod::Get, "/template-1"),
            (HttpMethod::Patch, "/template-1"),
            (HttpMethod::Post, "/template-1/validate"),
            (HttpMethod::Post, "/template-1/activate"),
            (HttpMethod::Post, "/template-1/deprecate"),
            (HttpMethod::Delete, "/template-1"),
        ] {
            let path = format!("/v1/application-templates{suffix}");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
        }
        for (method, path) in [
            (HttpMethod::Put, "/v1/application-templates/template-1"),
            (HttpMethod::Post, "/v1/application-templates/template-1"),
            (
                HttpMethod::Get,
                "/v1/application-templates/template-1/validate",
            ),
            (HttpMethod::Delete, "/v1/application-templates"),
            (
                HttpMethod::Get,
                "/v1/application-templates/template-1/extra",
            ),
        ] {
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn internal_applications_select_only_the_fourteen_frozen_methods_and_paths() {
        for (method, suffix) in [
            (HttpMethod::Post, ""),
            (HttpMethod::Get, ""),
            (HttpMethod::Get, "/application-1"),
            (HttpMethod::Get, "/application-1/evidence-facts"),
            (HttpMethod::Get, "/application-1/evidence-summary"),
            (
                HttpMethod::Post,
                "/application-1/evidence/api-checks/check-1/run",
            ),
            (HttpMethod::Post, "/evidence/reconcile"),
            (HttpMethod::Get, "/evidence/reconciliation-report"),
            (HttpMethod::Post, "/application-1/submit-evidence"),
            (HttpMethod::Post, "/application-1/approve"),
            (HttpMethod::Post, "/application-1/reject"),
            (HttpMethod::Post, "/application-1/issuance-offer"),
            (HttpMethod::Get, "/application-1/issuance-offer"),
            (HttpMethod::Get, "/application-1/issuance-events"),
        ] {
            let path = format!("/internal/applications{suffix}");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
        }
        for (method, path) in [
            (HttpMethod::Delete, "/internal/applications/application-1"),
            (
                HttpMethod::Put,
                "/internal/applications/application-1/approve",
            ),
            (
                HttpMethod::Get,
                "/internal/applications/application-1/approve",
            ),
            (
                HttpMethod::Post,
                "/internal/applications/application-1/evidence-summary",
            ),
            (
                HttpMethod::Get,
                "/internal/applications/application-1/extra",
            ),
        ] {
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn credential_lifecycle_selects_only_the_four_frozen_methods_and_paths() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-credential-lifecycle.json"
        ))
        .expect("credential lifecycle contract");
        let routes = contract["scope"]["http"]
            .as_array()
            .expect("credential lifecycle HTTP routes");
        assert_eq!(routes.len(), 4);

        let methods = [
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Patch,
            HttpMethod::Head,
            HttpMethod::Options,
            HttpMethod::Trace,
            HttpMethod::Connect,
        ];
        for route in routes {
            let method: HttpMethod =
                serde_json::from_value(route["method"].clone()).expect("lifecycle method");
            let path = route["path"]
                .as_str()
                .expect("lifecycle path")
                .replace("{credential_id}", "credential-1");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
            for candidate in methods {
                if candidate != method {
                    assert_eq!(
                        upstream_service(candidate, &path),
                        LEGACY_SERVICE,
                        "{candidate:?} {path}"
                    );
                }
            }

            let empty_id = path.replace("/credential-1/", "//");
            for near_miss in [
                path.trim_start_matches('/').to_owned(),
                format!("/{path}"),
                format!("{path}/"),
                format!("{path}/extra"),
                format!("{path}-extra"),
                empty_id,
            ] {
                assert_eq!(
                    upstream_service(method, &near_miss),
                    LEGACY_SERVICE,
                    "{method:?} {near_miss}"
                );
            }
        }
        assert_eq!(
            upstream_service(HttpMethod::Get, "/v1/issuance/credentials"),
            NATIVE_SERVICE,
            "the OID4VCI management list route must remain native"
        );
        assert_eq!(
            upstream_service(HttpMethod::Post, "/v1/issuance/credentials"),
            LEGACY_SERVICE
        );
        for path in [
            "/v1/issuance/credentials/credential-1",
            "/v1/issuance/credentials/credential-1/status/extra",
        ] {
            assert_eq!(upstream_service(HttpMethod::Get, path), LEGACY_SERVICE);
            assert_eq!(upstream_service(HttpMethod::Post, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn issued_credential_adapters_select_only_the_five_frozen_methods_and_paths() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-issued-credential-adapters.json"
        ))
        .expect("issued-credential adapter contract");
        let routes = contract["operations"].as_array().expect("operations");
        assert_eq!(routes.len(), 5);
        for route in routes {
            let method: HttpMethod = serde_json::from_value(route["method"].clone()).unwrap();
            let path = route["path"]
                .as_str()
                .unwrap()
                .replace("{credential_id}", "credential-1");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
            let other = if method == HttpMethod::Get {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            };
            assert_eq!(upstream_service(other, &path), LEGACY_SERVICE);
            let mut near_misses = vec![
                path.trim_start_matches('/').to_owned(),
                format!("/{path}"),
                format!("{path}/"),
            ];
            if path != "/v1/issued-credentials" {
                near_misses.push(format!("{path}/extra"));
            }
            for near_miss in near_misses {
                assert_eq!(upstream_service(method, &near_miss), LEGACY_SERVICE);
            }
        }
        assert_eq!(
            upstream_service(
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/renew"
            ),
            NATIVE_SERVICE,
            "the previously migrated renewal adapter must remain native"
        );
        for (method, path) in [
            (HttpMethod::Get, "/v1/issued-credentials/mine"),
            (HttpMethod::Post, "/v1/credentials/issued/batch-revoke"),
            (HttpMethod::Get, "/v1/credentials/revocations"),
        ] {
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn preexisting_native_routes_keep_route_table_path_matching_semantics() {
        let coverage: Coverage = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-native-coverage.json"
        ))
        .expect("issuance native coverage contract");
        let preexisting = coverage
            .native_http
            .into_iter()
            .filter(|route| {
                !route.credential_lifecycle_behavior_contract
                    && !route.issued_credential_adapter_behavior_contract
                    && !route.oid4vci_authorization_behavior_contract
                    && !route.retention_behavior_contract
            })
            .collect::<Vec<_>>();
        assert_eq!(preexisting.len(), 45);

        for route in preexisting {
            let canonical = route
                .path
                .split('/')
                .map(|segment| {
                    if segment.starts_with('{') && segment.ends_with('}') {
                        "sample"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            for candidate in [
                canonical.clone(),
                canonical.trim_start_matches('/').to_owned(),
                format!("/{canonical}"),
                format!("{canonical}/"),
            ] {
                let route_table_match = NATIVE_ROUTES
                    .find(&GatewayRequest::new(route.method, &candidate, 0))
                    .is_ok();
                assert_eq!(
                    is_native_http(route.method, &candidate),
                    route_table_match,
                    "{:?} {}",
                    route.method,
                    candidate
                );
            }
        }
    }

    #[test]
    fn didcomm_and_initiation_are_native_without_selecting_sibling_paths() {
        assert_eq!(
            upstream_service(HttpMethod::Post, "/v1/issuance/didcomm/deliver"),
            NATIVE_SERVICE
        );
        assert_eq!(
            upstream_service(HttpMethod::Post, "/v1/issuance/initiate"),
            NATIVE_SERVICE
        );
        for (method, path) in [
            (HttpMethod::Get, "/v1/issuance/didcomm/deliver"),
            (HttpMethod::Post, "/v1/issuance/didcomm/deliver/extra"),
            (HttpMethod::Post, "/v1/issuance/didcomm"),
            (HttpMethod::Get, "/v1/issuance/initiate"),
            (HttpMethod::Post, "/v1/issuance/initiate/extra"),
            (HttpMethod::Post, "/v1/issuance"),
        ] {
            assert_eq!(upstream_service(method, path), LEGACY_SERVICE);
        }
    }

    #[test]
    fn coverage_is_the_fail_closed_native_allow_list() {
        for (method, path) in [
            (HttpMethod::Post, "/v1/issuance/credential"),
            (HttpMethod::Post, "/v1/issuance/token"),
            (HttpMethod::Post, "/v1/issuance/nonce"),
            (HttpMethod::Get, "/v1/issuance/offers/tx-1"),
            (HttpMethod::Get, "/v1/issuance/transactions/tx-1"),
            (HttpMethod::Get, "/v1/issuance/transactions"),
            (
                HttpMethod::Get,
                "/.well-known/openid-credential-issuer/org/org-1/apple-wallet",
            ),
            (HttpMethod::Get, "/credentials/example/type"),
            (HttpMethod::Get, "/v1/issued-credentials"),
            (HttpMethod::Get, "/v1/issued-credentials/credential-1"),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/revoke",
            ),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/suspend",
            ),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/reinstate",
            ),
            (HttpMethod::Get, "/v1/issuance/authorize"),
            (HttpMethod::Post, "/v1/issuance/par"),
            (HttpMethod::Post, "/v1/issuance/deferred-credential"),
            (HttpMethod::Post, "/v1/issuance/notification"),
            (HttpMethod::Put, "/v1/issuance/oid4vci-clients"),
            (HttpMethod::Post, "/v1/issuance/transactions/tx-1/revoke"),
            (HttpMethod::Get, "/v1/issuance/credentials"),
        ] {
            assert!(is_native_http(method, path), "{method:?} {path}");
        }

        for (method, path) in [
            (HttpMethod::Get, "/.well-known/jwks.json"),
            (HttpMethod::Get, "/v1/issued-credentials/mine"),
        ] {
            assert!(!is_native_http(method, path), "{method:?} {path}");
        }
    }

    #[test]
    fn oid4vci_selects_only_the_seven_frozen_routes() {
        let routes = [
            (HttpMethod::Get, "/v1/issuance/authorize"),
            (HttpMethod::Post, "/v1/issuance/par"),
            (HttpMethod::Post, "/v1/issuance/deferred-credential"),
            (HttpMethod::Post, "/v1/issuance/notification"),
            (HttpMethod::Put, "/v1/issuance/oid4vci-clients"),
            (HttpMethod::Post, "/v1/issuance/transactions/tx-1/revoke"),
            (HttpMethod::Get, "/v1/issuance/credentials"),
        ];
        for (method, path) in routes {
            assert_eq!(upstream_service(method, path), NATIVE_SERVICE);
            let wrong_method = if method == HttpMethod::Get {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            };
            assert_eq!(upstream_service(wrong_method, path), LEGACY_SERVICE);
            for near_miss in [
                format!("{path}/"),
                format!("{path}/extra"),
                format!("{path}-extra"),
            ] {
                assert_eq!(upstream_service(method, &near_miss), LEGACY_SERVICE);
            }
        }
        for path in [
            "/v1/issuance/transactions//revoke",
            "/v1/issuance/transactions/tx-1/extra/revoke",
            "/v1/issuance/transactions/tx-1/revoke/extra",
        ] {
            assert_eq!(upstream_service(HttpMethod::Post, path), LEGACY_SERVICE);
        }
    }
}
