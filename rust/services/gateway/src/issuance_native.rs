//! Routing boundary for incrementally migrated issuance HTTP operations.
//!
//! The language-neutral coverage contract is the only allow-list. Anything
//! absent from it stays on the legacy issuance service, which prevents an
//! incomplete Rust executable from silently deleting production behavior.

use std::{collections::BTreeSet, sync::LazyLock};

use mmf_platform::{
    AuthenticationType, GatewayRequest, HttpMethod, RouteConfig, RouteMatchType, RouteTable,
};
use serde::Deserialize;

pub const LEGACY_SERVICE: &str = "issuance";
pub const NATIVE_SERVICE: &str = "issuance-native";
const CREDENTIAL_LIFECYCLE_TAG: &str = "credential-lifecycle";
const ISSUED_CREDENTIAL_ADAPTER_TAG: &str = "issued-credential-adapter";
const OID4VCI_AUTHORIZATION_TAG: &str = "oid4vci-authorization";
const CANVAS_MIRROR_TAG: &str = "canvas-mirror";
const RETENTION_TAG: &str = "retention";

const CANVAS_MIRROR_BATCH_PATHS: [&str; 3] = [
    "/v1/issuance/delivery-records/canvas-credentials/process-pending",
    "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
    "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
];

/// Public batch operations are always scoped by the authenticated gateway
/// tenant. Direct service calls and internal workers deliberately retain the
/// frozen optional/global organization behavior.
#[must_use]
pub fn is_canvas_mirror_public_batch(method: &str, path: &str) -> bool {
    method == "POST" && CANVAS_MIRROR_BATCH_PATHS.contains(&path)
}

#[derive(Debug, Deserialize)]
struct Coverage {
    native_http: Vec<NativeHttpRoute>,
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
    canvas_mirror_behavior_contract: bool,
    #[serde(default)]
    retention_behavior_contract: bool,
}

static NATIVE_ROUTES: LazyLock<RouteTable> = LazyLock::new(|| {
    let coverage: Coverage = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("embedded issuance native coverage contract must be valid");
    let mut table = RouteTable::default();
    for (index, route) in coverage.native_http.into_iter().enumerate() {
        let mut tags = BTreeSet::from(["native-migration".into()]);
        if route.credential_lifecycle_behavior_contract {
            tags.insert(CREDENTIAL_LIFECYCLE_TAG.into());
        }
        if route.issued_credential_adapter_behavior_contract {
            tags.insert(ISSUED_CREDENTIAL_ADAPTER_TAG.into());
        }
        if route.oid4vci_authorization_behavior_contract {
            tags.insert(OID4VCI_AUTHORIZATION_TAG.into());
        }
        if route.canvas_mirror_behavior_contract {
            tags.insert(CANVAS_MIRROR_TAG.into());
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
        && PASSPORT_PUBLIC_ROUTES
            .iter()
            .any(|route| route.method == method && exact_template_shape(&route.path, path))
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
    if method == HttpMethod::Get {
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
                || matched.route.tags.contains(CANVAS_MIRROR_TAG)
                || matched.route.tags.contains(RETENTION_TAG);
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
                    && !route.canvas_mirror_behavior_contract
                    && !route.retention_behavior_contract
            })
            .collect::<Vec<_>>();
        assert_eq!(preexisting.len(), 98);

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
    fn canvas_mirror_selects_only_the_six_frozen_methods_and_paths() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-canvas-mirror.json"
        ))
        .expect("Canvas mirror contract");
        let routes = contract["routes"].as_array().expect("Canvas mirror routes");
        assert_eq!(routes.len(), 6);
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
            let method: HttpMethod = serde_json::from_value(route["method"].clone()).unwrap();
            let path = route["path"]
                .as_str()
                .unwrap()
                .replace("{credential_id}", "credential-1")
                .replace("{organization_id}", "org-1");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
            for candidate in methods {
                if candidate != method {
                    assert_eq!(upstream_service(candidate, &path), LEGACY_SERVICE);
                }
            }
            let mut near_misses = vec![
                path.trim_start_matches('/').to_owned(),
                format!("/{path}"),
                format!("{path}/"),
                format!("{path}/extra"),
            ];
            if path.contains("credential-1") {
                near_misses.push(path.replace("/credential-1/", "//"));
            }
            if path.contains("org-1") {
                near_misses.push(path.replace("/org-1/", "//"));
            }
            for near_miss in near_misses {
                assert_eq!(upstream_service(method, &near_miss), LEGACY_SERVICE);
            }
        }
    }

    #[test]
    fn only_the_three_exact_public_canvas_batches_require_trusted_query_scope() {
        for path in CANVAS_MIRROR_BATCH_PATHS {
            assert!(is_canvas_mirror_public_batch("POST", path));
            assert!(!is_canvas_mirror_public_batch("GET", path));
            assert!(!is_canvas_mirror_public_batch("post", path));
            assert!(!is_canvas_mirror_public_batch("POST", &format!("{path}/")));
            assert!(!is_canvas_mirror_public_batch(
                "POST",
                &format!("{path}/extra")
            ));
        }
        assert!(!is_canvas_mirror_public_batch(
            "POST",
            "/v1/issued-credentials/credential-1/deliveries/canvas-credentials/publish"
        ));
    }

    #[test]
    fn canvas_operations_select_only_the_eight_exact_methods_and_paths() {
        for (method, suffix) in [
            (HttpMethod::Post, "/applications/app-1/canvas-sync"),
            (HttpMethod::Get, "/canvas-sync-jobs"),
            (HttpMethod::Get, "/canvas-sync-jobs/job-1"),
            (HttpMethod::Post, "/canvas-sync-jobs/job-1/retry"),
            (HttpMethod::Post, "/canvas-sync-jobs/job-1/resolve"),
            (HttpMethod::Get, "/canvas-award-candidates"),
            (HttpMethod::Get, "/evidence-policy-reviews"),
            (
                HttpMethod::Post,
                "/evidence-policy-reviews/review-1/resolve",
            ),
        ] {
            let path = format!("/v1/integrations/canvas{suffix}");
            assert_eq!(upstream_service(method, &path), NATIVE_SERVICE);
            let other = if method == HttpMethod::Post {
                HttpMethod::Get
            } else {
                HttpMethod::Post
            };
            assert_eq!(upstream_service(other, &path), LEGACY_SERVICE);
            assert_eq!(upstream_service(HttpMethod::Delete, &path), LEGACY_SERVICE);
            // A list's single child can intentionally be the selected job route.
            // Two extra segments must never match any operation.
            assert_eq!(
                upstream_service(method, &format!("{path}/extra/extra")),
                LEGACY_SERVICE
            );
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
    fn every_frozen_canvas_operation_uses_native_routing() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-canvas-operations.json"
        ))
        .unwrap();
        let routes = contract["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 8);
        for route in routes {
            let method: HttpMethod = serde_json::from_value(route["method"].clone()).unwrap();
            let path = format!(
                "{}{}",
                contract["route_prefix"].as_str().unwrap(),
                route["path"].as_str().unwrap()
            )
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') {
                    "synthetic"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");
            assert_eq!(
                upstream_service(method, &path),
                NATIVE_SERVICE,
                "{method:?} {path}"
            );
        }
    }

    #[test]
    fn every_frozen_canvas_management_route_is_native() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-canvas-management.json"
        ))
        .expect("Canvas management contract");
        let routes = contract["scope"]["routes"]
            .as_array()
            .expect("Canvas management routes");

        assert_eq!(routes.len(), 31);
        for route in routes {
            let method: HttpMethod =
                serde_json::from_value(route["method"].clone()).expect("Canvas management method");
            let mut path = route["path"]
                .as_str()
                .expect("Canvas management path")
                .to_owned();
            for parameter in [
                "application_id",
                "token",
                "platform_id",
                "binding_id",
                "secret_id",
                "canvas_account_id",
                "provider_event_id",
            ] {
                path = path.replace(&format!("{{{parameter}}}"), "sample");
            }
            assert!(is_native_http(method, &path), "{method:?} {path}");
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
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/lti/platforms/platform-1/login",
            ),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/lti/platforms/platform-1/experience-login",
            ),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/lti/platforms/platform-1/launch",
            ),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/lti/platforms/platform-1/experience",
            ),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/lti/experience-sessions/exchange",
            ),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/platforms/platform-1/oauth/authorizations",
            ),
            (HttpMethod::Get, "/v1/integrations/canvas/oauth/callback"),
            (
                HttpMethod::Delete,
                "/v1/integrations/canvas/platforms/platform-1/oauth",
            ),
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
            (
                HttpMethod::Get,
                "/v1/integrations/canvas/platforms/platform-1/oauth/authorizations",
            ),
            (HttpMethod::Post, "/v1/integrations/canvas/oauth/callback"),
            (
                HttpMethod::Post,
                "/v1/integrations/canvas/platforms/platform-1/oauth",
            ),
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
