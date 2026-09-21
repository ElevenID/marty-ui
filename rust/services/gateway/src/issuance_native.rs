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

#[derive(Debug, Deserialize)]
struct Coverage {
    native_http: Vec<NativeHttpRoute>,
}

#[derive(Debug, Deserialize)]
struct NativeHttpRoute {
    method: HttpMethod,
    path: String,
    #[serde(default)]
    credential_lifecycle_behavior_contract: bool,
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

#[must_use]
pub fn is_native_http(method: HttpMethod, path: &str) -> bool {
    NATIVE_ROUTES
        .find(&GatewayRequest::new(method, path, 0))
        .is_ok_and(|matched| {
            !matched.route.tags.contains(CREDENTIAL_LIFECYCLE_TAG)
                || is_canonical_absolute_path(path)
        })
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
        for path in [
            "/v1/issuance/credentials",
            "/v1/issuance/credentials/credential-1",
            "/v1/issuance/credentials/credential-1/status/extra",
        ] {
            assert_eq!(upstream_service(HttpMethod::Get, path), LEGACY_SERVICE);
            assert_eq!(upstream_service(HttpMethod::Post, path), LEGACY_SERVICE);
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
            .filter(|route| !route.credential_lifecycle_behavior_contract)
            .collect::<Vec<_>>();
        assert_eq!(preexisting.len(), 96);

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
        ] {
            assert!(is_native_http(method, path), "{method:?} {path}");
        }

        for (method, path) in [
            (HttpMethod::Post, "/v1/issuance/notification"),
            (HttpMethod::Post, "/v1/issuance/deferred-credential"),
            (HttpMethod::Get, "/.well-known/jwks.json"),
            (HttpMethod::Get, "/v1/issued-credentials/credential-1"),
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
}
