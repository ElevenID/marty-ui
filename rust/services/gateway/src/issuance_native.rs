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

#[derive(Debug, Deserialize)]
struct Coverage {
    native_http: Vec<NativeHttpRoute>,
}

#[derive(Debug, Deserialize)]
struct NativeHttpRoute {
    method: HttpMethod,
    path: String,
}

static NATIVE_ROUTES: LazyLock<RouteTable> = LazyLock::new(|| {
    let coverage: Coverage = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("embedded issuance native coverage contract must be valid");
    let mut table = RouteTable::default();
    for (index, route) in coverage.native_http.into_iter().enumerate() {
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
                tags: BTreeSet::from(["native-migration".into()]),
            })
            .expect("issuance native coverage routes must be unique and valid");
    }
    table
});

#[must_use]
pub fn is_native_http(method: HttpMethod, path: &str) -> bool {
    NATIVE_ROUTES
        .find(&GatewayRequest::new(method, path, 0))
        .is_ok()
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
    fn coverage_is_the_fail_closed_native_allow_list() {
        for (method, path) in [
            (HttpMethod::Post, "/v1/issuance/credential"),
            (HttpMethod::Post, "/v1/issuance/token"),
            (HttpMethod::Post, "/v1/issuance/nonce"),
            (HttpMethod::Get, "/v1/issuance/offers/tx-1"),
            (HttpMethod::Get, "/v1/issuance/transactions/tx-1"),
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
        ] {
            assert!(is_native_http(method, path), "{method:?} {path}");
        }

        for (method, path) in [
            (HttpMethod::Post, "/v1/issuance/notification"),
            (HttpMethod::Post, "/v1/issuance/deferred-credential"),
            (HttpMethod::Get, "/.well-known/jwks.json"),
            (HttpMethod::Get, "/v1/issued-credentials/credential-1"),
            (HttpMethod::Get, "/v1/issuance/transactions"),
        ] {
            let expected = method == HttpMethod::Get && path == "/v1/issuance/transactions";
            assert_eq!(is_native_http(method, path), expected, "{method:?} {path}");
        }
    }
}
