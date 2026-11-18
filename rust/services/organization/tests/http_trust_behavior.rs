use std::collections::BTreeMap;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use marty_organization::{authenticate_forwarded_http_request, ForwardedPrincipal, HttpTrustError};
use mmf_security::ServiceTokenAuthenticator;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    service_token: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    headers: BTreeMap<String, String>,
    expected: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-http-trust-behavior.json"
    )))
    .expect("HTTP trust fixture must be valid JSON")
}

fn result_name(result: &Result<ForwardedPrincipal, HttpTrustError>) -> &'static str {
    match result {
        Ok(ForwardedPrincipal::User { .. }) => "user",
        Ok(ForwardedPrincipal::ApiKey { .. }) => "api_key",
        Err(HttpTrustError::ServiceAuthenticationRequired) => "service_authentication_required",
        Err(HttpTrustError::UserAuthenticationRequired) => "user_authentication_required",
        Err(HttpTrustError::InvalidApiKeyContext) => "invalid_api_key_context",
    }
}

#[test]
fn gateway_credential_and_forwarded_identity_fail_closed() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let authenticator = ServiceTokenAuthenticator::new(Some(fixture.service_token), true)
        .expect("configured service token");
    for case in fixture.cases {
        let mut headers = HeaderMap::new();
        for (name, value) in case.headers {
            headers.insert(
                HeaderName::try_from(name).expect("header name"),
                HeaderValue::try_from(value).expect("header value"),
            );
        }
        let result = authenticate_forwarded_http_request(&headers, &authenticator);
        assert_eq!(result_name(&result), case.expected, "{}", case.name);
    }
}
