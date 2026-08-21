#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpOperation {
    pub method: &'static str,
    pub path: &'static str,
}

pub const TRUST_PROFILE_HTTP_OPERATIONS: &[HttpOperation] = &[
    operation("POST", "/v1/organizations/{organization_id}/trust-profiles"),
    operation("GET", "/v1/organizations/{organization_id}/trust-profiles"),
    operation(
        "GET",
        "/v1/organizations/{organization_id}/trust-profiles/{profile_id}",
    ),
    operation(
        "PUT",
        "/v1/organizations/{organization_id}/trust-profiles/{profile_id}",
    ),
    operation("POST", "/v1/trust-profiles"),
    operation("GET", "/v1/trust-profiles"),
    operation("GET", "/v1/trust-profiles/{profile_id}"),
    operation("PATCH", "/v1/trust-profiles/{profile_id}"),
    operation("POST", "/v1/trust-profiles/{profile_id}/activate"),
    operation("POST", "/v1/trust-profiles/{profile_id}/suspend"),
    operation("DELETE", "/v1/trust-profiles/{profile_id}"),
    operation("POST", "/v1/trust-profiles/{profile_id}/registry-sync"),
    operation("POST", "/v1/trust-profiles/{profile_id}/issuers"),
    operation("GET", "/v1/trust-profiles/{profile_id}/issuers"),
    operation("GET", "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}"),
    operation(
        "PATCH",
        "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}",
    ),
    operation(
        "DELETE",
        "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}",
    ),
    operation("GET", "/internal/v1/trust-profiles/{profile_id}"),
    operation(
        "GET",
        "/internal/v1/resource-owners/trust-profiles/{profile_id}",
    ),
    operation(
        "GET",
        "/internal/v1/resource-owners/issuer-entities/{issuer_entity_id}",
    ),
    operation("GET", "/v1/trust-frameworks"),
    operation("GET", "/v1/trust-frameworks/{framework_id}"),
    operation("GET", "/v1/trust-registry/sync"),
    operation("GET", "/v1/trust-registry/csca"),
    operation("GET", "/v1/trust-registry/dsc"),
    operation("GET", "/v1/trust-registry/csca/{country_code}"),
    operation("GET", "/v1/trust-registry/status"),
    operation("POST", "/v1/issuer-entities"),
    operation("GET", "/v1/issuer-entities"),
    operation("GET", "/v1/issuer-entities/{issuer_entity_id}"),
    operation("PATCH", "/v1/issuer-entities/{issuer_entity_id}"),
    operation("DELETE", "/v1/issuer-entities/{issuer_entity_id}"),
];

const fn operation(method: &'static str, path: &'static str) -> HttpOperation {
    HttpOperation { method, path }
}
