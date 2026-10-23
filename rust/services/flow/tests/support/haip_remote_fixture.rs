use marty_flow::HaipRemoteKey;
use serde_json::json;

pub const VERSION: &str = "0123456789abcdef0123456789abcdef";

// P-256 generator is public test data; no private session key is constructed.
pub fn key(organization_id: &str, flow_instance_id: &str) -> HaipRemoteKey {
    HaipRemoteKey {
        organization_id: organization_id.into(),
        flow_instance_id: flow_instance_id.into(),
        key_reference: format!(
            "didcomm/haip/keys/{organization_id}/{flow_instance_id}/versions/{VERSION}"
        ),
        public_jwk: json!({
            "kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc",
            "kid": format!("oid4vp-haip-{VERSION}"),
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        }),
    }
}
