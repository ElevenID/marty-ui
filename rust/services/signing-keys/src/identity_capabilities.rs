//! Public identity creation choices, using the actual custody selector.
//! This is configuration discovery, not a claim of provider health or publication.

use crate::{compat::select_identity_custody, domain::key_purposes, profiles};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub(crate) struct IdentityCapabilities {
    organization_id: String,
    managed_issuer_did_prefix: Option<String>,
    basis: &'static str,
    creation_options: Vec<IdentityOption>,
}

#[derive(Debug, Serialize)]
struct IdentityOption {
    key_purpose: &'static str,
    credential_format: &'static str,
    algorithm: &'static str,
}

fn requested_wire_format(purpose: &str, format: &str) -> Option<String> {
    profiles::custody_format(&profiles::CustodyFormatRequest {
        key_purpose: purpose.into(),
        credential_format: format.into(),
    })
    .ok()
    .map(|selection| selection.wire_format)
}

pub(crate) fn supports_tuple(purpose: &str, format: &str, algorithm: &str) -> bool {
    let format = format.to_ascii_uppercase();
    if !profiles::PROTOCOL_FORMATS.contains(&format.as_str()) {
        return false;
    }
    let Some(wire_format) = requested_wire_format(purpose, &format) else {
        return false;
    };
    key_purposes().iter().any(|entry| {
        entry.id == purpose
            && entry.credential_formats.contains(&wire_format.as_str())
            && entry.allowed_algorithms.contains(&algorithm)
    })
}

pub(crate) fn managed_did_prefix(public_domain: Option<&str>) -> Option<String> {
    let domain = public_domain?.trim();
    let url = reqwest::Url::parse(&format!("https://{domain}")).ok()?;
    if domain.is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    let authority = match url.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_owned(),
    };
    let authority = authority
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace(':', "%3A");
    Some(format!("did:web:{authority}:orgs:"))
}

pub(crate) fn project(
    organization_id: &str,
    registry: &Value,
    public_domain: Option<&str>,
) -> IdentityCapabilities {
    let prefix = managed_did_prefix(public_domain);
    let mut creation_options = Vec::new();
    if prefix.is_some() {
        for purpose in key_purposes() {
            for &format in profiles::PROTOCOL_FORMATS {
                let Some(wire_format) = requested_wire_format(purpose.id, format) else {
                    continue;
                };
                if !purpose.credential_formats.contains(&wire_format.as_str()) {
                    continue;
                }
                for &algorithm in purpose.allowed_algorithms {
                    // A placeholder is enough for this side-effect-free lookup:
                    // the real managed reference is derived when creating the DID.
                    if select_identity_custody(
                        registry,
                        format,
                        purpose.id,
                        algorithm,
                        "configuration-discovery-only",
                    )
                    .is_ok()
                    {
                        creation_options.push(IdentityOption {
                            key_purpose: purpose.id,
                            credential_format: format,
                            algorithm,
                        });
                    }
                }
            }
        }
    }
    IdentityCapabilities {
        organization_id: organization_id.into(),
        managed_issuer_did_prefix: prefix,
        basis: "configuration",
        creation_options,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry() -> Value {
        json!({"default_service_id":"private-provider", "services":[{
            "id":"private-provider", "key_reference":"private-key", "endpoint":"https://kms.internal",
            "auth_reference":"private-token", "credential_formats":["dc+sd-jwt"],
            "key_purposes":["vc_jwt_issuer"], "algorithms":["ES256"]
        }]})
    }

    #[test]
    fn options_follow_current_registry_without_exposing_custody() {
        let mut registry = registry();
        let value =
            serde_json::to_value(project("org-a", &registry, Some("issuer.example:8443"))).unwrap();
        assert_eq!(
            value,
            json!({
                "organization_id":"org-a", "managed_issuer_did_prefix":"did:web:issuer.example%3A8443:orgs:",
                "basis":"configuration", "creation_options":[{
                    "key_purpose":"vc_jwt_issuer", "credential_format":"SD_JWT_VC", "algorithm":"ES256"
                }]
            })
        );
        assert!(!value.to_string().contains("private-"));
        registry["services"][0]["algorithms"] = json!(["EdDSA"]);
        let changed =
            serde_json::to_value(project("org-a", &registry, Some("issuer.example"))).unwrap();
        assert_eq!(changed["creation_options"][0]["algorithm"], "EdDSA");
        assert_eq!(changed["creation_options"].as_array().unwrap().len(), 1);
        assert!(
            project("org-b", &json!({"services":[]}), Some("issuer.example"))
                .creation_options
                .is_empty()
        );
    }

    #[test]
    fn incompatible_default_is_not_bypassed_by_a_second_service() {
        let mut registry = registry();
        let mut second = registry["services"][0].clone();
        second["id"] = json!("another-provider");
        registry["services"][0]["algorithms"] = json!(["unsupported"]);
        registry["services"].as_array_mut().unwrap().push(second);
        assert!(project("org-a", &registry, Some("issuer.example"))
            .creation_options
            .is_empty());
    }

    #[test]
    fn request_identity_uses_canonical_purpose_format_with_protocol_and_algorithm_guards() {
        for format in ["SD_JWT_VC", "MDOC"] {
            assert!(supports_tuple("oid4vp_request_signing", format, "ES256"));
            assert!(!supports_tuple("oid4vp_request_signing", format, "EdDSA"));
        }
        assert!(!supports_tuple(
            "oid4vp_request_signing",
            "oauth-authz-req+jwt",
            "ES256"
        ));
        assert!(!supports_tuple("unknown-purpose", "SD_JWT_VC", "ES256"));
    }

    #[test]
    fn request_creation_options_use_the_same_custody_mapping_as_creation() {
        let mut registry = registry();
        registry["services"][0]["credential_formats"] = json!(["oauth-authz-req+jwt"]);
        registry["services"][0]["key_purposes"] = json!(["oid4vp_request_signing"]);
        let choices = project("org-a", &registry, Some("issuer.example"));
        for format in ["SD_JWT_VC", "MDOC"] {
            assert!(choices.creation_options.iter().any(|choice| {
                choice.key_purpose == "oid4vp_request_signing"
                    && choice.credential_format == format
                    && choice.algorithm == "ES256"
            }));
        }
        assert!(choices.creation_options.iter().all(|choice| {
            choice.key_purpose == "oid4vp_request_signing" && choice.algorithm == "ES256"
        }));
    }

    #[test]
    fn reserved_key_bindings_never_become_issuer_creation_options() {
        let mut registry = registry();
        registry["key_reference_purposes"] =
            json!({"private-provider":{"private-key":["lti_tool_signing"]}});
        assert!(project("org-a", &registry, Some("issuer.example"))
            .creation_options
            .is_empty());
        let error =
            select_identity_custody(&registry, "SD_JWT_VC", "vc_jwt_issuer", "ES256", "unused")
                .unwrap_err();
        assert!(!error.to_string().contains("private-"));
    }

    #[test]
    fn missing_or_invalid_public_authority_cannot_offer_creation() {
        for domain in [
            None,
            Some(""),
            Some("user:password@issuer.example"),
            Some("issuer.example/other"),
            Some("issuer.example?secret=bad"),
        ] {
            let value = project("org-a", &registry(), domain);
            assert!(value.managed_issuer_did_prefix.is_none());
            assert!(value.creation_options.is_empty());
        }
    }
}
