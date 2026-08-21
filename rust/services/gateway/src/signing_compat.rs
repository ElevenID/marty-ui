//! Classification for the legacy service-to-service signing-key surface.

use mmf_platform::HttpMethod;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigningCompatibilityOperation {
    FlowEnvelopeUnwrap,
    FlowEnvelopeWrap,
    IssuerContext,
    IssuerDidSign,
    CreateProfile,
    ListProfiles,
    ProfileIdentity { profile_id: String },
    GetProfile { profile_id: String },
    UpdateProfile { profile_id: String },
    DeleteProfile { profile_id: String },
    ProfileCertificate { profile_id: String },
    ProfilePublicIdentity { profile_id: String },
    ResolveIssuerDid,
    ServiceSign { service_id: String },
}

#[must_use]
pub fn operation(method: HttpMethod, path: &str) -> Option<SigningCompatibilityOperation> {
    let relative = path.strip_prefix("/internal/signing-keys/")?;
    match (method, relative) {
        (HttpMethod::Post, "flow-key-envelopes/unwrap") => {
            Some(SigningCompatibilityOperation::FlowEnvelopeUnwrap)
        }
        (HttpMethod::Post, "flow-key-envelopes/wrap") => {
            Some(SigningCompatibilityOperation::FlowEnvelopeWrap)
        }
        (HttpMethod::Get, "issuer-context") => Some(SigningCompatibilityOperation::IssuerContext),
        (HttpMethod::Post, "issuer-dids/sign") => {
            Some(SigningCompatibilityOperation::IssuerDidSign)
        }
        (HttpMethod::Post, "issuer-profiles") => Some(SigningCompatibilityOperation::CreateProfile),
        (HttpMethod::Get, "issuer-profiles") => Some(SigningCompatibilityOperation::ListProfiles),
        (HttpMethod::Get, "resolve-issuer-did") => {
            Some(SigningCompatibilityOperation::ResolveIssuerDid)
        }
        _ => parameterized(method, relative),
    }
}

fn parameterized(method: HttpMethod, relative: &str) -> Option<SigningCompatibilityOperation> {
    if method == HttpMethod::Post {
        if let Some(service_id) = relative
            .strip_prefix("services/")
            .and_then(|value| value.strip_suffix("/sign"))
            .filter(|value| !value.is_empty() && !value.contains('/'))
        {
            return Some(SigningCompatibilityOperation::ServiceSign {
                service_id: service_id.into(),
            });
        }
    }
    let profile = relative.strip_prefix("issuer-profiles/")?;
    if let Some(profile_id) = profile.strip_suffix("/identity") {
        return (method == HttpMethod::Get && valid_segment(profile_id)).then(|| {
            SigningCompatibilityOperation::ProfileIdentity {
                profile_id: profile_id.into(),
            }
        });
    }
    if let Some(profile_id) = profile.strip_suffix("/certificate") {
        return (method == HttpMethod::Put && valid_segment(profile_id)).then(|| {
            SigningCompatibilityOperation::ProfileCertificate {
                profile_id: profile_id.into(),
            }
        });
    }
    if let Some(profile_id) = profile.strip_suffix("/public-identity") {
        return (method == HttpMethod::Get && valid_segment(profile_id)).then(|| {
            SigningCompatibilityOperation::ProfilePublicIdentity {
                profile_id: profile_id.into(),
            }
        });
    }
    if !valid_segment(profile) {
        return None;
    }
    match method {
        HttpMethod::Get => Some(SigningCompatibilityOperation::GetProfile {
            profile_id: profile.into(),
        }),
        HttpMethod::Patch => Some(SigningCompatibilityOperation::UpdateProfile {
            profile_id: profile.into(),
        }),
        HttpMethod::Delete => Some(SigningCompatibilityOperation::DeleteProfile {
            profile_id: profile.into(),
        }),
        _ => None,
    }
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty() && !value.contains('/')
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u8,
        routes: Vec<RouteCase>,
    }

    #[derive(Deserialize)]
    struct RouteCase {
        method: HttpMethod,
        path: String,
        example_path: Option<String>,
        operation: String,
    }

    #[test]
    fn shared_internal_signing_route_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-internal-signing-behavior.json"
        ))
        .expect("internal signing contract");
        assert_eq!(contract.schema_version, 1);
        assert_eq!(contract.routes.len(), 14);
        for case in contract.routes {
            let path = case.example_path.as_deref().unwrap_or(&case.path);
            let actual = operation(case.method, path).expect("classified route");
            assert_eq!(operation_name(&actual), case.operation);
        }
    }

    fn operation_name(operation: &SigningCompatibilityOperation) -> &'static str {
        match operation {
            SigningCompatibilityOperation::FlowEnvelopeUnwrap => "flow_envelope_unwrap",
            SigningCompatibilityOperation::FlowEnvelopeWrap => "flow_envelope_wrap",
            SigningCompatibilityOperation::IssuerContext => "issuer_context",
            SigningCompatibilityOperation::IssuerDidSign => "issuer_did_sign",
            SigningCompatibilityOperation::CreateProfile => "create_profile",
            SigningCompatibilityOperation::ListProfiles => "list_profiles",
            SigningCompatibilityOperation::ProfileIdentity { .. } => "profile_identity",
            SigningCompatibilityOperation::GetProfile { .. } => "get_profile",
            SigningCompatibilityOperation::UpdateProfile { .. } => "update_profile",
            SigningCompatibilityOperation::DeleteProfile { .. } => "delete_profile",
            SigningCompatibilityOperation::ProfileCertificate { .. } => "profile_certificate",
            SigningCompatibilityOperation::ProfilePublicIdentity { .. } => {
                "profile_public_identity"
            }
            SigningCompatibilityOperation::ResolveIssuerDid => "resolve_issuer_did",
            SigningCompatibilityOperation::ServiceSign { .. } => "service_sign",
        }
    }
}
