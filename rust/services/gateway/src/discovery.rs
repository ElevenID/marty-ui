//! Gateway-owned public discovery documents.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::middleware::MIP_VERSION;

const SURFACE_FIELDS: &[&str] = &[
    "rel",
    "path_template",
    "org_scoped_path",
    "method",
    "auth_required",
    "discoverable",
    "response_schema_ref",
    "standard_ref",
];
const WALTID_FORMATS: &[&str] = &[
    "jwt_vc_json",
    "jwt_vc_json-ld",
    "ldp_vc",
    "mso_mdoc",
    "jwt_vc",
];

static INSERTION_DISCOVERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/\.well-known/(openid-credential-issuer|oauth-authorization-server)/org/([^/]+)(?:/(waltid|credential-manager|apple-wallet))?$")
        .expect("static insertion discovery regex")
});
static APPENDED_DISCOVERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/org/([^/]+)(?:/(waltid|credential-manager|apple-wallet))?/\.well-known/(openid-credential-issuer|oauth-authorization-server)$")
        .expect("static appended discovery regex")
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WellKnownProxyPlan {
    pub upstream_path: String,
    pub variant: Option<String>,
    pub normalize_issuer: bool,
}

#[must_use]
pub fn well_known_proxy_plan(path: &str) -> Option<WellKnownProxyPlan> {
    let root = match path {
        "/.well-known/openid-credential-issuer" | "/.well-known//openid-credential-issuer" => {
            Some(("/.well-known/openid-credential-issuer".to_owned(), true))
        }
        "/.well-known/oauth-authorization-server" => {
            Some(("/.well-known/oauth-authorization-server".to_owned(), false))
        }
        "/.well-known/jwks.json" => Some(("/.well-known/jwks.json".to_owned(), false)),
        _ => None,
    };
    if let Some((upstream_path, normalize_issuer)) = root {
        return Some(WellKnownProxyPlan {
            upstream_path,
            variant: None,
            normalize_issuer,
        });
    }
    if let Some(metadata_path) = path.strip_prefix("/credentials/") {
        let metadata_path = metadata_path.trim_matches('/');
        if !metadata_path.is_empty() {
            return Some(WellKnownProxyPlan {
                upstream_path: format!("/credentials/{metadata_path}"),
                variant: None,
                normalize_issuer: false,
            });
        }
    }
    if let Some(captures) = INSERTION_DISCOVERY.captures(path) {
        return discovery_plan(
            captures.get(1)?.as_str(),
            captures.get(2)?.as_str(),
            captures.get(3).map(|value| value.as_str()),
        );
    }
    let captures = APPENDED_DISCOVERY.captures(path)?;
    discovery_plan(
        captures.get(3)?.as_str(),
        captures.get(1)?.as_str(),
        captures.get(2).map(|value| value.as_str()),
    )
}

fn discovery_plan(
    kind: &str,
    organization_id: &str,
    variant: Option<&str>,
) -> Option<WellKnownProxyPlan> {
    let normalize_issuer = kind == "openid-credential-issuer";
    let upstream_variant = variant.filter(|value| *value != "waltid");
    let suffix = upstream_variant.map_or_else(String::new, |value| format!("/{value}"));
    Some(WellKnownProxyPlan {
        upstream_path: format!("/.well-known/{kind}/org/{organization_id}{suffix}"),
        variant: (normalize_issuer && variant == Some("waltid")).then(|| "waltid".into()),
        normalize_issuer,
    })
}

#[must_use]
pub fn normalize_issuer_metadata(metadata: &Value, variant: Option<&str>) -> Value {
    let Some(object) = metadata.as_object() else {
        return metadata.clone();
    };
    let mut normalized = if variant == Some("waltid") {
        normalize_waltid(object)
    } else {
        normalize_default(object)
    };
    let issuer_name = normalized.remove("issuer_display_name");
    if !normalized.contains_key("display") {
        if let Some(name) = issuer_name.filter(|value| !value.is_null()) {
            let name = name
                .as_str()
                .map_or_else(|| name.to_string(), str::to_owned);
            normalized.insert("display".into(), json!([{"name": name, "locale": "en-US"}]));
        }
    }
    Value::Object(normalized)
}

fn normalize_default(metadata: &Map<String, Value>) -> Map<String, Value> {
    let mut normalized = metadata.clone();
    let Some(configurations) = metadata
        .get("credential_configurations_supported")
        .and_then(Value::as_object)
    else {
        return normalized;
    };
    let mut changed = false;
    let mut output = Map::new();
    for (id, raw) in configurations {
        let Some(config) = raw.as_object() else {
            output.insert(id.clone(), raw.clone());
            continue;
        };
        let mut config = config.clone();
        let subject_present = config
            .get("credential_definition")
            .and_then(Value::as_object)
            .and_then(|definition| definition.get("credentialSubject"))
            .and_then(Value::as_object)
            .is_some_and(|subject| !subject.is_empty());
        if subject_present {
            if let Some(Value::Object(definition)) = config.get_mut("credential_definition") {
                definition.remove("credentialSubject");
            }
            let mut metadata_block = config
                .get("credential_metadata")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            metadata_block.remove("claims");
            if !metadata_block.contains_key("display") {
                if let Some(display) = config.get("display") {
                    metadata_block.insert("display".into(), display.clone());
                }
            }
            config.insert("credential_metadata".into(), Value::Object(metadata_block));
            changed = true;
        }
        output.insert(id.clone(), Value::Object(config));
    }
    if changed {
        normalized.insert(
            "credential_configurations_supported".into(),
            Value::Object(output),
        );
    }
    normalized
}

fn normalize_waltid(metadata: &Map<String, Value>) -> Map<String, Value> {
    let Some(configurations) = metadata
        .get("credential_configurations_supported")
        .and_then(Value::as_object)
    else {
        return metadata.clone();
    };
    let mut normalized = metadata
        .iter()
        .filter(|(key, _)| key.as_str() != "credential_configurations_supported")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    if let Some(issuer) = metadata.get("credential_issuer").and_then(Value::as_str) {
        let issuer = issuer.trim_end_matches('/');
        normalized.insert(
            "credential_issuer".into(),
            Value::String(if issuer.ends_with("/waltid") {
                issuer.into()
            } else {
                format!("{issuer}/waltid")
            }),
        );
    }
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for (id, raw) in configurations {
        let Some(config) = raw.as_object() else {
            continue;
        };
        let format = config
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("jwt_vc_json");
        if !WALTID_FORMATS.contains(&format) {
            continue;
        }
        let ids = if id.contains('#') {
            vec![id.clone()]
        } else {
            vec![id.clone(), format!("{id}#sd-jwt")]
        };
        for supported_id in ids {
            if !seen.insert(supported_id.clone()) {
                continue;
            }
            let mut entry = Map::from_iter([
                ("id".into(), Value::String(supported_id)),
                ("format".into(), Value::String(format.into())),
            ]);
            if let Some(types) = config
                .get("credential_definition")
                .and_then(Value::as_object)
                .and_then(|definition| definition.get("type"))
            {
                entry.insert(
                    "types".into(),
                    if types.is_string() {
                        Value::Array(vec![types.clone()])
                    } else {
                        types.clone()
                    },
                );
            }
            for field in ["display", "cryptographic_binding_methods_supported"] {
                if config.get(field).is_some_and(Value::is_array) {
                    entry.insert(field.into(), config[field].clone());
                }
            }
            let suites = config
                .get("cryptographic_suites_supported")
                .or_else(|| config.get("credential_signing_alg_values_supported"));
            if suites.is_some_and(Value::is_array) {
                entry.insert(
                    "cryptographic_suites_supported".into(),
                    suites.expect("checked above").clone(),
                );
            }
            entries.push(Value::Object(entry));
        }
    }
    normalized.insert(
        "credentials_supported".into(),
        Value::Array(entries.clone()),
    );
    normalized.insert(
        "credential_configurations_supported".into(),
        Value::Object(
            entries
                .into_iter()
                .filter_map(|entry| {
                    let id = entry.get("id")?.as_str()?.to_owned();
                    Some((id, entry))
                })
                .collect(),
        ),
    );
    normalized
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseIdentity {
    pub release_version: String,
    pub stack_version: String,
    pub marty_ui_sha: String,
    #[serde(default)]
    pub image_digests: BTreeMap<String, String>,
}

impl Default for ReleaseIdentity {
    fn default() -> Self {
        Self {
            release_version: "development".into(),
            stack_version: "development".into(),
            marty_ui_sha: "unknown".into(),
            image_digests: BTreeMap::new(),
        }
    }
}

#[must_use]
pub fn release_document(identity: &ReleaseIdentity) -> Value {
    json!({
        "component": "services",
        "release_version": identity.release_version,
        "deployment_release_marker": identity.release_version,
        "stack_version": identity.stack_version,
        "mip_version": MIP_VERSION,
        "marty_ui_sha": identity.marty_ui_sha,
        "image_digests": identity.image_digests,
    })
}

#[must_use]
pub fn openid_configuration(base_url: &str) -> Value {
    let base = base_url.trim_end_matches('/');
    json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/v1/issuance/authorize"),
        "token_endpoint": format!("{base}/v1/issuance/token"),
        "pushed_authorization_request_endpoint": format!("{base}/v1/issuance/par"),
        "credential_endpoint": format!("{base}/v1/issuance/credential"),
        "nonce_endpoint": format!("{base}/v1/issuance/nonce"),
        "deferred_credential_endpoint": format!("{base}/v1/issuance/deferred-credential"),
        "notification_endpoint": format!("{base}/v1/issuance/notification"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public", "pairwise"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
        "id_token_signing_alg_values_supported": ["EdDSA", "ES256"],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ],
        "token_endpoint_auth_methods_supported": ["none"]
    })
}

#[must_use]
pub fn mip_configuration(base_url: &str, profiles: &[Value]) -> Value {
    let base = base_url.trim_end_matches('/');
    let mut active = profiles
        .iter()
        .filter_map(project_profile)
        .collect::<Vec<_>>();
    active.sort_by(|left, right| {
        left.get("compliance_code")
            .and_then(Value::as_str)
            .cmp(&right.get("compliance_code").and_then(Value::as_str))
    });
    let codes = active
        .iter()
        .filter_map(|profile| profile.get("compliance_code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    json!({
        "mip_version": MIP_VERSION,
        "issuer": base,
        "mip_configuration_endpoint": format!("{base}/.well-known/mip-configuration"),
        "supported_versions": [MIP_VERSION],
        "implementation_classes": ["ISSUER", "VERIFIER", "REGISTRY"],
        "issuance_endpoint": format!("{base}/v1/issuance"),
        "openid_credential_issuer": format!("{base}/.well-known/openid-credential-issuer"),
        "presentation_endpoint": format!("{base}/v1/flows/verify"),
        "token_endpoint": format!("{base}/v1/issuance/token"),
        "authorization_endpoint": format!("{base}/v1/issuance/authorize"),
        "supported_credential_formats": ["MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD"],
        "supported_compliance_profiles": codes,
        "active_compliance_profiles": active,
        "supported_flow_types": [
            "oid4vci_pre_authorized",
            "oid4vci_authorization_code",
            "application_approval_issuance",
            "credential_renewal",
            "credential_revocation",
            "oid4vp_presentation",
            "mdl_presentation"
        ],
        "supported_signing_algorithms": ["ES256", "ES384", "EdDSA"],
        "proximity_supported": false,
        "scim_endpoint": format!("{base}/v1/organizations/{{org_id}}/scim/v2"),
        "revocation_endpoint": format!("{base}/v1/issuance/status-list"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "service_documentation": format!("{base}/docs")
    })
}

fn project_profile(profile: &Value) -> Option<Value> {
    let profile = profile.as_object()?;
    let code = profile
        .get("compliance_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let api_surface = profile
        .get("api_surface")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(project_surface)
        .collect::<Vec<_>>();
    let mut projected = Map::from_iter([
        ("compliance_code".into(), Value::String(code.into())),
        ("api_surface".into(), Value::Array(api_surface)),
    ]);
    for field in ["credential_format", "issuance_protocol"] {
        if let Some(value) = profile
            .get(field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            projected.insert(field.into(), Value::String(value.into()));
        }
    }
    Some(Value::Object(projected))
}

fn project_surface(surface: &Value) -> Option<Value> {
    let surface = surface.as_object()?;
    if surface.get("discoverable") == Some(&Value::Bool(false)) {
        return None;
    }
    let mut projected = Map::new();
    for field in SURFACE_FIELDS {
        if let Some(value) = surface.get(*field) {
            projected.insert((*field).into(), value.clone());
        }
    }
    projected.entry("discoverable").or_insert(Value::Bool(true));
    Some(Value::Object(projected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        base_url: String,
        openid_configuration: Value,
        compliance_profiles: Vec<Value>,
        mip_configuration: Value,
        release: ReleaseCase,
        well_known_plans: Vec<PlanCase>,
        issuer_metadata: MetadataCase,
    }

    #[derive(Deserialize)]
    struct ReleaseCase {
        input: ReleaseIdentity,
        expected: Value,
    }

    #[derive(Deserialize)]
    struct PlanCase {
        path: String,
        upstream_path: String,
        variant: Option<String>,
        normalize_issuer: bool,
    }

    #[derive(Deserialize)]
    struct MetadataCase {
        input: Value,
        default_expected: Value,
        waltid_expected: Value,
    }

    #[test]
    fn language_neutral_gateway_discovery_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-discovery-behavior.json"
        ))
        .expect("valid discovery contract");
        assert_eq!(contract.schema_version, 1);
        assert_eq!(
            openid_configuration(&contract.base_url),
            contract.openid_configuration
        );
        assert_eq!(
            mip_configuration(&contract.base_url, &contract.compliance_profiles),
            contract.mip_configuration
        );
        assert_eq!(
            release_document(&contract.release.input),
            contract.release.expected
        );
        for case in contract.well_known_plans {
            assert_eq!(
                well_known_proxy_plan(&case.path),
                Some(WellKnownProxyPlan {
                    upstream_path: case.upstream_path,
                    variant: case.variant,
                    normalize_issuer: case.normalize_issuer,
                })
            );
        }
        assert_eq!(
            normalize_issuer_metadata(&contract.issuer_metadata.input, None),
            contract.issuer_metadata.default_expected
        );
        assert_eq!(
            normalize_issuer_metadata(&contract.issuer_metadata.input, Some("waltid")),
            contract.issuer_metadata.waltid_expected
        );
    }
}
