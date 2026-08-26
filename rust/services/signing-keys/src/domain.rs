use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ServiceType {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub provider: &'static str,
    pub protocol: &'static str,
    pub category: &'static str,
    pub auth_modes: &'static [&'static str],
    pub connection_fields: &'static [&'static str],
    pub key_reference_label: &'static str,
    pub supports_inventory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyPurpose {
    pub id: &'static str,
    pub allowed_algorithms: &'static [&'static str],
    pub credential_formats: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderCapabilities {
    pub supported_algorithms: &'static [&'static str],
    pub signature_encoding: &'static str,
    pub public_key_export: bool,
    pub hardware_attestation: bool,
    pub key_import: bool,
    pub key_create: bool,
    pub key_delete: bool,
    pub key_list: bool,
    pub rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceCapability {
    pub service_type_id: &'static str,
    pub label: &'static str,
    pub capabilities: ProviderCapabilities,
}

const PURPOSE_ALL_ALGORITHMS: &[&str] = &["ES256", "ES384", "EdDSA", "RS256"];
const CSCA_ALGORITHMS: &[&str] = &["ES256", "ES384", "ES512", "EdDSA", "RS256"];
const P521_PROVIDER_ALGORITHMS: &[&str] = &["ES256", "ES384", "ES512", "RS256", "EdDSA"];
const GCP_ALGORITHMS: &[&str] = &["ES256", "ES384", "RS256", "EdDSA"];
const CUSTOM_TRANSIT_ALGORITHMS: &[&str] = &["ES256", "ES384", "RS256", "EdDSA"];
const EC_AND_EDDSA: &[&str] = &["ES256", "ES384", "EdDSA"];
const ES256_AND_EDDSA: &[&str] = &["ES256", "EdDSA"];
const CLOUD_RSA_EC: &[&str] = &["ES256", "ES384", "ES512", "RS256"];

const SERVICE_TYPES: &[ServiceType] = &[
    ServiceType {
        id: "openbao-transit",
        label: "OpenBao Transit",
        description: "Register an OpenBao transit service that exposes signing keys remotely.",
        provider: "openbao",
        protocol: "vault-transit",
        category: "service-hsm",
        auth_modes: &["service_token", "token", "approle", "mtls"],
        connection_fields: &["endpoint", "mount", "namespace"],
        key_reference_label: "Transit key name",
        supports_inventory: true,
    },
    ServiceType {
        id: "hashicorp-vault-transit",
        label: "HashiCorp Vault Transit",
        description: "Use Vault Transit as the signing backend for issuance keys.",
        provider: "hashicorp-vault",
        protocol: "vault-transit",
        category: "service-hsm",
        auth_modes: &["token", "approle", "mtls"],
        connection_fields: &["endpoint", "mount", "namespace"],
        key_reference_label: "Transit key name",
        supports_inventory: true,
    },
    ServiceType {
        id: "aws-kms",
        label: "AWS KMS",
        description: "Register a customer-managed AWS KMS key for remote signing.",
        provider: "aws",
        protocol: "aws-kms",
        category: "cloud-kms",
        auth_modes: &["iam_role", "access_key", "assume_role"],
        connection_fields: &["region"],
        key_reference_label: "Key ARN",
        supports_inventory: false,
    },
    ServiceType {
        id: "azure-key-vault",
        label: "Azure Key Vault",
        description: "Register an Azure Key Vault key as a signing source.",
        provider: "azure",
        protocol: "azure-key-vault",
        category: "cloud-kms",
        auth_modes: &["managed_identity", "client_secret", "certificate"],
        connection_fields: &["endpoint"],
        key_reference_label: "Key identifier",
        supports_inventory: false,
    },
    ServiceType {
        id: "gcp-cloud-kms",
        label: "Google Cloud KMS",
        description: "Register a Google Cloud KMS crypto key version.",
        provider: "gcp",
        protocol: "gcp-kms",
        category: "cloud-kms",
        auth_modes: &["workload_identity", "service_account"],
        connection_fields: &["region"],
        key_reference_label: "Crypto key resource",
        supports_inventory: false,
    },
    ServiceType {
        id: "custom-transit-compatible",
        label: "Custom Transit-Compatible Service",
        description:
            "Any service that implements the transit-compatible signing protocol Marty supports.",
        provider: "custom",
        protocol: "vault-transit-compatible",
        category: "custom",
        auth_modes: &["token", "mtls", "api_key", "custom"],
        connection_fields: &["endpoint", "mount", "namespace"],
        key_reference_label: "Key reference",
        supports_inventory: false,
    },
];

pub fn service_types() -> &'static [ServiceType] {
    SERVICE_TYPES
}

pub fn service_type(id: &str) -> ServiceType {
    SERVICE_TYPES
        .iter()
        .copied()
        .find(|service_type| service_type.id == id)
        .unwrap_or_else(|| {
            SERVICE_TYPES
                .iter()
                .copied()
                .find(|service_type| service_type.id == "custom-transit-compatible")
                .expect("custom service type")
        })
}

pub fn key_purposes() -> Vec<KeyPurpose> {
    vec![
        KeyPurpose {
            id: "vc_jwt_issuer",
            allowed_algorithms: PURPOSE_ALL_ALGORITHMS,
            credential_formats: &["jwt_vc_json", "dc+sd-jwt", "ldp_vc"],
        },
        KeyPurpose {
            id: "mdoc_dsc",
            allowed_algorithms: EC_AND_EDDSA,
            credential_formats: &["mso_mdoc", "zk_mdoc"],
        },
        KeyPurpose {
            id: "x509_doc_signer",
            allowed_algorithms: PURPOSE_ALL_ALGORITHMS,
            credential_formats: &["mso_mdoc", "zk_mdoc"],
        },
        KeyPurpose {
            id: "holder_binding",
            allowed_algorithms: ES256_AND_EDDSA,
            credential_formats: &["mso_mdoc", "zk_mdoc", "dc+sd-jwt"],
        },
        KeyPurpose {
            id: "presentation_signing",
            allowed_algorithms: ES256_AND_EDDSA,
            credential_formats: &["jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "zk_mdoc"],
        },
        KeyPurpose {
            id: "oid4vp_request_signing",
            allowed_algorithms: &["ES256"],
            credential_formats: &["oauth-authz-req+jwt"],
        },
        KeyPurpose {
            id: "vdsnc_signing",
            allowed_algorithms: EC_AND_EDDSA,
            credential_formats: &["mso_mdoc"],
        },
        KeyPurpose {
            id: "csca",
            allowed_algorithms: CSCA_ALGORITHMS,
            credential_formats: &["mso_mdoc", "zk_mdoc"],
        },
        KeyPurpose {
            id: "jwks_signing",
            allowed_algorithms: PURPOSE_ALL_ALGORITHMS,
            credential_formats: &["jwt_vc_json", "dc+sd-jwt"],
        },
        KeyPurpose {
            id: "lti_tool_signing",
            allowed_algorithms: &["RS256"],
            credential_formats: &["lti_tool_jwt"],
        },
    ]
}

fn capabilities(
    algorithms: &'static [&'static str],
    signature_encoding: &'static str,
    hardware_attestation: bool,
    key_import: bool,
    key_delete: bool,
    key_list: bool,
) -> ProviderCapabilities {
    ProviderCapabilities {
        supported_algorithms: algorithms,
        signature_encoding,
        public_key_export: true,
        hardware_attestation,
        key_import,
        key_create: true,
        key_delete,
        key_list,
        rotation: true,
    }
}

pub fn service_capabilities() -> Vec<ServiceCapability> {
    vec![
        ServiceCapability {
            service_type_id: "openbao-transit",
            label: "OpenBao Transit",
            capabilities: capabilities(P521_PROVIDER_ALGORITHMS, "der", false, false, true, true),
        },
        ServiceCapability {
            service_type_id: "hashicorp-vault-transit",
            label: "HashiCorp Vault Transit",
            capabilities: capabilities(P521_PROVIDER_ALGORITHMS, "der", false, false, true, true),
        },
        ServiceCapability {
            service_type_id: "aws-kms",
            label: "AWS KMS",
            capabilities: capabilities(CLOUD_RSA_EC, "der", true, true, false, false),
        },
        ServiceCapability {
            service_type_id: "azure-key-vault",
            label: "Azure Key Vault",
            capabilities: capabilities(CLOUD_RSA_EC, "der", true, true, true, true),
        },
        ServiceCapability {
            service_type_id: "gcp-cloud-kms",
            label: "Google Cloud KMS",
            capabilities: capabilities(GCP_ALGORITHMS, "der", true, true, false, true),
        },
        ServiceCapability {
            service_type_id: "custom-transit-compatible",
            label: "Custom Transit-Compatible Service",
            capabilities: ProviderCapabilities {
                supported_algorithms: CUSTOM_TRANSIT_ALGORITHMS,
                signature_encoding: "der",
                public_key_export: false,
                hardware_attestation: false,
                key_import: false,
                key_create: false,
                key_delete: false,
                key_list: false,
                rotation: false,
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_purpose_and_provider_is_unique() {
        let purposes = key_purposes();
        let mut purpose_ids = purposes.iter().map(|value| value.id).collect::<Vec<_>>();
        purpose_ids.sort_unstable();
        purpose_ids.dedup();
        assert_eq!(purpose_ids.len(), purposes.len());

        let providers = service_capabilities();
        let mut provider_ids = providers
            .iter()
            .map(|value| value.service_type_id)
            .collect::<Vec<_>>();
        provider_ids.sort_unstable();
        provider_ids.dedup();
        assert_eq!(provider_ids.len(), providers.len());
    }

    #[test]
    fn transit_ecdsa_signatures_are_provider_native_der() {
        for provider in service_capabilities().into_iter().filter(|value| {
            value.service_type_id.contains("transit") && value.capabilities.public_key_export
        }) {
            assert_eq!(provider.capabilities.signature_encoding, "der");
        }
    }
}
