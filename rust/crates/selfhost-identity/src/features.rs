//! Fixed, optional identities for the native feature profile. These are not
//! additions to SELFHOST_ROLES and cannot change the baseline producer output.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "elevenid.native-feature-identities/v1";
pub const METADATA: &str = "feature_identity_metadata";
pub const WORKLOAD_CA: &str = "feature_workload_ca";
pub const CLIENT_CA_DER: &str = "feature_workload_client_ca_der";
pub const RENEWAL_ROLE_ID: &str = "feature_identity_renewal_role_id";
pub const RENEWAL_SECRET_ID: &str = "feature_identity_renewal_secret_id";
pub const RENEWAL_AUTH_MOUNT: &str = "native-feature-renewal";
pub const RENEWAL_AUTH_ROLE: &str = "identity-renewer";
pub const RENEWAL_LOGIN_MAX_SECONDS: u64 = 600;
pub const RENEWAL_POLICY: &str = "native-feature-identity-renewal";
pub const LEAF_ROLE: &str = "native-feature-identity-leaf";
pub const PKI_MOUNT: &str = "workload-pki";
pub const MAX_LEAF_SECONDS: u64 = 28_800;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Provision,
    Renew,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub schema: String,
    pub installation_id: String,
    pub feature_profile_sha256: String,
    pub operation: Operation,
    pub wallet_governance: bool,
    pub public_verification: bool,
    pub delegated_use: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub role: &'static str,
    pub key: &'static str,
    pub certificate: &'static str,
    pub token: &'static str,
    pub common_name: &'static str,
    pub uri: &'static str,
    pub server: bool,
    pub client: bool,
}

pub const TRUST_PROFILE: Identity = Identity {
    role: "native-feature-trust-profile-server",
    key: "feature-workload-tls-trust-profile-server",
    certificate: "feature_trust_profile_server_cert",
    token: "feature_trust_profile_tls_kms_token",
    common_name: "trust-profile",
    uri: "",
    server: true,
    client: false,
};
pub const DEPLOYMENT_PROFILE: Identity = Identity {
    role: "native-feature-deployment-profile-server",
    key: "feature-workload-tls-deployment-profile-server",
    certificate: "feature_deployment_profile_server_cert",
    token: "feature_deployment_profile_tls_kms_token",
    common_name: "deployment-profile",
    uri: "",
    server: true,
    client: false,
};
pub const DELEGATED_USE_SERVER: Identity = Identity {
    role: "native-feature-delegated-use-server",
    key: "feature-workload-tls-delegated-use-server",
    certificate: "feature_delegated_use_server_cert",
    token: "feature_delegated_use_server_tls_kms_token",
    common_name: "delegated-use",
    uri: "",
    server: true,
    client: false,
};
pub const DELEGATED_USE_CLIENT: Identity = Identity {
    role: "native-feature-delegated-use-client",
    key: "feature-workload-tls-delegated-use-client",
    certificate: "feature_delegated_use_client_cert",
    token: "feature_delegated_use_client_tls_kms_token",
    common_name: "delegated-use",
    uri: "spiffe://marty.internal/service/delegated-use",
    server: false,
    client: true,
};
/// This identity has no machine principal or delegated authority until an owner
/// registers the actual key/agent and binds this exact leaf fingerprint.
pub const NATIVE_CALLER: Identity = Identity {
    role: "native-feature-agent-client",
    key: "feature-workload-tls-native-agent-client",
    certificate: "feature_native_agent_client_cert",
    token: "feature_native_agent_client_tls_kms_token",
    common_name: "native-feature-agent",
    uri: "spiffe://marty.internal/native-feature-agent",
    server: false,
    client: true,
};

pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Selection {
    pub fn validate(&self) -> Result<(), &'static str> {
        let uuid = &self.installation_id;
        let valid_uuid = uuid.len() == 36
            && uuid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            && uuid.bytes().any(|b| b != b'0' && b != b'-');
        if self.schema != SCHEMA
            || !valid_uuid
            || !hash(&self.feature_profile_sha256)
            || !(self.wallet_governance || self.public_verification || self.delegated_use)
        {
            return Err("invalid native feature identity selection");
        }
        Ok(())
    }

    pub fn identities(&self) -> Vec<Identity> {
        let mut roles = Vec::new();
        if self.wallet_governance || self.delegated_use {
            roles.push(TRUST_PROFILE);
        }
        if self.delegated_use {
            roles.extend([
                DEPLOYMENT_PROFILE,
                DELEGATED_USE_SERVER,
                DELEGATED_USE_CLIENT,
                NATIVE_CALLER,
            ]);
        }
        roles
    }

    /// The names are public contracts. No caller chooses a token policy, key
    /// name, provider path, arbitrary output name, host or SAN.
    pub fn output_names(&self) -> BTreeSet<String> {
        let mut result = BTreeSet::from([METADATA.into(), WORKLOAD_CA.into()]);
        if self.operation == Operation::Provision {
            result.extend([RENEWAL_ROLE_ID.into(), RENEWAL_SECRET_ID.into()]);
        }
        for role in self.identities() {
            result.extend([role.certificate.into(), role.token.into()]);
        }
        if self.delegated_use {
            result.extend([
                CLIENT_CA_DER.into(),
                "feature_delegated_use_request_mint_token".into(),
                "feature_delegated_use_receipt_mint_token".into(),
            ]);
        }
        if self.public_verification {
            result.insert("feature_public_verification_holder_mint_token".into());
        }
        if self.public_verification || self.delegated_use {
            result.extend([
                "feature_sign_grant_verify_token".into(),
                "feature_signing_keys_openbao_token".into(),
            ]);
        }
        result
    }

    pub fn grant_origins(&self) -> Vec<&'static str> {
        let mut origins = Vec::new();
        if self.public_verification {
            origins.push("flow-demo-holder");
        }
        if self.delegated_use {
            origins.push("delegated-decision");
        }
        origins
    }

    pub fn runtime_policies(&self) -> BTreeSet<String> {
        let mut result: BTreeSet<String> = self
            .identities()
            .iter()
            .map(|role| role.role.into())
            .collect();
        if self.public_verification || self.delegated_use {
            result.extend([
                "credential-service".into(),
                "signing-keys-managed".into(),
                "sign-grant-verify".into(),
                "native-feature-sign-grant-verify".into(),
            ]);
        }
        if self.public_verification {
            result.extend([
                "native-feature-demo-holder-custody".into(),
                "native-feature-mint-flow-demo-holder".into(),
            ]);
        }
        if self.delegated_use {
            result.extend([
                "sign-grant-mint-flow-wallet".into(),
                "native-feature-mint-delegated-decision".into(),
            ]);
        }
        result
    }

    pub fn receipt(&self) -> serde_json::Value {
        serde_json::json!({
            "schema":SCHEMA, "selection":self,
            "keys":self.identities().iter().map(|role| serde_json::json!({
                "role":role.role,"key_name":role.key,"version":1,
                "certificate_file":role.certificate,"token_file":role.token,
            })).collect::<Vec<_>>(),
            "grant_origins":self.grant_origins(),
            "files":self.output_names(), "leaf_max_lifetime_seconds":MAX_LEAF_SECONDS,
            "governed_authority_created":false, "installation_ready":false,
        })
    }
}

pub fn tls_policy(role: Identity) -> String {
    format!("path \"transit/keys/{}\" {{ capabilities = [\"read\"] }}\npath \"transit/sign/{}\" {{ capabilities = [\"update\"] }}\n", role.key, role.key)
}

pub fn mint_policy(origin: &str) -> Option<String> {
    matches!(origin, "flow-demo-holder" | "delegated-decision").then(|| format!(
        "path \"transit/hmac/marty-sign-grant-{origin}-v1/sha2-256\" {{ capabilities = [\"update\"] }}\n"))
}

pub fn verification_policy(selection: &Selection) -> String {
    selection.grant_origins().iter().map(|origin| format!(
        "path \"transit/verify/marty-sign-grant-{origin}-v1/sha2-256\" {{ capabilities = [\"update\"] }}\n")).collect()
}

/// Additive custody is only for the existing demo-holder key namespace; the
/// baseline credential and issuer policy stays exactly as installed.
pub const DEMO_HOLDER_CUSTODY_POLICY: &str = "path \"transit/keys/demo-holder-*\" {\n  capabilities = [\"create\", \"update\", \"read\"]\n  allowed_parameters = { \"type\" = [\"ecdsa-p256\"] }\n}\npath \"transit/sign/demo-holder-*\" { capabilities = [\"update\"] }\npath \"transit/verify/demo-holder-*\" { capabilities = [\"update\"] }\n";

#[cfg(test)]
mod tests {
    use super::*;
    fn selected() -> Selection {
        Selection {
            schema: SCHEMA.into(),
            installation_id: "00000000-0000-4000-8000-000000000001".into(),
            feature_profile_sha256: "a".repeat(64),
            operation: Operation::Provision,
            wallet_governance: true,
            public_verification: true,
            delegated_use: true,
        }
    }
    #[test]
    fn selected_inventory_is_disjoint_from_every_baseline_identity_and_owner_authority() {
        let selected = selected();
        selected.validate().unwrap();
        let mut keys = BTreeSet::new();
        let mut names = BTreeSet::new();
        for role in selected.identities() {
            assert!(keys.insert(role.key));
            assert!(names.insert(role.certificate));
            assert!(names.insert(role.token));
            assert!(role.server ^ role.client);
            assert!(crate::SELFHOST_ROLES
                .iter()
                .all(|base| base.key_name != role.key
                    && base.cert_file != role.certificate
                    && base.token_file != role.token));
            assert!(!tls_policy(role).contains("transit/keys/*"));
        }
        assert!(selected
            .output_names()
            .iter()
            .all(|name| name.starts_with("feature_") && !name.contains('/')));
        let mut renewed = selected.clone();
        renewed.operation = Operation::Renew;
        assert!(!renewed.output_names().contains(RENEWAL_ROLE_ID));
        assert!(!renewed.output_names().contains(RENEWAL_SECRET_ID));
        assert_eq!(selected.identities(), renewed.identities());
    }
    #[test]
    fn signing_authorities_are_distinct_and_do_not_create_governed_keys() {
        let selected = selected();
        let verify = verification_policy(&selected);
        assert!(!verify.contains("transit/hmac") && !verify.contains("transit/sign/"));
        for origin in selected.grant_origins() {
            let mint = mint_policy(origin).unwrap();
            assert!(!mint.contains("transit/verify") && !mint.contains("transit/keys"));
        }
        assert!(mint_policy("../../sys").is_none());
        assert!(!DEMO_HOLDER_CUSTODY_POLICY.contains("exportable"));
        assert!(!DEMO_HOLDER_CUSTODY_POLICY.contains("import"));
        assert_eq!(selected.receipt()["governed_authority_created"], false);
    }
}
