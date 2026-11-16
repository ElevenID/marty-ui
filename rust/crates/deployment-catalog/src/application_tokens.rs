//! Closed ordinary application-token inventory shared by bootstrap and replacement.
//! The two initial-only credentials never enter routine replacement authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA: &str = "marty.kubernetes-application-tokens/v1";
const SPEC: &str =
    include_str!("../../../../deploy-config/catalog/kubernetes-application-tokens.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenSpec {
    pub input: String,
    pub file: String,
    pub policies: Vec<String>,
    pub ttl_seconds: u64,
    pub replacement_role: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    tokens: Vec<TokenSpec>,
}

pub fn specifications() -> Vec<TokenSpec> {
    let inventory: Inventory =
        serde_json::from_str(SPEC).expect("compiled application-token inventory must be valid");
    assert_eq!(inventory.schema, SCHEMA);
    inventory.tokens
}

pub fn runtime_specs() -> Vec<TokenSpec> {
    specifications()
        .into_iter()
        .filter(|spec| spec.replacement_role.is_some())
        .collect()
}

/// Only public input names, fixed policy bundles and requested TTLs are emitted.
pub fn contract() -> Value {
    serde_json::from_str(SPEC).expect("compiled application-token inventory must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn replacement_inventory_has_exact_runtime_scopes_and_initial_only_exclusions() {
        let specs = specifications();
        let runtime = runtime_specs();
        let expected = BTreeSet::from([
            "SIGNING_KEYS_OPENBAO_TOKEN",
            "DIDCOMM_ISSUANCE_OPENBAO_TOKEN",
            "NOTIFICATION_OPENBAO_TOKEN",
            "GATEWAY_SIGN_GRANT_MINT_TOKEN",
            "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN",
            "FLOW_SIGN_GRANT_MINT_TOKEN",
            "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN",
            "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN",
            "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN",
            "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN",
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN",
        ]);
        assert_eq!(specs.len(), 13);
        assert_eq!(runtime.len(), 11);
        assert_eq!(
            runtime
                .iter()
                .map(|spec| spec.input.as_str())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            specs
                .iter()
                .map(|spec| spec.file.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            13
        );
        assert_eq!(
            runtime
                .iter()
                .map(|spec| spec.replacement_role.as_deref().unwrap())
                .collect::<BTreeSet<_>>()
                .len(),
            11
        );
        for spec in &specs {
            assert_eq!(spec.file, spec.input.to_ascii_lowercase());
            assert_eq!(
                spec.ttl_seconds,
                if spec.input == "OPENBAO_BOOTSTRAP_TOKEN" {
                    7200
                } else {
                    28800
                }
            );
            assert!(!spec.policies.is_empty());
            assert!(spec
                .policies
                .iter()
                .all(|policy| policy != "root" && policy != "default"));
            if spec.input == "SIGNING_KEYS_OPENBAO_TOKEN" {
                assert_eq!(
                    spec.policies,
                    ["credential-service", "signing-keys-managed"]
                );
            } else {
                assert_eq!(spec.policies.len(), 1);
            }
            if expected.contains(spec.input.as_str()) {
                assert_eq!(
                    spec.replacement_role.as_deref(),
                    Some(
                        format!("selfhost-application-leaf-{}", spec.file.replace('_', "-"))
                            .as_str()
                    )
                );
            } else {
                assert!(["OPENBAO_SERVICE_TOKEN", "OPENBAO_BOOTSTRAP_TOKEN"]
                    .contains(&spec.input.as_str()));
                assert!(spec.replacement_role.is_none());
            }
        }
        let public = contract();
        assert_eq!(public["schema"], SCHEMA);
        assert_eq!(public["tokens"], serde_json::to_value(&specs).unwrap());
    }
}
