//! Canonical, public inputs for a Gateway-authorized service CSR ceremony.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCsrIntent {
    #[serde(default)]
    pub organization_id: Option<String>,
    pub country: String,
    pub organization: String,
    pub common_name: String,
    pub key_reference: String,
    pub algorithm: String,
}

#[derive(Serialize)]
struct BoundServiceCsrIntent<'a> {
    country: &'a str,
    organization: &'a str,
    common_name: &'a str,
    key_reference: &'a str,
    algorithm: &'a str,
}

impl ServiceCsrIntent {
    /// The tenant and service ID are separate grant fields. Serialize the
    /// remaining signed intent once in shared Rust code for both producer and
    /// consumer; the eventual CSR DER is bound again at the KMS call.
    pub fn bound_payload(&self) -> Vec<u8> {
        serde_json::to_vec(&BoundServiceCsrIntent {
            country: &self.country,
            organization: &self.organization,
            common_name: &self.common_name,
            key_reference: &self.key_reference,
            algorithm: &self.algorithm,
        })
        .expect("fixed CSR intent fields serialize")
    }
}

/// Public issuer CSR inputs. The selected KMS key is resolved from the
/// managed issuer profile and must never be supplied by the caller.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerCsrIntent {
    #[serde(default)]
    pub organization_id: Option<String>,
    pub issuer_did: String,
    pub key_purpose: String,
    pub credential_format: String,
    pub algorithm: String,
    pub country: String,
    pub organization: String,
    pub common_name: String,
}

#[derive(Serialize)]
struct BoundIssuerCsrIntent<'a> {
    issuer_did: &'a str,
    key_purpose: &'a str,
    credential_format: &'a str,
    algorithm: &'a str,
    country: &'a str,
    organization: &'a str,
    common_name: &'a str,
}

impl IssuerCsrIntent {
    /// The authenticated tenant and route are separate grant fields; the
    /// resolved KMS key and generated CSR bytes are bound at final signing.
    pub fn bound_payload(&self) -> Vec<u8> {
        serde_json::to_vec(&BoundIssuerCsrIntent {
            issuer_did: &self.issuer_did,
            key_purpose: &self.key_purpose,
            credential_format: &self.credential_format,
            algorithm: &self.algorithm,
            country: &self.country,
            organization: &self.organization,
            common_name: &self.common_name,
        })
        .expect("fixed issuer CSR intent fields serialize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_field_cannot_change_the_bound_csr_intent() {
        let first: ServiceCsrIntent = serde_json::from_str(
            r#"{"organization_id":"tenant-1","country":"US","organization":"Example","common_name":"example.invalid","key_reference":"key-1","algorithm":"ES256"}"#,
        )
        .unwrap();
        let second: ServiceCsrIntent = serde_json::from_str(
            r#"{"algorithm":"ES256","key_reference":"key-1","common_name":"example.invalid","organization":"Example","country":"US"}"#,
        )
        .unwrap();
        assert_eq!(first.bound_payload(), second.bound_payload());
        assert!(!String::from_utf8(first.bound_payload())
            .unwrap()
            .contains("tenant-1"));
        assert!(serde_json::from_str::<ServiceCsrIntent>(
            r#"{"country":"US","organization":"Example","common_name":"example.invalid","key_reference":"key-1","algorithm":"ES256","private_key":"secret"}"#,
        )
        .is_err());
    }

    #[test]
    fn issuer_csr_binds_public_identity_and_rejects_caller_key() {
        let first: IssuerCsrIntent = serde_json::from_str(
            r#"{"organization_id":"org-a","issuer_did":"did:web:example.test:issuer","key_purpose":"csca","credential_format":"MDOC","algorithm":"ES256","country":"US","organization":"Example","common_name":"Issuer"}"#,
        )
        .unwrap();
        let second: IssuerCsrIntent = serde_json::from_str(
            r#"{"issuer_did":"did:web:example.test:issuer","key_purpose":"csca","credential_format":"MDOC","algorithm":"ES256","country":"US","organization":"Example","common_name":"Issuer"}"#,
        )
        .unwrap();
        assert_eq!(first.bound_payload(), second.bound_payload());
        assert!(!String::from_utf8(first.bound_payload())
            .unwrap()
            .contains("org-a"));
        assert!(serde_json::from_str::<IssuerCsrIntent>(
            r#"{"issuer_did":"did:web:example.test:issuer","key_purpose":"csca","credential_format":"MDOC","algorithm":"ES256","country":"US","organization":"Example","common_name":"Issuer","key_reference":"attacker-key"}"#,
        )
        .is_err());
    }
}
