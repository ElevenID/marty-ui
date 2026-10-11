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
}
