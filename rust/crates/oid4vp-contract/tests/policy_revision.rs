use marty_oid4vp_contract::{digest_policy_snapshot, digest_query_document, FrozenPolicyIdentity};
use serde_json::json;

#[test]
fn policy_snapshot_digest_is_canonical_and_domain_separated() {
    let left = json!({"organization_id": "org", "policy": {"id": "policy", "version": 1}});
    let right: serde_json::Value =
        serde_json::from_str(r#"{"policy":{"version":1,"id":"policy"},"organization_id":"org"}"#)
            .unwrap();
    assert_eq!(
        digest_policy_snapshot(&left).unwrap(),
        digest_policy_snapshot(&right).unwrap()
    );
    assert_ne!(
        digest_policy_snapshot(&left).unwrap(),
        digest_query_document(&left).unwrap()
    );
}

#[test]
fn policy_identity_requires_bounded_id_positive_version_and_canonical_digest() {
    let valid = FrozenPolicyIdentity {
        id: "policy-1".into(),
        version: 1,
        content_digest: digest_policy_snapshot(&json!({"policy": "saved"})).unwrap(),
    };
    valid.validate().unwrap();
    for invalid in [
        FrozenPolicyIdentity {
            id: String::new(),
            ..valid.clone()
        },
        FrozenPolicyIdentity {
            id: "policy\nspoof".into(),
            ..valid.clone()
        },
        FrozenPolicyIdentity {
            id: "x".repeat(256),
            ..valid.clone()
        },
        FrozenPolicyIdentity {
            version: 0,
            ..valid.clone()
        },
        FrozenPolicyIdentity {
            content_digest: "0".repeat(64),
            ..valid.clone()
        },
        FrozenPolicyIdentity {
            content_digest: format!("sha256:{}", "A".repeat(64)),
            ..valid.clone()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}
